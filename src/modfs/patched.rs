use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    fs::File,
    hash::{Hash, Hasher},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::LazyLock,
};

#[cfg(test)]
use std::cell::RefCell;

use smash_arc::{Hash40, Region};

use super::ModFsError;

const PATCHED_FORMAT: u32 = 2;

const HEADER_LEN: usize = 24;

const BLOB_SUFFIX: &str = ".bin";
const TMP_SUFFIX: &str = ".tmp";

static ENABLED: LazyLock<bool> = LazyLock::new(|| std::env::var("ARCROP_PATCH_CACHE").map(|v| v != "0").unwrap_or(true));

pub fn enabled() -> bool {
    *ENABLED
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceStamp {
    pub path: PathBuf,
    pub size: u64,
    pub mtime: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatchedEntry {
    pub path: PathBuf,
    pub len: usize,
    pub key: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MaterialiseReport {
    pub hits: usize,
    pub written: usize,
    pub failed: usize,
    pub pruned: usize,
    pub disabled: bool,
    pub elapsed_ms: u128,
}

#[derive(Default)]
pub struct PatchedIndex {
    entries: HashMap<Hash40, PatchedEntry>,
}

impl PatchedIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, hash: Hash40, entry: PatchedEntry) {
        self.entries.insert(hash, entry);
    }

    pub fn get(&self, hash: Hash40) -> Option<&PatchedEntry> {
        self.entries.get(&hash)
    }

    pub fn len(&self, hash: Hash40) -> Option<usize> {
        self.entries.get(&hash).map(|entry| entry.len)
    }

    pub fn count(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
thread_local! {
    static DIR_OVERRIDE: RefCell<Option<PathBuf>> = RefCell::new(None);
}

pub fn dir() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = DIR_OVERRIDE.with(|slot| slot.borrow().clone()) {
        return path;
    }
    crate::utils::paths::cache().join("patched").into()
}

pub fn blob_name(hash: Hash40) -> String {
    format!("{:010x}{}", hash.0, BLOB_SUFFIX)
}

pub fn blob_path(hash: Hash40) -> PathBuf {
    dir().join(blob_name(hash))
}

pub fn parse_blob_name(name: &str) -> Option<Hash40> {
    let stem = name.strip_suffix(BLOB_SUFFIX)?;
    if stem.len() != 10 || !stem.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(stem, 16).ok().map(Hash40)
}

pub fn stamp(path: &Path) -> SourceStamp {
    let size = std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
    SourceStamp {
        path: path.to_path_buf(),
        size,
        mtime: mtime(path),
    }
}

#[cfg(target_os = "switch")]
fn mtime(path: &Path) -> u64 {
    let Some(text) = path.to_str() else {
        return 0;
    };
    let terminated = format!("{}\0", text);
    let mut stamp = skyline::nn::fs::FileTimeStamp::default();
    let result = unsafe { skyline::nn::fs::GetFileTimeStampForDebug(&mut stamp, terminated.as_ptr()) };
    if result != 0 {
        return 0;
    }
    stamp.modify.time
}

#[cfg(not(target_os = "switch"))]
fn mtime(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

pub fn key(region: Region, base_size: usize, chain: &[&str], sources: &[SourceStamp]) -> u64 {
    let mut hasher = DefaultHasher::new();
    env!("CARGO_PKG_VERSION").hash(&mut hasher);
    PATCHED_FORMAT.hash(&mut hasher);
    (region as u32).hash(&mut hasher);
    base_size.hash(&mut hasher);
    chain.hash(&mut hasher);

    let mut sorted: Vec<&SourceStamp> = sources.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    sorted.len().hash(&mut hasher);
    for source in sorted {
        source.path.hash(&mut hasher);
        source.size.hash(&mut hasher);
        source.mtime.hash(&mut hasher);
    }
    hasher.finish()
}

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn mix(mut sum: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        sum ^= byte as u64;
        sum = sum.wrapping_mul(FNV_PRIME);
    }
    sum
}

fn payload_sum(bytes: &[u8]) -> u64 {
    mix(FNV_OFFSET, bytes)
}

fn stream_sum(file: &mut File, len: u64) -> std::io::Result<u64> {
    let mut sum = FNV_OFFSET;
    let mut left = len;
    let mut buf = [0u8; 8192];
    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        let n = file.read(&mut buf[..want])?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short payload"));
        }
        sum = mix(sum, &buf[..n]);
        left -= n as u64;
    }
    Ok(sum)
}

pub fn encode_header(key: u64, len: u64, sum: u64) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[..8].copy_from_slice(&key.to_le_bytes());
    header[8..16].copy_from_slice(&len.to_le_bytes());
    header[16..].copy_from_slice(&sum.to_le_bytes());
    header
}

pub fn decode_header(bytes: &[u8]) -> Option<(u64, u64, u64)> {
    if bytes.len() < HEADER_LEN {
        return None;
    }
    let mut key = [0u8; 8];
    let mut len = [0u8; 8];
    let mut sum = [0u8; 8];
    key.copy_from_slice(&bytes[..8]);
    len.copy_from_slice(&bytes[8..16]);
    sum.copy_from_slice(&bytes[16..HEADER_LEN]);
    Some((u64::from_le_bytes(key), u64::from_le_bytes(len), u64::from_le_bytes(sum)))
}

fn park(path: &Path, reason: &str) {
    let bad = path.with_extension("bad");
    let _ = std::fs::remove_file(&bad);
    if std::fs::rename(path, &bad).is_err() {
        return;
    }
    let _ = std::fs::create_dir_all(dir());
    let Ok(mut log) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir().join("reject.log"))
    else {
        return;
    };
    let _ = writeln!(log, "{reason}");
}

pub fn probe(hash: Hash40, key: u64) -> Option<PatchedEntry> {
    let path = blob_path(hash);
    let mut file = File::open(&path).ok()?;
    let mut header = [0u8; HEADER_LEN];
    if file.read_exact(&mut header).is_err() {
        drop(file);
        park(&path, &format!("{:010x} short-header", hash.0));
        return None;
    }
    let (stored_key, len, sum) = decode_header(&header)?;
    if stored_key != key {
        return None;
    }
    let size = file.metadata().ok()?.len();
    if size != HEADER_LEN as u64 + len {
        drop(file);
        park(&path, &format!("{:010x} size file {size:#x} header {len:#x}", hash.0));
        return None;
    }
    let actual = match stream_sum(&mut file, len) {
        Ok(actual) => actual,
        Err(_) => {
            drop(file);
            park(&path, &format!("{:010x} short-payload", hash.0));
            return None;
        }
    };
    drop(file);
    if actual != sum {
        park(
            &path,
            &format!(
                "{:010x} checksum key {key:016x} len {len:#x} stored {sum:016x} actual {actual:016x}",
                hash.0
            ),
        );
        return None;
    }
    Some(PatchedEntry {
        path,
        len: len as usize,
        key,
    })
}

pub fn write(hash: Hash40, key: u64, bytes: &[u8]) -> std::io::Result<PatchedEntry> {
    let path = blob_path(hash);
    let tmp = dir().join(format!("{:010x}{}", hash.0, TMP_SUFFIX));
    {
        let mut file = File::create(&tmp)?;
        file.write_all(&encode_header(key, bytes.len() as u64, payload_sum(bytes)))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    let _ = std::fs::remove_file(&path);
    if let Err(e) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(PatchedEntry {
        path,
        len: bytes.len(),
        key,
    })
}

pub fn prune(keep: &HashSet<Hash40>) -> usize {
    let Ok(entries) = std::fs::read_dir(dir()) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if name.ends_with(TMP_SUFFIX) {
            if std::fs::remove_file(entry.path()).is_ok() {
                removed += 1;
            }
            continue;
        }
        let Some(hash) = parse_blob_name(name) else {
            continue;
        };
        if keep.contains(&hash) {
            continue;
        }
        if std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

fn open_payload(entry: &PatchedEntry) -> Result<File, ModFsError> {
    let mut file = File::open(&entry.path)?;
    file.seek(SeekFrom::Start(HEADER_LEN as u64))?;
    Ok(file)
}

pub fn read(entry: &PatchedEntry) -> Result<Vec<u8>, ModFsError> {
    let mut file = open_payload(entry)?;
    let mut bytes = Vec::with_capacity(entry.len);
    file.read_to_end(&mut bytes)?;
    if bytes.len() != entry.len {
        return Err(ModFsError::Handler(format!(
            "patched blob {} holds {:#x} bytes but its header says {:#x}",
            entry.path.display(),
            bytes.len(),
            entry.len
        )));
    }
    Ok(bytes)
}

pub fn read_into(entry: &PatchedEntry, buffer: &mut [u8]) -> Result<usize, ModFsError> {
    let file = open_payload(entry)?;
    super::stream_into(file, buffer, entry.len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(path: &str, size: u64, mtime: u64) -> SourceStamp {
        SourceStamp {
            path: PathBuf::from(path),
            size,
            mtime,
        }
    }

    fn sample() -> Vec<SourceStamp> {
        vec![source("a/one.prcx", 10, 100), source("b/two.prcx", 20, 200)]
    }

    #[test]
    fn header_round_trips() {
        let header = encode_header(0xdead_beef_1234_5678, 0x4321, 0x1111);
        assert_eq!(decode_header(&header), Some((0xdead_beef_1234_5678, 0x4321, 0x1111)));
    }

    #[test]
    fn header_rejects_truncation() {
        let header = encode_header(1, 2, 3);
        for len in 0..HEADER_LEN {
            assert_eq!(decode_header(&header[..len]), None, "{} bytes should not decode", len);
        }
    }

    #[test]
    fn blob_names_round_trip() {
        let hash = Hash40(0x00ab_cdef_12);
        assert_eq!(blob_name(hash), "00abcdef12.bin");
        assert_eq!(parse_blob_name(&blob_name(hash)), Some(hash));
    }

    #[test]
    fn blob_names_reject_strangers() {
        assert_eq!(parse_blob_name("discovery.cache"), None);
        assert_eq!(parse_blob_name("00abcdef12.tmp"), None);
        assert_eq!(parse_blob_name("abcdef12.bin"), None);
        assert_eq!(parse_blob_name("00abcdef1234.bin"), None);
        assert_eq!(parse_blob_name("00abcdefzz.bin"), None);
    }

    #[test]
    fn key_is_stable() {
        let chain = ["prc"];
        assert_eq!(
            key(Region::UsEnglish, 0x100, &chain, &sample()),
            key(Region::UsEnglish, 0x100, &chain, &sample())
        );
    }

    #[test]
    fn key_changes_with_base_size() {
        let chain = ["prc"];
        assert_ne!(
            key(Region::UsEnglish, 0x100, &chain, &sample()),
            key(Region::UsEnglish, 0x200, &chain, &sample())
        );
    }

    #[test]
    fn key_changes_with_source_size() {
        let chain = ["prc"];
        let mut grown = sample();
        grown[0].size += 1;
        assert_ne!(
            key(Region::UsEnglish, 0x100, &chain, &sample()),
            key(Region::UsEnglish, 0x100, &chain, &grown)
        );
    }

    #[test]
    fn key_changes_with_mtime() {
        let chain = ["prc"];
        let mut touched = sample();
        touched[1].mtime += 1;
        assert_ne!(
            key(Region::UsEnglish, 0x100, &chain, &sample()),
            key(Region::UsEnglish, 0x100, &chain, &touched)
        );
    }

    #[test]
    fn key_changes_with_region() {
        let chain = ["msbt"];
        assert_ne!(
            key(Region::UsEnglish, 0x100, &chain, &sample()),
            key(Region::EuEnglish, 0x100, &chain, &sample())
        );
    }

    #[test]
    fn key_changes_with_chain_order() {
        assert_ne!(
            key(Region::UsEnglish, 0x100, &["prc", "msbt"], &sample()),
            key(Region::UsEnglish, 0x100, &["msbt", "prc"], &sample())
        );
    }

    #[test]
    fn key_ignores_source_order() {
        let chain = ["prc"];
        let mut reversed = sample();
        reversed.reverse();
        assert_eq!(
            key(Region::UsEnglish, 0x100, &chain, &sample()),
            key(Region::UsEnglish, 0x100, &chain, &reversed)
        );
    }

    #[test]
    fn key_counts_duplicate_sources() {
        let chain = ["prc"];
        let mut doubled = sample();
        doubled.push(sample()[0].clone());
        assert_ne!(
            key(Region::UsEnglish, 0x100, &chain, &sample()),
            key(Region::UsEnglish, 0x100, &chain, &doubled)
        );
    }

    #[test]
    fn corrupted_blob_is_kept_and_rebuilt() {
        let root = std::env::temp_dir().join(format!("arcrop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        DIR_OVERRIDE.with(|slot| *slot.borrow_mut() = Some(root.clone()));
        let hash = Hash40(0x0a11);
        let payload = b"patched-bytes";
        let key = 0x55aa;
        write(hash, key, payload).unwrap();
        let path = blob_path(hash);
        let mut stored = std::fs::read(&path).unwrap();
        stored[HEADER_LEN] ^= 0xff;
        std::fs::write(&path, &stored).unwrap();
        assert!(probe(hash, key).is_none());
        assert_eq!(std::fs::read(path.with_extension("bad")).unwrap(), stored);
        let entry = write(hash, key, payload).unwrap();
        let indexed = probe(hash, key).unwrap();
        assert_eq!((indexed.len, read(&indexed).unwrap()), (entry.len, payload.to_vec()));
        DIR_OVERRIDE.with(|slot| *slot.borrow_mut() = None);
        let _ = std::fs::remove_dir_all(root);
    }
}
