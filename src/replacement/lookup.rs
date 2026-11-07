use std::{
    collections::{HashMap, HashSet},
    ops::{Deref, DerefMut}, sync::{LazyLock, RwLock},
};

use serde::{Deserialize, Serialize};
use smash_arc::{ArcLookup, Hash40, LoadedArc};

use super::LoadedArcEx;
use crate::hashes;

// FilePath -> (DirInfo, child_index)
#[derive(Deserialize, Serialize)]
pub struct UnshareLookup(HashMap<Hash40, (Hash40, usize)>);

#[derive(Deserialize, Serialize)]
pub struct ShareLookup {
    pub is_shared_search: HashSet<Hash40>,
    pub shared_file_lookup: HashMap<Hash40, Vec<Hash40>>,
}

impl Deref for UnshareLookup {
    type Target = HashMap<Hash40, (Hash40, usize)>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for UnshareLookup {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

enum UnshareLookupState {
    Unloaded,
    Generated(UnshareLookup),
}

enum ShareLookupState {
    Unloaded,
    Generated(ShareLookup),
}

static UNSHARE_LOOKUP: LazyLock<RwLock<UnshareLookupState>> = LazyLock::new(|| RwLock::new(UnshareLookupState::Unloaded));

static SHARE_LOOKUP: LazyLock<RwLock<ShareLookupState>> = LazyLock::new(|| RwLock::new(ShareLookupState::Unloaded));

/// Discovery publishes the key on another thread, after a short delay. Wait for it
/// before trusting or replacing a LUT, then give up so boot can still build one in memory.
fn published_lut_key() -> Option<u64> {
    let start = std::time::Instant::now();
    loop {
        if let Some(key) = crate::fs::published_lut_key() {
            return Some(key);
        }
        if start.elapsed() >= std::time::Duration::from_secs(20) {
            error!("Mod discovery did not publish a LUT key. The share tables will be rebuilt in memory.");
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn read_cached_lut<T: serde::de::DeserializeOwned>(file_name: &str, key: u64) -> Option<T> {
    let path = crate::utils::paths::cache().join(file_name);
    let data = match std::fs::read(&path) {
        Ok(data) => data,
        Err(err) => {
            error!("Unable to read '{}'. Reason: {:?}", path, err);
            return None;
        },
    };
    let Some(payload) = crate::fs::read_keyed_payload(&data, key) else {
        error!("'{}' does not match this mod set. It will be rebuilt.", path);
        return None;
    };
    match bincode::deserialize(payload) {
        Ok(lut) => Some(lut),
        Err(err) => {
            error!("Unable to parse '{}'. Reason: {:?}. Boot time might be a bit slow.", path, err);
            None
        },
    }
}

fn write_cached_lut<T: serde::Serialize>(file_name: &str, key: u64, value: &T) {
    let path = crate::utils::paths::cache().join(file_name);
    match bincode::serialize(value) {
        Ok(payload) => {
            let bytes = crate::fs::prefix_key(key, &payload);
            if let Err(err) = std::fs::write(&path, bytes) {
                error!("Failed to write LUT to cache file at '{}'. Reason: {:?}", path, err);
            }
        },
        Err(err) => error!("Failed to serialize LUT into bytes. Reason: {:?}", err),
    }
}

pub fn initialize_unshare(arc: Option<&LoadedArc>) {
    let key = published_lut_key();
    let mut lookup_state = UNSHARE_LOOKUP.write().unwrap();
    if matches!(*lookup_state, UnshareLookupState::Generated(_)) {
        return;
    }
    if let Some(key) = key {
        if let Some(lut) = read_cached_lut("unshare.lut", key) {
            *lookup_state = UnshareLookupState::Generated(lut);
            return;
        }
    }
    let Some(arc) = arc else {
        return;
    };

    let mut lookup = UnshareLookup(HashMap::new());
    let file_paths = arc.get_file_paths();
    for dir_info in arc.get_dir_infos() {
        for (child_index, file_info) in arc.get_file_infos()[dir_info.file_info_range()].iter().enumerate() {
            lookup.insert(file_paths[file_info.file_path_index].path.hash40(), (dir_info.path.hash40(), child_index));
        }
    }
    if let Some(key) = key {
        write_cached_lut("unshare.lut", key, &lookup);
    }
    *lookup_state = UnshareLookupState::Generated(lookup);
}

pub fn initialize_share(arc: Option<&LoadedArc>) {
    let key = published_lut_key();
    let mut lookup_state = SHARE_LOOKUP.write().unwrap();
    if matches!(*lookup_state, ShareLookupState::Generated(_)) {
        return;
    }
    if let Some(key) = key {
        if let Some(lut) = read_cached_lut("share.lut", key) {
            *lookup_state = ShareLookupState::Generated(lut);
            return;
        }
    }
    let Some(arc) = arc else {
        return;
    };

    let lookup = {
            let mut path_shared: HashMap<Hash40, Vec<Hash40>> = HashMap::new();

            let mut shared_files = HashSet::new();

            let filepaths = arc.get_file_paths();

            for (current_index, file_path) in filepaths.iter().enumerate() {
                let hash = file_path.path.hash40();

                let shared_file_index = match arc.get_shared_file(hash) {
                    Ok(idx) => {
                        if usize::from(idx) == current_index {
                            continue;
                        }
                        idx
                    },
                    Err(_) => {
                        error!(
                            "Failed to get shared file for '{}' ({:#x}) while generating share.lut",
                            hashes::find(hash),
                            hash.0
                        );
                        continue;
                    },
                };

                let shared_hash = filepaths[shared_file_index].path.hash40();

                if let Some(shared_file_hashes) = path_shared.get_mut(&shared_hash) {
                    shared_file_hashes.push(hash);
                } else {
                    let _ = path_shared.insert(shared_hash, vec![hash]);
                }
            }

            for (src, shared) in path_shared.iter() {
                shared_files.insert(*src);
                for share in shared {
                    shared_files.insert(*share);
                }
            }

            ShareLookup {
                is_shared_search: shared_files,
                shared_file_lookup: path_shared,
            }
    };
    if let Some(key) = key {
        write_cached_lut("share.lut", key, &lookup);
    }
    *lookup_state = ShareLookupState::Generated(lookup);
}

pub fn initialize(arc: Option<&LoadedArc>) {
    initialize_unshare(arc);
    initialize_share(arc);
}

impl UnshareLookup {
    pub fn get_dir_entry_for_file<H: Into<Hash40>>(&self, hash: H) -> Option<(Hash40, usize)> {
        self.get(&hash.into()).copied()
    }
}

impl ShareLookup {
    pub fn is_shared_file<H: Into<Hash40>>(&self, hash: H) -> bool {
        self.is_shared_search.contains(&hash.into())
    }

    pub fn add_shared_file<H: Into<Hash40>>(&mut self, hash: H, shared_to: H) {
        let shared_to = shared_to.into();
        let hash = hash.into();
        self.is_shared_search.insert(shared_to);
        self.is_shared_search.insert(hash);

        if let Some(list) = self.shared_file_lookup.get_mut(&shared_to) {
            list.push(hash);
        } else {
            self.shared_file_lookup.insert(shared_to, vec![hash]);
        }
    }

    pub fn remove_shared_file<H: Into<Hash40>>(&mut self, hash: H) -> bool {
        self.is_shared_search.remove(&hash.into())
    }

    pub fn get_shared_file_count<H: Into<Hash40>>(&self, hash: H) -> usize {
        self.shared_file_lookup.get(&hash.into()).map_or(0, |hashes| hashes.len())
    }

    pub fn get_shared_file<H: Into<Hash40>>(&self, hash: H, index: usize) -> Option<Hash40> {
        self.shared_file_lookup.get(&hash.into()).and_then(|hashes| hashes.get(index).copied())
    }
}

pub fn with_lookups<F>(f: F)
where
    F: FnOnce(&UnshareLookup, &mut ShareLookup),
{
    let unshare = UNSHARE_LOOKUP.read().unwrap();
    let mut share = SHARE_LOOKUP.write().unwrap();
    match (&*unshare, &mut *share) {
        (UnshareLookupState::Generated(unshare_lut), ShareLookupState::Generated(share_lut)) => f(unshare_lut, share_lut),
        _ => {
            warn!("Lookup tables are not initialized");
        },
    }
}
