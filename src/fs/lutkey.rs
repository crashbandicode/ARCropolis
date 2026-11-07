use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

/// Discovery's mod-set key mixed with the game version, so a copied or stale LUT is rebuilt.
pub fn lut_key(discovery_key: u64, game_version: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    discovery_key.hash(&mut hasher);
    game_version.hash(&mut hasher);
    hasher.finish()
}

pub fn read_keyed_payload(bytes: &[u8], key: u64) -> Option<&[u8]> {
    if bytes.len() < 8 {
        return None;
    }
    let mut stored = [0u8; 8];
    stored.copy_from_slice(&bytes[..8]);
    if u64::from_le_bytes(stored) != key {
        return None;
    }
    Some(&bytes[8..])
}

pub fn prefix_key(key: u64, payload: &[u8]) -> Vec<u8> {
    let mut bytes = key.to_le_bytes().to_vec();
    bytes.extend_from_slice(payload);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lut_with_a_different_key_is_rebuilt() {
        let payload = b"share-lut-body";
        let bytes = prefix_key(0x1111_2222_3333_4444, payload);
        assert_eq!(read_keyed_payload(&bytes, 0x1111_2222_3333_4444), Some(payload.as_slice()));
        assert_eq!(read_keyed_payload(&bytes, 0x2222_3333_4444_5555), None);
        assert_eq!(read_keyed_payload(payload, 0x1111_2222_3333_4444), None);

        let current = lut_key(0xA, "13.0.5");
        let other_mods = lut_key(0xB, "13.0.5");
        let other_game = lut_key(0xA, "13.0.4");
        assert_ne!(current, other_mods);
        assert_ne!(current, other_game);
        assert_eq!(read_keyed_payload(&prefix_key(other_mods, payload), current), None);
    }
}
