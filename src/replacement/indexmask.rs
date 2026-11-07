pub const NO_CHILD: u32 = 0xFF_FFFF;
pub const INVALID_INDEX: u32 = 0xFFFF_FFFF;

/// `DirectoryOffset.directory_index` stores its child in the low 24 bits.
/// `0x40FFFFFF` is the no-child marker with bit 30 set, and a raw compare lets it through.
pub fn child_index(index: u32) -> Option<usize> {
    let index = (index & NO_CHILD) as usize;
    if index == NO_CHILD as usize {
        None
    } else {
        Some(index)
    }
}

/// A plain index whose empty values are exactly `0xFFFFFF` and `0xFFFFFFFF`.
/// High bits are not a flag on path-list indexes or load-thread directory indexes, so they are not masked.
pub fn plain_index(index: u32, len: usize) -> Option<usize> {
    if index == NO_CHILD || index == INVALID_INDEX {
        return None;
    }
    let index = index as usize;
    (index < len).then_some(index)
}

#[cfg(test)]
mod tests {
    use super::{child_index, plain_index, NO_CHILD};

    #[test]
    fn flagged_directory_sentinel_is_empty() {
        assert_eq!(child_index(0x40FF_FFFF), None);
        assert_eq!(child_index(NO_CHILD), None);
        assert_eq!(child_index(0x4000_002A), Some(0x2A));
    }

    #[test]
    fn plain_index_rejects_sentinels_and_bounds() {
        assert_eq!(plain_index(NO_CHILD, 10), None);
        assert_eq!(plain_index(0xFFFF_FFFF, 10), None);
        assert_eq!(plain_index(0x40FF_FFFF, 10), None);
        assert_eq!(plain_index(0x4000_002A, 100), None);
        assert_eq!(plain_index(3, 10), Some(3));
        assert_eq!(plain_index(10, 10), None);
    }
}
