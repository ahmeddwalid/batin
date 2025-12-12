//! Shared utility functions
//!
//! Common pattern matching and byte manipulation utilities.

/// Find a pattern in data and return its position
///
/// # Examples
/// ```
/// use batin::utils::find_bytes;
///
/// assert_eq!(find_bytes(b"hello world", b"world"), Some(6));
/// assert_eq!(find_bytes(b"hello", b"xyz"), None);
/// ```
pub fn find_bytes(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() {
        return Some(0);
    }
    if pattern.len() > data.len() {
        return None;
    }
    data.windows(pattern.len())
        .position(|window| window == pattern)
}

/// Find all occurrences of a pattern in data
pub fn find_all_bytes(data: &[u8], pattern: &[u8]) -> Vec<usize> {
    if pattern.is_empty() || pattern.len() > data.len() {
        return Vec::new();
    }
    data.windows(pattern.len())
        .enumerate()
        .filter_map(
            |(idx, window)| {
                if window == pattern {
                    Some(idx)
                } else {
                    None
                }
            },
        )
        .collect()
}

/// Read a little-endian u32 from byte slice
pub fn read_le_u32(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Read a big-endian u32 from byte slice
pub fn read_be_u32(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_bytes() {
        assert_eq!(find_bytes(b"hello world", b"world"), Some(6));
        assert_eq!(find_bytes(b"hello", b"xyz"), None);
        assert_eq!(find_bytes(b"hello", b""), Some(0));
        assert_eq!(find_bytes(b"", b"hello"), None);
    }

    #[test]
    fn test_find_all_bytes() {
        let data = b"abcabcabc";
        let positions = find_all_bytes(data, b"abc");
        assert_eq!(positions, vec![0, 3, 6]);
    }

    #[test]
    fn test_read_le_u32() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_le_u32(&data, 0), Some(0x04030201));
    }

    #[test]
    fn test_read_be_u32() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_be_u32(&data, 0), Some(0x01020304));
    }
}
