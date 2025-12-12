//! File hashing module
//!
//! Provides cryptographic hash calculation for files using MD5, SHA-256, and SHA-512.

use md5::Md5;
use sha2::{Digest, Sha256, Sha512};

/// File hashes structure
#[derive(Debug, Clone, serde::Serialize)]
pub struct FileHashes {
    /// MD5 hash (128-bit)
    pub md5: String,
    /// SHA-256 hash (256-bit)
    pub sha256: String,
    /// Optional SHA-512 hash (512-bit)
    pub sha512: Option<String>,
}

/// Calculate file hashes (MD5, SHA-256, SHA-512)
///
/// # Examples
/// ```no_run
/// use batin::hasher::calculate_hashes;
///
/// let data = b"Hello, World!";
/// let hashes = calculate_hashes(data, true);
/// println!("MD5: {}", hashes.md5);
/// println!("SHA-256: {}", hashes.sha256);
/// ```
pub fn calculate_hashes(data: &[u8], include_sha512: bool) -> FileHashes {
    // Calculate MD5
    let mut md5_hasher = Md5::new();
    md5_hasher.update(data);
    let md5 = format!("{:x}", md5_hasher.finalize());

    // Calculate SHA-256
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(data);
    let sha256 = format!("{:x}", sha256_hasher.finalize());

    // Optionally calculate SHA-512
    let sha512 = if include_sha512 {
        let mut sha512_hasher = Sha512::new();
        sha512_hasher.update(data);
        Some(format!("{:x}", sha512_hasher.finalize()))
    } else {
        None
    };

    FileHashes {
        md5,
        sha256,
        sha512,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_calculation() {
        let data = b"test data";
        let hashes = calculate_hashes(data, true);

        // MD5 should be 32 hex chars
        assert_eq!(hashes.md5.len(), 32);
        // SHA-256 should be 64 hex chars
        assert_eq!(hashes.sha256.len(), 64);
        // SHA-512 should be 128 hex chars
        assert_eq!(hashes.sha512.unwrap().len(), 128);
    }
}
