//! Shannon Entropy calculation and analysis module
//!
//! Provides high-performance entropy analysis for detecting packed, encrypted,
//! or otherwise obfuscated content using single-pass algorithms.

use crate::Result;

/// Entropy analysis profile with all computed metrics
#[derive(Debug, Clone, serde::Serialize)]
pub struct EntropyProfile {
    /// Global Shannon entropy (0.0-8.0 bits per byte)
    pub global_entropy: f64,
    /// Block-wise entropy values for local analysis
    pub block_entropies: Vec<f64>,
    /// Chi-square statistic for randomness testing
    pub chi_square: f64,
    /// Whether file appears to be packed (high entropy, low chi-square)
    pub is_packed: bool,
    /// Whether file appears to be encrypted (very high entropy, uniform distribution)
    pub is_encrypted: bool,
}

/// Entropy and chi-square statistics computed in a single pass
#[derive(Debug, Clone)]
pub struct EntropyStats {
    /// Shannon entropy value (0.0-8.0 bits per byte)
    pub entropy: f64,
    /// Chi-square statistic for randomness
    pub chi_square: f64,
    /// Byte frequency distribution (256 buckets)
    pub frequency: [usize; 256],
}

/// Calculate both Shannon entropy and chi-square in a single pass
///
/// This is more efficient than calling `calculate_shannon_entropy()` and
/// `chi_square_test()` separately, as it only iterates through the data once.
///
/// # Arguments
/// * `data` - The byte data to analyze
///
/// # Returns
/// `EntropyStats` containing entropy, chi-square, and frequency distribution
pub fn calculate_entropy_stats(data: &[u8]) -> EntropyStats {
    if data.is_empty() {
        return EntropyStats {
            entropy: 0.0,
            chi_square: 0.0,
            frequency: [0; 256],
        };
    }

    // Single pass: build frequency table
    let mut frequency = [0usize; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let expected = len / 256.0;

    // Calculate both entropy and chi-square from the same frequency table
    let mut entropy = 0.0;
    let mut chi_square = 0.0;

    for &count in &frequency {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
        let diff = count as f64 - expected;
        chi_square += (diff * diff) / expected;
    }

    EntropyStats {
        entropy,
        chi_square,
        frequency,
    }
}

/// Calculate Shannon entropy of byte data
///
/// Uses fixed-size array instead of HashMap for better performance.
/// For bulk analysis, prefer `calculate_entropy_stats()` which also
/// provides chi-square in a single pass.
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    calculate_entropy_stats(data).entropy
}

/// Sliding window entropy analysis
///
/// Computes entropy for overlapping windows to detect local variations
/// in randomness (useful for finding encrypted/compressed sections).
pub fn sliding_window_entropy(data: &[u8], window_size: usize) -> Vec<f64> {
    if data.len() < window_size {
        return vec![calculate_shannon_entropy(data)];
    }

    data.windows(window_size)
        .step_by(window_size / 2) // 50% overlap
        .map(calculate_shannon_entropy)
        .collect()
}

/// Chi-square test for randomness
///
/// Lower values indicate more uniform (random-like) distribution.
/// For bulk analysis, prefer `calculate_entropy_stats()` which also
/// provides entropy in a single pass.
pub fn chi_square_test(data: &[u8]) -> f64 {
    calculate_entropy_stats(data).chi_square
}

/// Comprehensive entropy analysis with configurable thresholds
///
/// Uses optimized single-pass calculation for entropy and chi-square.
///
/// # Arguments
/// * `data` - The byte data to analyze
/// * `entropy_threshold` - Minimum entropy for packed detection (default: 7.2)
/// * `packed_chi_square_threshold` - Max chi-square for packed detection (default: 100.0)
/// * `encrypted_entropy_threshold` - Min entropy for encrypted detection (default: 7.8)
/// * `encrypted_chi_square_threshold` - Max chi-square for encrypted detection (default: 50.0)
pub fn analyze_entropy(
    data: &[u8],
    entropy_threshold: f64,
    packed_chi_square_threshold: f64,
    encrypted_entropy_threshold: f64,
    encrypted_chi_square_threshold: f64,
) -> Result<EntropyProfile> {
    // Single-pass calculation for global stats
    let stats = calculate_entropy_stats(data);
    let global_entropy = stats.entropy;
    let chi_square = stats.chi_square;

    // Block-wise analysis for local entropy variations
    let block_entropies = sliding_window_entropy(data, 256);

    // Packed executable detection: high entropy + low chi-square
    let is_packed = global_entropy > entropy_threshold && chi_square < packed_chi_square_threshold;

    // Encryption detection: very high entropy + uniform distribution
    let is_encrypted =
        global_entropy > encrypted_entropy_threshold && chi_square < encrypted_chi_square_threshold;

    Ok(EntropyProfile {
        global_entropy,
        block_entropies,
        chi_square,
        is_packed,
        is_encrypted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // Low entropy: repeated data
        let low_entropy_data = vec![0u8; 1024];
        assert!(calculate_shannon_entropy(&low_entropy_data) < 1.0);

        // High entropy: random-like data
        let high_entropy_data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        assert!(calculate_shannon_entropy(&high_entropy_data) > 7.0);
    }

    #[test]
    fn test_single_pass_entropy_stats() {
        // Test that single-pass calculation matches individual functions
        let data: Vec<u8> = (0..=255).cycle().take(1024).collect();

        let stats = calculate_entropy_stats(&data);
        let individual_entropy = calculate_shannon_entropy(&data);
        let individual_chi = chi_square_test(&data);

        // Results should be identical
        assert!((stats.entropy - individual_entropy).abs() < 0.0001);
        assert!((stats.chi_square - individual_chi).abs() < 0.0001);
    }

    #[test]
    fn test_empty_data() {
        let stats = calculate_entropy_stats(&[]);
        assert_eq!(stats.entropy, 0.0);
        assert_eq!(stats.chi_square, 0.0);
    }

    #[test]
    fn test_chi_square_uniform() {
        // Perfectly uniform distribution should have chi-square near 0
        let uniform: Vec<u8> = (0..=255)
            .flat_map(|b| std::iter::repeat(b).take(4))
            .collect();
        let chi = chi_square_test(&uniform);
        assert!(chi < 1.0, "Uniform distribution should have low chi-square");
    }

    #[test]
    fn test_sliding_window() {
        let data: Vec<u8> = (0..=255).cycle().take(2048).collect();
        let windows = sliding_window_entropy(&data, 256);
        assert!(!windows.is_empty());
        // All windows should have high entropy for uniform distribution
        for w in &windows {
            assert!(*w > 7.0);
        }
    }
}
