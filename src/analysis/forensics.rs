//! File fragment classification for forensics

use crate::detection::entropy::calculate_shannon_entropy;
use crate::{DetectionError, Result};

#[derive(Debug, Clone)]
pub struct FragmentClassification {
    pub likely_type: String,
    pub confidence: f64,
    pub entropy: f64,
}

/// Classify file fragments using entropy profiling
pub fn classify_fragment(fragment: &[u8]) -> Result<FragmentClassification> {
    if fragment.len() < 512 {
        return Err(DetectionError::CorruptedStructure(
            "Fragment too small for analysis".to_string(),
        ));
    }

    let entropy = calculate_shannon_entropy(fragment);

    let (likely_type, confidence) = match entropy {
        e if e < 3.0 => ("binary_zeros", 0.9),
        e if e >= 3.0 && e < 5.0 => ("text", 0.7),
        e if e >= 5.0 && e < 6.5 => ("native_code", 0.6),
        e if e >= 6.5 && e < 7.5 => ("compressed", 0.7),
        _ => ("encrypted", 0.8),
    };

    Ok(FragmentClassification {
        likely_type: likely_type.to_string(),
        confidence,
        entropy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_classification() {
        // Text-like fragment
        let text_fragment = b"This is a test text fragment with readable ASCII content ".repeat(10);
        let classification = classify_fragment(&text_fragment).unwrap();
        assert_eq!(classification.likely_type, "text");

        // High entropy fragment (compressed/encrypted)
        let high_entropy: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let classification = classify_fragment(&high_entropy).unwrap();
        assert!(classification.entropy > 7.0);
    }
}
