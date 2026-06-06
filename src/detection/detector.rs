//! Pluggable detector stages.
//!
//! A [`Detector`] is a composable analysis stage that inspects raw bytes and
//! contributes [`EmbeddedThreat`]s. Built-in stages (signatures, entropy,
//! polyglot, embedded) remain in the core pipeline; this registry lets third
//! parties add extra stages (e.g. a YARA scanner) without forking.
//!
//! Registered detectors run during [`crate::FileType::from_bytes`] after the
//! built-in embedded scan, and their findings can escalate the threat level.

use super::embedded::EmbeddedThreat;
use std::sync::{LazyLock, RwLock};

/// A custom detection stage operating on the (bounded) file bytes.
pub trait Detector: Send + Sync {
    /// Human-readable name, used in diagnostics.
    fn name(&self) -> &str;

    /// Inspect `data` and return any threats found.
    fn scan(&self, data: &[u8]) -> Vec<EmbeddedThreat>;
}

static CUSTOM_DETECTORS: LazyLock<RwLock<Vec<Box<dyn Detector>>>> =
    LazyLock::new(|| RwLock::new(Vec::new()));

/// Register a custom detector. It will run on every subsequent detection.
pub fn register_detector(detector: Box<dyn Detector>) {
    if let Ok(mut detectors) = CUSTOM_DETECTORS.write() {
        detectors.push(detector);
    }
}

/// Number of currently registered custom detectors.
pub fn detector_count() -> usize {
    CUSTOM_DETECTORS.read().map(|d| d.len()).unwrap_or(0)
}

/// Run all registered custom detectors and collect their findings.
pub(crate) fn run_custom_detectors(data: &[u8]) -> Vec<EmbeddedThreat> {
    let mut findings = Vec::new();
    if let Ok(detectors) = CUSTOM_DETECTORS.read() {
        for detector in detectors.iter() {
            findings.extend(detector.scan(data));
        }
    }
    findings
}

/// Remove all registered detectors (test isolation helper).
#[cfg(test)]
pub fn clear_detectors() {
    if let Ok(mut detectors) = CUSTOM_DETECTORS.write() {
        detectors.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ThreatLevel;

    struct AlwaysFlag;
    impl Detector for AlwaysFlag {
        fn name(&self) -> &str {
            "always-flag"
        }
        fn scan(&self, _data: &[u8]) -> Vec<EmbeddedThreat> {
            vec![EmbeddedThreat {
                threat_type: crate::detection::ThreatType::Unknown,
                offset: 0,
                severity: ThreatLevel::Critical,
                description: "test detector".to_string(),
            }]
        }
    }

    #[test]
    fn register_and_run_detector() {
        clear_detectors();
        assert_eq!(detector_count(), 0);
        register_detector(Box::new(AlwaysFlag));
        assert_eq!(detector_count(), 1);
        let findings = run_custom_detectors(b"anything");
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, ThreatLevel::Critical));
        clear_detectors();
    }
}
