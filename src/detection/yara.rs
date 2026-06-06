//! YARA rule scanning (optional `yara` feature).
//!
//! Wraps the pure-Rust [`yara_x`] engine as a [`Detector`] so analysts can run
//! their existing YARA rules as an additional detection stage. A rule match is
//! reported as a [`Dangerous`](crate::ThreatLevel::Dangerous) embedded threat.

use super::detector::Detector;
use super::embedded::EmbeddedThreat;
use crate::{DetectionError, Result, ThreatLevel, ThreatType};
use std::path::Path;

/// A detector backed by a set of compiled YARA rules.
pub struct YaraDetector {
    rules: yara_x::Rules,
}

impl YaraDetector {
    /// Compile YARA rules from source text.
    pub fn from_source(source: &str) -> Result<Self> {
        let rules = yara_x::compile(source).map_err(|e| {
            DetectionError::InvalidConfig(format!("failed to compile YARA rules: {e}"))
        })?;
        Ok(Self { rules })
    }

    /// Compile YARA rules from a file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let source = std::fs::read_to_string(path).map_err(DetectionError::Io)?;
        Self::from_source(&source)
    }
}

impl Detector for YaraDetector {
    fn name(&self) -> &str {
        "yara"
    }

    fn scan(&self, data: &[u8]) -> Vec<EmbeddedThreat> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = match scanner.scan(data) {
            Ok(results) => results,
            Err(_) => return Vec::new(),
        };

        results
            .matching_rules()
            .map(|rule| EmbeddedThreat {
                threat_type: ThreatType::Unknown,
                offset: 0,
                severity: ThreatLevel::Dangerous,
                description: format!("YARA rule matched: {}", rule.identifier()),
            })
            .collect()
    }
}

/// Compile YARA rules from a file and register them as a custom detector.
///
/// After this call, every detection runs the rules as an extra stage.
pub fn register_yara_rules_from_file<P: AsRef<Path>>(path: P) -> Result<()> {
    let detector = YaraDetector::from_file(path)?;
    super::detector::register_detector(Box::new(detector));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = r#"
        rule contains_evil {
            strings:
                $a = "evil"
            condition:
                $a
        }
    "#;

    #[test]
    fn compiles_and_matches() {
        let detector = YaraDetector::from_source(RULE).unwrap();
        let hits = detector.scan(b"there is evil here");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].description.contains("contains_evil"));
    }

    #[test]
    fn no_match_on_clean_data() {
        let detector = YaraDetector::from_source(RULE).unwrap();
        assert!(detector.scan(b"all good").is_empty());
    }

    #[test]
    fn invalid_rule_errors() {
        assert!(YaraDetector::from_source("rule { this is not valid }").is_err());
    }
}
