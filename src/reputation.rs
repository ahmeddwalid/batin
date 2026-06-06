//! Online hash reputation lookups (`online` feature).
//!
//! Queries the VirusTotal v3 API for a file's SHA-256 and summarises the
//! analysis verdicts. This sends the hash to a third party, so it is gated
//! behind the `online` feature and must be invoked explicitly.

use crate::{DetectionError, Result};

/// Summary of analysis verdicts from a reputation provider.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Reputation {
    pub malicious: u64,
    pub suspicious: u64,
    pub harmless: u64,
    pub undetected: u64,
}

impl Reputation {
    /// Whether any engine flagged the sample as malicious or suspicious.
    pub fn is_flagged(&self) -> bool {
        self.malicious > 0 || self.suspicious > 0
    }
}

/// Parse a VirusTotal v3 file report into a [`Reputation`].
///
/// Pure function (no I/O) so it can be unit-tested offline.
pub fn parse_reputation(report: &serde_json::Value) -> Option<Reputation> {
    let stats = report
        .get("data")?
        .get("attributes")?
        .get("last_analysis_stats")?;
    let get = |k: &str| stats.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
    Some(Reputation {
        malicious: get("malicious"),
        suspicious: get("suspicious"),
        harmless: get("harmless"),
        undetected: get("undetected"),
    })
}

/// Look up a SHA-256 on VirusTotal.
///
/// Returns `Ok(None)` if the hash is unknown to VirusTotal (HTTP 404), or
/// `Ok(Some(reputation))` when a report exists. Requires a valid API key.
#[cfg(feature = "online")]
pub fn virustotal_lookup(sha256: &str, api_key: &str) -> Result<Option<Reputation>> {
    let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
    match ureq::get(&url).set("x-apikey", api_key).call() {
        Ok(response) => {
            let body = response
                .into_string()
                .map_err(|e| DetectionError::CorruptedStructure(format!("VT response: {e}")))?;
            let json: serde_json::Value = serde_json::from_str(&body)
                .map_err(|e| DetectionError::CorruptedStructure(format!("VT JSON: {e}")))?;
            Ok(parse_reputation(&json))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(ureq::Error::Status(code, _)) => Err(DetectionError::CorruptedStructure(format!(
            "VirusTotal returned HTTP {code}"
        ))),
        Err(e) => Err(DetectionError::CorruptedStructure(format!(
            "VirusTotal request failed: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_analysis_stats() {
        let report = serde_json::json!({
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 42,
                        "suspicious": 3,
                        "harmless": 0,
                        "undetected": 20
                    }
                }
            }
        });
        let rep = parse_reputation(&report).unwrap();
        assert_eq!(rep.malicious, 42);
        assert_eq!(rep.suspicious, 3);
        assert!(rep.is_flagged());
    }

    #[test]
    fn missing_stats_returns_none() {
        let report = serde_json::json!({ "data": { "attributes": {} } });
        assert!(parse_reputation(&report).is_none());
    }

    #[test]
    fn clean_sample_not_flagged() {
        let report = serde_json::json!({
            "data": { "attributes": { "last_analysis_stats": {
                "malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 5
            }}}
        });
        assert!(!parse_reputation(&report).unwrap().is_flagged());
    }
}
