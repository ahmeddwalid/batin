//! WebAssembly bindings for Batin's synchronous detection core.
//!
//! Builds for `wasm32-unknown-unknown` because it depends on `batin` with
//! default features disabled, leaving out tokio/rayon. Build with
//! `wasm-pack build` or `cargo build --target wasm32-unknown-unknown`.

use batin::{DetectionConfig, FileType};
use wasm_bindgen::prelude::*;

/// Detect the file type of a byte buffer, returning a JSON string.
///
/// Throws (rejects) with the error message if detection fails.
#[wasm_bindgen]
pub fn detect_json(data: &[u8]) -> Result<String, JsValue> {
    let config = DetectionConfig::default();
    let file_type =
        FileType::from_bytes(data, &config).map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string(&file_type).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Return the bindings crate version.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_png_on_host() {
        let png: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13];
        let json = detect_json(png).unwrap();
        assert!(json.contains("\"extension\":\"png\""));
    }
}
