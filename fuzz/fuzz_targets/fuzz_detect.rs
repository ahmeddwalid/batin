#![no_main]
use batin::{DetectionConfig, FileType};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let config = DetectionConfig::default();

    // This should NEVER panic, even with malformed input
    let _ = FileType::from_bytes(data, &config);
});
