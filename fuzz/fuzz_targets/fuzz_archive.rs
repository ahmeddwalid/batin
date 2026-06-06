#![no_main]
use batin::{archive, DetectionConfig};
use libfuzzer_sys::fuzz_target;

// Archive scanning must never panic on malformed ZIP/TAR/gzip input.
fuzz_target!(|data: &[u8]| {
    let config = DetectionConfig::default();
    let _ = archive::scan_archive(data, 3, &config);
});
