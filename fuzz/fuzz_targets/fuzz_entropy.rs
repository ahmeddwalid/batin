#![no_main]
use batin::detection::entropy::analyze_entropy;
use libfuzzer_sys::fuzz_target;

// Entropy analysis must never panic, including on empty or adversarial input.
fuzz_target!(|data: &[u8]| {
    let _ = analyze_entropy(data, 7.2, 100.0, 7.8, 50.0);
});
