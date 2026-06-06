#![no_main]
use batin::parse_binary;
use libfuzzer_sys::fuzz_target;

// PE/ELF/Mach-O parsing must never panic on malformed binaries.
fuzz_target!(|data: &[u8]| {
    let _ = parse_binary(data);
});
