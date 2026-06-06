//! C ABI bindings for Batin.
//!
//! This crate exposes a minimal C-callable surface over the synchronous
//! detection core. It is a separate crate because the FFI boundary requires
//! `unsafe`, which the core library forbids (`#![forbid(unsafe_code)]`).
//!
//! See `include/batin.h` for the C declarations.

use batin::{DetectionConfig, FileType};
use std::ffi::{c_char, CString};

/// Detect the file type of a byte buffer and return a JSON description.
///
/// # Safety
/// `data` must point to at least `len` readable bytes (or be null with len 0).
/// The returned pointer is a heap-allocated, NUL-terminated UTF-8 string that
/// the caller must release with [`batin_free_string`]. Returns null on
/// allocation failure.
#[no_mangle]
pub unsafe extern "C" fn batin_detect_json(data: *const u8, len: usize) -> *mut c_char {
    let bytes: &[u8] = if data.is_null() || len == 0 {
        &[]
    } else {
        // SAFETY: caller guarantees `data`..`data+len` is valid for reads.
        std::slice::from_raw_parts(data, len)
    };

    let config = DetectionConfig::default();
    let json = match FileType::from_bytes(bytes, &config) {
        Ok(ft) => serde_json::to_string(&ft).unwrap_or_else(|_| "null".to_string()),
        Err(e) => serde_json::json!({ "error": e.to_string() }).to_string(),
    };

    match CString::new(json) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a string previously returned by [`batin_detect_json`].
///
/// # Safety
/// `ptr` must be a pointer returned by [`batin_detect_json`], or null. Passing
/// any other pointer, or freeing twice, is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn batin_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // SAFETY: reconstructs the CString we leaked with into_raw.
        drop(CString::from_raw(ptr));
    }
}

/// Return the library version as a static, NUL-terminated C string.
#[no_mangle]
pub extern "C" fn batin_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_and_free_roundtrip() {
        let png: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13];
        // SAFETY: valid buffer, and we free the returned pointer.
        let ptr = unsafe { batin_detect_json(png.as_ptr(), png.len()) };
        assert!(!ptr.is_null());
        let json = unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_str()
            .unwrap()
            .to_string();
        assert!(json.contains("\"extension\":\"png\""));
        unsafe { batin_free_string(ptr) };
    }

    #[test]
    fn null_input_is_safe() {
        let ptr = unsafe { batin_detect_json(std::ptr::null(), 0) };
        // Empty input is unknown format -> error JSON, still a valid string.
        assert!(!ptr.is_null());
        unsafe { batin_free_string(ptr) };
    }

    #[test]
    fn version_is_nul_terminated() {
        let p = batin_version();
        let s = unsafe { std::ffi::CStr::from_ptr(p) }.to_str().unwrap();
        assert!(!s.is_empty());
    }
}
