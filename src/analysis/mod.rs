//! Analysis module
//!
//! File structure analysis and validation.
//!
//! - `pe_parser` - PE/ELF binary parsing
//! - `validation` - Content structure validation
//! - `forensics` - File fragment classification

pub mod forensics;
pub mod pe_parser;
pub mod validation;

// Re-exports
pub use forensics::classify_fragment;
#[cfg(feature = "binary-parsing")]
pub use pe_parser::parse_binary;
pub use pe_parser::{BinaryFormat, BinaryMetadata, Section};
pub use validation::{validate_pdf, validate_pe, validate_png, validate_zip, ValidationResult};
