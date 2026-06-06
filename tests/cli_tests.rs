//! CLI integration tests for the `batin` binary.
//!
//! These exercise argument parsing, output formats, filtering, and archive
//! recursion end-to-end by invoking the compiled binary. They only run when the
//! `cli` feature (and thus the binary) is built.
#![cfg(feature = "cli")]

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::io::Write;
use tempfile::TempDir;

const PNG_MAGIC: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

fn batin() -> Command {
    Command::cargo_bin("batin").expect("binary builds")
}

/// Write a minimal PNG file into `dir` and return its path.
fn write_png(dir: &TempDir, name: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut data = PNG_MAGIC.to_vec();
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D]);
    data.extend_from_slice(b"IHDR");
    data.extend_from_slice(&[0u8; 64]);
    fs::write(&path, data).unwrap();
    path
}

#[test]
fn scan_png_table_output() {
    let dir = TempDir::new().unwrap();
    let path = write_png(&dir, "image.png");

    batin()
        .arg("scan")
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("png"));
}

#[test]
fn scan_json_output_is_valid() {
    let dir = TempDir::new().unwrap();
    let path = write_png(&dir, "image.png");

    let output = batin()
        .arg("scan")
        .arg(&path)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    let arr = parsed.as_array().expect("array of results");
    assert_eq!(arr[0]["file_type"]["extension"], "png");
}

#[test]
fn scan_csv_output_has_header() {
    let dir = TempDir::new().unwrap();
    let path = write_png(&dir, "image.png");

    batin()
        .arg("scan")
        .arg(&path)
        .arg("--csv")
        .assert()
        .success()
        .stdout(predicate::str::contains("Path,Type,MIME"));
}

#[test]
fn min_threat_filters_out_safe_files() {
    let dir = TempDir::new().unwrap();
    write_png(&dir, "image.png");

    let output = batin()
        .arg("scan")
        .arg(dir.path())
        .arg("--json")
        .arg("--min-threat")
        .arg("dangerous")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 0);
}

#[test]
fn exclude_glob_skips_matching_files() {
    let dir = TempDir::new().unwrap();
    write_png(&dir, "keep.png");
    write_png(&dir, "skip.png");

    let output = batin()
        .arg("scan")
        .arg(dir.path())
        .arg("--json")
        .arg("--exclude")
        .arg("*skip*")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let paths: Vec<String> = parsed
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["path"].as_str().unwrap().to_string())
        .collect();
    assert!(paths.iter().any(|p| p.contains("keep.png")));
    assert!(!paths.iter().any(|p| p.contains("skip.png")));
}

#[test]
fn output_flag_writes_file() {
    let dir = TempDir::new().unwrap();
    let path = write_png(&dir, "image.png");
    let out = dir.path().join("report.json");

    batin()
        .arg("scan")
        .arg(&path)
        .arg("--json")
        .arg("-o")
        .arg(&out)
        .assert()
        .success();

    let written = fs::read_to_string(&out).unwrap();
    assert!(written.contains("\"extension\""));
}

#[test]
fn scan_archives_reports_nested_entries() {
    let dir = TempDir::new().unwrap();
    let zip_path = dir.path().join("bundle.zip");

    // Build a ZIP containing a PNG.
    let file = fs::File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("inner.png", zip::write::FileOptions::default())
        .unwrap();
    let mut png = PNG_MAGIC.to_vec();
    png.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D]);
    png.extend_from_slice(b"IHDR");
    zip.write_all(&png).unwrap();
    zip.finish().unwrap();

    let output = batin()
        .arg("scan")
        .arg(&zip_path)
        .arg("--scan-archives")
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let paths: Vec<String> = parsed
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["path"].as_str().unwrap().to_string())
        .collect();
    assert!(
        paths.iter().any(|p| p.contains("inner.png")),
        "expected nested inner.png entry, got: {paths:?}"
    );
}

#[test]
fn sarif_format_is_valid() {
    let dir = TempDir::new().unwrap();
    let path = write_png(&dir, "image.png");

    let output = batin()
        .arg("scan")
        .arg(&path)
        .arg("--format")
        .arg("sarif")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).expect("valid SARIF JSON");
    assert_eq!(parsed["version"], "2.1.0");
    assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "batin");
}

#[test]
fn ndjson_format_one_object_per_line() {
    let dir = TempDir::new().unwrap();
    write_png(&dir, "a.png");
    write_png(&dir, "b.png");

    let output = batin()
        .arg("scan")
        .arg(dir.path())
        .arg("--format")
        .arg("ndjson")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(output).unwrap();
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2);
    for line in lines {
        let _: serde_json::Value = serde_json::from_str(line).expect("each line is valid JSON");
    }
}

#[test]
fn html_format_is_self_contained() {
    let dir = TempDir::new().unwrap();
    let path = write_png(&dir, "image.png");

    batin()
        .arg("scan")
        .arg(&path)
        .arg("--format")
        .arg("html")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("<!DOCTYPE html>").and(predicate::str::contains("image.png")),
        );
}

#[test]
fn hash_deny_flags_critical() {
    let dir = TempDir::new().unwrap();
    let path = write_png(&dir, "image.png");

    // Compute the file's SHA-256 and put it in a denylist.
    let data = fs::read(&path).unwrap();
    use sha2::{Digest, Sha256};
    let sha = format!("{:x}", Sha256::digest(&data));
    let deny = dir.path().join("deny.txt");
    fs::write(&deny, format!("# bad hashes\n{sha}\n")).unwrap();

    let output = batin()
        .arg("scan")
        .arg(&path)
        .arg("--hash-deny")
        .arg(&deny)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(parsed[0]["file_type"]["threat_level"], "Critical");
}

#[test]
fn completions_generate() {
    batin()
        .arg("completions")
        .arg("bash")
        .assert()
        .success()
        .stdout(predicate::str::contains("_batin"));
}

#[test]
fn man_page_generates() {
    batin()
        .arg("man")
        .assert()
        .success()
        .stdout(predicate::str::contains("batin"));
}

#[test]
fn no_input_exits_with_error() {
    batin()
        .assert()
        .failure()
        .stderr(predicate::str::contains("No input"));
}

#[test]
fn hash_flag_includes_hashes() {
    let dir = TempDir::new().unwrap();
    let path = write_png(&dir, "image.png");

    let output = batin()
        .arg("scan")
        .arg(&path)
        .arg("--hash")
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let hashes = &parsed.as_array().unwrap()[0]["file_type"]["hashes"];
    assert!(hashes["sha256"].is_string());
}
