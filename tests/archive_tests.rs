//! Archive-scanning integration tests with real ZIP/TAR/gzip fixtures.
#![cfg(feature = "archive")]

use batin::archive::{scan_archive, scan_archive_with_config, ArchiveConfig};
use batin::DetectionConfig;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, b'I', b'H', b'D', b'R',
];
const MZ_EXE: &[u8] = &[0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];

fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data) in files {
        zip.start_file(*name, zip::write::FileOptions::default())
            .unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn make_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, data) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append_data(&mut header, name, *data).unwrap();
    }
    builder.into_inner().unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn scans_zip_entries() {
    let zip = make_zip(&[("photo.png", PNG)]);
    let entries = scan_archive(&zip, 3, &DetectionConfig::default()).unwrap();
    let png = entries.iter().find(|e| e.path == "photo.png").unwrap();
    assert_eq!(png.file_type.as_ref().unwrap().extension, "png");
}

#[test]
fn recurses_into_nested_zip() {
    let inner = make_zip(&[("photo.png", PNG)]);
    let outer = make_zip(&[("nested.zip", &inner)]);

    let entries = scan_archive(&outer, 5, &DetectionConfig::default()).unwrap();
    assert!(
        entries.iter().any(|e| e.path == "nested.zip/photo.png"),
        "expected recursion into nested zip, got: {:?}",
        entries.iter().map(|e| &e.path).collect::<Vec<_>>()
    );
}

#[test]
fn scans_tar_gz_with_embedded_executable() {
    let tar = make_tar(&[("payload.bin", MZ_EXE)]);
    let targz = gzip(&tar);

    let entries = scan_archive(&targz, 5, &DetectionConfig::default()).unwrap();
    let exe = entries
        .iter()
        .find(|e| e.path.contains("payload.bin"))
        .expect("payload.bin found inside tar.gz");
    assert_eq!(exe.file_type.as_ref().unwrap().extension, "exe");
}

#[test]
fn recurses_zip_inside_tar() {
    let inner_zip = make_zip(&[("photo.png", PNG)]);
    let tar = make_tar(&[("archive.zip", &inner_zip)]);

    let entries = scan_archive(&tar, 5, &DetectionConfig::default()).unwrap();
    assert!(
        entries.iter().any(|e| e.path == "archive.zip/photo.png"),
        "expected zip-in-tar recursion, got: {:?}",
        entries.iter().map(|e| &e.path).collect::<Vec<_>>()
    );
}

#[test]
fn depth_limit_stops_recursion() {
    let inner = make_zip(&[("photo.png", PNG)]);
    let outer = make_zip(&[("nested.zip", &inner)]);

    // Depth 1 processes only the outer container; the nested zip is not entered.
    let entries = scan_archive(&outer, 1, &DetectionConfig::default()).unwrap();
    assert!(entries.iter().any(|e| e.path == "nested.zip"));
    assert!(!entries.iter().any(|e| e.path.contains("photo.png")));
}

#[test]
fn per_file_size_limit_skips_large_entries() {
    let big = vec![0u8; 4096];
    let zip = make_zip(&[("big.bin", &big), ("small.png", PNG)]);

    let ac = ArchiveConfig {
        max_extracted_file_size: 1024,
        ..Default::default()
    };
    let entries = scan_archive_with_config(&zip, 3, &DetectionConfig::default(), &ac).unwrap();

    let big_entry = entries.iter().find(|e| e.path == "big.bin").unwrap();
    assert!(big_entry.skipped, "large entry should be skipped");
    assert!(big_entry.file_type.is_none());
}

#[test]
fn entry_count_limit_is_respected() {
    let files: Vec<(String, Vec<u8>)> = (0..10)
        .map(|i| (format!("f{i}.png"), PNG.to_vec()))
        .collect();
    let refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let zip = make_zip(&refs);

    let ac = ArchiveConfig {
        max_entries: 3,
        ..Default::default()
    };
    let entries = scan_archive_with_config(&zip, 3, &DetectionConfig::default(), &ac).unwrap();
    assert_eq!(entries.len(), 3);
}
