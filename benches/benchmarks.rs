//! Benchmarks for Batin
//!
//! Run with: cargo bench

use batin::detection::entropy::calculate_shannon_entropy;
use batin::detection::signatures::SignatureDatabase;
use batin::{DetectionConfig, FileType};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// Benchmark entropy calculation with varying data sizes
fn bench_entropy_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy");

    for size in [1024, 4096, 16384, 65536, 262144].iter() {
        let data: Vec<u8> = (0..*size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| calculate_shannon_entropy(black_box(data)))
        });
    }

    group.finish();
}

/// Benchmark signature matching with various file headers
fn bench_signature_matching(c: &mut Criterion) {
    let db = SignatureDatabase::default();
    let mut group = c.benchmark_group("signatures");

    // Test data with known signatures
    let test_cases = vec![
        ("png", vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        ("pdf", b"%PDF-1.4".to_vec()),
        ("zip", vec![0x50, 0x4B, 0x03, 0x04]),
        ("exe", b"MZ".to_vec()),
        ("unknown", vec![0x12, 0x34, 0x56, 0x78]),
    ];

    for (name, header) in test_cases {
        let mut data = header.clone();
        data.resize(1024, 0);

        group.bench_function(name, |b| b.iter(|| db.match_signatures(black_box(&data))));
    }

    group.finish();
}

/// Benchmark full file type detection
fn bench_file_detection(c: &mut Criterion) {
    let config = DetectionConfig::default();
    let mut group = c.benchmark_group("detection");

    // PNG file data
    let mut png_data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    png_data.resize(3072, 0);

    group.bench_function("full_detection", |b| {
        b.iter(|| FileType::from_bytes(black_box(&png_data), &config))
    });

    // With entropy disabled
    let config_no_entropy = DetectionConfig {
        enable_entropy: false,
        ..Default::default()
    };

    group.bench_function("detection_no_entropy", |b| {
        b.iter(|| FileType::from_bytes(black_box(&png_data), &config_no_entropy))
    });

    // With all features disabled
    let config_minimal = DetectionConfig {
        enable_entropy: false,
        enable_polyglot: false,
        enable_embedded: false,
        ..Default::default()
    };

    group.bench_function("detection_minimal", |b| {
        b.iter(|| FileType::from_bytes(black_box(&png_data), &config_minimal))
    });

    group.finish();
}

/// Benchmark signature database operations
fn bench_database_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("database");

    group.bench_function("db_creation", |b| b.iter(|| SignatureDatabase::default()));

    let db = SignatureDatabase::default();

    group.bench_function("zip_format_detection", |b| {
        let zip_data = vec![0x50, 0x4B, 0x03, 0x04];
        b.iter(|| db.detect_zip_format(black_box(&zip_data)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_entropy_calculation,
    bench_signature_matching,
    bench_file_detection,
    bench_database_operations,
);

criterion_main!(benches);
