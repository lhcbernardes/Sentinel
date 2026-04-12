use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sentinel_rs::anomaly::ransomware::RansomwareDetector;

fn bench_entropy_calculation(c: &mut Criterion) {
    // Random encrypted data
    let encrypted_data: Vec<u8> = (0..4096).map(|_| rand::random::<u8>()).collect();

    // Compressible pattern data
    let pattern_data: Vec<u8> = (0..4096).flat_map(|i| vec![i as u8; 16]).collect();

    // Zero data
    let zero_data = vec![0u8; 4096];

    let mut group = c.benchmark_group("entropy_calculation");

    group.bench_function("random_encrypted_4k", |b| {
        b.iter(|| {
            RansomwareDetector::calculate_entropy(black_box(&encrypted_data));
        });
    });

    group.bench_function("pattern_compressible_4k", |b| {
        b.iter(|| {
            RansomwareDetector::calculate_entropy(black_box(&pattern_data));
        });
    });

    group.bench_function("zero_data_4k", |b| {
        b.iter(|| {
            RansomwareDetector::calculate_entropy(black_box(&zero_data));
        });
    });

    // Smaller data
    let small_data: Vec<u8> = (0..256).map(|_| rand::random::<u8>()).collect();
    group.bench_function("random_encrypted_256b", |b| {
        b.iter(|| {
            RansomwareDetector::calculate_entropy(black_box(&small_data));
        });
    });

    group.finish();
}

fn bench_encryption_detection(c: &mut Criterion) {
    let encrypted_data: Vec<u8> = (0..2048).map(|_| rand::random::<u8>()).collect();
    let normal_data: Vec<u8> = (0..2048).map(|i| i as u8).collect();

    let mut group = c.benchmark_group("encryption_detection");

    group.bench_function("encrypted_data", |b| {
        b.iter(|| {
            RansomwareDetector::detect_encryption_pattern(black_box(&encrypted_data));
        });
    });

    group.bench_function("normal_data", |b| {
        b.iter(|| {
            RansomwareDetector::detect_encryption_pattern(black_box(&normal_data));
        });
    });

    group.finish();
}

fn bench_extension_check(c: &mut Criterion) {
    let suspicious = "document.encrypted.locked";
    let normal = "document.pdf";
    let ransomware_note = "README_FOR_DECRYPT.txt";

    let mut group = c.benchmark_group("extension_check");

    group.bench_function("suspicious", |b| {
        b.iter(|| {
            RansomwareDetector::check_extension(black_box(suspicious));
        });
    });

    group.bench_function("normal", |b| {
        b.iter(|| {
            RansomwareDetector::check_extension(black_box(normal));
        });
    });

    group.bench_function("ransomware_note", |b| {
        b.iter(|| {
            RansomwareDetector::check_extension(black_box(ransomware_note));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_entropy_calculation,
    bench_encryption_detection,
    bench_extension_check
);
criterion_main!(benches);
