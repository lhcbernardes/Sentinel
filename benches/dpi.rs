use base64::{engine::general_purpose::STANDARD, Engine};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sentinel_rs::sniffer::dpi::DpiEngine;

fn bench_dpi_inspection(c: &mut Criterion) {
    let engine = DpiEngine::new();

    // Test payloads - base64 encoded sample data
    let payloads = vec![
        ("http", "SFRUUC8xLjEgMjAwIE9LDQoNCg=="), // "HTTP/1.1 200 OK"
        (
            "tls",
            "BAoICgAEAAAAAgAAAAIAAAAAgAAABgAAAAFgAAAC4AAAABAC4AAAADAAQAAQAAAAEAAgAAAAEAAA==",
        ), // TLS ClientHello
        (
            "dns",
            "AAABAAABAAAAAAAAA3d3dwV3YW5haWRnYW1lLmNvbQAAABYBAAAB",
        ), // DNS query
        ("ssh", "U1NILTIuMC1Vc2VuY3J5cHRlZC1yY3QAAAAA"), // SSH banner
        ("empty", ""),
        (
            "random",
            "aW5jb3JyaWR0IGxvcmVtIGlzIHNpbXBsZSBhbmQgc29tZXRpbWVzIHVzZWZ1bA==",
        ), // "incorrect lorem ipsum"
    ];

    let mut group = c.benchmark_group("dpi_inspection");

    for (protocol, payload) in payloads {
        group.bench_with_input(
            BenchmarkId::new("inspect", protocol),
            payload,
            |b, payload| {
                b.iter(|| {
                    engine.inspect(black_box(payload), black_box(protocol));
                });
            },
        );
    }

    group.finish();
}

fn bench_dpi_pii_detection(c: &mut Criterion) {
    let engine = DpiEngine::new();

    let test_cases = vec![
        ("email_only", "Contact: user@example.com"),
        ("phone_only", "Phone: 555-123-4567"),
        ("cpf_only", "ID: 123.456.789-00"),
        (
            "all_pii",
            "user@test.com, phone: 555.123.4567, ID: 123.456.789-00",
        ),
        (
            "no_pii",
            "This is a normal text message with no sensitive data",
        ),
    ];

    let mut group = c.benchmark_group("dpi_pii_detection");

    for (name, data) in test_cases {
        let encoded = STANDARD.encode(data);
        group.bench_function(BenchmarkId::new("inspect", name), |b| {
            b.iter(|| {
                engine.inspect(black_box(&encoded), black_box("test"));
            });
        });
    }

    group.finish();
}

fn bench_dpi_sensitive_data(c: &mut Criterion) {
    let engine = DpiEngine::new();

    let test_cases = vec![
        ("credit_card", "Card: 4111-1111-1111-1111"),
        ("ssn", "SSN: 123-45-6789"),
        ("password", "password=supersecret123"),
        ("api_key", "api_key=abc123def456ghi789jkl012"),
        (
            "mixed",
            "api_key=xxx, password=yyy, card=4111 1111 1111 1111",
        ),
        ("clean", "This message contains no sensitive data"),
    ];

    let mut group = c.benchmark_group("dpi_sensitive_data");

    for (name, data) in test_cases {
        let encoded = STANDARD.encode(data);
        group.bench_function(BenchmarkId::new("inspect", name), |b| {
            b.iter(|| {
                engine.inspect(black_box(&encoded), black_box("test"));
            });
        });
    }

    group.finish();
}

fn bench_dpi_engine_creation(c: &mut Criterion) {
    c.bench_function("dpi_engine_new", |b| {
        b.iter(|| {
            let _ = DpiEngine::new();
        });
    });
}

criterion_group!(
    benches,
    bench_dpi_inspection,
    bench_dpi_pii_detection,
    bench_dpi_sensitive_data,
    bench_dpi_engine_creation
);
criterion_main!(benches);
