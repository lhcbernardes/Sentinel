use criterion::{black_box, BenchmarkId, Criterion};
use sentinel_rs::blocking::blocklist::Blocklist;
use std::sync::Arc;

fn bench_blocklist_is_blocked(c: &mut Criterion) {
    let blocklist = Arc::new(Blocklist::new());

    // Pre-populate with test domains
    blocklist.load_default_lists();

    // Add many entries for realistic testing
    for i in 0..10000 {
        blocklist.add_attacker(format!("attacker-{}.evil.com", i));
    }

    let test_domains = vec![
        "google-analytics.com",       // tracker (blocked)
        "nonexistent-domain-xyz.com", // not blocked
        "attacker-5000.evil.com",     // attacker (blocked)
        "malware-domain.com",         // malware (blocked)
    ];

    let mut group = c.benchmark_group("blocklist_is_blocked");

    for domain in test_domains {
        group.bench_function(BenchmarkId::new("blocked", domain), |b| {
            b.iter(|| {
                blocklist.is_blocked(black_box(domain));
            });
        });

        group.bench_function(BenchmarkId::new("not_blocked", domain), |b| {
            b.iter(|| {
                blocklist.is_blocked(black_box(domain));
            });
        });
    }

    group.finish();
}

fn bench_blocklist_creation(c: &mut Criterion) {
    c.bench_function("blocklist_new", |b| {
        b.iter(|| {
            let _ = Blocklist::new();
        });
    });
}

fn bench_blocklist_stats(c: &mut Criterion) {
    let blocklist = Arc::new(Blocklist::new());
    blocklist.load_default_lists();

    c.bench_function("blocklist_stats", |b| {
        b.iter(|| {
            black_box(blocklist.stats());
        });
    });
}

criterion::criterion_group!(
    benches,
    bench_blocklist_is_blocked,
    bench_blocklist_creation,
    bench_blocklist_stats
);
criterion::criterion_main!(benches);
