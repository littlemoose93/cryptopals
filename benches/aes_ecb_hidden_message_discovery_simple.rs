use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cryptopals::set_2::find_hidden_message_simple;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("aes_ecb_hidden_message_discovery_simple", |b| {
        b.iter(|| find_hidden_message_simple(black_box(8)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
