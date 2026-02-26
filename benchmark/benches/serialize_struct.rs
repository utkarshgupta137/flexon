use benchmark::*;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::{fs::read_to_string, time::Duration};

macro_rules! bench {
    ($($name:ident: $type:ident),* $(,)?) => {
        $(
            fn $name(c: &mut Criterion) {
                let path = format!("data/{}.json", stringify!($name));
                let src = read_to_string(&path).unwrap();
                let val = flexon::from_str::<$type>(&src).unwrap();
                let mut group = c.benchmark_group(stringify!($name));

                group.throughput(Throughput::Bytes(src.len() as _));
                group.measurement_time(Duration::from_secs(20));

                group.bench_function("flexon::to_string", |b| {
                    b.iter(|| flexon::to_string(&val).unwrap())
                });

                group.bench_function("sonic_rs::to_string", |b| {
                    b.iter(|| sonic_rs::to_string(&val).unwrap())
                });

                group.bench_function("serde_json::to_string", |b| {
                    b.iter(|| serde_json::to_string(&val).unwrap())
                });

                group.bench_function("simd_json::to_string", |b| {
                    b.iter(|| simd_json::to_string(&val).unwrap())
                });
            }
        )*

        criterion_group!(benches, $($name),*);
    }
}

bench! {
    twitter: Twitter,
    citm_catalog: CitmCatalog,
    canada: Canada,
    // github_events: GithubEvents,
}

criterion_main!(benches);
