#[macro_use]
extern crate criterion;

use criterion::{Criterion, Throughput};
use std::convert::TryInto;

fn parse_bench_compare(c: &mut Criterion) {
    let log = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource= \"Application\" eventID=\"1011\"] BOMAn application event log entry...";
    let mut group = c.benchmark_group("RFC5424");

    group.throughput(Throughput::Bytes(log.len().try_into().unwrap()));
    group.bench_function("Original", |b| {
        b.iter(|| syslog_rfc5424::parser::parse_message(log))
    });
    group.bench_function("New", |b| b.iter(|| syslog_loose::parse_message(log)));
    group.finish();
}

criterion_group!(benches, parse_bench_compare);
criterion_main!(benches);
