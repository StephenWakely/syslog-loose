#[macro_use]
extern crate criterion;

use criterion::{BenchmarkId, Criterion, Throughput};
use criterion_cycles_per_byte::CyclesPerByte;
use std::convert::TryInto;
use std::include_str;
use syslog_loose::Variant;

struct Parameter<'a> {
    line: &'a str,
    name: &'a str,
}

static PARAMETERS: [Parameter; 4] = [
    Parameter {
        line: include_str!("rfc5424/with_structured_data.txt"),
        name: "with_structured_data",
    },
    Parameter {
        line: include_str!("rfc5424/with_structured_data_long_msg.txt"),
        name: "with_structured_data_long_message",
    },
    Parameter {
        line: include_str!("rfc5424/without_structured_data_long_msg.txt"),
        name: "with_structured_data_long_message",
    },
    Parameter {
        line: include_str!("rfc5424/without_structured_data.txt"),
        name: "without_structured_data",
    },
];

static RFC3164_PARAMETERS: [Parameter; 4] = [
    Parameter {
        line: include_str!("rfc3164/simple.txt"),
        name: "simple",
    },
    Parameter {
        line: include_str!("rfc3164/long_msg.txt"),
        name: "long_msg",
    },
    Parameter {
        line: include_str!("rfc3164/with_structured_data.txt"),
        name: "with_structured_data",
    },
    Parameter {
        line: include_str!("rfc3164/rfc3339_timestamp.txt"),
        name: "rfc3339_timestamp",
    },
];

fn parse_bench_rfc5424(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("RFC5424");
    for param in &PARAMETERS {
        let name = param.name;
        let line = param.line;
        let bytes = param.line.len().try_into().unwrap();

        group.throughput(Throughput::Bytes(bytes));
        group.bench_with_input(BenchmarkId::new(name, bytes), line, |b, line| {
            b.iter(|| syslog_loose::parse_message(line, Variant::Either))
        });
    }
    group.finish();
}

fn parse_bench_rfc3164(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("RFC3164");
    for param in &RFC3164_PARAMETERS {
        let name = param.name;
        let line = param.line;
        let bytes = param.line.len().try_into().unwrap();

        group.throughput(Throughput::Bytes(bytes));
        group.bench_with_input(BenchmarkId::new(name, bytes), line, |b, line| {
            b.iter(|| syslog_loose::parse_message(line, Variant::Either))
        });
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = parse_bench_rfc5424, parse_bench_rfc3164
);
criterion_main!(benches);
