// This program spins in a busy loop, calling `parse_message` on a static bit of
// text. This is done to interrogate the performance of `parse_message` with
// tools like [flamegraph](https://github.com/flamegraph-rs/flamegraph).
use syslog_loose::{Message, Variant};

fn main() {
    let log: &str = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource= \"Application\" eventID=\"1011\"] BOMAn application event log entry...";

    loop {
        let _: Message<&str> = syslog_loose::parse_message(log, Variant::Either);
    }
}
