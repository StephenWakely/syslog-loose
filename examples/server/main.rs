extern crate syslog_loose;

use chrono::prelude::*;
use std::net::UdpSocket;
use syslog_loose::Variant;

fn resolve_year((month, _date, _hour, _min, _sec): syslog_loose::IncompleteDate) -> i32 {
    let now = Utc::now();
    if now.month() == 1 && month == 12 {
        now.year() - 1
    } else {
        now.year()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("127.0.0.1:9000")?;
    println!("Listening on port 9000...");
    let mut buf = [0u8; 2048];
    loop {
        let (data_read, _) = socket.recv_from(&mut buf)?;
        let line = std::str::from_utf8(&buf[0..data_read])?;
        println!("{}", line);
        println!(
            "{:#?}",
            syslog_loose::parse_message_with_year(line, resolve_year, Variant::Either)
        );
    }
}
