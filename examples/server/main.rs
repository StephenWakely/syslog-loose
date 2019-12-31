extern crate syslog_loose;

use std::net::UdpSocket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("127.0.0.1:9000")?;
    println!("Listening on port 9000...");
    let mut buf = [0u8; 2048];
    loop {
        let (data_read, _) = socket.recv_from(&mut buf)?;
        let line = std::str::from_utf8(&buf[0..data_read])?;
        match syslog_loose::parse_message(&line) {
            Ok(msg) => println!("{:#?}", msg),
            Err(err) => println!("ERROR : {}", err),
        }
    }
}
