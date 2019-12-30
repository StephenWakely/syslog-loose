///! The parsed Header struct.
///! RFC 3164 contains only a subset of these fields. 5424 can theoretically hold all fields.
use chrono::{DateTime, FixedOffset};

#[derive(Debug, PartialEq, Eq)]
pub struct Header<'a> {
    pub pri: u8,
    pub version: Option<u32>,
    pub timestamp: Option<DateTime<FixedOffset>>,
    pub hostname: Option<&'a str>,
    pub appname: Option<&'a str>,
    pub procid: Option<&'a str>,
    pub msgid: Option<&'a str>,
}

