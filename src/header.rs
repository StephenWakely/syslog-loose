///! The parsed Header struct.
///! RFC 3164 contains only a subset of these fields. 5424 can theoretically hold all fields.
use chrono::{DateTime, FixedOffset};
use crate::pri::{SyslogFacility, SyslogSeverity};

#[derive(Debug, PartialEq, Eq)]
pub struct Header<'a> {
    pub facility: Option<SyslogFacility>,
    pub severity: Option<SyslogSeverity>,
    pub version: Option<u32>,
    pub timestamp: Option<DateTime<FixedOffset>>,
    pub hostname: Option<&'a str>,
    pub appname: Option<&'a str>,
    pub procid: Option<&'a str>,
    pub msgid: Option<&'a str>,
}

impl<'a> Header<'a> {
    /// Create an empty header
    pub fn new() -> Self {
        Header {
            facility: None,
            severity: None,
            version: None,
            timestamp: None,
            hostname: None,
            appname: None,
            procid: None,
            msgid:  None,
        }
    }
}

