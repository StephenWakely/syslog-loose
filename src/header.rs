///! The parsed Header struct.
///! RFC 3164 contains only a subset of these fields. 5424 can theoretically hold all fields.
use chrono::{DateTime, FixedOffset};
use crate::pri::{SyslogFacility, SyslogSeverity, compose_pri};
use std::fmt;

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

impl<'a> fmt::Display for Header<'a>{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>{} {} {} {} {} {}", 
               compose_pri(self.facility.unwrap_or(SyslogFacility::LOG_KERN), 
                           self.severity.unwrap_or(SyslogSeverity::SEV_EMERG)),
               self.version.map(|v| v.to_string()).unwrap_or("".to_string()),
               self.timestamp.map(|t| t.to_rfc3339()).unwrap_or("-".to_string()),
               self.hostname.unwrap_or("-"),
               self.appname.unwrap_or("-"),
               self.procid.unwrap_or("-"),
               self.msgid.unwrap_or("-"))
    }
}
