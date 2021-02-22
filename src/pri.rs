use crate::parsers::digits;
use nom::{bytes::complete::tag, combinator::map, combinator::opt, sequence::delimited, IResult};

// Taken from https://github.com/Roguelazer/rust-syslog-rfc5424/blob/af76363081314f91433e014c76fd834acef756d5/src/facility.rs
// Many thanks.

#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
/// Syslog facilities. Taken From RFC 5424, but I've heard that some platforms mix these around.
/// Names are from Linux.
pub enum SyslogFacility {
    LOG_KERN = 0,
    LOG_USER = 1,
    LOG_MAIL = 2,
    LOG_DAEMON = 3,
    LOG_AUTH = 4,
    LOG_SYSLOG = 5,
    LOG_LPR = 6,
    LOG_NEWS = 7,
    LOG_UUCP = 8,
    LOG_CRON = 9,
    LOG_AUTHPRIV = 10,
    LOG_FTP = 11,
    LOG_NTP = 12,
    LOG_AUDIT = 13,
    LOG_ALERT = 14,
    LOG_CLOCKD = 15,
    LOG_LOCAL0 = 16,
    LOG_LOCAL1 = 17,
    LOG_LOCAL2 = 18,
    LOG_LOCAL3 = 19,
    LOG_LOCAL4 = 20,
    LOG_LOCAL5 = 21,
    LOG_LOCAL6 = 22,
    LOG_LOCAL7 = 23,
}

impl SyslogFacility {
    /// Convert an int (as used in the wire serialization) into a `SyslogFacility`
    pub(crate) fn from_int(i: i32) -> Option<Self> {
        match i {
            0 => Some(SyslogFacility::LOG_KERN),
            1 => Some(SyslogFacility::LOG_USER),
            2 => Some(SyslogFacility::LOG_MAIL),
            3 => Some(SyslogFacility::LOG_DAEMON),
            4 => Some(SyslogFacility::LOG_AUTH),
            5 => Some(SyslogFacility::LOG_SYSLOG),
            6 => Some(SyslogFacility::LOG_LPR),
            7 => Some(SyslogFacility::LOG_NEWS),
            8 => Some(SyslogFacility::LOG_UUCP),
            9 => Some(SyslogFacility::LOG_CRON),
            10 => Some(SyslogFacility::LOG_AUTHPRIV),
            11 => Some(SyslogFacility::LOG_FTP),
            12 => Some(SyslogFacility::LOG_NTP),
            13 => Some(SyslogFacility::LOG_AUDIT),
            14 => Some(SyslogFacility::LOG_ALERT),
            15 => Some(SyslogFacility::LOG_CLOCKD),
            16 => Some(SyslogFacility::LOG_LOCAL0),
            17 => Some(SyslogFacility::LOG_LOCAL1),
            18 => Some(SyslogFacility::LOG_LOCAL2),
            19 => Some(SyslogFacility::LOG_LOCAL3),
            20 => Some(SyslogFacility::LOG_LOCAL4),
            21 => Some(SyslogFacility::LOG_LOCAL5),
            22 => Some(SyslogFacility::LOG_LOCAL6),
            23 => Some(SyslogFacility::LOG_LOCAL7),
            _ => None,
        }
    }

    /// Convert a syslog facility into a unique string representation
    pub fn as_str(self) -> &'static str {
        match self {
            SyslogFacility::LOG_KERN => "kern",
            SyslogFacility::LOG_USER => "user",
            SyslogFacility::LOG_MAIL => "mail",
            SyslogFacility::LOG_DAEMON => "daemon",
            SyslogFacility::LOG_AUTH => "auth",
            SyslogFacility::LOG_SYSLOG => "syslog",
            SyslogFacility::LOG_LPR => "lpr",
            SyslogFacility::LOG_NEWS => "news",
            SyslogFacility::LOG_UUCP => "uucp",
            SyslogFacility::LOG_CRON => "cron",
            SyslogFacility::LOG_AUTHPRIV => "authpriv",
            SyslogFacility::LOG_FTP => "ftp",
            SyslogFacility::LOG_NTP => "ntp",
            SyslogFacility::LOG_AUDIT => "audit",
            SyslogFacility::LOG_ALERT => "alert",
            SyslogFacility::LOG_CLOCKD => "clockd",
            SyslogFacility::LOG_LOCAL0 => "local0",
            SyslogFacility::LOG_LOCAL1 => "local1",
            SyslogFacility::LOG_LOCAL2 => "local2",
            SyslogFacility::LOG_LOCAL3 => "local3",
            SyslogFacility::LOG_LOCAL4 => "local4",
            SyslogFacility::LOG_LOCAL5 => "local5",
            SyslogFacility::LOG_LOCAL6 => "local6",
            SyslogFacility::LOG_LOCAL7 => "local7",
        }
    }
}

// Taken from https://github.com/Roguelazer/rust-syslog-rfc5424/blob/af76363081314f91433e014c76fd834acef756d5/src/severity.rs
// Many thanks!

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
/// Syslog Severities from RFC 5424.
pub enum SyslogSeverity {
    SEV_EMERG = 0,
    SEV_ALERT = 1,
    SEV_CRIT = 2,
    SEV_ERR = 3,
    SEV_WARNING = 4,
    SEV_NOTICE = 5,
    SEV_INFO = 6,
    SEV_DEBUG = 7,
}

impl SyslogSeverity {
    /// Convert an int (as used in the wire serialization) into a `SyslogSeverity`
    ///
    /// Returns an Option, but the wire protocol will only include 0..7, so should
    /// never return None in practical usage.
    pub(crate) fn from_int(i: i32) -> Option<Self> {
        match i {
            0 => Some(SyslogSeverity::SEV_EMERG),
            1 => Some(SyslogSeverity::SEV_ALERT),
            2 => Some(SyslogSeverity::SEV_CRIT),
            3 => Some(SyslogSeverity::SEV_ERR),
            4 => Some(SyslogSeverity::SEV_WARNING),
            5 => Some(SyslogSeverity::SEV_NOTICE),
            6 => Some(SyslogSeverity::SEV_INFO),
            7 => Some(SyslogSeverity::SEV_DEBUG),
            _ => None,
        }
    }

    /// Convert a syslog severity into a unique string representation
    pub fn as_str(self) -> &'static str {
        match self {
            SyslogSeverity::SEV_EMERG => "emerg",
            SyslogSeverity::SEV_ALERT => "alert",
            SyslogSeverity::SEV_CRIT => "crit",
            SyslogSeverity::SEV_ERR => "err",
            SyslogSeverity::SEV_WARNING => "warning",
            SyslogSeverity::SEV_NOTICE => "notice",
            SyslogSeverity::SEV_INFO => "info",
            SyslogSeverity::SEV_DEBUG => "debug",
        }
    }
}

/// The pri field is composed of both the facility and severity values.
/// The first byte is the Severity, the remaining are the Facility.
pub fn decompose_pri(pri: u8) -> (Option<SyslogFacility>, Option<SyslogSeverity>) {
    let facility = pri >> 3;
    let severity = pri & 0x7;

    (
        SyslogFacility::from_int(facility as i32),
        SyslogSeverity::from_int(severity as i32),
    )
}

/// Compose the facility and severity as a single integer.
pub(crate) fn compose_pri(facility: SyslogFacility, severity: SyslogSeverity) -> i32 {
    ((facility as i32) << 3) + (severity as i32)
}

// The message priority. An integer surrounded by <>
// This number contains both the facility and the severity.
pub(crate) fn pri(input: &str) -> IResult<&str, (Option<SyslogFacility>, Option<SyslogSeverity>)> {
    map(
        opt(delimited(tag("<"), map(digits, decompose_pri), tag(">"))),
        |pri| pri.unwrap_or((None, None)),
    )(input)
}

#[test]
fn test_pri_composes() {
    assert_eq!(
        compose_pri(SyslogFacility::LOG_LOCAL4, SyslogSeverity::SEV_NOTICE),
        165
    );
}

#[test]
fn test_pri_decomposes() {
    assert_eq!(
        decompose_pri(0),
        (
            Some(SyslogFacility::LOG_KERN),
            Some(SyslogSeverity::SEV_EMERG)
        )
    );

    assert_eq!(
        decompose_pri(165),
        (
            Some(SyslogFacility::LOG_LOCAL4),
            Some(SyslogSeverity::SEV_NOTICE)
        )
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pri() {
        assert_eq!(
            pri("<34>").unwrap(),
            (
                "",
                (
                    Some(SyslogFacility::LOG_AUTH),
                    Some(SyslogSeverity::SEV_CRIT)
                )
            )
        );
    }

    #[test]
    fn parse_missing_pri() {
        assert_eq!(pri("1 xxx").unwrap(), ("1 xxx", (None, None)));
    }
}
