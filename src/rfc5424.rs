///! Parsers for rfc 5424 specific formats.
use crate::{
    header::Header,
    parsers::{appname, digits, hostname, msgid, procid},
    pri::pri,
    timestamp::timestamp_3339,
};
use nom::{
    character::complete::space1,
    combinator::map,
    sequence::tuple,
    IResult,
};

/// Parse the version number - just a simple integer.
fn version(input: &str) -> IResult<&str, u32> {
    digits(input)
}

/// Parse the full 5424 header
pub(crate) fn header(input: &str) -> IResult<&str, Header> {
    map(
        tuple((
            pri, version, space1, timestamp_3339, space1, hostname, space1, appname, space1, procid,
            space1, msgid,
        )),
        |(pri, version, _, timestamp, _, hostname, _, appname, _, procid, _, msgid)| Header {
            facility: pri.0,
            severity: pri.1,
            version: Some(version),
            timestamp: Some(timestamp),
            hostname,
            appname,
            procid,
            msgid,
        },
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pri::{SyslogFacility, SyslogSeverity};
    use chrono::prelude::*;

    #[test]
    fn parse_5424_header() {
        assert_eq!(
            header("<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 ").unwrap(),
            (
                " ",
                Header {
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    version: Some(1),
                    timestamp: Some(
                        FixedOffset::west(0)
                            .ymd(2003, 10, 11)
                            .and_hms_milli(22, 14, 15, 3)
                    ),
                    hostname: Some("mymachine.example.com"),
                    appname: Some("su"),
                    procid: None,
                    msgid: Some("ID47"),
                }
            )
        )
    }
}
