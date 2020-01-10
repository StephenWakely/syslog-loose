///! Parsers for rfc 5424 specific formats.
use crate::header::Header;
use crate::parsers::{appname, digits, hostname, msgid, procid};
use crate::pri::pri;
use chrono::prelude::*;
use nom::{
    bytes::complete::take_until,
    character::complete::space1,
    combinator::{map, map_res},
    sequence::tuple,
    IResult,
};

/// The timestamp for 5424 messages yyyy-mm-ddThh:mm:ss.mmmmZ
fn timestamp(input: &str) -> IResult<&str, DateTime<FixedOffset>> {
    map_res(take_until(" "), chrono::DateTime::parse_from_rfc3339)(input)
}

/// Parse the version number - just a simple integer.
fn version(input: &str) -> IResult<&str, u32> {
    digits(input)
}

/// Parse the full 5424 header
pub(crate) fn header(input: &str) -> IResult<&str, Header> {
    map(
        tuple((
            pri, version, space1, timestamp, space1, hostname, space1, appname, space1, procid,
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

#[test]
fn parse_timestamp_5424() {
    assert_eq!(
        timestamp("1985-04-12T23:20:50.52Z ").unwrap(),
        (
            " ",
            FixedOffset::east(0)
                .ymd(1985, 4, 12)
                .and_hms_milli(23, 20, 50, 520)
        )
    );

    assert_eq!(
        timestamp("1985-04-12T23:20:50.52-07:00 ").unwrap(),
        (
            " ",
            FixedOffset::west(7 * 3600)
                .ymd(1985, 4, 12)
                .and_hms_milli(23, 20, 50, 520)
        )
    );

    assert_eq!(
        timestamp("2003-10-11T22:14:15.003Z ").unwrap(),
        (
            " ",
            FixedOffset::west(0)
                .ymd(2003, 10, 11)
                .and_hms_milli(22, 14, 15, 3),
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pri::{SyslogFacility, SyslogSeverity};

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
