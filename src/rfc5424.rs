///! Parsers for rfc 5424 specific formats.
use crate::header::Header;
use crate::parsers::{appname, hostname, msgid, procid, u32_digits};
use crate::pri::pri;
use chrono::prelude::*;
use nom::character::complete::space1;

// The timestamp for 5424 messages yyyy-mm-ddThh:mm:ss.mmmmZ
named!(timestamp(&str) -> DateTime<FixedOffset>,
       map_res!(take_until!(" "), chrono::DateTime::parse_from_rfc3339)
);

// Parse the version number - just a simple integer.
named!(version(&str) -> u32,
       do_parse!( version: u32_digits >>
                  (version)
       ));

// Parse the full 5424 header
named!(pub(crate) header(&str) -> Header,
       do_parse! (
           pri: pri >>
           version: version >>
           space1 >>
           timestamp: timestamp >>
           space1 >>
           hostname: hostname >>
           space1 >>
           appname: appname >>
           space1 >>
           procid: procid >>
           space1 >>
           msgid: msgid >>
           (
               Header { facility: pri.0,
                        severity: pri.1,
                        version: Some(version),
                        timestamp: Some(timestamp),
                        hostname,
                        appname,
                        procid,
                        msgid,
               })
       ));

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

named!(esc(&str) -> &str,
       escaped!(
           take_while1!(|c: char| c.is_numeric() )
       , '\\', one_of!("\"n\\")
       ));

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
