//! Parsers for rfc 5424 specific formats.
use crate::{
    message::{Message, Protocol},
    parsers::{appname, digits, hostname, msgid, procid},
    pri::pri,
    structured_data::structured_data,
    timestamp::timestamp_3339,
};
use nom::{
    character::complete::{space0, space1},
    combinator::{map, rest},
    sequence::tuple,
    IResult,
};

/// Parse the version number - just a simple integer.
fn version(input: &str) -> IResult<&str, u32> {
    digits(input)
}

/// Parse the message as per RFC5424
pub(crate) fn parse(input: &str) -> IResult<&str, Message<&str>> {
    map(
        tuple((
            pri,
            version,
            space1,
            timestamp_3339,
            space1,
            hostname,
            space1,
            appname,
            space1,
            procid,
            space1,
            msgid,
            space0,
            structured_data,
            space0,
            rest,
        )),
        |(
            pri,
            version,
            _,
            timestamp,
            _,
            hostname,
            _,
            appname,
            _,
            procid,
            _,
            msgid,
            _,
            structured_data,
            _,
            msg,
        )| Message {
            protocol: Protocol::RFC5424(version),
            facility: pri.0,
            severity: pri.1,
            timestamp: Some(timestamp),
            hostname,
            appname,
            procid: procid.map(|p| p.into()),
            msgid,
            structured_data,
            msg,
        },
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pri::{SyslogFacility, SyslogSeverity};
    use chrono::{prelude::*, Duration};

    #[test]
    fn parse_5424() {
        assert_eq!(
            parse("<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - message")
                .unwrap(),
            (
                "",
                Message {
                    protocol: Protocol::RFC5424(1),
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    timestamp: Some(
                        FixedOffset::west_opt(0)
                            .unwrap()
                            .with_ymd_and_hms(2003, 10, 11, 22, 14, 15,)
                            .unwrap()
                            + Duration::milliseconds(3)
                    ),
                    hostname: Some("mymachine.example.com"),
                    appname: Some("su"),
                    procid: None,
                    msgid: Some("ID47"),
                    structured_data: vec![],
                    msg: "message",
                }
            )
        )
    }
}
