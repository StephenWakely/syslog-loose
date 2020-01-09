///! Parsers for rfc 3164 specific formats.
use crate::{
    header::Header,
    parsers::{digits, hostname},
    pri::pri,
};
use chrono::prelude::*;
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, take, take_while},
    character::complete::{space0, space1},
    combinator::{map, map_res, opt},
    sequence::{delimited, preceded, tuple},
    IResult,
};

/// An incomplete date is a tuple of (month, date, hour, minutes, seconds)
pub type IncompleteDate = (u32, u32, u32, u32, u32);

/// The month as a three letter string. Returns the number.
fn parse_month(s: &str) -> Result<u32, String> {
    match s.to_lowercase().as_ref() {
        "jan" => Ok(1),
        "feb" => Ok(2),
        "mar" => Ok(3),
        "apr" => Ok(4),
        "may" => Ok(5),
        "jun" => Ok(6),
        "jul" => Ok(7),
        "aug" => Ok(8),
        "sep" => Ok(9),
        "oct" => Ok(10),
        "nov" => Ok(11),
        "dec" => Ok(12),
        _ => Err(format!("Invalid month {}", s)),
    }
}

/// The timestamp for 3164 messages. MMM DD HH:MM:SS
fn timestamp_no_year(input: &str) -> IResult<&str, IncompleteDate> {
    map(
        tuple((
            map_res(take(3_usize), parse_month),
            space1,
            digits,
            space1,
            digits,
            tag(":"),
            digits,
            tag(":"),
            digits,
            opt(tag(":")),
        )),
        |(month, _, date, _, hour, _, minute, _, seconds, _)| (month, date, hour, minute, seconds),
    )(input)
}

/// Timestamp including year. MMM DD YYYY HH:MM:SS
fn timestamp_with_year(input: &str) -> IResult<&str, DateTime<FixedOffset>> {
    map(
        tuple((
            map_res(take(3_usize), parse_month),
            space1,
            digits,
            space1,
            digits,
            space1,
            digits,
            tag(":"),
            digits,
            tag(":"),
            digits,
            opt(tag(":")),
        )),
        |(month, _, date, _, year, _, hour, _, minute, _, seconds, _)| {
            FixedOffset::west(0)
                .ymd(year, month, date)
                .and_hms(hour, minute, seconds)
        },
    )(input)
}

/// Makes a timestamp given all the fields of the date less the year
/// and a function to resolve the year.
fn make_timestamp<F>((mon, d, h, min, s): IncompleteDate, get_year: F) -> DateTime<FixedOffset>
where
    F: FnOnce(IncompleteDate) -> i32,
{
    let year = get_year((mon, d, h, min, s));
    FixedOffset::west(0).ymd(year, mon, d).and_hms(h, min, s)
}

/// Parse the timestamp, either with year or without.
fn timestamp<F>(get_year: F) -> impl Fn(&str) -> IResult<&str, DateTime<FixedOffset>>
where
    F: FnOnce(IncompleteDate) -> i32 + Copy,
{
    move |input| {
        alt((
            map(timestamp_no_year, |ts| make_timestamp(ts, get_year)),
            timestamp_with_year,
        ))(input)
    }
}

// Parse the tag - a process name optionally followed by a pid in [].
pub(crate) fn systag(input: &str) -> IResult<&str, (&str, Option<&str>)> {
    map(
        tuple((
            take_while(|c: char| !c.is_whitespace() && c != ':' && c != '['),
            opt(delimited(tag("["), is_not("]"), tag("]"))),
        )),
        |(tag, pid)| (tag, pid),
    )(input)
}

/// Parses the header.
/// Fails if it cant parse a 3164 format header.
pub fn header<F>(input: &str, get_year: F) -> IResult<&str, Header>
where
    F: FnOnce(IncompleteDate) -> i32 + Copy,
{
    map(
        tuple((
            pri,
            opt(space0),
            timestamp(get_year),
            opt(preceded(space1, hostname)),
            opt(preceded(space1, systag)),
            opt(tag(":")),
            opt(space0),
        )),
        |(pri, _, timestamp, hostname, tag, _, _)| Header {
            facility: pri.0,
            severity: pri.1,
            timestamp: Some(timestamp),
            hostname: hostname.flatten(),
            version: None,
            appname: tag.map(|(appname, _)| appname),
            procid: tag.and_then(|(_, pid)| pid),
            msgid: None,
        },
    )(input)
}

#[test]
fn parse_timestamp_3164() {
    assert_eq!(
        timestamp_no_year("Dec 28 16:49:07 ").unwrap(),
        (" ", (12, 28, 16, 49, 7))
    );
}

#[test]
fn parse_timestamp_3164_trailing_colon() {
    assert_eq!(
        timestamp_no_year("Dec 28 16:49:07:").unwrap(),
        ("", (12, 28, 16, 49, 7))
    );
}

#[test]
fn parse_timestamp_with_year_3164() {
    assert_eq!(
        timestamp(|_| 2019)("Dec 28 2008 16:49:07 ",).unwrap(),
        (
            " ",
            FixedOffset::west(0).ymd(2008, 12, 28).and_hms(16, 49, 07)
        )
    );
}

#[test]
fn parse_tag_with_pid() {
    assert_eq!(systag("app[23]").unwrap(), ("", ("app", Some("23"))));
}

#[test]
fn parse_tag_without_pid() {
    assert_eq!(systag("app ").unwrap(), (" ", ("app", None)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pri::{SyslogFacility, SyslogSeverity};

    #[test]
    fn parse_3164_header_timestamp() {
        /*
        Note the requirement for there to be a : to separate the header and the message.
        I can't see a way around this. a is a valid hostname and message is a valid appname..
        This is not completely compliant with the RFC.
        Are there any significant systems that will send a syslog like this?
        */
        assert_eq!(
            header("<34>Oct 11 22:14:15 : a message", |_| 2019).unwrap(),
            (
                "a message",
                Header {
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    timestamp: Some(FixedOffset::west(0).ymd(2019, 10, 11).and_hms(22, 14, 15)),
                    hostname: None,
                    version: None,
                    appname: None,
                    procid: None,
                    msgid: None,
                }
            )
        );
    }

    #[test]
    fn parse_3164_header_timestamp_uppercase() {
        assert_eq!(
            header("<34>OCT 11 22:14:15 : a message", |_| 2019).unwrap(),
            (
                "a message",
                Header {
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    timestamp: Some(FixedOffset::west(0).ymd(2019, 10, 11).and_hms(22, 14, 15)),
                    hostname: None,
                    version: None,
                    appname: None,
                    procid: None,
                    msgid: None,
                }
            )
        );
    }

    #[test]
    fn parse_3164_header_timestamp_host() {
        assert_eq!(
            header("<34>Oct 11 22:14:15 mymachine: a message", |_| 2019).unwrap(),
            (
                "a message",
                Header {
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    timestamp: Some(FixedOffset::west(0).ymd(2019, 10, 11).and_hms(22, 14, 15)),
                    hostname: Some("mymachine"),
                    version: None,
                    appname: None,
                    procid: None,
                    msgid: None,
                }
            )
        );
    }

    #[test]
    fn parse_3164_header_timestamp_host_appname_pid() {
        assert_eq!(
            header("<34>Oct 11 22:14:15 mymachine app[323]: a message", |_| {
                2019
            })
            .unwrap(),
            (
                "a message",
                Header {
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    timestamp: Some(FixedOffset::west(0).ymd(2019, 10, 11).and_hms(22, 14, 15)),
                    hostname: Some("mymachine"),
                    version: None,
                    appname: Some("app"),
                    procid: Some("323"),
                    msgid: None,
                }
            )
        );
    }
}
