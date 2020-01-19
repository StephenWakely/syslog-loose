///! Parsers for rfc 3164 specific formats.
use crate::{
    message::{Message, Protocol},
    parsers::optional,
    pri::pri,
    structured_data::structured_data,
    timestamp::{timestamp_3164, IncompleteDate},
};
use nom::{
    bytes::complete::{is_not, tag, take_while},
    character::complete::{space0, space1},
    combinator::{map, opt, rest},
    sequence::{delimited, preceded, tuple},
    IResult,
};

// Parse the tag - a process name followed by a pid in [].
pub(crate) fn systag(input: &str) -> IResult<&str, (&str, &str)> {
    tuple((
        take_while(|c: char| !c.is_whitespace() && c != ':' && c != '['),
        delimited(tag("["), is_not("]"), tag("]")),
    ))(input)
}

/// Resolves the final two potential fields in the header.
/// Sometimes, there is only one field, this may be the host or the tag.
/// We can determine if this field is the tag only if it follows the format appname[procid].
///
/// Each field has three potential states :
///   None => Means the field hasnt been specified at all.
///   Some(None) => Means the field was specified, but was specified as being empty (with '-')
///   Some(Some(_)) => The field was specified and given a value.
fn resolve_host_and_tag<'a>(
    field1: Option<Option<&'a str>>,
    field2: Option<Option<&'a str>>,
) -> (Option<&'a str>, Option<&'a str>, Option<&'a str>) {
    match (field1, field2) {
        // Both field specified, tag just needs parsing to see if there is a procid
        (Some(host), Some(Some(tag))) => match systag(tag) {
            Ok(("", (app, procid))) => (host, Some(app), Some(procid)),
            _ => (host, Some(tag), None),
        },

        // Only one field specified, is this the host or the tag?
        (Some(Some(field)), None) => match systag(field) {
            Ok(("", (app, procid))) => (None, Some(app), Some(procid)),
            _ => (Some(field), None, None),
        },

        // This one should never happen, but just for completeness...
        (None, Some(Some(field))) => match systag(field) {
            Ok(("", (app, procid))) => (None, Some(app), Some(procid)),
            _ => (Some(field), None, None),
        },

        // No field specified.
        _ => (None, None, None),
    }
}

/// Parses the message as per RFC3164.
pub fn parse<F>(input: &str, get_year: F) -> IResult<&str, Message<&str>>
where
    F: FnOnce(IncompleteDate) -> i32 + Copy,
{
    map(
        tuple((
            pri,
            opt(space0),
            timestamp_3164(get_year),
            opt(preceded(space1, optional)),
            opt(preceded(space1, optional)),
            opt(tag(":")),
            opt(space0),
            opt(structured_data),
            opt(space0),
            rest,
        )),
        |(pri, _, timestamp, field1, field2, _, _, structured_data, _, msg)| {
            let (host, appname, pid) = resolve_host_and_tag(field1, field2);

            Message {
                protocol: Protocol::RFC3164,
                facility: pri.0,
                severity: pri.1,
                timestamp: Some(timestamp),
                hostname: host,
                appname: appname,
                procid: pid,
                msgid: None,
                structured_data: structured_data.unwrap_or(vec![]),
                msg,
            }
        },
    )(input)
}

#[test]
fn parse_tag_with_pid() {
    assert_eq!(systag("app[23]").unwrap(), ("", ("app", "23")));
}

#[test]
fn parse_tag_without_pid() {
    assert_eq!(systag("app ").is_err(), true);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pri::{SyslogFacility, SyslogSeverity};
    use chrono::prelude::*;

    #[test]
    fn parse_3164_timestamp() {
        /*
        Note the requirement for there to be a : to separate the header and the message.
        I can't see a way around this. a is a valid hostname and message is a valid appname..
        This is not completely compliant with the RFC.
        Are there any significant systems that will send a syslog like this?
        */
        assert_eq!(
            parse("<34>Oct 11 22:14:15 : a message", |_| 2019).unwrap(),
            (
                "",
                Message {
                    protocol: Protocol::RFC3164,
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    timestamp: Some(FixedOffset::west(0).ymd(2019, 10, 11).and_hms(22, 14, 15)),
                    hostname: None,
                    appname: None,
                    procid: None,
                    msgid: None,
                    structured_data: vec![],
                    msg: "a message",
                }
            )
        );
    }

    #[test]
    fn parse_3164_timestamp_uppercase() {
        assert_eq!(
            parse("<34>OCT 11 22:14:15 : a message", |_| 2019).unwrap(),
            (
                "",
                Message {
                    protocol: Protocol::RFC3164,
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    timestamp: Some(FixedOffset::west(0).ymd(2019, 10, 11).and_hms(22, 14, 15)),
                    hostname: None,
                    appname: None,
                    procid: None,
                    msgid: None,
                    structured_data: vec![],
                    msg: "a message",
                }
            )
        );
    }

    #[test]
    fn parse_3164_timestamp_host() {
        assert_eq!(
            parse("<34>Oct 11 22:14:15 mymachine: a message", |_| 2019).unwrap(),
            (
                "",
                Message {
                    protocol: Protocol::RFC3164,
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    timestamp: Some(FixedOffset::west(0).ymd(2019, 10, 11).and_hms(22, 14, 15)),
                    hostname: Some("mymachine"),
                    appname: None,
                    procid: None,
                    msgid: None,
                    structured_data: vec![],
                    msg: "a message",
                }
            )
        );
    }

    #[test]
    fn parse_3164_timestamp_host_appname_pid() {
        assert_eq!(
            parse("<34>Oct 11 22:14:15 mymachine app[323]: a message", |_| {
                2019
            })
            .unwrap(),
            (
                "",
                Message {
                    protocol: Protocol::RFC3164,
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    timestamp: Some(FixedOffset::west(0).ymd(2019, 10, 11).and_hms(22, 14, 15)),
                    hostname: Some("mymachine"),
                    appname: Some("app"),
                    procid: Some("323"),
                    msgid: None,
                    structured_data: vec![],
                    msg: "a message",
                }
            )
        );
    }

    #[test]
    fn parse_3164_3339_timestamp_host_appname_pid() {
        assert_eq!(
            parse(
                "<34>2020-10-11T22:14:15.00Z mymachine app[323]: a message",
                |_| { 2019 }
            )
            .unwrap(),
            (
                "",
                Message {
                    protocol: Protocol::RFC3164,
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    timestamp: Some(FixedOffset::west(0).ymd(2020, 10, 11).and_hms(22, 14, 15)),
                    hostname: Some("mymachine"),
                    appname: Some("app"),
                    procid: Some("323"),
                    msgid: None,
                    structured_data: vec![],
                    msg: "a message",
                }
            )
        );
    }
}
