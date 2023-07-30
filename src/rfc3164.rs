//! Parsers for rfc 3164 specific formats.
use crate::{
    message::{Message, Protocol},
    parsers::{hostname, tagname},
    pri::pri,
    structured_data::structured_data_optional,
    timestamp::{timestamp_3164, IncompleteDate},
};
use chrono::prelude::*;
use nom::{
    bytes::complete::{is_not, tag, take_while},
    character::complete::space0,
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
pub fn parse<F, Tz: TimeZone + Copy>(
    input: &str,
    get_year: F,
    tz: Option<Tz>,
) -> IResult<&str, Message<&str>>
where
    F: FnOnce(IncompleteDate) -> i32 + Copy,
{
    map(
        tuple((
            pri,
            opt(space0),
            timestamp_3164(get_year, tz),
            opt(preceded(tag(" "), hostname)),
            opt(preceded(tag(" "), tagname)),
            opt(space0),
            opt(tag(":")),
            opt(space0),
            opt(structured_data_optional(false)),
            opt(space0),
            rest,
        )),
        |(pri, _, timestamp, field1, field2, _, _, _, structured_data, _, msg)| {
            let (host, appname, pid) = resolve_host_and_tag(field1, field2);

            Message {
                protocol: Protocol::RFC3164,
                facility: pri.0,
                severity: pri.1,
                timestamp: Some(timestamp),
                hostname: host,
                appname,
                procid: pid.map(|p| p.into()),
                msgid: None,
                structured_data: structured_data.unwrap_or_default(),
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
    assert!(systag("app ").is_err());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        pri::{SyslogFacility, SyslogSeverity},
        procid::ProcId,
    };

    #[test]
    fn parse_3164_timestamp() {
        /*
        Note the requirement for there to be either a `:` or 2 spaces (see next test) to separate the header and the message.
        I can't see a way around this. a is a valid hostname and message is a valid appname..
        This is not completely compliant with the RFC.
        */
        assert_eq!(
            parse("<34>Oct 11 22:14:15 : a message", |_| 2019, Some(Utc.fix())).unwrap(),
            (
                "",
                Message {
                    protocol: Protocol::RFC3164,
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    timestamp: Some(
                        Utc.with_ymd_and_hms(2019, 10, 11, 22, 14, 15)
                            .unwrap()
                            .into()
                    ),
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
    fn parse_3164_no_tag_json_msg() {
        /* We can parse a missing appname and procname with no `:` message divider only if there are two spaces after the hostname.
        Otherwise the message is going to be confused with the appname.
        */
        let msg = r#"<134>Oct 30 16:05:54 opsaudit  {\"username\": \"admin\", \"ip\": \"7.7.7.7\", \"type\": \"\", \"user_agent\": \"Go-http-client/1.1\", \"datetime\": \"2020-10-30 16:05:45\", \"mfa\": 0, \"status\": true, \"city\": \"局域网\", \"optype\": \"user-login\"}"#;

        assert_eq!(
            parse(msg, |_| 2020, Some(Utc.fix())).unwrap(),
            (
                "",
                Message {
                    facility: Some(SyslogFacility::LOG_LOCAL0),
                    severity: Some(SyslogSeverity::SEV_INFO),
                    timestamp: Some(
                        Utc.with_ymd_and_hms(2020, 10, 30, 16, 5, 54)
                            .unwrap()
                            .into()
                    ),
                    hostname: Some("opsaudit"),
                    appname: None,
                    procid: None,
                    msgid: None,
                    protocol: Protocol::RFC3164,
                    structured_data: vec![],
                    msg: r#"{\"username\": \"admin\", \"ip\": \"7.7.7.7\", \"type\": \"\", \"user_agent\": \"Go-http-client/1.1\", \"datetime\": \"2020-10-30 16:05:45\", \"mfa\": 0, \"status\": true, \"city\": \"局域网\", \"optype\": \"user-login\"}"#,
                }
            )
        );
    }

    #[test]
    fn parse_3164_timestamp_uppercase() {
        assert_eq!(
            parse::<_, FixedOffset>("<34>OCT 11 22:14:15 : a message", |_| 2019, Some(Utc.fix()))
                .unwrap(),
            (
                "",
                Message {
                    protocol: Protocol::RFC3164,
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    timestamp: Some(
                        Utc.with_ymd_and_hms(2019, 10, 11, 22, 14, 15)
                            .unwrap()
                            .into()
                    ),
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
            parse::<_, FixedOffset>(
                "<34>Oct 11 22:14:15 mymachine: a message",
                |_| 2019,
                Some(Utc.fix())
            )
            .unwrap(),
            (
                "",
                Message {
                    protocol: Protocol::RFC3164,
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    timestamp: Some(
                        Utc.with_ymd_and_hms(2019, 10, 11, 22, 14, 15)
                            .unwrap()
                            .into()
                    ),
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
    fn parse_3164_host_with_space() {
        assert_eq!(
            parse::<_, Utc>("<54> 1970-01-01T00:01:31+00:00 host :", |_| 2019, None).unwrap(),
            (
                "",
                Message {
                    protocol: Protocol::RFC3164,
                    facility: Some(SyslogFacility::LOG_LPR,),
                    severity: Some(SyslogSeverity::SEV_INFO,),
                    timestamp: Some(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 31).unwrap().into()),
                    hostname: Some("host",),
                    appname: None,
                    procid: None,
                    msgid: None,
                    structured_data: vec![],
                    msg: "",
                }
            )
        );
    }

    #[test]
    fn parse_3164_timestamp_host_appname_pid() {
        assert_eq!(
            parse::<_, FixedOffset>(
                "<34>Oct 11 22:14:15 mymachine app[323]: a message",
                |_| { 2019 },
                Some(Utc.fix())
            )
            .unwrap(),
            (
                "",
                Message {
                    protocol: Protocol::RFC3164,
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    timestamp: Some(
                        Utc.with_ymd_and_hms(2019, 10, 11, 22, 14, 15)
                            .unwrap()
                            .into()
                    ),
                    hostname: Some("mymachine"),
                    appname: Some("app"),
                    procid: Some(ProcId::PID(323)),
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
            parse::<_, Local>(
                "<34>2020-10-11T22:14:15.00Z mymachine app[323]: a message",
                |_| { 2019 },
                None
            )
            .unwrap(),
            (
                "",
                Message {
                    protocol: Protocol::RFC3164,
                    facility: Some(SyslogFacility::LOG_AUTH),
                    severity: Some(SyslogSeverity::SEV_CRIT),
                    timestamp: Some(
                        FixedOffset::west_opt(0)
                            .unwrap()
                            .with_ymd_and_hms(2020, 10, 11, 22, 14, 15)
                            .unwrap()
                    ),
                    hostname: Some("mymachine"),
                    appname: Some("app"),
                    procid: Some(ProcId::PID(323)),
                    msgid: None,
                    structured_data: vec![],
                    msg: "a message",
                }
            )
        );
    }

    #[test]
    fn parse_3164_3339_datetime_in_message() {
        assert_eq!(
            parse::<_, FixedOffset>(
                "<131>Jun 8 11:54:08 master apache_error [Tue Jun 08 11:54:08.929301 2021] [php7:emerg] [pid 1374899] [client 95.223.77.60:41888] rest of message",
                |_| { 2021 },
                Some(Utc.fix())
            )
            .unwrap(),
            (
                "",
                Message {
                    protocol: Protocol::RFC3164,
                    facility: Some(SyslogFacility::LOG_LOCAL0),
                    severity: Some(SyslogSeverity::SEV_ERR),
                    timestamp: Some(FixedOffset::west_opt(0).unwrap().with_ymd_and_hms(2021, 6, 8,11, 54, 8).unwrap()),
                    hostname: Some("master"),
                    appname: Some("apache_error"),
                    procid: None,
                    msgid: None,
                    structured_data: vec![],
                    msg: "[Tue Jun 08 11:54:08.929301 2021] [php7:emerg] [pid 1374899] [client 95.223.77.60:41888] rest of message",
                }
            )
        );
    }
}
