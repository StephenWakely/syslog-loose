#[macro_use]
extern crate nom;

mod error;
mod header;
mod parsers;
mod pri;
mod rfc3164;
mod rfc5424;
mod structured_data;
mod timestamp;

use crate::header::Header;
use chrono::prelude::*;
use nom::{character::complete::space0, IResult};

pub use pri::{SyslogFacility, SyslogSeverity};
pub use timestamp::IncompleteDate;

#[derive(Debug, PartialEq, Eq)]
pub enum Protocol {
    RFC3164,
    RFC5424,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Message<'a> {
    pub header: Header<'a>,
    pub protocol: Protocol,
    pub structured_data: Vec<structured_data::StructuredElement<'a>>,
    pub msg: &'a str,
}

/// Attempt to parse 5424 first, if this fails move on to 3164.
fn parse<F>(input: &str, get_year: F) -> IResult<&str, Message>
where
    F: FnOnce(IncompleteDate) -> i32 + Copy,
{
    match rfc5424::header(input) {
        Ok((input, header)) => {
            let (input, _) = space0(input)?;
            let (input, structured_data) = structured_data::structured_data(input)?;
            let (input, _) = space0(input)?;
            let msg = Message {
                header,
                protocol: Protocol::RFC5424,
                structured_data,
                msg: input,
            };

            Ok(("", msg))
        }
        Err(_) => {
            let (input, header) = rfc3164::header(input, get_year)?;
            let (input, _) = space0(input)?;
            let (input, structured_data) = opt!(input, structured_data::structured_data)?;
            let (input, _) = space0(input)?;
            // The remaining unparsed text becomes the message body.
            let msg = Message {
                header,
                protocol: Protocol::RFC3164,
                structured_data: structured_data.unwrap_or(vec![]),
                msg: input,
            };
            Ok(("", msg))
        }
    }
}

///
/// Parse the message.
///
/// # Arguments
///
/// * input - the string containing the message.
/// * get_year - a function that is called if the parsed message contains a date with no year.
///              the function takes a (month, date, hour, minute, second) tuple and should return the year to use.
///
pub fn parse_message_with_year<F>(input: &str, get_year: F) -> Message
where
    F: FnOnce(IncompleteDate) -> i32 + Copy,
{
    parse(input, get_year).map(|(_, result)| result).unwrap_or(
        // If we fail to parse, the entire input becomes the message
        // the rest of the fields are empty.
        Message {
            header: Header::new(),
            protocol: Protocol::RFC3164,
            structured_data: vec![],
            msg: input,
        },
    )
}

/// Parses the message.
/// For messages where the timestamp doesn't specify a year it just
/// takes the current year.
///
/// # Arguments
///
/// * input - the string containing the message.
///
pub fn parse_message(input: &str) -> Message {
    parse_message_with_year(input, |_| Utc::now().year())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_year((month, _date, _hour, _min, _sec): IncompleteDate) -> i32 {
        if month == 12 {
            2019
        } else {
            2020
        }
    }

    #[test]
    fn parse_nginx() {
        // The nginx logs in 3164.
        let msg = "<190>Dec 28 16:49:07 plertrood-thinkpad-x220 nginx: 127.0.0.1 - - [28/Dec/2019:16:49:07 +0000] \"GET / HTTP/1.1\" 304 0 \"-\" \"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\"";

        assert_eq!(
            parse_message_with_year(msg, with_year),
            Message {
                header: Header {
                    facility: Some(SyslogFacility::LOG_LOCAL7),
                    severity: Some(SyslogSeverity::SEV_INFO),
                    version: None,
                    timestamp: Some(FixedOffset::west(0).ymd(2019, 12, 28).and_hms(16, 49, 07)),
                    hostname: Some("plertrood-thinkpad-x220"),
                    appname: Some("nginx"),
                    procid: None,
                    msgid: None,
                },
                protocol: Protocol::RFC3164,
                structured_data: vec![],
                msg: "127.0.0.1 - - [28/Dec/2019:16:49:07 +0000] \"GET / HTTP/1.1\" 304 0 \"-\" \"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\"",
            }
        );
    }

    #[test]
    fn parse_rsyslog() {
        // rsyslog sends messages in 3164 with some structured data.
        let msg = "<46>Jan  5 15:33:03 plertrood-ThinkPad-X220 rsyslogd:  [origin software=\"rsyslogd\" swVersion=\"8.32.0\" x-pid=\"20506\" x-info=\"http://www.rsyslog.com\"] start";

        assert_eq!(
            parse_message_with_year(msg, with_year),
            Message {
                header: Header {
                    facility: Some(SyslogFacility::LOG_SYSLOG),
                    severity: Some(SyslogSeverity::SEV_INFO),
                    version: None,
                    timestamp: Some(
                        FixedOffset::west(0)
                            .ymd(2020, 1, 5)
                            .and_hms_milli(15, 33, 3, 0)
                    ),
                    hostname: Some("plertrood-ThinkPad-X220"),
                    appname: Some("rsyslogd"),
                    procid: None,
                    msgid: None,
                },
                protocol: Protocol::RFC3164,
                structured_data: vec![structured_data::StructuredElement {
                    id: "origin",
                    params: vec![
                        ("software", "rsyslogd"),
                        ("swVersion", "8.32.0"),
                        ("x-pid", "20506"),
                        ("x-info", "http://www.rsyslog.com"),
                    ]
                }],
                msg: "start",
            }
        );
    }

    #[test]
    fn parse_haproxy() {
        // haproxy doesnt include the hostname.
        let msg = "<133>Jan 13 16:33:35 haproxy[73411]: Proxy sticky-servers started.";
        assert_eq!(
            parse_message_with_year(msg, with_year),
            Message {
                header: Header {
                    facility: Some(SyslogFacility::LOG_LOCAL0),
                    severity: Some(SyslogSeverity::SEV_NOTICE),
                    version: None,
                    timestamp: Some(
                        FixedOffset::west(0)
                            .ymd(2020, 1, 13)
                            .and_hms_milli(16, 33, 35, 0)
                    ),
                    hostname: None,
                    appname: Some("haproxy"),
                    procid: Some("73411"),
                    msgid: None,
                },
                protocol: Protocol::RFC3164,
                structured_data: vec![],
                msg: "Proxy sticky-servers started.",
            }
        );
    }

    #[test]
    fn parse_5424_no_structured_data() {
        let msg = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8";

        assert_eq!(
            parse_message(msg),
            Message {
                header: Header {
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
                },
                protocol: Protocol::RFC5424,
                structured_data: vec![],
                msg: "BOM'su root' failed for lonvick on /dev/pts/8",
            }
        );
    }

    #[test]
    fn parse_5424_structured_data() {
        let msg = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] BOMAn application event log entry...";

        assert_eq!(
            parse_message(msg),
            Message {
                header: Header {
                    facility: Some(SyslogFacility::LOG_LOCAL4),
                    severity: Some(SyslogSeverity::SEV_NOTICE),
                    version: Some(1),
                    timestamp: Some(
                        FixedOffset::west(0)
                            .ymd(2003, 10, 11)
                            .and_hms_milli(22, 14, 15, 3)
                    ),
                    hostname: Some("mymachine.example.com"),
                    appname: Some("evntslog"),
                    procid: None,
                    msgid: Some("ID47"),
                },
                protocol: Protocol::RFC5424,
                structured_data: vec![structured_data::StructuredElement {
                    id: "exampleSDID@32473",
                    params: vec![
                        ("iut", "3"),
                        ("eventSource", "Application"),
                        ("eventID", "1011")
                    ]
                },],
                msg: "BOMAn application event log entry...",
            }
        );
    }

    #[test]
    fn parse_5424_multiple_structured_data() {
        let msg = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource= \"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"] BOMAn application event log entry...";

        assert_eq!(
            parse_message(msg),
            Message {
                header: Header {
                    facility: Some(SyslogFacility::LOG_LOCAL4),
                    severity: Some(SyslogSeverity::SEV_NOTICE),
                    version: Some(1),
                    timestamp: Some(
                        FixedOffset::west(0)
                            .ymd(2003, 10, 11)
                            .and_hms_milli(22, 14, 15, 3)
                    ),
                    hostname: Some("mymachine.example.com"),
                    appname: Some("evntslog"),
                    procid: None,
                    msgid: Some("ID47"),
                },
                protocol: Protocol::RFC5424,
                structured_data: vec![
                    structured_data::StructuredElement {
                        id: "exampleSDID@32473",
                        params: vec![
                            ("iut", "3"),
                            ("eventSource", "Application"),
                            ("eventID", "1011")
                        ]
                    },
                    structured_data::StructuredElement {
                        id: "examplePriority@32473",
                        params: vec![("class", "high"),]
                    }
                ],
                msg: "BOMAn application event log entry...",
            }
        );
    }

    #[test]
    fn parse_3164_invalid_structured_data() {
        // Can 3164 parse ok when there is something looking similar to structured data - but not quite.
        // Remove the id from the rsyslog messages structured data. This should now go into the msg.
        let msg = "<46>Jan  5 15:33:03 plertrood-ThinkPad-X220 rsyslogd:  [software=\"rsyslogd\" swVersion=\"8.32.0\" x-pid=\"20506\" x-info=\"http://www.rsyslog.com\"] start";

        assert_eq!(parse_message_with_year(msg, with_year),
                   Message {
                       header: Header {
                           facility: Some(SyslogFacility::LOG_SYSLOG),
                           severity: Some(SyslogSeverity::SEV_INFO),
                           version: None,
                           timestamp: Some(
                               FixedOffset::west(0)
                                   .ymd(2020, 1, 5)
                                   .and_hms_milli(15, 33, 3, 0)
                           ),
                           hostname: Some("plertrood-ThinkPad-X220"),
                           appname: Some("rsyslogd"),
                           procid: None,
                           msgid: None,
                       },
                       protocol: Protocol::RFC3164,
                       structured_data: vec![],
                       msg: "[software=\"rsyslogd\" swVersion=\"8.32.0\" x-pid=\"20506\" x-info=\"http://www.rsyslog.com\"] start",
                   });
    }

    #[test]
    fn parse_european_chars() {
        let msg = "<46>Jan 5 10:01:00 Übergröße außerplanmäßig größenordnungsmäßig";

        assert_eq!(
            parse_message_with_year(msg, with_year),
            Message {
                header: Header {
                    facility: Some(SyslogFacility::LOG_SYSLOG),
                    severity: Some(SyslogSeverity::SEV_INFO),
                    version: None,
                    timestamp: Some(
                        FixedOffset::west(0)
                            .ymd(2020, 1, 5)
                            .and_hms_milli(10, 1, 0, 0)
                    ),
                    hostname: Some("Übergröße"),
                    appname: Some("außerplanmäßig"),
                    procid: None,
                    msgid: None,
                },
                protocol: Protocol::RFC3164,
                structured_data: vec![],
                msg: "größenordnungsmäßig",
            }
        );
    }

    #[test]
    fn parse_invalid_message() {
        let msg = "complete and utter gobbledegook";

        assert_eq!(
            parse_message_with_year(msg, with_year),
            Message {
                header: Header {
                    facility: None,
                    severity: None,
                    version: None,
                    timestamp: None,
                    hostname: None,
                    appname: None,
                    procid: None,
                    msgid: None,
                },
                protocol: Protocol::RFC3164,
                structured_data: vec![],
                msg: "complete and utter gobbledegook",
            }
        );
    }
}
