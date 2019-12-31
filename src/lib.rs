#[macro_use]
extern crate nom;

mod header;
mod parsers;
mod rfc3164;
mod rfc5424;

use crate::header::Header;
use chrono::prelude::*;
use nom::{character::complete::space0, IResult};

#[derive(Debug, PartialEq, Eq)]
pub enum Protocol {
    RFC3164,
    RFC5424,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Message<'a> {
    header: Header<'a>,
    protocol: Protocol,
    structured_data: Vec<rfc5424::StructuredElement<'a>>,
    msg: &'a str,
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
pub fn parse_message_with_year<F>(input: &str, get_year: F) -> IResult<&str, Message>
where
    F: FnOnce(rfc3164::IncompleteDate) -> i32,
{
    match rfc5424::header(input) {
        Ok((input, header)) => {
            let (input, _) = space0(input)?;
            let (input, structured_data) = rfc5424::structured_data(input)?;
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
            // The remaining unparsed text becomes the message body.
            let msg = Message {
                header,
                protocol: Protocol::RFC3164,
                structured_data: vec![],
                msg: input,
            };
            Ok(("", msg))
        }
    }
}

/// Parses the message.
/// For messages where the timestamp doesn't specify a year it just
/// takes the current year.
///
/// # Arguments
///
/// * input - the string containing the message.
///
pub fn parse_message(input: &str) -> IResult<&str, Message> {
    parse_message_with_year(input, |_| Utc::now().year())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nginx() {
        // The nginx logs in 3164.
        let msg = "<190>Dec 28 16:49:07 plertrood-thinkpad-x220 nginx: 127.0.0.1 - - [28/Dec/2019:16:49:07 +0000] \"GET / HTTP/1.1\" 304 0 \"-\" \"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\"";

        assert_eq!(
            parse_message_with_year(msg,
                                    |(month, _date, _hour, _min, _sec)| {
                                        if month == 12 {
                                            2019
                                        } else {
                                            2020
                                        }
                                    }).unwrap(),
            ("",
             Message {
                 header: Header {
                     pri: 190,
                     version: None,
                     timestamp: Some(FixedOffset::west(0).ymd(2019, 12, 28).and_hms(16, 49, 07)),
                     hostname: Some("plertrood-thinkpad-x220"),
                     appname: None,
                     procid: None,
                     msgid: None,
                 },
                 protocol: Protocol::RFC3164,
                 structured_data: vec![],
                 msg: "nginx: 127.0.0.1 - - [28/Dec/2019:16:49:07 +0000] \"GET / HTTP/1.1\" 304 0 \"-\" \"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\"",
             })
        );
    }

    #[test]
    fn parse_5424_no_structured_data() {
        let msg = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8";

        assert_eq!(
            parse_message(msg).unwrap(),
            (
                "",
                Message {
                    header: Header {
                        pri: 34,
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
            )
        );
    }

    #[test]
    fn parse_5424_structured_data() {
        let msg = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] BOMAn application event log entry...";

        assert_eq!(
            parse_message(msg).unwrap(),
            (
                "",
                Message {
                    header: Header {
                        pri: 165,
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
                    structured_data: vec![rfc5424::StructuredElement {
                        id: "exampleSDID@32473",
                        params: vec![
                            ("iut", "3"),
                            ("eventSource", "Application"),
                            ("eventID", "1011")
                        ]
                    },],
                    msg: "BOMAn application event log entry...",
                }
            )
        );
    }

}
