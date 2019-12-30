#[macro_use]
extern crate nom;

mod parsers;
mod rfc3164;
mod rfc5424;
mod header;

use chrono::prelude::*;
use nom::{character::complete::space0, IResult};
use crate::header::Header;

pub enum Protocol {
    Unknown,
    RFC3164,
    RFC5424,
}


#[derive(Debug, PartialEq, Eq)]
pub struct Message<'a> {
    header: Header<'a>,
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
    let (input, header) = match rfc5424::header(input) {
        Ok(res) => res,
        Err(_) => rfc3164::header(input, get_year)?,
    };

    let (input, _) = space0(input)?;

    // The remaining unparsed text becomes the message body.
    Ok(("", Message { header, msg: input }))
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
                 msg: "nginx: 127.0.0.1 - - [28/Dec/2019:16:49:07 +0000] \"GET / HTTP/1.1\" 304 0 \"-\" \"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\"",
             })
        );
    }

    #[test]
    fn parse_5424() {
        let msg = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8";

        assert_eq!(
            parse_message(msg).unwrap(),
            (
                "",
                Message {
                    header: Header {
                        pri: 34,
                        version: Some(1),
                        timestamp: Some(FixedOffset::west(0)
                                        .ymd(2003, 10, 11)
                                        .and_hms_milli(22, 14, 15, 3)),
                        hostname: Some("mymachine.example.com"),
                        appname: Some("su"),
                        procid: None,
                        msgid: Some("ID47"),
                    },
                    msg: "- BOM'su root' failed for lonvick on /dev/pts/8",
                }
            )
        );
    }
}
