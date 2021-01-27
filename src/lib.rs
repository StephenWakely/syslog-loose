extern crate nom;

mod error;
mod message;
mod parsers;
mod pri;
mod procid;
mod rfc3164;
mod rfc5424;
mod structured_data;
mod timestamp;

use chrono::prelude::*;
use nom::{branch::alt, IResult};

pub use message::{Message, Protocol};
pub use pri::{decompose_pri, SyslogFacility, SyslogSeverity};
pub use procid::ProcId;
pub use structured_data::StructuredElement;
pub use timestamp::IncompleteDate;

/// Attempt to parse 5424 first, if this fails move on to 3164.
fn parse<F>(input: &str, get_year: F, tz: Option<FixedOffset>) -> IResult<&str, Message<&str>>
where
    F: FnOnce(IncompleteDate) -> i32 + Copy,
{
    alt((rfc5424::parse, |input| rfc3164::parse(input, get_year, tz)))(input.trim())
}

///
/// Parse the message.
///
/// # Arguments
///
/// * input - the string containing the message.
/// * tz - a default timezone to use if the parsed timestamp does not specify one
/// * get_year - a function that is called if the parsed message contains a date with no year.
///              the function takes a (month, date, hour, minute, second) tuple and should return the year to use.
///
pub fn parse_message_with_year_tz<F>(
    input: &str,
    get_year: F,
    tz: Option<FixedOffset>,
) -> Message<&str>
where
    F: FnOnce(IncompleteDate) -> i32 + Copy,
{
    parse(input, get_year, tz)
        .map(|(_, result)| result)
        .unwrap_or(
            // If we fail to parse, the entire input becomes the message
            // the rest of the fields are empty.
            Message {
                facility: None,
                severity: None,
                timestamp: None,
                hostname: None,
                appname: None,
                procid: None,
                msgid: None,
                protocol: Protocol::RFC3164,
                structured_data: vec![],
                msg: input,
            },
        )
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
pub fn parse_message_with_year<F>(input: &str, get_year: F) -> Message<&str>
where
    F: FnOnce(IncompleteDate) -> i32 + Copy,
{
    parse_message_with_year_tz(input, get_year, None)
}

/// Parses the message.
/// For messages where the timestamp doesn't specify a year it just
/// takes the current year.
///
/// # Arguments
///
/// * input - the string containing the message.
///
pub fn parse_message(input: &str) -> Message<&str> {
    parse_message_with_year(input, |_| Local::now().year())
}

///
/// Pase the message exactly. If it can't parse the message an Error is returned.
/// Note, since it is hard to locate exactly what is causing the error due to the parser trying
/// so many different combinations, a simple hardcoded string is returned as the error message.
///
/// # Arguments
///
/// * input - the string containing the message.
/// * get_year - a function that is called if the parsed message contains a date with no year.
///              the function takes a (month, date, hour, minute, second) tuple and should return the year to use.
///
pub fn parse_message_with_year_exact<F>(input: &str, get_year: F) -> Result<Message<&str>, String>
where
    F: FnOnce(IncompleteDate) -> i32 + Copy,
{
    parse(input, get_year, None)
        .map(|(_, result)| result)
        .map_err(|_| "Unable to parse input as valid syslog message".to_string())
}
