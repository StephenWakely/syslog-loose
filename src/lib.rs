extern crate nom;

mod error;
mod message;
mod parsers;
mod pri;
mod rfc3164;
mod rfc5424;
mod structured_data;
mod timestamp;

use chrono::prelude::*;
use nom::{branch::alt, IResult};

pub use message::{Message, Protocol};
pub use pri::{decompose_pri, SyslogFacility, SyslogSeverity};
pub use structured_data::StructuredElement;
pub use timestamp::IncompleteDate;

/// Attempt to parse 5424 first, if this fails move on to 3164.
fn parse<F>(input: &str, get_year: F) -> IResult<&str, Message<&str>>
where
    F: FnOnce(IncompleteDate) -> i32 + Copy,
{
    alt((rfc5424::parse, |input| rfc3164::parse(input, get_year)))(input)
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
    parse(input, get_year).map(|(_, result)| result).unwrap_or(
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

/// Parses the message.
/// For messages where the timestamp doesn't specify a year it just
/// takes the current year.
///
/// # Arguments
///
/// * input - the string containing the message.
///
pub fn parse_message(input: &str) -> Message<&str> {
    parse_message_with_year(input, |_| Utc::now().year())
}
