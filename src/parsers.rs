///! Parsers shared by both protocols.
use nom::{
    bytes::complete::take_while,
    character::complete::digit1,
    combinator::map,
    combinator::map_res,
    IResult,
};
use std::str::FromStr;

pub(crate) fn digits<T>(input: &str) -> IResult<&str, T>
where
    T: FromStr,
{
    map_res(digit1, FromStr::from_str)(input)
}

/// Parse either a string up to white space or a ':'.
/// If the string is '-' this is taken to be an empty value.
pub(crate) fn optional(input: &str) -> IResult<&str, Option<&str>> {
    map(
        // Note we need to use the ':' as a separator between the 3164 headers and the message.
        // So the header fields can't use them. Need to be aware of this to check
        // if this will be an issue.
        take_while(|c: char| !c.is_whitespace() && c != ':'),
        |value| {
            if value == "-" || value == "" {
                None
            } else {
                Some(value)
            }
        },
    )(input)
}

/// Parse the host name or ip address.
pub(crate) fn hostname(input: &str) -> IResult<&str, Option<&str>> {
    optional(input)
}

/// Parse the app name
pub(crate) fn appname(input: &str) -> IResult<&str, Option<&str>> {
    optional(input)
}

/// Parse the Process Id
pub(crate) fn procid(input: &str) -> IResult<&str, Option<&str>> {
    optional(input)
}

/// Parse the Message Id
pub(crate) fn msgid(input: &str) -> IResult<&str, Option<&str>> {
    optional(input)
}
