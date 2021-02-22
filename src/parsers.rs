///! Parsers shared by both protocols.
use nom::{
    bytes::complete::take_while1, character::complete::digit1, combinator::map,
    combinator::map_res, IResult,
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
fn optional(input: &str, has_colons: bool) -> IResult<&str, Option<&str>> {
    map(
        // Note we need to use the ':' as a separator between the 3164 headers and the message.
        // So the header fields can't use them. Need to be aware of this to check
        // if this will be an issue.
        take_while1(|c: char| !c.is_whitespace() && (has_colons || c != ':')),
        |value: &str| {
            if value == "-" || value.is_empty() {
                None
            } else {
                Some(value)
            }
        },
    )(input)
}

/// Parse the host name or ip address.
pub(crate) fn hostname(input: &str) -> IResult<&str, Option<&str>> {
    optional(input, false)
}

// Parse the tagname
pub(crate) fn tagname(input: &str) -> IResult<&str, Option<&str>> {
    optional(input, false)
}

/// Parse the app name
pub(crate) fn appname(input: &str) -> IResult<&str, Option<&str>> {
    optional(input, true)
}

/// Parse the Process Id
pub(crate) fn procid(input: &str) -> IResult<&str, Option<&str>> {
    optional(input, false)
}

/// Parse the Message Id
pub(crate) fn msgid(input: &str) -> IResult<&str, Option<&str>> {
    optional(input, false)
}

#[test]
fn parse_optional_exclamations() {
    assert_eq!(optional("!!!", false), Ok(("", Some("!!!"))));
}

#[test]
fn appname_can_have_colons() {
    assert_eq!(
        appname("OX-XXX-CONTEUDO:rpd"),
        Ok(("", Some("OX-XXX-CONTEUDO:rpd")))
    );
}
