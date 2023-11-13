//! Parsers shared by both protocols.
use nom::{
    bytes::complete::take_while1,
    character::complete::digit1,
    combinator::map_res,
    error::{make_error, ErrorKind},
    Err, IResult,
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
    let (remaining, value) =
        take_while1(|c: char| !c.is_whitespace() && (has_colons || c != ':'))(input)?;

    if value.trim() == ":" {
        // A colon by itself indicates we are at the separator between headers and message.
        Err(Err::Error(make_error(input, ErrorKind::Fail)))
    } else if value.ends_with(':') {
        // If the field ends with a colon, the colon should be treated as the separator between
        // the headers and the message, we return the field but leave the separator.
        let split = value.len() - 1;
        Ok((&input[split..], Some(&value[0..split])))
    } else if value == "-" || value.is_empty() {
        // The field is just empty.
        Ok((remaining, None))
    } else {
        Ok((remaining, Some(value)))
    }
}

/// Parse the host name or ip address.
pub(crate) fn hostname(input: &str) -> IResult<&str, Option<&str>> {
    optional(input, true)
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
    optional(input, true)
}

/// Parse the Message Id
pub(crate) fn msgid(input: &str) -> IResult<&str, Option<&str>> {
    optional(input, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_optional_exclamations() {
        assert_eq!(optional("!!!", true), Ok(("", Some("!!!"))));
    }

    #[test]
    fn appname_can_have_colons() {
        assert_eq!(
            appname("OX-XXX-CONTEUDO:rpd"),
            Ok(("", Some("OX-XXX-CONTEUDO:rpd")))
        );
    }

    #[test]
    fn parse_hostname() {
        assert_eq!(hostname("zork "), Ok((" ", Some("zork"))));
        assert_eq!(hostname("192.168.0.1 "), Ok((" ", Some("192.168.0.1"))));
        assert_eq!(hostname("::13.1.68.3 "), Ok((" ", Some("::13.1.68.3"))));
        assert_eq!(
            hostname("2001:0db8:85a3:0000:0000:8a2e:0370:7334 "),
            Ok((" ", Some("2001:0db8:85a3:0000:0000:8a2e:0370:7334")))
        );
    }

    #[test]
    fn trailing_colon() {
        assert_eq!(hostname("zork: "), Ok((": ", Some("zork"))))
    }
}
