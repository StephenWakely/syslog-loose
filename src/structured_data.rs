use nom::{
    branch::alt,
    bytes::complete::{escaped, tag, take_till1, take_until, take_while1},
    character::complete::{one_of, space0, space1},
    combinator::map,
    multi::{many1, separated_list},
    sequence::{delimited, separated_pair, terminated, tuple},
    IResult,
};

#[derive(Debug, PartialEq, Eq)]
pub struct StructuredElement<'a> {
    pub id: &'a str,
    pub params: Vec<(&'a str, &'a str)>,
}

/// Parse the param value - a string delimited by '"' - '\' escapes \ and "
fn param_value(input: &str) -> IResult<&str, &str> {
    delimited(
        tag("\""),
        escaped(
            take_while1(|c: char| c != '\\' && c != '"'),
            '\\',
            one_of("\"n\\"),
        ),
        tag("\""),
    )(input)
}

/// Parse a param name="value"
fn param(input: &str) -> IResult<&str, (&str, &str)> {
    separated_pair(take_until("="), terminated(tag("="), space0), param_value)(input)
}

/// Parse a single structured data record.
/// [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]
fn structured_datum(input: &str) -> IResult<&str, StructuredElement> {
    delimited(
        tag("["),
        map(
            tuple((
                take_till1(|c: char| c.is_whitespace() || c == '='),
                space1,
                separated_list(tag(" "), param),
            )),
            |(id, _, params)| StructuredElement { id, params },
        ),
        tag("]"),
    )(input)
}

/// Parse multiple structured data elements.
pub(crate) fn structured_data(input: &str) -> IResult<&str, Vec<StructuredElement>> {
    alt((map(tag("-"), |_| vec![]), many1(structured_datum)))(input)
}

#[test]
fn parse_param_value() {
    assert_eq!(
        param_value("\"Some \\\"lovely\\\" string\"").unwrap(),
        ("", "Some \\\"lovely\\\" string")
    );
}

#[test]
fn parse_structured_data() {
    assert_eq!(
        structured_datum(
            "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"]"
        )
        .unwrap(),
        (
            "",
            StructuredElement {
                id: "exampleSDID@32473",
                params: vec![
                    ("iut", "3"),
                    ("eventSource", "Application"),
                    ("eventID", "1011"),
                ]
            }
        )
    );
}

#[test]
fn parse_structured_data_with_space() {
    assert_eq!(
        structured_datum(
            "[exampleSDID@32473 iut=\"3\" eventSource= \"Application\" eventID=\"1011\"]"
        )
        .unwrap(),
        (
            "",
            StructuredElement {
                id: "exampleSDID@32473",
                params: vec![
                    ("iut", "3"),
                    ("eventSource", "Application"),
                    ("eventID", "1011"),
                ]
            }
        )
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_multiple_structured_data() {
        assert_eq!(
            structured_data(
            "[exampleSDID@32473 iut=\"3\" eventSource= \"Application\" eventID=\"1011\"][sproink onk=\"ponk\" zork=\"shnork\"]"
            ) .unwrap(),
            (
                "",
                vec![
                    StructuredElement {
                        id: "exampleSDID@32473",
                        params: vec![
                            ("iut", "3"),
                            ("eventSource", "Application"),
                            ("eventID", "1011"),
                        ]
                    },
                    StructuredElement {
                        id: "sproink",
                        params: vec![
                            ("onk", "ponk"),
                            ("zork", "shnork"),
                        ]
                    }
                ]
            )
        );
    }
}
