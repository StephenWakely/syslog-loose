use nom::{
    branch::alt,
    bytes::complete::{escaped, tag, take_till1, take_until, take_while1},
    character::complete::{one_of, space0},
    combinator::map,
    multi::{many1, separated_list0},
    sequence::{delimited, separated_pair, terminated, tuple},
    IResult,
};
use std::fmt;

#[derive(Clone, Debug, Eq)]
pub struct StructuredElement<S: AsRef<str> + Ord + Clone> {
    pub id: S,
    pub params: Vec<(S, S)>,
}

impl<S: AsRef<str> + Ord + Clone> fmt::Display for StructuredElement<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}", self.id.as_ref())?;

        for (name, value) in &self.params {
            write!(f, " {}=\"{}\"", name.as_ref(), value.as_ref())?;
        }

        write!(f, "]")
    }
}

impl<S: AsRef<str> + Ord + Clone> PartialEq for StructuredElement<S> {
    fn eq(&self, other: &Self) -> bool {
        if self.id.as_ref() != other.id.as_ref() {
            return false;
        }

        let mut params1 = self.params.clone();
        params1.sort();

        let mut params2 = self.params.clone();
        params2.sort();

        params1
            .iter()
            .zip(params2)
            .all(|((ref name1, ref value1), (ref name2, ref value2))| {
                name1.as_ref() == name2.as_ref() && value1.as_ref() == value2.as_ref()
            })
    }
}

impl From<StructuredElement<&str>> for StructuredElement<String> {
    fn from(element: StructuredElement<&str>) -> Self {
        StructuredElement {
            id: element.id.to_string(),
            params: element
                .params
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        }
    }
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
    separated_pair(
        take_till1(|c: char| c == ']' || c == '='),
        terminated(tag("="), space0),
        param_value,
    )(input)
}

/// Parse a single structured data record.
/// [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]
fn structured_datum(input: &str) -> IResult<&str, Option<StructuredElement<&str>>> {
    alt((
        delimited(
            tag("["),
            map(
                tuple((
                    take_till1(|c: char| c.is_whitespace() || c == ']' || c == '='),
                    space0,
                    separated_list0(tag(" "), param),
                )),
                |(id, _, params)| Some(StructuredElement { id, params }),
            ),
            tag("]"),
        ),
        // If the element fails to parse, just parse it and return None.
        delimited(tag("["), map(take_until("]"), |_| None), tag("]")),
    ))(input)
}

/// Parse multiple structured data elements.
pub(crate) fn structured_data(input: &str) -> IResult<&str, Vec<StructuredElement<&str>>> {
    alt((
        map(tag("-"), |_| vec![]),
        map(many1(structured_datum), |items| {
            items.iter().filter_map(|item| item.clone()).collect()
        }),
    ))(input)
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
            Some(StructuredElement {
                id: "exampleSDID@32473",
                params: vec![
                    ("iut", "3"),
                    ("eventSource", "Application"),
                    ("eventID", "1011"),
                ]
            })
        )
    );
}

#[test]
fn parse_structured_data_no_values() {
    assert_eq!(
        structured_datum("[exampleSDID@32473]").unwrap(),
        (
            "",
            Some(StructuredElement {
                id: "exampleSDID@32473",
                params: vec![]
            })
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
            Some(StructuredElement {
                id: "exampleSDID@32473",
                params: vec![
                    ("iut", "3"),
                    ("eventSource", "Application"),
                    ("eventID", "1011"),
                ]
            })
        )
    );
}

#[test]
fn parse_invalid_structured_data() {
    assert_eq!(structured_datum("[exampleSDID@32473 iut=]"), Ok(("", None)));
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

    #[test]
    fn parse_structured_data_ignores_invalid_elements() {
        assert_eq!(
            structured_data("[abc][id aa=]").unwrap(),
            (
                "",
                vec![StructuredElement {
                    id: "abc",
                    params: vec![],
                },]
            )
        )
    }

    #[test]
    fn parse_multiple_structured_data_first_item_id_only() {
        assert_eq!(
            structured_data("[abc][id aa=\"bb\"]").unwrap(),
            (
                "",
                vec![
                    StructuredElement {
                        id: "abc",
                        params: vec![],
                    },
                    StructuredElement {
                        id: "id",
                        params: vec![("aa", "bb")],
                    },
                ]
            )
        )
    }
}
