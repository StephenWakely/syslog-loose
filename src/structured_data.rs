use nom::{
    branch::alt,
    bytes::complete::{escaped, tag, take_till1, take_until, take_while1},
    character::complete::{anychar, space0},
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

pub struct ParamsIter<'a, S: AsRef<str>> {
    pos: usize,
    params: &'a Vec<(S, S)>,
}

impl<S: AsRef<str> + Ord + Clone> StructuredElement<S> {
    /// Since we parse the message without any additional allocations, we can't parse out the
    /// escapes during parsing as that would require allocating an extra string to store the
    /// stripped version.
    /// So params returns an iterator that will allocate and return a string with the escapes
    /// stripped out.
    pub fn params(&self) -> ParamsIter<'_, S> {
        ParamsIter {
            pos: 0,
            params: &self.params,
        }
    }
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

        let mut params2 = other.params.clone();
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

impl<'a, S: AsRef<str> + Ord + Clone> Iterator for ParamsIter<'a, S> {
    type Item = (&'a S, String);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.params.len() {
            None
        } else {
            let (key, value) = &self.params[self.pos];
            self.pos += 1;
            let mut trimmed = String::with_capacity(value.as_ref().len());
            let mut escaped = false;
            for c in value.as_ref().chars() {
                if c == '\\' && !escaped {
                    escaped = true;
                } else if c == 'n' && escaped {
                    escaped = false;
                    trimmed.push('\n');
                } else if c != '"' && c != ']' && c != '\\' && escaped {
                    // If the character following the escape isn't a \, " or ] we treat it like an normal unescaped character.
                    escaped = false;
                    trimmed.push('\\');
                    trimmed.push(c);
                } else {
                    escaped = false;
                    trimmed.push(c);
                }
            }
            Some((key, trimmed))
        }
    }
}

/// Parse the param value - a string delimited by '"' - '\' escapes \ and "
fn param_value(input: &str) -> IResult<&str, &str> {
    alt((
        // We need to handle an empty string separately since `escaped`
        // doesn't work unless it has some input.
        map(tag(r#""""#), |_| ""),
        delimited(
            tag("\""),
            escaped(take_while1(|c: char| c != '\\' && c != '"'), '\\', anychar),
            tag("\""),
        ),
    ))(input)
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
fn structured_datum_strict(input: &str) -> IResult<&str, Option<StructuredElement<&str>>> {
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
    )(input)
}

/// Parse a single structured data record allowing anything between brackets.
fn structured_datum_permissive(input: &str) -> IResult<&str, Option<StructuredElement<&str>>> {
    alt((
        structured_datum_strict,
        // If the element fails to parse, just parse it and return None.
        delimited(tag("["), map(take_until("]"), |_| None), tag("]")),
    ))(input)
}

/// Parse a single structured data record.
fn structured_datum(
    allow_failure: bool,
) -> impl FnMut(&str) -> IResult<&str, Option<StructuredElement<&str>>> {
    if allow_failure {
        structured_datum_permissive
    } else {
        structured_datum_strict
    }
}

/// Parse multiple structured data elements.
pub(crate) fn structured_data(input: &str) -> IResult<&str, Vec<StructuredElement<&str>>> {
    structured_data_optional(true)(input)
}

/// Parse multiple structured data elements.
pub(crate) fn structured_data_optional(
    allow_failure: bool,
) -> impl FnMut(&str) -> IResult<&str, Vec<StructuredElement<&str>>> {
    move |input| {
        alt((
            map(tag("-"), |_| vec![]),
            map(many1(structured_datum(allow_failure)), |items| {
                items.iter().filter_map(|item| item.clone()).collect()
            }),
        ))(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_param_value() {
        assert_eq!(
            param_value("\"Some \\\"lovely\\\" string\"").unwrap(),
            ("", "Some \\\"lovely\\\" string")
        );
    }

    #[test]
    fn parse_empty_param_value() {
        assert_eq!(param_value(r#""""#).unwrap(), ("", ""));
    }

    #[test]
    fn parse_structured_data() {
        assert_eq!(
            structured_datum_strict(
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
            structured_datum(false)("[exampleSDID@32473]").unwrap(),
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
            structured_datum(false)(
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
        assert_eq!(
            structured_datum(true)("[exampleSDID@32473 iut=]"),
            Ok(("", None))
        );
    }

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
    fn parse_structured_data_keep_invalid_elements() {
        assert_eq!(
            structured_data_optional(false)("[abc][id aa=]").unwrap(),
            (
                "[id aa=]",
                vec![StructuredElement {
                    id: "abc",
                    params: vec![],
                },]
            )
        )
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

    #[test]
    fn params_remove_escapes() {
        let data = structured_data(
            r#"[id aa="hullo \"there\"" bb="let's \\\\do this\\\\" cc="hello [bye\]" dd="hello\nbye" ee="not \esc\aped"]"#,
        )
        .unwrap();
        let params = data.1[0].params().collect::<Vec<_>>();

        assert_eq!(
            params,
            vec![
                (&"aa", r#"hullo "there""#.to_string()),
                (&"bb", r#"let's \\do this\\"#.to_string(),),
                (&"cc", r#"hello [bye]"#.to_string(),),
                (
                    &"dd",
                    r#"hello
bye"#
                        .to_string(),
                ),
                (&"ee", r#"not \esc\aped"#.to_string())
            ]
        );
    }

    #[test]
    fn sd_param_escapes() {
        let (_, value) = param_value(r#""Here are some escaped characters -> \"\\\]""#).unwrap();
        assert_eq!(r#"Here are some escaped characters -> \"\\\]"#, value);

        let (_, value) = param_value(r#""These should not be escaped -> \n\m\o""#).unwrap();
        assert_eq!(r#"These should not be escaped -> \n\m\o"#, value);
    }
}
