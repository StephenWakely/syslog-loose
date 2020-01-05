use nom::character::complete::space1;

#[derive(Debug, PartialEq, Eq)]
pub struct StructuredElement<'a> {
    pub id: &'a str,
    pub params: Vec<(&'a str, &'a str)>,
}

// Parse the param value - a string delimited by '"' - '\' escapes \ and "
named!(param_value(&str) -> &str,
       delimited!( char!('"'),
                   escaped!(take_while1!(|c: char| {
                       c != '\\' && c != '"'
                   }), '\\', one_of!("\"n\\")),
                   char!('"')
       ));

// Parse a param name="value"
named!(param(&str) -> (&str, &str),
       separated_pair!( take_until!("="),
                        tag!("="),
                        call!(param_value)
       ));

// Parse a single structured data record.
// [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]
named!(structured_datum(&str) -> StructuredElement,
       delimited!( char!('['),
                   do_parse!( id: take_till1!(|c: char| c.is_whitespace() || c == '=') >>
                              space1 >>
                              params: separated_list!(tag!(" "),
                                                      call!(param)) >>
                              ( StructuredElement { id, params })),
                   char!(']')
       ));

// Parse multiple structured data elements.
named!(pub(crate) structured_data(&str) -> Vec<StructuredElement>,
       alt!( do_parse!(tag!("-") >> (vec![]) ) |
             many1!(structured_datum)
       ));

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
