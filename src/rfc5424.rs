use crate::header::Header;
use crate::parsers::{appname, hostname, msgid, pri, procid, u32_digits};
///! Parsers for rfc 5424 specific formats.
use chrono::prelude::*;
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
                   do_parse!( id: take_until!(" ") >>
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

// The timestamp for 5424 messages yyyy-mm-ddThh:mm:ss.mmmmZ
named!(timestamp(&str) -> DateTime<FixedOffset>,
       map_res!(take_until!(" "), chrono::DateTime::parse_from_rfc3339)
);

// Parse the version number - just a simple integer.
named!(version(&str) -> u32,
       do_parse!( version: u32_digits >>
                  (version)
       ));

// Parse the full 5424 header
named!(pub(crate) header(&str) -> Header,
       do_parse! (
           pri: pri >>
           version: version >>
           space1 >>
           timestamp: timestamp >>
           space1 >>
           hostname: hostname >>
           space1 >>
           appname: appname >>
           space1 >>
           procid: procid >>
           space1 >>
           msgid: msgid >>

           (Header { pri,
                     version: Some(version),
                     timestamp: Some(timestamp),
                     hostname,
                     appname,
                     procid,
                     msgid,
           })
       ));

#[test]
fn parse_timestamp_5424() {
    assert_eq!(
        timestamp("1985-04-12T23:20:50.52Z ").unwrap(),
        (
            " ",
            FixedOffset::east(0)
                .ymd(1985, 4, 12)
                .and_hms_milli(23, 20, 50, 520)
        )
    );

    assert_eq!(
        timestamp("1985-04-12T23:20:50.52-07:00 ").unwrap(),
        (
            " ",
            FixedOffset::west(7 * 3600)
                .ymd(1985, 4, 12)
                .and_hms_milli(23, 20, 50, 520)
        )
    );

    assert_eq!(
        timestamp("2003-10-11T22:14:15.003Z ").unwrap(),
        (
            " ",
            FixedOffset::west(0)
                .ymd(2003, 10, 11)
                .and_hms_milli(22, 14, 15, 3),
        )
    )
}

named!(esc(&str) -> &str,
       escaped!(
           take_while1!(|c: char| c.is_numeric() )
       , '\\', one_of!("\"n\\")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_5424_header() {
        assert_eq!(
            header("<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 ").unwrap(),
            (
                " ",
                Header {
                    pri: 34,
                    version: Some(1),
                    timestamp: Some(
                        FixedOffset::west(0)
                            .ymd(2003, 10, 11)
                            .and_hms_milli(22, 14, 15, 3)
                    ),
                    hostname: Some("mymachine.example.com"),
                    appname: Some("su"),
                    procid: None,
                    msgid: Some("ID47"),
                }
            )
        )
    }
}
