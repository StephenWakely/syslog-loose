///! Parsers shared by both protocols.
use nom;
use nom::character::complete::digit1;
use std::str::FromStr;

named!(pub(crate) u8_digits<&str, u8>, map_res!(digit1, FromStr::from_str));
named!(pub(crate) i8_digits<&str, i8>, map_res!(digit1, FromStr::from_str));
named!(pub(crate) u32_digits<&str, u32>, map_res!(digit1, FromStr::from_str));
named!(pub(crate) i32_digits<&str, i32>, map_res!(digit1, FromStr::from_str));

named!(optional(&str) -> Option<&str>,
       do_parse! (
           // Note we need to use the ':' as a separator between the 3164 headers and the message.
           // So the header fields can't use them. Need to be aware of this to check 
           // if this will be an issue.
           value: take_while!(|c: char| !c.is_whitespace() && c != ':') >>
           ( if value == "-" || value == "" {
               None
             } else {
               Some(value)
             })
       ));


// Parse the host name or ip address.
named!(pub(crate) hostname(&str) -> Option<&str>, call!(optional));

// Parse the app name
named!(pub(crate) appname(&str) -> Option<&str>, call!(optional));

// Parse the Process Id
named!(pub(crate) procid(&str) -> Option<&str>, call!(optional));

// Parse the Message Id
named!(pub(crate) msgid(&str) -> Option<&str>, call!(optional));

