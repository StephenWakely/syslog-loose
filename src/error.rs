use std::{error, fmt};

/// Wrap nom errors with our own
#[derive(Debug)]
pub struct ParseError<'a>(pub nom::Err<(&'a str, nom::error::ErrorKind)>);

impl<'a> fmt::Display for ParseError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ParseError(err) = self;
        write!(f, "{:#?}", err)
    }
}

impl<'a> error::Error for ParseError<'a> {}
