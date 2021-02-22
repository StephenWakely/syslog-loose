use quickcheck::{Arbitrary, Gen};
use std::num::NonZeroU8;

trait FilterChars {
    fn valid(c: char) -> bool;
}

fn gen_string<F>(g: &mut Gen, valid_char: F) -> String
where
    F: Fn(char) -> bool,
{
    // We generate an arbitrary `u16` and then pad it out to usize to avoid
    // quickcheck trying to make truly huge allocations.
    let size = NonZeroU8::arbitrary(g).get() as usize;

    let mut s = String::with_capacity(size);
    let mut c = 0;
    let mut chr = char::arbitrary(g);

    while c < size {
        if valid_char(chr) {
            s.push(chr);
            c += 1;
        }
        chr = char::arbitrary(g);
    }

    s
}

pub(crate) trait ArbitraryString {
    fn get_str(self) -> String;
}

macro_rules! arbitrary_string {
    ($name: ident, $filter: expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $name(pub String);

        impl ArbitraryString for $name {
            fn get_str(self) -> String {
                let $name(value) = self;
                value
            }
        }

        impl Arbitrary for $name {
            fn arbitrary(g: &mut Gen) -> $name {
                let s = gen_string(g, $filter);
                $name(s)
            }

            fn shrink(&self) -> Box<dyn Iterator<Item = $name>> {
                // Shrink a string by shrinking a vector of its characters.
                let string = self.clone().get_str();

                Box::new(
                    string
                        .shrink()
                        .map(|x: String| {
                            let mut s: String = String::new();
                            for c in x.chars() {
                                if $filter(c) {
                                    s.push(c);
                                }
                            }
                            s
                        })
                        .filter(|x| x.len() > 5)
                        .map(|x| $name(x)),
                )
            }
        }
    };
}

arbitrary_string!(NonEmptyString, |c: char| {
    !c.is_whitespace() && !c.is_control() && c.is_ascii()
});

// Structured data names cannot contain ] = or whitespace
arbitrary_string!(NameString, |c: char| {
    !c.is_whitespace() && !c.is_control() && c.is_ascii() && c != ']' && c != '=' && c != '-'
});

// Technically ] and " values need to be escaped, but we will ignore them for quickcheck.
arbitrary_string!(ValueString, |c: char| {
    !c.is_whitespace()
        && !c.is_control()
        && c.is_ascii()
        && c != ']'
        && c != '"'
        && c != '\\'
        && c != '-'
});

// App names can't have a [ in them as this means the start of the procid
arbitrary_string!(AppNameString, |c: char| {
    !c.is_whitespace() && !c.is_control() && c.is_ascii() && c != '[' && c != ':' && c != '-'
});

// hostnames can't have a [ or a :
arbitrary_string!(HostNameString, |c: char| {
    !c.is_whitespace() && !c.is_control() && c.is_ascii() && c != '[' && c != ':'
});

// ProcIds can't have a ] or a :
arbitrary_string!(ProcIdString, |c: char| {
    !c.is_whitespace() && !c.is_control() && c.is_ascii() && c != ']' && c != ':' && c != '-'
});

// Header fields can't contain a : as this is a sign the message is about to start.
arbitrary_string!(NoColonString, |c: char| {
    !c.is_whitespace() && !c.is_control() && c.is_ascii() && c != ':' && c != '-'
});
