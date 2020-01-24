use quickcheck::{Arbitrary, Gen};
use rand::Rng;

trait FilterChars {
    fn valid(c: char) -> bool;
}

fn gen_string<G, F>(g: &mut G, valid_char: F) -> String
where
    G: Gen,
    F: Fn(char) -> bool,
{
    let size = {
        let s = g.size();
        g.gen_range(1, s)
    };

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

pub(crate) fn gen_str<G: Gen>(g: &mut G) -> Option<String> {
    let value: Option<NoColonString> = Arbitrary::arbitrary(g);
    value.map(|s| s.get_str())
}

macro_rules! arbitrary_string {
    ($name: ident, $filter: expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $name(pub String);

        impl $name {
            pub(crate) fn get_str(self) -> String {
                let $name(value) = self;
                value
            }
        }

        impl Arbitrary for $name {
            fn arbitrary<G: Gen>(g: &mut G) -> $name {
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
    !c.is_whitespace() && !c.is_control() && c.is_ascii() && c != ']' && c != '='
});

// Technically ] and " values need to be escaped, but we will ignore them for quickcheck.
arbitrary_string!(ValueString, |c: char| {
    !c.is_whitespace() && !c.is_control() && c.is_ascii() && c != ']' && c != '"' && c != '\\'
});

// Header fields can't contain a : as this is a sign the message is about to start. 
arbitrary_string!(NoColonString, |c: char| {
    !c.is_whitespace() && !c.is_control() && c.is_ascii() && c != ':'
});
