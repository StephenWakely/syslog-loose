use quickcheck::{Arbitrary, Gen};
use rand::Rng;
use std::iter::FromIterator;

/// A struct that allows us to generate arbitrary values for strings that do not contain whitespace. 
/// Most fields in the syslog message can be assumed to not contain whitespace as this is what
/// used to delimit the fields.
#[derive(Clone)]
pub struct NonEmptyString(String);

impl NonEmptyString {
    pub(crate) fn get_str(self) -> String {
        let NonEmptyString(value) = self;
        value
    }
}

impl FromIterator<char> for NonEmptyString {
    fn from_iter<I: IntoIterator<Item = char>>(iter: I) -> NonEmptyString {
        let string = String::from_iter(iter);
        NonEmptyString(string)
    }
}

impl Arbitrary for NonEmptyString {
    fn arbitrary<G: Gen>(g: &mut G) -> NonEmptyString {
        let size = {
            let s = g.size();
            g.gen_range(1, s)
        };
        let mut s = String::with_capacity(size);
        let mut c = 0;
        let chr = char::arbitrary(g);
        
        while c < size {
            if chr.is_ascii() {
                s.push(char::arbitrary(g));
                c += 1; 
            }
        }
        NonEmptyString(s)
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = NonEmptyString>> {
        // Shrink a string by shrinking a vector of its characters.
        let string = self.clone().get_str();
        let chars: Vec<char> = string.chars().collect();
        Box::new(chars.shrink().map(|x| x.into_iter().collect::<NonEmptyString>()))
    }
}

pub(crate) fn gen_str<G: Gen>(g: &mut G) -> Option<String> {
    let value:Option<NonEmptyString> = Arbitrary::arbitrary(g);
    value.map(|s| s.get_str())
}
