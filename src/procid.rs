use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum ProcId<S: AsRef<str> + Ord + PartialEq + Clone> {
    PID(i32),
    Name(S),
}

impl<S: AsRef<str> + Ord + PartialEq + Clone> fmt::Display for ProcId<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcId::PID(pid) => write!(f, "{}", pid),
            ProcId::Name(name) => write!(f, "{}", name.as_ref()),
        }
    }
}

impl From<ProcId<&str>> for ProcId<String> {
    fn from(procid: ProcId<&str>) -> Self {
        match procid {
            ProcId::PID(pid) => ProcId::PID(pid),
            ProcId::Name(name) => ProcId::Name(name.to_string()),
        }
    }
}

impl<'a> From<&'a str> for ProcId<&'a str> {
    fn from(s: &str) -> ProcId<&str> {
        match s.parse() {
            Ok(pid) => ProcId::PID(pid),
            Err(_) => ProcId::Name(s),
        }
    }
}
