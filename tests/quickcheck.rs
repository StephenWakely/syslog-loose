#![cfg(feature = "quickcheck")]
extern crate quickcheck;
extern crate quickcheck_macros;

mod non_empty_string;

use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::prelude::*;
use non_empty_string::{
    AppNameString, ArbitraryString, HostNameString, NameString, NoColonString, ProcIdString,
    ValueString,
};
use quickcheck::{Arbitrary, Gen, QuickCheck, TestResult};
use syslog_loose::{
    decompose_pri, parse_message, Message, ProcId, Protocol, StructuredElement, Variant,
};

/// Create a wrapper struct for us to implement Arbitrary against
#[derive(Clone, Debug)]
struct Wrapper<A>(A);

impl<A> Wrapper<A> {
    fn unwrap(self) -> A {
        let Wrapper(value) = self;
        value
    }
}

pub(crate) fn gen_str<A>(g: &mut Gen) -> Option<String>
where
    A: Arbitrary + ArbitraryString,
{
    let value: Option<A> = Arbitrary::arbitrary(g);
    value.map(|s| s.get_str())
}

impl Arbitrary for Wrapper<Message<String>> {
    fn arbitrary(g: &mut Gen) -> Wrapper<Message<String>> {
        // RFC 5424 defines the priority as being a byte sized numeric from 0 to
        // 191 inclusive. Modulo will bias the resulting priority toward the
        // first 65 priorities. It's unfortunate that `Gen` doesn't expose its
        // `gen_range` function, but alas.
        let priority: u8 = u8::arbitrary(g) % 192;
        let (facility, severity) = decompose_pri(priority);
        let msg: String = Arbitrary::arbitrary(g);
        let structured_data: Vec<Wrapper<StructuredElement<String>>> = Arbitrary::arbitrary(g);
        let protocol = if Arbitrary::arbitrary(g) {
            Protocol::RFC3164
        } else {
            Protocol::RFC5424(1)
        };

        let (appname, procid, msgid) = match protocol {
            Protocol::RFC3164 => {
                // 3164 cant have a procid without an app name
                // Also no Msg Id
                let appname = gen_str::<AppNameString>(g);
                let procid = match appname {
                    None => None,
                    Some(_) => {
                        let procid: Wrapper<ProcId<String>> = Arbitrary::arbitrary(g);
                        Some(procid.unwrap())
                    }
                };
                (appname, procid, None)
            }
            Protocol::RFC5424(_) => (
                gen_str::<NoColonString>(g),
                {
                    let procid: Option<Wrapper<ProcId<String>>> = Arbitrary::arbitrary(g);
                    procid.map(|p| p.unwrap())
                },
                gen_str::<NoColonString>(g),
            ),
        };

        let hostname = match u8::arbitrary(g) % 3 {
            0 => gen_str::<HostNameString>(g),
            1 => Some(Ipv4Addr::arbitrary(g).to_string()),
            _ => Some(Ipv6Addr::arbitrary(g).to_string()),
        };

        // Timestamp seconds are i64 in chrono but the parse function will panic
        // if `nsecs` is out of range. This happens when `nsecs` is equivalent
        // to a number of days greater than the `i32::MAX`. If we limit `secs`
        // to i32 itself this can't happen.
        let secs: i32 = i32::arbitrary(g);
        Wrapper(Message {
            facility,
            severity,
            timestamp: Some(Utc.timestamp_opt(secs as i64, 0).unwrap().into()),
            hostname,
            appname,
            procid,
            msgid,
            protocol,
            structured_data: structured_data.iter().map(|s| s.clone().unwrap()).collect(),
            msg: msg.trim().into(),
        })
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Wrapper<Message<String>>>> {
        let message = self.clone().unwrap();
        let timestamp = message.timestamp;
        let facility = message.facility;
        let severity = message.severity;
        let protocol = message.protocol.clone();
        let structured_data: Vec<Wrapper<StructuredElement<String>>> = message
            .structured_data
            .iter()
            .map(|s| Wrapper(s.clone()))
            .collect();

        Box::new(
            (
                message.hostname.clone().map(HostNameString),
                message.appname.clone().map(AppNameString),
                message.procid.clone().map(Wrapper),
                message.msgid.clone().map(NoColonString),
                structured_data,
                message.msg.clone(),
            )
                .shrink()
                .map(
                    move |(hostname, appname, procid, msgid, structured_data, msg)| {
                        // Make sure procid doesnt shrink down to something without
                        // the appname for 3164.
                        let procid = match (&appname, &protocol) {
                            (_, Protocol::RFC5424(_)) => procid,
                            (None, Protocol::RFC3164) => None,
                            _ => procid,
                        };

                        Wrapper(Message {
                            facility,
                            severity,
                            timestamp,
                            hostname: hostname.clone().map(|s| s.get_str()),
                            appname: appname.clone().map(|s| s.get_str()),
                            procid: procid.clone().map(|s| s.unwrap()),
                            msgid: msgid.clone().map(|s| s.get_str()),
                            protocol: protocol.clone(),
                            structured_data: structured_data
                                .iter()
                                .map(|s| s.clone().unwrap())
                                .collect(),
                            msg: msg.trim().into(),
                        })
                    },
                ),
        )
    }
}

impl Arbitrary for Wrapper<ProcId<String>> {
    fn arbitrary(g: &mut Gen) -> Wrapper<ProcId<String>> {
        Wrapper(if Arbitrary::arbitrary(g) {
            ProcId::PID(Arbitrary::arbitrary(g))
        } else {
            loop {
                let name: ProcIdString = Arbitrary::arbitrary(g);
                let ProcIdString(inner) = &name;
                // A `ProdIdString` is ambiguous to the parser if it's all digit
                // characters, like "8". We have try to parse the result into an
                // i32 and if it succeeds then this generated ProcIdString will
                // be confused for a ProdId::PID on parsing.
                let is_ambiguous = inner.parse::<i32>().is_ok();
                if !is_ambiguous {
                    break ProcId::Name(name.get_str());
                }
            }
        })
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Wrapper<ProcId<String>>>> {
        let procid = self.clone().unwrap();

        match procid {
            ProcId::PID(pid) => Box::new(pid.shrink().map(|pid| Wrapper(ProcId::PID(pid)))),

            ProcId::Name(name) => Box::new(
                ProcIdString(name)
                    .shrink()
                    .map(|name| Wrapper(ProcId::Name(name.get_str()))),
            ),
        }
    }
}

impl Arbitrary for Wrapper<StructuredElement<String>> {
    fn arbitrary(g: &mut Gen) -> Wrapper<StructuredElement<String>> {
        let params: Vec<(NameString, ValueString)> = Arbitrary::arbitrary(g);
        let id: NameString = Arbitrary::arbitrary(g);

        Wrapper(StructuredElement {
            id: id.get_str(),
            params: params
                .iter()
                .map(|(key, value)| (key.clone().get_str(), value.clone().get_str()))
                .collect(),
        })
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Wrapper<StructuredElement<String>>>> {
        let element = self.clone().unwrap();
        Box::new(
            (
                NameString(element.id.clone()),
                element
                    .params
                    .iter()
                    .map(|(name, value)| ((NameString(name.clone()), ValueString(value.clone()))))
                    .collect(),
            )
                .shrink()
                .map(
                    |(id, params): (NameString, Vec<(NameString, ValueString)>)| {
                        Wrapper(StructuredElement {
                            id: id.get_str(),
                            params: params
                                .iter()
                                .map(|(name, value)| {
                                    (name.clone().get_str(), value.clone().get_str())
                                })
                                .collect(),
                        })
                    },
                ),
        )
    }
}

// assume that Some("-") is equivalent to None
fn is_same_hostname(expected: Option<String>, parsed: Option<String>) -> bool {
    expected == parsed
        || (expected == Some("-".into()) && parsed.is_none())
        || (expected.is_none() && parsed == Some("-".into()))
}

fn inner_parses_generated_messages(msg: Wrapper<Message<String>>) -> TestResult {
    let msg: Message<String> = msg.unwrap();

    // Display the message.
    let text = format!("{}", msg);

    // Parse it.
    let parsed: Message<&str> = parse_message(&text, Variant::Either);
    let parsed = parsed.into();
    let result = msg == parsed;

    if !result {
        println!("msg: {:#?}\ntext: {}\nparsed: {:#?}", msg, text, parsed);
    }

    assert_eq!(msg.protocol, parsed.protocol);
    assert_eq!(msg.facility, parsed.facility);
    assert_eq!(msg.severity, parsed.severity);
    assert_eq!(msg.timestamp, parsed.timestamp);
    assert!(is_same_hostname(msg.hostname, parsed.hostname));
    assert_eq!(msg.appname, parsed.appname);
    assert_eq!(msg.procid, parsed.procid);
    assert_eq!(msg.msgid, parsed.msgid);
    assert_eq!(msg.structured_data, parsed.structured_data);
    assert_eq!(msg.msg, parsed.msg);

    // Do we still have the same message?
    quickcheck::TestResult::from_bool(result)
}

#[test]
fn parses_generated_messages() {
    QuickCheck::new()
        .min_tests_passed(1_000)
        .tests(2_000)
        .max_tests(10_000)
        .quickcheck(inner_parses_generated_messages as fn(Wrapper<Message<String>>) -> TestResult);
}
