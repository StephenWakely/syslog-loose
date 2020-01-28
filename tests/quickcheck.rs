extern crate quickcheck;
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

mod non_empty_string;

use non_empty_string::{gen_str, NameString, NoColonString, ValueString};
use chrono::prelude::*;
use quickcheck::{Arbitrary, Gen};
use syslog_loose::{decompose_pri, parse_message, Message, Protocol, StructuredElement};

/// Create a wrapper struct for us to implement Arbitrary against 
#[derive(Clone, Debug)]
struct Wrapper<A>(A);

impl<A> Wrapper<A> {
    fn unwrap(self) -> A {
        let Wrapper(value) = self;
        value
    }
}

impl Arbitrary for Wrapper<Message<String>> {
    fn arbitrary<G: Gen>(g: &mut G) -> Wrapper<Message<String>> {
        let (facility, severity) = decompose_pri(Arbitrary::arbitrary(g));
        let msg: String = Arbitrary::arbitrary(g);
        let structured_data: Vec<Wrapper<StructuredElement<String>>> = Arbitrary::arbitrary(g);

        Wrapper(Message {
            facility,
            severity,
            timestamp: Some(Utc.timestamp(Arbitrary::arbitrary(g), 0).into()),
            hostname: gen_str(g),
            appname: gen_str(g),
            procid: gen_str(g),
            msgid: gen_str(g),
            protocol: Protocol::RFC5424(1),
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
                message.hostname.clone().map(NoColonString),
                message.appname.clone().map(NoColonString),
                message.procid.clone().map(NoColonString),
                message.msgid.clone().map(NoColonString),
                structured_data,
                message.msg.clone(),
            )
                .shrink()
                .map(
                    move |(hostname, appname, procid, msgid, structured_data, msg)| {
                        Wrapper(Message {
                            facility,
                            severity,
                            timestamp,
                            hostname: hostname.clone().map(|s| s.get_str()),
                            appname: appname.clone().map(|s| s.get_str()),
                            procid: procid.clone().map(|s| s.get_str()),
                            msgid: msgid.clone().map(|s| s.get_str()),
                            protocol: protocol.clone(),
                            structured_data: structured_data.iter().map(|s| s.clone().unwrap()).collect(),
                            msg: msg.trim().into(),
                        })
                    },
                ),
        )
    }
}

impl Arbitrary for Wrapper<StructuredElement<String>> {
    fn arbitrary<G: Gen>(g: &mut G) -> Wrapper<StructuredElement<String>> {
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
                element.params
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

#[quickcheck]
fn quickcheck_parses_generated_messages(msg: Wrapper<Message<String>>) -> quickcheck::TestResult {
    let msg = msg.unwrap();
    
    // Display the message.
    let text = format!("{}", msg);

    // Parse it.
    let parsed = parse_message(&text);
    let parsed = parsed.into();
    let result = msg == parsed;

    if !result {
        println!("{:#?}", msg);
        println!("{}", text);
        println!("{:#?}", parsed);
    }

    // Do we still have the same message?
    quickcheck::TestResult::from_bool(result)
}
