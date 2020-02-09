extern crate quickcheck;
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

mod non_empty_string;

use chrono::prelude::*;
use non_empty_string::{
    AppNameString, ArbitraryString, HostNameString, NameString, NoColonString, ProcIdString,
    ValueString,
};
use quickcheck::{Arbitrary, Gen};
use syslog_loose::{decompose_pri, parse_message, Message, ProcId, Protocol, StructuredElement};

/// Create a wrapper struct for us to implement Arbitrary against
#[derive(Clone, Debug)]
struct Wrapper<A>(A);

impl<A> Wrapper<A> {
    fn unwrap(self) -> A {
        let Wrapper(value) = self;
        value
    }
}

pub(crate) fn gen_str<G, A>(g: &mut G) -> Option<String>
where
    G: Gen,
    A: Arbitrary + ArbitraryString,
{
    let value: Option<A> = Arbitrary::arbitrary(g);
    value.map(|s| s.get_str())
}

impl Arbitrary for Wrapper<Message<String>> {
    fn arbitrary<G: Gen>(g: &mut G) -> Wrapper<Message<String>> {
        let (facility, severity) = decompose_pri(Arbitrary::arbitrary(g));
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
                let appname = gen_str::<G, AppNameString>(g);
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
                gen_str::<G, NoColonString>(g),
                {
                    let procid: Option<Wrapper<ProcId<String>>> = Arbitrary::arbitrary(g);
                    procid.map(|p| p.unwrap())
                },
                gen_str::<G, NoColonString>(g),
            ),
        };

        Wrapper(Message {
            facility,
            severity,
            timestamp: Some(Utc.timestamp(Arbitrary::arbitrary(g), 0).into()),
            hostname: gen_str::<G, HostNameString>(g),
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
    fn arbitrary<G: Gen>(g: &mut G) -> Wrapper<ProcId<String>> {
        Wrapper(if Arbitrary::arbitrary(g) {
            ProcId::PID(Arbitrary::arbitrary(g))
        } else {
            let name: ProcIdString = Arbitrary::arbitrary(g);
            ProcId::Name(name.get_str())
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
