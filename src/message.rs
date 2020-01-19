use crate::pri::{compose_pri, SyslogFacility, SyslogSeverity};
use crate::structured_data;
use chrono::prelude::*;
use std::fmt;


#[cfg(test)]
use crate::non_empty_string::gen_str;
#[cfg(test)]
use crate::pri::decompose_pri;
#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Protocol {
    RFC3164,
    RFC5424(u32),
}

#[derive(Clone, Debug)]
pub struct Message<S: AsRef<str> + Ord + PartialEq + Clone> {
    pub protocol: Protocol,
    pub facility: Option<SyslogFacility>,
    pub severity: Option<SyslogSeverity>,
    pub timestamp: Option<DateTime<FixedOffset>>,
    pub hostname: Option<S>,
    pub appname: Option<S>,
    pub procid: Option<S>,
    pub msgid: Option<S>,
    pub structured_data: Vec<structured_data::StructuredElement<S>>,
    pub msg: S,
}

impl<S: AsRef<str> + Ord + PartialEq + Clone> fmt::Display for Message<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let empty = "-".to_string();
        
        write!(
            f,
            "<{}>{} {} {} {} {} {} ",
            compose_pri(
                self.facility.unwrap_or(SyslogFacility::LOG_SYSLOG),
                self.severity.unwrap_or(SyslogSeverity::SEV_DEBUG)
            ),
            match self.protocol {
                Protocol::RFC3164 => "".to_string(),
                Protocol::RFC5424(version) => version.to_string()
            },
            self.timestamp.unwrap_or(Utc::now().into()).to_rfc3339(),
            self.hostname
                .as_ref()
                .map(|s| s.as_ref())
                .unwrap_or(&empty),
            self.appname
                .as_ref()
                .map(|s| s.as_ref())
                .unwrap_or(&empty),
            self.procid
                .as_ref()
                .map(|s| s.as_ref())
                .unwrap_or(&empty),
            self.msgid
                .as_ref()
                .map(|s| s.as_ref())
                .unwrap_or(&empty),
        )?;

        if self.structured_data.len() == 0 {
            if let Protocol::RFC5424(_) = self.protocol {
                write!(f, "-")?;
            }
        } else {
            for elem in &self.structured_data {
                write!(f, "{}", elem)?;
            }
        }

        write!(f, " {}", self.msg.as_ref())
    }
}

impl<S: AsRef<str> + Ord + Clone> PartialEq for Message<S> {
    fn eq(&self, other: &Self) -> bool {
        self.facility == other.facility
            && self.severity == other.severity
            && self.timestamp == other.timestamp
            && self.hostname == other.hostname
            && self.appname == other.appname
            && self.procid == other.procid
            && self.msgid == other.msgid
            && self.structured_data == other.structured_data
            && self.msg == other.msg
    }
}

impl From<Message<&str>> for Message<String> {
    fn from(message: Message<&str>) -> Self {
        Message {
            facility: message.facility,
            severity: message.severity,
            timestamp: message.timestamp,
            hostname: message.hostname.map(|s| s.to_string()),
            appname: message.appname.map(|s| s.to_string()),
            procid: message.procid.map(|s| s.to_string()),
            msgid: message.msgid.map(|s| s.to_string()),
            protocol: message.protocol,
            structured_data: message
                .structured_data
                .iter()
                .map(|e| e.clone().into())
                .collect(),
            msg: message.msg.to_string(),
        }
    }
}



#[cfg(test)]
impl Arbitrary for Message<String> {
    fn arbitrary<G: Gen>(g: &mut G) -> Message<String> {
        let (facility, severity) = decompose_pri(Arbitrary::arbitrary(g));

        Message {
            facility,
            severity,
            timestamp: Some(Utc.timestamp(Arbitrary::arbitrary(g), 0).into()),
            hostname: gen_str(g),
            appname: gen_str(g),
            procid: gen_str(g),
            msgid: gen_str(g),
            protocol: Protocol::RFC5424(1),
            structured_data: Arbitrary::arbitrary(g),
            msg: Arbitrary::arbitrary(g),
        }
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Message<String>>> {
        let timestamp = self.timestamp;
        let facility = self.facility;
        let severity = self.severity;
        let protocol = self.protocol.clone();
 
        Box::new(
            (
                self.hostname.clone(),
                self.appname.clone(),
                self.procid.clone(),
                self.msgid.clone(),
                self.structured_data.clone(),
                self.msg.clone(),
            )
                .shrink()
                .map(move |(hostname, appname, procid, msgid, structured_data, msg)| Message {
                    facility,
                    severity,
                    timestamp,
                    hostname,
                    appname,
                    procid,
                    msgid,
                    protocol: protocol.clone(),
                    structured_data,
                    msg,
                }),
        )
    }
}
