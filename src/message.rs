use crate::pri::{compose_pri, SyslogFacility, SyslogSeverity};
use crate::procid::ProcId;
use crate::structured_data;
use chrono::prelude::*;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
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
    pub procid: Option<ProcId<S>>,
    pub msgid: Option<S>,
    pub structured_data: Vec<structured_data::StructuredElement<S>>,
    pub msg: S,
}

impl<S: AsRef<str> + Ord + PartialEq + Clone> fmt::Display for Message<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let empty = "-".to_string();

        write!(
            f,
            "<{}>{} {} {} ",
            compose_pri(
                self.facility.unwrap_or(SyslogFacility::LOG_SYSLOG),
                self.severity.unwrap_or(SyslogSeverity::SEV_DEBUG)
            ),
            match self.protocol {
                Protocol::RFC3164 => "".to_string(),
                Protocol::RFC5424(version) => version.to_string(),
            },
            self.timestamp
                .unwrap_or_else(|| Utc::now().into())
                .to_rfc3339(),
            self.hostname.as_ref().map(|s| s.as_ref()).unwrap_or(&empty)
        )?;

        match self.protocol {
            Protocol::RFC5424(_) => {
                write!(
                    f,
                    "{} ",
                    self.appname.as_ref().map(|s| s.as_ref()).unwrap_or(&empty)
                )?;
                match &self.procid {
                    None => write!(f, "- ")?,
                    Some(procid) => write!(f, "{} ", procid)?,
                };
            }
            Protocol::RFC3164 => match (&self.appname, &self.procid) {
                (Some(appname), Some(procid)) => write!(f, "{}[{}]: ", appname.as_ref(), procid)?,
                (Some(appname), None) => write!(f, "{}: ", appname.as_ref())?,
                _ => write!(f, ": ")?,
            },
        }

        if let Protocol::RFC5424(_) = self.protocol {
            write!(
                f,
                "{} ",
                self.msgid.as_ref().map(|s| s.as_ref()).unwrap_or(&empty)
            )?;
        }

        if self.structured_data.is_empty() {
            if let Protocol::RFC5424(_) = self.protocol {
                write!(f, "- ")?;
            }
        } else {
            for elem in &self.structured_data {
                write!(f, "{}", elem)?;
            }
            write!(f, " ")?;
        }

        write!(f, "{}", self.msg.as_ref())
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
            procid: message.procid.map(|s| s.into()),
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
