use chrono::{prelude::*, Duration};
use syslog_loose::{
    parse_message, parse_message_with_year, parse_message_with_year_exact,
    parse_message_with_year_exact_tz, IncompleteDate, Message, ProcId, Protocol, StructuredElement,
    SyslogFacility, SyslogSeverity, Variant,
};

fn with_year((month, _date, _hour, _min, _sec): IncompleteDate) -> i32 {
    if month == 12 {
        2019
    } else {
        2020
    }
}

#[test]
fn parse_nginx() {
    // The nginx logs in 3164.
    let msg = "<190>Dec 28 16:49:07 plertrood-thinkpad-x220 nginx: 127.0.0.1 - - [28/Dec/2019:16:49:07 +0000] \"GET / HTTP/1.1\" 304 0 \"-\" \"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\"";

    assert_eq!(
        parse_message_with_year(msg, with_year, Variant::RFC3164),
        Message {
            facility: Some(SyslogFacility::LOG_LOCAL7),
            severity: Some(SyslogSeverity::SEV_INFO),
            timestamp: Some(Local.with_ymd_and_hms(2019, 12, 28,16, 49, 7).unwrap().into()),
            hostname: Some("plertrood-thinkpad-x220"),
            appname: Some("nginx"),
            procid: None,
            msgid: None,
            protocol: Protocol::RFC3164,
            structured_data: vec![],
            msg: "127.0.0.1 - - [28/Dec/2019:16:49:07 +0000] \"GET / HTTP/1.1\" 304 0 \"-\" \"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\"",
        }
    );
}

#[test]
fn parse_chrono_tz() {
    let msg = "<46>Jan  5 15:33:03 plertrood-ThinkPad-X220 rsyslogd: start";

    assert_eq!(
        parse_message_with_year_exact_tz(
            msg,
            with_year,
            Some(chrono_tz::Europe::Paris),
            Variant::Either
        )
        .unwrap(),
        Message {
            facility: Some(SyslogFacility::LOG_SYSLOG),
            severity: Some(SyslogSeverity::SEV_INFO),
            timestamp: Some(
                FixedOffset::east_opt(3600)
                    .unwrap()
                    .with_ymd_and_hms(2020, 1, 5, 15, 33, 3)
                    .unwrap()
            ),
            hostname: Some("plertrood-ThinkPad-X220"),
            appname: Some("rsyslogd"),
            procid: None,
            msgid: None,
            protocol: Protocol::RFC3164,
            structured_data: vec![],
            msg: "start",
        }
    );
}

#[test]
fn parse_rsyslog() {
    // rsyslog sends messages in 3164 with some structured data.
    let msg = "<46>Jan  5 15:33:03 plertrood-ThinkPad-X220 rsyslogd:  [origin software=\"rsyslogd\" swVersion=\"8.32.0\" x-pid=\"20506\" x-info=\"http://www.rsyslog.com\"] start";

    assert_eq!(
        parse_message_with_year(msg, with_year, Variant::Either),
        Message {
            facility: Some(SyslogFacility::LOG_SYSLOG),
            severity: Some(SyslogSeverity::SEV_INFO),
            timestamp: Some(
                Local
                    .with_ymd_and_hms(2020, 1, 5, 15, 33, 3)
                    .unwrap()
                    .into()
            ),
            hostname: Some("plertrood-ThinkPad-X220"),
            appname: Some("rsyslogd"),
            procid: None,
            msgid: None,
            protocol: Protocol::RFC3164,
            structured_data: vec![StructuredElement {
                id: "origin",
                params: vec![
                    ("software", "rsyslogd"),
                    ("swVersion", "8.32.0"),
                    ("x-pid", "20506"),
                    ("x-info", "http://www.rsyslog.com"),
                ]
            }],
            msg: "start",
        }
    );
}

#[test]
fn parse_haproxy() {
    // haproxy doesnt include the hostname.
    let msg = "<133>Jan 13 16:33:35 haproxy[73411]: Proxy sticky-servers started.";
    assert_eq!(
        parse_message_with_year(msg, with_year, Variant::Either),
        Message {
            facility: Some(SyslogFacility::LOG_LOCAL0),
            severity: Some(SyslogSeverity::SEV_NOTICE),
            timestamp: Some(
                Local
                    .with_ymd_and_hms(2020, 1, 13, 16, 33, 35)
                    .unwrap()
                    .into()
            ),
            hostname: None,
            appname: Some("haproxy"),
            procid: Some(ProcId::PID(73411)),
            msgid: None,
            protocol: Protocol::RFC3164,
            structured_data: vec![],
            msg: "Proxy sticky-servers started.",
        }
    );
}

#[test]
fn parse_5424_no_structured_data() {
    let msg = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8";

    assert_eq!(
        parse_message(msg, Variant::RFC5424),
        Message {
            facility: Some(SyslogFacility::LOG_AUTH),
            severity: Some(SyslogSeverity::SEV_CRIT),
            timestamp: Some(
                FixedOffset::west_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(2003, 10, 11, 22, 14, 15)
                    .unwrap()
                    + Duration::milliseconds(3)
            ),
            hostname: Some("mymachine.example.com"),
            appname: Some("su"),
            procid: None,
            msgid: Some("ID47"),
            protocol: Protocol::RFC5424(1),
            structured_data: vec![],
            msg: "BOM'su root' failed for lonvick on /dev/pts/8",
        }
    );
}

#[test]
fn parse_5424_structured_data() {
    let msg = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] BOMAn application event log entry...";

    assert_eq!(
        parse_message(msg, Variant::RFC5424),
        Message {
            facility: Some(SyslogFacility::LOG_LOCAL4),
            severity: Some(SyslogSeverity::SEV_NOTICE),
            timestamp: Some(
                FixedOffset::west_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(2003, 10, 11, 22, 14, 15)
                    .unwrap()
                    + Duration::milliseconds(3)
            ),
            hostname: Some("mymachine.example.com"),
            appname: Some("evntslog"),
            procid: None,
            msgid: Some("ID47"),
            protocol: Protocol::RFC5424(1),
            structured_data: vec![StructuredElement {
                id: "exampleSDID@32473",
                params: vec![
                    ("iut", "3"),
                    ("eventSource", "Application"),
                    ("eventID", "1011")
                ]
            },],
            msg: "BOMAn application event log entry...",
        }
    );
}

#[test]
fn parse_5424_empty_structured_data() {
    let msg = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"\" eventID=\"1011\"] BOMAn application event log entry...";

    assert_eq!(
        parse_message(msg, Variant::RFC5424),
        Message {
            facility: Some(SyslogFacility::LOG_LOCAL4),
            severity: Some(SyslogSeverity::SEV_NOTICE),
            timestamp: Some(
                FixedOffset::west_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(2003, 10, 11, 22, 14, 15)
                    .unwrap()
                    + Duration::milliseconds(3)
            ),
            hostname: Some("mymachine.example.com"),
            appname: Some("evntslog"),
            procid: None,
            msgid: Some("ID47"),
            protocol: Protocol::RFC5424(1),
            structured_data: vec![StructuredElement {
                id: "exampleSDID@32473",
                params: vec![("iut", "3"), ("eventSource", ""), ("eventID", "1011")]
            },],
            msg: "BOMAn application event log entry...",
        }
    );
}

#[test]
fn parse_5424_multiple_structured_data() {
    let msg = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource= \"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"] BOMAn application event log entry...";

    assert_eq!(
        parse_message(msg, Variant::RFC5424),
        Message {
            facility: Some(SyslogFacility::LOG_LOCAL4),
            severity: Some(SyslogSeverity::SEV_NOTICE),
            timestamp: Some(
                FixedOffset::west_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(2003, 10, 11, 22, 14, 15)
                    .unwrap()
                    + Duration::milliseconds(3)
            ),
            hostname: Some("mymachine.example.com"),
            appname: Some("evntslog"),
            procid: None,
            msgid: Some("ID47"),
            protocol: Protocol::RFC5424(1),
            structured_data: vec![
                StructuredElement {
                    id: "exampleSDID@32473",
                    params: vec![
                        ("iut", "3"),
                        ("eventSource", "Application"),
                        ("eventID", "1011")
                    ]
                },
                StructuredElement {
                    id: "examplePriority@32473",
                    params: vec![("class", "high"),]
                }
            ],
            msg: "BOMAn application event log entry...",
        }
    );
}

#[test]
fn parse_3164_invalid_structured_data() {
    // Can 3164 parse ok when there is something looking similar to structured data - but not quite.
    // Remove the id from the rsyslog messages structured data. This should now go into the msg.
    let msg = "<46>Jan  5 15:33:03 plertrood-ThinkPad-X220 rsyslogd:  [software=\"rsyslogd\" swVersion=\"8.32.0\" x-pid=\"20506\" x-info=\"http://www.rsyslog.com\"] start";

    assert_eq!(
        parse_message_with_year(msg, with_year, Variant::Either),
        Message {
            facility: Some(SyslogFacility::LOG_SYSLOG),
            severity: Some(SyslogSeverity::SEV_INFO),
            timestamp: Some(Local.with_ymd_and_hms(2020, 1, 5, 15, 33, 3).unwrap().into()),
            hostname: Some("plertrood-ThinkPad-X220"),
            appname: Some("rsyslogd"),
            procid: None,
            msgid: None,
            protocol: Protocol::RFC3164,
            structured_data: vec![],
            msg: "[software=\"rsyslogd\" swVersion=\"8.32.0\" x-pid=\"20506\" x-info=\"http://www.rsyslog.com\"] start",
        }
    );
}

#[test]
fn parse_3164_no_tag() {
    let msg = "<46>Jan  5 15:33:03 plertrood-ThinkPad-X220  [software=\"rsyslogd\" swVersion=\"8.32.0\" x-pid=\"20506\" x-info=\"http://www.rsyslog.com\"] start";

    assert_eq!(
        parse_message_with_year(msg, with_year, Variant::Either),
        Message {
            facility: Some(SyslogFacility::LOG_SYSLOG),
            severity: Some(SyslogSeverity::SEV_INFO),
            timestamp: Some(Local.with_ymd_and_hms(2020, 1, 5,15, 33, 3).unwrap().into()),
            hostname: Some("plertrood-ThinkPad-X220"),
            appname: None,
            procid: None,
            msgid: None,
            protocol: Protocol::RFC3164,
            structured_data: vec![],
            msg: "[software=\"rsyslogd\" swVersion=\"8.32.0\" x-pid=\"20506\" x-info=\"http://www.rsyslog.com\"] start",
        }
    );
}

#[test]
fn parse_european_chars() {
    let msg = "<46>Jan 5 10:01:00 Übergröße außerplanmäßig größenordnungsmäßig";

    assert_eq!(
        parse_message_with_year(msg, with_year, Variant::Either),
        Message {
            facility: Some(SyslogFacility::LOG_SYSLOG),
            severity: Some(SyslogSeverity::SEV_INFO),
            timestamp: Some(Local.with_ymd_and_hms(2020, 1, 5, 10, 1, 0).unwrap().into()),
            hostname: Some("Übergröße"),
            appname: Some("außerplanmäßig"),
            procid: None,
            msgid: None,
            protocol: Protocol::RFC3164,
            structured_data: vec![],
            msg: "größenordnungsmäßig",
        }
    );
}

#[test]
fn parse_invalid_message() {
    let msg = "complete and utter gobbledegook";

    assert_eq!(
        parse_message_with_year(msg, with_year, Variant::Either),
        Message {
            facility: None,
            severity: None,
            timestamp: None,
            hostname: None,
            appname: None,
            procid: None,
            msgid: None,
            protocol: Protocol::RFC3164,
            structured_data: vec![],
            msg: "complete and utter gobbledegook",
        }
    );
}

#[test]
fn parse_blank_msg() {
    let ook = Message {
        facility: Some(SyslogFacility::LOG_CRON),
        severity: Some(SyslogSeverity::SEV_ERR),
        timestamp: Some(
            FixedOffset::west_opt(0)
                .unwrap()
                .with_ymd_and_hms(1969, 12, 3, 23, 58, 58)
                .unwrap(),
        ),
        hostname: None,
        appname: None,
        procid: None,
        msgid: None,
        protocol: Protocol::RFC5424(1),
        structured_data: vec![],
        msg: "",
    };

    println!("{}", ook);
    let msg = format!("{}", ook);

    assert_eq!(
        parse_message(&msg, Variant::Either),
        Message {
            facility: Some(SyslogFacility::LOG_CRON),
            severity: Some(SyslogSeverity::SEV_ERR),
            timestamp: Some(
                FixedOffset::west_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(1969, 12, 3, 23, 58, 58)
                    .unwrap(),
            ),
            hostname: None,
            appname: None,
            procid: None,
            msgid: None,
            protocol: Protocol::RFC3164,
            structured_data: vec![],
            msg: "",
        }
    );
}

/*

The following tests have been taken from Vector (vector.dev)
https://github.com/timberio/vector/blob/fff92728c9490824ff9d0ae76669adc901bb5499/src/sources/syslog.rs

*/

#[test]
fn syslog_ng_network_syslog_protocol() {
    let msg = "i am foobar";
    let raw = format!(
        r#"<13>1 2019-02-13T19:48:34+00:00 74794bfb6795 root 8449 - {}{} {}"#,
        r#"[meta sequenceId="1" sysUpTime="37" language="EN"]"#,
        r#"[origin ip="192.168.0.1" software="test"]"#,
        msg
    );

    assert_eq!(
        parse_message(&raw, Variant::Either),
        Message {
            facility: Some(SyslogFacility::LOG_USER),
            severity: Some(SyslogSeverity::SEV_NOTICE),
            timestamp: Some(
                FixedOffset::west_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(2019, 2, 13, 19, 48, 34)
                    .unwrap()
            ),
            hostname: Some("74794bfb6795"),
            appname: Some("root"),
            procid: Some(ProcId::PID(8449)),
            msgid: None,
            protocol: Protocol::RFC5424(1),
            structured_data: vec![
                StructuredElement {
                    id: "meta",
                    params: vec![("sequenceId", "1"), ("sysUpTime", "37"), ("language", "EN")]
                },
                StructuredElement {
                    id: "origin",
                    params: vec![("ip", "192.168.0.1"), ("software", "test"),]
                }
            ],
            msg: "i am foobar",
        }
    )
}

#[test]
fn handles_incorrect_sd_element() {
    let msg = format!(
        r#"<13>1 2019-02-13T19:48:34+00:00 74794bfb6795 root 8449 - {} qwerty"#,
        r#"[incorrect x]"#
    );

    let should = Message {
        facility: Some(SyslogFacility::LOG_USER),
        severity: Some(SyslogSeverity::SEV_NOTICE),
        timestamp: Some(
            FixedOffset::west_opt(0)
                .unwrap()
                .with_ymd_and_hms(2019, 2, 13, 19, 48, 34)
                .unwrap(),
        ),
        hostname: Some("74794bfb6795"),
        appname: Some("root"),
        procid: Some(ProcId::PID(8449)),
        msgid: None,
        protocol: Protocol::RFC5424(1),
        structured_data: vec![],
        msg: "qwerty",
    };

    assert_eq!(parse_message(&msg, Variant::Either), should);

    let msg = format!(
        r#"<13>1 2019-02-13T19:48:34+00:00 74794bfb6795 root 8449 - {} qwerty"#,
        r#"[incorrect x=]"#
    );

    assert_eq!(parse_message(&msg, Variant::Either), should);
}

#[test]
fn handles_empty_sd_element() {
    let msg = format!(
        r#"<13>1 2019-02-13T19:48:34+00:00 74794bfb6795 root 8449 - {} qwerty"#,
        r#"[empty]"#
    );

    assert_eq!(
        parse_message(&msg, Variant::Either),
        Message {
            facility: Some(SyslogFacility::LOG_USER),
            severity: Some(SyslogSeverity::SEV_NOTICE),
            timestamp: Some(
                FixedOffset::west_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(2019, 2, 13, 19, 48, 34)
                    .unwrap()
            ),
            hostname: Some("74794bfb6795"),
            appname: Some("root"),
            procid: Some(ProcId::PID(8449)),
            msgid: None,
            protocol: Protocol::RFC5424(1),
            structured_data: vec![StructuredElement {
                id: "empty",
                params: vec![]
            }],
            msg: "qwerty",
        }
    );

    let msg = format!(
        r#"<13>1 2019-02-13T19:48:34+00:00 74794bfb6795 root 8449 - {} qwerty"#,
        r#"[non_empty x="1"][empty]"#
    );

    assert_eq!(
        parse_message(&msg, Variant::Either),
        Message {
            facility: Some(SyslogFacility::LOG_USER),
            severity: Some(SyslogSeverity::SEV_NOTICE),
            timestamp: Some(
                FixedOffset::west_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(2019, 2, 13, 19, 48, 34)
                    .unwrap()
            ),
            hostname: Some("74794bfb6795"),
            appname: Some("root"),
            procid: Some(ProcId::PID(8449)),
            msgid: None,
            protocol: Protocol::RFC5424(1),
            structured_data: vec![
                StructuredElement {
                    id: "non_empty",
                    params: vec![("x", "1")]
                },
                StructuredElement {
                    id: "empty",
                    params: vec![]
                },
            ],
            msg: "qwerty",
        }
    );

    let msg = format!(
        r#"<13>1 2019-02-13T19:48:34+00:00 74794bfb6795 root 8449 - {} qwerty"#,
        r#"[empty][non_empty x="1"]"#
    );

    assert_eq!(
        parse_message(&msg, Variant::Either),
        Message {
            facility: Some(SyslogFacility::LOG_USER),
            severity: Some(SyslogSeverity::SEV_NOTICE),
            timestamp: Some(
                FixedOffset::west_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(2019, 2, 13, 19, 48, 34)
                    .unwrap()
            ),
            hostname: Some("74794bfb6795"),
            appname: Some("root"),
            procid: Some(ProcId::PID(8449)),
            msgid: None,
            protocol: Protocol::RFC5424(1),
            structured_data: vec![
                StructuredElement {
                    id: "empty",
                    params: vec![]
                },
                StructuredElement {
                    id: "non_empty",
                    params: vec![("x", "1")]
                },
            ],
            msg: "qwerty",
        }
    );

    let msg = format!(
        r#"<13>1 2019-02-13T19:48:34+00:00 74794bfb6795 root 8449 - {} qwerty"#,
        r#"[empty not_really="testing the test"]"#
    );

    assert_eq!(
        parse_message(&msg, Variant::Either),
        Message {
            facility: Some(SyslogFacility::LOG_USER),
            severity: Some(SyslogSeverity::SEV_NOTICE),
            timestamp: Some(
                FixedOffset::west_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(2019, 2, 13, 19, 48, 34)
                    .unwrap()
            ),
            hostname: Some("74794bfb6795"),
            appname: Some("root"),
            procid: Some(ProcId::PID(8449)),
            msgid: None,
            protocol: Protocol::RFC5424(1),
            structured_data: vec![StructuredElement {
                id: "empty",
                params: vec![("not_really", "testing the test")]
            },],
            msg: "qwerty",
        }
    );
}

#[test]
fn handles_weird_whitespace() {
    // this should also match rsyslog omfwd with template=RSYSLOG_SyslogProtocol23Format
    let raw = r#"
            <13>1 2019-02-13T19:48:34+00:00 74794bfb6795 root 8449 - [meta sequenceId="1"] i am foobar
            "#;
    let cleaned = r#"<13>1 2019-02-13T19:48:34+00:00 74794bfb6795 root 8449 - [meta sequenceId="1"] i am foobar"#;

    assert_eq!(
        parse_message(raw, Variant::Either),
        parse_message(cleaned, Variant::Either)
    );
}

#[test]
fn syslog_ng_default_network() {
    let raw = r#"<13>Feb 13 20:07:26 74794bfb6795 root[8539]: i am foobar"#;

    assert_eq!(
        parse_message_with_year(raw, with_year, Variant::Either),
        Message {
            facility: Some(SyslogFacility::LOG_USER),
            severity: Some(SyslogSeverity::SEV_NOTICE),
            timestamp: Some(
                Local
                    .with_ymd_and_hms(2020, 2, 13, 20, 7, 26)
                    .unwrap()
                    .into()
            ),
            hostname: Some("74794bfb6795"),
            appname: Some("root"),
            procid: Some(ProcId::PID(8539)),
            msgid: None,
            protocol: Protocol::RFC3164,
            structured_data: vec![],
            msg: "i am foobar",
        }
    );
}

#[test]
fn rsyslog_omfwd_tcp_default() {
    let raw = r#"<190>Feb 13 21:31:56 74794bfb6795 liblogging-stdlog:  [origin software="rsyslogd" swVersion="8.24.0" x-pid="8979" x-info="http://www.rsyslog.com"] start"#;

    assert_eq!(
        parse_message_with_year(raw, with_year, Variant::Either),
        Message {
            facility: Some(SyslogFacility::LOG_LOCAL7),
            severity: Some(SyslogSeverity::SEV_INFO),
            timestamp: Some(
                Local
                    .with_ymd_and_hms(2020, 2, 13, 21, 31, 56)
                    .unwrap()
                    .into()
            ),
            hostname: Some("74794bfb6795"),
            appname: Some("liblogging-stdlog"),
            procid: None,
            msgid: None,
            protocol: Protocol::RFC3164,
            structured_data: vec![StructuredElement {
                id: "origin",
                params: vec![
                    ("software", "rsyslogd"),
                    ("swVersion", "8.24.0"),
                    ("x-pid", "8979"),
                    ("x-info", "http://www.rsyslog.com")
                ]
            }],
            msg: "start",
        }
    );
}

#[test]
fn rsyslog_omfwd_tcp_forward_format() {
    let raw = r#"<190>2019-02-13T21:53:30.605850+00:00 74794bfb6795 liblogging-stdlog:  [origin software="rsyslogd" swVersion="8.24.0" x-pid="9043" x-info="http://www.rsyslog.com"] start"#;

    assert_eq!(
        parse_message_with_year(raw, with_year, Variant::Either),
        Message {
            facility: Some(SyslogFacility::LOG_LOCAL7),
            severity: Some(SyslogSeverity::SEV_INFO),
            timestamp: Some(
                FixedOffset::west_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(2019, 2, 13, 21, 53, 30)
                    .unwrap()
                    + Duration::microseconds(605_850)
            ),
            hostname: Some("74794bfb6795"),
            appname: Some("liblogging-stdlog"),
            procid: None,
            msgid: None,
            protocol: Protocol::RFC3164,
            structured_data: vec![StructuredElement {
                id: "origin",
                params: vec![
                    ("software", "rsyslogd"),
                    ("swVersion", "8.24.0"),
                    ("x-pid", "9043"),
                    ("x-info", "http://www.rsyslog.com")
                ]
            }],
            msg: "start",
        }
    );
}

#[test]
fn logical_system_juniper_routers() {
    let raw = r#"<28>1 2020-05-22T14:59:09.250-03:00 OX-XXX-MX204 OX-XXX-CONTEUDO:rpd 6589 - - bgp_listen_accept: %DAEMON-4: Connection attempt from unconfigured neighbor: 2001:XXX::219:166+57284"#;

    assert_eq!(
        parse_message_with_year(raw, with_year, Variant::Either),
        Message {
            facility: Some(SyslogFacility::LOG_DAEMON),
            severity: Some(SyslogSeverity::SEV_WARNING),
            timestamp: Some(
                FixedOffset::west_opt(1800 * 6).unwrap()
                    .with_ymd_and_hms(2020, 5, 22,14, 59, 9).unwrap() + Duration::microseconds(250000)
            ),
            hostname: Some("OX-XXX-MX204"),
            appname: Some("OX-XXX-CONTEUDO:rpd"),
            procid: Some(ProcId::PID(6589)),
            msgid: None,
            protocol: Protocol::RFC5424(1),
            structured_data: vec![],
            msg: "bgp_listen_accept: %DAEMON-4: Connection attempt from unconfigured neighbor: 2001:XXX::219:166+57284",
        }
    );
}

#[test]
fn parse_missing_pri() {
    let msg = "Dec 28 16:49:07 plertrood-thinkpad-x220 nginx: 127.0.0.1 - - [28/Dec/2019:16:49:07 +0000] \"GET / HTTP/1.1\" 304 0 \"-\" \"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\"";

    assert_eq!(
        parse_message_with_year(msg, with_year, Variant::Either),
        Message {
            facility: None,
            severity: None,
            timestamp: Some(Local.with_ymd_and_hms(2019, 12, 28,16, 49, 7).unwrap().into()),
            hostname: Some("plertrood-thinkpad-x220"),
            appname: Some("nginx"),
            procid: None,
            msgid: None,
            protocol: Protocol::RFC3164,
            structured_data: vec![],
            msg: "127.0.0.1 - - [28/Dec/2019:16:49:07 +0000] \"GET / HTTP/1.1\" 304 0 \"-\" \"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\"",
        }
    );
}

#[test]
fn parse_missing_pri_5424() {
    let raw = r#"1 2020-05-22T14:59:09.250-03:00 OX-XXX-MX204 OX-XXX-CONTEUDO:rpd 6589 - - bgp_listen_accept: %DAEMON-4: Connection attempt from unconfigured neighbor: 2001:XXX::219:166+57284"#;

    assert_eq!(
        parse_message_with_year(raw, with_year, Variant::Either),
        Message {
            facility: None,
            severity: None,
            timestamp: Some(
                FixedOffset::west_opt(1800 * 6).unwrap()
                    .with_ymd_and_hms(2020, 5, 22,14, 59, 9).unwrap() + Duration::microseconds(250000)
            ),
            hostname: Some("OX-XXX-MX204"),
            appname: Some("OX-XXX-CONTEUDO:rpd"),
            procid: Some(ProcId::PID(6589)),
            msgid: None,
            protocol: Protocol::RFC5424(1),
            structured_data: vec![],
            msg: "bgp_listen_accept: %DAEMON-4: Connection attempt from unconfigured neighbor: 2001:XXX::219:166+57284",
        }
    );
}

#[test]
fn parse_exact_error() {
    let raw = r#"I am an invalid syslog message, but I do like cheese"#;

    assert_eq!(
        parse_message_with_year_exact(raw, with_year, Variant::Either),
        Err("unable to parse input as valid syslog message".to_string())
    );
}

#[test]
fn parse_exact_with_tz() {
    let raw = r#"<13>Feb 13 20:07:26 74794bfb6795 root[8539]: i am foobar"#;
    let tz = chrono::FixedOffset::east_opt(5 * 3600).unwrap();
    assert_eq!(
        parse_message_with_year_exact_tz(raw, with_year, Some(tz), Variant::Either).unwrap(),
        Message {
            facility: Some(SyslogFacility::LOG_USER),
            severity: Some(SyslogSeverity::SEV_NOTICE),
            timestamp: Some(tz.with_ymd_and_hms(2020, 2, 13, 20, 7, 26).unwrap()),
            hostname: Some("74794bfb6795"),
            appname: Some("root"),
            procid: Some(ProcId::PID(8539)),
            msgid: None,
            protocol: Protocol::RFC3164,
            structured_data: vec![],
            msg: "i am foobar",
        }
    );
}

#[test]
fn parse_invalid_date() {
    fn non_leapyear((_month, _date, _hour, _min, _sec): IncompleteDate) -> i32 {
        2019
    }

    let raw = r#"<134> Feb 29 14:07:19 myhostname sshd - - - this is my message"#;
    assert!(parse_message_with_year_exact(raw, non_leapyear, Variant::Either).is_err());
}

#[test]
fn parse_vrl() {
    let msg = "<13>Feb 13 20:07:26 74794bfb6795 root[8539]:syslog message";

    assert_eq!(
        Message {
            facility: Some(SyslogFacility::LOG_USER),
            severity: Some(SyslogSeverity::SEV_NOTICE),
            timestamp: Some(
                FixedOffset::west_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(2020, 2, 13, 20, 07, 26)
                    .unwrap()
            ),
            hostname: Some("74794bfb6795"),
            appname: Some("root"),
            procid: Some(ProcId::PID(8539)),
            msgid: None,
            protocol: Protocol::RFC3164,
            structured_data: vec![],
            msg: "syslog message",
        },
        parse_message_with_year(msg, with_year, Variant::Either)
    )
}

#[test]
fn parse_ipv4_hostname() {
    let msg = "<34>1 2003-10-11T22:14:15.003Z 42.52.1.1 su - ID47 - bananas and peas";
    assert_eq!(
        Message {
            facility: Some(SyslogFacility::LOG_AUTH),
            severity: Some(SyslogSeverity::SEV_CRIT),
            timestamp: Some(
                FixedOffset::west_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(2003, 10, 11, 22, 14, 15)
                    .unwrap()
                    + Duration::milliseconds(3)
            ),
            hostname: Some("42.52.1.1"),
            appname: Some("su"),
            procid: None,
            msgid: Some("ID47"),
            protocol: Protocol::RFC5424(1),
            structured_data: vec![],
            msg: "bananas and peas",
        },
        parse_message(msg, Variant::RFC5424)
    )
}

#[test]
fn parse_ipv6_hostname() {
    let msg = "<34>1 2003-10-11T22:14:15.003Z ::FFFF:129.144.52.38 su - ID47 - bananas and peas";
    assert_eq!(
        Message {
            facility: Some(SyslogFacility::LOG_AUTH),
            severity: Some(SyslogSeverity::SEV_CRIT),
            timestamp: Some(
                FixedOffset::west_opt(0)
                    .unwrap()
                    .with_ymd_and_hms(2003, 10, 11, 22, 14, 15)
                    .unwrap()
                    + Duration::milliseconds(3)
            ),
            hostname: Some("::FFFF:129.144.52.38"),
            appname: Some("su"),
            procid: None,
            msgid: Some("ID47"),
            protocol: Protocol::RFC5424(1),
            structured_data: vec![],
            msg: "bananas and peas",
        },
        parse_message(msg, Variant::RFC5424)
    )
}
