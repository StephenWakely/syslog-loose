
# Syslog Loose

A simple parser that aims to parse syslog messages.

First attempts to parse the header according to [RFC5424](https://tools.ietf.org/html/rfc5424). If this fails it will fall back to [RFC3164](https://tools.ietf.org/html/rfc3164).

The goal will be to extract as much correct information from the message rather than to be pedantically correct to the standard.

[RFC3164](https://tools.ietf.org/html/rfc3164#section-5.4) specifies dates without the year. It is possible to pass a function to the parser to resolve the year. For example, you may want to resolve all dates to the current year unless it is the 1st January and you have a log message from the 31st December.

```rust

fn resolve_year((month, _date, _hour, _min, _sec): syslog_loose::IncompleteDate) -> i32 {
    let now = Utc::now();
    if now.month() == 1 && month == 12 {
        now.year() - 1
    } else {
        now.year()
    }
}

parse_message_with_year(msg, resolve_year)

```
