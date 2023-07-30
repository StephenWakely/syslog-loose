# Syslog Loose

A simple parser that aims to parse syslog messages. The goal is to extract as much correct information from the message rather than to be pedantically correct to the standard.

There are two standards for formatting Syslog messages.

## [RFC5424](https://tools.ietf.org/html/rfc5424) 

RFC5424 is well defined and unambiguous. Syslog-loose fill first attempt to parse the message according to this standard. Many systems do not produce messages according to RFC5424 unfortunately, so if this fails it will fall back to:

## [RFC3164](https://tools.ietf.org/html/rfc3164)

RFC3164 is a much looser, more ambiguous format.

Lets look at a sample message:

```
<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
```

The first field `<34>` is a combination of the facility and severity of the message. This can be missing, if so `None` is returned for both fields. See [here](https://tools.ietf.org/html/rfc3164#section-4.1.1).

The date field, technically for 3164 it needs to be in the format `MMM DD HH:MM:SS`. There is no year specified. It is possible to pass a function to `parse_message_with_year` that you can use to resolve the year. For example, you may want to resolve all dates to the current year unless it is the 1st January and you have a log message from the 31st December.


The parser will also work for timestamps in [3339 format](https://tools.ietf.org/html/rfc3339) (eg. 1985-04-12T23:20:50.52Z).

The next two fields are optional and are the hostname or the appname together with the (optional) process id. These fields should be terminated by a `:`. For example:

```
mymachine app[323] :
```

This gives us:

hostname = mymachine
appname = app
procid = 323

```
mymachine app :
```

hostname = mymachine
appname = app
procid = None

```
mymachine :
```

hostname = mymachine
appname = None
procid = None

```
app[323] :
```

This gives us:

hostname = None
appname = app
procid = 323


The text following the `:` is the message. The message can first start with [structured data](https://tools.ietf.org/html/rfc5424#section-6.3), comprising one or more sections surrounded by `[` and `]` in the format: `[id key="value"..]`. Multiple key value pairs, separated by space, can be specified. Any remaining text is parsed as the free-form message. Any structured data sections that fail to parse are ignored.


# Example

```rust

fn resolve_year((month, _date, _hour, _min, _sec): syslog_loose::IncompleteDate) -> i32 {
    let now = Utc::now();
    if now.month() == 1 && month == 12 {
        now.year() - 1
    } else {
        now.year()
    }
}

parse_message_with_year(msg, resolve_year, Variant::Either)

```

# Timezones

Dates in a RFC3164 message may not necessarily specify a Timezone. If you wish to specify a timezone manually you can parse the message with `parse_message_with_year_tz`. The `tz` parameter contains an Option of a chrono [`FixedOffset`](https://docs.rs/chrono/0.4.13/chrono/offset/struct.FixedOffset.html) that specifies the offset from UTC.

If no timezone is specified the date will be parsed in the local time - unless that time cannot exist in the local timezone (that nonexistent period of time when clocks go forward), then the timezone will be parsed as UTC.
