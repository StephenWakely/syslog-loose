use crate::parsers::digits;
use chrono::prelude::*;
use nom::{
    branch::alt,
    bytes::complete::take_until,
    bytes::complete::{tag, take},
    character::complete::space1,
    combinator::{map, map_res, opt},
    sequence::tuple,
    IResult,
};

/// The timestamp for 5424 messages yyyy-mm-ddThh:mm:ss.mmmmZ
pub(crate) fn timestamp_3339(input: &str) -> IResult<&str, DateTime<FixedOffset>> {
    map_res(take_until(" "), chrono::DateTime::parse_from_rfc3339)(input)
}

/// An incomplete date is a tuple of (month, date, hour, minutes, seconds)
pub type IncompleteDate = (u32, u32, u32, u32, u32);

/// The month as a three letter string. Returns the number.
fn parse_month(s: &str) -> Result<u32, String> {
    match s.to_lowercase().as_ref() {
        "jan" => Ok(1),
        "feb" => Ok(2),
        "mar" => Ok(3),
        "apr" => Ok(4),
        "may" => Ok(5),
        "jun" => Ok(6),
        "jul" => Ok(7),
        "aug" => Ok(8),
        "sep" => Ok(9),
        "oct" => Ok(10),
        "nov" => Ok(11),
        "dec" => Ok(12),
        _ => Err(format!("Invalid month {}", s)),
    }
}

/// The timestamp for 3164 messages. MMM DD HH:MM:SS
fn timestamp_3164_no_year(input: &str) -> IResult<&str, IncompleteDate> {
    map(
        tuple((
            map_res(take(3_usize), parse_month),
            space1,
            digits,
            space1,
            digits,
            tag(":"),
            digits,
            tag(":"),
            digits,
            opt(tag(":")),
        )),
        |(month, _, date, _, hour, _, minute, _, seconds, _)| (month, date, hour, minute, seconds),
    )(input)
}

/// Timestamp including year. MMM DD YYYY HH:MM:SS
fn timestamp_3164_with_year(input: &str) -> IResult<&str, NaiveDateTime> {
    map(
        tuple((
            map_res(take(3_usize), parse_month),
            space1,
            digits,
            space1,
            digits,
            space1,
            digits,
            tag(":"),
            digits,
            tag(":"),
            digits,
            opt(tag(":")),
        )),
        |(month, _, date, _, year, _, hour, _, minute, _, seconds, _)| {
            NaiveDate::from_ymd(year, month, date).and_hms(hour, minute, seconds)
        },
    )(input)
}

/// Makes a timestamp given all the fields of the date less the year
/// and a function to resolve the year.
fn make_timestamp<F, Tz: TimeZone>(
    idate: IncompleteDate,
    get_year: F,
    tz: Option<Tz>,
) -> DateTime<FixedOffset>
where
    F: FnOnce(IncompleteDate) -> i32,
{
    let year = get_year(idate);
    let (mon, d, h, min, s) = idate;
    match tz {
        Some(offset) => {
            let datetime = offset.ymd(year, mon, d).and_hms(h, min, s);
            let fix_offset = datetime.offset().fix();
            datetime.with_timezone(&fix_offset)
        }
        None => Local.ymd(year, mon, d).and_hms(h, min, s).into(),
    }
}

/// Parse the timestamp in the format specified in RFC3164,
/// either with year or without.
/// MMM DD HH:MM:SS or MMM DD YYYY HH:MM:SS
//
/// # Arguments
///
/// * get_year - a function that is called if the parsed message contains a date with no year.
///              the function takes a (month, date, hour, minute, second) tuple and should return the year to use.
/// * tz - An optional timezone.
///        If None is specified and the parsed date doesn't specify a timezone the date is parsed in time local time.
///
pub(crate) fn timestamp_3164<F, Tz: TimeZone + Copy>(
    get_year: F,
    tz: Option<Tz>,
) -> impl Fn(&str) -> IResult<&str, DateTime<FixedOffset>>
where
    F: FnOnce(IncompleteDate) -> i32 + Copy,
{
    move |input| {
        alt((
            map(timestamp_3164_no_year, |ts| {
                make_timestamp::<_, Tz>(ts, get_year, tz)
            }),
            map(timestamp_3164_with_year, |naive_date| match tz {
                Some(tz) => {
                    let offset = tz.offset_from_utc_datetime(&naive_date).fix();
                    DateTime::<FixedOffset>::from_utc(naive_date, offset).into()
                }
                None => match Local.from_local_datetime(&naive_date).earliest() {
                    Some(timestamp) => timestamp.into(),
                    None => Local.from_utc_datetime(&naive_date).into(),
                },
            }),
            timestamp_3339,
        ))(input)
    }
}

#[test]
fn parse_timestamp_3339() {
    assert_eq!(
        timestamp_3339("1985-04-12T23:20:50.52Z ").unwrap(),
        (
            " ",
            FixedOffset::east(0)
                .ymd(1985, 4, 12)
                .and_hms_milli(23, 20, 50, 520)
        )
    );

    assert_eq!(
        timestamp_3339("1985-04-12T23:20:50.52-07:00 ").unwrap(),
        (
            " ",
            FixedOffset::west(7 * 3600)
                .ymd(1985, 4, 12)
                .and_hms_milli(23, 20, 50, 520)
        )
    );

    assert_eq!(
        timestamp_3339("2003-10-11T22:14:15.003Z ").unwrap(),
        (
            " ",
            FixedOffset::west(0)
                .ymd(2003, 10, 11)
                .and_hms_milli(22, 14, 15, 3),
        )
    )
}

#[test]
fn parse_timestamp_3164() {
    assert_eq!(
        timestamp_3164_no_year("Dec 28 16:49:07 ").unwrap(),
        (" ", (12, 28, 16, 49, 7))
    );
}

#[test]
fn parse_timestamp_3164_trailing_colon() {
    assert_eq!(
        timestamp_3164_no_year("Dec 28 16:49:07:").unwrap(),
        ("", (12, 28, 16, 49, 7))
    );
}

#[test]
fn parse_timestamp_with_year_3164() {
    assert_eq!(
        timestamp_3164(|_| 2019, Some(Utc.fix()))("Dec 28 2008 16:49:07 ",).unwrap(),
        (
            " ",
            FixedOffset::west(0).ymd(2008, 12, 28).and_hms(16, 49, 07)
        )
    );
}

#[test]
fn parse_timestamp_no_year_3164_local_time() {
    let offset = Local
        .offset_from_local_datetime(&NaiveDate::from_ymd(2019, 08, 04).and_hms(16, 49, 07))
        .unwrap();
    assert_eq!(
        timestamp_3164::<_, Local>(|_| 2019, None)("Aug 4 16:49:07 ",).unwrap(),
        (" ", offset.ymd(2019, 8, 4).and_hms(16, 49, 07))
    );
}

#[test]
fn parse_timestamp_with_year_3164_local_time() {
    let offset = Local
        .offset_from_local_datetime(&NaiveDate::from_ymd(2020, 08, 04).and_hms(16, 49, 07))
        .unwrap();
    assert_eq!(
        timestamp_3164::<_, Local>(|_| 2019, None)("Aug 4 2020 16:49:07 ",).unwrap(),
        (" ", offset.ymd(2020, 8, 4).and_hms(16, 49, 07))
    );
}
