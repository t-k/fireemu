//! Logical time.
//!
//! `LogicalInstant` is nanoseconds since the Unix epoch as an `i128`. All arithmetic is
//! checked; the core never silently wraps or rounds. RFC 3339 parsing and formatting is
//! implemented here with `std` only because the control API and traces need it and the core
//! must not pull in a date/time dependency (ADR-001).

use core::fmt;

/// A signed duration in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct LogicalDuration(i128);

impl LogicalDuration {
    /// Zero duration.
    pub const ZERO: Self = Self(0);

    /// Builds a duration from nanoseconds.
    #[must_use]
    pub const fn from_nanos(nanos: i128) -> Self {
        Self(nanos)
    }

    /// Builds a duration from milliseconds.
    #[must_use]
    pub const fn from_millis(millis: i64) -> Self {
        Self(millis as i128 * 1_000_000)
    }

    /// Builds a duration from seconds.
    #[must_use]
    pub const fn from_seconds(seconds: i64) -> Self {
        Self(seconds as i128 * 1_000_000_000)
    }

    /// Nanoseconds.
    #[must_use]
    pub const fn as_nanos(self) -> i128 {
        self.0
    }

    /// Whole milliseconds, truncated toward zero.
    #[must_use]
    pub const fn as_millis(self) -> i128 {
        self.0 / 1_000_000
    }

    /// Whole seconds, truncated toward zero.
    #[must_use]
    pub const fn as_seconds(self) -> i128 {
        self.0 / 1_000_000_000
    }

    /// Whether the duration is strictly greater than zero.
    #[must_use]
    pub const fn is_positive(self) -> bool {
        self.0 > 0
    }

    /// Checked addition.
    #[must_use]
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        match self.0.checked_add(other.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }
}

/// A point in logical time: nanoseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct LogicalInstant(i128);

impl LogicalInstant {
    /// The Unix epoch.
    pub const UNIX_EPOCH: Self = Self(0);
    /// Largest representable instant.
    pub const MAX: Self = Self(i128::MAX);
    /// Smallest representable instant.
    pub const MIN: Self = Self(i128::MIN);

    /// Builds an instant from nanoseconds since the Unix epoch.
    #[must_use]
    pub const fn from_nanos(nanos: i128) -> Self {
        Self(nanos)
    }

    /// Builds an instant from whole seconds since the Unix epoch.
    #[must_use]
    pub const fn from_unix_seconds(seconds: i64) -> Self {
        Self(seconds as i128 * 1_000_000_000)
    }

    /// Nanoseconds since the Unix epoch.
    #[must_use]
    pub const fn as_nanos(self) -> i128 {
        self.0
    }

    /// Checked addition of a duration.
    #[must_use]
    pub const fn checked_add(self, d: LogicalDuration) -> Option<Self> {
        match self.0.checked_add(d.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Checked signed difference `self - earlier`.
    #[must_use]
    pub const fn checked_duration_since(self, earlier: Self) -> Option<LogicalDuration> {
        match self.0.checked_sub(earlier.0) {
            Some(v) => Some(LogicalDuration(v)),
            None => None,
        }
    }

    /// Parses an RFC 3339 timestamp such as `2026-08-29T12:01:00.123Z` or
    /// `2026-08-29T21:01:00+09:00`. Fractional seconds up to nine digits are accepted.
    pub fn parse_rfc3339(input: &str) -> Result<Self, TimeParseError> {
        rfc3339::parse(input)
    }

    /// Formats the instant as RFC 3339 in UTC. Fractional nanoseconds are printed with nine
    /// digits only when non-zero so that canonical output stays stable.
    ///
    /// RFC 3339 only covers years 0000-9999; instants outside that range return
    /// [`TimeFormatError`] instead of a string the parser would reject.
    pub fn to_rfc3339(self) -> Result<String, TimeFormatError> {
        rfc3339::format(self)
    }
}

/// `Display` prints RFC 3339 when representable and an explicit `nanos=<i128>` form
/// otherwise, so that diagnostics never carry a malformed timestamp.
impl fmt::Display for LogicalInstant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_rfc3339() {
            Ok(s) => f.write_str(&s),
            Err(_) => write!(f, "nanos={}", self.0),
        }
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian civil date.
#[must_use]
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_prime = (month + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Proleptic Gregorian `(year, month, day)` for a day count since 1970-01-01.
#[must_use]
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let (year, month, day) = civil_from_days_wide(i128::from(days));
    (
        i64::try_from(year).unwrap_or(if year.is_negative() {
            i64::MIN
        } else {
            i64::MAX
        }),
        i64::try_from(month).unwrap_or(1),
        i64::try_from(day).unwrap_or(1),
    )
}

fn civil_from_days_wide(days: i128) -> (i128, i128, i128) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Error returned when an instant cannot be represented as RFC 3339.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeFormatError {
    /// Proleptic Gregorian year of the instant, outside 0..=9999.
    pub year: i128,
}

impl fmt::Display for TimeFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "year {} is outside the RFC 3339 range 0000-9999",
            self.year
        )
    }
}

impl std::error::Error for TimeFormatError {}

/// Error returned when an RFC 3339 string cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeParseError {
    /// Byte offset at which parsing failed.
    pub offset: usize,
    /// Static description of what was expected.
    pub expected: &'static str,
}

impl fmt::Display for TimeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid RFC 3339 timestamp at byte {}: expected {}",
            self.offset, self.expected
        )
    }
}

impl std::error::Error for TimeParseError {}

mod rfc3339 {
    use super::{LogicalInstant, TimeFormatError, TimeParseError};

    const NANOS_PER_SEC: i128 = 1_000_000_000;
    const SECS_PER_DAY: i64 = 86_400;

    struct Cursor<'a> {
        bytes: &'a [u8],
        pos: usize,
    }

    impl Cursor<'_> {
        fn err(&self, expected: &'static str) -> TimeParseError {
            TimeParseError {
                offset: self.pos,
                expected,
            }
        }

        fn digits(&mut self, n: usize, expected: &'static str) -> Result<u32, TimeParseError> {
            let mut value: u32 = 0;
            for _ in 0..n {
                let b = *self.bytes.get(self.pos).ok_or_else(|| self.err(expected))?;
                if !b.is_ascii_digit() {
                    return Err(self.err(expected));
                }
                value = value * 10 + u32::from(b - b'0');
                self.pos += 1;
            }
            Ok(value)
        }

        fn expect(&mut self, c: u8, expected: &'static str) -> Result<(), TimeParseError> {
            match self.bytes.get(self.pos) {
                Some(&b) if b == c => {
                    self.pos += 1;
                    Ok(())
                }
                _ => Err(self.err(expected)),
            }
        }

        fn peek(&self) -> Option<u8> {
            self.bytes.get(self.pos).copied()
        }
    }

    pub(super) fn parse(input: &str) -> Result<LogicalInstant, TimeParseError> {
        let mut c = Cursor {
            bytes: input.as_bytes(),
            pos: 0,
        };
        let year = c.digits(4, "four-digit year")?;
        c.expect(b'-', "'-' after year")?;
        let month = c.digits(2, "two-digit month")?;
        c.expect(b'-', "'-' after month")?;
        let day = c.digits(2, "two-digit day")?;
        match c.peek() {
            Some(b'T' | b't') => c.pos += 1,
            _ => return Err(c.err("'T' date-time separator")),
        }
        let hour = c.digits(2, "two-digit hour")?;
        c.expect(b':', "':' after hour")?;
        let minute = c.digits(2, "two-digit minute")?;
        c.expect(b':', "':' after minute")?;
        let second = c.digits(2, "two-digit second")?;

        let mut nanos: i128 = 0;
        if c.peek() == Some(b'.') {
            c.pos += 1;
            let start = c.pos;
            let mut scale: i128 = NANOS_PER_SEC / 10;
            while let Some(b) = c.peek() {
                if !b.is_ascii_digit() {
                    break;
                }
                if scale == 0 {
                    return Err(c.err("at most nine fractional digits"));
                }
                nanos += i128::from(b - b'0') * scale;
                scale /= 10;
                c.pos += 1;
            }
            if c.pos == start {
                return Err(c.err("fractional digits after '.'"));
            }
        }

        let offset_secs: i64 = match c.peek() {
            Some(b'Z' | b'z') => {
                c.pos += 1;
                0
            }
            Some(sign @ (b'+' | b'-')) => {
                c.pos += 1;
                let oh = c.digits(2, "two-digit offset hour")?;
                c.expect(b':', "':' in offset")?;
                let om = c.digits(2, "two-digit offset minute")?;
                if oh > 23 || om > 59 {
                    return Err(c.err("offset within +-23:59"));
                }
                let secs = i64::from(oh) * 3_600 + i64::from(om) * 60;
                if sign == b'+' {
                    secs
                } else {
                    -secs
                }
            }
            _ => return Err(c.err("'Z' or numeric offset")),
        };
        if c.pos != c.bytes.len() {
            return Err(c.err("end of input"));
        }

        if !(1..=12).contains(&month) {
            return Err(TimeParseError {
                offset: 5,
                expected: "month 01-12",
            });
        }
        if day == 0 || day > days_in_month(i64::from(year), month) {
            return Err(TimeParseError {
                offset: 8,
                expected: "valid day of month",
            });
        }
        if hour > 23 {
            return Err(TimeParseError {
                offset: 11,
                expected: "hour 00-23",
            });
        }
        if minute > 59 {
            return Err(TimeParseError {
                offset: 14,
                expected: "minute 00-59",
            });
        }
        // Leap second (60) is accepted by RFC 3339 grammar but Firestore timestamps never carry
        // one; we reject it to keep the logical clock strictly proleptic.
        if second > 59 {
            return Err(TimeParseError {
                offset: 17,
                expected: "second 00-59",
            });
        }

        let days = super::days_from_civil(i64::from(year), i64::from(month), i64::from(day));
        let local_secs = days * SECS_PER_DAY
            + i64::from(hour) * 3_600
            + i64::from(minute) * 60
            + i64::from(second);
        let utc_secs = local_secs - offset_secs;
        Ok(LogicalInstant(i128::from(utc_secs) * NANOS_PER_SEC + nanos))
    }

    pub(super) fn format(instant: LogicalInstant) -> Result<String, TimeFormatError> {
        let secs = instant.0.div_euclid(NANOS_PER_SEC);
        let nanos = instant.0.rem_euclid(NANOS_PER_SEC);
        let days = secs.div_euclid(i128::from(SECS_PER_DAY));
        let sod = secs.rem_euclid(i128::from(SECS_PER_DAY));
        let (year, month, day) = super::civil_from_days_wide(days);
        if !(0..=9_999).contains(&year) {
            return Err(TimeFormatError { year });
        }
        let hour = sod / 3_600;
        let minute = (sod % 3_600) / 60;
        let second = sod % 60;
        Ok(if nanos == 0 {
            format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
        } else {
            format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanos:09}Z")
        })
    }

    fn is_leap(y: i64) -> bool {
        (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
    }

    fn days_in_month(y: i64, m: u32) -> u32 {
        match m {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if is_leap(y) => 29,
            2 => 28,
            _ => 0,
        }
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn civil_round_trip_over_wide_range() {
            for days in (-800_000..800_000).step_by(37) {
                let (y, m, d) = super::super::civil_from_days_wide(days);
                let back = super::super::days_from_civil(
                    i64::try_from(y).unwrap(),
                    i64::try_from(m).unwrap(),
                    i64::try_from(d).unwrap(),
                );
                assert_eq!(i128::from(back), days);
            }
        }
    }
}
