//! Schedules over the virtual clock (spec 11): Unix cron (five fields, names, ranges,
//! lists, steps) and the App Engine text form used by `onSchedule` (`every 5 minutes`,
//! `every day 09:00`, `every monday 09:00`). Time zones are limited to zones without
//! daylight saving time (a fixed offset table); others are refused rather than approximated.

use std::fmt;

use ftd_core_types::time::LogicalInstant;

/// A set of allowed values of one cron field (bit `n` = value `n`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FieldSet(u64);

impl FieldSet {
    const fn contains(self, v: u32) -> bool {
        v < 64 && (self.0 >> v) & 1 == 1
    }
}

/// A parsed schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    source: String,
    /// App Engine interval (`every N minutes|hours`): runs every N units from the schedule's
    /// start, unrelated to the wall clock (`Some(seconds)`); `None` = cron fields.
    interval_seconds: Option<i64>,
    minutes: FieldSet,
    hours: FieldSet,
    days_of_month: FieldSet,
    months: FieldSet,
    days_of_week: FieldSet,
    /// `*` in both day fields = every day; a restricted day-of-week with `*` day-of-month
    /// (or vice versa) applies only the restricted one (Vixie cron semantics).
    dom_restricted: bool,
    dow_restricted: bool,
}

/// Schedule parse errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleError {
    /// Not five fields and not a recognised App Engine form.
    Malformed(String),
    /// A field value is out of range.
    OutOfRange {
        /// Field name.
        field: &'static str,
        /// Offending text.
        value: String,
    },
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(s) => write!(f, "unrecognised schedule {s:?}"),
            Self::OutOfRange { field, value } => {
                write!(f, "cron field {field}: {value:?} is out of range")
            }
        }
    }
}

impl std::error::Error for ScheduleError {}

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];
const DAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

fn parse_value(
    text: &str,
    field: &'static str,
    names: &[&str],
    base: u32,
) -> Result<u32, ScheduleError> {
    if let Ok(n) = text.parse::<u32>() {
        return Ok(n);
    }
    let lower = text.to_ascii_lowercase();
    names
        .iter()
        .position(|n| *n == lower)
        .map(|i| u32::try_from(i).unwrap_or(0) + base)
        .ok_or_else(|| ScheduleError::OutOfRange {
            field,
            value: text.to_owned(),
        })
}

fn parse_field(
    text: &str,
    field: &'static str,
    min: u32,
    max: u32,
    names: &[&str],
) -> Result<(FieldSet, bool), ScheduleError> {
    let mut set = 0u64;
    let mut restricted = false;
    for item in text.split(',') {
        let (range, step) = match item.split_once('/') {
            Some((r, s)) => (
                r,
                s.parse::<u32>().ok().filter(|s| *s >= 1).ok_or_else(|| {
                    ScheduleError::OutOfRange {
                        field,
                        value: item.to_owned(),
                    }
                })?,
            ),
            None => (item, 1),
        };
        let (lo, hi) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            restricted = true;
            (
                parse_value(a, field, names, min)?,
                parse_value(b, field, names, min)?,
            )
        } else {
            restricted = true;
            let v = parse_value(range, field, names, min)?;
            // `N/step` means "from N to max every step".
            if step > 1 {
                (v, max)
            } else {
                (v, v)
            }
        };
        if lo < min || hi > max || lo > hi {
            return Err(ScheduleError::OutOfRange {
                field,
                value: item.to_owned(),
            });
        }
        let mut v = lo;
        while v <= hi {
            set |= 1 << v;
            v += step;
        }
        if range == "*" && step > 1 {
            restricted = true;
        }
    }
    Ok((FieldSet(set), restricted))
}

impl Schedule {
    /// Parses a cron expression or an App Engine text schedule.
    pub fn parse(text: &str) -> Result<Self, ScheduleError> {
        let text = text.trim();
        if let Some(seconds) = app_engine_interval(text)? {
            return Ok(Self {
                source: text.to_owned(),
                interval_seconds: Some(seconds),
                minutes: FieldSet(0),
                hours: FieldSet(0),
                days_of_month: FieldSet(0),
                months: FieldSet(0),
                days_of_week: FieldSet(0),
                dom_restricted: false,
                dow_restricted: false,
            });
        }
        let expanded = match text {
            "@hourly" => "0 * * * *".to_owned(),
            "@daily" | "@midnight" => "0 0 * * *".to_owned(),
            "@weekly" => "0 0 * * 0".to_owned(),
            "@monthly" => "0 0 1 * *".to_owned(),
            "@yearly" | "@annually" => "0 0 1 1 *".to_owned(),
            t if t.to_ascii_lowercase().starts_with("every ") => app_engine_to_cron(t)?,
            t => t.to_owned(),
        };
        let fields: Vec<&str> = expanded.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(ScheduleError::Malformed(text.to_owned()));
        }
        let (minutes, _) = parse_field(fields[0], "minute", 0, 59, &[])?;
        let (hours, _) = parse_field(fields[1], "hour", 0, 23, &[])?;
        let (days_of_month, month_days_restricted) =
            parse_field(fields[2], "day-of-month", 1, 31, &[])?;
        let (months, _) = parse_field(fields[3], "month", 1, 12, &MONTHS)?;
        let (mut days_of_week, weekdays_restricted) =
            parse_field(fields[4], "day-of-week", 0, 7, &DAYS)?;
        // 7 is Sunday too.
        if days_of_week.contains(7) {
            days_of_week = FieldSet(days_of_week.0 | 1);
        }
        Ok(Self {
            source: text.to_owned(),
            interval_seconds: None,
            minutes,
            hours,
            days_of_month,
            months,
            days_of_week,
            dom_restricted: month_days_restricted,
            dow_restricted: weekdays_restricted,
        })
    }

    /// The schedule text as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }

    fn matches(&self, c: &Civil) -> bool {
        if !self.minutes.contains(c.minute) || !self.hours.contains(c.hour) {
            return false;
        }
        if !self.months.contains(c.month) {
            return false;
        }
        let dom = self.days_of_month.contains(c.day);
        let dow = self.days_of_week.contains(c.weekday);
        match (self.dom_restricted, self.dow_restricted) {
            (true, true) => dom || dow,
            (true, false) => dom,
            (false, true) => dow,
            (false, false) => true,
        }
    }

    /// The first run strictly after `after` in the zone with `offset_seconds` from UTC.
    #[must_use]
    pub fn next_after(&self, after: LogicalInstant, offset_seconds: i64) -> Option<LogicalInstant> {
        self.next_after_in(after, &FixedOffset(offset_seconds))
    }

    /// The first run strictly after `after` in `zone`. Intervals are anchored at the Unix
    /// epoch; cron fields are matched in the zone's civil time and searched over the next
    /// eight years (a leap-day schedule waits at most that long), after which the schedule
    /// is treated as unsatisfiable. A civil minute that does not exist (a daylight-saving
    /// gap) is skipped; an ambiguous one (a fall-back hour) runs at its first occurrence.
    #[must_use]
    pub fn next_after_in(
        &self,
        after: LogicalInstant,
        zone: &dyn ZoneRules,
    ) -> Option<LogicalInstant> {
        let after_secs = after.as_nanos().div_euclid(1_000_000_000);
        let after_secs = i64::try_from(after_secs).ok()?;
        if let Some(interval) = self.interval_seconds {
            let next = after_secs.div_euclid(interval) * interval + interval;
            return Some(LogicalInstant::from_unix_seconds(next));
        }
        // Start at the next whole minute of local time.
        let mut local = zone.local_of(after_secs).div_euclid(60) * 60 + 60;
        let limit = local + 8 * 366 * 86_400;
        while local < limit {
            let c = Civil::from_unix(local);
            if !self.months.contains(c.month) {
                // Jump to the first day of the next month.
                let (y, m) = if c.month == 12 {
                    (c.year + 1, 1)
                } else {
                    (c.year, c.month + 1)
                };
                local = days_from_civil(y, m, 1) * 86_400;
                continue;
            }
            let dom = self.days_of_month.contains(c.day);
            let dow = self.days_of_week.contains(c.weekday);
            let day_ok = match (self.dom_restricted, self.dow_restricted) {
                (true, true) => dom || dow,
                (true, false) => dom,
                (false, true) => dow,
                (false, false) => true,
            };
            if !day_ok {
                local = (local.div_euclid(86_400) + 1) * 86_400;
                continue;
            }
            if !self.hours.contains(c.hour) {
                local = (local.div_euclid(3_600) + 1) * 3_600;
                continue;
            }
            if self.matches(&c) {
                if let Some(utc) = zone.utc_of(local) {
                    // A run must be strictly after `after` in UTC too (a fall-back hour can
                    // map a later civil minute to an earlier instant).
                    if utc > after_secs {
                        return Some(LogicalInstant::from_unix_seconds(utc));
                    }
                }
            }
            local += 60;
        }
        None
    }

    /// Every run in `(from, to]`, at most `max` (the runtime's catch-up cap).
    #[must_use]
    pub fn runs_between(
        &self,
        from_exclusive: LogicalInstant,
        to_inclusive: LogicalInstant,
        offset_seconds: i64,
        max: usize,
    ) -> Vec<LogicalInstant> {
        self.runs_between_in(
            from_exclusive,
            to_inclusive,
            &FixedOffset(offset_seconds),
            max,
        )
    }

    /// [`Self::runs_between`] in `zone`.
    #[must_use]
    pub fn runs_between_in(
        &self,
        from_exclusive: LogicalInstant,
        to_inclusive: LogicalInstant,
        zone: &dyn ZoneRules,
        max: usize,
    ) -> Vec<LogicalInstant> {
        let mut out = Vec::new();
        let mut cursor = from_exclusive;
        while out.len() < max {
            match self.next_after_in(cursor, zone) {
                Some(t) if t.as_nanos() <= to_inclusive.as_nanos() => {
                    out.push(t);
                    cursor = t;
                }
                _ => break,
            }
        }
        out
    }
}

/// `every N minutes|hours` (App Engine interval form): the interval in seconds.
fn app_engine_interval(text: &str) -> Result<Option<i64>, ScheduleError> {
    let lower = text.to_ascii_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();
    let malformed = || ScheduleError::Malformed(text.to_owned());
    match words.as_slice() {
        ["every", n, unit] if n.chars().all(|c| c.is_ascii_digit()) => {
            let n: i64 = n.parse().map_err(|_| malformed())?;
            match *unit {
                "minutes" | "mins" | "minute" if (1..=1440).contains(&n) => Ok(Some(n * 60)),
                "hours" | "hour" if (1..=24).contains(&n) => Ok(Some(n * 3_600)),
                _ => Err(malformed()),
            }
        }
        _ => Ok(None),
    }
}

/// `every day HH:MM`, `every monday HH:MM` → cron.
fn app_engine_to_cron(text: &str) -> Result<String, ScheduleError> {
    let lower = text.to_ascii_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();
    let malformed = || ScheduleError::Malformed(text.to_owned());
    match words.as_slice() {
        ["every", day, time] => {
            let (h, m) = time.split_once(':').ok_or_else(malformed)?;
            let h: u32 = h.parse().map_err(|_| malformed())?;
            let m: u32 = m.parse().map_err(|_| malformed())?;
            if h > 23 || m > 59 {
                return Err(malformed());
            }
            let dow = match *day {
                "day" => "*".to_owned(),
                d => {
                    let idx = DAYS
                        .iter()
                        .position(|n| d.starts_with(n))
                        .ok_or_else(malformed)?;
                    idx.to_string()
                }
            };
            Ok(format!("{m} {h} * * {dow}"))
        }
        _ => Err(malformed()),
    }
}

/// Conversion between UTC seconds and a zone's civil time (spec 11.4: daylight-saving
/// rules live in an audited adapter; the core only knows this interface).
pub trait ZoneRules {
    /// Civil seconds (UTC seconds plus the offset in force at that instant).
    fn local_of(&self, utc_secs: i64) -> i64;
    /// UTC seconds of a civil time; `None` when the civil time does not exist (a gap),
    /// the earliest occurrence when it exists twice (a fall-back hour).
    fn utc_of(&self, local_secs: i64) -> Option<i64>;
}

/// A zone with one fixed offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedOffset(pub i64);

impl ZoneRules for FixedOffset {
    fn local_of(&self, utc_secs: i64) -> i64 {
        utc_secs + self.0
    }

    fn utc_of(&self, local_secs: i64) -> Option<i64> {
        Some(local_secs - self.0)
    }
}

/// Civil date-time fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    /// Year.
    pub year: i64,
    /// Month 1-12.
    pub month: u32,
    /// Day 1-31.
    pub day: u32,
    /// Hour 0-23.
    pub hour: u32,
    /// Minute 0-59.
    pub minute: u32,
    /// Weekday, 0 = Sunday.
    pub weekday: u32,
}

impl Civil {
    /// Civil fields of a Unix timestamp (seconds).
    #[must_use]
    pub fn from_unix(secs: i64) -> Self {
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        let weekday = u32::try_from((days + 4).rem_euclid(7)).unwrap_or(0);
        Self {
            year,
            month,
            day,
            hour: u32::try_from(rem / 3_600).unwrap_or(0),
            minute: u32::try_from((rem % 3_600) / 60).unwrap_or(0),
            weekday,
        }
    }
}

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
#[must_use]
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Civil date of days since 1970-01-01.
#[must_use]
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Time zone errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeZoneError {
    /// Unknown or daylight-saving zone (not approximated).
    Unsupported(String),
}

impl fmt::Display for TimeZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(z) => write!(
                f,
                "time zone {z:?} is not supported (only UTC and fixed-offset zones without daylight saving time)"
            ),
        }
    }
}

impl std::error::Error for TimeZoneError {}

/// UTC offset in seconds of a zone that has had a single fixed offset since 1992 (the
/// virtual clock defaults to the 2020s; earlier instants in these zones are not modelled).
/// Every other zone, daylight-saving ones included, is refused rather than approximated.
pub fn fixed_offset_seconds(zone: Option<&str>) -> Result<i64, TimeZoneError> {
    let Some(zone) = zone else { return Ok(0) };
    let offset = match zone {
        "UTC" | "Etc/UTC" | "GMT" | "Etc/GMT" => 0,
        "Asia/Tokyo" | "Asia/Seoul" | "Japan" => 32_400,
        "Asia/Shanghai" | "Asia/Singapore" | "Asia/Hong_Kong" | "Asia/Taipei"
        | "Asia/Kuala_Lumpur" => 28_800,
        "Asia/Bangkok" | "Asia/Jakarta" | "Asia/Ho_Chi_Minh" => 25_200,
        "Asia/Kolkata" | "Asia/Calcutta" => 19_800,
        "Asia/Dubai" => 14_400,
        "Africa/Johannesburg" => 7_200,
        "Africa/Lagos" => 3_600,
        "Africa/Nairobi" | "Asia/Riyadh" => 10_800,
        "America/Phoenix" => -25_200,
        "Pacific/Honolulu" => -36_000,
        _ => return Err(TimeZoneError::Unsupported(zone.to_owned())),
    };
    Ok(offset)
}
