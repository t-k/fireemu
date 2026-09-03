//! Schedules over the virtual clock (spec 11): Unix cron (five fields, names, ranges,
//! lists, steps) and the App Engine text form used by `onSchedule` (`every 5 minutes`,
//! `every day 09:00`, `every monday 09:00`). Time zones are limited to zones without
//! daylight saving time (a fixed offset table); others are refused rather than approximated.

use std::fmt;

use fireemu_core_types::time::LogicalInstant;

/// A set of allowed values of one cron field (bit `n` = value `n`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FieldSet(u64);

impl FieldSet {
    const fn contains(self, v: u32) -> bool {
        v < 64 && (self.0 >> v) & 1 == 1
    }

    /// The lowest allowed value at or above `v`, so a search lands on the next allowed
    /// minute or hour instead of stepping through the ones in between.
    const fn next_from(self, v: u32) -> Option<u32> {
        if v >= 64 {
            return None;
        }
        let above = (self.0 >> v) << v;
        if above == 0 {
            None
        } else {
            Some(above.trailing_zeros())
        }
    }

    /// The highest allowed value at or below `v` (the reverse search's counterpart).
    const fn prev_from(self, v: u32) -> Option<u32> {
        let mask = if v >= 63 {
            u64::MAX
        } else {
            (1u64 << (v + 1)) - 1
        };
        let below = self.0 & mask;
        if below == 0 {
            None
        } else {
            Some(below.ilog2())
        }
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

    /// Whether the day fields admit this date. A restricted day-of-week with `*` day-of-month
    /// (or vice versa) applies only the restricted one; both restricted means either matches
    /// (Vixie cron semantics).
    fn day_matches(&self, c: &Civil) -> bool {
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
        let mut steps = 0;
        self.next_after_in_counted(after, zone, &mut steps)
    }

    /// [`Self::next_after_in`], adding the search steps it took to `steps` (the deterministic
    /// work counter the catch-up bound is asserted with).
    fn next_after_in_counted(
        &self,
        after: LogicalInstant,
        zone: &dyn ZoneRules,
        steps: &mut u64,
    ) -> Option<LogicalInstant> {
        let after_secs = after.as_nanos().div_euclid(1_000_000_000);
        let after_secs = i64::try_from(after_secs).ok()?;
        if let Some(interval) = self.interval_seconds {
            *steps += 1;
            let next = after_secs.div_euclid(interval) * interval + interval;
            return Some(LogicalInstant::from_unix_seconds(next));
        }
        // Start at the next whole minute of local time.
        let mut local = zone.local_of(after_secs).div_euclid(60) * 60 + 60;
        let limit = local + 8 * 366 * 86_400;
        while local < limit {
            *steps += 1;
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
            if !self.day_matches(&c) {
                local = (local.div_euclid(86_400) + 1) * 86_400;
                continue;
            }
            let day = local.div_euclid(86_400) * 86_400;
            if !self.hours.contains(c.hour) {
                // Jump to the next allowed hour of the day, or to the next day.
                local = match self.hours.next_from(c.hour + 1) {
                    Some(h) => day + i64::from(h) * 3_600,
                    None => day + 86_400,
                };
                continue;
            }
            let hour = local.div_euclid(3_600) * 3_600;
            let Some(minute) = self.minutes.next_from(c.minute) else {
                local = hour + 3_600;
                continue;
            };
            if minute != c.minute {
                local = hour + i64::from(minute) * 60;
                continue;
            }
            if let Some(utc) = zone.utc_of(local) {
                // A run must be strictly after `after` in UTC too (a fall-back hour can
                // map a later civil minute to an earlier instant).
                if utc > after_secs {
                    return Some(LogicalInstant::from_unix_seconds(utc));
                }
            }
            // Jump to the next allowed minute of this hour, or to the next hour.
            local = match self.minutes.next_from(c.minute + 1) {
                Some(m) => hour + i64::from(m) * 60,
                None => hour + 3_600,
            };
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

    /// [`Self::window_in`] in the zone with `offset_seconds` from UTC.
    #[must_use]
    pub fn window(
        &self,
        from_exclusive: LogicalInstant,
        to_inclusive: LogicalInstant,
        offset_seconds: i64,
        count_cap: u64,
    ) -> RunWindow {
        self.window_in(
            from_exclusive,
            to_inclusive,
            &FixedOffset(offset_seconds),
            count_cap,
        )
    }

    /// What the `latest` and `none` catch-up policies need to know about the runs in
    /// `(from, to]` without enumerating them one occurrence at a time: the most recent run
    /// and how many runs the window holds.
    ///
    /// The latest run comes from a reverse search whose cost depends on the schedule's
    /// calendar density, never on how many runs the window holds. The count is exact up to
    /// `count_cap` and [`RunCount::AtLeast`] beyond it; an interval schedule (`every N
    /// minutes`) is counted exactly in constant time whatever the cap. [`RunWindow::steps`]
    /// reports the search steps taken, so a test can hold the bound.
    #[must_use]
    pub fn window_in(
        &self,
        from_exclusive: LogicalInstant,
        to_inclusive: LogicalInstant,
        zone: &dyn ZoneRules,
        count_cap: u64,
    ) -> RunWindow {
        let mut steps = 0u64;
        let empty = RunWindow {
            latest: None,
            count: RunCount::Exact(0),
            steps: 0,
        };
        let (Ok(from_secs), Ok(to_secs)) = (
            i64::try_from(from_exclusive.as_nanos().div_euclid(1_000_000_000)),
            i64::try_from(to_inclusive.as_nanos().div_euclid(1_000_000_000)),
        ) else {
            return empty;
        };
        if to_secs <= from_secs {
            return empty;
        }
        if let Some(interval) = self.interval_seconds {
            // Runs sit on multiples of the interval since the epoch, so both answers are
            // one division each.
            steps += 2;
            let last = to_secs.div_euclid(interval) * interval;
            let latest = (last > from_secs).then(|| LogicalInstant::from_unix_seconds(last));
            let count = to_secs.div_euclid(interval) - from_secs.div_euclid(interval);
            return RunWindow {
                latest,
                count: RunCount::Exact(u64::try_from(count).unwrap_or(0)),
                steps,
            };
        }
        let latest = self
            .last_cron_run(from_secs, to_secs, zone, &mut steps)
            .map(LogicalInstant::from_unix_seconds);
        let count = self.count_cron_runs(from_exclusive, to_inclusive, zone, count_cap, &mut steps);
        RunWindow {
            latest,
            count,
            steps,
        }
    }

    /// The latest cron run in `(from_secs, to_secs]`, searched backwards in civil time.
    ///
    /// Civil time maps to UTC monotonically (a gap has no instant, a fall-back hour runs at
    /// its first occurrence), so the first candidate found walking backwards whose instant
    /// lands in the window is the latest run, and the first candidate at or before `from` ends
    /// the search.
    ///
    /// The walk starts at `to` plus the widest offset the zone held over the last
    /// [`REVERSE_PROBE_HOURS`] hours, not at `to`'s own civil time: an offset change (a
    /// fall-back hour, a zone that moved) can put a later civil minute at an earlier instant.
    /// Candidates whose instant lands after `to` are rejected on the way down. An instant
    /// further back than that cannot have a higher civil time than `to`'s, because no zone is
    /// more than 26 hours wide.
    fn last_cron_run(
        &self,
        from_secs: i64,
        to_secs: i64,
        zone: &dyn ZoneRules,
        steps: &mut u64,
    ) -> Option<i64> {
        // The widest offset in force over the last day and a bit, sampled hourly: no zone
        // holds an offset for less than an hour, so every offset of the range is seen. `to`
        // plus that offset is at or above the civil time of every run still in the window.
        let mut max_offset = zone.local_of(to_secs) - to_secs;
        for hour in 1..=REVERSE_PROBE_HOURS {
            *steps += 1;
            let probe = to_secs - hour * 3_600;
            max_offset = max_offset.max(zone.local_of(probe) - probe);
        }
        let mut local = (to_secs + max_offset).div_euclid(60) * 60 + 60;
        let floor = local - 8 * 366 * 86_400;
        while local >= floor {
            *steps += 1;
            let c = Civil::from_unix(local);
            if !self.months.contains(c.month) {
                // Jump to the last minute before this month.
                local = days_from_civil(c.year, c.month, 1) * 86_400 - 60;
                continue;
            }
            if !self.day_matches(&c) {
                local = local.div_euclid(86_400) * 86_400 - 60;
                continue;
            }
            let day = local.div_euclid(86_400) * 86_400;
            if !self.hours.contains(c.hour) {
                // Back to the last minute of the previous allowed hour, or of the previous day.
                local = match (c.hour, self.hours.prev_from(c.hour.saturating_sub(1))) {
                    (0, _) | (_, None) => day - 60,
                    (_, Some(h)) => day + i64::from(h) * 3_600 + 59 * 60,
                };
                continue;
            }
            let hour = local.div_euclid(3_600) * 3_600;
            let Some(minute) = self.minutes.prev_from(c.minute) else {
                local = hour - 60;
                continue;
            };
            if minute != c.minute {
                local = hour + i64::from(minute) * 60;
                continue;
            }
            if let Some(utc) = zone.utc_of(local) {
                if utc <= to_secs {
                    return (utc > from_secs).then_some(utc);
                }
            }
            // Back to the previous allowed minute of this hour, or before the hour.
            local = match (c.minute, self.minutes.prev_from(c.minute.saturating_sub(1))) {
                (0, _) | (_, None) => hour - 60,
                (_, Some(m)) => hour + i64::from(m) * 60,
            };
        }
        None
    }

    /// How many cron runs `(from, to]` holds, counted forward and stopped at `count_cap`.
    fn count_cron_runs(
        &self,
        from_exclusive: LogicalInstant,
        to_inclusive: LogicalInstant,
        zone: &dyn ZoneRules,
        count_cap: u64,
        steps: &mut u64,
    ) -> RunCount {
        let mut counted = 0u64;
        let mut cursor = from_exclusive;
        loop {
            match self.next_after_in_counted(cursor, zone, steps) {
                Some(t) if t.as_nanos() <= to_inclusive.as_nanos() => {
                    counted += 1;
                    cursor = t;
                    if counted >= count_cap {
                        // One more run in the window means the count stops here.
                        return match self.next_after_in_counted(cursor, zone, steps) {
                            Some(next) if next.as_nanos() <= to_inclusive.as_nanos() => {
                                RunCount::AtLeast(counted)
                            }
                            _ => RunCount::Exact(counted),
                        };
                    }
                }
                _ => return RunCount::Exact(counted),
            }
        }
    }
}

/// How far back the reverse search probes the zone's offset before it starts walking: more
/// than the 26 hours between the earliest and the latest offset any zone uses, so the walk
/// starts at or above the civil time of every run that could still be in the window.
const REVERSE_PROBE_HOURS: i64 = 27;

/// How many runs a bounded count found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunCount {
    /// The window holds exactly this many runs.
    Exact(u64),
    /// The window holds at least this many runs; counting stopped at the cap.
    AtLeast(u64),
}

impl RunCount {
    /// The number counted (the cap, when counting stopped there).
    #[must_use]
    pub const fn value(self) -> u64 {
        match self {
            Self::Exact(n) | Self::AtLeast(n) => n,
        }
    }

    /// Whether the count is exact.
    #[must_use]
    pub const fn is_exact(self) -> bool {
        matches!(self, Self::Exact(_))
    }

    /// Whether the window is known to hold no run.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        matches!(self, Self::Exact(0))
    }

    /// The count with `n` runs taken out of it (the ones a policy keeps).
    #[must_use]
    pub const fn saturating_sub(self, n: u64) -> Self {
        match self {
            Self::Exact(v) => Self::Exact(v.saturating_sub(n)),
            Self::AtLeast(v) => Self::AtLeast(v.saturating_sub(n)),
        }
    }
}

impl fmt::Display for RunCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.value();
        let unit = if n == 1 { "run" } else { "runs" };
        if self.is_exact() {
            write!(f, "{n} {unit}")
        } else {
            write!(f, "at least {n} {unit}")
        }
    }
}

/// A bounded look at the runs a schedule has in a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunWindow {
    /// The most recent run in the window, if any.
    pub latest: Option<LogicalInstant>,
    /// How many runs the window holds, exact up to the cap the caller gave.
    pub count: RunCount,
    /// Search steps taken. Bounded by the schedule's calendar density and the count cap,
    /// never by how many runs the window holds.
    pub steps: u64,
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
    fireemu_core_types::time::days_from_civil(y, i64::from(m), i64::from(d))
}

/// Civil date of days since 1970-01-01.
#[must_use]
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let (year, month, day) = fireemu_core_types::time::civil_from_days(z);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
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
