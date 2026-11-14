//! Production's Cloud Tasks admission, for the strict profile.
//!
//! Everything here is a pure function of the request body, the queue and the clock. The answers and the order of the checks are
//! what two production recordings of `createTask` showed (TASK-QUEUE-FUNCTIONS, runs 47574c and b01fa6, 122 steps each, the
//! pairwise table of id, schedule time, dispatch deadline and body size included), so a check whose text or place was not
//! recorded says so with `UNRECORDED`.
//!
//! Order of the checks, from the pairs that were wrong on two axes at once:
//! 1. JSON field names (`Invalid JSON payload received. Unknown name ...`);
//! 2. the proto parse of `scheduleTime` and `dispatchDeadline` (both messages, in that order, joined by a new line);
//! 3. `Task.payload_type is not set.`;
//! 4. the task name: its shape, its id, then its queue;
//! 5. the dispatch deadline's range;
//! 6. how far ahead `scheduleTime` is;
//! 7. the task's size (UNRECORDED: its place relative to the others).

use std::time::Duration;

use serde_json::{json, Map, Value};

/// The largest task Cloud Tasks takes (documented 1 MiB; recorded: 1,000,070 bytes were accepted, 1,100,070 refused).
pub const MAX_TASK_BYTES: usize = 1_048_576;
/// Production's `Task.scheduleTime` horizon: `720h`.
pub const MAX_SCHEDULE_AHEAD_SECONDS: i64 = 720 * 3600;
/// The dispatch deadline's range, in nanoseconds: `[15s, 30m]`.
const DEADLINE_MIN_NANOS: i128 = 15 * 1_000_000_000;
const DEADLINE_MAX_NANOS: i128 = 30 * 60 * 1_000_000_000;
/// The default dispatch deadline of an HTTP task, which a deadline of `0s` also selects (recorded).
pub const DEFAULT_DEADLINE_SECONDS: u64 = 600;

/// A refusal in Cloud Tasks' own form: the HTTP status, the `google.rpc.Code` name and the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// HTTP status.
    pub http: u16,
    /// `google.rpc.Code` name.
    pub status: &'static str,
    /// The message text.
    pub message: String,
    /// `error.details`: what production attached to an argument error (a `BadRequest` naming the field, or a `Help` link to
    /// the definition of the field).
    pub details: Option<Value>,
}

impl Refusal {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self {
            http: 400,
            status: "INVALID_ARGUMENT",
            message: message.into(),
            details: None,
        }
    }

    /// An argument error with a `google.rpc.BadRequest` detail: one violation of `(field, description)` for each pair.
    fn bad_request(message: impl Into<String>, violations: &[(&str, &str)]) -> Self {
        let violations: Vec<Value> = violations
            .iter()
            .map(|(field, description)| {
                if field.is_empty() {
                    json!({"description": description})
                } else {
                    json!({"field": field, "description": description})
                }
            })
            .collect();
        Self {
            details: Some(json!([{
                "@type": "type.googleapis.com/google.rpc.BadRequest",
                "fieldViolations": violations,
            }])),
            ..Self::invalid(message)
        }
    }

    /// An argument error with a `google.rpc.Help` detail linking to the definition of a task field.
    fn help(message: impl Into<String>, definition_of: &str) -> Self {
        Self {
            details: Some(json!([{
                "@type": "type.googleapis.com/google.rpc.Help",
                "links": [{
                    "description": format!("Definition of {definition_of}"),
                    "url": "https://cloud.google.com/tasks/docs/reference/rest/v2/projects.locations.queues.tasks#Task.FIELDS.name",
                }],
            }])),
            ..Self::invalid(message)
        }
    }

    /// `{"error": {"code", "message", "status", "details"?}}`.
    #[must_use]
    pub fn body(&self) -> Value {
        let mut error = json!({"code": self.http, "message": self.message, "status": self.status});
        if let Some(details) = &self.details {
            error["details"] = details.clone();
        }
        json!({ "error": error })
    }

    /// The answer for a queue that does not exist (recorded for createTask and getQueue).
    #[must_use]
    pub fn queue_missing() -> Self {
        Self {
            http: 404,
            status: "NOT_FOUND",
            message: "Queue does not exist. If you just created the queue, wait at least a minute for the queue to initialize."
                .to_owned(),
            details: None,
        }
    }

    /// A task that is in the queue under that name now.
    #[must_use]
    pub fn already_exists() -> Self {
        Self {
            http: 409,
            status: "ALREADY_EXISTS",
            message: "Requested entity already exists".to_owned(),
            details: None,
        }
    }

    /// A task name that was used by a task that finished or was deleted not long ago.
    #[must_use]
    pub fn existed_too_recently() -> Self {
        Self {
            http: 409,
            status: "ALREADY_EXISTS",
            message: "The task cannot be created because a task with this name existed too recently. For more information about task de-duplication see https://cloud.google.com/tasks/docs/reference/rest/v2/projects.locations.queues.tasks/create#body.request_body.FIELDS.task."
                .to_owned(),
            details: None,
        }
    }

    /// A task that is not in the queue (deleteTask, recorded).
    #[must_use]
    pub fn task_not_found() -> Self {
        Self {
            http: 404,
            status: "NOT_FOUND",
            message: "Requested entity was not found.".to_owned(),
            details: None,
        }
    }
}

/// How long a finished or deleted task's name stays taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameReuse {
    /// The pinned emulator's rule: a finished name stays taken (bounded here by the history caps).
    Retained,
    /// The name is free as soon as the task is gone (the strict profile's development default).
    Immediate,
    /// Production's tombstone: the name is taken for this long (documented as about an hour).
    Window(Duration),
}

// ---- civil time ------------------------------------------------------------------------------

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

/// An RFC 3339 instant as nanoseconds since the Unix epoch.
///
/// Only upper-case `T` and `Z`, a numeric offset `+hh:mm` or `-hh:mm`, at most nine fractional digits, and a second of 60
/// (a leap second: it is the next second, as the recorded `2026-12-31T23:59:60Z` was read). The range is the proto
/// `Timestamp`'s: years 1 to 9999.
#[must_use]
pub fn parse_timestamp(text: &str) -> Option<i128> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || !text.is_ascii() {
        return None;
    }
    let number = |from: usize, to: usize| -> Option<i64> {
        let part = text.get(from..to)?;
        if part.bytes().all(|b| b.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut at = 19;
    let mut nanos: i128 = 0;
    if bytes[at] == b'.' {
        let start = at + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        let digits = end - start;
        if digits == 0 || digits > 9 {
            return None;
        }
        nanos =
            text[start..end].parse::<i128>().ok()? * 10_i128.pow(u32::try_from(9 - digits).ok()?);
        at = end;
    }
    let offset_seconds: i64 = match text.get(at..)? {
        "Z" => 0,
        zone if zone.len() == 6 && (zone.starts_with('+') || zone.starts_with('-')) => {
            let z = zone.as_bytes();
            if z[3] != b':' {
                return None;
            }
            let (hh, mm) = (number(at + 1, at + 3)?, number(at + 4, at + 6)?);
            if hh > 23 || mm > 59 {
                return None;
            }
            let magnitude = hh * 3600 + mm * 60;
            if z[0] == b'-' {
                -magnitude
            } else {
                magnitude
            }
        }
        _ => return None,
    };
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
        - offset_seconds;
    Some(i128::from(seconds) * 1_000_000_000 + nanos)
}

/// `YYYY-MM-DDTHH:MM:SS` of whole seconds since the epoch, in UTC.
fn civil_text(seconds: i64) -> String {
    let (y, m, d) = civil_from_days(seconds.div_euclid(86_400));
    let rest = seconds.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// A proto `Timestamp` as Cloud Tasks prints it in a JSON answer: UTC, `Z`, and a fraction of 0, 3, 6 or 9 digits.
#[must_use]
pub fn format_proto_timestamp(nanos: i128) -> String {
    let seconds = i64::try_from(nanos.div_euclid(1_000_000_000)).unwrap_or(0);
    let fraction = u32::try_from(nanos.rem_euclid(1_000_000_000)).unwrap_or(0);
    let digits = if fraction == 0 {
        String::new()
    } else if fraction % 1_000_000 == 0 {
        format!(".{:03}", fraction / 1_000_000)
    } else if fraction % 1000 == 0 {
        format!(".{:06}", fraction / 1000)
    } else {
        format!(".{fraction:09}")
    };
    format!("{}{digits}Z", civil_text(seconds))
}

/// The offset of `America/Los_Angeles` at a UTC instant, in seconds (the US rule since 2007: daylight time from the second
/// Sunday of March, 02:00 local, to the first Sunday of November, 02:00 local).
fn los_angeles_offset(seconds: i64) -> i64 {
    let year = civil_from_days(seconds.div_euclid(86_400)).0;
    let nth_sunday = |month: i64, nth: i64| -> i64 {
        let first = days_from_civil(year, month, 1);
        // 1970-01-01 was a Thursday: day 0 is Thursday, so Sunday is `(days + 4) % 7 == 0`.
        let to_sunday = (7 - (first + 4).rem_euclid(7)) % 7;
        first + to_sunday + (nth - 1) * 7
    };
    let start = nth_sunday(3, 2) * 86_400 + 2 * 3600 + 8 * 3600;
    let end = nth_sunday(11, 1) * 86_400 + 2 * 3600 + 7 * 3600;
    if (start..end).contains(&seconds) {
        -7 * 3600
    } else {
        -8 * 3600
    }
}

/// The text Cloud Tasks puts in "is too far in the future": the instant in Los Angeles time, the fraction without trailing zeros.
fn los_angeles_text(nanos: i128) -> String {
    let seconds = i64::try_from(nanos.div_euclid(1_000_000_000)).unwrap_or(0);
    let fraction = u32::try_from(nanos.rem_euclid(1_000_000_000)).unwrap_or(0);
    let offset = los_angeles_offset(seconds);
    let local = civil_text(seconds + offset);
    let digits = if fraction == 0 {
        String::new()
    } else {
        format!(".{}", format!("{fraction:09}").trim_end_matches('0'))
    };
    let magnitude = offset.abs();
    let sign = if offset < 0 { '-' } else { '+' };
    format!(
        "{local}{digits}{sign}{:02}:{:02}",
        magnitude / 3600,
        (magnitude % 3600) / 60
    )
}

// ---- durations -------------------------------------------------------------------------------

/// The most seconds a proto `Duration` holds, either way.
const MAX_DURATION_SECONDS: i128 = 315_576_000_000;

/// A proto `Duration` text: an optional minus, digits, up to nine fractional digits, and `s`. Nanoseconds.
#[must_use]
pub fn parse_duration(text: &str) -> Option<i128> {
    let body = text.strip_suffix('s')?;
    let (negative, body) = body
        .strip_prefix('-')
        .map_or((false, body), |rest| (true, rest));
    let (whole, fraction) = body.split_once('.').map_or((body, ""), |(w, f)| (w, f));
    if body.ends_with('.')
        || whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 9
    {
        return None;
    }
    if !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let seconds: i128 = whole.parse().ok()?;
    let nanos: i128 = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<i128>().ok()? * 10_i128.pow(u32::try_from(9 - fraction.len()).ok()?)
    };
    // The proto Duration holds at most 315,576,000,000 seconds either way (UNRECORDED: production's text for a longer one
    // was not observed; it is refused here as an invalid format, which no recorded answer contradicts).
    if seconds > MAX_DURATION_SECONDS {
        return None;
    }
    let total = seconds.checked_mul(1_000_000_000)?.checked_add(nanos)?;
    if total > MAX_DURATION_SECONDS * 1_000_000_000 + 999_999_999 {
        return None;
    }
    Some(if negative { -total } else { total })
}

/// A duration as a proto prints it in JSON: whole seconds, or a fraction of 3, 6 or 9 digits.
#[must_use]
pub fn format_duration(nanos: i128) -> String {
    let seconds = nanos.div_euclid(1_000_000_000);
    let fraction = nanos.rem_euclid(1_000_000_000);
    if fraction == 0 {
        format!("{seconds}s")
    } else if fraction % 1_000_000 == 0 {
        format!("{seconds}.{:03}s", fraction / 1_000_000)
    } else if fraction % 1000 == 0 {
        format!("{seconds}.{:06}s", fraction / 1000)
    } else {
        format!("{seconds}.{fraction:09}s")
    }
}

// ---- task names ------------------------------------------------------------------------------

/// Whether `id` is a Cloud Tasks task id: 1 to 500 of `[A-Za-z0-9_-]`.
#[must_use]
pub fn valid_task_id(id: &str) -> bool {
    (1..=500).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

const NAME_FORMAT: &str = "Task name must be formatted: \"projects/<PROJECT_ID>/locations/<LOCATION_ID>/queues/<QUEUE_ID>/tasks/<TASK_ID>\".";

/// A generated task id: 19 decimal digits, as production's were (all 19 digits in 116 of 122, 20 in a few). The value is not
/// meaningful; it is a mix of the clock and a counter, so that two tasks do not share one.
#[must_use]
pub fn generated_task_id(now_nanos: i128, counter: u64) -> String {
    let mut x = u64::try_from(now_nanos.rem_euclid(i128::from(u64::MAX))).unwrap_or(0)
        ^ counter.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    let id = 1_000_000_000_000_000_000_u64 + x % 8_000_000_000_000_000_000_u64;
    id.to_string()
}

// ---- the retry gaps --------------------------------------------------------------------------

/// The shortest gap production left before a retry once a task kept failing, by the number of the gap (the first retry
/// follows gap 1). Recorded for a queue with `minBackoff` 1 s, `maxBackoff` 2 s, `maxDoublings` 1 and 100 attempts, in both
/// runs (45 and 44 attempts): gap 1 was 1 s and gaps 2 to 11 were 2 s (the declared schedule), gaps 12 to 14 were 4 s, gaps 15
/// and 16 were 8 s and every gap from 17 on was 10 s. How this depends on the declared `maxBackoff` was not recorded, so it
/// is a floor under the declared gap, never a replacement for it.
#[must_use]
pub const fn production_gap_floor_millis(gap_number: u32) -> u64 {
    match gap_number {
        0..=11 => 0,
        12..=14 => 4_000,
        15..=16 => 8_000,
        _ => 10_000,
    }
}

/// The gap before a retry: the declared one, or under `production` backoff no shorter than production's recorded floor.
#[must_use]
pub fn retry_gap_millis(declared_millis: u64, gap_number: u32, production: bool) -> u64 {
    if production {
        declared_millis.max(production_gap_floor_millis(gap_number))
    } else {
        declared_millis
    }
}

// ---- the answer layout -----------------------------------------------------------------------

/// The order of the fields of a Cloud Tasks answer, as proto prints them (recorded in 110 task answers and 92 errors of the two
/// TASK-QUEUE-FUNCTIONS recordings, all with the same order). A field not named here follows, in alphabetical order. The members of
/// `headers` are not ordered by this list: production printed them in a different order from one run to the next.
const FIELD_ORDER: [&str; 24] = [
    "name",
    "httpRequest",
    "url",
    "httpMethod",
    "headers",
    "body",
    "oidcToken",
    "serviceAccountEmail",
    "audience",
    "scheduleTime",
    "createTime",
    "dispatchDeadline",
    "view",
    "error",
    "code",
    "message",
    "status",
    "details",
    "@type",
    "fieldViolations",
    "links",
    "field",
    "description",
    "url",
];

/// A value as production prints an answer: multi-line JSON with two-space indentation, fields in proto order, `<`, `>` and `&`
/// escaped and a newline at the end (`{}` for an empty answer), the layout of every recorded answer (638 bytes for a task whose
/// compact form is 543).
#[must_use]
pub fn pretty(value: &Value) -> String {
    let mut out = String::new();
    write_pretty(value, 0, "", &mut out);
    out.push('\n');
    // Production escapes `<`, `>` and `&` inside strings (`\u003c`; recorded in the message of a malformed task name). They can
    // only occur inside a string of the text above, so a plain replacement is exact.
    out.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

/// The members of a link are `description` then `url`, the opposite of `url` before the rest in a request.
const LINK_ORDER: [&str; 2] = ["description", "url"];

/// `parent` is the name of the member that holds `value` (an array's items have their array's name).
fn write_pretty(value: &Value, depth: usize, parent: &str, out: &mut String) {
    let in_headers = parent == "headers";
    let pad = |n: usize| "  ".repeat(n);
    match value {
        Value::Object(map) if map.is_empty() => out.push_str("{}"),
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            if !in_headers {
                let order: &[&str] = if parent == "links" {
                    &LINK_ORDER
                } else {
                    &FIELD_ORDER
                };
                members.sort_by_key(|(key, _)| {
                    order
                        .iter()
                        .position(|known| known == key)
                        .unwrap_or(order.len())
                });
            }
            out.push_str("{\n");
            for (index, (key, member)) in members.iter().enumerate() {
                out.push_str(&pad(depth + 1));
                out.push_str(&Value::String((*key).clone()).to_string());
                out.push_str(": ");
                write_pretty(member, depth + 1, key, out);
                out.push_str(if index + 1 == members.len() {
                    "\n"
                } else {
                    ",\n"
                });
            }
            out.push_str(&pad(depth));
            out.push('}');
        }
        Value::Array(items) if items.is_empty() => out.push_str("[]"),
        Value::Array(items) => {
            out.push_str("[\n");
            for (index, item) in items.iter().enumerate() {
                out.push_str(&pad(depth + 1));
                write_pretty(item, depth + 1, parent, out);
                out.push_str(if index + 1 == items.len() {
                    "\n"
                } else {
                    ",\n"
                });
            }
            out.push_str(&pad(depth));
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

// ---- the admission ---------------------------------------------------------------------------

/// What the admission decided.
#[derive(Debug, Clone, PartialEq)]
pub struct Admitted {
    /// The task's full name (given, or generated).
    pub name: String,
    /// `scheduleTime` as the answer prints it; in the past it is the time of the request.
    pub schedule_time: String,
    /// The same instant in nanoseconds.
    pub schedule_nanos: i128,
    /// The dispatch deadline, in whole seconds (rounded up), and as the answer prints it.
    pub deadline_seconds: u64,
    /// The dispatch deadline as the answer prints it.
    pub deadline_text: String,
    /// `createTime`: the request's second.
    pub create_time: String,
    /// `BASIC` or `FULL`.
    pub view: &'static str,
}

const TASK_FIELDS: [&str; 10] = [
    "name",
    "appEngineHttpRequest",
    "httpRequest",
    "scheduleTime",
    "createTime",
    "dispatchDeadline",
    "dispatchCount",
    "responseCount",
    "firstAttempt",
    "lastAttempt",
];
const HTTP_FIELDS: [&str; 6] = [
    "url",
    "httpMethod",
    "headers",
    "body",
    "oauthToken",
    "oidcToken",
];

fn unknown_name(field: &str, at: Option<&str>) -> Refusal {
    let message = match at {
        Some(at) => format!(
            "Invalid JSON payload received. Unknown name \"{field}\" at '{at}': Cannot find field."
        ),
        None => {
            format!("Invalid JSON payload received. Unknown name \"{field}\": Cannot find field.")
        }
    };
    let violation = [(at.unwrap_or(""), message.as_str())];
    Refusal::bad_request(message.clone(), &violation)
}

/// Checks a createTask body the way production does and decides what the task is. `queue` is
/// `projects/<p>/locations/<l>/queues/<q>`; `size` is the task's size in bytes (the decoded body and the names and values of its headers, as the strict enqueue counts it);
/// `default_deadline_seconds` is the dispatch deadline of a task that names none ([`DEFAULT_DEADLINE_SECONDS`] in production).
///
/// # Errors
/// The refusal production gave for the first check that failed.
#[allow(clippy::too_many_lines)] // One ordered pass over the checks production makes; splitting it would hide the order.
pub fn admit(
    queue: &str,
    body: &Value,
    now_nanos: i128,
    counter: u64,
    default_deadline_seconds: u64,
    size: impl FnOnce() -> usize,
) -> Result<Admitted, Refusal> {
    let empty = Map::new();
    let request = body.as_object().unwrap_or(&empty);
    // 1. JSON field names.
    if let Some(field) = request
        .keys()
        .find(|k| !["task", "responseView"].contains(&k.as_str()))
    {
        return Err(unknown_name(field, None));
    }
    let task = request.get("task").and_then(Value::as_object);
    if let Some(task) = task {
        if let Some(field) = task.keys().find(|k| !TASK_FIELDS.contains(&k.as_str())) {
            return Err(unknown_name(field, Some("task")));
        }
        if let Some(http) = task.get("httpRequest").and_then(Value::as_object) {
            if let Some(field) = http.keys().find(|k| !HTTP_FIELDS.contains(&k.as_str())) {
                return Err(unknown_name(field, Some("task.http_request")));
            }
        }
    }
    let view = match request.get("responseView").and_then(Value::as_str) {
        Some("FULL") => "FULL",
        _ => "BASIC",
    };
    // 2. The proto parse of the two times.
    let schedule_text = task
        .and_then(|t| t.get("scheduleTime"))
        .and_then(Value::as_str);
    let deadline_text = task
        .and_then(|t| t.get("dispatchDeadline"))
        .and_then(Value::as_str);
    let schedule = schedule_text.map(parse_timestamp);
    let deadline = deadline_text.map(parse_duration);
    let mut format_errors: Vec<(&str, &str)> = Vec::new();
    if schedule == Some(None) {
        format_errors.push(("task.schedule_time", "Invalid value at 'task.schedule_time' (type.googleapis.com/google.protobuf.Timestamp), Field 'scheduleTime', Illegal timestamp format; timestamps must end with 'Z' or have a valid timezone offset."));
    }
    if deadline == Some(None) {
        format_errors.push(("task.dispatch_deadline", "Invalid value at 'task.dispatch_deadline' (type.googleapis.com/google.protobuf.Duration), Field 'dispatchDeadline', Illegal duration format; duration must end with 's'"));
    }
    if !format_errors.is_empty() {
        let message: Vec<&str> = format_errors.iter().map(|(_, text)| *text).collect();
        return Err(Refusal::bad_request(message.join("\n"), &format_errors));
    }
    // 3. A task needs a payload.
    let has_payload = task
        .is_some_and(|t| t.contains_key("httpRequest") || t.contains_key("appEngineHttpRequest"));
    if !has_payload {
        return Err(Refusal::invalid("Task.payload_type is not set."));
    }
    let task = task.unwrap_or(&empty);
    // 4. The task name.
    let name = match task.get("name").and_then(Value::as_str) {
        Some(given) if !given.is_empty() => {
            let parts: Vec<&str> = given.split('/').collect();
            let shaped = parts.len() == 8
                && parts[0] == "projects"
                && parts[2] == "locations"
                && parts[4] == "queues"
                && parts[6] == "tasks"
                && !parts[1].is_empty()
                && !parts[3].is_empty()
                && !parts[5].is_empty()
                && !parts[7].is_empty();
            if !shaped {
                return Err(Refusal::help(NAME_FORMAT, "task name"));
            }
            if !valid_task_id(parts[7]) {
                return Err(Refusal::help(
                    format!(
                        "Task ID \"{}\" can contain only letters ([A-Za-z]), numbers ([0-9]), hyphens (-), or underscores (_). Task ID must between 1 and 500 characters.",
                        parts[7]
                    ),
                    "task ID",
                ));
            }
            let named_queue = parts[..6].join("/");
            if named_queue != queue {
                return Err(Refusal::invalid(format!(
                    "The queue name from request ('{queue}') must be the same as the queue name in the named task ('{named_queue}')."
                )));
            }
            given.to_owned()
        }
        _ => format!("{queue}/tasks/{}", generated_task_id(now_nanos, counter)),
    };
    // 5. The dispatch deadline's range; 0 is the default.
    let deadline_nanos = match deadline.flatten() {
        None | Some(0) => i128::from(default_deadline_seconds) * 1_000_000_000,
        Some(n) if (DEADLINE_MIN_NANOS..=DEADLINE_MAX_NANOS).contains(&n) => n,
        Some(_) => {
            return Err(Refusal::invalid(
                "Task.dispatchDeadline must be between [15s, 30m].",
            ))
        }
    };
    // 6. How far ahead the task may be scheduled.
    let schedule_nanos = match schedule.flatten() {
        Some(at) if at - now_nanos > i128::from(MAX_SCHEDULE_AHEAD_SECONDS) * 1_000_000_000 => {
            return Err(Refusal::invalid(format!(
                "The Task.scheduleTime, {}, is too far in the future. Schedule time must be no more than 720h in the future.",
                los_angeles_text(at)
            )));
        }
        // A time in the past, or none, is the time of the request, in microseconds.
        Some(at) if at > now_nanos => at - at.rem_euclid(1000),
        _ => now_nanos - now_nanos.rem_euclid(1000),
    };
    // 7. The task's size.
    if size() > MAX_TASK_BYTES {
        return Err(Refusal::invalid("Task size too large"));
    }
    let create_seconds = now_nanos.div_euclid(1_000_000_000) * 1_000_000_000;
    Ok(Admitted {
        name,
        schedule_time: format_proto_timestamp(schedule_nanos),
        schedule_nanos,
        deadline_seconds: u64::try_from((deadline_nanos + 999_999_999) / 1_000_000_000)
            .unwrap_or(DEFAULT_DEADLINE_SECONDS),
        deadline_text: format_duration(deadline_nanos),
        create_time: format_proto_timestamp(create_seconds),
        view,
    })
}

/// The answer to a createTask: the Task resource (not wrapped), without its body unless the view is FULL.
#[must_use]
pub fn answer(
    admitted: &Admitted,
    url: &str,
    http_request: &Map<String, Value>,
    body_base64: Option<&str>,
) -> Value {
    let mut headers = Map::new();
    if let Some(given) = http_request.get("headers").and_then(Value::as_object) {
        for (name, value) in given {
            let lower = name.to_ascii_lowercase();
            // Cloud Tasks owns these: `User-Agent` is its own, the others are dropped from the task.
            if lower == "user-agent"
                || lower.starts_with("x-google-")
                || lower.starts_with("x-appengine-")
            {
                continue;
            }
            headers.insert(name.clone(), value.clone());
        }
    }
    headers.insert("User-Agent".to_owned(), json!("Google-Cloud-Tasks"));
    let mut http = Map::new();
    http.insert("url".to_owned(), json!(url));
    http.insert("httpMethod".to_owned(), json!("POST"));
    http.insert("headers".to_owned(), Value::Object(headers));
    if admitted.view == "FULL" {
        if let Some(body) = body_base64 {
            http.insert("body".to_owned(), json!(body));
        }
    }
    for key in ["oauthToken", "oidcToken"] {
        if let Some(value) = http_request.get(key) {
            http.insert(key.to_owned(), value.clone());
        }
    }
    json!({
        "name": admitted.name,
        "httpRequest": Value::Object(http),
        "scheduleTime": admitted.schedule_time,
        "createTime": admitted.create_time,
        "dispatchDeadline": admitted.deadline_text,
        "view": admitted.view,
    })
}

/// Returns the stored HTTP task in the requested Cloud Tasks response view.
#[must_use]
pub(crate) fn get_answer(
    observation: &crate::task_scheduler::TaskObservation,
    full: bool,
) -> Value {
    let task = &observation.task;
    let mut headers = Map::new();
    for (name, value) in &task.headers {
        let lower = name.to_ascii_lowercase();
        if lower == "user-agent"
            || lower.starts_with("x-google-")
            || lower.starts_with("x-appengine-")
        {
            continue;
        }
        headers.insert(name.clone(), json!(value));
    }
    headers.insert("User-Agent".to_owned(), json!("Google-Cloud-Tasks"));
    let mut http = Map::new();
    http.insert("url".to_owned(), json!(task.url));
    http.insert("httpMethod".to_owned(), json!("POST"));
    http.insert("headers".to_owned(), Value::Object(headers));
    if full {
        http.insert(
            "body".to_owned(),
            json!(crate::tasks::encode_base64(task.delivery_body())),
        );
    }
    if let Some(oidc) = &task.oidc {
        http.insert(
            "oidcToken".to_owned(),
            json!({
                "serviceAccountEmail": oidc.service_account_email,
                "audience": oidc.audience,
            }),
        );
    }
    if let Some(oauth_token) = &task.oauth_token {
        http.insert("oauthToken".to_owned(), oauth_token.clone());
    }
    let mut result = Map::new();
    result.insert("name".to_owned(), json!(task.name));
    result.insert("httpRequest".to_owned(), Value::Object(http));
    if let Some(schedule_time) = &observation.schedule_time {
        result.insert("scheduleTime".to_owned(), json!(schedule_time));
    }
    if let Some(create_time) = &task.create_time {
        result.insert("createTime".to_owned(), json!(create_time));
    }
    result.insert("dispatchDeadline".to_owned(), json!(task.dispatch_deadline));
    result.insert(
        "dispatchCount".to_owned(),
        json!(observation.dispatch_count),
    );
    result.insert(
        "responseCount".to_owned(),
        json!(observation.response_count),
    );
    if let Some(attempt) = &observation.first_attempt {
        result.insert(
            "firstAttempt".to_owned(),
            json!({"dispatchTime": attempt.dispatch_time}),
        );
    }
    if let Some(attempt) = &observation.last_attempt {
        let mut last = Map::new();
        if let Some(schedule_time) = &attempt.schedule_time {
            last.insert("scheduleTime".to_owned(), json!(schedule_time));
        }
        last.insert("dispatchTime".to_owned(), json!(attempt.dispatch_time));
        if let Some(response_time) = &attempt.response_time {
            last.insert("responseTime".to_owned(), json!(response_time));
        }
        if let Some(status) = attempt.response_status {
            last.insert(
                "responseStatus".to_owned(),
                json!({
                    "code": rpc_code_for_http(status),
                    "message": format!("HTTP response status {status}"),
                }),
            );
        }
        result.insert("lastAttempt".to_owned(), Value::Object(last));
    }
    result.insert(
        "view".to_owned(),
        json!(if full { "FULL" } else { "BASIC" }),
    );
    Value::Object(result)
}

fn rpc_code_for_http(status: u16) -> u8 {
    match status {
        200..=299 => 0, // OK
        400 => 3,       // INVALID_ARGUMENT
        401 => 16,      // UNAUTHENTICATED
        403 => 7,       // PERMISSION_DENIED
        404 => 5,       // NOT_FOUND
        409 => 6,       // ALREADY_EXISTS
        429 => 8,       // RESOURCE_EXHAUSTED
        500 => 13,      // INTERNAL
        501 => 12,      // UNIMPLEMENTED
        503 => 14,      // UNAVAILABLE
        504 => 4,       // DEADLINE_EXCEEDED
        _ => 2,         // UNKNOWN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUEUE: &str = "projects/p/locations/us-central1/queues/q";
    const NOW: i128 = 1_794_388_019_589_154_000;

    #[allow(clippy::needless_pass_by_value)] // Test helper: callers build the value inline.
    fn run(task: Value) -> Result<Admitted, Refusal> {
        admit(
            QUEUE,
            &json!({ "task": task }),
            NOW,
            1,
            DEFAULT_DEADLINE_SECONDS,
            || 100,
        )
    }
    fn base() -> Value {
        json!({"httpRequest": {"url": "u", "httpMethod": "POST", "body": "e30="}})
    }
    #[allow(clippy::needless_pass_by_value)] // Test helper: callers build the value inline.
    fn with(extra: Value) -> Value {
        let mut task = base();
        for (k, v) in extra.as_object().unwrap() {
            task[k] = v.clone();
        }
        task
    }
    fn message(task: Value) -> String {
        run(task).unwrap_err().message
    }

    #[test]
    fn timestamps_parse_to_the_nanosecond_and_refuse_every_other_form() {
        assert_eq!(parse_timestamp("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_timestamp("2026-11-11T09:06:59.589154Z"),
            Some(1_794_388_019_589_154_000)
        );
        assert_eq!(
            parse_timestamp("2026-11-11T18:06:59.589154+09:00"),
            Some(1_794_388_019_589_154_000)
        );
        assert_eq!(
            parse_timestamp("2026-11-11T01:06:59.589154-08:00"),
            Some(1_794_388_019_589_154_000)
        );
        assert_eq!(
            parse_timestamp("2026-12-31T23:59:60Z"),
            parse_timestamp("2027-01-01T00:00:00Z")
        );
        assert_eq!(
            parse_timestamp("2026-11-11T09:06:59.123456789Z"),
            Some(1_794_388_019_123_456_789)
        );
        for bad in [
            "tomorrow",
            "2026-11-12T00:00:00",
            "2026-11-12 00:00:00Z",
            "2026-11-12t00:00:00z",
            "2026-13-01T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2026-11-12T24:00:00Z",
            "2026-11-12T00:60:00Z",
            "2026-11-12T00:00:61Z",
            "2026-11-12T00:00:00.Z",
            "2026-11-12T00:00:00.1234567890Z",
            "2026-11-12T00:00:00+0900",
            "2026-11-12T00:00:00+24:00",
            "0000-01-01T00:00:00Z",
            "2026-11-12T00:00:00ZZ",
            "",
        ] {
            assert_eq!(parse_timestamp(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_timestamp_prints_with_zero_three_six_or_nine_digits() {
        assert_eq!(
            format_proto_timestamp(1_794_388_019_000_000_000),
            "2026-11-11T09:06:59Z"
        );
        assert_eq!(
            format_proto_timestamp(1_794_388_019_640_000_000),
            "2026-11-11T09:06:59.640Z"
        );
        assert_eq!(
            format_proto_timestamp(1_794_388_019_589_154_000),
            "2026-11-11T09:06:59.589154Z"
        );
        assert_eq!(
            format_proto_timestamp(1_794_388_019_589_154_001),
            "2026-11-11T09:06:59.589154001Z"
        );
    }

    #[test]
    fn los_angeles_time_follows_the_us_daylight_rule() {
        let at = |text: &str| los_angeles_text(parse_timestamp(text).unwrap());
        // The recorded messages.
        assert_eq!(
            at("2026-12-11T10:07:20.400Z"),
            "2026-12-11T02:07:20.4-08:00"
        );
        assert_eq!(at("2026-12-31T16:00:00-08:00"), "2026-12-31T16:00:00-08:00");
        assert_eq!(at("9999-12-31T23:59:59Z"), "9999-12-31T15:59:59-08:00");
        // The edges of daylight time in 2026: 8 March 02:00 and 1 November 02:00 local.
        assert_eq!(at("2026-03-08T09:59:59Z"), "2026-03-08T01:59:59-08:00");
        assert_eq!(at("2026-03-08T10:00:00Z"), "2026-03-08T03:00:00-07:00");
        assert_eq!(at("2026-11-01T08:59:59Z"), "2026-11-01T01:59:59-07:00");
        assert_eq!(at("2026-11-01T09:00:00Z"), "2026-11-01T01:00:00-08:00");
        assert_eq!(at("2026-07-04T19:00:00Z"), "2026-07-04T12:00:00-07:00");
    }

    #[test]
    fn durations_parse_and_print_as_a_proto_does() {
        assert_eq!(parse_duration("15s"), Some(15_000_000_000));
        assert_eq!(parse_duration("15.5s"), Some(15_500_000_000));
        assert_eq!(parse_duration("-1s"), Some(-1_000_000_000));
        assert_eq!(parse_duration("0s"), Some(0));
        for bad in [
            "30",
            "s",
            "1.s",
            ".5s",
            "1.2.3s",
            "1x",
            "1.0000000001s",
            "",
            "+5s",
            "1 s",
        ] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
        assert_eq!(format_duration(15_000_000_000), "15s");
        assert_eq!(format_duration(15_500_000_000), "15.500s");
        assert_eq!(format_duration(15_000_500_000), "15.000500s");
        assert_eq!(format_duration(600_000_000_001), "600.000000001s");
    }

    #[test]
    fn a_task_id_is_one_to_five_hundred_of_letters_digits_hyphens_and_underscores() {
        assert!(valid_task_id("a"));
        assert!(valid_task_id(&"x".repeat(500)));
        assert!(!valid_task_id(&"x".repeat(501)));
        assert!(!valid_task_id(""));
        for bad in ["a b", "a.b", "a/b", "é", "a+b"] {
            assert!(!valid_task_id(bad), "{bad}");
        }
        assert!(valid_task_id("A-z_0-9"));
    }

    #[test]
    fn the_recorded_refusals_have_the_recorded_text() {
        assert_eq!(
            run(json!({})).unwrap_err().message,
            "Task.payload_type is not set."
        );
        assert_eq!(
            admit(QUEUE, &json!({}), NOW, 1, DEFAULT_DEADLINE_SECONDS, || 0)
                .unwrap_err()
                .message,
            "Task.payload_type is not set."
        );
        assert_eq!(
            message(with(json!({"fireemuUnknownField": 1}))),
            "Invalid JSON payload received. Unknown name \"fireemuUnknownField\" at 'task': Cannot find field."
        );
        assert_eq!(message(with(json!({"scheduleTime": "tomorrow"}))), "Invalid value at 'task.schedule_time' (type.googleapis.com/google.protobuf.Timestamp), Field 'scheduleTime', Illegal timestamp format; timestamps must end with 'Z' or have a valid timezone offset.");
        assert_eq!(message(with(json!({"dispatchDeadline": "30"}))), "Invalid value at 'task.dispatch_deadline' (type.googleapis.com/google.protobuf.Duration), Field 'dispatchDeadline', Illegal duration format; duration must end with 's'");
        assert_eq!(
            message(with(json!({"dispatchDeadline": "14s"}))),
            "Task.dispatchDeadline must be between [15s, 30m]."
        );
        assert_eq!(
            message(with(json!({"dispatchDeadline": "1801s"}))),
            "Task.dispatchDeadline must be between [15s, 30m]."
        );
        assert_eq!(
            message(with(json!({"dispatchDeadline": "-1s"}))),
            "Task.dispatchDeadline must be between [15s, 30m]."
        );
        assert_eq!(
            message(with(json!({"name": format!("{QUEUE}/tasks/a b")}))),
            "Task ID \"a b\" can contain only letters ([A-Za-z]), numbers ([0-9]), hyphens (-), or underscores (_). Task ID must between 1 and 500 characters."
        );
        for bad in [
            format!("{QUEUE}/tasks/a/b"),
            format!("{QUEUE}/tasks/"),
            "q".to_owned(),
        ] {
            assert_eq!(message(with(json!({"name": bad}))), NAME_FORMAT);
        }
        assert_eq!(
            message(with(json!({"name": "projects/other/locations/us-central1/queues/q/tasks/a"}))),
            "The queue name from request ('projects/p/locations/us-central1/queues/q') must be the same as the queue name in the named task ('projects/other/locations/us-central1/queues/q')."
        );
    }

    #[test]
    fn two_format_errors_come_together_schedule_first() {
        assert_eq!(
            message(with(json!({"scheduleTime": "tomorrow", "dispatchDeadline": "30"}))),
            "Invalid value at 'task.schedule_time' (type.googleapis.com/google.protobuf.Timestamp), Field 'scheduleTime', Illegal timestamp format; timestamps must end with 'Z' or have a valid timezone offset.\nInvalid value at 'task.dispatch_deadline' (type.googleapis.com/google.protobuf.Duration), Field 'dispatchDeadline', Illegal duration format; duration must end with 's'"
        );
    }

    #[test]
    fn the_checks_run_in_the_recorded_order() {
        let bad_id = format!("{QUEUE}/tasks/a b");
        // A format error beats a bad id; a bad id beats a deadline range; the range beats a time too far ahead.
        assert!(
            message(with(json!({"name": bad_id, "scheduleTime": "x"}))).contains("schedule_time")
        );
        assert!(
            message(with(json!({"name": bad_id, "dispatchDeadline": "14s"})))
                .starts_with("Task ID")
        );
        assert!(message(with(
            json!({"dispatchDeadline": "14s", "scheduleTime": "2099-01-01T00:00:00Z"})
        ))
        .starts_with("Task.dispatchDeadline"));
        // The unknown name beats everything, and a missing payload comes after the format errors.
        assert!(message(with(json!({"zzz": 1, "scheduleTime": "x"})))
            .starts_with("Invalid JSON payload"));
        let no_payload = json!({"scheduleTime": "x"});
        assert!(message(no_payload).contains("schedule_time"));
    }

    #[test]
    fn a_time_too_far_ahead_names_the_instant_in_los_angeles() {
        let far = format_proto_timestamp(
            NOW + i128::from(MAX_SCHEDULE_AHEAD_SECONDS + 3600) * 1_000_000_000,
        );
        let text = message(with(json!({"scheduleTime": far})));
        assert!(
            text.starts_with("The Task.scheduleTime, 2026-12-11T"),
            "{text}"
        );
        assert!(text.ends_with("-08:00, is too far in the future. Schedule time must be no more than 720h in the future."), "{text}");
        let edge =
            format_proto_timestamp(NOW + i128::from(MAX_SCHEDULE_AHEAD_SECONDS) * 1_000_000_000);
        assert!(
            run(with(json!({"scheduleTime": edge}))).is_ok(),
            "exactly 720h is accepted"
        );
        let beyond = format_proto_timestamp(
            NOW + i128::from(MAX_SCHEDULE_AHEAD_SECONDS) * 1_000_000_000 + 1000,
        );
        assert!(run(with(json!({"scheduleTime": beyond}))).is_err());
    }

    #[test]
    fn the_size_is_checked_last_against_a_mebibyte() {
        let big = admit(
            QUEUE,
            &json!({"task": base()}),
            NOW,
            1,
            DEFAULT_DEADLINE_SECONDS,
            || MAX_TASK_BYTES + 1,
        );
        assert_eq!(big.unwrap_err().message, "Task size too large");
        assert!(admit(
            QUEUE,
            &json!({"task": base()}),
            NOW,
            1,
            DEFAULT_DEADLINE_SECONDS,
            || MAX_TASK_BYTES
        )
        .is_ok());
        let both = admit(
            QUEUE,
            &json!({"task": with(json!({"dispatchDeadline": "14s"}))}),
            NOW,
            1,
            DEFAULT_DEADLINE_SECONDS,
            || MAX_TASK_BYTES + 1,
        );
        assert!(both
            .unwrap_err()
            .message
            .starts_with("Task.dispatchDeadline"));
    }

    #[test]
    fn what_an_accepted_task_is() {
        let given = format!("{QUEUE}/tasks/mine");
        let a = run(with(json!({"name": given.clone()}))).unwrap();
        assert_eq!(a.name, given);
        assert_eq!(a.deadline_seconds, 600);
        assert_eq!(a.deadline_text, "600s");
        assert_eq!(a.schedule_time, "2026-11-11T09:06:59.589154Z");
        assert_eq!(a.create_time, "2026-11-11T09:06:59Z");
        assert_eq!(a.view, "BASIC");
        // A name that was not given is generated: 19 digits, under the queue.
        let generated = run(base()).unwrap();
        let id = generated
            .name
            .strip_prefix(&format!("{QUEUE}/tasks/"))
            .unwrap();
        assert_eq!(id.len(), 19);
        assert!(id.bytes().all(|b| b.is_ascii_digit()));
        // 0s is the default; a fraction stays a fraction.
        assert_eq!(
            run(with(json!({"dispatchDeadline": "0s"})))
                .unwrap()
                .deadline_text,
            "600s"
        );
        // The development default is shorter: a task that names none, or 0s, gets it, and a named one is kept.
        let dev = |deadline: Value| {
            admit(QUEUE, &json!({"task": with(deadline)}), NOW, 1, 60, || 1).unwrap()
        };
        assert_eq!(
            (
                dev(json!({})).deadline_text.as_str(),
                dev(json!({})).deadline_seconds
            ),
            ("60s", 60)
        );
        assert_eq!(dev(json!({"dispatchDeadline": "0s"})).deadline_text, "60s");
        assert_eq!(dev(json!({"dispatchDeadline": "30s"})).deadline_text, "30s");
        let fraction = run(with(json!({"dispatchDeadline": "15.5s"}))).unwrap();
        assert_eq!(
            (fraction.deadline_text.as_str(), fraction.deadline_seconds),
            ("15.500s", 16)
        );
        assert!(run(with(json!({"dispatchDeadline": "15s"}))).is_ok());
        assert!(run(with(json!({"dispatchDeadline": "1800s"}))).is_ok());
        // A schedule time in the past is the time of the request; the future is kept, to the microsecond.
        let past = run(with(json!({"scheduleTime": "2026-11-11T08:06:59Z"}))).unwrap();
        assert_eq!(past.schedule_time, "2026-11-11T09:06:59.589154Z");
        let nanos = run(with(
            json!({"scheduleTime": "2026-11-11T09:07:21.273123456Z"}),
        ))
        .unwrap();
        assert_eq!(nanos.schedule_time, "2026-11-11T09:07:21.273123Z");
        let offset = run(with(
            json!({"scheduleTime": "2026-11-11T18:07:22.640+09:00"}),
        ))
        .unwrap();
        assert_eq!(offset.schedule_time, "2026-11-11T09:07:22.640Z");
        assert_eq!(
            run(with(json!({"scheduleTime": "2026-12-31T23:59:60Z"})))
                .unwrap_err()
                .http,
            400
        );
        let leap = admit(
            QUEUE,
            &json!({"task": with(json!({"scheduleTime": "2026-11-11T09:07:00Z"}))}),
            NOW,
            1,
            DEFAULT_DEADLINE_SECONDS,
            || 1,
        )
        .unwrap();
        assert_eq!(leap.schedule_time, "2026-11-11T09:07:00Z");
    }

    #[test]
    fn the_answer_is_the_task_without_its_body_unless_the_view_is_full() {
        let task = with(json!({"name": format!("{QUEUE}/tasks/t")}));
        let mut http = task["httpRequest"].as_object().unwrap().clone();
        http.insert("headers".to_owned(), json!({"Content-Type": "application/json", "User-Agent": "mine", "X-Google-Probe": "g", "X-AppEngine-Probe": "a", "X-Kept": "k"}));
        http.insert(
            "oidcToken".to_owned(),
            json!({"serviceAccountEmail": "e", "audience": "a"}),
        );
        let basic = answer(
            &run(task.clone()).unwrap(),
            "http://local/f",
            &http,
            Some("e30="),
        );
        assert_eq!(basic["httpRequest"]["body"], Value::Null);
        assert_eq!(basic["httpRequest"]["url"], "http://local/f");
        assert_eq!(basic["httpRequest"]["httpMethod"], "POST");
        assert_eq!(
            basic["httpRequest"]["headers"],
            json!({"Content-Type": "application/json", "User-Agent": "Google-Cloud-Tasks", "X-Kept": "k"})
        );
        assert_eq!(basic["httpRequest"]["oidcToken"]["audience"], "a");
        assert_eq!(basic["view"], "BASIC");
        assert_eq!(basic["dispatchDeadline"], "600s");
        let full = admit(
            QUEUE,
            &json!({"task": task, "responseView": "FULL"}),
            NOW,
            1,
            DEFAULT_DEADLINE_SECONDS,
            || 1,
        )
        .unwrap();
        let full = answer(&full, "u", &http, Some("e30="));
        assert_eq!(full["httpRequest"]["body"], "e30=");
        assert_eq!(full["view"], "FULL");
    }

    #[test]
    fn errors_are_google_rpc_statuses() {
        let body = run(json!({})).unwrap_err().body();
        assert_eq!(body["error"]["code"], 400);
        assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
        assert_eq!(
            Refusal::queue_missing().body()["error"]["status"],
            "NOT_FOUND"
        );
        assert_eq!(
            Refusal::already_exists().body()["error"]["message"],
            "Requested entity already exists"
        );
        assert_eq!(Refusal::task_not_found().http, 404);
        assert!(Refusal::existed_too_recently()
            .message
            .contains("existed too recently"));
    }

    #[test]
    fn generated_ids_are_nineteen_digits_and_do_not_repeat() {
        let mut seen = std::collections::BTreeSet::new();
        for counter in 0..2000_u64 {
            let id = generated_task_id(NOW + i128::from(counter) * 7, counter);
            assert_eq!(id.len(), 19, "{id}");
            assert!(id.bytes().all(|b| b.is_ascii_digit()));
            assert!(seen.insert(id));
        }
    }

    proptest::proptest! {
        #[test]
        fn a_printed_timestamp_parses_back_to_the_same_microsecond(micros in 0_i128..253_402_300_799_000_000) {
            let nanos = micros * 1000;
            proptest::prop_assert_eq!(parse_timestamp(&format_proto_timestamp(nanos)), Some(nanos));
        }

        #[test]
        fn a_printed_duration_parses_back(nanos in 0_i128..4_000_000_000_000) {
            proptest::prop_assert_eq!(parse_duration(&format_duration(nanos)), Some(nanos));
        }

        #[test]
        fn the_deadline_range_is_exactly_fifteen_seconds_to_thirty_minutes(millis in -5_000_i64..2_000_000) {
            let text = format_duration(i128::from(millis) * 1_000_000);
            let result = run(with(json!({"dispatchDeadline": text})));
            let seconds = f64::from(i32::try_from(millis).unwrap()) / 1000.0;
            let accepted = millis == 0 || (15.0..=1800.0).contains(&seconds);
            proptest::prop_assert_eq!(result.is_ok(), accepted, "{} ms", millis);
        }

        #[test]
        fn a_task_id_is_valid_exactly_when_every_byte_is_allowed(id in "[ -~]{0,20}") {
            let allowed = !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            proptest::prop_assert_eq!(valid_task_id(&id), allowed);
        }
    }

    // ---- near misses for the calendar, the timestamp parser and the generated id (cargo-mutants survivors) ----------------

    #[test]
    fn the_calendar_agrees_with_itself_for_every_day_and_knows_leap_years() {
        for (year, leap) in [
            (1900, false),
            (2000, true),
            (2023, false),
            (2024, true),
            (2100, false),
            (2400, true),
        ] {
            assert_eq!(days_in_month(year, 2), if leap { 29 } else { 28 }, "{year}");
        }
        for (month, days) in [
            (1, 31),
            (3, 31),
            (4, 30),
            (5, 31),
            (6, 30),
            (7, 31),
            (8, 31),
            (9, 30),
            (10, 31),
            (11, 30),
            (12, 31),
        ] {
            assert_eq!(days_in_month(2026, month), days, "{month}");
        }
        for (y, m, d) in [
            (2000, 2, 29),
            (2400, 2, 29),
            (1600, 2, 29),
            (1900, 3, 1),
            (2100, 3, 1),
            (1, 1, 1),
            (9999, 12, 31),
        ] {
            assert_eq!(civil_from_days(days_from_civil(y, m, d)), (y, m, d));
        }
        let first = days_from_civil(1, 1, 1);
        let last = days_from_civil(9999, 12, 31);
        let mut previous = civil_from_days(first);
        for days in first + 1..=last {
            let next = civil_from_days(days);
            assert_eq!(days_from_civil(next.0, next.1, next.2), days);
            assert!(next > previous);
            previous = next;
        }
    }

    #[test]
    fn each_separator_of_a_timestamp_is_checked_on_its_own_and_so_is_the_zone() {
        for bad in [
            "2026x11-11T00:00:00Z",
            "2026-11x11T00:00:00Z",
            "2026-11-11x00:00:00Z",
            "2026-11-11T00x00:00Z",
            "2026-11-11T00:00x00Z",
            "2026-11-11T00:00:00.5",
            "2026-11-11T00:00:00.123456789",
            "2026-11-11T00:00:00+01:000",
            "2026-11-11T00:00:00x01:00",
            "2026-11-11T00:00:00+01x00",
            "2026-11-11T00:00:00+24:00",
            "2026-11-11T00:00:00-24:00",
            "2026-11-11T00:00:00+00:60",
        ] {
            assert_eq!(parse_timestamp(bad), None, "{bad}");
        }
        for ok in [
            "2026-11-11T00:00:00+23:59",
            "2026-11-11T00:00:00-23:59",
            "2026-11-11T00:00:00+00:59",
            "2026-11-11T23:59:59Z",
        ] {
            assert!(parse_timestamp(ok).is_some(), "{ok}");
        }
        let z = parse_timestamp("2026-11-11T08:30:00Z").unwrap();
        assert_eq!(parse_timestamp("2026-11-11T10:00:00+01:30"), Some(z));
        assert_eq!(parse_timestamp("2026-11-11T07:00:00-01:30"), Some(z));
        assert_eq!(
            parse_timestamp("2026-11-11T08:30:00.5Z"),
            Some(z + 500_000_000)
        );
        assert_eq!(
            parse_timestamp("2026-11-11T08:30:00.000000001Z"),
            Some(z + 1)
        );
        assert_eq!(
            parse_timestamp("2026-11-11T08:30:00.12Z"),
            Some(z + 120_000_000)
        );
    }

    #[test]
    fn los_angeles_changes_offset_at_two_in_the_morning_on_the_second_sunday_of_march_and_the_first_of_november(
    ) {
        let at =
            |text: &str| i64::try_from(parse_timestamp(text).unwrap() / 1_000_000_000).unwrap();
        for (when, offset) in [
            ("2026-03-08T09:59:59Z", -8),
            ("2026-03-08T10:00:00Z", -7),
            ("2026-11-01T08:59:59Z", -7),
            ("2026-11-01T09:00:00Z", -8),
            ("2027-03-14T09:59:59Z", -8),
            ("2027-03-14T10:00:00Z", -7),
            ("2027-11-07T08:59:59Z", -7),
            ("2027-11-07T09:00:00Z", -8),
            ("2026-07-01T00:00:00Z", -7),
            ("2026-01-01T00:00:00Z", -8),
        ] {
            assert_eq!(los_angeles_offset(at(when)), offset * 3600, "{when}");
        }
        assert_eq!(
            los_angeles_text(parse_timestamp("2026-07-01T07:30:00.25Z").unwrap()),
            "2026-07-01T00:30:00.25-07:00"
        );
        assert_eq!(
            los_angeles_text(parse_timestamp("2026-01-01T07:30:00Z").unwrap()),
            "2025-12-31T23:30:00-08:00"
        );
    }

    #[test]
    fn a_generated_id_is_nineteen_digits_distinct_per_counter_and_stable() {
        assert_eq!(
            generated_task_id(1_794_388_019_589_154_000, 1),
            "2468936114089018478"
        );
        assert_eq!(
            generated_task_id(1_794_388_019_589_154_000, 2),
            "6833466583304792347"
        );
        assert_eq!(
            generated_task_id(1_794_388_019_589_154_000, 123_456_789),
            "5451868352343746280"
        );
        assert_eq!(generated_task_id(0, 0), "1000000000000000000");
        let mut seen = std::collections::BTreeSet::new();
        for counter in 0..2000 {
            let id = generated_task_id(NOW, counter);
            assert_eq!(id.len(), 19);
            assert!(valid_task_id(&id));
            assert!(seen.insert(id));
        }
    }

    #[test]
    fn an_empty_name_is_no_name_and_the_horizon_is_inclusive_and_a_future_time_is_cut_to_the_microsecond(
    ) {
        let admitted = run(with(json!({"name": ""}))).unwrap();
        let id = admitted
            .name
            .strip_prefix(&format!("{QUEUE}/tasks/"))
            .unwrap();
        assert_eq!(id.len(), 19);
        let horizon = NOW + i128::from(MAX_SCHEDULE_AHEAD_SECONDS) * 1_000_000_000;
        assert!(run(with(
            json!({"scheduleTime": format_proto_timestamp(horizon)})
        ))
        .is_ok());
        assert!(run(with(
            json!({"scheduleTime": format_proto_timestamp(horizon + 1_000)})
        ))
        .is_err());
        let at = NOW + 3_600_000_000_000 + 789;
        let admitted = run(with(json!({"scheduleTime": format_proto_timestamp(at)}))).unwrap();
        assert_eq!(admitted.schedule_nanos, NOW + 3_600_000_000_000);
    }

    #[test]
    fn a_request_with_no_schedule_is_stamped_with_its_own_microsecond() {
        let admitted = admit(
            QUEUE,
            &json!({ "task": base() }),
            NOW + 789,
            1,
            DEFAULT_DEADLINE_SECONDS,
            || 100,
        )
        .unwrap();
        assert_eq!(admitted.schedule_nanos, NOW);
        assert_eq!(admitted.schedule_time, "2026-11-11T09:06:59.589154Z");
    }

    // ---- a duration of any length is refused, never a panic or a wrap (review S1 of 2026-11-12) ------------------------------

    #[test]
    fn a_duration_beyond_the_proto_range_is_refused_and_the_edge_is_taken() {
        // The proto Duration holds up to 315,576,000,000 seconds either way.
        assert_eq!(
            parse_duration("315576000000s"),
            Some(315_576_000_000_i128 * 1_000_000_000)
        );
        assert_eq!(
            parse_duration("-315576000000s"),
            Some(-315_576_000_000_i128 * 1_000_000_000)
        );
        assert_eq!(
            parse_duration("315576000000.999999999s"),
            Some(315_576_000_000_999_999_999)
        );
        for bad in [
            "315576000001s",
            "-315576000001s",
            "1000000000000000000000000000000s",
            "99999999999999999999999999999999999999s",
            "-99999999999999999999999999999999999999s",
            "999999999999999999999999999999999999999999999999s",
        ] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
        for text in [
            "1000000000000000000000000000000s",
            "99999999999999999999999999999999999999s",
            "-1000000000000000000000000000000s",
        ] {
            let error = run(with(json!({"dispatchDeadline": text}))).unwrap_err();
            assert_eq!(error.http, 400, "{text}");
            assert_eq!(error.status, "INVALID_ARGUMENT", "{text}");
        }
    }

    proptest::proptest! {
        /// Any digits, with or without a sign and a fraction, parse to a value inside the proto range or to nothing;
        /// admission answers a 400 for it and never panics.
        #[test]
        fn a_duration_of_any_digits_never_panics_and_stays_inside_the_proto_range(
            negative in proptest::bool::ANY,
            whole in "[0-9]{1,60}",
            fraction in proptest::option::of("[0-9]{1,12}"),
        ) {
            let text = format!(
                "{}{whole}{}s",
                if negative { "-" } else { "" },
                fraction.as_deref().map_or(String::new(), |f| format!(".{f}")),
            );
            if let Some(nanos) = parse_duration(&text) {
                proptest::prop_assert!(nanos.abs() <= 315_576_000_000_999_999_999_i128, "{}", text);
            }
            let result = run(with(json!({"dispatchDeadline": text})));
            if let Ok(admitted) = &result {
                proptest::prop_assert!((15..=1800).contains(&admitted.deadline_seconds) || admitted.deadline_seconds == DEFAULT_DEADLINE_SECONDS);
            }
        }
    }

    #[test]
    fn an_answer_is_printed_as_production_printed_it() {
        let admitted = run(with(json!({"name": format!("{QUEUE}/tasks/layout")}))).unwrap();
        let http = json!({"headers": {"Content-Type": "application/json"}, "oidcToken": {"audience": "https://u", "serviceAccountEmail": "a@b"}});
        let text = pretty(&answer(
            &admitted,
            "https://u/",
            http.as_object().unwrap(),
            None,
        ));
        assert_eq!(
            text,
            format!(
                "{{\n  \"name\": \"{QUEUE}/tasks/layout\",\n  \"httpRequest\": {{\n    \"url\": \"https://u/\",\n    \"httpMethod\": \"POST\",\n    \"headers\": {{\n      \"Content-Type\": \"application/json\",\n      \"User-Agent\": \"Google-Cloud-Tasks\"\n    }},\n    \"oidcToken\": {{\n      \"serviceAccountEmail\": \"a@b\",\n      \"audience\": \"https://u\"\n    }}\n  }},\n  \"scheduleTime\": \"{}\",\n  \"createTime\": \"{}\",\n  \"dispatchDeadline\": \"600s\",\n  \"view\": \"BASIC\"\n}}\n",
                admitted.schedule_time, admitted.create_time
            )
        );
        let error = Refusal::invalid("Task.payload_type is not set.");
        assert_eq!(
            pretty(&error.body()),
            "{\n  \"error\": {\n    \"code\": 400,\n    \"message\": \"Task.payload_type is not set.\",\n    \"status\": \"INVALID_ARGUMENT\"\n  }\n}\n"
        );
        assert_eq!(pretty(&json!({})), "{}\n");
        assert_eq!(
            pretty(&json!({"a": [], "b": {}})),
            "{\n  \"a\": [],\n  \"b\": {}\n}\n"
        );
        assert_eq!(
            pretty(&json!({"a": [1, [2]]})),
            "{\n  \"a\": [\n    1,\n    [\n      2\n    ]\n  ]\n}\n"
        );
    }

    proptest::proptest! {
        /// Whatever the value, the printed text parses back to it and ends with one newline.
        #[test]
        fn a_printed_answer_parses_back_to_the_same_value(
            keys in proptest::collection::vec("[a-zA-Z]{1,8}", 0..6),
            text in "[ -~]{0,20}",
            number in proptest::num::i64::ANY,
        ) {
            let mut map = Map::new();
            for (index, key) in keys.iter().enumerate() {
                map.insert(key.clone(), json!({"s": text, "n": number, "a": [index, null, true], "e": {}, "l": []}));
            }
            map.insert("headers".to_owned(), json!({"name": "x", "Zeta": 1}));
            let value = Value::Object(map);
            let printed = pretty(&value);
            proptest::prop_assert!(printed.ends_with('\n') && !printed.ends_with("\n\n"), "{}", printed);
            proptest::prop_assert_eq!(serde_json::from_str::<Value>(&printed).unwrap(), value);
        }
    }

    #[test]
    fn the_production_gaps_of_the_recorded_queue_are_the_declared_ones_and_then_the_floor() {
        use fireemu_core_functions::manifest::TaskRetryConfig;
        // tqwindow of the recordings: minBackoff 1 s, maxBackoff 2 s, maxDoublings 1; the strict schedule's step of gap n is n.
        let retry = TaskRetryConfig {
            max_attempts: 100,
            max_retry_millis: Some(6_000),
            max_backoff_millis: 2_000,
            max_doublings: 1,
            min_backoff_millis: 1_000,
        };
        let gaps: Vec<u64> = (1..=20)
            .map(|n| retry_gap_millis(retry.backoff_millis(n), n, true))
            .collect();
        let expected_seconds = [
            1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4, 4, 4, 8, 8, 10, 10, 10, 10,
        ];
        assert_eq!(gaps, expected_seconds.map(|s| s * 1000));
        // Declared backoff keeps the declared gaps, and a declared gap above the floor is kept.
        let declared: Vec<u64> = (1..=20)
            .map(|n| retry_gap_millis(retry.backoff_millis(n), n, false))
            .collect();
        assert_eq!(declared[11], 2_000);
        assert_eq!(declared[19], 2_000);
        assert_eq!(retry_gap_millis(30_000, 17, true), 30_000);
        assert_eq!(retry_gap_millis(0, 12, true), 4_000);
        assert_eq!(retry_gap_millis(3_999, 12, true), 4_000);
        assert_eq!(retry_gap_millis(4_001, 12, true), 4_001);
    }

    proptest::proptest! {
        /// The production gap is never shorter than the declared one or than the floor, never longer than the larger of the two,
        /// and the floor never shrinks as the gap number grows.
        #[test]
        fn the_production_gap_is_the_larger_of_the_declared_gap_and_a_floor_that_only_grows(
            declared in 0_u64..100_000_000,
            n in 0_u32..1_000,
        ) {
            let gap = retry_gap_millis(declared, n, true);
            proptest::prop_assert!(gap >= declared);
            proptest::prop_assert!(gap >= production_gap_floor_millis(n));
            proptest::prop_assert!(gap == declared || gap == production_gap_floor_millis(n));
            proptest::prop_assert!(production_gap_floor_millis(n) <= production_gap_floor_millis(n + 1));
            proptest::prop_assert_eq!(retry_gap_millis(declared, n, false), declared);
        }
    }

    #[test]
    fn the_html_characters_of_a_message_are_escaped_as_production_escaped_them() {
        let refusal = Refusal::invalid(NAME_FORMAT);
        let text = pretty(&refusal.body());
        assert!(text.contains(r#"\"projects/\u003cPROJECT_ID\u003e/locations/\u003cLOCATION_ID\u003e/queues/\u003cQUEUE_ID\u003e/tasks/\u003cTASK_ID\u003e\""#), "{text}");
        assert!(!text.contains('<') && !text.contains('>'));
        assert!(pretty(&json!({"a": "x & y"})).contains("x \\u0026 y"));
        // It still parses back to the message.
        assert_eq!(
            serde_json::from_str::<Value>(&text).unwrap()["error"]["message"],
            NAME_FORMAT
        );
    }

    #[test]
    fn an_argument_error_carries_the_details_production_attached() {
        let detail = |task: Value| run(task).unwrap_err().body()["error"]["details"].clone();
        let url = "https://cloud.google.com/tasks/docs/reference/rest/v2/projects.locations.queues.tasks#Task.FIELDS.name";
        // A task ID and a task name: a Help link to the definition.
        assert_eq!(
            detail(with(json!({"name": format!("{QUEUE}/tasks/a b")}))),
            json!([{"@type": "type.googleapis.com/google.rpc.Help", "links": [{"description": "Definition of task ID", "url": url}]}])
        );
        assert_eq!(
            detail(with(json!({"name": "projects/p/tasks/x"}))),
            json!([{"@type": "type.googleapis.com/google.rpc.Help", "links": [{"description": "Definition of task name", "url": url}]}])
        );
        // A malformed time: a BadRequest naming the proto field, one violation for each time.
        let schedule = "Invalid value at 'task.schedule_time' (type.googleapis.com/google.protobuf.Timestamp), Field 'scheduleTime', Illegal timestamp format; timestamps must end with 'Z' or have a valid timezone offset.";
        let deadline = "Invalid value at 'task.dispatch_deadline' (type.googleapis.com/google.protobuf.Duration), Field 'dispatchDeadline', Illegal duration format; duration must end with 's'";
        assert_eq!(
            detail(with(json!({"scheduleTime": "tomorrow"}))),
            json!([{"@type": "type.googleapis.com/google.rpc.BadRequest", "fieldViolations": [{"field": "task.schedule_time", "description": schedule}]}])
        );
        assert_eq!(
            detail(with(json!({"dispatchDeadline": "30"}))),
            json!([{"@type": "type.googleapis.com/google.rpc.BadRequest", "fieldViolations": [{"field": "task.dispatch_deadline", "description": deadline}]}])
        );
        assert_eq!(
            detail(with(
                json!({"scheduleTime": "tomorrow", "dispatchDeadline": "30"})
            )),
            json!([{"@type": "type.googleapis.com/google.rpc.BadRequest", "fieldViolations": [
                {"field": "task.schedule_time", "description": schedule},
                {"field": "task.dispatch_deadline", "description": deadline}]}])
        );
        // An unknown name: the field is where the name was found.
        let unknown =
            "Invalid JSON payload received. Unknown name \"x\" at 'task': Cannot find field.";
        assert_eq!(
            detail(with(json!({"x": 1}))),
            json!([{"@type": "type.googleapis.com/google.rpc.BadRequest", "fieldViolations": [{"field": "task", "description": unknown}]}])
        );
        // Other refusals carry none, and the printed form puts the details last, in production's order.
        assert_eq!(
            detail(with(json!({"dispatchDeadline": "14s"}))),
            Value::Null
        );
        assert!(run(json!({})).unwrap_err().body()["error"]
            .get("details")
            .is_none());
        let printed = pretty(
            &run(with(json!({"name": format!("{QUEUE}/tasks/a b")})))
                .unwrap_err()
                .body(),
        );
        assert!(printed.contains("    \"status\": \"INVALID_ARGUMENT\",\n    \"details\": [\n      {\n        \"@type\": \"type.googleapis.com/google.rpc.Help\",\n        \"links\": [\n          {\n            \"description\": \"Definition of task ID\",\n            \"url\": "), "{printed}");
    }
}
