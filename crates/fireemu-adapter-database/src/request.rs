//! Parsing a REST request: the `.json` path, the query parameters and the query.

use std::collections::BTreeMap;

use fireemu_core_database::{ErrorKind, Json, Limit, Limits, OrderBy, Path, QueryParams};
use fireemu_core_types::codec::{self, PlusMode};

use crate::json_text::{parse, Style};

/// A refusal before anything is read or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The status code.
    pub status: u16,
    /// The `error` text (or the plain-text body for [`Refusal::plain`]).
    pub message: String,
    /// Whether the body is the plain message rather than a JSON error object.
    pub plain: bool,
}

impl Refusal {
    /// A JSON error answer.
    pub fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            plain: false,
        }
    }

    /// A 400 JSON error answer.
    pub fn bad(message: impl Into<String>) -> Self {
        Self::new(400, message)
    }
}

/// Whether `raw_path` reaches the rules route as [`location`] routes it: its first
/// non-empty segment, percent-decoded, is `.settings`, however many slashes come first and
/// whatever follows (review r11 M34). Decided before the credential is read.
pub fn names_settings(raw_path: &str) -> bool {
    let stem = raw_path.strip_suffix(".json").unwrap_or(raw_path);
    percent_decode(stem).split('/').find(|s| !s.is_empty()) == Some(".settings")
}

/// The location part of a target: the raw `/a/b.json` path made into a database path.
pub enum Location {
    /// A database path.
    Data(Path),
    /// Under `/.settings` (served with the rules, RTDB-03).
    Settings,
    /// Under `/.inspect`: what follows, as written (`databases.json` lists the namespaces).
    Inspect(String),
}

/// Splits `target` into its path and decoded query parameters (the last of a repeated
/// name wins).
pub fn split_target(target: &str) -> (&str, BTreeMap<String, String>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let params = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(name), percent_decode(value))
        })
        .collect();
    (path, params)
}

/// The refusal of an ambiguous request (review r11 M35, M36, ruling 18): a query parameter
/// given more than once, or more than one credential (`auth`, `access_token`, an
/// `Authorization` header). The official emulator takes the first value and prefers `auth`;
/// a request that could mean two things is refused here instead (a listed difference).
pub fn check_ambiguity(target: &str, authorization_count: usize) -> Result<(), Refusal> {
    let query = target.split_once('?').map_or("", |(_, query)| query);
    let mut seen = std::collections::BTreeSet::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let name = percent_decode(pair.split_once('=').map_or(pair, |(name, _)| name));
        if !seen.insert(name.clone()) {
            return Err(Refusal::bad(format!(
                "Ambiguous request: the query parameter '{name}' is given more than once."
            )));
        }
    }
    let credentials = usize::from(seen.contains("auth"))
        + usize::from(seen.contains("access_token"))
        + authorization_count;
    if credentials > 1 {
        return Err(Refusal::bad(
            "Ambiguous request: more than one credential (auth, access_token or an Authorization header).",
        ));
    }
    Ok(())
}

/// Decodes `%XX` escapes; a malformed escape stays as it is. `+` is not a space.
///
/// A target with a malformed escape is refused first ([`check_escapes`]), so the literal
/// fallback only matters to callers that decode text of their own.
pub fn percent_decode(text: &str) -> String {
    codec::percent_decode(text, PlusMode::Literal)
}

/// Refuses a target holding a `%` that does not introduce two hexadecimal digits, anywhere
/// in its path or query. The official emulator answers such a request 400 `Bad Request`
/// before it looks at the namespace, the method or the path.
pub fn check_escapes(target: &str) -> Result<(), Refusal> {
    if codec::percent_escapes_are_well_formed(target) {
        Ok(())
    } else {
        Err(Refusal::bad("Bad Request"))
    }
}

/// The database location a raw path names. `writing` adds the depth limit.
pub fn location(raw_path: &str, writing: bool, limits: &Limits) -> Result<Location, Refusal> {
    // `/.inspect` is answered whatever follows it, `.json` or not.
    if let Some(rest) = raw_path.trim_start_matches('/').strip_prefix(".inspect") {
        if rest.is_empty() || rest.starts_with('/') {
            return Ok(Location::Inspect(rest.trim_start_matches('/').to_owned()));
        }
    }
    let Some(stem) = raw_path.strip_suffix(".json") else {
        return Err(Refusal {
            status: 400,
            message: "Append .json to your URL to use the REST API.".to_owned(),
            plain: true,
        });
    };
    let decoded = percent_decode(stem);
    if names_settings(raw_path) {
        return Ok(Location::Settings);
    }
    let path = Path::parse(&decoded, limits).map_err(|err| match err.kind {
        ErrorKind::PathTooLong => Refusal::bad(format!(
            "Invalid path: Path specified exceeds the maximum length that can be written ({} bytes).",
            limits.max_path_bytes
        )),
        _ => Refusal::bad("Invalid path: Invalid token in path"),
    })?;
    if path.is_info() {
        return Err(Refusal::bad("Invalid path: Invalid token in path"));
    }
    if writing && path.depth() > limits.max_depth {
        return Err(Refusal::bad(format!(
            "Invalid path: Path specified exceeds the maximum depth that can be written ({}).",
            limits.max_depth
        )));
    }
    Ok(Location::Data(path))
}

/// The output options of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// `print=pretty` or the compact default.
    pub style: Style,
    /// `print=silent`.
    pub silent: bool,
    /// `format=export`.
    pub export: bool,
    /// `shallow=true`.
    pub shallow: bool,
    /// `callback=` (JSONP).
    pub callback: Option<String>,
    /// `download=` (attachment file name).
    pub download: Option<String>,
}

/// `disableTriggers` on a write (import sends it): `true` or `false`, and only from an
/// administrator (an OAuth access token, which the official emulator does not verify; an
/// `auth=` user is not one). Reads ignore it.
pub fn check_disable_triggers(
    params: &BTreeMap<String, String>,
    writing: bool,
    authorization: Option<&str>,
) -> Result<(), Refusal> {
    let Some(value) = params.get("disableTriggers").filter(|_| writing) else {
        return Ok(());
    };
    if value != "true" && value != "false" {
        return Err(Refusal::bad(
            "disableTriggers should be one of {true, false}",
        ));
    }
    let administrator = authorization.is_some_and(|v| v.starts_with("Bearer "))
        || params.contains_key("access_token");
    if !administrator {
        return Err(Refusal::bad(
            "Only users with firebasedatabase.instances.update permissions are allowed to specify disableTriggers",
        ));
    }
    Ok(())
}

/// The `writeSizeLimit` refusal: the official emulator lists the values in one order,
/// production (recorded in RTDB-REST-20261104-01) in another.
const WRITE_SIZE_LIMIT_EMULATOR: &str =
    "writeSizeLimit should be one of {medium, tiny, large, unlimited, small}";
const WRITE_SIZE_LIMIT_PRODUCTION: &str =
    "writeSizeLimit should be one of {tiny, large, small, medium, unlimited}";

/// Reads the output options. A write ignores `format`; a read checks `format` and
/// ignores `writeSizeLimit` ([`check_write_size_limit`]).
pub fn output(params: &BTreeMap<String, String>, writing: bool) -> Result<Output, Refusal> {
    let export = if writing {
        false
    } else {
        match params.get("format").map(String::as_str) {
            None => false,
            Some("export") => true,
            Some(_) => return Err(Refusal::bad("Export format must be export if present")),
        }
    };
    let print = params.get("print").map(String::as_str);
    Ok(Output {
        style: if print == Some("pretty") {
            Style::Pretty
        } else {
            Style::Compact
        },
        silent: print == Some("silent"),
        export,
        // The official emulator reads `true` in any case.
        shallow: params
            .get("shallow")
            .is_some_and(|value| value.eq_ignore_ascii_case("true")),
        callback: params.get("callback").cloned(),
        download: params.get("download").cloned(),
    })
}

/// Checks `writeSizeLimit` on a write, before anything else of the write's own (the official
/// emulator's order); a read ignores it. `production_shapes` picks production's text.
pub fn check_write_size_limit(
    params: &BTreeMap<String, String>,
    production_shapes: bool,
) -> Result<(), Refusal> {
    let Some(limit) = params.get("writeSizeLimit") else {
        return Ok(());
    };
    if matches!(
        limit.as_str(),
        "tiny" | "small" | "medium" | "large" | "unlimited"
    ) {
        return Ok(());
    }
    Err(Refusal::bad(if production_shapes {
        WRITE_SIZE_LIMIT_PRODUCTION
    } else {
        WRITE_SIZE_LIMIT_EMULATOR
    }))
}

const QUERY_PARAMS: [&str; 8] = [
    "orderBy",
    "startAt",
    "startAfter",
    "endAt",
    "endBefore",
    "equalTo",
    "limitToFirst",
    "limitToLast",
];

/// Whether any query parameter is present.
pub fn has_query(params: &BTreeMap<String, String>) -> bool {
    QUERY_PARAMS.iter().any(|name| params.contains_key(*name))
}

/// Reads the query of a `GET` that is not shallow, in the order the official emulator checks
/// it: the order, the pairs that exclude each other, the bounds, then (`check_timeout`, a
/// plain read) the `timeout`, then the limits.
pub fn query(
    params: &BTreeMap<String, String>,
    check_timeout: bool,
) -> Result<Option<QueryParams>, Refusal> {
    if !has_query(params) {
        if check_timeout {
            timeout(params)?;
        }
        return Ok(None);
    }
    let Some(order_text) = params.get("orderBy") else {
        return Err(Refusal::bad(
            "orderBy must be defined when other query parameters are defined",
        ));
    };
    let order_by = order_by(order_text)?;
    if params.contains_key("startAt") && params.contains_key("startAfter") {
        return Err(Refusal::bad(
            "Only one of startAfter and startAt may be specified",
        ));
    }
    if params.contains_key("endAt") && params.contains_key("endBefore") {
        return Err(Refusal::bad(
            "Only one of endAt and endBefore may be specified",
        ));
    }
    let ranged = ["startAt", "startAfter", "endAt", "endBefore"]
        .iter()
        .any(|name| params.contains_key(*name));
    if params.contains_key("equalTo") && ranged {
        return Err(Refusal::bad(
            "equalTo cannot be specified in addition to startAfter, startAt, endAt, or endBefore",
        ));
    }
    let mut query = QueryParams::ordered_by(order_by);
    let key_order = query.order_by == OrderBy::Key;
    let bound = |name: &str| -> Result<Option<(Json, Option<String>)>, Refusal> {
        params
            .get(name)
            .map(|text| bound_value(text, key_order))
            .transpose()
    };
    if let Some((value, key)) = bound("equalTo")? {
        query = query.equal_to(value, key.as_deref());
    }
    if let Some((value, key)) = bound("startAt")? {
        query = query.start_at(value, key.as_deref());
    }
    if let Some((value, key)) = bound("startAfter")? {
        query = query.start_after(value, key.as_deref());
    }
    if let Some((value, key)) = bound("endAt")? {
        query = query.end_at(value, key.as_deref());
    }
    if let Some((value, key)) = bound("endBefore")? {
        query = query.end_before(value, key.as_deref());
    }
    if check_timeout {
        timeout(params)?;
    }
    let first = limit(params, "limitToFirst")?;
    let last = limit(params, "limitToLast")?;
    query.limit = match (first, last) {
        (Some(_), Some(_)) => {
            return Err(Refusal::bad(
                "Only one of limitToFirst and limitToLast may be specified",
            ))
        }
        (Some(n), None) => Some(Limit::First(n)),
        (None, Some(n)) => Some(Limit::Last(n)),
        (None, None) => None,
    };
    Ok(Some(query))
}

/// A page of the keys of a shallow read: the keys after `start_after` (compared as text),
/// the first `limit` of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShallowPage {
    /// `startAfter`, as written (not JSON).
    pub start_after: Option<String>,
    /// `limitToFirst`.
    pub limit: Option<u32>,
}

/// Reads the query of a shallow `GET`, in the official emulator's order: `limitToFirst`, then
/// the parameters a shallow read refuses. `equalTo`, `endBefore` and `timeout` are ignored.
pub fn shallow_page(params: &BTreeMap<String, String>) -> Result<Option<ShallowPage>, Refusal> {
    let limit = limit(params, "limitToFirst")?;
    for (name, message) in [
        ("limitToLast", "limitToLast not supported for with shallow GET"),
        (
            "startAt",
            "startAt not supported for with shallow GET, use startAfter",
        ),
        (
            "endAt",
            "endAt not supported for with shallow GET, use limitToFirst",
        ),
        (
            "orderBy",
            "orderBy not supported for with shallow GET, keys are returned in lexicographical order",
        ),
    ] {
        if params.contains_key(name) {
            return Err(Refusal::bad(message));
        }
    }
    let start_after = params.get("startAfter").cloned();
    Ok((limit.is_some() || start_after.is_some()).then_some(ShallowPage { start_after, limit }))
}

const TIMEOUT_FORMAT: &str =
    "timeout must contain length and unit (s/seconds/min/minutes), such as 1s, 2seconds, or 3min";

/// The longest `timeout` a read accepts, in nanoseconds (15 minutes).
const TIMEOUT_MAX_NANOS: i64 = 900_000_000_000;

/// Checks `timeout` as the official emulator does: Scala's `Duration(text)` (whitespace
/// dropped, a number and a unit of its table) that is positive and at most 15 minutes. A
/// duration beyond what Scala holds (2^63 - 1 ns) is its 500.
pub fn timeout(params: &BTreeMap<String, String>) -> Result<(), Refusal> {
    let Some(text) = params.get("timeout") else {
        return Ok(());
    };
    match duration_nanos(text) {
        Err(DurationError::Format) => Err(Refusal::bad(TIMEOUT_FORMAT)),
        Err(DurationError::Range) => Err(Refusal::new(500, "Unexpected server error")),
        Ok(nanos) if nanos <= 0 => Err(Refusal::bad("timeout must be positive")),
        Ok(nanos) if nanos > TIMEOUT_MAX_NANOS => {
            Err(Refusal::bad("timeout must not be longer than 15 minutes"))
        }
        Ok(_) => Ok(()),
    }
}

/// Why a duration text did not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationError {
    /// Not a number and a unit (Scala's `NumberFormatException`).
    Format,
    /// Outside what a Scala duration holds (its `IllegalArgumentException`).
    Range,
}

/// The nanoseconds of a duration unit Scala's `Duration` knows.
fn unit_nanos(unit: &str) -> Option<i64> {
    Some(match unit {
        "d" | "day" | "days" => 86_400_000_000_000,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600_000_000_000,
        "m" | "min" | "mins" | "minute" | "minutes" => 60_000_000_000,
        "s" | "sec" | "secs" | "second" | "seconds" => 1_000_000_000,
        "ms" | "milli" | "millis" | "millisecond" | "milliseconds" => 1_000_000,
        "\u{b5}s" | "micro" | "micros" | "microsecond" | "microseconds" => 1_000,
        "ns" | "nano" | "nanos" | "nanosecond" | "nanoseconds" => 1,
        _ => return None,
    })
}

/// Java's `Character.isWhitespace`: the Unicode space, line and paragraph separators but the
/// no-break spaces, and the ASCII controls tab to carriage return and file to unit separator.
fn java_whitespace(c: char) -> bool {
    matches!(c, '\t'..='\r' | '\u{1c}'..='\u{1f}' | ' ' | '\u{1680}' | '\u{2028}' | '\u{2029}' | '\u{205f}' | '\u{3000}')
        || (('\u{2000}'..='\u{200a}').contains(&c) && c != '\u{2007}')
}

/// The largest magnitude a double reads exactly (2^53); Scala reads a longer length as a long.
const MAX_PRECISE_DOUBLE: f64 = 9_007_199_254_740_992.0;

/// The nanoseconds of `text` as Scala 2.12's `Duration.apply(String)` reads it, without its
/// `Inf` spellings (the official emulator refuses them as a format error).
pub fn duration_nanos(text: &str) -> Result<i64, DurationError> {
    let compact: String = text.chars().filter(|c| !java_whitespace(*c)).collect();
    let unit_start = compact
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_alphabetic())
        .last()
        .map_or(compact.len(), |(at, _)| at);
    let (length, unit) = compact.split_at(unit_start);
    let per = unit_nanos(unit).ok_or(DurationError::Format)?;
    let value = java_parse_double(length).ok_or(DurationError::Format)?;
    if (-MAX_PRECISE_DOUBLE..=MAX_PRECISE_DOUBLE).contains(&value) {
        // `fromNanos(unit.toNanos(1) * length)`: rounded half up, refused beyond a long.
        #[allow(clippy::cast_precision_loss)]
        let nanos = per as f64 * value;
        #[allow(clippy::cast_precision_loss)]
        let limit = i64::MAX as f64;
        if nanos > limit || nanos < -limit {
            return Err(DurationError::Range);
        }
        #[allow(clippy::cast_possible_truncation)]
        let rounded = (nanos + 0.5).floor() as i64;
        // Scala's durations stop at -(2^63 - 1) ns as well.
        if rounded == i64::MIN {
            return Err(DurationError::Range);
        }
        return Ok(rounded);
    }
    // A long length: `new FiniteDuration(length, unit)`, bounded by 2^63 - 1 ns.
    let whole = java_parse_long(length).ok_or(DurationError::Format)?;
    let bound = i64::MAX / per;
    if whole > bound || whole < -bound {
        return Err(DurationError::Range);
    }
    Ok(whole * per)
}

/// Java's `Long.parseLong`: an optional sign and ASCII digits.
fn java_parse_long(text: &str) -> Option<i64> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.strip_prefix('+').unwrap_or(text).parse().ok()
}

/// Java's `Double.parseDouble` for a text without trailing letters (the unit took them): the
/// text trimmed of characters up to U+0020, an optional sign, then a decimal number with an
/// optional exponent, or a hexadecimal one with its binary exponent.
fn java_parse_double(text: &str) -> Option<f64> {
    let trimmed = text.trim_matches(|c: char| c <= ' ');
    let (negative, body) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let magnitude = if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        hex_double(hex)?
    } else {
        decimal_double(body)?
    };
    Some(if negative { -magnitude } else { magnitude })
}

fn decimal_double(body: &str) -> Option<f64> {
    let (mantissa, exponent) = match body.find(['e', 'E']) {
        Some(at) => (&body[..at], Some(&body[at + 1..])),
        None => (body, None),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = |t: &str| t.bytes().all(|b| b.is_ascii_digit());
    if (whole.is_empty() && fraction.is_empty()) || !digits(whole) || !digits(fraction) {
        return None;
    }
    if let Some(exponent) = exponent {
        let exponent_digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        if exponent_digits.is_empty() || !digits(exponent_digits) {
            return None;
        }
    }
    body.parse().ok()
}

fn hex_double(hex: &str) -> Option<f64> {
    let (mantissa, exponent) = hex.split_once(['p', 'P'])?;
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let hex_digits = |t: &str| t.bytes().all(|b| b.is_ascii_hexdigit());
    if (whole.is_empty() && fraction.is_empty()) || !hex_digits(whole) || !hex_digits(fraction) {
        return None;
    }
    let exponent_digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
    if exponent_digits.is_empty() || !exponent_digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut value = 0.0f64;
    for digit in whole.chars().chain(fraction.chars()) {
        value = value * 16.0 + f64::from(digit.to_digit(16)?);
    }
    let shift: i64 = exponent.parse().unwrap_or(if exponent.starts_with('-') {
        i64::MIN
    } else {
        i64::MAX
    });
    let fraction_bits = i64::try_from(fraction.len()).ok()?.saturating_mul(4);
    let power = i32::try_from(shift.saturating_sub(fraction_bits).clamp(-2000, 2000)).ok()?;
    Some(value * 2f64.powi(power))
}

fn order_by(text: &str) -> Result<OrderBy, Refusal> {
    let invalid = || Refusal::bad("orderBy must be a valid JSON encoded path");
    let Ok(Json::String(name)) = parse(text) else {
        return Err(invalid());
    };
    match name.as_str() {
        "$key" => Ok(OrderBy::Key),
        "$value" => Ok(OrderBy::Value),
        "$priority" => Ok(OrderBy::Priority),
        _ => {
            // The official emulator reads `.priority` as the priority order and the root
            // (`""` or `/`) as a child path whose index is named "".
            let path = Path::parse(&name, &Limits::default()).map_err(|_| invalid())?;
            if path.is_info() {
                return Err(invalid());
            }
            if path.depth() == 1 && path.is_priority() {
                return Ok(OrderBy::Priority);
            }
            Ok(OrderBy::Child(path))
        }
    }
}

fn limit(params: &BTreeMap<String, String>, name: &str) -> Result<Option<u32>, Refusal> {
    let Some(text) = params.get(name) else {
        return Ok(None);
    };
    let value: i64 = text
        .parse()
        .map_err(|_| Refusal::bad(format!("{name} must be an integer")))?;
    if value <= 0 {
        return Err(Refusal::bad(format!("{name} must be positive")));
    }
    Ok(Some(u32::try_from(value).unwrap_or(u32::MAX)))
}

/// A bound parameter: a JSON primitive, optionally followed by `,` and a JSON string key.
/// An object or array value is read as `null`, as the official emulator reads `{}`.
fn bound_value(text: &str, key_order: bool) -> Result<(Json, Option<String>), Refusal> {
    let not_primitive = || Refusal::bad("Constraint index field must be a JSON primitive");
    let (value, key) = match parse(text) {
        Ok(value) => (value, None),
        Err(_) => split_bound(text).ok_or_else(not_primitive)?,
    };
    if key_order {
        if key.is_some() {
            return Err(Refusal::bad("Too many parameters for key index"));
        }
        if !matches!(value, Json::String(_)) {
            return Err(Refusal::bad(
                "Provided key index type is invalid, must be string",
            ));
        }
    }
    let value = match value {
        Json::Array(_) | Json::Object(_) => Json::Null,
        primitive => primitive,
    };
    Ok((value, key))
}

/// `value,"key"`: a JSON value, a comma and a JSON string key.
fn split_bound(text: &str) -> Option<(Json, Option<String>)> {
    // One pass: the value ends where its grammar ends, then a comma and a JSON string.
    let (value, end) = crate::json_parse::parse_prefix(text).ok()?;
    let rest = text[end..].trim_start().strip_prefix(',')?;
    match parse(rest).ok()? {
        Json::String(key) => Some((value, Some(key))),
        _ => None,
    }
}

/// The `.indexOn` entry a query needs, if it needs one: a child path or `.value`.
pub fn required_index(order_by: &OrderBy) -> Option<String> {
    match order_by {
        OrderBy::Child(path) => Some(path.keys().join("/")),
        OrderBy::Value => Some(".value".to_owned()),
        OrderBy::Key | OrderBy::Priority => None,
    }
}
