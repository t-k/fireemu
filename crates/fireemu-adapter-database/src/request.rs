//! Parsing a REST request: the `.json` path, the query parameters and the query.

use std::collections::BTreeMap;

use fireemu_core_database::{ErrorKind, Json, Limit, Limits, OrderBy, Path, QueryParams};

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

/// The location part of a target: the raw `/a/b.json` path made into a database path.
pub enum Location {
    /// A database path.
    Data(Path),
    /// Under `/.settings` (served with the rules, RTDB-03).
    Settings,
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

/// Decodes `%XX` escapes; a malformed escape stays as it is. `+` is not a space.
pub fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(value) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(value);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The database location a raw path names. `writing` adds the depth limit.
pub fn location(raw_path: &str, writing: bool, limits: &Limits) -> Result<Location, Refusal> {
    let Some(stem) = raw_path.strip_suffix(".json") else {
        return Err(Refusal {
            status: 400,
            message: "Append .json to your URL to use the REST API.".to_owned(),
            plain: true,
        });
    };
    let decoded = percent_decode(stem);
    if decoded.split('/').find(|s| !s.is_empty()) == Some(".settings") {
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

/// Reads the output options and checks `format` and `writeSizeLimit`.
pub fn output(params: &BTreeMap<String, String>) -> Result<Output, Refusal> {
    let export = match params.get("format").map(String::as_str) {
        None => false,
        Some("export") => true,
        Some(_) => return Err(Refusal::bad("Export format must be export if present")),
    };
    if let Some(limit) = params.get("writeSizeLimit") {
        if !matches!(
            limit.as_str(),
            "tiny" | "small" | "medium" | "large" | "unlimited"
        ) {
            return Err(Refusal::bad(
                "writeSizeLimit should be one of {medium, tiny, large, unlimited, small}",
            ));
        }
    }
    let print = params.get("print").map(String::as_str);
    Ok(Output {
        style: if print == Some("pretty") {
            Style::Pretty
        } else {
            Style::Compact
        },
        silent: print == Some("silent"),
        export,
        shallow: params.get("shallow").map(String::as_str) == Some("true"),
        callback: params.get("callback").cloned(),
        download: params.get("download").cloned(),
    })
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

/// Reads the query of a `GET`, in the order the official emulator checks it.
pub fn query(
    params: &BTreeMap<String, String>,
    shallow: bool,
) -> Result<Option<QueryParams>, Refusal> {
    if !has_query(params) {
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
    let first = limit(params, "limitToFirst")?;
    let last = limit(params, "limitToLast")?;
    let mut query = QueryParams::ordered_by(order_by);
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
    if shallow {
        return Err(Refusal::bad(
            "orderBy not supported for with shallow GET, keys are returned in lexicographical order",
        ));
    }
    Ok(Some(query))
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
            let path = Path::parse(&name, &Limits::default()).map_err(|_| invalid())?;
            if path.is_root() || path.is_info() || path.is_priority() {
                return Err(invalid());
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

/// `value,"key"`: the first comma after which both halves parse.
fn split_bound(text: &str) -> Option<(Json, Option<String>)> {
    text.match_indices(',').find_map(|(at, _)| {
        let value = parse(&text[..at]).ok()?;
        match parse(&text[at + 1..]).ok()? {
            Json::String(key) => Some((value, Some(key))),
            _ => None,
        }
    })
}

/// The `.indexOn` entry a query needs, if it needs one: a child path or `.value`.
pub fn required_index(order_by: &OrderBy) -> Option<String> {
    match order_by {
        OrderBy::Child(path) => Some(path.keys().join("/")),
        OrderBy::Value => Some(".value".to_owned()),
        OrderBy::Key | OrderBy::Priority => None,
    }
}
