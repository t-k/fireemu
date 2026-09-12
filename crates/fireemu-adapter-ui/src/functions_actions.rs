//! Deterministic request/response shaping for the Functions console actions: invoking an
//! HTTP or callable function through the loopback Functions port, enqueuing a Cloud Task, and
//! computing a schedule's next run. The async loopback call and the runtime call live in
//! [`crate::api`]; this module holds only the pure shaping, so it can be unit-tested and
//! mutated in isolation with no runtime, no clock and no socket.
//!
//! An invocation is forwarded to the Functions port rather than dispatched inside the
//! runtime on purpose: the callable trust boundary (App Check enforcement, ID-token
//! verification and re-insertion, CORS) lives in that port's request handler, so a request
//! shaped here and sent over loopback reaches a function through exactly the path an SDK
//! client's request takes. What the console sends is what curl would send.

use fireemu_adapter_functions::zone;
use fireemu_core_functions::cron::Schedule;
use fireemu_core_types::hash::base64_standard;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Map, Value};

/// The largest response body the invoke front renders inline. A larger body is reported as
/// truncated with its true length rather than shipped whole into the browser: the console is a
/// probe, not a download surface.
pub const MAX_INVOKE_RESPONSE_BYTES: usize = 128 * 1024;

/// A forwarded invocation, ready for [`fireemu_adapter_functions::http::forward`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokePlan {
    /// HTTP method (validated to be framable and a plausible method token).
    pub method: String,
    /// The request target, `path[?query]`, already prefixed with the function's own route.
    pub path_and_query: String,
    /// Request headers, in the order given, with a default `content-type` for a JSON body.
    pub headers: Vec<(String, String)>,
    /// The request body bytes.
    pub body: Vec<u8>,
}

/// Whether every byte of `s` is safe to write into a request line or a header (no control
/// character, no space, no other byte a framing writer would misread).
fn is_target_safe(s: &str) -> bool {
    s.bytes()
        .all(|b| b > 0x20 && b != 0x7f && b != b'?' && b != b'#')
}

/// Whether `name` is a framable header name (token characters only, no separators).
fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b':' && b != b'(' && b != b')')
}

/// Whether `value` is a framable header value (no control character bar horizontal tab).
fn is_header_value(value: &str) -> bool {
    value.bytes().all(|b| b >= 0x20 && b != 0x7f || b == b'\t')
}

/// Reads the request body of an invoke request: `body` (a UTF-8 string) or `bodyBase64`
/// (raw bytes), never both, and never a non-string for either.
fn read_body(req: &Value) -> Result<Vec<u8>, String> {
    match (req.get("body"), req.get("bodyBase64")) {
        (Some(Value::Null) | None, Some(Value::Null) | None) => Ok(Vec::new()),
        (Some(b), Some(b64)) if !b.is_null() && !b64.is_null() => {
            Err("body and bodyBase64 are mutually exclusive".to_owned())
        }
        (Some(Value::String(text)), _) => Ok(text.clone().into_bytes()),
        (_, Some(Value::String(encoded))) => decode_base64(encoded)
            .ok_or_else(|| "bodyBase64 must be standard base64".to_owned()),
        _ => Err("body must be a string and bodyBase64 must be a base64 string".to_owned()),
    }
}

/// Builds the loopback request that invokes `function` (region `region`) of `project`.
///
/// The request shape is the console's own: `method` (default `POST`), an optional `path`
/// appended to the function's route, an optional `query`, an optional `headers` object, and
/// the body. A callable is invoked by `POST`ing `{"data": ...}`; an `onRequest` function is
/// invoked with whatever method, path and body the caller names.
///
/// # Errors
///
/// The method, path, query or a header that could not be framed safely, or a body given as
/// both text and base64, is refused before anything is sent.
pub fn build_invoke(
    project: &str,
    region: &str,
    function: &str,
    req: &Value,
) -> Result<InvokePlan, String> {
    let method = match req.get("method") {
        None | Some(Value::Null) => "POST".to_owned(),
        Some(Value::String(m)) => m.to_ascii_uppercase(),
        Some(_) => return Err("method must be a string".to_owned()),
    };
    if method.is_empty() || method.len() > 16 || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err("method must be an HTTP method token".to_owned());
    }

    let extra_path = match req.get("path") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(p)) => p.clone(),
        Some(_) => return Err("path must be a string".to_owned()),
    };
    if !extra_path.is_empty() && !extra_path.starts_with('/') {
        return Err("path must begin with '/'".to_owned());
    }
    let full_path = format!("/{project}/{region}/{function}{extra_path}");
    if !is_target_safe(&full_path) {
        return Err("path must not contain spaces or control characters".to_owned());
    }

    let query = match req.get("query") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(q)) => q.trim_start_matches('?').to_owned(),
        Some(_) => return Err("query must be a string".to_owned()),
    };
    if !query.is_empty() && !is_target_safe(&format!("x{query}")) {
        return Err("query must not contain spaces or control characters".to_owned());
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut has_content_type = false;
    if let Some(map) = req.get("headers") {
        let map = map
            .as_object()
            .ok_or_else(|| "headers must be an object of strings".to_owned())?;
        for (name, value) in map {
            let value = value
                .as_str()
                .ok_or_else(|| format!("header {name:?} must be a string"))?;
            if !is_header_name(name) || !is_header_value(value) {
                return Err(format!("header {name:?} is not a valid header"));
            }
            if name.eq_ignore_ascii_case("content-type") {
                has_content_type = true;
            }
            headers.push((name.clone(), value.to_owned()));
        }
    }

    let body = read_body(req)?;
    // A JSON body with no declared type is what a callable and most `onRequest` handlers
    // expect; the caller can override it with an explicit header.
    if !body.is_empty() && !has_content_type {
        headers.push(("content-type".to_owned(), "application/json".to_owned()));
    }

    let path_and_query = if query.is_empty() {
        full_path
    } else {
        format!("{full_path}?{query}")
    };
    Ok(InvokePlan {
        method,
        path_and_query,
        headers,
        body,
    })
}

/// Encodes a forwarded response for the console: the status, the response headers, the body
/// as UTF-8 text when it is valid and small enough (else standard base64), and how long the
/// round trip took. A body past [`MAX_INVOKE_RESPONSE_BYTES`] is reported as truncated with
/// its true length rather than shipped whole.
#[must_use]
pub fn encode_response(
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    duration_millis: u128,
) -> Value {
    let full_len = body.len();
    let truncated = full_len > MAX_INVOKE_RESPONSE_BYTES;
    let shown = if truncated {
        &body[..MAX_INVOKE_RESPONSE_BYTES]
    } else {
        body
    };
    let headers: Vec<Value> = headers
        .iter()
        .map(|(name, value)| json!([name, value]))
        .collect();
    let mut out = json!({
        "status": status,
        "headers": headers,
        "bodyLength": full_len,
        "truncated": truncated,
        "durationMs": duration_millis.min(u128::from(u64::MAX)),
    });
    if let Ok(text) = std::str::from_utf8(shown) {
        out["body"] = Value::String(text.to_owned());
        out["bodyEncoding"] = Value::String("utf8".to_owned());
    } else {
        out["body"] = Value::String(base64_standard(shown));
        out["bodyEncoding"] = Value::String("base64".to_owned());
    }
    out
}

/// Whether `id` is a Cloud Tasks task id: `[A-Za-z0-9_-]+`, at most 500 characters, exactly
/// as the Admin SDK's `isTaskId` validates one.
fn is_task_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 500
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Builds the enqueue body the Admin SDK sends for `getFunctions().taskQueue(q).enqueue(data)`
/// so the runtime's own `enqueue_task` accepts it unchanged: `data` wrapped as
/// `{"data": ...}`, base64-encoded, under an empty `url` the queue substitutes with its own
/// default URI, plus the `Content-Type: application/json` header the SDK always sends.
///
/// A named task carries the resource name the SDK builds, so a duplicate id is refused the
/// same way. Extra `headers` are spread after the default, as the SDK spreads `opts.headers`.
///
/// # Errors
///
/// A task id that is not `[A-Za-z0-9_-]{1,500}`, or a non-string header, is refused with the
/// Admin SDK's own wording.
pub fn build_task_body(
    project: &str,
    location: &str,
    queue: &str,
    data: &Value,
    id: Option<&str>,
    headers: Option<&Map<String, Value>>,
) -> Result<Value, String> {
    let mut header_map = Map::new();
    header_map.insert(
        "Content-Type".to_owned(),
        Value::String("application/json".to_owned()),
    );
    if let Some(headers) = headers {
        for (name, value) in headers {
            let value = value
                .as_str()
                .ok_or_else(|| format!("header {name:?} must be a string"))?;
            header_map.insert(name.clone(), Value::String(value.to_owned()));
        }
    }
    let encoded = base64_standard(json!({ "data": data }).to_string().as_bytes());
    let mut task = json!({
        "httpRequest": {
            "url": "",
            "body": encoded,
            "headers": header_map,
        },
    });
    if let Some(id) = id {
        if !is_task_id(id) {
            return Err(
                "id can contain only letters ([A-Za-z]), numbers ([0-9]), hyphens (-), or \
                 underscores (_). The maximum length is 500 characters."
                    .to_owned(),
            );
        }
        task["name"] = Value::String(format!(
            "projects/{project}/locations/{location}/queues/{queue}/tasks/{id}"
        ));
    }
    Ok(json!({ "task": task }))
}

/// The next time `schedule` (in `time_zone`, `None` meaning UTC) runs strictly after `now`,
/// as an RFC 3339 UTC string. `None` when the zone is unknown, the schedule has no run within
/// its search horizon, or the instant is not representable as RFC 3339.
#[must_use]
pub fn next_run_rfc3339(
    schedule: &Schedule,
    time_zone: Option<&str>,
    now: LogicalInstant,
) -> Option<String> {
    let zone = zone::resolve(time_zone).ok()?;
    let next = schedule.next_after_in(now, &*zone)?;
    next.to_rfc3339().ok()
}

/// Standard base64 decoding (padding and whitespace tolerated), for an invoke body given as
/// `bodyBase64`.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for byte in text.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        let value = u32::try_from(TABLE.iter().position(|t| *t == byte)?).ok()?;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            #[allow(clippy::cast_possible_truncation)]
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_callable_invocation_takes_the_functions_route_and_a_json_content_type() {
        let plan = build_invoke(
            "demo-app",
            "us-central1",
            "add",
            &json!({"body": "{\"data\":{\"a\":1,\"b\":2}}"}),
        )
        .unwrap();
        assert_eq!(plan.method, "POST");
        assert_eq!(plan.path_and_query, "/demo-app/us-central1/add");
        assert_eq!(
            plan.headers,
            vec![("content-type".to_owned(), "application/json".to_owned())]
        );
        assert_eq!(plan.body, b"{\"data\":{\"a\":1,\"b\":2}}");
    }

    #[test]
    fn an_on_request_invocation_carries_method_path_query_and_headers() {
        let plan = build_invoke(
            "demo-app",
            "us-central1",
            "echo",
            &json!({
                "method": "get",
                "path": "/hello",
                "query": "?x=1&y=2",
                "headers": {"x-smoke": "hi"},
            }),
        )
        .unwrap();
        assert_eq!(plan.method, "GET");
        assert_eq!(plan.path_and_query, "/demo-app/us-central1/echo/hello?x=1&y=2");
        // No body, so no default content-type is added; only the header the caller gave.
        assert_eq!(plan.headers, vec![("x-smoke".to_owned(), "hi".to_owned())]);
        assert!(plan.body.is_empty());
    }

    #[test]
    fn an_explicit_content_type_is_not_overridden() {
        let plan = build_invoke(
            "p",
            "r",
            "f",
            &json!({"headers": {"Content-Type": "text/plain"}, "body": "hi"}),
        )
        .unwrap();
        assert_eq!(
            plan.headers,
            vec![("Content-Type".to_owned(), "text/plain".to_owned())]
        );
    }

    #[test]
    fn a_base64_body_is_decoded_to_bytes() {
        let plan = build_invoke("p", "r", "f", &json!({"bodyBase64": "aGVsbG8="})).unwrap();
        assert_eq!(plan.body, b"hello");
    }

    #[test]
    fn unsafe_method_path_query_and_headers_are_refused() {
        assert!(build_invoke("p", "r", "f", &json!({"method": "PO ST"})).is_err());
        assert!(build_invoke("p", "r", "f", &json!({"method": "GET\r\nX"})).is_err());
        assert!(build_invoke("p", "r", "f", &json!({"path": "no-leading-slash"})).is_err());
        assert!(build_invoke("p", "r", "f", &json!({"path": "/a b"})).is_err());
        assert!(build_invoke("p", "r", "f", &json!({"path": "/a\u{0000}b"})).is_err());
        assert!(build_invoke("p", "r", "f", &json!({"query": "a=1 2"})).is_err());
        assert!(build_invoke("p", "r", "f", &json!({"headers": {"bad name": "v"}})).is_err());
        assert!(build_invoke("p", "r", "f", &json!({"headers": {"x": "v\nsmuggle"}})).is_err());
        assert!(build_invoke("p", "r", "f", &json!({"headers": {"x": 1}})).is_err());
    }

    #[test]
    fn body_and_body_base64_are_mutually_exclusive() {
        let e = build_invoke("p", "r", "f", &json!({"body": "a", "bodyBase64": "YQ=="}))
            .unwrap_err();
        assert!(e.contains("mutually exclusive"), "{e}");
    }

    #[test]
    fn the_response_body_is_utf8_when_valid_and_base64_otherwise() {
        let text = encode_response(200, &[("content-type".to_owned(), "application/json".to_owned())], b"{\"sum\":3}", 12);
        assert_eq!(text["status"], 200);
        assert_eq!(text["body"], "{\"sum\":3}");
        assert_eq!(text["bodyEncoding"], "utf8");
        assert_eq!(text["bodyLength"], 9);
        assert_eq!(text["truncated"], false);
        assert_eq!(text["durationMs"], 12);
        assert_eq!(text["headers"], json!([["content-type", "application/json"]]));

        let binary = encode_response(200, &[], &[0xff, 0xfe, 0x00], 0);
        assert_eq!(binary["bodyEncoding"], "base64");
        assert_eq!(binary["body"], base64_standard(&[0xff, 0xfe, 0x00]));
    }

    #[test]
    fn an_oversized_response_body_is_truncated_with_its_true_length() {
        let big = vec![b'a'; MAX_INVOKE_RESPONSE_BYTES + 10];
        let out = encode_response(200, &[], &big, 1);
        assert_eq!(out["truncated"], true);
        assert_eq!(out["bodyLength"], big.len());
        assert_eq!(
            out["body"].as_str().unwrap().len(),
            MAX_INVOKE_RESPONSE_BYTES,
            "only the shown prefix is returned"
        );
    }

    #[test]
    fn an_enqueue_body_wraps_data_and_leaves_the_url_for_the_queue_to_fill() {
        let body = build_task_body(
            "demo-app",
            "us-central1",
            "countJob",
            &json!({"id": "x", "n": 3}),
            None,
            None,
        )
        .unwrap();
        let http = &body["task"]["httpRequest"];
        assert_eq!(http["url"], "");
        assert_eq!(http["headers"]["Content-Type"], "application/json");
        // The body is the base64 of `{"data": <data>}`, exactly the Admin SDK's shape.
        let decoded = decode_base64(http["body"].as_str().unwrap()).unwrap();
        let parsed: Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(parsed, json!({"data": {"id": "x", "n": 3}}));
        assert!(body["task"].get("name").is_none());
    }

    #[test]
    fn a_named_task_carries_the_resource_name_and_extra_headers() {
        let extra = json!({"x-trace": "abc"});
        let body = build_task_body(
            "demo-app",
            "us-central1",
            "countJob",
            &json!({}),
            Some("task-1"),
            extra.as_object(),
        )
        .unwrap();
        assert_eq!(
            body["task"]["name"],
            "projects/demo-app/locations/us-central1/queues/countJob/tasks/task-1"
        );
        assert_eq!(body["task"]["httpRequest"]["headers"]["x-trace"], "abc");
        assert_eq!(
            body["task"]["httpRequest"]["headers"]["Content-Type"],
            "application/json"
        );
    }

    #[test]
    fn an_invalid_task_id_is_refused_with_the_admin_sdk_wording() {
        let e = build_task_body("p", "l", "q", &json!({}), Some("bad id!"), None).unwrap_err();
        assert!(e.contains("letters ([A-Za-z])"), "{e}");
        assert!(build_task_body("p", "l", "q", &json!({}), Some(""), None).is_err());
        let long = "a".repeat(501);
        assert!(build_task_body("p", "l", "q", &json!({}), Some(&long), None).is_err());
        // 500 is the boundary that is still accepted.
        let max = "a".repeat(500);
        assert!(build_task_body("p", "l", "q", &json!({}), Some(&max), None).is_ok());
    }

    #[test]
    fn the_next_run_is_the_first_instant_strictly_after_now_in_the_zone() {
        // 2026-08-29T12:01:00Z. "every 5 minutes" is anchored at the epoch, so the next run
        // is 12:05:00Z regardless of zone.
        let now = LogicalInstant::from_unix_seconds(1_788_004_860);
        let schedule = Schedule::parse("every 5 minutes").unwrap();
        assert_eq!(
            next_run_rfc3339(&schedule, Some("Asia/Tokyo"), now).unwrap(),
            "2026-08-29T12:05:00Z"
        );
    }

    #[test]
    fn a_daily_cron_next_run_respects_the_time_zone() {
        // 0 3 * * * in Asia/Tokyo (UTC+9) is 18:00Z the previous day. At 12:01Z on 2026-08-29
        // the next Tokyo 03:00 is 2026-08-29T18:00:00Z.
        let now = LogicalInstant::from_unix_seconds(1_788_004_860);
        let schedule = Schedule::parse("0 3 * * *").unwrap();
        assert_eq!(
            next_run_rfc3339(&schedule, Some("Asia/Tokyo"), now).unwrap(),
            "2026-08-29T18:00:00Z"
        );
        // The same cron in UTC is 03:00Z the next day.
        assert_eq!(
            next_run_rfc3339(&schedule, None, now).unwrap(),
            "2026-08-30T03:00:00Z"
        );
    }

    #[test]
    fn an_unknown_zone_has_no_next_run() {
        let now = LogicalInstant::from_unix_seconds(1_788_004_860);
        let schedule = Schedule::parse("every 5 minutes").unwrap();
        assert!(next_run_rfc3339(&schedule, Some("Mars/Phobos"), now).is_none());
    }
}
