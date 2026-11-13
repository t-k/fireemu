//! Cloud Tasks: the enqueue surface the Admin SDK writes to, and the dispatch an
//! `onTaskDispatched` function receives.
//!
//! The official Local Emulator Suite runs a Tasks emulator on port 9499 and points
//! `CLOUD_TASKS_EMULATOR_HOST` at it, without a scheme (unlike `CLOUD_EVENTARC_EMULATOR_HOST`,
//! which has one). fireemu serves the same routes on a dedicated Tasks port that starts with
//! the Functions runtime and exports the variable accordingly, so
//! `getFunctions().taskQueue(name).enqueue(payload)` reaches it unchanged.
//!
//! What the Admin SDK sends (`firebase-admin/lib/functions/functions-api-client-internal.js`):
//!
//! ```json
//! POST /projects/{p}/locations/{l}/queues/{function}/tasks
//! {"task": {"httpRequest": {"url": "", "oidcToken": {...},
//!                           "body": "<base64 of {\"data\": payload}>",
//!                           "headers": {"Content-Type": "application/json"}},
//!           "scheduleTime"?, "dispatchDeadline"?, "name"?}}
//! ```
//!
//! The empty `url` is the hinge: `TaskQueue.enqueue` (`taskQueue.js:304`) substitutes the
//! queue's `defaultUri` on a strict `=== ""`, and the queue's `defaultUri` is the function's
//! own `/{project}/{region}/{name}`. A `null` or absent url is *not* substituted upstream, and
//! is not here either.

use std::collections::BTreeMap;

use serde_json::{json, Value};

/// What the enqueue route accepted, ready to dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    /// Full resource name.
    pub name: String,
    /// Where to POST it.
    pub url: String,
    /// The task's own headers, spread over the emulator's (they win, as upstream spreads
    /// them last).
    pub headers: BTreeMap<String, String>,
    /// The decoded body -- `{"data": payload}` for anything the Admin SDK enqueued.
    pub body: Value,
    /// The original JSON parser failure, retained for the emulator profile's current refusal.
    pub body_json_error: Option<String>,
    /// The decoded bytes exactly as the enqueuer wrote them. Production delivers these (member
    /// order and spacing included); `body` is only the parsed echo of the enqueue response.
    pub(crate) raw_body: Vec<u8>,
    /// `createTime` supplied by the strict Cloud Tasks surface.
    pub create_time: Option<String>,
    /// `scheduleTime`, echoed into `X-CloudTasks-TaskETA`. Native task mode does not delay dispatch:
    /// nothing in the official `dispatchTasks` or `runTask` consults it either.
    /// Explicit virtual task mode gates eligibility on this value.
    pub schedule_time: Option<String>,
    /// The abort deadline, in seconds; `dispatchDeadline` without its trailing `s`, else 60.
    pub dispatch_deadline_seconds: u64,
    /// Exact accepted protobuf duration spelling, including fractional seconds.
    pub dispatch_deadline: String,
    /// Accepted `httpRequest.oauthToken` configuration, echoed by getTask.
    pub oauth_token: Option<Value>,
    /// `httpRequest.oidcToken`: the service account and audience the task names. Cloud Tasks delivers an
    /// `Authorization: Bearer` OIDC token for them; the strict profile delivers an emulator-issued token of the same
    /// shape.
    pub oidc: Option<TaskOidc>,
}

/// The identity a task asks Cloud Tasks to deliver as (`httpRequest.oidcToken`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskOidc {
    /// `serviceAccountEmail`.
    pub service_account_email: String,
    /// `audience`; the task's URL when the task names none.
    pub audience: String,
}

impl Task {
    /// The bytes one dispatch carries as its request body: the task's body as it was enqueued.
    #[must_use]
    pub fn delivery_body(&self) -> &[u8] {
        &self.raw_body
    }

    /// Approximate heap data retained while this task is pending or being dispatched.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        let headers = self
            .headers
            .iter()
            .map(|(name, value)| name.len().saturating_add(value.len()))
            .sum::<usize>();
        self.name
            .len()
            .saturating_add(self.url.len())
            .saturating_add(headers)
            .saturating_add(
                self.schedule_time
                    .as_ref()
                    .map_or(0, std::string::String::len),
            )
            .saturating_add(serde_json::to_vec(&self.body).map_or(usize::MAX, |body| body.len()))
            .saturating_add(self.raw_body.len())
            .saturating_add(self.create_time.as_ref().map_or(0, String::len))
            .saturating_add(self.dispatch_deadline.len())
            .saturating_add(
                self.oauth_token
                    .as_ref()
                    .and_then(|token| serde_json::to_vec(token).ok())
                    .map_or(0, |encoded| encoded.len()),
            )
            // Reserve the bounded dispatch/response attempt snapshot retained while active.
            .saturating_add(256)
    }
}

/// Why an enqueue was refused, with the status the Admin SDK will see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnqueueRefusal {
    /// HTTP status.
    pub status: u16,
    /// Body. The official emulator answers plain text on these two, which is why the Admin
    /// SDK reports them as `Unexpected response with status: N and body: ...` rather than a
    /// mapped code -- except 409, which it special-cases to `task-already-exists`.
    pub body: String,
}

/// Encodes a task request body for the Cloud Tasks JSON representation.
pub(crate) fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0_u32, |acc, (index, byte)| {
            acc | (u32::from(*byte) << (16 - 8 * index))
        });
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(char::from(TABLE[((n >> (18 - 6 * index)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Parses Cloud Tasks' `responseView` query parameter, defaulting to BASIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidResponseView;

pub(crate) fn response_view(target: &str) -> Result<bool, InvalidResponseView> {
    let Some((_, query)) = target.split_once('?') else {
        return Ok(false);
    };
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if decode_query_component(key).map_err(|()| InvalidResponseView)? != b"responseView" {
            continue;
        }
        return match decode_query_component(value)
            .map_err(|()| InvalidResponseView)?
            .as_slice()
        {
            b"BASIC" | b"VIEW_UNSPECIFIED" => Ok(false),
            b"FULL" => Ok(true),
            _ => Err(InvalidResponseView),
        };
    }
    Ok(false)
}

fn decode_query_component(value: &str) -> Result<Vec<u8>, ()> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => decoded.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let hex = |byte: u8| match byte {
                    b'0'..=b'9' => Some(byte - b'0'),
                    b'a'..=b'f' => Some(byte - b'a' + 10),
                    b'A'..=b'F' => Some(byte - b'A' + 10),
                    _ => None,
                };
                let high = hex(bytes[index + 1]).ok_or(())?;
                let low = hex(bytes[index + 2]).ok_or(())?;
                decoded.push((high << 4) | low);
                index += 2;
            }
            b'%' => return Err(()),
            byte => decoded.push(byte),
        }
        index += 1;
    }
    Ok(decoded)
}

/// The route a functions-port path names, if it is one of the Cloud Tasks routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// `GET /queueStats`: statistics for all registered queues.
    QueueStats,
    /// `POST /projects/{p}/locations/{l}/queues/{q}`: create or update a queue.
    CreateQueue {
        /// Project.
        project: String,
        /// Location.
        location: String,
        /// Queue, which is the function name.
        queue: String,
    },
    /// `POST /projects/{p}/locations/{l}/queues/{q}/tasks`: enqueue.
    Enqueue {
        /// Project.
        project: String,
        /// Location.
        location: String,
        /// Queue.
        queue: String,
    },
    /// `DELETE /projects/{p}/locations/{l}/queues/{q}/tasks/{id}`.
    DeleteTask {
        /// Project.
        project: String,
        /// Location.
        location: String,
        /// Queue.
        queue: String,
        /// Task id.
        task: String,
    },
}

/// Classifies a path against the Cloud Tasks routes.
#[must_use]
pub fn route(path: &str) -> Option<Route> {
    if path.trim_end_matches('/') == "/queueStats" {
        return Some(Route::QueueStats);
    }
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let (project, location, queue) = match parts.as_slice() {
        ["projects", p, "locations", l, "queues", q, ..]
            if !p.is_empty() && !l.is_empty() && !q.is_empty() =>
        {
            ((*p).to_owned(), (*l).to_owned(), (*q).to_owned())
        }
        _ => return None,
    };
    match parts.len() {
        6 => Some(Route::CreateQueue {
            project,
            location,
            queue,
        }),
        7 if parts[6] == "tasks" => Some(Route::Enqueue {
            project,
            location,
            queue,
        }),
        8 if parts[6] == "tasks" && !parts[7].is_empty() => Some(Route::DeleteTask {
            project,
            location,
            queue,
            task: parts[7].to_owned(),
        }),
        _ => None,
    }
}

/// The queue key the official emulator builds, and sends back in `X-CloudTasks-QueueName`.
///
/// It is the internal key, `queue:{project}-{location}-{queue}`, not the bare queue id that
/// production sends -- so a handler that reads `request.queueName` sees this shape under both
/// emulators (`tasksEmulator.js:124`, `taskQueue.js:194`).
#[must_use]
pub fn queue_key(project: &str, location: &str, queue: &str) -> String {
    format!("queue:{project}-{location}-{queue}")
}

/// Accepts one enqueue body against a queue whose `default_uri` is known.
///
/// `next_id` supplies the id for a task that did not name itself. The official emulator uses
/// `Math.random()` there and gives the generated name a leading slash the delete route can
/// never match again; fireemu uses the same resource shape as a named task, so a generated
/// task can be deleted by the id the response reports.
pub fn accept(
    project: &str,
    location: &str,
    queue: &str,
    default_uri: &str,
    body: &Value,
    next_id: u64,
) -> Result<Task, EnqueueRefusal> {
    let task = body.get("task").ok_or_else(|| EnqueueRefusal {
        status: 400,
        body: "the request body must carry a task".to_owned(),
    })?;
    let http = task.get("httpRequest").ok_or_else(|| EnqueueRefusal {
        status: 400,
        body: "the task must carry an httpRequest".to_owned(),
    })?;
    let prefix = format!("projects/{project}/locations/{location}/queues/{queue}/tasks");
    let name = task
        .get("name")
        .and_then(Value::as_str)
        .map_or_else(|| format!("{prefix}/{next_id}"), str::to_owned);
    // Only the empty string is replaced, exactly as `taskQueue.js:304` replaces it.
    let url = match http.get("url").and_then(Value::as_str) {
        Some("") | None => default_uri.to_owned(),
        Some(url) => url.to_owned(),
    };
    let encoded = http
        .get("body")
        .and_then(Value::as_str)
        .ok_or_else(|| EnqueueRefusal {
            status: 400,
            body: "the task's httpRequest must carry a base64 body".to_owned(),
        })?;
    let decoded = decode_base64(encoded).ok_or_else(|| EnqueueRefusal {
        status: 400,
        body: "the task's httpRequest body is not base64".to_owned(),
    })?;
    let (body, body_json_error) = match serde_json::from_slice(&decoded) {
        Ok(body) => (body, None),
        Err(error) => (Value::Null, Some(error.to_string())),
    };
    let mut headers = BTreeMap::new();
    if let Some(map) = http.get("headers").and_then(Value::as_object) {
        for (k, v) in map {
            if let Some(v) = v.as_str() {
                headers.insert(k.clone(), v.to_owned());
            }
        }
    }
    let dispatch_deadline = task
        .get("dispatchDeadline")
        .and_then(Value::as_str)
        .map_or_else(|| "60s".to_owned(), str::to_owned);
    let dispatch_deadline_seconds = dispatch_deadline
        .trim_end_matches('s')
        .parse::<u64>()
        .unwrap_or(60);
    let oidc = http
        .get("oidcToken")
        .and_then(Value::as_object)
        .and_then(|token| {
            let email = token.get("serviceAccountEmail")?.as_str()?;
            let audience = token
                .get("audience")
                .and_then(Value::as_str)
                .filter(|audience| !audience.is_empty());
            Some(TaskOidc {
                service_account_email: email.to_owned(),
                audience: audience.map_or_else(|| url.clone(), str::to_owned),
            })
        });
    Ok(Task {
        name,
        url,
        headers,
        body,
        body_json_error,
        raw_body: decoded,
        create_time: None,
        schedule_time: task
            .get("scheduleTime")
            .and_then(Value::as_str)
            .map(str::to_owned),
        dispatch_deadline_seconds,
        dispatch_deadline,
        oauth_token: http.get("oauthToken").cloned(),
        oidc,
    })
}

/// The `Authorization` value of a strict delivery for a task that named an `oidcToken`: `Bearer` and a three segment
/// token with the claims of the identity token Cloud Tasks signs for a service account (`iss`, `aud`, `sub`, `email`,
/// `email_verified`, `iat`, `exp`). The emulator issues it unsigned (`alg: none`, an empty third segment): it has
/// no key Google verifies, so only the scheme and the three segments are production's, never the signature or the values.
#[must_use]
pub fn oidc_authorization(oidc: &TaskOidc, now_millis: u64) -> String {
    let issued = now_millis / 1000;
    let subject = oidc
        .service_account_email
        .bytes()
        .fold(1_u64, |hash, byte| {
            hash.wrapping_mul(1_099_511_628_211)
                .wrapping_add(u64::from(byte))
        })
        % 10_000_000_000_000_000_000;
    let claims = json!({
        "aud": oidc.audience,
        "email": oidc.service_account_email,
        "email_verified": true,
        "exp": issued + 3600,
        "iat": issued,
        "iss": "https://accounts.google.com",
        "sub": format!("{subject:020}"),
    });
    format!(
        "Bearer {}",
        fireemu_core_auth::jwt::encode_payload_with(&claims.to_string(), None)
    )
}

/// The response the Admin SDK expects from a successful enqueue.
///
/// It echoes the task with the body **decoded**, because the official emulator decodes
/// `req.body.task.httpRequest.body` in place before sending it back. Production returns the
/// base64 it was given.
#[must_use]
pub fn accepted_response(task: &Task) -> Value {
    json!({"task": {
        "name": task.name,
        "httpRequest": {
            "url": task.url,
            "body": task.body,
            "headers": task.headers,
        },
        "scheduleTime": task.schedule_time,
    }})
}

/// Whose headers a dispatch carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchShape<'a> {
    /// The official emulator's: the internal queue key, the ETA as it was written (a schedule
    /// time as given, else the dispatch instant in milliseconds), and no user agent.
    Official,
    /// Production's, as recorded on 2026-11-04 (sandbox run PYCHECK-EVENTS-20261104-01): the
    /// bare queue id, the ETA as seconds with six decimals, and the `Google-Cloud-Tasks` user
    /// agent. Production also sends an OIDC `Authorization` header and Cloud Run's own headers,
    /// which a local dispatch has no source for.
    Production {
        /// The queue id, `onJob` for `.../queues/onJob`.
        queue: &'a str,
    },
}

/// Whether `text` is a `scheduleTime` the strict profile admits: an RFC 3339 timestamp that is
/// not a leap second. (The Cloud Tasks reference does not say how an invalid one is refused;
/// a malformed `google.protobuf.Timestamp` in the JSON API is `INVALID_ARGUMENT` by the proto3
/// JSON mapping. UNRECORDED.)
#[must_use]
pub fn valid_schedule_time(text: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(text)
        .is_ok_and(|time| chrono::Timelike::nanosecond(&time) < 1_000_000_000)
}

/// The ETA production writes: Unix seconds with six decimals, from the signed total of
/// microseconds (nanoseconds are truncated, an instant before the epoch is a negative number of
/// seconds). A schedule time that is not an RFC 3339 timestamp is kept as given.
fn production_eta(schedule_time: Option<&str>, now_millis: u64) -> String {
    let micros: i128 = match schedule_time {
        None => i128::from(now_millis) * 1000,
        Some(text) => match chrono::DateTime::parse_from_rfc3339(text) {
            Ok(time) => i128::from(time.timestamp_micros()),
            Err(_) => return text.to_owned(),
        },
    };
    let sign = if micros < 0 { "-" } else { "" };
    let magnitude = micros.unsigned_abs();
    format!(
        "{sign}{}.{:06}",
        magnitude / 1_000_000,
        magnitude % 1_000_000
    )
}

/// Whether Cloud Tasks owns a request header, so that a task cannot set it: `User-Agent` (set to
/// `Google-Cloud-Tasks`, documented and echoed by the recorded create answer), the
/// `X-CloudTasks-*` names (replaced by the service's own, documented; not recorded) and the
/// `X-Google-*` and `X-AppEngine-*` families ("Google use only", ignored or replaced,
/// documented; not recorded).
fn service_owned(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "user-agent"
        || ["x-cloudtasks-", "x-google-", "x-appengine-"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// Marks a strict dispatch carrying the daemon-issued identity token; public invoke entry points remove caller-supplied copies.
pub const TASK_IDENTITY_HEADER: &str = "x-fireemu-task-identity";

/// Removes caller-supplied task identity markers while preserving the other headers.
pub fn without_task_identity(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case(TASK_IDENTITY_HEADER))
        .cloned()
        .collect()
}

/// The headers one dispatch carries (`taskQueue.js:192`).
///
/// `attempt` is 1-based, so the first delivery reports `X-CloudTasks-TaskRetryCount: 0`.
/// `execution_count` counts the non-5xx failures, which is what the official emulator counts.
/// The task's own headers go on last and win, as the spread there does.
#[must_use]
pub fn dispatch_headers(
    task: &Task,
    queue_key: &str,
    attempt: u32,
    execution_count: u32,
    previous_response: Option<u16>,
    now_millis: u64,
    shape: DispatchShape<'_>,
) -> Vec<(String, String)> {
    let queue_name = match shape {
        DispatchShape::Official => queue_key,
        DispatchShape::Production { queue } => queue,
    };
    let eta = match shape {
        DispatchShape::Official => task
            .schedule_time
            .clone()
            .unwrap_or_else(|| now_millis.to_string()),
        DispatchShape::Production { .. } => {
            production_eta(task.schedule_time.as_deref(), now_millis)
        }
    };
    let mut out = vec![
        ("Content-Type".to_owned(), "application/json".to_owned()),
        ("X-CloudTasks-QueueName".to_owned(), queue_name.to_owned()),
        (
            "X-CloudTasks-TaskName".to_owned(),
            task.name
                .rsplit('/')
                .next()
                .unwrap_or(&task.name)
                .to_owned(),
        ),
        (
            "X-CloudTasks-TaskRetryCount".to_owned(),
            (attempt.saturating_sub(1)).to_string(),
        ),
        (
            "X-CloudTasks-TaskExecutionCount".to_owned(),
            execution_count.to_string(),
        ),
        ("X-CloudTasks-TaskETA".to_owned(), eta),
    ];
    if matches!(shape, DispatchShape::Production { .. }) {
        out.push(("User-Agent".to_owned(), "Google-Cloud-Tasks".to_owned()));
        // The task's own Authorization header is replaced by the identity token it asked for.
        if let Some(oidc) = &task.oidc {
            out.push((
                "Authorization".to_owned(),
                oidc_authorization(oidc, now_millis),
            ));
            out.push((TASK_IDENTITY_HEADER.to_owned(), "1".to_owned()));
        }
    }
    if let Some(status) = previous_response {
        out.push((
            "X-CloudTasks-TaskPreviousResponse".to_owned(),
            status.to_string(),
        ));
    }
    // Production sends an empty retry reason on every retry (recorded on five of the six attempts of one task, and on the
    // retry after a timeout).
    if attempt > 1 && matches!(shape, DispatchShape::Production { .. }) {
        out.push(("X-CloudTasks-TaskRetryReason".to_owned(), String::new()));
    }
    let mut forged = Vec::new();
    for (k, v) in &task.headers {
        if k.eq_ignore_ascii_case(TASK_IDENTITY_HEADER) {
            continue;
        }
        // The identity token the task asked for replaces any Authorization header of its own.
        if matches!(shape, DispatchShape::Production { .. })
            && task.oidc.is_some()
            && k.eq_ignore_ascii_case("authorization")
        {
            continue;
        }
        if matches!(shape, DispatchShape::Production { .. }) && service_owned(k) {
            // A task's own `X-CloudTasks-*` header reaches the function in front of the service's (recorded: a task that
            // set `X-CloudTasks-TaskName` was delivered as one header whose value was both, the task's first); the other
            // service-owned names are dropped or replaced.
            if k.to_ascii_lowercase().starts_with("x-cloudtasks-") {
                forged.push((k.clone(), v.clone()));
            }
            continue;
        }
        out.retain(|(existing, _)| !existing.eq_ignore_ascii_case(k));
        out.push((k.clone(), v.clone()));
    }
    out.splice(0..0, forged);
    out
}

/// Standard base64 with padding, which is what `Buffer.toString("base64")` produces.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let value = |c: u8| {
        TABLE
            .iter()
            .position(|t| *t == c)
            .and_then(|i| u32::try_from(i).ok())
    };
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for byte in text.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        acc = (acc << 6) | value(byte)?;
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
    use super::{
        accept, dispatch_headers, oidc_authorization, queue_key, route, without_task_identity,
        DispatchShape, Route, Task, TaskOidc, TASK_IDENTITY_HEADER,
    };
    use fireemu_core_functions::manifest::TaskRetryConfig;
    use serde_json::json;
    use serde_json::Value;

    #[test]
    fn task_identity_filter_removes_mixed_case_and_preserves_order() {
        let headers = vec![
            ("first".into(), "a".into()),
            ("X-Fireemu-Task-Identity".into(), "1".into()),
            ("second".into(), "b".into()),
            (TASK_IDENTITY_HEADER.into(), "yes".into()),
        ];
        assert_eq!(
            without_task_identity(&headers),
            vec![("first".into(), "a".into()), ("second".into(), "b".into())]
        );
    }

    proptest::proptest! {
        #[test]
        fn task_identity_filter_preserves_other_headers(entries in proptest::collection::vec((proptest::bool::ANY, "[a-z]{0,12}", "[a-z]{0,12}"), 0..40)) {
            let headers: Vec<(String, String)> = entries.into_iter().map(|(marker, name, value)| {
                (if marker { "X-Fireemu-Task-Identity".to_owned() } else { name }, value)
            }).collect();
            let result = without_task_identity(&headers);
            proptest::prop_assert!(result.iter().all(|(name, _)| !name.eq_ignore_ascii_case(TASK_IDENTITY_HEADER)));
            let expected: Vec<_> = headers.into_iter().filter(|(name, _)| !name.eq_ignore_ascii_case(TASK_IDENTITY_HEADER)).collect();
            proptest::prop_assert_eq!(result, expected);
        }
    }

    /// Standard base64 with padding.
    fn b64(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn enqueue_body() -> serde_json::Value {
        json!({"task": {"httpRequest": {
            "url": "",
            "oidcToken": {"serviceAccountEmail": "emulated-service-acct@email.com"},
            // base64 of {"data":{"n":1}}
            "body": "eyJkYXRhIjp7Im4iOjF9fQ==",
            "headers": {"Content-Type": "application/json"}
        }}})
    }

    #[test]
    fn task_routes_are_told_apart_and_a_function_url_is_not_one() {
        assert_eq!(route("/queueStats"), Some(Route::QueueStats));
        assert_eq!(route("/queueStats/"), Some(Route::QueueStats));
        assert_eq!(
            route("/projects/demo/locations/us-central1/queues/onJob"),
            Some(Route::CreateQueue {
                project: "demo".to_owned(),
                location: "us-central1".to_owned(),
                queue: "onJob".to_owned(),
            })
        );
        assert_eq!(
            route("/projects/demo/locations/us-central1/queues/onJob/tasks"),
            Some(Route::Enqueue {
                project: "demo".to_owned(),
                location: "us-central1".to_owned(),
                queue: "onJob".to_owned(),
            })
        );
        assert_eq!(
            route("/projects/demo/locations/us-central1/queues/onJob/tasks/t1"),
            Some(Route::DeleteTask {
                project: "demo".to_owned(),
                location: "us-central1".to_owned(),
                queue: "onJob".to_owned(),
                task: "t1".to_owned(),
            })
        );
        for path in [
            "/demo/us-central1/someFunction",
            "/projects/demo/locations/us-central1/channels/firebase:publishEvents",
            "/projects/demo/locations/us-central1/queues",
        ] {
            assert_eq!(route(path), None, "{path}");
        }
    }

    /// The empty `url` the Admin SDK sends under the emulator is what the queue's default URI
    /// replaces, and the base64 `{"data": ...}` wrapper is decoded once, here.
    #[test]
    fn an_enqueue_takes_the_queues_default_uri_and_decodes_its_body() {
        let task = accept(
            "demo",
            "us-central1",
            "onJob",
            "http://127.0.0.1:5001/demo/us-central1/onJob",
            &enqueue_body(),
            7,
        )
        .expect("a well-formed task is accepted");
        assert_eq!(task.url, "http://127.0.0.1:5001/demo/us-central1/onJob");
        assert_eq!(task.body, json!({"data": {"n": 1}}));
        assert_eq!(
            task.name,
            "projects/demo/locations/us-central1/queues/onJob/tasks/7"
        );
        assert_eq!(task.dispatch_deadline_seconds, 60);

        // A task that names its own URL keeps it: only the empty string is substituted.
        let mut body = enqueue_body();
        body["task"]["httpRequest"]["url"] = json!("http://elsewhere/x");
        let task = accept("demo", "us-central1", "onJob", "http://unused", &body, 8)
            .expect("an explicit url is accepted");
        assert_eq!(task.url, "http://elsewhere/x");
    }

    #[test]
    fn the_dispatch_headers_are_the_official_set() {
        let task = accept(
            "demo",
            "us-central1",
            "onJob",
            "http://127.0.0.1:5001/demo/us-central1/onJob",
            &enqueue_body(),
            7,
        )
        .expect("accepted");
        let headers = dispatch_headers(
            &task,
            &queue_key("demo", "us-central1", "onJob"),
            1,
            0,
            None,
            1_700_000_000_000,
            DispatchShape::Official,
        );
        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(
            get("X-CloudTasks-QueueName"),
            Some("queue:demo-us-central1-onJob")
        );
        assert_eq!(get("X-CloudTasks-TaskName"), Some("7"));
        // The first delivery is retry count 0.
        assert_eq!(get("X-CloudTasks-TaskRetryCount"), Some("0"));
        assert_eq!(get("X-CloudTasks-TaskExecutionCount"), Some("0"));
        assert_eq!(get("X-CloudTasks-TaskETA"), Some("1700000000000"));
        assert_eq!(get("X-CloudTasks-TaskPreviousResponse"), None);
        // Never sent, by either emulator.
        assert_eq!(get("X-CloudTasks-TaskRetryReason"), None);

        let retried = dispatch_headers(
            &task,
            "queue:demo-us-central1-onJob",
            3,
            2,
            Some(503),
            1_700_000_000_000,
            DispatchShape::Official,
        );
        let get = |name: &str| {
            retried
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("X-CloudTasks-TaskRetryCount"), Some("2"));
        assert_eq!(get("X-CloudTasks-TaskPreviousResponse"), Some("503"));
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Production delivers the bytes the task was created with (recorded 2026-11-04, sandbox run
    /// PYCHECK-EVENTS-20261104-01: the body of a raw task request arrived with the enqueuer's own
    /// member order). Re-serialising the parsed value sorted the members.
    #[test]
    fn a_task_body_is_delivered_byte_for_byte() {
        let text = r#"{ "data": {"run": "r", "label": "l", "n": [3, 1, 2]},"z":null }"#;
        let mut body = enqueue_body();
        body["task"]["httpRequest"]["body"] = json!(b64(text.as_bytes()));
        let task =
            accept("demo", "us-central1", "onJob", "http://unused", &body, 1).expect("accepted");
        assert_eq!(task.delivery_body(), text.as_bytes());
        // The echo of the enqueue keeps the decoded JSON, as before.
        assert_eq!(task.body["data"]["label"], json!("l"));
    }

    #[test]
    fn the_retained_size_counts_the_delivered_bytes_exactly_once() {
        let task_with = |text: &str| {
            let mut body = enqueue_body();
            body["task"]["httpRequest"]["body"] = json!(b64(text.as_bytes()));
            accept("demo", "us-central1", "q", "http://u", &body, 1).unwrap()
        };
        // The same decoded JSON, written compactly and with 25 more bytes of white space: the
        // parsed value is equal, so only the delivered bytes can make the sizes differ.
        let compact = task_with(r#"{"data":{"n":1}}"#);
        let spaced = task_with("{ \"data\" :\n { \"n\" : 1 } \n\n\n\n\n}");
        assert_eq!(compact.body, spaced.body);
        let extra = spaced.delivery_body().len() - compact.delivery_body().len();
        assert!(extra > 0);
        assert_eq!(spaced.retained_bytes() - compact.retained_bytes(), extra);
    }

    /// What production sent to a Tasks function (recorded 2026-11-04, sandbox run
    /// PYCHECK-EVENTS-20261104-01): the bare queue id, the ETA as seconds with six decimals, and
    /// the `Google-Cloud-Tasks` user agent.
    #[test]
    fn the_production_shape_sends_the_bare_queue_the_decimal_eta_and_the_user_agent() {
        let task = accept(
            "demo",
            "us-central1",
            "onJob",
            "http://unused",
            &enqueue_body(),
            7,
        )
        .expect("accepted");
        let headers = dispatch_headers(
            &task,
            &queue_key("demo", "us-central1", "onJob"),
            1,
            0,
            None,
            1_700_000_000_123,
            DispatchShape::Production { queue: "onJob" },
        );
        assert_eq!(header(&headers, "X-CloudTasks-QueueName"), Some("onJob"));
        assert_eq!(
            header(&headers, "X-CloudTasks-TaskETA"),
            Some("1700000000.123000")
        );
        assert_eq!(header(&headers, "User-Agent"), Some("Google-Cloud-Tasks"));
        assert_eq!(header(&headers, "Content-Type"), Some("application/json"));
        assert_eq!(header(&headers, "X-CloudTasks-TaskName"), Some("7"));
        assert_eq!(header(&headers, "X-CloudTasks-TaskRetryCount"), Some("0"));
        assert_eq!(
            header(&headers, "X-CloudTasks-TaskExecutionCount"),
            Some("0")
        );
    }

    #[test]
    fn the_official_shape_has_no_user_agent_and_keeps_the_internal_queue_key() {
        let task = accept(
            "demo",
            "us-central1",
            "onJob",
            "http://unused",
            &enqueue_body(),
            7,
        )
        .expect("accepted");
        let headers = dispatch_headers(
            &task,
            &queue_key("demo", "us-central1", "onJob"),
            1,
            0,
            None,
            1_700_000_000_123,
            DispatchShape::Official,
        );
        assert_eq!(
            header(&headers, "X-CloudTasks-QueueName"),
            Some("queue:demo-us-central1-onJob")
        );
        assert_eq!(
            header(&headers, "X-CloudTasks-TaskETA"),
            Some("1700000000123")
        );
        assert_eq!(header(&headers, "User-Agent"), None);
    }

    /// The ETA is the signed total of microseconds, so an instant before the epoch reads as a
    /// negative number of seconds and not as a floor with a positive fraction. Nanoseconds are
    /// truncated, never rounded up. (Production refuses or never sends such times; these fix the
    /// formatter only. UNRECORDED.)
    #[test]
    fn the_production_eta_is_signed_whole_microseconds() {
        for (schedule, expected) in [
            ("1970-01-01T00:00:00Z", "0.000000"),
            ("1970-01-01T00:00:00.000001Z", "0.000001"),
            ("1969-12-31T23:59:59.500000Z", "-0.500000"),
            ("1969-12-31T23:59:59.000001Z", "-0.999999"),
            ("1969-12-31T23:59:59Z", "-1.000000"),
            ("1969-12-31T23:59:58.250000Z", "-1.750000"),
            ("1970-01-01T00:00:00.9999999Z", "0.999999"),
            ("1970-01-01T00:00:00.123456789Z", "0.123456"),
            ("2026-02-01T00:30:00.9999995+00:00", "1769905800.999999"),
        ] {
            assert_eq!(
                super::production_eta(Some(schedule), 0),
                expected,
                "{schedule}"
            );
        }
    }

    /// The same rule decides what the strict profile admits at enqueue: an RFC 3339 timestamp
    /// that is not a leap second. The Cloud Tasks reference does not say how an invalid
    /// `scheduleTime` is refused; a malformed `google.protobuf.Timestamp` in the JSON API is
    /// `INVALID_ARGUMENT` (400) by the proto3 JSON mapping. UNRECORDED.
    #[test]
    fn a_schedule_time_is_valid_when_it_is_an_rfc_3339_timestamp_and_not_a_leap_second() {
        for good in [
            "2026-02-01T00:30:00Z",
            "2026-02-01T00:30:00.5Z",
            "2026-02-01T01:30:00.123456+01:00",
            "1970-01-01T00:00:00Z",
        ] {
            assert!(super::valid_schedule_time(good), "{good}");
        }
        for bad in [
            "",
            "soon",
            "2026-02-01",
            "2026-02-01T00:30:00",
            "2026-02-30T00:30:00Z",
            "2026-02-01T24:00:00Z",
            "2016-12-31T23:59:60Z",
            " 2026-02-01T00:30:00Z",
            "1700000000",
        ] {
            assert!(!super::valid_schedule_time(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_production_eta_of_a_scheduled_task_is_its_schedule_time_with_six_decimals() {
        for (schedule, expected) in [
            ("2026-02-01T00:30:00Z", "1769905800.000000"),
            ("2026-02-01T00:30:00.5Z", "1769905800.500000"),
            ("2026-02-01T01:30:00.123456+01:00", "1769905800.123456"),
        ] {
            let mut body = enqueue_body();
            body["task"]["scheduleTime"] = json!(schedule);
            let task = accept("demo", "us-central1", "q", "http://u", &body, 1).unwrap();
            let headers = dispatch_headers(
                &task,
                "queue:demo-us-central1-q",
                1,
                0,
                None,
                1,
                DispatchShape::Production { queue: "q" },
            );
            assert_eq!(
                header(&headers, "X-CloudTasks-TaskETA"),
                Some(expected),
                "{schedule}"
            );
        }
        // A schedule time that is not a timestamp is kept as given rather than invented.
        let mut body = enqueue_body();
        body["task"]["scheduleTime"] = json!("soon");
        let task = accept("demo", "us-central1", "q", "http://u", &body, 1).unwrap();
        let headers = dispatch_headers(
            &task,
            "queue:demo-us-central1-q",
            1,
            0,
            None,
            1,
            DispatchShape::Production { queue: "q" },
        );
        assert_eq!(header(&headers, "X-CloudTasks-TaskETA"), Some("soon"));
    }

    fn with_task_headers(headers: serde_json::Value) -> super::Task {
        let mut body = enqueue_body();
        body["task"]["httpRequest"]["headers"] = headers;
        accept("demo", "us-central1", "q", "http://u", &body, 1).unwrap()
    }

    fn count(headers: &[(String, String)], name: &str) -> usize {
        headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .count()
    }

    /// Cloud Tasks documents `User-Agent` as "set to Google-Cloud-Tasks" and `X-Google-*` and
    /// `X-AppEngine-*` as ignored or replaced (HttpRequest.headers). Its request-header guide says
    /// the `X-CloudTasks-*` names are replaced by the service's own values. Only the user agent
    /// was recorded (the create answer echoed `Google-Cloud-Tasks`); the `X-CloudTasks-*`
    /// replacement and the dropped `X-Google-*` follow the documentation and the recording of 2026-11-11 (a task's own
    /// `X-CloudTasks-*` header reaches the function in front of the service's).
    #[test]
    fn the_production_shape_keeps_the_service_headers_whatever_the_task_sets_and_the_official_shape_does_not(
    ) {
        let owned = [
            ("User-Agent", "custom/1"),
            ("user-agent", "custom/2"),
            ("USER-AGENT", "custom/3"),
            ("X-CloudTasks-QueueName", "other"),
            ("x-cloudtasks-taskname", "other"),
            ("X-CLOUDTASKS-TASKETA", "soon"),
            ("X-CloudTasks-TaskRetryCount", "5"),
            ("x-cloudtasks-taskexecutioncount", "5"),
        ];
        for (name, value) in owned {
            let task = with_task_headers(json!({ name: value, "X-Custom": "kept" }));
            let production = dispatch_headers(
                &task,
                "queue:demo-us-central1-q",
                1,
                0,
                None,
                1_700_000_000_123,
                DispatchShape::Production { queue: "q" },
            );
            if name.to_ascii_lowercase().starts_with("x-cloudtasks-") {
                // Recorded: the task's header reaches the function in front of the service's, so the function sees
                // both (Node joins them as `<task's>, <service's>`).
                let values: Vec<&str> = production
                    .iter()
                    .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.as_str())
                    .collect();
                assert_eq!(values.len(), 2, "{name}: the task's and the service's");
                assert_eq!(values[0], value, "{name}: the task's value comes first");
                assert_ne!(values[1], value, "{name}: the service's value follows");
            } else {
                assert_eq!(
                    count(&production, name),
                    1,
                    "{name}: one header of that name in production"
                );
                assert!(
                    production.iter().all(|(_, v)| v != value),
                    "{name}: the task's value is not delivered in production"
                );
            }
            assert_eq!(header(&production, "X-Custom"), Some("kept"), "{name}");
            let official = dispatch_headers(
                &task,
                "queue:demo-us-central1-q",
                1,
                0,
                None,
                1_700_000_000_123,
                DispatchShape::Official,
            );
            assert_eq!(
                count(&official, name),
                1,
                "{name}: one header of that name in the official shape"
            );
            assert_eq!(
                header(&official, name),
                Some(value),
                "{name}: the task's value wins there"
            );
        }
    }

    #[test]
    fn the_production_shape_values_are_the_services_when_the_task_names_the_same_headers() {
        let task = with_task_headers(json!({
            "User-Agent": "custom/1",
            "X-CloudTasks-QueueName": "other",
            "X-CloudTasks-TaskETA": "soon",
            "X-CloudTasks-TaskRetryCount": "9",
        }));
        let headers = dispatch_headers(
            &task,
            "queue:demo-us-central1-q",
            3,
            2,
            None,
            1_700_000_000_123,
            DispatchShape::Production { queue: "q" },
        );
        // The service's value is the last of the header's lines (a task's own comes in front of it).
        let last = |name: &str| {
            headers
                .iter()
                .rev()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(header(&headers, "User-Agent"), Some("Google-Cloud-Tasks"));
        assert_eq!(last("X-CloudTasks-QueueName"), Some("q"));
        assert_eq!(last("X-CloudTasks-TaskETA"), Some("1700000000.123000"));
        assert_eq!(last("X-CloudTasks-TaskRetryCount"), Some("2"));
    }

    /// UNRECORDED: the documentation lists `X-CloudTasks-TaskPreviousResponse` as present only after
    /// a failed attempt, so a task cannot make it appear on the first one.
    #[test]
    fn a_task_cannot_add_the_previous_response_header_in_production() {
        let task = with_task_headers(json!({"X-CloudTasks-TaskPreviousResponse": "500"}));
        let first = dispatch_headers(
            &task,
            "k",
            1,
            0,
            None,
            1,
            DispatchShape::Production { queue: "q" },
        );
        // Only the task's own header is there (the service sends none on a first delivery).
        assert_eq!(
            header(&first, "X-CloudTasks-TaskPreviousResponse"),
            Some("500")
        );
        assert_eq!(count(&first, "X-CloudTasks-TaskPreviousResponse"), 1);
        let retried = dispatch_headers(
            &task,
            "k",
            2,
            1,
            Some(503),
            1,
            DispatchShape::Production { queue: "q" },
        );
        let previous: Vec<&str> = retried
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("X-CloudTasks-TaskPreviousResponse"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(
            previous,
            ["500", "503"],
            "the task's value in front of the service's"
        );
        let official = dispatch_headers(&task, "k", 1, 0, None, 1, DispatchShape::Official);
        assert_eq!(
            header(&official, "X-CloudTasks-TaskPreviousResponse"),
            Some("500")
        );
    }

    /// UNRECORDED: documented as "Google use only" and ignored or replaced.
    #[test]
    fn google_use_only_headers_of_a_task_are_dropped_in_production_only() {
        let task = with_task_headers(json!({
            "X-Google-Thing": "a", "x-appengine-thing": "b", "X-GoogleFoo": "kept", "Content-Type": "text/plain"
        }));
        let production = dispatch_headers(
            &task,
            "k",
            1,
            0,
            None,
            1,
            DispatchShape::Production { queue: "q" },
        );
        assert_eq!(header(&production, "X-Google-Thing"), None);
        assert_eq!(header(&production, "X-AppEngine-Thing"), None);
        assert_eq!(header(&production, "X-GoogleFoo"), Some("kept"));
        // Content-Type "won't be set by Cloud Tasks": the task's own is delivered.
        assert_eq!(header(&production, "Content-Type"), Some("text/plain"));
        assert_eq!(count(&production, "Content-Type"), 1);
        let official = dispatch_headers(&task, "k", 1, 0, None, 1, DispatchShape::Official);
        assert_eq!(header(&official, "X-Google-Thing"), Some("a"));
        assert_eq!(header(&official, "X-AppEngine-Thing"), Some("b"));
    }

    /// The official backoff formula and stop condition, with the official defaults.
    #[test]
    fn the_backoff_doubles_to_its_ceiling_and_attempts_alone_stop_the_default_queue() {
        let retry = TaskRetryConfig::default();
        assert_eq!(retry.backoff_millis(1), 100);
        assert_eq!(retry.backoff_millis(2), 200);
        assert_eq!(retry.backoff_millis(3), 400);
        // 2^16 doublings of 100 ms is well past the one-hour ceiling.
        assert_eq!(retry.backoff_millis(40), retry.max_backoff_millis);

        assert!(!retry.exhausted(3, 0));
        assert!(retry.exhausted(4, 0));

        // A positive maxRetrySeconds keeps a task retrying past maxAttempts until the clock
        // runs out, which is the one case where the attempt count is not the whole story.
        let budgeted = TaskRetryConfig {
            max_retry_millis: Some(5_000),
            ..TaskRetryConfig::default()
        };
        assert!(!budgeted.exhausted(9, 4_000));
        assert!(budgeted.exhausted(9, 6_000));
    }

    #[test]
    fn production_sends_an_empty_retry_reason_from_the_second_delivery_on_and_the_official_emulator_never(
    ) {
        let task = accept(
            "demo",
            "us-central1",
            "onJob",
            "http://127.0.0.1:5001/demo/us-central1/onJob",
            &enqueue_body(),
            7,
        )
        .expect("accepted");
        let reason = |attempt: u32, shape: DispatchShape<'_>| {
            dispatch_headers(
                &task,
                "queue:demo-us-central1-onJob",
                attempt,
                attempt - 1,
                None,
                1_700_000_000_000,
                shape,
            )
            .into_iter()
            .find(|(k, _)| k == "X-CloudTasks-TaskRetryReason")
            .map(|(_, v)| v)
        };
        let production = || DispatchShape::Production { queue: "onJob" };
        assert_eq!(reason(1, production()), None);
        assert_eq!(reason(2, production()), Some(String::new()));
        assert_eq!(reason(3, production()), Some(String::new()));
        for attempt in 1..=3 {
            assert_eq!(reason(attempt, DispatchShape::Official), None, "{attempt}");
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn production_delivers_the_identity_token_a_task_asked_for_as_a_three_segment_bearer() {
        let body = json!({"task": {"httpRequest": {
            "url": "", "body": "e30=",
            "headers": {"Authorization": "Bearer forged", "X-Own": "1", "X-Fireemu-Task-Identity": "1"},
            "oidcToken": {"serviceAccountEmail": "sa@example.test", "audience": "https://aud.example.test"},
        }}});
        let task = accept(
            "demo",
            "us-central1",
            "onJob",
            "http://127.0.0.1:5001/demo/us-central1/onJob",
            &body,
            7,
        )
        .expect("accepted");
        assert_eq!(
            task.oidc,
            Some(TaskOidc {
                service_account_email: "sa@example.test".to_owned(),
                audience: "https://aud.example.test".to_owned()
            })
        );
        let headers = |shape: DispatchShape<'_>, task: &Task| {
            dispatch_headers(
                task,
                "queue:demo-us-central1-onJob",
                1,
                0,
                None,
                1_700_000_000_000,
                shape,
            )
        };
        let production = headers(DispatchShape::Production { queue: "onJob" }, &task);
        assert_eq!(
            production
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(TASK_IDENTITY_HEADER))
                .map(|(_, v)| v.as_str())
                .collect::<Vec<_>>(),
            ["1"]
        );
        let authorization: Vec<&str> = production
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(authorization.len(), 1, "the task's own header is replaced");
        let token = authorization[0].strip_prefix("Bearer ").expect("a Bearer");
        assert_eq!(token.split('.').count(), 3);
        let claims = fireemu_core_auth::jwt::decode_unsigned(token).expect("decodes");
        assert_eq!(claims.sub().map(str::len), Some(20));
        // The subject is a stable number of the identity: not zero, the same for the same account, another for another one.
        let subject = |email: &str| {
            let other = TaskOidc {
                service_account_email: email.to_owned(),
                audience: "a".to_owned(),
            };
            let token = oidc_authorization(&other, 1_700_000_000_000);
            let payload = fireemu_core_auth::jwt::base64url_decode(
                token
                    .strip_prefix("Bearer ")
                    .unwrap()
                    .split('.')
                    .nth(1)
                    .unwrap(),
            )
            .unwrap();
            serde_json::from_slice::<Value>(&payload).unwrap()["sub"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        assert_eq!(subject("sa@example.test"), subject("sa@example.test"));
        assert_ne!(subject("sa@example.test"), subject("other@example.test"));
        assert_ne!(subject("sa@example.test"), "0".repeat(20));
        assert!(subject("sa@example.test")
            .bytes()
            .all(|b| b.is_ascii_digit()));
        assert!(
            subject("sa@example.test")
                .chars()
                .take(10)
                .any(|c| c != '0'),
            "a hash, not a small number"
        );
        let payload =
            fireemu_core_auth::jwt::base64url_decode(token.split('.').nth(1).unwrap()).unwrap();
        let payload: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload["aud"], "https://aud.example.test");
        assert_eq!(payload["email"], "sa@example.test");
        assert_eq!(payload["iss"], "https://accounts.google.com");
        assert_eq!(payload["iat"], 1_700_000_000_u64);
        assert_eq!(payload["exp"], 1_700_003_600_u64);
        assert!(production.iter().any(|(k, v)| k == "X-Own" && v == "1"));
        // The official emulator keeps the task's own header and adds none.
        let official = headers(DispatchShape::Official, &task);
        assert!(!official
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(TASK_IDENTITY_HEADER)));
        let official: Vec<&str> = official
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(official, ["Bearer forged"]);
        // A task that named no identity gets no Authorization header from Cloud Tasks.
        let mut anonymous = task.clone();
        anonymous.oidc = None;
        anonymous.headers.remove("Authorization");
        anonymous
            .headers
            .insert("X-Fireemu-Task-Identity".to_owned(), "1".to_owned());
        let production = headers(DispatchShape::Production { queue: "onJob" }, &anonymous);
        assert!(!production
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("authorization")));
        assert!(!production
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(TASK_IDENTITY_HEADER)));
        let official_anonymous = headers(DispatchShape::Official, &anonymous);
        assert!(!official_anonymous
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(TASK_IDENTITY_HEADER)));
        // No audience: the URL.
        let body = json!({"task": {"httpRequest": {"url": "", "body": "e30=", "oidcToken": {"serviceAccountEmail": "sa@example.test"}}}});
        let task = accept(
            "demo",
            "us-central1",
            "onJob",
            "http://127.0.0.1:5001/demo/us-central1/onJob",
            &body,
            8,
        )
        .unwrap();
        assert_eq!(
            task.oidc.unwrap().audience,
            "http://127.0.0.1:5001/demo/us-central1/onJob"
        );
    }
}
