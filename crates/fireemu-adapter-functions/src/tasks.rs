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
    /// `scheduleTime`, echoed into `X-CloudTasks-TaskETA`. It does **not** delay dispatch:
    /// nothing in the official `dispatchTasks` or `runTask` consults it either.
    pub schedule_time: Option<String>,
    /// The abort deadline, in seconds; `dispatchDeadline` without its trailing `s`, else 60.
    pub dispatch_deadline_seconds: u64,
}

impl Task {
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

/// The route a functions-port path names, if it is one of the Cloud Tasks routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
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

/// Classifies a path against the three Cloud Tasks routes.
#[must_use]
pub fn route(path: &str) -> Option<Route> {
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
    let body: Value = serde_json::from_slice(&decoded).map_err(|e| EnqueueRefusal {
        status: 400,
        body: format!("the task's httpRequest body is not JSON: {e}"),
    })?;
    let mut headers = BTreeMap::new();
    if let Some(map) = http.get("headers").and_then(Value::as_object) {
        for (k, v) in map {
            if let Some(v) = v.as_str() {
                headers.insert(k.clone(), v.to_owned());
            }
        }
    }
    let dispatch_deadline_seconds = task
        .get("dispatchDeadline")
        .and_then(Value::as_str)
        .and_then(|d| d.trim_end_matches('s').parse::<u64>().ok())
        .unwrap_or(60);
    Ok(Task {
        name,
        url,
        headers,
        body,
        schedule_time: task
            .get("scheduleTime")
            .and_then(Value::as_str)
            .map(str::to_owned),
        dispatch_deadline_seconds,
    })
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
) -> Vec<(String, String)> {
    let mut out = vec![
        ("Content-Type".to_owned(), "application/json".to_owned()),
        ("X-CloudTasks-QueueName".to_owned(), queue_key.to_owned()),
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
        (
            "X-CloudTasks-TaskETA".to_owned(),
            task.schedule_time
                .clone()
                .unwrap_or_else(|| now_millis.to_string()),
        ),
    ];
    if let Some(status) = previous_response {
        out.push((
            "X-CloudTasks-TaskPreviousResponse".to_owned(),
            status.to_string(),
        ));
    }
    for (k, v) in &task.headers {
        out.retain(|(existing, _)| !existing.eq_ignore_ascii_case(k));
        out.push((k.clone(), v.clone()));
    }
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
    use super::{accept, dispatch_headers, queue_key, route, Route};
    use fireemu_core_functions::manifest::TaskRetryConfig;
    use serde_json::json;

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
    fn the_three_routes_are_told_apart_and_a_function_url_is_not_one() {
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
}
