//! The strict profile's createTask and deleteTask through the runtime: production's answers and refusals (recorded on
//! 2026-11-11, TASK-QUEUE-FUNCTIONS runs 47574c and b01fa6), the name reuse rules, and the emulator profile unchanged.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_functions::application_clock::ApplicationClockPolicy;
use fireemu_adapter_functions::http::FunctionsHttpProfile;
use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{CodebaseSpec, FunctionsConfig, FunctionsRuntime};
use fireemu_adapter_functions::tasks_production::NameReuse;
use fireemu_core_functions::manifest::{TaskRateLimits, TaskRetryConfig, Trigger};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

struct Harness {
    runtime: Arc<FunctionsRuntime>,
    dir: std::path::PathBuf,
    clock: Arc<Mutex<VirtualClock>>,
    probe: std::path::PathBuf,
    log: std::path::PathBuf,
}

async fn start(
    name: &str,
    profile: FunctionsHttpProfile,
    reuse: NameReuse,
    deadline: u64,
) -> Harness {
    start_full(name, profile, reuse, deadline, retry(1, 500), false, false).await
}

/// A retry configuration with the official defaults but for the attempts and the minimum backoff.
fn retry(max_attempts: u32, min_backoff_millis: u64) -> TaskRetryConfig {
    TaskRetryConfig {
        max_attempts,
        min_backoff_millis,
        ..TaskRetryConfig::default()
    }
}

/// `probe` makes the fake runner record every delivery of a task queue in `entries` (a task whose name holds `failing`
/// answers 500) and hold the others until `entries.taskA.release` exists; `virtual_tasks` moves task time only with
/// the test's clock.
async fn start_full(
    name: &str,
    profile: FunctionsHttpProfile,
    reuse: NameReuse,
    deadline: u64,
    retry: TaskRetryConfig,
    virtual_tasks: bool,
    production_gaps: bool,
) -> Harness {
    let dir =
        std::env::temp_dir().join(format!("fireemu-task-shape-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("requests");
    let probe = dir.join("entries");
    std::fs::write(dir.join("entries.taskA.release"), "").unwrap();
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: vec![
            (
                "FIREEMU_FAKE_REQUEST_LOG".to_owned(),
                log.display().to_string(),
            ),
            (
                "FIREEMU_FAKE_TASK_PROBE".to_owned(),
                probe.display().to_string(),
            ),
        ],
        hello_timeout: Duration::from_secs(60),
    };
    let runner = Runner::spawn_spec(&spec)
        .await
        .expect("the fake runner starts");
    let mut manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
    let mut function = manifest.get("echo").unwrap().clone();
    "taskA".clone_into(&mut function.name);
    "taskA".clone_into(&mut function.entry_point);
    function.trigger = Trigger::TaskQueue {
        retry,
        rate_limits: TaskRateLimits {
            max_concurrent_dispatches: 1,
            max_dispatches_per_second: 500.0,
        },
    };
    manifest.functions.push(function);
    let clock = Arc::new(Mutex::new(VirtualClock::new(START)));
    let runtime = FunctionsRuntime::with_codebases(
        vec![CodebaseSpec {
            name: "default".to_owned(),
            manifest,
            runner: Arc::new(runner),
            spawn: Some(spec),
            cleanup_dir: None,
        }],
        FunctionsConfig {
            project: "demo-app".into(),
            functions_host: Some("127.0.0.1:5001".into()),
            clock_policy: ApplicationClockPolicy {
                tasks_virtual: virtual_tasks,
                ..ApplicationClockPolicy::default()
            },
            honour_task_schedule_time: true,
            task_name_reuse: reuse,
            task_default_deadline_seconds: deadline,
            task_retry_production_gaps: production_gaps,
            ..FunctionsConfig::for_tests(1, "runner-secret".into())
        },
        clock.clone(),
        profile,
    )
    .expect("one codebase");
    tokio::spawn(runtime.clone().dispatch_loop());
    Harness {
        runtime,
        dir,
        clock,
        probe,
        log,
    }
}

impl Harness {
    async fn stop(self) {
        self.runtime.shutdown().await;
        let _ = std::fs::remove_dir_all(self.dir);
    }

    async fn idle(&self) {
        tokio::time::timeout(Duration::from_secs(6), async {
            while !self.runtime.is_idle() {
                self.runtime.idle_notify().notified().await;
            }
        })
        .await
        .expect("the task queue became idle");
    }
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

const BASE: &str = "projects/demo-app/locations/us-central1/queues/taskA";

fn body_of(extra: &Value) -> Value {
    let mut task = json!({"httpRequest": {"url": "", "body": base64(br#"{"data":{"a":1}}"#), "headers": {"Content-Type": "application/json"}}});
    for (key, value) in extra.as_object().unwrap() {
        task[key] = value.clone();
    }
    json!({"task": task})
}

fn refusal(h: &Harness, body: &Value) -> (u16, Value) {
    let refusal = h
        .runtime
        .enqueue_task("demo-app", "us-central1", "taskA", body)
        .expect_err("refused");
    (
        refusal.status,
        serde_json::from_str(&refusal.body).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn the_strict_profile_answers_with_the_task_and_refuses_in_production_s_words() {
    let h = start(
        "strict-answers",
        FunctionsHttpProfile::Strict,
        NameReuse::Immediate,
        600,
    )
    .await;
    let answer = h
        .runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &body_of(&json!({})))
        .unwrap();
    // The Task itself, not wrapped; no body in the BASIC view; a generated name of 19 digits.
    let name = answer["name"].as_str().unwrap();
    let id = name.strip_prefix(&format!("{BASE}/tasks/")).unwrap();
    assert_eq!(
        (id.len(), id.bytes().all(|b| b.is_ascii_digit())),
        (19, true)
    );
    assert_eq!(answer["view"], "BASIC");
    assert_eq!(answer["dispatchDeadline"], "600s");
    assert!(answer["httpRequest"].get("body").is_none());
    assert_eq!(
        answer["httpRequest"]["headers"]["User-Agent"],
        "Google-Cloud-Tasks"
    );
    assert!(answer["createTime"].as_str().unwrap().ends_with('Z'));
    h.idle().await;
    let (status, error) = refusal(&h, &body_of(&json!({"dispatchDeadline": "14s"})));
    assert_eq!(status, 400);
    assert_eq!(error["error"]["status"], "INVALID_ARGUMENT");
    assert_eq!(
        error["error"]["message"],
        "Task.dispatchDeadline must be between [15s, 30m]."
    );
    let (status, error) = refusal(&h, &body_of(&json!({"name": format!("{BASE}/tasks/a b")})));
    assert_eq!(status, 400);
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("Task ID \"a b\" can contain only letters"));
    let (status, error) = refusal(&h, &json!({}));
    assert_eq!(
        (status, error["error"]["message"].as_str()),
        (400, Some("Task.payload_type is not set."))
    );
    let missing = h
        .runtime
        .enqueue_task("demo-app", "us-central1", "nope", &body_of(&json!({})))
        .expect_err("no queue");
    assert_eq!(missing.status, 404);
    assert!(missing.body.contains("Queue does not exist"));
    h.stop().await;
}

#[tokio::test]
async fn a_live_task_name_is_taken_and_deleting_the_pending_task_releases_it_by_the_reuse_rule() {
    let scheduled =
        json!({"name": format!("{BASE}/tasks/held"), "scheduleTime": "2099-01-01T00:00:00Z"});
    // Too far ahead to hold: 720h is the horizon, so hold it a week out.
    let week = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let at = now + 7 * 86_400;
        let days = i64::try_from(at / 86_400).unwrap();
        let (y, m, d) = civil(days);
        format!("{y:04}-{m:02}-{d:02}T00:00:00Z")
    };
    let _ = scheduled;
    let held = json!({"name": format!("{BASE}/tasks/held"), "scheduleTime": week});
    for (reuse, after_delete) in [
        (NameReuse::Immediate, 200_u16),
        (NameReuse::Window(Duration::from_secs(3600)), 409),
    ] {
        let h = start("strict-held", FunctionsHttpProfile::Strict, reuse, 600).await;
        h.runtime
            .enqueue_task("demo-app", "us-central1", "taskA", &body_of(&held))
            .unwrap();
        let (status, error) = refusal(&h, &body_of(&held));
        assert_eq!(
            (status, error["error"]["message"].as_str()),
            (409, Some("Requested entity already exists"))
        );
        h.runtime
            .delete_task_strict("demo-app", "us-central1", "taskA", "held")
            .unwrap();
        let again = h
            .runtime
            .delete_task_strict("demo-app", "us-central1", "taskA", "held")
            .expect_err("gone");
        assert_eq!(again.status, 404);
        assert!(again.body.contains("Requested entity was not found."));
        match h
            .runtime
            .enqueue_task("demo-app", "us-central1", "taskA", &body_of(&held))
        {
            Ok(_) => assert_eq!(after_delete, 200),
            Err(e) => {
                assert_eq!(after_delete, 409);
                assert!(e.body.contains("existed too recently"), "{}", e.body);
            }
        }
        h.stop().await;
    }
}

fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[tokio::test]
async fn a_finished_task_name_is_free_at_once_by_default_and_taken_inside_the_production_window() {
    for (reuse, second_accepted) in [
        (NameReuse::Immediate, true),
        (NameReuse::Window(Duration::from_secs(3600)), false),
    ] {
        let h = start("strict-finished", FunctionsHttpProfile::Strict, reuse, 600).await;
        let task = json!({"name": format!("{BASE}/tasks/once")});
        h.runtime
            .enqueue_task("demo-app", "us-central1", "taskA", &body_of(&task))
            .unwrap();
        h.idle().await;
        let second = h
            .runtime
            .enqueue_task("demo-app", "us-central1", "taskA", &body_of(&task));
        assert_eq!(second.is_ok(), second_accepted, "{reuse:?}");
        if let Err(e) = second {
            assert_eq!(e.status, 409);
            assert!(e.body.contains("existed too recently"));
        }
        h.stop().await;
    }
}

#[tokio::test]
async fn the_dispatch_deadline_a_task_names_none_of_is_the_configured_default() {
    for (configured, text) in [(600_u64, "600s"), (60, "60s")] {
        let h = start(
            "strict-deadline",
            FunctionsHttpProfile::Strict,
            NameReuse::Immediate,
            configured,
        )
        .await;
        let answer = h
            .runtime
            .enqueue_task(
                "demo-app",
                "us-central1",
                "taskA",
                &body_of(&json!({"dispatchDeadline": "0s"})),
            )
            .unwrap();
        assert_eq!(answer["dispatchDeadline"], text);
        h.stop().await;
    }
}

#[tokio::test]
async fn the_emulator_profile_keeps_the_official_answers_and_plain_text_refusals() {
    let h = start(
        "emulator-answers",
        FunctionsHttpProfile::Emulator,
        NameReuse::Retained,
        60,
    )
    .await;
    let task = json!({"name": format!("{BASE}/tasks/mine")});
    let answer = h
        .runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &body_of(&task))
        .unwrap();
    assert!(
        answer.get("task").is_some(),
        "the official answer wraps the task"
    );
    h.idle().await;
    let second = h
        .runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &body_of(&task))
        .expect_err("kept forever");
    assert_eq!(second.status, 409);
    assert_eq!(second.body, "A task with the same name already exists");
    let odd = h.runtime.enqueue_task(
        "demo-app",
        "us-central1",
        "taskA",
        &body_of(&json!({"dispatchDeadline": "14s"})),
    );
    assert!(odd.is_ok(), "the official emulator takes any deadline");
    h.stop().await;
}

// ---- through the Tasks listener ----------------------------------------------------------------------------------------

/// One HTTP/1.1 request to the Tasks listener: the status, the head and the body.
async fn wire(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
) -> (u16, String, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let _ = stream.write_all(body).await;
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw).await;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // A chunked body is joined without its sizes only for the short answers these tests read.
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        let mut out = String::new();
        let mut rest = body;
        while let Some((size, tail)) = rest.split_once("\r\n") {
            let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
            if n == 0 || tail.len() < n {
                break;
            }
            out.push_str(&tail[..n]);
            rest = tail[n..].trim_start_matches("\r\n");
        }
        out
    } else {
        body.to_owned()
    };
    (status, head.to_owned(), body)
}

async fn tasks_listener(
    h: &Harness,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(fireemu_adapter_functions::http::serve_tasks(
        listener,
        h.runtime.clone(),
        fireemu_adapter_functions::http::HttpAdmission::new(),
    ));
    (addr, server)
}

/// A JSON text of exactly `bytes` bytes.
fn json_of_size(bytes: usize) -> String {
    format!("{{\"data\":\"{}\"}}", "x".repeat(bytes - 11))
}

const TASKS: &str = "/projects/demo-app/locations/us-central1/queues/taskA/tasks";

#[tokio::test]
async fn the_strict_listener_answers_json_in_both_directions_and_reads_a_task_of_a_mebibyte() {
    let h = start(
        "strict-wire",
        FunctionsHttpProfile::Strict,
        NameReuse::Immediate,
        600,
    )
    .await;
    let (addr, server) = tasks_listener(&h).await;
    let ok = body_of(&json!({"name": format!("{BASE}/tasks/wire-a")}));
    let (status, head, body) = wire(addr, "POST", TASKS, ok.to_string().as_bytes()).await;
    assert_eq!(status, 200, "{head} {body}");
    let answer: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(answer["name"], format!("{BASE}/tasks/wire-a"));
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: application/json; charset=utf-8"),
        "{head}"
    );
    // Production's layout: multi-line JSON, two-space indentation, the proto field order, a newline at the end.
    assert!(
        body.starts_with(&format!(
            "{{\n  \"name\": \"{BASE}/tasks/wire-a\",\n  \"httpRequest\": {{\n    \"url\": "
        )),
        "{body}"
    );
    assert!(body.ends_with("\n  \"view\": \"BASIC\"\n}\n"), "{body}");
    // A refusal is production's JSON, with the JSON content type.
    let bad = body_of(&json!({"dispatchDeadline": "14s"}));
    let (status, head, body) = wire(addr, "POST", TASKS, bad.to_string().as_bytes()).await;
    assert_eq!(status, 400);
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: application/json; charset=utf-8"),
        "{head}"
    );
    assert_eq!(
        body,
        "{\n  \"error\": {\n    \"code\": 400,\n    \"message\": \"Task.dispatchDeadline must be between [15s, 30m].\",\n    \"status\": \"INVALID_ARGUMENT\"\n  }\n}\n"
    );
    // A request over the official emulator's 100 KiB JSON limit is still read: a task may be up to 1 MiB.
    let big = body_of(&json!({"name": format!("{BASE}/tasks/wire-big")}));
    let mut big = big;
    big["task"]["httpRequest"]["body"] = json!(base64(json_of_size(150_000).as_bytes()));
    let (status, _, body) = wire(addr, "POST", TASKS, big.to_string().as_bytes()).await;
    assert_eq!(status, 200, "{body}");
    // A request a little over a mebibyte is read in full too, and the admission answers for the task: it is too large.
    let mut over = body_of(&json!({"name": format!("{BASE}/tasks/wire-over")}));
    over["task"]["httpRequest"]["body"] = json!(base64(json_of_size(1_500_000).as_bytes()));
    let (status, _, body) = wire(addr, "POST", TASKS, over.to_string().as_bytes()).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("Task size too large"), "{body}");
    // The request itself is bounded: a few mebibytes are refused before they are read in full.
    let mut huge = body_of(&json!({"name": format!("{BASE}/tasks/wire-huge")}));
    huge["task"]["httpRequest"]["body"] = json!(base64(json_of_size(3_500_000).as_bytes()));
    let (status, _, _) = wire(addr, "POST", TASKS, huge.to_string().as_bytes()).await;
    assert_eq!(status, 413);
    server.abort();
    h.stop().await;
}

#[tokio::test]
async fn the_strict_listener_deletes_with_json_and_refuses_other_methods() {
    let h = start(
        "strict-wire-delete",
        FunctionsHttpProfile::Strict,
        NameReuse::Immediate,
        600,
    )
    .await;
    let (addr, server) = tasks_listener(&h).await;
    let week = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (y, m, d) = civil(i64::try_from((now + 7 * 86_400) / 86_400).unwrap());
        format!("{y:04}-{m:02}-{d:02}T00:00:00Z")
    };
    let queued = body_of(&json!({"name": format!("{BASE}/tasks/wire-del"), "scheduleTime": week}));
    assert_eq!(
        wire(addr, "POST", TASKS, queued.to_string().as_bytes())
            .await
            .0,
        200
    );
    let path = format!("{TASKS}/wire-del");
    assert_eq!(wire(addr, "GET", &path, b"").await.0, 405);
    assert_eq!(wire(addr, "PUT", &path, b"").await.0, 405);
    assert_eq!(wire(addr, "POST", &path, b"{}").await.0, 405);
    let (status, head, body) = wire(addr, "DELETE", &path, b"").await;
    assert_eq!((status, body.as_str()), (200, "{}\n"));
    assert!(head
        .to_ascii_lowercase()
        .contains("content-type: application/json; charset=utf-8"));
    let (status, head, body) = wire(addr, "DELETE", &path, b"").await;
    assert_eq!(status, 404);
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: application/json; charset=utf-8"),
        "{head}"
    );
    assert_eq!(
        body,
        "{\n  \"error\": {\n    \"code\": 404,\n    \"message\": \"Requested entity was not found.\",\n    \"status\": \"NOT_FOUND\"\n  }\n}\n"
    );
    server.abort();
    h.stop().await;
}

#[tokio::test]
async fn the_emulator_listener_keeps_plain_text_refusals_and_the_hundred_kibibyte_limit() {
    let h = start(
        "emulator-wire",
        FunctionsHttpProfile::Emulator,
        NameReuse::Retained,
        60,
    )
    .await;
    let (addr, server) = tasks_listener(&h).await;
    let ok = body_of(&json!({"name": format!("{BASE}/tasks/wire-e")}));
    let (status, head, body) = wire(addr, "POST", TASKS, ok.to_string().as_bytes()).await;
    assert_eq!(status, 200, "{body}");
    // The emulator profile answers as it always has: the task wrapped, compact JSON, the plain JSON content type.
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: application/json\r\n"),
        "{head}"
    );
    assert!(!body.contains('\n') && body.starts_with("{\""), "{body}");
    assert!(serde_json::from_str::<Value>(&body)
        .unwrap()
        .get("task")
        .is_some());
    h.idle().await;
    let (status, head, body) = wire(addr, "POST", TASKS, ok.to_string().as_bytes()).await;
    assert_eq!(status, 409);
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: text/plain"),
        "{head}"
    );
    assert_eq!(body, "A task with the same name already exists");
    let mut big = ok.clone();
    big["task"]["name"] = json!(format!("{BASE}/tasks/wire-e2"));
    big["task"]["httpRequest"]["body"] = json!(base64(json_of_size(150_000).as_bytes()));
    assert_eq!(
        wire(addr, "POST", TASKS, big.to_string().as_bytes())
            .await
            .0,
        413
    );
    for method in ["GET", "PUT", "POST", "PATCH"] {
        let (status, head, body) = wire(addr, method, &format!("{TASKS}/never-was"), b"").await;
        assert_eq!(status, 404, "{method}");
        assert_eq!(
            body, format!("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot {method} {TASKS}/never-was</pre>\n</body>\n</html>\n"),
            "{method}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("content-type: text/html; charset=utf-8"),
            "{head}"
        );
    }
    let (status, head, _) = wire(addr, "DELETE", &format!("{TASKS}/never-was"), b"").await;
    assert_eq!(status, 404);
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: text/plain"),
        "{head}"
    );
    server.abort();
    h.stop().await;
}

#[tokio::test]
async fn emulator_delete_removes_a_pending_task_before_dispatch() {
    let h = start_full(
        "emulator-delete",
        FunctionsHttpProfile::Emulator,
        NameReuse::Retained,
        60,
        retry(1, 500),
        true,
        false,
    )
    .await;
    let (addr, server) = tasks_listener(&h).await;
    let due = LogicalInstant::from_unix_seconds(1_788_004_920)
        .to_rfc3339()
        .unwrap();
    let queued = body_of(&json!({"name": format!("{BASE}/tasks/delete-me"), "scheduleTime": due}));
    assert_eq!(
        wire(addr, "POST", TASKS, queued.to_string().as_bytes())
            .await
            .0,
        200
    );
    assert_eq!(h.runtime.pending_tasks().len(), 1);
    let path = format!("{TASKS}/delete-me");
    for method in ["GET", "PUT"] {
        let (status, head, body) = wire(addr, method, &path, b"").await;
        assert_eq!(status, 404);
        assert!(head
            .to_ascii_lowercase()
            .contains("content-type: text/html; charset=utf-8"));
        assert!(body.contains(&format!("Cannot {method} {path}")));
        assert_eq!(h.runtime.pending_tasks().len(), 1);
    }
    let (status, head, body) = wire(addr, "DELETE", &path, b"").await;
    assert_eq!((status, body.as_str()), (200, "{\"res\":\"OK\"}"));
    assert!(head
        .to_ascii_lowercase()
        .contains("content-type: application/json; charset=utf-8"));
    assert!(h.runtime.pending_tasks().is_empty());
    assert_eq!(h.runtime.run_tasks_now("taskA", None), 0);
    h.idle().await;
    assert!(!h.probe.exists() || std::fs::read_to_string(&h.probe).unwrap().is_empty());
    let (status, _, body) = wire(addr, "DELETE", &path, b"").await;
    assert_eq!(
        (status, body.as_str()),
        (404, "Tried to remove a task that doesn't exist")
    );
    server.abort();
    h.stop().await;
}

// ---- the checks of the queue and of the size, and the pieces of the dispatch that differ in the strict profile ------------

fn refused(
    result: Result<Value, fireemu_adapter_functions::tasks::EnqueueRefusal>,
) -> (u16, String) {
    let refusal = result.expect_err("refused");
    (refusal.status, refusal.body)
}

#[tokio::test]
async fn the_strict_profile_refuses_a_queue_that_is_not_served_here() {
    let h = start(
        "strict-queue",
        FunctionsHttpProfile::Strict,
        NameReuse::Immediate,
        600,
    )
    .await;
    let body = body_of(&json!({}));
    // Another location, another project, a function that is not a queue, and a queue that does not exist.
    for (project, location, queue) in [
        ("demo-app", "europe-west1", "taskA"),
        ("other-project", "us-central1", "taskA"),
        ("demo-app", "us-central1", "echo"),
        ("demo-app", "us-central1", "missing"),
    ] {
        let (status, text) = refused(h.runtime.enqueue_task(project, location, queue, &body));
        assert_eq!(status, 404, "{project} {location} {queue}");
        assert!(text.contains("Queue does not exist"), "{text}");
        let (status, text) = refused(
            h.runtime
                .delete_task_strict(project, location, queue, "x")
                .map(|()| json!({})),
        );
        assert_eq!(status, 404, "{project} {location} {queue}");
        assert!(text.contains("Queue does not exist"), "{text}");
    }
    h.stop().await;
}

#[tokio::test]
async fn the_task_size_counts_the_decoded_body_and_the_headers_against_one_mebibyte() {
    let h = start(
        "strict-size",
        FunctionsHttpProfile::Strict,
        NameReuse::Immediate,
        600,
    )
    .await;
    let sized = |bytes: usize, header: Option<(&str, &str)>| {
        let mut task = body_of(&json!({}));
        task["task"]["httpRequest"]["body"] = json!(base64(json_of_size(bytes).as_bytes()));
        if let Some((key, value)) = header {
            task["task"]["httpRequest"]["headers"][key] = json!(value);
        }
        task
    };
    let enqueue = |task: &Value| {
        h.runtime
            .enqueue_task("demo-app", "us-central1", "taskA", task)
    };
    // The base task carries the header `Content-Type: application/json` (28 bytes of name and value); a body of
    // 1,048,548 bytes (a whole number of base64 groups) brings the task to exactly one mebibyte, which is accepted.
    let exact = 1_048_548_usize;
    let first = enqueue(&sized(exact, None));
    assert!(first.is_ok(), "{:?}", first.err().map(|e| e.body));
    let (status, text) = refused(enqueue(&sized(exact + 3, None)));
    assert_eq!((status, text.contains("Task size too large")), (400, true));
    // Headers count their names and values: three bytes of room are left, and a header of three fits, one of four does not.
    assert!(enqueue(&sized(exact - 3, Some(("abc", "")))).is_ok());
    let (status, text) = refused(enqueue(&sized(exact - 3, Some(("abc", "d")))));
    assert_eq!((status, text.contains("Task size too large")), (400, true));
    h.stop().await;
}

#[test]
fn the_configuration_names_its_task_settings_in_its_debug_form() {
    let text = format!("{:?}", FunctionsConfig::for_tests(1, "s".into()));
    assert!(text.contains("task_name_reuse"), "{text}");
    assert!(text.contains("task_default_deadline_seconds"), "{text}");
}

#[tokio::test]
async fn two_tasks_without_a_name_in_the_same_instant_get_two_names() {
    let h = start_full(
        "strict-ids",
        FunctionsHttpProfile::Strict,
        NameReuse::Immediate,
        600,
        retry(1, 500),
        true,
        false,
    )
    .await;
    let mut names = std::collections::BTreeSet::new();
    for _ in 0..5 {
        let answer = h
            .runtime
            .enqueue_task("demo-app", "us-central1", "taskA", &body_of(&json!({})))
            .unwrap();
        assert!(
            names.insert(answer["name"].as_str().unwrap().to_owned()),
            "a name was given twice"
        );
    }
    h.stop().await;
}

#[tokio::test]
async fn a_finished_name_is_held_for_exactly_the_window_on_the_virtual_clock() {
    let h = start_full(
        "strict-window",
        FunctionsHttpProfile::Strict,
        NameReuse::Window(Duration::from_secs(3600)),
        600,
        retry(1, 500),
        true,
        false,
    )
    .await;
    let task = body_of(&json!({"name": format!("{BASE}/tasks/windowed")}));
    h.runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &task)
        .unwrap();
    h.clock
        .lock()
        .unwrap()
        .advance(fireemu_core_types::time::LogicalDuration::from_seconds(1))
        .unwrap();
    h.idle().await;
    let advance = |seconds: i64| {
        h.clock
            .lock()
            .unwrap()
            .advance(fireemu_core_types::time::LogicalDuration::from_seconds(
                seconds,
            ))
            .unwrap();
    };
    advance(3599);
    let (status, text) = refused(
        h.runtime
            .enqueue_task("demo-app", "us-central1", "taskA", &task),
    );
    assert_eq!(status, 409, "{text}");
    assert!(text.contains("existed too recently"), "{text}");
    advance(1);
    assert!(
        h.runtime
            .enqueue_task("demo-app", "us-central1", "taskA", &task)
            .is_ok(),
        "free at the window"
    );
    h.stop().await;
}

#[tokio::test]
async fn an_overrun_deadline_is_a_504_for_the_next_attempt_in_strict() {
    // (The official profile keeps the official deadline of the task, a minute, so only the strict one is cut off here.)
    for (profile, previous) in [(FunctionsHttpProfile::Strict, Some("504"))] {
        // A deadline of one second; the runner holds the task (no release file) until it is cut off.
        let h = start_full(
            "deadline",
            profile,
            NameReuse::Immediate,
            1,
            retry(2, 100),
            false,
            false,
        )
        .await;
        std::fs::remove_file(h.dir.join("entries.taskA.release")).unwrap();
        // A task may not name less than 15 s, so the default carries the one second.
        let task = body_of(&json!({"name": format!("{BASE}/tasks/slow")}));
        h.runtime
            .enqueue_task("demo-app", "us-central1", "taskA", &task)
            .unwrap();
        let second = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let text = std::fs::read_to_string(&h.log).unwrap_or_default();
                let deliveries: Vec<Value> = text
                    .lines()
                    .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                    .filter(|e| e["path"].as_str().is_some_and(|p| p.ends_with("/taskA")))
                    .collect();
                if deliveries.len() >= 2 {
                    break deliveries[1].clone();
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "a second attempt came; the runner saw: {}",
                std::fs::read_to_string(&h.log).unwrap_or_default()
            )
        });
        assert_eq!(
            second["headers"]["x-cloudtasks-taskpreviousresponse"].as_str(),
            previous,
            "{profile:?}"
        );
        std::fs::write(h.dir.join("entries.taskA.release"), "").unwrap();
        h.stop().await;
    }
}

#[tokio::test]
async fn the_first_retry_waits_the_minimum_backoff_in_strict_and_twice_it_in_the_official_profile()
{
    let mut gaps = Vec::new();
    for profile in [FunctionsHttpProfile::Strict, FunctionsHttpProfile::Emulator] {
        let h = start_full(
            "backoff",
            profile,
            NameReuse::Immediate,
            60,
            retry(2, 1000),
            false,
            false,
        )
        .await;
        h.runtime
            .enqueue_task(
                "demo-app",
                "us-central1",
                "taskA",
                &body_of(&json!({"name": format!("{BASE}/tasks/failing-1")})),
            )
            .unwrap();
        let mut first = None;
        let gap = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let lines = std::fs::read_to_string(&h.probe)
                    .unwrap_or_default()
                    .lines()
                    .count();
                if lines >= 1 && first.is_none() {
                    first = Some(std::time::Instant::now());
                }
                if lines >= 2 {
                    break first.unwrap().elapsed();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("a retry came");
        gaps.push(gap);
        h.stop().await;
    }
    assert!(
        gaps[0] < Duration::from_millis(1700),
        "strict {:?}",
        gaps[0]
    );
    assert!(
        gaps[1] > Duration::from_millis(1800),
        "official {:?}",
        gaps[1]
    );
}

#[tokio::test]
async fn a_refusal_that_is_not_google_json_stays_plain_text_in_the_strict_listener_too() {
    let h = start(
        "strict-wire-closed",
        FunctionsHttpProfile::Strict,
        NameReuse::Immediate,
        600,
    )
    .await;
    let (addr, server) = tasks_listener(&h).await;
    h.runtime.shutdown().await;
    let ok = body_of(&json!({"name": format!("{BASE}/tasks/after-shutdown")}));
    let (status, head, body) = wire(addr, "POST", TASKS, ok.to_string().as_bytes()).await;
    assert_eq!(status, 503, "{body}");
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: text/plain"),
        "{head}"
    );
    server.abort();
    let _ = std::fs::remove_dir_all(h.dir);
}

#[tokio::test]
async fn the_retry_gaps_of_a_failing_task_follow_production_after_a_dozen_failures_in_strict() {
    use fireemu_core_types::time::LogicalDuration;
    // tqwindow of the recordings: minBackoff 1 s, maxBackoff 2 s, one doubling, 100 attempts.
    let queue = TaskRetryConfig {
        max_attempts: 100,
        max_retry_millis: None,
        max_backoff_millis: 2_000,
        max_doublings: 1,
        min_backoff_millis: 1_000,
    };
    // The gaps in milliseconds before attempt 2, 3, ...: production's, then the declared ones.
    let production = [
        1000, 2000, 2000, 2000, 2000, 2000, 2000, 2000, 2000, 2000, 2000, 4000, 4000, 4000, 8000,
        8000, 10_000,
    ];
    for (production_gaps, expected) in [
        (true, production.to_vec()),
        (
            false,
            production
                .iter()
                .enumerate()
                .map(|(i, _)| if i == 0 { 1000 } else { 2000 })
                .collect(),
        ),
    ] {
        let h = start_full(
            "gaps",
            FunctionsHttpProfile::Strict,
            NameReuse::Immediate,
            600,
            queue,
            true,
            production_gaps,
        )
        .await;
        h.runtime
            .enqueue_task(
                "demo-app",
                "us-central1",
                "taskA",
                &body_of(&json!({"name": format!("{BASE}/tasks/failing-gaps")})),
            )
            .unwrap();
        let deliveries = || {
            std::fs::read_to_string(&h.probe)
                .unwrap_or_default()
                .lines()
                .count()
        };
        let advance = |millis: i64| {
            h.clock
                .lock()
                .unwrap()
                .advance(LogicalDuration::from_millis(millis))
                .unwrap()
        };
        let wait_for = |count: usize| async move {
            tokio::time::timeout(Duration::from_secs(10), async {
                while deliveries() < count {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "attempt {count} never came with production gaps {production_gaps}; the runner saw {}",
                    deliveries()
                )
            });
        };
        // The task is waiting out a backoff (nothing runnable) before the clock is moved, or the move would be counted into the gap.
        let backed_off = || async {
            tokio::time::timeout(Duration::from_secs(10), async {
                while !h.runtime.is_idle_with_scope(true) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the task backed off");
        };
        advance(1000);
        wait_for(1).await;
        backed_off().await;
        for (gap, millis) in expected.iter().enumerate() {
            let attempt = gap + 1;
            // One millisecond short of the gap: no retry yet; at the gap: the retry.
            advance(millis - 1);
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert_eq!(
                deliveries(),
                attempt,
                "gap {} ({production_gaps}): sooner than {millis} ms",
                gap + 1
            );
            advance(1);
            wait_for(attempt + 1).await;
            backed_off().await;
        }
        h.stop().await;
    }
}
