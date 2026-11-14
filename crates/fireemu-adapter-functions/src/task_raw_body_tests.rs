use crate::http::FunctionsHttpProfile;
use crate::runtime::{CodebaseSpec, FunctionsConfig, FunctionsRuntime};
use crate::task_scheduler::{NameState, TaskScheduler};
use fireemu_core_functions::manifest::{
    FunctionGeneration, FunctionManifest, FunctionSpec, PlatformOptions, TaskRateLimits,
    TaskRetryConfig, Trigger,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{json, Value};

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn enqueue_body(encoded: &str) -> Value {
    json!({"task": {"httpRequest": {"url": "", "body": encoded}}})
}

#[test]
fn emulator_deadline_keeps_the_previous_integer_or_default_interpretation() {
    for (input, expected) in [("15.5s", 60), ("-1s", 60), ("NaNs", 60), ("17s", 17)] {
        let mut body = enqueue_body(&encode(b"null"));
        body["task"]["dispatchDeadline"] = json!(input);
        let task = crate::tasks::accept("demo", "us-central1", "q", "unused", &body, 1).unwrap();
        assert_eq!(task.dispatch_deadline_seconds, expected, "input {input}");
    }
}

#[test]
fn response_view_defaults_to_basic_and_decodes_known_enum_values() {
    assert_eq!(crate::tasks::response_view("/task"), Ok(false));
    assert_eq!(
        crate::tasks::response_view("/task?responseView=BASIC"),
        Ok(false)
    );
    assert_eq!(
        crate::tasks::response_view("/task?responseView=VIEW_UNSPECIFIED"),
        Ok(false)
    );
    assert_eq!(
        crate::tasks::response_view("/task?responseView=%46ULL"),
        Ok(true)
    );
    assert_eq!(
        crate::tasks::response_view("/task?other=x&responseView=FULL"),
        Ok(true)
    );
    assert!(crate::tasks::response_view("/task?responseView=bad").is_err());
    assert!(crate::tasks::response_view("/task?responseView=%XZ").is_err());
}

#[test]
fn valid_json_null_is_distinct_from_an_invalid_raw_body() {
    let task = crate::tasks::accept(
        "demo",
        "us-central1",
        "q",
        "http://unused",
        &enqueue_body(&encode(b"null")),
        1,
    )
    .unwrap();
    assert_eq!(task.body, Value::Null);
    assert_eq!(task.body_json_error, None);
}

#[test]
fn empty_body_bytes_are_preserved() {
    let task = crate::tasks::accept(
        "demo",
        "us-central1",
        "q",
        "http://unused",
        &enqueue_body(&encode(b"")),
        1,
    )
    .unwrap();
    assert_eq!(task.delivery_body(), b"");
    assert!(task.body_json_error.is_some());
}

#[test]
fn arbitrary_non_json_body_bytes_are_preserved_for_dispatch() {
    let raw = [0xff, 0xfe, 0x00];
    let task = crate::tasks::accept(
        "demo",
        "us-central1",
        "q",
        "http://unused",
        &enqueue_body(&encode(&raw)),
        1,
    )
    .expect("strict tasks retain arbitrary HTTP body bytes");
    assert_eq!(task.delivery_body(), raw);
    assert!(task.body_json_error.is_some());
}

proptest::proptest! {
    #[test]
    fn base64_encoding_matches_standard_for_arbitrary_bytes(
        bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)
    ) {
        proptest::prop_assert_eq!(
            crate::tasks::encode_base64(&bytes),
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        );
    }
}

#[tokio::test]
async fn generated_pict_rows_drive_body_and_view_contracts() {
    let cases = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/task-get-raw-body-pict.tsv"
    ))
    .unwrap();
    let mut lines = cases.lines();
    assert_eq!(lines.next(), Some("Operation\tBody\tView\tProfile"));
    let mut rows = 0;
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(fields.len(), 4, "malformed generated row: {line}");
        let [operation, body_kind, _, profile] = fields.as_slice() else {
            unreachable!();
        };
        let raw = match *body_kind {
            "json" => br#"{"data":1}"#.as_slice(),
            "non_json_utf8" => b"plain text".as_slice(),
            "binary" => &[0xff, 0x00, 0x7f],
            "empty" => b"".as_slice(),
            other => panic!("unexpected body value {other}"),
        };
        let profile = match *profile {
            "strict" => FunctionsHttpProfile::Strict,
            "emulator" => FunctionsHttpProfile::Emulator,
            other => panic!("unexpected profile value {other}"),
        };
        let (mut scheduler, runtime, now) = pict_runtime(profile);
        let mut request = enqueue_body(&encode(raw));
        let name = "projects/p/locations/us-central1/queues/q/tasks/pict";
        request["task"]["name"] = json!(if *operation == "get_missing" {
            "projects/p/locations/us-central1/queues/q/tasks/other"
        } else {
            name
        });
        let admitted = runtime.enqueue_task("p", "us-central1", "q", &request);
        if profile == FunctionsHttpProfile::Emulator && *body_kind != "json" {
            let error = admitted.expect_err("emulator admission rejects non-JSON bodies");
            assert_eq!(error.status, 400, "{line}");
            assert_eq!(
                error.body,
                format!(
                    "the task's httpRequest body is not JSON: {}",
                    serde_json::from_slice::<Value>(raw).unwrap_err()
                ),
                "{line}"
            );
        } else {
            admitted.unwrap_or_else(|error| panic!("{line}: {}", error.body));
            let task =
                crate::tasks::accept("p", "us-central1", "q", "http://function", &request, 1)
                    .unwrap();
            assert_eq!(task.delivery_body(), raw, "{line}");
            scheduler
                .enqueue_at("q", task, TaskRetryConfig::default(), 256, now)
                .unwrap();
        }
        if *operation == "get_dispatched" {
            let (dispatches, _) = scheduler.dispatch_ready(
                now + Duration::from_secs(1),
                "p",
                |_| Some("us-central1".to_owned()),
                1,
            );
            assert_eq!(dispatches.len(), 1, "{line}");
            scheduler.record_dispatch_attempt(&dispatches[0], "2026-08-29T10:41:00Z".to_owned());
        }
        assert_pict_views(line, &fields, raw, &mut scheduler, &runtime, now, name);
        runtime.shutdown().await;
        rows += 1;
    }
    assert_eq!(rows, 21);
}

fn pict_runtime(profile: FunctionsHttpProfile) -> (TaskScheduler, Arc<FunctionsRuntime>, Instant) {
    let manifest = FunctionManifest {
        functions: vec![FunctionSpec {
            name: "q".to_owned(),
            region: "us-central1".to_owned(),
            entry_point: "q".to_owned(),
            trigger: Trigger::TaskQueue {
                retry: TaskRetryConfig::default(),
                rate_limits: TaskRateLimits::default(),
            },
            timeout_seconds: 60,
            retry: false,
            generation: FunctionGeneration::Second,
            concurrency: None,
            platform_options: PlatformOptions::default(),
        }],
        ignored: Vec::new(),
    };
    let now = Instant::now();
    let scheduler = TaskScheduler::from_manifest(&manifest, now);
    let runtime = FunctionsRuntime::with_codebases(
        vec![CodebaseSpec {
            name: "default".to_owned(),
            function: None,
            manifest,
            runner: Arc::new(crate::runner::Runner::unstarted("pict")),
            spawn: None,
            cleanup_dir: None,
        }],
        FunctionsConfig {
            project: "p".to_owned(),
            functions_host: Some("127.0.0.1:5001".to_owned()),
            ..FunctionsConfig::for_tests(1, "test-only".to_owned())
        },
        Arc::new(Mutex::new(fireemu_core_session::clock::VirtualClock::new(
            fireemu_core_types::time::LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        profile,
    )
    .unwrap();
    (scheduler, runtime, now)
}

fn assert_pict_views(
    line: &str,
    fields: &[&str],
    raw: &[u8],
    scheduler: &mut TaskScheduler,
    runtime: &FunctionsRuntime,
    now: Instant,
    name: &str,
) {
    let [operation, body_kind, view, profile] = fields else {
        unreachable!();
    };
    // The combined PICT level represents both query cases; execute both for every such row.
    let targets: &[&str] = match *view {
        "BASIC" => &["/task?responseView=BASIC"],
        "FULL" => &["/task?responseView=FULL"],
        "invalid_or_absent" => &["/task?responseView=bad", "/task"],
        other => panic!("unexpected view value {other}"),
    };
    for target in targets {
        let parsed = crate::tasks::response_view(target);
        if target.contains("=bad") {
            assert!(parsed.is_err(), "{line}");
            continue;
        }
        let full = parsed.unwrap();
        assert_eq!(full, *view == "FULL", "{line}");
        let observation = scheduler.get_task("q", name, now);
        if *operation == "get_missing" || (*profile == "emulator" && *body_kind != "json") {
            assert_eq!(observation.unwrap_err(), NameState::Free, "{line}");
            let error = runtime
                .get_task_strict("p", "us-central1", "q", "pict", full)
                .unwrap_err();
            assert_eq!(error.status, 404, "{line}");
            assert_eq!(
                serde_json::from_str::<Value>(&error.body).unwrap(),
                json!({"error": {
                    "code": 404, "message": "Requested entity was not found.", "status": "NOT_FOUND"
                }}),
                "{line}"
            );
            continue;
        }
        let observation = observation.unwrap();
        let answer = crate::tasks_production::get_answer(&observation, full);
        if *operation == "get_dispatched" {
            assert_eq!(answer["dispatchCount"], 1, "{line}");
            assert_eq!(
                answer["firstAttempt"]["dispatchTime"], "2026-08-29T10:41:00Z",
                "{line}"
            );
            assert!(
                answer["lastAttempt"].get("responseTime").is_none(),
                "{line}"
            );
        } else {
            assert!(answer.get("dispatchCount").is_none(), "{line}");
            assert!(answer.get("firstAttempt").is_none(), "{line}");
            assert!(answer.get("lastAttempt").is_none(), "{line}");
        }
        assert!(answer.get("responseCount").is_none(), "{line}");
        if full {
            assert_eq!(answer["httpRequest"]["body"], encode(raw), "{line}");
        } else {
            assert!(answer["httpRequest"].get("body").is_none(), "{line}");
        }
    }
}
