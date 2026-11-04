//! What a dispatched task looks like at the runner: the body is the enqueuer's bytes in both
//! profiles, and the strict profile sends production's headers (the bare queue id, the ETA as
//! seconds with six decimals, the `Google-Cloud-Tasks` user agent) where the emulator profile
//! keeps the official emulator's. Production's shape was recorded on 2026-11-04 (sandbox run
//! PYCHECK-EVENTS-20261104-01, the raw twin of a task queue function).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_functions::application_clock::ApplicationClockPolicy;
use fireemu_adapter_functions::http::FunctionsHttpProfile;
use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{CodebaseSpec, FunctionsConfig, FunctionsRuntime};
use fireemu_core_functions::manifest::{TaskRateLimits, TaskRetryConfig, Trigger};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

struct Harness {
    runtime: Arc<FunctionsRuntime>,
    clock: Arc<Mutex<VirtualClock>>,
    virtual_tasks: bool,
    log: std::path::PathBuf,
    dir: std::path::PathBuf,
}

async fn start(name: &str, profile: FunctionsHttpProfile) -> Harness {
    start_with(name, profile, false).await
}

/// `virtual_tasks` drives task time by the pinned virtual clock, so a task's ETA is exact.
async fn start_with(name: &str, profile: FunctionsHttpProfile, virtual_tasks: bool) -> Harness {
    let dir =
        std::env::temp_dir().join(format!("fireemu-task-shape-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("requests");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: vec![(
            "FIREEMU_FAKE_REQUEST_LOG".to_owned(),
            log.display().to_string(),
        )],
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
        retry: TaskRetryConfig {
            max_attempts: 1,
            ..TaskRetryConfig::default()
        },
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
            ..FunctionsConfig::for_tests(1, "runner-secret".into())
        },
        clock.clone(),
        profile,
    )
    .expect("one codebase");
    tokio::spawn(runtime.clone().dispatch_loop());
    Harness {
        runtime,
        clock,
        virtual_tasks,
        log,
        dir,
    }
}

impl Harness {
    /// Enqueues one task with `body_text` as its bytes and returns the request the runner saw.
    fn task(id: u32, body_text: &str, extra: &Value) -> Value {
        let mut http = json!({"url": "", "body": base64(body_text.as_bytes())});
        if let Some(headers) = extra.get("headers") {
            http["headers"] = headers.clone();
        }
        let mut task = json!({
            "name": format!("projects/demo-app/locations/us-central1/queues/taskA/tasks/{id}"),
            "httpRequest": http,
        });
        if let Some(schedule) = extra.get("scheduleTime") {
            task["scheduleTime"] = schedule.clone();
        }
        json!({"task": task})
    }

    async fn dispatched(&self, id: u32, body_text: &str, extra: Value) -> Value {
        self.runtime
            .enqueue_task(
                "demo-app",
                "us-central1",
                "taskA",
                &Self::task(id, body_text, &extra),
            )
            .unwrap();
        if self.virtual_tasks {
            // Virtual task time moves only when the test moves it; the task was scheduled at the enqueue instant.
            self.clock
                .lock()
                .unwrap()
                .advance(LogicalDuration::from_seconds(1))
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(4), async {
            while !self.runtime.is_idle() {
                self.runtime.idle_notify().notified().await;
            }
        })
        .await
        .expect("the task queue became idle");
        let text = std::fs::read_to_string(&self.log).expect("the runner logged the request");
        let line = text
            .lines()
            .rfind(|line| line.contains("/taskA"))
            .expect("the task reached the runner");
        serde_json::from_str(line).unwrap()
    }

    async fn stop(self) {
        self.runtime.shutdown().await;
        let _ = std::fs::remove_dir_all(self.dir);
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

const BODY: &str = r#"{"data":{"run":"pcrun-1","label":"pctaskraw"}}"#;

#[tokio::test]
async fn the_body_reaches_the_runner_as_the_enqueuer_wrote_it_in_both_profiles() {
    for (name, profile) in [
        ("body-strict", FunctionsHttpProfile::Strict),
        ("body-emulator", FunctionsHttpProfile::Emulator),
    ] {
        let h = start(name, profile).await;
        let request = h.dispatched(1, BODY, json!({})).await;
        assert_eq!(request["body"], BODY, "{name}");
        // Members out of alphabetical order, spaces and a trailing null survive too.
        let odd = r#"{ "data": {"z": 1, "a": [3, 1]}, "n": null }"#;
        let request = h.dispatched(2, odd, json!({})).await;
        assert_eq!(request["body"], odd, "{name}");
        h.stop().await;
    }
}

#[tokio::test]
async fn the_strict_profile_sends_production_s_task_headers() {
    let h = start("headers-strict", FunctionsHttpProfile::Strict).await;
    let request = h.dispatched(42, BODY, json!({})).await;
    let headers = &request["headers"];
    assert_eq!(headers["x-cloudtasks-queuename"], "taskA");
    assert_eq!(headers["user-agent"], "Google-Cloud-Tasks");
    let eta = headers["x-cloudtasks-tasketa"].as_str().unwrap();
    let (seconds, micros) = eta.split_once('.').expect("seconds.micros");
    assert!(seconds.parse::<u64>().is_ok() && micros.len() == 6 && micros.parse::<u32>().is_ok());
    assert_eq!(headers["x-cloudtasks-taskname"], "42");
    assert_eq!(headers["x-cloudtasks-taskretrycount"], "0");
    assert_eq!(headers["content-type"], "application/json");
    h.stop().await;
}

#[tokio::test]
async fn the_emulator_profile_keeps_the_official_emulator_s_task_headers() {
    let h = start("headers-emulator", FunctionsHttpProfile::Emulator).await;
    let request = h.dispatched(7, BODY, json!({})).await;
    let headers = &request["headers"];
    assert_eq!(
        headers["x-cloudtasks-queuename"],
        "queue:demo-app-us-central1-taskA"
    );
    assert!(headers
        .get("user-agent")
        .is_none_or(|agent| agent != "Google-Cloud-Tasks"));
    assert!(!headers["x-cloudtasks-tasketa"]
        .as_str()
        .unwrap()
        .contains('.'));
    h.stop().await;
}

#[tokio::test]
async fn the_strict_eta_is_the_virtual_task_time_with_six_decimals() {
    let h = start_with("eta-virtual", FunctionsHttpProfile::Strict, true).await;
    let request = h.dispatched(5, BODY, json!({})).await;
    // The virtual clock is pinned at START, so the ETA is exactly that instant.
    assert_eq!(
        request["headers"]["x-cloudtasks-tasketa"],
        "1788004860.000000"
    );
    h.stop().await;
}

#[tokio::test]
async fn the_strict_profile_refuses_a_schedule_time_that_is_not_a_timestamp_and_the_emulator_profile_delivers_it(
) {
    let strict = start("schedule-strict", FunctionsHttpProfile::Strict).await;
    for bad in ["soon", "", "2026-02-01", "2016-12-31T23:59:60Z"] {
        let refusal = strict
            .runtime
            .enqueue_task(
                "demo-app",
                "us-central1",
                "taskA",
                &Harness::task(9, BODY, &json!({"scheduleTime": bad})),
            )
            .expect_err(bad);
        assert_eq!(refusal.status, 400, "{bad:?}");
    }
    assert!(!strict.log.exists(), "nothing was dispatched");
    // A valid one is accepted.
    strict
        .runtime
        .enqueue_task(
            "demo-app",
            "us-central1",
            "taskA",
            &Harness::task(10, BODY, &json!({"scheduleTime": "2026-02-01T00:30:00Z"})),
        )
        .unwrap();
    strict.stop().await;
    let emulator = start("schedule-emulator", FunctionsHttpProfile::Emulator).await;
    let request = emulator
        .dispatched(11, BODY, json!({"scheduleTime": "soon"}))
        .await;
    assert_eq!(request["headers"]["x-cloudtasks-tasketa"], "soon");
    emulator.stop().await;
}

#[tokio::test]
async fn the_strict_profile_keeps_the_service_headers_a_task_tries_to_set_and_the_emulator_profile_does_not(
) {
    let headers = json!({
        "headers": {
            "user-agent": "custom/1",
            "X-CLOUDTASKS-QUEUENAME": "other",
            "x-cloudtasks-taskretrycount": "7",
            "X-Custom": "kept",
        }
    });
    let strict = start("override-strict", FunctionsHttpProfile::Strict).await;
    let request = strict.dispatched(20, BODY, headers.clone()).await;
    let got = &request["headers"];
    assert_eq!(got["user-agent"], "Google-Cloud-Tasks");
    assert_eq!(got["x-cloudtasks-queuename"], "taskA");
    assert_eq!(got["x-cloudtasks-taskretrycount"], "0");
    assert_eq!(got["x-custom"], "kept");
    strict.stop().await;
    let emulator = start("override-emulator", FunctionsHttpProfile::Emulator).await;
    let request = emulator.dispatched(21, BODY, headers).await;
    let got = &request["headers"];
    assert_eq!(got["user-agent"], "custom/1");
    assert_eq!(got["x-cloudtasks-queuename"], "other");
    assert_eq!(got["x-cloudtasks-taskretrycount"], "7");
    emulator.stop().await;
}
