//! The runtime against a fake runner: dispatch, outcomes, retries in virtual time,
//! schedules, await-idle, and the protocol helpers.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_functions::events::{firestore_event, storage_event};
use fireemu_adapter_functions::http::parse_response;
use fireemu_adapter_functions::manifest_json::{manifest_to_json, parse_manifest};
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{CodebaseSpec, FunctionsConfig, FunctionsRuntime};
use fireemu_adapter_grpc::local::CommitEvent;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{CommitVersion, Document, DocumentChange};
use fireemu_core_firestore::value::Value as FsValue;
use fireemu_core_functions::manifest::{
    BlockingAuthEvent, TaskRateLimits, TaskRetryConfig, Trigger,
};
use fireemu_core_functions::manifest::{DocumentEvent, FunctionGeneration, ObjectEvent};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::{NewMetadata, Precondition, StorageEvent, StorageState};
use fireemu_core_types::ids::SessionId;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::json;

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

#[tokio::test]
async fn runner_log_frames_preserve_function_and_user_metadata() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let runner = Runner::spawn_spec(&SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(20),
    })
    .await
    .unwrap();

    let invocation = runner
        .invoke(
            json!({
                "type": "invoke",
                "invocationId": "log-metadata-1",
                "function": "ok",
                "entryPoint": "ok",
                "trigger": "firestore",
                "event": {"data": {}}
            }),
            Duration::from_secs(5),
        )
        .await;
    assert_eq!(
        invocation.outcome,
        fireemu_adapter_functions::runner::InvokeOutcome::Ok
    );
    let logs = runner.logs_since(None);
    let log = logs
        .lines
        .iter()
        .find(|line| line.message() == "invoked ok")
        .expect("the invocation log is retained");
    assert_eq!(log.display(), "info log-metadata-1 invoked ok");
    assert_eq!(log.function(), Some("ok"));
    assert!(log.is_user());
    assert_eq!(log.fields()["code"], 47);
    assert_eq!(log.fields()["nested"]["attempts"], json!([1, 2]));
    runner.shutdown().await;
}

fn doc(path: &str, v: i64) -> Document {
    Document {
        path: DocumentPath::parse(
            &fireemu_core_types::ids::ProjectId::try_new("demo-app").unwrap(),
            &fireemu_core_types::ids::DatabaseId::default_database(),
            path,
        )
        .unwrap(),
        fields: [("v".to_owned(), FsValue::Integer(v))]
            .into_iter()
            .collect(),
        create_time: START,
        update_time: START,
        version: CommitVersion::default(),
    }
}

fn commit(changes: Vec<DocumentChange>) -> CommitEvent {
    CommitEvent {
        actor: fireemu_adapter_grpc::local::Actor::system(),
        project: "demo-app".into(),
        database: fireemu_core_types::ids::DatabaseId::DEFAULT.into(),
        version: 1,
        commit_time: Some(START),
        changes: Arc::from(changes),
    }
}

async fn start() -> (Arc<FunctionsRuntime>, Arc<Mutex<VirtualClock>>) {
    start_with(fireemu_adapter_functions::runtime::OverlapPolicy::Allow).await
}

async fn start_with(
    overlap: fireemu_adapter_functions::runtime::OverlapPolicy,
) -> (Arc<FunctionsRuntime>, Arc<Mutex<VirtualClock>>) {
    start_with_policies(
        overlap,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
    )
    .await
}

async fn start_with_policies(
    overlap: fireemu_adapter_functions::runtime::OverlapPolicy,
    catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy,
) -> (Arc<FunctionsRuntime>, Arc<Mutex<VirtualClock>>) {
    start_with_policies_and_manifest(overlap, catch_up, |_| {}).await
}

async fn start_with_policies_and_manifest(
    overlap: fireemu_adapter_functions::runtime::OverlapPolicy,
    catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy,
    configure: impl FnOnce(&mut fireemu_core_functions::manifest::FunctionManifest),
) -> (Arc<FunctionsRuntime>, Arc<Mutex<VirtualClock>>) {
    start_with_runtime_options(overlap, catch_up, 4, true, configure).await
}

async fn start_with_runtime_options(
    overlap: fireemu_adapter_functions::runtime::OverlapPolicy,
    catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy,
    max_running: usize,
    respawnable: bool,
    configure: impl FnOnce(&mut fireemu_core_functions::manifest::FunctionManifest),
) -> (Arc<FunctionsRuntime>, Arc<Mutex<VirtualClock>>) {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(20),
    };
    let runner = Runner::spawn_spec(&spec).await.unwrap();
    let mut manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
    configure(&mut manifest);
    let clock = Arc::new(Mutex::new(VirtualClock::new(START)));
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            project: "demo-app".into(),
            default_bucket: "demo-app.appspot.com".into(),
            location: "nam5".into(),
            session: SessionId::new(7),
            max_running,
            debug_mode: false,
            retry_attempts: 4,
            max_catch_up_runs: 1000,
            runner_secret: "s".into(),
            overlap,
            catch_up,
            functions_host: None,
        },
        clock.clone(),
        Arc::new(runner),
        respawnable.then_some(spec),
    );
    tokio::spawn(runtime.clone().dispatch_loop());
    (runtime, clock)
}

async fn start_task_runtime(
    probe: &Path,
    configure: impl Fn(&str) -> TaskRateLimits,
) -> Arc<FunctionsRuntime> {
    start_task_runtime_with_max(probe, 4, configure).await
}

async fn start_task_runtime_with_max(
    probe: &Path,
    max_running: usize,
    configure: impl Fn(&str) -> TaskRateLimits,
) -> Arc<FunctionsRuntime> {
    start_task_runtime_with_policy(probe, max_running, |name| {
        (TaskRetryConfig::default(), configure(name))
    })
    .await
}

async fn start_task_runtime_with_policy(
    probe: &Path,
    max_running: usize,
    configure: impl Fn(&str) -> (TaskRetryConfig, TaskRateLimits),
) -> Arc<FunctionsRuntime> {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: vec![(
            "FIREEMU_FAKE_TASK_PROBE".to_owned(),
            probe.display().to_string(),
        )],
        hello_timeout: Duration::from_secs(20),
    };
    let runner = Runner::spawn_spec(&spec).await.unwrap();
    let mut manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
    let template = manifest.get("echo").unwrap().clone();
    for name in ["taskA", "taskB"] {
        let mut function = template.clone();
        name.clone_into(&mut function.name);
        name.clone_into(&mut function.entry_point);
        let (retry, rate_limits) = configure(name);
        function.trigger = Trigger::TaskQueue { retry, rate_limits };
        manifest.functions.push(function);
    }
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            project: "demo-app".into(),
            default_bucket: "demo-app.appspot.com".into(),
            location: "nam5".into(),
            session: SessionId::new(7),
            max_running,
            debug_mode: false,
            retry_attempts: 1,
            max_catch_up_runs: 1,
            runner_secret: "s".into(),
            overlap: fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
            catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::All,
            functions_host: Some("127.0.0.1:5001".into()),
        },
        Arc::new(Mutex::new(VirtualClock::new(START))),
        Arc::new(runner),
        Some(spec),
    );
    tokio::spawn(runtime.clone().dispatch_loop());
    runtime
}

fn task_body(id: &str) -> serde_json::Value {
    json!({"task": {
        "name": format!("projects/demo-app/locations/us-central1/queues/task/tasks/{id}"),
        "httpRequest": {"url": "", "body": "eyJkYXRhIjp7fX0="}
    }})
}

async fn wait_for_task_entries(probe: &Path, expected: usize) -> Vec<String> {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let entries = std::fs::read_to_string(probe)
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if entries.len() >= expected {
                return entries;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("task entries reached the probe")
}

#[tokio::test]
async fn task_queue_concurrency_is_isolated_per_queue() {
    let dir = std::env::temp_dir().join(format!(
        "fireemu-functions-task-limits-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("entries");
    let runtime = start_task_runtime(&probe, |_| TaskRateLimits {
        max_concurrent_dispatches: 1,
        max_dispatches_per_second: 500.0,
    })
    .await;

    runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &task_body("a1"))
        .unwrap();
    runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &task_body("a2"))
        .unwrap();
    runtime
        .enqueue_task("demo-app", "us-central1", "taskB", &task_body("b1"))
        .unwrap();

    let _ = wait_for_task_entries(&probe, 2).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let entries = std::fs::read_to_string(&probe).unwrap();
    assert_eq!(entries.lines().filter(|line| *line == "taskA").count(), 1);
    assert_eq!(entries.lines().filter(|line| *line == "taskB").count(), 1);

    std::fs::write(format!("{}.taskA.release", probe.display()), b"").unwrap();
    std::fs::write(format!("{}.taskB.release", probe.display()), b"").unwrap();
    tokio::time::timeout(Duration::from_secs(4), async {
        while !runtime.is_idle() {
            runtime.idle_notify().notified().await;
        }
    })
    .await
    .expect("all task queues became idle");
    runtime.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn reset_task_completion_cannot_release_a_new_generation_task() {
    let dir = std::env::temp_dir().join(format!(
        "fireemu-functions-task-reset-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("entries");
    let runtime = start_task_runtime(&probe, |_| TaskRateLimits {
        max_concurrent_dispatches: 1,
        max_dispatches_per_second: 500.0,
    })
    .await;

    let body = task_body("same");
    runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &body)
        .unwrap();
    let _ = wait_for_task_entries(&probe, 1).await;
    runtime.reset();
    assert_eq!(runtime.status()["tasksInFlight"], 0);

    runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &body)
        .unwrap();
    let _ = wait_for_task_entries(&probe, 2).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(runtime.status()["tasksInFlight"], 1);

    std::fs::write(format!("{}.taskA.release", probe.display()), b"").unwrap();
    tokio::time::timeout(Duration::from_secs(4), async {
        while !runtime.is_idle() {
            runtime.idle_notify().notified().await;
        }
    })
    .await
    .expect("the new generation task became idle");
    runtime.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn shutdown_cancels_pending_tasks_and_closes_admission() {
    let dir = std::env::temp_dir().join(format!(
        "fireemu-functions-task-shutdown-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("entries");
    let runtime = start_task_runtime(&probe, |_| TaskRateLimits {
        max_concurrent_dispatches: 1,
        max_dispatches_per_second: 1.0,
    })
    .await;
    runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &task_body("pending"))
        .unwrap();

    runtime.shutdown().await;
    assert!(runtime.is_idle());
    assert_eq!(runtime.status()["tasksInFlight"], 0);
    let refusal = runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &task_body("late"))
        .unwrap_err();
    assert_eq!(refusal.status, 503);
    assert!(refusal.body.contains("shutting down"));
    assert!(!probe.exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn shutdown_aborts_an_active_task_and_its_retry_lifecycle() {
    let dir = std::env::temp_dir().join(format!(
        "fireemu-functions-task-active-shutdown-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("entries");
    let runtime = start_task_runtime(&probe, |_| TaskRateLimits {
        max_concurrent_dispatches: 1,
        max_dispatches_per_second: 500.0,
    })
    .await;
    runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &task_body("active"))
        .unwrap();
    let _ = wait_for_task_entries(&probe, 1).await;

    tokio::time::timeout(Duration::from_secs(4), runtime.shutdown())
        .await
        .expect("shutdown aborts the active delivery without waiting for its retry deadline");
    assert!(runtime.is_idle());
    assert_eq!(runtime.status()["tasksInFlight"], 0);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(std::fs::read_to_string(&probe).unwrap().lines().count(), 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn local_http_contention_defers_a_task_without_spending_its_retry_budget() {
    let dir = std::env::temp_dir().join(format!(
        "fireemu-functions-task-contention-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("entries");
    let runtime = start_task_runtime_with_max(&probe, 1, |_| TaskRateLimits {
        max_concurrent_dispatches: 1,
        max_dispatches_per_second: 500.0,
    })
    .await;
    let target = runtime
        .http_target("demo-app", "us-central1", "hold")
        .unwrap();
    let occupied_runtime = runtime.clone();
    let occupied = tokio::spawn(async move {
        occupied_runtime
            .invoke_http(&target, "POST", "/hold", &[], &[])
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &task_body("deferred"))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!probe.exists(), "the task must wait for local capacity");

    assert_eq!(occupied.await.unwrap().status, 204);
    let _ = wait_for_task_entries(&probe, 1).await;
    std::fs::write(format!("{}.taskA.release", probe.display()), b"").unwrap();
    tokio::time::timeout(Duration::from_secs(4), async {
        while !runtime.is_idle() {
            runtime.idle_notify().notified().await;
        }
    })
    .await
    .expect("the deferred task became idle");
    runtime.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn local_capacity_wait_before_first_delivery_does_not_spend_max_retry_duration() {
    let dir = std::env::temp_dir().join(format!(
        "fireemu-functions-task-retry-duration-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("entries");
    let runtime = start_task_runtime_with_policy(&probe, 1, |_| {
        (
            TaskRetryConfig {
                max_attempts: 1,
                max_retry_millis: Some(100),
                max_backoff_millis: 100,
                max_doublings: 0,
                min_backoff_millis: 10,
            },
            TaskRateLimits {
                max_concurrent_dispatches: 1,
                max_dispatches_per_second: 500.0,
            },
        )
    })
    .await;
    let target = runtime
        .http_target("demo-app", "us-central1", "hold")
        .unwrap();
    let occupied_runtime = runtime.clone();
    let occupied = tokio::spawn(async move {
        occupied_runtime
            .invoke_http(&target, "POST", "/hold", &[], &[])
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &task_body("failing"))
        .unwrap();
    assert_eq!(occupied.await.unwrap().status, 204);
    let entries = wait_for_task_entries(&probe, 2).await;
    assert_eq!(
        &entries[..2],
        ["taskA:0:0", "taskA:1:0"],
        "one genuine retry must survive pre-delivery contention"
    );
    tokio::time::timeout(Duration::from_secs(4), async {
        while !runtime.is_idle() {
            runtime.idle_notify().notified().await;
        }
    })
    .await
    .expect("the failed task exhausts its bounded retry policy");
    runtime.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn retry_rate_wait_cannot_outlive_an_exhausted_retry_duration() {
    let dir = std::env::temp_dir().join(format!(
        "fireemu-functions-task-rate-expiry-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("entries");
    let runtime = start_task_runtime_with_policy(&probe, 1, |_| {
        (
            TaskRetryConfig {
                max_attempts: 1,
                max_retry_millis: Some(100),
                max_backoff_millis: 100,
                max_doublings: 0,
                min_backoff_millis: 10,
            },
            TaskRateLimits {
                max_concurrent_dispatches: 1,
                max_dispatches_per_second: 0.5,
            },
        )
    })
    .await;
    runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &task_body("failing"))
        .unwrap();
    let _ = wait_for_task_entries(&probe, 1).await;

    tokio::time::timeout(Duration::from_millis(500), async {
        while !runtime.is_idle() {
            runtime.idle_notify().notified().await;
        }
    })
    .await
    .expect("retry-duration expiry wins over a later rate token");
    assert_eq!(std::fs::read_to_string(&probe).unwrap().lines().count(), 1);
    runtime.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn multi_codebase_runtime_exposes_and_stops_every_current_runner() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(20),
    };
    let first = Arc::new(Runner::spawn_spec(&spec).await.unwrap());
    let second = Arc::new(Runner::spawn_spec(&spec).await.unwrap());
    let first_manifest = parse_manifest(first.hello().manifest.as_ref().unwrap()).unwrap();
    let mut second_manifest = parse_manifest(second.hello().manifest.as_ref().unwrap()).unwrap();
    for function in &mut second_manifest.functions {
        function.name = format!("secondary_{}", function.name);
    }
    let runtime = FunctionsRuntime::with_codebases(
        vec![
            CodebaseSpec {
                name: "primary".to_owned(),
                manifest: first_manifest,
                runner: first.clone(),
                spawn: None,
                cleanup_dir: None,
            },
            CodebaseSpec {
                name: "secondary".to_owned(),
                manifest: second_manifest,
                runner: second.clone(),
                spawn: None,
                cleanup_dir: None,
            },
        ],
        FunctionsConfig {
            project: "demo-app".into(),
            default_bucket: "demo-app.appspot.com".into(),
            location: "nam5".into(),
            session: SessionId::new(7),
            max_running: 4,
            debug_mode: false,
            retry_attempts: 1,
            max_catch_up_runs: 1,
            runner_secret: "s".into(),
            overlap: fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
            catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::All,
            functions_host: None,
        },
        Arc::new(Mutex::new(VirtualClock::new(START))),
    )
    .unwrap();

    let runners = runtime.current_runners();
    assert_eq!(
        runners
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        vec!["primary", "secondary"]
    );
    assert!(runners.iter().all(|(_, runner)| runner.is_alive()));

    runtime.shutdown().await;
    assert!(!first.is_alive());
    assert!(!second.is_alive());
}

#[tokio::test]
async fn shutdown_rejects_late_reload_and_reset_runner_installation() {
    let (runtime, _clock) = start().await;
    let manifest = runtime.manifest().clone();
    let target = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    runtime.shutdown().await;

    let error = runtime
        .invoke_http(&target, "POST", "/", &[], &[])
        .await
        .unwrap_err();
    assert!(error.contains("shutting down"), "{error}");

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(20),
    };
    let replacement = Arc::new(Runner::spawn_spec(&spec).await.unwrap());
    let error = runtime
        .reload_codebase(CodebaseSpec {
            name: "default".to_owned(),
            manifest,
            runner: replacement.clone(),
            spawn: Some(spec),
            cleanup_dir: None,
        })
        .unwrap_err();
    assert!(error.contains("shutting down"), "{error}");
    assert!(!replacement.is_alive());

    runtime.reset();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !runtime.runner().is_alive(),
        "reset must not install a runner after shutdown begins"
    );
}

#[tokio::test]
async fn rejected_manifest_reload_keeps_the_eventarc_generation_and_table() {
    let (runtime, _clock) = start().await;
    let before = runtime.eventarc_triggers().unwrap();
    let generation = runtime.trigger_generation();
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spawn = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(20),
    };
    let replacement = Arc::new(Runner::spawn_spec(&spawn).await.unwrap());
    let mut changed = runtime.manifest().clone();
    changed
        .functions
        .retain(|function| function.name != "customEvent");
    let error = runtime
        .reload_codebase(CodebaseSpec {
            name: "default".to_owned(),
            manifest: changed,
            runner: replacement.clone(),
            spawn: Some(spawn),
            cleanup_dir: None,
        })
        .unwrap_err();
    assert!(error.contains("changed its trigger manifest"), "{error}");
    assert_eq!(runtime.trigger_generation(), generation);
    assert_eq!(runtime.eventarc_triggers().unwrap(), before);
    assert!(!replacement.is_alive());
    runtime.shutdown().await;
}

#[tokio::test]
async fn hot_reload_rejects_a_policy_only_blocking_auth_manifest_change() {
    let (runtime, _clock) = start_with_policies_and_manifest(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        |manifest| {
            let mut blocking = parse_manifest(&json!({"functions": [{
                "name": "policyGuard",
                "trigger": {
                    "type": "blockingAuth",
                    "eventType": "beforeSignIn",
                    "accessToken": true
                }
            }]}))
            .unwrap();
            manifest.functions.append(&mut blocking.functions);
        },
    )
    .await;
    let generation = runtime.trigger_generation();
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spawn = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(20),
    };
    let replacement = Arc::new(Runner::spawn_spec(&spawn).await.unwrap());
    let mut changed = runtime.manifest().clone();
    let guard = changed
        .functions
        .iter_mut()
        .find(|function| function.name == "policyGuard")
        .unwrap();
    let Trigger::BlockingAuth { token_policy, .. } = &mut guard.trigger else {
        unreachable!();
    };
    token_policy.id_token = true;

    let error = runtime
        .reload_codebase(CodebaseSpec {
            name: "default".to_owned(),
            manifest: changed,
            runner: replacement.clone(),
            spawn: Some(spawn),
            cleanup_dir: None,
        })
        .unwrap_err();
    assert!(error.contains("changed its trigger manifest"), "{error}");
    assert_eq!(runtime.trigger_generation(), generation);
    assert!(!replacement.is_alive());
    runtime.shutdown().await;
}

#[tokio::test]
async fn omitted_second_generation_concurrency_admits_two_http_requests() {
    let (runtime, _clock) = start_with_policies_and_manifest(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        |manifest| {
            let hold = manifest
                .functions
                .iter_mut()
                .find(|function| function.name == "hold")
                .unwrap();
            hold.platform_options.available_memory_mb = Some(512);
            hold.platform_options.max_instances = Some(1);
        },
    )
    .await;
    let target = runtime
        .http_target("demo-app", "us-central1", "hold")
        .unwrap();

    let first = runtime.invoke_http(&target, "POST", "/hold", &[], &[]);
    let second = runtime.invoke_http(&target, "POST", "/hold", &[], &[]);
    let (first, second) = tokio::join!(first, second);

    assert_eq!(first.unwrap().status, 204);
    assert_eq!(second.unwrap().status, 204);
    runtime.runner().shutdown().await;
}

#[tokio::test]
async fn blocking_auth_admission_shares_the_global_functions_budget() {
    let (runtime, _clock) = start_with_policies_and_manifest(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        |manifest| {
            let mut blocking = parse_manifest(&json!({"functions": [{
                "name": "beforeCreate",
                "generation": 2,
                "trigger": {"type": "blockingAuth", "eventType": "beforeCreate", "accessToken": true, "idToken": false, "refreshToken": true}
            }, {
                "name": "limitedBeforeSignIn",
                "generation": 2,
                "concurrency": 1,
                "platformOptions": {"maxInstances": 1},
                "trigger": {"type": "blockingAuth", "eventType": "beforeSignIn"}
            }]}))
            .unwrap();
            manifest.functions.append(&mut blocking.functions);
        },
    )
    .await;
    let mut admissions = Vec::new();
    for _ in 0..4 {
        let (target, admission) = runtime
            .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
            .unwrap()
            .unwrap();
        assert!(target.token_policy.access_token);
        assert!(!target.token_policy.id_token);
        assert!(target.token_policy.refresh_token);
        admissions.push(admission);
    }
    assert!(runtime
        .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
        .is_err());

    let target = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    let refusal = runtime
        .invoke_http(&target, "POST", "/", &[], &[])
        .await
        .unwrap_err();
    assert!(refusal.contains("concurrency limit"), "{refusal}");

    admissions.pop();
    let (_, replacement) = runtime
        .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
        .unwrap()
        .unwrap();
    drop(replacement);
    drop(admissions);
    let (_, limited) = runtime
        .try_admit_blocking_auth(BlockingAuthEvent::BeforeSignIn)
        .unwrap()
        .unwrap();
    assert!(runtime
        .try_admit_blocking_auth(BlockingAuthEvent::BeforeSignIn)
        .is_err());
    drop(limited);
    assert!(runtime.is_idle());
    runtime.runner().shutdown().await;
}

#[tokio::test]
async fn an_http_invocation_can_exhaust_the_shared_blocking_auth_budget() {
    let (runtime, _clock) = start_with_runtime_options(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        1,
        true,
        |manifest| {
            let mut blocking = parse_manifest(&json!({"functions": [{
                "name": "beforeCreate",
                "generation": 2,
                "trigger": {"type": "blockingAuth", "eventType": "beforeCreate"}
            }]}))
            .unwrap();
            manifest.functions.append(&mut blocking.functions);
        },
    )
    .await;
    let target = runtime
        .http_target("demo-app", "us-central1", "hold")
        .unwrap();
    let invoking = {
        let runtime = runtime.clone();
        tokio::spawn(async move {
            runtime
                .invoke_http(&target, "POST", "/hold", &[], &[])
                .await
        })
    };
    for _ in 0..100 {
        if !runtime.is_idle() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        !runtime.is_idle(),
        "the HTTP invocation did not reserve its slot"
    );
    assert!(runtime
        .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
        .is_err());
    assert_eq!(invoking.await.unwrap().unwrap().status, 204);
    runtime.runner().shutdown().await;
}

#[tokio::test]
async fn a_stuck_blocking_auth_invocation_recycles_its_runner() {
    let (runtime, _clock) = start_with_policies_and_manifest(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        |manifest| {
            let mut blocking = parse_manifest(&json!({"functions": [{
                "name": "beforeCreate",
                "generation": 2,
                "trigger": {"type": "blockingAuth", "eventType": "beforeCreate"}
            }]}))
            .unwrap();
            manifest.functions.append(&mut blocking.functions);
        },
    )
    .await;
    let retired = runtime.runner();
    let (target, admission) = runtime
        .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
        .unwrap()
        .unwrap();
    drop(admission);
    assert!(runtime.restart_runner_after_blocking_failure(&target));
    assert!(!runtime.restart_runner_after_blocking_failure(&target));
    assert!(runtime
        .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
        .is_err());

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let replacement = runtime.runner();
        if !Arc::ptr_eq(&retired, &replacement) && replacement.is_alive() {
            assert!(
                !runtime.restart_runner_after_blocking_failure(&target),
                "a retired target must not restart the live replacement"
            );
            replacement.shutdown().await;
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the stuck runner was not replaced"
        );
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn a_non_respawnable_blocking_runner_is_not_killed_after_transport_failure() {
    let (runtime, _clock) = start_with_runtime_options(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        1,
        false,
        |manifest| {
            let mut blocking = parse_manifest(&json!({"functions": [{
                "name": "beforeCreate",
                "generation": 2,
                "trigger": {"type": "blockingAuth", "eventType": "beforeCreate"}
            }]}))
            .unwrap();
            manifest.functions.append(&mut blocking.functions);
        },
    )
    .await;
    let runner = runtime.runner();
    let (target, admission) = runtime
        .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
        .unwrap()
        .unwrap();
    drop(admission);

    assert!(!runtime.restart_runner_after_blocking_failure(&target));
    assert!(runner.is_alive());
    assert!(Arc::ptr_eq(&runner, &runtime.runner()));
    runner.kill_now();
    assert!(
        runtime
            .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
            .is_err(),
        "a dead runner without a restart ticket must fail closed"
    );
    runner.shutdown().await;
}

#[tokio::test]
async fn a_blocking_restart_cannot_replace_a_newer_hot_reload_generation() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let fast = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(20),
    };
    let mut slow = fast.clone();
    slow.env = vec![("FIREEMU_FAKE_HELLO_DELAY_MS".to_owned(), "500".to_owned())];
    let initial = Runner::spawn_spec(&fast).await.unwrap();
    let mut manifest = parse_manifest(initial.hello().manifest.as_ref().unwrap()).unwrap();
    let mut blocking = parse_manifest(&json!({"functions": [{
        "name": "beforeCreate",
        "generation": 2,
        "trigger": {"type": "blockingAuth", "eventType": "beforeCreate"}
    }]}))
    .unwrap();
    manifest.functions.append(&mut blocking.functions);
    let runtime = FunctionsRuntime::new(
        manifest.clone(),
        FunctionsConfig {
            project: "demo-app".into(),
            default_bucket: "demo-app.appspot.com".into(),
            location: "nam5".into(),
            session: SessionId::new(7),
            max_running: 1,
            debug_mode: false,
            retry_attempts: 1,
            max_catch_up_runs: 1,
            runner_secret: "s".into(),
            overlap: fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
            catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::All,
            functions_host: None,
        },
        Arc::new(Mutex::new(VirtualClock::new(START))),
        Arc::new(initial),
        Some(slow),
    );
    let before_reload = runtime.eventarc_triggers().unwrap().to_string();
    assert!(
        before_reload.contains("us-central1-customEvent-0-locations/us-central1/channels/custom")
    );
    let (target, admission) = runtime
        .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
        .unwrap()
        .unwrap();
    drop(admission);
    assert!(runtime.restart_runner_after_blocking_failure(&target));

    tokio::time::sleep(Duration::from_millis(50)).await;
    let replacement = Arc::new(Runner::spawn_spec(&fast).await.unwrap());
    let expected = replacement.clone();
    runtime
        .reload_codebase(CodebaseSpec {
            name: "default".to_owned(),
            manifest,
            runner: replacement,
            spawn: Some(fast),
            cleanup_dir: None,
        })
        .unwrap();
    let after_reload = runtime.eventarc_triggers().unwrap().to_string();
    assert!(
        !after_reload.contains("us-central1-customEvent-0-locations/us-central1/channels/custom")
    );
    assert!(
        after_reload.contains("us-central1-customEvent-1-locations/us-central1/channels/custom")
    );

    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(Arc::ptr_eq(&runtime.runner(), &expected));
    assert!(expected.is_alive());
    expected.shutdown().await;
}

#[tokio::test]
async fn max_instances_caps_http_admission_before_the_global_limit() {
    let (runtime, _clock) = start_with_policies_and_manifest(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        |manifest| {
            let hold = manifest
                .functions
                .iter_mut()
                .find(|function| function.name == "hold")
                .unwrap();
            hold.concurrency = Some(1);
            hold.platform_options.max_instances = Some(1);
        },
    )
    .await;
    let target = runtime
        .http_target("demo-app", "us-central1", "hold")
        .unwrap();
    let first_runtime = runtime.clone();
    let first_target = target.clone();
    let first = tokio::spawn(async move {
        first_runtime
            .invoke_http(&first_target, "POST", "/hold", &[], &[])
            .await
    });
    for _ in 0..100 {
        if !runtime.is_idle() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(!runtime.is_idle(), "the first HTTP request did not enter");

    let second = runtime
        .invoke_http(&target, "POST", "/hold", &[], &[])
        .await
        .unwrap_err();
    assert!(second.contains("concurrency limit"), "{second}");
    assert_eq!(first.await.unwrap().unwrap().status, 204);
    runtime.runner().shutdown().await;
}

#[tokio::test]
async fn events_are_dispatched_and_retried_in_virtual_time() {
    let (runtime, clock) = start().await;
    assert!(runtime.is_idle());
    // items/a is created: `ok` (created) and `fail` (written) both match.
    runtime.on_commit(&commit(vec![DocumentChange {
        path: doc("items/a", 1).path,
        before: None,
        after: Some(doc("items/a", 1).into()),
    }]));
    assert!(!runtime.is_idle());
    // `fail` retries: the session stays busy until virtual time releases the retry.
    let waited = runtime.await_idle(Duration::from_millis(800)).await;
    assert!(waited.is_err(), "retry-waiting keeps the session busy");
    let history = runtime.history();
    assert!(history
        .iter()
        .any(|r| r.function == "ok" && r.outcome == "ok"));
    assert!(history
        .iter()
        .any(|r| r.function == "fail" && r.attempt == 1 && r.outcome.starts_with("failed")));
    // Retries: attempts 2..4 happen as the clock advances (backoff 10s, 20s, 40s).
    for _ in 0..3 {
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(60))
            .unwrap();
        runtime.on_clock_changed();
        let _ = runtime.await_idle(Duration::from_millis(500)).await;
    }
    assert!(runtime.await_idle(Duration::from_secs(2)).await.is_ok());
    let dead = runtime.dead_letters();
    assert_eq!(dead.len(), 1, "{dead:?}");
    assert_eq!((dead[0].function.as_str(), dead[0].attempt), ("fail", 4));
    // A non-matching path fires nothing.
    runtime.on_commit(&commit(vec![DocumentChange {
        path: doc("other/x", 1).path,
        before: None,
        after: Some(doc("other/x", 1).into()),
    }]));
    assert!(runtime.is_idle());
    // Schedules: the retries advanced 3 minutes; 12 more make 15, i.e. three "every 5
    // minutes" runs (catch-up enqueues every missed run).
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(12 * 60))
        .unwrap();
    runtime.on_clock_changed();
    assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
    let ticks = runtime
        .history()
        .iter()
        .filter(|r| r.function == "tick")
        .count();
    assert_eq!(ticks, 3);
    runtime.run_schedule("tick").unwrap();
    assert!(runtime.run_schedule("ok").is_err(), "not a schedule");
    assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
    // Storage: the slow function times out (1s) and is dead-lettered (no retry).
    let mut store = StorageState::new(1);
    let meta = store
        .put(
            &BucketName::try_new("demo-app.appspot.com").unwrap(),
            &ObjectName::try_new("a.txt").unwrap(),
            b"x".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            START,
        )
        .unwrap();
    runtime.on_storage_event(&StorageEvent::Finalized(meta));
    // The event is dead-lettered at the deadline, but the handler is still running in the
    // runner, so the session is not idle until it finishes.
    let busy = runtime.await_idle(Duration::from_secs(3)).await;
    assert!(busy.is_err(), "{busy:?}");
    assert!(runtime
        .dead_letters()
        .iter()
        .any(|r| r.function == "slow" && r.outcome == "timeout"));
    assert_eq!(runtime.status()["running"], 1);
    let status = runtime.status();
    assert_eq!(
        status["running"], 1,
        "the hung handler still holds its slot"
    );
    assert_eq!(status["deadLettered"], 2);
    // Killing the runner releases the slot and stops dispatch.
    runtime.runner().shutdown().await;
    assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
    assert!(!runtime.runner_alive());
}

#[tokio::test]
async fn reset_discards_in_flight_work() {
    let (runtime, _clock) = start().await;
    runtime.on_commit(&commit(vec![DocumentChange {
        path: doc("items/b", 1).path,
        before: Some(doc("items/b", 0).into()),
        after: Some(doc("items/b", 1).into()),
    }]));
    // `fail` (written) will be retry-waiting; a reset drops it, kills the runner and
    // restarts it, after which dispatch resumes.
    let _ = runtime.await_idle(Duration::from_millis(500)).await;
    assert!(!runtime.is_idle());
    runtime.reset();
    assert!(runtime.is_idle());
    assert_eq!(runtime.status()["epoch"], 1);
    for _ in 0..100 {
        if runtime.runner_alive() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(runtime.runner_alive(), "the runner was restarted");
    runtime.on_commit(&commit(vec![DocumentChange {
        path: doc("items/c", 1).path,
        before: None,
        after: Some(doc("items/c", 1).into()),
    }]));
    let _ = runtime.await_idle(Duration::from_secs(5)).await;
    assert!(runtime
        .history()
        .iter()
        .any(|r| r.function == "ok" && r.outcome == "ok" && r.event_id > 1));
    runtime.runner().shutdown().await;
}

#[tokio::test]
async fn reload_generation_wins_over_an_older_reset_respawn() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let fast = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(20),
    };
    let mut slow = fast.clone();
    slow.env = vec![("FIREEMU_FAKE_HELLO_DELAY_MS".to_owned(), "500".to_owned())];
    let initial = Runner::spawn_spec(&fast).await.unwrap();
    let manifest = parse_manifest(initial.hello().manifest.as_ref().unwrap()).unwrap();
    let clock = Arc::new(Mutex::new(VirtualClock::new(START)));
    let runtime = FunctionsRuntime::new(
        manifest.clone(),
        FunctionsConfig {
            project: "demo-app".into(),
            default_bucket: "demo-app.appspot.com".into(),
            location: "nam5".into(),
            session: SessionId::new(7),
            max_running: 4,
            debug_mode: false,
            retry_attempts: 4,
            max_catch_up_runs: 1000,
            runner_secret: "s".into(),
            overlap: fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
            catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::All,
            functions_host: None,
        },
        clock,
        Arc::new(initial),
        Some(slow),
    );

    runtime.reset();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let replacement = Arc::new(Runner::spawn_spec(&fast).await.unwrap());
    let expected = replacement.clone();
    runtime
        .reload_codebase(CodebaseSpec {
            name: "default".to_owned(),
            manifest,
            runner: replacement,
            spawn: Some(fast),
            cleanup_dir: None,
        })
        .unwrap();

    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(Arc::ptr_eq(&runtime.runner(), &expected));
    assert!(runtime.runner_alive());
}

#[tokio::test]
async fn a_crash_fault_still_kills_a_runner_that_cannot_be_respawned() {
    use fireemu_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule, FaultState};

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(20),
    };
    let runner = Runner::spawn_spec(&spec).await.unwrap();
    let manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            project: "demo-app".into(),
            default_bucket: "demo-app.appspot.com".into(),
            location: "nam5".into(),
            session: SessionId::new(7),
            max_running: 4,
            debug_mode: false,
            retry_attempts: 4,
            max_catch_up_runs: 1000,
            runner_secret: "s".into(),
            overlap: fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
            catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::All,
            functions_host: None,
        },
        Arc::new(Mutex::new(VirtualClock::new(START))),
        Arc::new(runner),
        None,
    );
    let faults = Arc::new(Mutex::new(FaultState::default()));
    faults.lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "functions.invoke".into(),
                nth: None,
                function: Some("echo".into()),
                event_type: None,
            },
            action: FaultAction::CrashRunner,
        }],
    });
    runtime.set_faults(faults);
    let target = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();

    let error = runtime
        .invoke_http(&target, "GET", "/", &[], &[])
        .await
        .unwrap_err();
    assert!(
        error.contains("runner crashed"),
        "unexpected error: {error}"
    );
    assert!(!runtime.runner_alive());
}

#[tokio::test]
async fn schedule_retry_options_control_attempts_and_logical_backoff() {
    let (runtime, clock) = start().await;
    runtime.run_schedule("failSchedule").unwrap();
    let _ = runtime.await_idle(Duration::from_millis(200)).await;
    assert_eq!(
        runtime
            .history()
            .iter()
            .filter(|record| record.function == "failSchedule")
            .count(),
        1
    );

    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(3))
        .unwrap();
    runtime.on_clock_changed();
    let _ = runtime.await_idle(Duration::from_millis(200)).await;
    assert_eq!(
        runtime
            .history()
            .iter()
            .filter(|record| record.function == "failSchedule")
            .count(),
        2
    );

    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(6))
        .unwrap();
    runtime.on_clock_changed();
    assert!(runtime.await_idle(Duration::from_secs(2)).await.is_ok());
    let attempts: Vec<u32> = runtime
        .history()
        .iter()
        .filter(|record| record.function == "failSchedule")
        .map(|record| record.attempt)
        .collect();
    assert_eq!(attempts, vec![1, 2, 3]);
    assert!(runtime
        .dead_letters()
        .iter()
        .any(|record| record.function == "failSchedule" && record.attempt == 3));
    runtime.runner().shutdown().await;
}

#[test]
fn manifest_json_round_trips_and_rejects_bad_input() {
    let v = json!({"functions": [
        {"name": "a", "generation": 1, "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.updated", "document": "x/{id}"}, "timeoutSeconds": 5, "retry": true},
        {"name": "b", "generation": 2, "concurrency": null, "trigger": {"type": "callable"}, "platformOptions": {"preserveExternalChanges": true, "availableMemoryMb": 1024, "minInstances": 1, "maxInstances": 5, "cpu": "gcf_gen1", "ingressSettings": "ALLOW_INTERNAL_ONLY", "invoker": ["public"], "serviceAccountEmail": "runner@example.test", "vpcConnector": "connector", "vpcEgressSettings": "PRIVATE_RANGES_ONLY", "networkInterfaces": [{"network": "default", "tags": ["local"]}], "labels": {"team": "emulator"}, "secrets": ["API_KEY"]}},
        {"name": "c", "trigger": {"type": "schedule", "schedule": "0 3 * * *", "timeZone": "Asia/Tokyo", "retryConfig": {"retryCount": 4, "maxRetrySeconds": 90, "maxBackoffSeconds": 30, "maxDoublings": 2, "minBackoffSeconds": 3}}, "region": "asia-northeast1", "retry": true},
        {"name": "d", "trigger": {"type": "storage", "eventType": "google.cloud.storage.object.v1.deleted", "bucket": "b"}},
        {"name": "e", "trigger": {"type": "blockingAuth", "eventType": "providers/cloud.auth/eventTypes/user.beforeSignIn", "accessToken": true, "idToken": false, "refreshToken": true}}
    ]});
    let m = parse_manifest(&v).unwrap();
    assert_eq!(m.functions.len(), 5);
    assert_eq!(m.functions[2].region, "asia-northeast1");
    let back = manifest_to_json(&m);
    assert_eq!(back["functions"][0]["retry"], true);
    assert_eq!(back["functions"][0]["generation"], 1);
    assert_eq!(back["functions"][1]["trigger"]["callable"], true);
    assert_eq!(back["functions"][1]["generation"], 2);
    assert!(back["functions"][1]["concurrency"].is_null());
    assert_eq!(
        back["functions"][1]["platformOptions"],
        v["functions"][1]["platformOptions"]
    );
    assert_eq!(
        back["functions"][2]["trigger"]["retryConfig"],
        json!({
            "retryCount": 4,
            "maxRetrySeconds": 90,
            "maxBackoffSeconds": 30,
            "maxDoublings": 2,
            "minBackoffSeconds": 3,
        })
    );
    assert_eq!(back["functions"][4]["trigger"]["eventType"], "beforeSignIn");
    assert_eq!(back["functions"][4]["trigger"]["accessToken"], true);
    assert_eq!(back["functions"][4]["trigger"]["idToken"], false);
    assert_eq!(back["functions"][4]["trigger"]["refreshToken"], true);
    for bad in [
        json!({"functions": [{"name": "x", "trigger": {"type": "firestore", "eventType": "nope", "document": "a/{b}"}}]}),
        json!({"functions": [{"name": "x", "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.created", "document": "a"}}]}),
        json!({"functions": [{"name": "x", "trigger": {"type": "schedule", "schedule": "* * * * *", "timeZone": "Mars/Olympus"}}]}),
        json!({"functions": [{"name": "x", "trigger": {"type": "pubsub"}}]}),
        json!({"functions": [{"name": "x", "trigger": {"type": "blockingAuth", "eventType": "beforeSignIn", "accessToken": "yes"}}]}),
        json!({"functions": [{"name": "x", "trigger": {"type": "http"}}, {"name": "x", "trigger": {"type": "http"}}]}),
        json!({"nope": 1}),
    ] {
        assert!(parse_manifest(&bad).is_err(), "{bad}");
    }
    assert!(parse_manifest(&json!({
        "functions": [{"name": "bad", "generation": 3, "trigger": {"type": "http"}}]
    }))
    .is_err());
}

#[test]
fn blocking_auth_manifest_round_trips_all_token_policies() {
    for bits in 0_u8..8 {
        let access_token = bits & 1 != 0;
        let id_token = bits & 2 != 0;
        let refresh_token = bits & 4 != 0;
        let input = json!({"functions": [{
            "name": format!("policy{bits}"),
            "trigger": {
                "type": "blockingAuth",
                "eventType": "beforeSignIn",
                "accessToken": access_token,
                "idToken": id_token,
                "refreshToken": refresh_token
            }
        }]});
        let manifest = parse_manifest(&input).unwrap();
        let output = manifest_to_json(&manifest);
        assert_eq!(
            output["functions"][0]["trigger"],
            input["functions"][0]["trigger"]
        );
    }
}

#[test]
fn manifest_json_preserves_fractional_task_dispatch_rates() {
    let manifest = parse_manifest(&json!({"functions": [{
        "name": "fractionalQueue",
        "generation": 2,
        "trigger": {
            "type": "tasks",
            "rateLimits": {
                "maxConcurrentDispatches": 1,
                "maxDispatchesPerSecond": 0.5
            }
        }
    }]}))
    .unwrap();

    let Trigger::TaskQueue { rate_limits, .. } = manifest.functions[0].trigger else {
        panic!("expected a task queue trigger");
    };
    assert!((rate_limits.max_dispatches_per_second - 0.5).abs() < f64::EPSILON);
    assert_eq!(
        manifest_to_json(&manifest)["functions"][0]["trigger"]["rateLimits"]
            ["maxDispatchesPerSecond"],
        0.5
    );
}

#[test]
fn manifest_json_requires_generation_for_second_generation_capacity_options() {
    for field in [
        json!({"concurrency": 1}),
        json!({"platformOptions": {"cpu": "gcf_gen1"}}),
        json!({"platformOptions": {"networkInterfaces": [{"network": "default"}]}}),
    ] {
        let mut function = json!({"name": "ambiguous", "trigger": {"type": "http"}});
        function.as_object_mut().unwrap().extend(
            field
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        let error = parse_manifest(&json!({"functions": [function]})).unwrap_err();
        assert!(error.contains("generation"), "{error}");
    }

    let legacy = parse_manifest(&json!({"functions": [{
        "name": "legacy",
        "trigger": {"type": "http"},
        "platformOptions": {"availableMemoryMb": 512, "minInstances": 1, "maxInstances": 3}
    }]}))
    .unwrap();
    assert_eq!(legacy.functions[0].generation, FunctionGeneration::First);
    assert_eq!(legacy.functions[0].effective_concurrency(), 1);
    assert_eq!(legacy.functions[0].http_capacity(100), 3);

    let second = parse_manifest(&json!({"functions": [
        {"name": "defaultCpu", "generation": 2, "trigger": {"type": "http"}},
        {"name": "legacyCpu", "generation": 2, "trigger": {"type": "http"}, "platformOptions": {"cpu": "gcf_gen1"}}
    ]}))
    .unwrap();
    assert_eq!(second.functions[0].effective_concurrency(), 80);
    assert_eq!(second.functions[1].effective_concurrency(), 1);
}

#[test]
fn cloudevents_carry_the_shapes_the_sdk_decodes() {
    let before = doc("todos/t1", 1);
    let after = doc("todos/t1", 2);
    let e = firestore_event(
        "e1",
        "demo-app",
        fireemu_core_types::ids::DatabaseId::DEFAULT,
        "nam5",
        "todos/t1",
        DocumentEvent::Updated,
        Some(&before),
        Some(&after),
        START,
        None,
    );
    assert_eq!(e["type"], "google.cloud.firestore.document.v1.updated");
    assert_eq!(
        e["source"],
        "projects/demo-app/databases/(default)/documents/todos/t1"
    );
    assert_eq!(e["subject"], "documents/todos/t1");
    assert_eq!(e["document"], "todos/t1");
    assert_eq!(e["database"], fireemu_core_types::ids::DatabaseId::DEFAULT);
    assert_eq!(e["datacontenttype"], "application/json");
    assert_eq!(e["data"]["value"]["fields"]["v"]["integerValue"], "2");
    assert_eq!(e["data"]["oldValue"]["fields"]["v"]["integerValue"], "1");
    assert_eq!(e["data"]["updateMask"]["fieldPaths"], json!(["v"]));
    let created = firestore_event(
        "e2",
        "demo-app",
        fireemu_core_types::ids::DatabaseId::DEFAULT,
        "nam5",
        "todos/t1",
        DocumentEvent::Created,
        None,
        Some(&after),
        START,
        None,
    );
    assert!(created["data"].get("oldValue").is_none());
    assert!(created["data"].get("updateMask").is_none());
    let mut store = StorageState::new(1);
    let meta = store
        .put(
            &BucketName::try_new("demo-app.appspot.com").unwrap(),
            &ObjectName::try_new("dir/a.txt").unwrap(),
            b"abc".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            START,
        )
        .unwrap();
    let s = storage_event("e3", ObjectEvent::Finalized, &meta, START);
    assert_eq!(s["type"], "google.cloud.storage.object.v1.finalized");
    assert_eq!(s["bucket"], "demo-app.appspot.com");
    assert_eq!(s["subject"], "objects/dir/a.txt");
    assert_eq!(s["data"]["size"], "3");
    assert_eq!(s["data"]["name"], "dir/a.txt");
    assert!(s["data"]["selfLink"]
        .as_str()
        .unwrap()
        .ends_with("/o/dir%2Fa.txt"));
}

#[test]
fn http_responses_are_parsed_with_every_body_framing() {
    let chunked = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n1\r\n!\r\n0\r\n\r\n";
    let r = parse_response(chunked, "GET").unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, &b"hello!"[..]));
    assert_eq!(
        r.headers,
        vec![("Content-Type".to_owned(), "text/plain".to_owned())]
    );
    let hop_by_hop = b"HTTP/1.1 200 OK\r\nConnection: x-private\r\nx-private: secret\r\nUpgrade: websocket\r\nTE: trailers\r\nTrailer: x-checksum\r\nProxy-Authenticate: Basic\r\nProxy-Authorization: Basic secret\r\nx-public: value\r\nContent-Length: 2\r\n\r\nok";
    assert_eq!(
        parse_response(hop_by_hop, "GET").unwrap().headers,
        vec![("x-public".to_owned(), "value".to_owned())]
    );
    let sized = b"HTTP/1.1 404 Not Found\r\ncontent-length: 3\r\n\r\nnopIGNORED";
    assert_eq!(parse_response(sized, "GET").unwrap().body, b"nop");
    // HEAD and body-less statuses omit the declared body; a truncated GET is an error.
    let head = b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\n";
    assert!(parse_response(head, "HEAD").unwrap().body.is_empty());
    assert!(parse_response(head, "GET").is_err());
    assert!(parse_response(b"HTTP/1.1 204 No Content\r\n\r\n", "GET")
        .unwrap()
        .body
        .is_empty());
    let closed = b"HTTP/1.1 500 X\r\n\r\nwhole body";
    assert_eq!(parse_response(closed, "GET").unwrap().body, b"whole body");
    assert!(parse_response(b"garbage", "GET").is_err());
    assert!(parse_response(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nshort", "GET").is_err());
}

#[test]
fn iana_zones_follow_daylight_saving_time() {
    use fireemu_adapter_functions::zone::resolve;
    use fireemu_core_functions::cron::Schedule;
    let t = |s: &str| LogicalInstant::parse_rfc3339(s).unwrap();
    let ny = resolve(Some("America/New_York")).unwrap();
    let nine = Schedule::parse("0 9 * * *").unwrap();
    // EST (UTC-5) in January, EDT (UTC-4) in July.
    assert_eq!(
        nine.next_after_in(t("2026-01-10T00:00:00Z"), &*ny).unwrap(),
        t("2026-01-10T14:00:00Z")
    );
    assert_eq!(
        nine.next_after_in(t("2026-07-10T00:00:00Z"), &*ny).unwrap(),
        t("2026-07-10T13:00:00Z")
    );
    // 2026-03-08: clocks jump from 02:00 to 03:00; a 02:30 schedule has no run that day.
    let half_past_two = Schedule::parse("30 2 * * *").unwrap();
    assert_eq!(
        half_past_two
            .next_after_in(t("2026-03-08T00:00:00Z"), &*ny)
            .unwrap(),
        t("2026-03-09T06:30:00Z"),
        "the gap day is skipped; 02:30 EDT on the 9th is 06:30Z"
    );
    // 2026-11-01: 01:30 happens twice; the schedule runs once, at the first occurrence.
    let half_past_one = Schedule::parse("30 1 * * *").unwrap();
    let runs = half_past_one.runs_between_in(
        t("2026-11-01T00:00:00Z"),
        t("2026-11-02T00:00:00Z"),
        &*ny,
        10,
    );
    assert_eq!(runs, vec![t("2026-11-01T05:30:00Z")]);
    // Fixed-offset aliases and unknown zones.
    assert!(resolve(Some("Asia/Tokyo")).is_ok());
    assert!(resolve(Some("Mars/Olympus")).is_err());
    assert!(!fireemu_adapter_functions::zone::database_version().is_empty());
}

#[tokio::test]
async fn overlap_policies_skip_queue_or_reject_concurrent_schedule_runs() {
    use fireemu_adapter_functions::runtime::OverlapPolicy;
    // reject: a second due run while the first is queued is a counted dead letter.
    let (runtime, _clock) = start_with(OverlapPolicy::Reject).await;
    runtime.run_schedule("tick").unwrap();
    let second = runtime.run_schedule("tick");
    assert!(second.is_err(), "{second:?}");
    assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
    assert_eq!(runtime.status()["overlapRejected"], 1);
    assert!(runtime
        .dead_letters()
        .iter()
        .any(|r| r.function == "tick" && r.outcome == "rejected: overlap"));
    runtime.runner().shutdown().await;
    // skip: the second run is dropped and recorded.
    let (runtime, _clock) = start_with(OverlapPolicy::Skip).await;
    runtime.run_schedule("tick").unwrap();
    assert!(runtime.run_schedule("tick").is_err());
    assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
    assert!(runtime
        .history()
        .iter()
        .any(|r| r.function == "tick" && r.outcome == "skipped: overlap"));
    assert_eq!(runtime.status()["overlapRejected"], 0);
    runtime.runner().shutdown().await;
    // queue: both runs happen, one after the other.
    let (runtime, _clock) = start_with(OverlapPolicy::Queue).await;
    runtime.run_schedule("tick").unwrap();
    runtime.run_schedule("tick").unwrap();
    assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
    assert_eq!(
        runtime
            .history()
            .iter()
            .filter(|r| r.function == "tick" && r.outcome == "ok")
            .count(),
        2
    );
    runtime.runner().shutdown().await;
}

#[tokio::test]
async fn pubsub_messages_and_auth_user_events_reach_their_functions() {
    use fireemu_core_auth::mfa::TotpPolicy;
    use fireemu_core_auth::store::{AuthStore, NewUser};
    use fireemu_core_types::determinism::SplitMix64;
    let (runtime, _clock) = start().await;
    // Two messages on a subscribed topic, one on a topic nobody listens to.
    let ids = runtime.publish(
        "jobs",
        &[
            serde_json::json!({"data": "aGVsbG8=", "attributes": {"k": "v"}}),
            serde_json::json!({"data": "d29ybGQ=", "orderingKey": "o1"}),
        ],
    );
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
    let silent = runtime.publish("nobody", &[serde_json::json!({"data": ""})]);
    assert_eq!(silent.len(), 1, "message ids are assigned regardless");
    assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
    let on_job = runtime
        .history()
        .iter()
        .filter(|r| r.function == "onJob" && r.outcome == "ok")
        .count();
    assert_eq!(on_job, 2);
    // A user created and deleted in the Auth store.
    let mut store = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
    let uid = store
        .create_user(NewUser::email("u@example.com"), START)
        .unwrap();
    let mut events = store.take_user_events();
    assert_eq!(events.len(), 1);
    store.delete_user_by_id(uid.as_str()).unwrap();
    events.extend(store.take_user_events());
    assert_eq!(events.len(), 2);
    assert!(store.take_user_events().is_empty(), "drained once");
    for e in &events {
        runtime.on_user_event(e);
    }
    assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
    let names: Vec<String> = runtime
        .history()
        .iter()
        .filter(|r| r.function.starts_with("on") && r.function != "onJob")
        .map(|r| r.function.clone())
        .collect();
    assert_eq!(names, vec!["onUser".to_owned(), "onGone".to_owned()]);
}

#[test]
fn pubsub_and_auth_events_carry_the_shapes_the_sdk_decodes() {
    use fireemu_adapter_functions::events::{auth_event, firestore_event, pubsub_event};
    use fireemu_core_auth::mfa::TotpPolicy;
    use fireemu_core_auth::store::{AuthStore, NewUser};
    use fireemu_core_functions::manifest::{AuthEvent, DocumentEvent};
    use fireemu_core_types::determinism::SplitMix64;
    let msg = serde_json::json!({"data": "aGVsbG8=", "attributes": {"k": "v"}, "orderingKey": "o"});
    let e = pubsub_event("m1", "demo-app", "jobs", &msg, START);
    assert_eq!(e["type"], "google.cloud.pubsub.topic.v1.messagePublished");
    assert_eq!(
        e["source"],
        "//pubsub.googleapis.com/projects/demo-app/topics/jobs"
    );
    assert_eq!(e["data"]["message"]["messageId"], "m1");
    assert_eq!(e["data"]["message"]["data"], "aGVsbG8=");
    assert_eq!(e["data"]["message"]["attributes"]["k"], "v");
    assert_eq!(e["data"]["message"]["orderingKey"], "o");
    assert_eq!(
        e["data"]["subscription"],
        "projects/demo-app/subscriptions/emulator-sub-jobs"
    );
    let mut store = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
    let uid = store
        .create_user(NewUser::email("u@example.com"), START)
        .unwrap();
    let user = store.user(&uid).unwrap().clone();
    let e = auth_event("a1", "demo-app", AuthEvent::Created, &user, START);
    assert_eq!(e["type"], "google.firebase.auth.user.v1.created");
    assert_eq!(e["data"]["uid"], uid.as_str());
    assert_eq!(e["data"]["email"], "u@example.com");
    assert_eq!(e["data"]["emailVerified"], false);
    assert_eq!(e["data"]["providerData"][0]["providerId"], "password");
    assert!(e["data"]["metadata"]["creationTime"].is_string());
    // withAuthContext: the type gains the suffix and the principal travels as attributes.
    let d = doc("audited/x", 1);
    let plain = firestore_event(
        "f1",
        "demo-app",
        fireemu_core_types::ids::DatabaseId::DEFAULT,
        "nam5",
        "audited/x",
        DocumentEvent::Created,
        None,
        Some(&d),
        START,
        None,
    );
    assert_eq!(plain["type"], "google.cloud.firestore.document.v1.created");
    assert!(plain.get("authtype").is_none());
    let with = firestore_event(
        "f2",
        "demo-app",
        fireemu_core_types::ids::DatabaseId::DEFAULT,
        "nam5",
        "audited/x",
        DocumentEvent::Created,
        None,
        Some(&d),
        START,
        Some(("app_user", Some("u1"))),
    );
    assert_eq!(
        with["type"],
        "google.cloud.firestore.document.v1.created.withAuthContext"
    );
    assert_eq!(with["authtype"], "app_user");
    assert_eq!(with["authid"], "u1");
}

#[tokio::test]
async fn with_auth_context_triggers_see_the_committing_principal() {
    let (runtime, _clock) = start().await;
    let mut ev = commit(vec![DocumentChange {
        path: doc("audited/a", 1).path,
        before: None,
        after: Some(doc("audited/a", 1).into()),
    }]);
    ev.actor = fireemu_adapter_grpc::local::Actor {
        auth_type: "app_user".into(),
        auth_id: Some("alice".into()),
    };
    runtime.on_commit(&ev);
    assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
    assert!(runtime
        .history()
        .iter()
        .any(|r| r.function == "withAuth" && r.outcome == "ok"));
}

#[tokio::test]
async fn catch_up_policies_keep_all_the_latest_or_no_due_runs() {
    use fireemu_adapter_functions::runtime::{CatchUpPolicy, OverlapPolicy};
    // Fifteen minutes hold three runs of the "every 5 minutes" schedule. What a policy drops
    // is one summary record per job and clock change, carrying the exact count.
    for (policy, expected_runs, expected_skipped) in [
        (CatchUpPolicy::All, 3, None),
        (
            CatchUpPolicy::Latest,
            1,
            Some("skipped: catch-up latest (2 runs)"),
        ),
        (
            CatchUpPolicy::None,
            0,
            Some("skipped: catch-up none (3 runs)"),
        ),
    ] {
        let (runtime, clock) = start_with_policies(OverlapPolicy::Allow, policy).await;
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(15 * 60))
            .unwrap();
        runtime.on_clock_changed();
        assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
        let history = runtime.history();
        let runs = history
            .iter()
            .filter(|r| r.function == "tick" && r.outcome == "ok")
            .count();
        let skips: Vec<&str> = history
            .iter()
            .filter(|r| r.function == "tick" && r.outcome.starts_with("skipped: catch-up"))
            .map(|r| r.outcome.as_str())
            .collect();
        assert_eq!(runs, expected_runs, "{policy:?}");
        assert_eq!(
            skips,
            expected_skipped.into_iter().collect::<Vec<_>>(),
            "{policy:?}"
        );
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn fault_plans_duplicate_delay_dead_letter_and_crash_the_runner() {
    use fireemu_core_auth::mfa::TotpPolicy;
    use fireemu_core_auth::store::{AuthStore, NewUser};
    use fireemu_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule, FaultState};
    use fireemu_core_types::determinism::SplitMix64;
    let (runtime, clock) = start().await;
    let faults = Arc::new(Mutex::new(FaultState::default()));
    let rule = |operation: &str, function: &str, nth: Option<u64>, action| FaultRule {
        matches: FaultMatch {
            operation: operation.into(),
            nth,
            function: Some(function.into()),
            event_type: None,
        },
        action,
    };
    faults.lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![
            // Deliveries to `onJob` are duplicated twice: three invocations per message.
            rule(
                "functions.deliver",
                "onJob",
                None,
                FaultAction::Duplicate { count: 2 },
            ),
            // `withAuth` invocations are dead-lettered without calling the runner.
            rule(
                "functions.invoke",
                "withAuth",
                None,
                FaultAction::DeadLetter,
            ),
            // `onUser` invocations are held for an hour of virtual time.
            rule(
                "functions.invoke",
                "onUser",
                None,
                FaultAction::Delay { seconds: 3600 },
            ),
            // `onGone` crashes the runner (restarted, the event redelivered).
            rule(
                "functions.invoke",
                "onGone",
                Some(1),
                FaultAction::CrashRunner,
            ),
        ],
    });
    runtime.set_faults(faults);
    runtime.publish("jobs", &[serde_json::json!({"data": ""})]);
    assert!(
        runtime.await_idle(Duration::from_secs(5)).await.is_ok(),
        "{}",
        runtime.status()
    );
    let on_job = runtime
        .history()
        .iter()
        .filter(|r| r.function == "onJob" && r.outcome == "ok")
        .count();
    assert_eq!(on_job, 3, "duplicate x2");
    runtime.on_commit(&commit(vec![DocumentChange {
        path: doc("audited/c", 1).path,
        before: None,
        after: Some(doc("audited/c", 1).into()),
    }]));
    assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
    assert!(runtime
        .dead_letters()
        .iter()
        .any(|d| d.function == "withAuth" && d.outcome.contains("dead letter")));
    assert!(!runtime
        .runner()
        .logs_since(None)
        .lines
        .iter()
        .any(|line| line.display().contains("invoked withAuth")));
    // Delayed: not idle until the clock passes the hold.
    let mut store = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
    let uid = store
        .create_user(NewUser::email("d@example.com"), START)
        .unwrap();
    for e in store.take_user_events() {
        runtime.on_user_event(&e);
    }
    assert!(
        runtime
            .await_idle(Duration::from_millis(500))
            .await
            .is_err(),
        "held by the delay"
    );
    assert!(!runtime.history().iter().any(|r| r.function == "onUser"));
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(3600))
        .unwrap();
    runtime.on_clock_changed();
    assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
    assert!(runtime
        .history()
        .iter()
        .any(|r| r.function == "onUser" && r.outcome == "ok"));
    // Crash: the runner dies on the attempt, a fresh one takes over and the event succeeds.
    store.delete_user_by_id(uid.as_str()).unwrap();
    for e in store.take_user_events() {
        runtime.on_user_event(&e);
    }
    assert!(runtime.await_idle(Duration::from_secs(20)).await.is_ok());
    let on_gone: Vec<String> = runtime
        .history()
        .iter()
        .filter(|r| r.function == "onGone")
        .map(|r| r.outcome.clone())
        .collect();
    assert!(
        on_gone.iter().any(|o| o.starts_with("runner gone")),
        "{on_gone:?}"
    );
    assert!(on_gone.iter().any(|o| o == "ok"), "{on_gone:?}");
    assert!(runtime.runner_alive());
}

#[tokio::test]
async fn catch_up_latest_and_none_stay_idle_beyond_the_cap() {
    use fireemu_adapter_functions::runtime::{CatchUpPolicy, OverlapPolicy};
    // FN-CATCHUP-01 / 02: ten years of an "every 5 minutes" schedule is more than a million
    // occurrences. Neither policy keeps more than one of them, and neither enumerates them:
    // the deterministic work counter stays in the hundreds and the retained history gains one
    // summary record, not one record per missed run.
    for (policy, expected_runs, expected_skipped) in [
        (
            CatchUpPolicy::Latest,
            1,
            "skipped: catch-up latest (1051775 runs)",
        ),
        (
            CatchUpPolicy::None,
            0,
            "skipped: catch-up none (1051776 runs)",
        ),
    ] {
        let (runtime, clock) = start_with_policies(OverlapPolicy::Allow, policy).await;
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(3_652 * 24 * 3600))
            .unwrap();
        runtime.on_clock_changed();
        assert!(
            runtime.await_idle(Duration::from_secs(5)).await.is_ok(),
            "{policy:?}: {}",
            runtime.status()
        );
        let history = runtime.history();
        let runs = history
            .iter()
            .filter(|r| r.function == "tick" && r.outcome == "ok")
            .count();
        assert_eq!(runs, expected_runs, "{policy:?}");
        let skipped: Vec<&str> = history
            .iter()
            .filter(|r| r.function == "tick" && r.outcome.starts_with("skipped: catch-up"))
            .map(|r| r.outcome.as_str())
            .collect();
        assert_eq!(skipped, vec![expected_skipped], "{policy:?}");
        // The cron job in the manifest ("0 3 * * *") has 3652 runs in the same window. A cron
        // schedule is counted forward, so the count stops at the catch-up cap and the summary
        // says so rather than paying for the rest.
        let nightly: Vec<&str> = history
            .iter()
            .filter(|r| r.function == "nightly" && r.outcome.starts_with("skipped: catch-up"))
            .map(|r| r.outcome.as_str())
            .collect();
        assert_eq!(
            nightly,
            vec![match policy {
                CatchUpPolicy::Latest => "skipped: catch-up latest (at least 999 runs)",
                _ => "skipped: catch-up none (at least 1000 runs)",
            }],
            "{policy:?}"
        );
        // Both jobs together: 1.05 million occurrences answered in a few thousand steps.
        assert!(
            runtime.catch_up_steps() <= 20_000,
            "{policy:?}: {} steps for 1055428 occurrences",
            runtime.catch_up_steps()
        );
        assert_eq!(runtime.status()["catchUpPending"], false);
    }
}

#[tokio::test]
async fn scheduled_runs_obey_delivery_faults_and_delays_keep_their_outcome() {
    use fireemu_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule, FaultState};
    let (runtime, clock) = start().await;
    let faults = Arc::new(Mutex::new(FaultState::default()));
    let rule = |operation: &str, nth: Option<u64>, event_type: Option<&str>, action| FaultRule {
        matches: FaultMatch {
            operation: operation.into(),
            nth,
            function: Some("tick".into()),
            event_type: event_type.map(str::to_owned),
        },
        action,
    };
    faults.lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![
            // Scheduled deliveries are duplicated once: two invocations per run.
            rule(
                "functions.deliver",
                None,
                Some("google.cloud.scheduler.job.v1.executed"),
                FaultAction::Duplicate { count: 1 },
            ),
            // The first invocation is held for a minute, then dead-lettered (both actions
            // of the rule set apply, in that order).
            rule(
                "functions.invoke",
                Some(1),
                None,
                FaultAction::Delay { seconds: 60 },
            ),
            rule("functions.invoke", Some(1), None, FaultAction::DeadLetter),
        ],
    });
    runtime.set_faults(faults);
    runtime.run_schedule("tick").unwrap();
    assert!(
        runtime
            .await_idle(Duration::from_millis(500))
            .await
            .is_err(),
        "held by the delay"
    );
    assert!(runtime.dead_letters().iter().all(|d| d.function != "tick"));
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(60))
        .unwrap();
    runtime.on_clock_changed();
    assert!(
        runtime.await_idle(Duration::from_secs(5)).await.is_ok(),
        "{}",
        runtime.status()
    );
    assert!(runtime
        .dead_letters()
        .iter()
        .any(|d| d.function == "tick" && d.outcome.contains("dead letter")));
    assert_eq!(
        runtime
            .history()
            .iter()
            .filter(|r| r.function == "tick" && r.outcome == "ok")
            .count(),
        1,
        "the duplicate ran: {:?}",
        runtime.history()
    );
}

/// A finalized object event for the `slow` function (the fake runner never answers it).
fn slow_object(name: &str) -> StorageEvent {
    let mut store = StorageState::new(1);
    let meta = store
        .put(
            &BucketName::try_new("demo-app.appspot.com").unwrap(),
            &ObjectName::try_new(name).unwrap(),
            b"x".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            START,
        )
        .unwrap();
    StorageEvent::Finalized(meta)
}

#[tokio::test]
async fn a_completion_that_resolves_after_a_reset_appends_no_record() {
    // FN-EPOCH-01 / 02 / 04 / 05: a handler that finishes (or times out) after a reset must
    // not append an invocation record or a dead letter to the new epoch, while the records
    // committed before the reset stay visible.
    let (runtime, _clock) = start().await;
    runtime.on_commit(&commit(vec![DocumentChange {
        path: doc("items/a", 1).path,
        before: None,
        after: Some(doc("items/a", 1).into()),
    }]));
    for _ in 0..100 {
        if runtime
            .history()
            .iter()
            .any(|r| r.function == "ok" && r.outcome == "ok")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        runtime
            .history()
            .iter()
            .any(|r| r.function == "ok" && r.outcome == "ok"),
        "{:?}",
        runtime.history()
    );

    // A `slow` invocation is in flight (1 s deadline, no answer from the runner).
    runtime.on_storage_event(&slow_object("late.txt"));
    for _ in 0..200 {
        if runtime.status()["running"].as_u64().unwrap_or(0) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        runtime.status()["running"].as_u64().unwrap_or(0) > 0,
        "the slow handler is running: {}",
        runtime.status()
    );

    // Two resets while it is unresolved: neither new epoch may observe it.
    runtime.reset();
    runtime.reset();
    // Well past the 1 s deadline of `slow`, so its completion has certainly run.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let after = runtime.history();
    assert!(
        after
            .iter()
            .any(|r| r.function == "ok" && r.outcome == "ok"),
        "the pre-reset record survives: {after:?}"
    );
    assert!(
        !after.iter().any(|r| r.function == "slow"),
        "no stale record reached the new epoch: {after:?}"
    );
    assert!(
        !runtime.dead_letters().iter().any(|r| r.function == "slow"),
        "no stale dead letter reached the new epoch: {:?}",
        runtime.dead_letters()
    );

    // FN-EPOCH-03: a current-epoch completion is still recorded.
    for _ in 0..200 {
        if runtime.runner_alive() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    runtime.on_commit(&commit(vec![DocumentChange {
        path: doc("items/z", 1).path,
        before: None,
        after: Some(doc("items/z", 1).into()),
    }]));
    let _ = runtime.await_idle(Duration::from_secs(5)).await;
    assert!(
        runtime
            .history()
            .iter()
            .filter(|r| r.function == "ok" && r.outcome == "ok")
            .count()
            >= 2,
        "{:?}",
        runtime.history()
    );
    runtime.runner().shutdown().await;
}

#[test]
fn the_bounded_run_window_matches_enumeration_in_iana_zones() {
    // FN-CATCHUP-03 / 04: the direct computation the `latest` and `none` catch-up policies
    // use agrees with the enumerating one against the real daylight-saving rules, across the
    // 2026 spring gap and fall fold and over a year of a southern-hemisphere zone.
    use fireemu_adapter_functions::zone::resolve;
    use fireemu_core_functions::cron::{RunCount, Schedule};
    let t = |s: &str| LogicalInstant::parse_rfc3339(s).unwrap();
    let zones = [
        "America/New_York",
        "Europe/Berlin",
        "Australia/Lord_Howe",
        "Pacific/Chatham",
        "Asia/Tokyo",
    ];
    let schedules = [
        "* * * * *",
        "30 2 * * *",
        "30 1 * * *",
        "0 9 * * *",
        "*/15 9-17 * * mon-fri",
        "0 0 1 * *",
    ];
    let ranges = [
        ("2026-03-07T00:00:00Z", "2026-03-09T12:00:00Z"),
        ("2026-10-03T00:00:00Z", "2026-10-05T12:00:00Z"),
        ("2026-11-01T00:00:00Z", "2026-11-02T12:00:00Z"),
        ("2026-11-01T05:00:00Z", "2026-11-01T06:20:00Z"),
        ("2026-04-04T00:00:00Z", "2026-04-06T00:00:00Z"),
    ];
    for name in zones {
        let zone = resolve(Some(name)).unwrap();
        for source in schedules {
            let s = Schedule::parse(source).unwrap();
            for (from, to) in ranges {
                let (from, to) = (t(from), t(to));
                let expected = s.runs_between_in(from, to, &*zone, 100_000);
                let window = s.window_in(from, to, &*zone, 100_000);
                let label = format!("{name} {source} {from:?}..{to:?}");
                assert_eq!(window.latest, expected.last().copied(), "latest: {label}");
                assert_eq!(
                    window.count,
                    RunCount::Exact(expected.len() as u64),
                    "count: {label}"
                );
            }
        }
    }
}

#[tokio::test]
async fn diagnostic_retention_is_bounded_and_counters_survive_eviction() {
    // FN-RET-01 / 03 / 04: completing twice the retention budget leaves a bounded window in
    // the order the records were made, while the cumulative counters keep every outcome.
    let (runtime, _clock) = start().await;
    runtime.set_retention(8, 4);
    for i in 0..20 {
        let ids = runtime.publish("jobs", &[json!({"n": i})]);
        assert_eq!(ids.len(), 1);
    }
    assert!(
        runtime.await_idle(Duration::from_secs(10)).await.is_ok(),
        "{}",
        runtime.status()
    );
    let history = runtime.history();
    assert_eq!(history.len(), 8, "the retained window is bounded");
    assert!(
        history.iter().all(|r| r.function == "onJob"),
        "the newest records are the ones kept: {history:?}"
    );
    // Oldest first inside the window: the event IDs increase.
    let ids: Vec<u128> = history.iter().map(|r| r.event_id).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "order inside the window is preserved");
    // The cumulative counter kept every success, evicted records included.
    assert_eq!(runtime.status()["succeeded"], 20);
    runtime.runner().shutdown().await;
}

#[tokio::test]
async fn history_cursors_deliver_deltas_and_resync_across_eviction_and_reset() {
    // FN-RET-05 / 06: two readers at different cursors each receive only what they are
    // missing; identical records are still told apart by their sequence; a cursor that fell
    // out of the retained window, and one from before a reset, are answered with an explicit
    // resync instead of a duplicate or a gap.
    use fireemu_adapter_functions::runtime::CatchUpPolicy;
    let (runtime, clock) = start_with_policies(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        CatchUpPolicy::None,
    )
    .await;
    runtime.set_retention(8, 8);

    // A reader from the start sees the empty snapshot.
    let first = runtime.history_since(None);
    assert!(first.records.is_empty() && !first.resync);
    let generation = first.cursor.generation;

    // Two identical skipped-schedule records: same function, same outcome text.
    for _ in 0..2 {
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(15 * 60))
            .unwrap();
        runtime.on_clock_changed();
    }
    let delta = runtime.history_since(Some(first.cursor));
    assert!(!delta.resync);
    let skipped: Vec<&str> = delta
        .records
        .iter()
        .filter(|r| r.record.function == "tick")
        .map(|r| r.record.outcome.as_str())
        .collect();
    assert_eq!(
        skipped,
        vec![
            "skipped: catch-up none (3 runs)",
            "skipped: catch-up none (3 runs)"
        ],
        "identical records, delivered once each"
    );
    let sequences: Vec<u64> = delta.records.iter().map(|r| r.sequence).collect();
    let mut unique = sequences.clone();
    unique.dedup();
    assert_eq!(sequences, unique, "sequences are distinct and increasing");
    assert!(sequences.windows(2).all(|w| w[0] < w[1]));

    // A second reader still on the first cursor gets exactly the same delta; a reader on the
    // new cursor gets nothing.
    let again = runtime.history_since(Some(first.cursor));
    assert_eq!(again.records, delta.records, "cursors are independent");
    let caught_up = runtime.history_since(Some(delta.cursor));
    assert!(caught_up.records.is_empty() && !caught_up.resync);

    // More records than the window holds: the stale cursor can no longer be answered.
    let stale = delta.cursor;
    for _ in 0..12 {
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(15 * 60))
            .unwrap();
        runtime.on_clock_changed();
    }
    let expired = runtime.history_since(Some(stale));
    assert!(expired.resync, "an evicted cursor forces a resync");
    assert_eq!(expired.records.len(), 8, "the resync carries the window");
    assert_eq!(expired.cursor.generation, generation);

    // A reset bumps the generation: the cursor from the previous one is refused as well.
    let before_reset = expired.cursor;
    runtime.reset();
    let after_reset = runtime.history_since(Some(before_reset));
    assert!(after_reset.resync, "a pre-reset cursor forces a resync");
    assert_ne!(
        after_reset.cursor.generation, before_reset.generation,
        "the reset bumped the generation"
    );
    // The records committed before the reset are still visible (cross-epoch history).
    assert!(after_reset
        .records
        .iter()
        .any(|r| r.record.function == "tick"));
    // Sequences keep increasing across the reset, so no record is mistaken for another.
    let highest = after_reset
        .records
        .iter()
        .map(|r| r.sequence)
        .max()
        .unwrap_or(0);
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(15 * 60))
        .unwrap();
    runtime.on_clock_changed();
    let fresh = runtime.history_since(Some(after_reset.cursor));
    assert!(!fresh.resync);
    assert!(
        fresh.records.iter().all(|r| r.sequence > highest),
        "sequences continue past the reset"
    );
    runtime.runner().shutdown().await;
}

#[tokio::test]
async fn resources_report_running_invocations_as_outstanding_roots() {
    use fireemu_core_types::resources::RootBudget;
    let (runtime, _clock) = start().await;
    let idle = runtime.resources(RootBudget::DEFAULT);
    assert_eq!(idle.service, "functions");
    assert_eq!(idle.roots.total, 0);
    let gauge = |report: &fireemu_core_types::resources::ServiceResources, id: &str| {
        report
            .gauges
            .iter()
            .find(|g| g.id == id)
            .unwrap_or_else(|| panic!("{id} in {:?}", report.gauges))
            .clone()
    };
    assert_eq!(
        gauge(&idle, "outbox.records").limit,
        Some(fireemu_adapter_functions::runtime::MAX_ACTIVE_EVENT_RECORDS as u64)
    );
    assert_eq!(
        gauge(&idle, "outbox.bytes").limit,
        Some(fireemu_adapter_functions::runtime::MAX_ACTIVE_EVENT_BYTES as u64)
    );
    assert_eq!(gauge(&idle, "invocations.running").current, 0);

    runtime.on_storage_event(&slow_object("held.txt"));
    for _ in 0..200 {
        if runtime.status()["running"].as_u64().unwrap_or(0) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let busy = runtime.resources(RootBudget::DEFAULT);
    assert_eq!(gauge(&busy, "invocations.running").current, 1);
    assert_eq!(
        gauge(&busy, "invocations.running").limit,
        Some(runtime.max_global_concurrency() as u64)
    );
    let outstanding: Vec<_> = busy.roots.roots.iter().filter(|r| r.outstanding).collect();
    assert!(!outstanding.is_empty(), "{:?}", busy.roots);
    assert!(outstanding.iter().any(|r| r.kind == "invocation"));
    assert!(
        busy.roots.roots.iter().all(|r| !r.id.contains("held.txt")),
        "a root never carries the event payload: {:?}",
        busy.roots
    );
    assert!(busy
        .refusals
        .iter()
        .any(|r| r.reason == "schedule.overlap" && r.count == 0));
    runtime.reset();
}
