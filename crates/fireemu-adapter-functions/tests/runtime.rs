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
    BlockingAuthEvent, TaskRateLimits, TaskRetryConfig, Trigger, DEFAULT_TIMEOUT_SECONDS,
};
use fireemu_core_functions::manifest::{DocumentEvent, FunctionGeneration, ObjectEvent};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_storage::etag::production_etag;
use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::{NewMetadata, Precondition, StorageEvent, StorageState};
use fireemu_core_types::ids::SessionId;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::json;

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const RUNNER_HELLO_TIMEOUT: Duration = Duration::from_secs(60);

#[test]
fn spawn_spec_debug_redacts_environment_and_command_arguments() {
    let spec = SpawnSpec {
        command: vec!["node".to_owned(), "--token=command-sentinel-47".to_owned()],
        cwd: Some("/functions".to_owned()),
        env: vec![(
            "LOCAL_SECRET".to_owned(),
            "environment-sentinel-48".to_owned(),
        )],
        hello_timeout: Duration::from_secs(7),
    };
    let spec_debug = format!("{spec:?}");
    for sentinel in ["command-sentinel-47", "environment-sentinel-48"] {
        assert!(!spec_debug.contains(sentinel), "{spec_debug}");
    }
    assert!(spec_debug.contains("hello_timeout"), "{spec_debug}");
}

#[test]
fn functions_config_debug_redacts_runner_secret() {
    let config = FunctionsConfig {
        project: "demo-app".to_owned(),
        default_bucket: "demo-app.appspot.com".to_owned(),
        location: "nam5".to_owned(),
        session: SessionId::new(7),
        max_running: 4,
        debug_mode: false,
        retry_attempts: 4,
        max_catch_up_runs: 10,
        runner_secret: "runtime-sentinel-49".to_owned(),
        overlap: fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        functions_host: None,
        subscription_naming: fireemu_adapter_functions::events::SubscriptionNaming::default(),
        auth_context: fireemu_adapter_functions::events::AuthContextNaming::default(),
    };

    let config_debug = format!("{config:?}");
    assert!(
        !config_debug.contains("runtime-sentinel-49"),
        "{config_debug}"
    );
    assert!(config_debug.contains("project"), "{config_debug}");
}

#[tokio::test]
async fn runner_log_frames_preserve_function_and_user_metadata() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let runner = Runner::spawn_spec(&SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: RUNNER_HELLO_TIMEOUT,
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
    start_with_runtime_options_and_env(
        overlap,
        catch_up,
        max_running,
        respawnable,
        Vec::new(),
        configure,
    )
    .await
}

async fn start_with_runtime_options_and_env(
    overlap: fireemu_adapter_functions::runtime::OverlapPolicy,
    catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy,
    max_running: usize,
    respawnable: bool,
    env: Vec<(String, String)>,
    configure: impl FnOnce(&mut fireemu_core_functions::manifest::FunctionManifest),
) -> (Arc<FunctionsRuntime>, Arc<Mutex<VirtualClock>>) {
    start_runtime(
        overlap,
        catch_up,
        max_running,
        respawnable,
        env,
        1000,
        configure,
    )
    .await
}

/// The default runtime with a catch-up cap of `max_catch_up_runs` (`all` policy).
async fn start_with_catch_up_cap(
    max_catch_up_runs: usize,
) -> (Arc<FunctionsRuntime>, Arc<Mutex<VirtualClock>>) {
    start_runtime(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        true,
        Vec::new(),
        max_catch_up_runs,
        |_| {},
    )
    .await
}

async fn start_runtime(
    overlap: fireemu_adapter_functions::runtime::OverlapPolicy,
    catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy,
    max_running: usize,
    respawnable: bool,
    env: Vec<(String, String)>,
    max_catch_up_runs: usize,
    configure: impl FnOnce(&mut fireemu_core_functions::manifest::FunctionManifest),
) -> (Arc<FunctionsRuntime>, Arc<Mutex<VirtualClock>>) {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env,
        hello_timeout: RUNNER_HELLO_TIMEOUT,
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
            max_catch_up_runs,
            runner_secret: "s".into(),
            overlap,
            catch_up,
            functions_host: None,
            subscription_naming: fireemu_adapter_functions::events::SubscriptionNaming::default(),
            auth_context: fireemu_adapter_functions::events::AuthContextNaming::default(),
        },
        clock.clone(),
        Arc::new(runner),
        respawnable.then_some(spec),
    );
    tokio::spawn(runtime.clone().dispatch_loop());
    (runtime, clock)
}

async fn wait_for_runner(runtime: &FunctionsRuntime) {
    let deadline = tokio::time::Instant::now() + RUNNER_HELLO_TIMEOUT + Duration::from_secs(1);
    while !runtime.runner_alive() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the runner did not restart within its hello timeout"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn rapid_resets_share_one_in_flight_runner_spawn() {
    let dir = std::env::temp_dir().join(format!("fireemu-reset-spawn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("starts");
    let (runtime, _clock) = start_with_runtime_options_and_env(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        true,
        vec![
            (
                "FIREEMU_FAKE_START_PROBE".to_owned(),
                probe.display().to_string(),
            ),
            ("FIREEMU_FAKE_HELLO_DELAY_MS".to_owned(), "1500".to_owned()),
        ],
        |_| {},
    )
    .await;
    runtime.reset();
    runtime.reset();
    runtime.reset();
    wait_for_runner(&runtime).await;
    assert_eq!(std::fs::read_to_string(&probe).unwrap().lines().count(), 2);
    runtime.shutdown().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn http_immediately_after_reset_uses_one_replacement() {
    let dir = std::env::temp_dir().join(format!("fireemu-http-reset-spawn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("starts");
    let (runtime, _clock) = start_with_runtime_options_and_env(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        true,
        vec![(
            "FIREEMU_FAKE_START_PROBE".to_owned(),
            probe.display().to_string(),
        )],
        |_| {},
    )
    .await;
    let stale_target = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    runtime.reset();
    assert_eq!(
        runtime
            .invoke_http(&stale_target, "GET", "/after-reset", &[], &[])
            .await
            .unwrap()
            .status,
        200
    );
    assert_eq!(std::fs::read_to_string(&probe).unwrap().lines().count(), 2);
    runtime.shutdown().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn fixed_inspector_reload_holds_recovery_until_the_new_runner_is_published() {
    let dir = std::env::temp_dir().join(format!("fireemu-inspector-gate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("starts");
    let env = vec![(
        "FIREEMU_FAKE_START_PROBE".to_owned(),
        probe.display().to_string(),
    )];
    let (runtime, _clock) = start_with_runtime_options_and_env(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        true,
        env.clone(),
        |_| {},
    )
    .await;
    let target = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    let guard = runtime
        .stop_runner_for_fixed_inspector_reload("default")
        .await
        .unwrap();
    runtime.publish("jobs", &[json!({"data": "YQ=="})]);
    let pending = {
        let runtime = runtime.clone();
        tokio::spawn(async move {
            runtime
                .invoke_http(&target, "GET", "/after-reload", &[], &[])
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!pending.is_finished());
    assert_eq!(std::fs::read_to_string(&probe).unwrap().lines().count(), 1);
    let spec = SpawnSpec {
        command: vec![
            "python3".to_owned(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py").to_owned(),
        ],
        cwd: None,
        env,
        hello_timeout: RUNNER_HELLO_TIMEOUT,
    };
    let replacement = Arc::new(Runner::spawn_spec(&spec).await.unwrap());
    runtime
        .reload_codebase(CodebaseSpec {
            name: "default".to_owned(),
            manifest: runtime.manifest().clone(),
            runner: replacement.clone(),
            spawn: Some(spec),
            cleanup_dir: None,
        })
        .unwrap();
    drop(guard);
    assert_eq!(pending.await.unwrap().unwrap().status, 200);
    runtime.await_idle(Duration::from_secs(3)).await.unwrap();
    assert!(runtime
        .history()
        .iter()
        .any(|record| { record.function == "onJob" && record.outcome == "ok" }));
    assert!(Arc::ptr_eq(&runtime.runner(), &replacement));
    assert_eq!(std::fs::read_to_string(&probe).unwrap().lines().count(), 2);
    runtime.shutdown().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn fixed_inspector_reload_wakes_queued_background_work() {
    let (runtime, _clock) = start_with_runtime_options(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        true,
        |_| {},
    )
    .await;
    let guard = runtime
        .stop_runner_for_fixed_inspector_reload("default")
        .await
        .unwrap();
    runtime.publish("jobs", &[json!({"data": "YQ=="})]);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!runtime.is_idle());
    assert!(runtime.history().is_empty());
    let spec = SpawnSpec {
        command: vec![
            "python3".to_owned(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py").to_owned(),
        ],
        cwd: None,
        env: Vec::new(),
        hello_timeout: RUNNER_HELLO_TIMEOUT,
    };
    let replacement = Arc::new(Runner::spawn_spec(&spec).await.unwrap());
    runtime
        .reload_codebase(CodebaseSpec {
            name: "default".to_owned(),
            manifest: runtime.manifest().clone(),
            runner: replacement,
            spawn: Some(spec),
            cleanup_dir: None,
        })
        .unwrap();
    drop(guard);
    runtime.await_idle(Duration::from_secs(3)).await.unwrap();
    assert!(runtime
        .history()
        .iter()
        .any(|record| { record.function == "onJob" && record.outcome == "ok" }));
    runtime.shutdown().await;
}

#[tokio::test]
async fn reset_during_runner_hello_discards_the_superseded_spawn() {
    let dir =
        std::env::temp_dir().join(format!("fireemu-stale-reset-spawn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("starts");
    let (runtime, _clock) = start_with_runtime_options_and_env(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        true,
        vec![
            (
                "FIREEMU_FAKE_START_PROBE".to_owned(),
                probe.display().to_string(),
            ),
            ("FIREEMU_FAKE_HELLO_DELAY_MS".to_owned(), "1500".to_owned()),
        ],
        |_| {},
    )
    .await;
    runtime.reset();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let starts = std::fs::read_to_string(&probe).unwrap();
        if starts.lines().count() >= 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the first replacement did not start"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    runtime.reset();
    runtime.reset();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(std::fs::read_to_string(&probe).unwrap().lines().count(), 2);
    wait_for_runner(&runtime).await;
    assert_eq!(std::fs::read_to_string(&probe).unwrap().lines().count(), 3);
    let target = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    assert_eq!(
        runtime
            .invoke_http(&target, "GET", "/echo", &[], &[])
            .await
            .unwrap()
            .status,
        200
    );
    runtime.shutdown().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn reset_joins_an_in_flight_blocking_auth_runner_spawn() {
    let dir = std::env::temp_dir().join(format!("fireemu-auth-reset-spawn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("starts");
    let (runtime, _clock) = start_with_runtime_options_and_env(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        true,
        vec![
            (
                "FIREEMU_FAKE_START_PROBE".to_owned(),
                probe.display().to_string(),
            ),
            ("FIREEMU_FAKE_HELLO_DELAY_MS".to_owned(), "1500".to_owned()),
        ],
        |manifest| {
            manifest.functions.extend(
                parse_manifest(&json!({"functions": [{
                    "name": "beforeCreate",
                    "generation": 2,
                    "trigger": {"type": "blockingAuth", "eventType": "beforeCreate"}
                }]}))
                .unwrap()
                .functions,
            );
        },
    )
    .await;
    let (target, admission) = runtime
        .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
        .unwrap()
        .unwrap();
    drop(admission);
    assert!(runtime.restart_runner_after_blocking_failure(&target));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let starts = std::fs::read_to_string(&probe).unwrap();
        if starts.lines().count() >= 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the Blocking Auth replacement did not start"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    runtime.reset();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(std::fs::read_to_string(&probe).unwrap().lines().count(), 2);
    wait_for_runner(&runtime).await;
    assert_eq!(std::fs::read_to_string(&probe).unwrap().lines().count(), 3);
    runtime.shutdown().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

async fn wait_for_ok_since(
    runtime: &FunctionsRuntime,
    cursor: fireemu_adapter_functions::runtime::HistoryCursor,
) {
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(u64::from(DEFAULT_TIMEOUT_SECONDS) + 1);
    loop {
        let delta = runtime.history_since(Some(cursor));
        assert!(!delta.resync, "the current-epoch cursor remains valid");
        if delta
            .records
            .iter()
            .any(|r| r.record.function == "ok" && r.record.outcome == "ok")
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the current-epoch completion was not recorded: {:?}",
            delta.records
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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
    start_task_runtime_with_policy_and_env(probe, max_running, configure, Vec::new()).await
}

async fn start_task_runtime_with_policy_and_env(
    probe: &Path,
    max_running: usize,
    configure: impl Fn(&str) -> (TaskRetryConfig, TaskRateLimits),
    extra_env: Vec<(String, String)>,
) -> Arc<FunctionsRuntime> {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let mut env = vec![(
        "FIREEMU_FAKE_TASK_PROBE".to_owned(),
        probe.display().to_string(),
    )];
    env.extend(extra_env);
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env,
        hello_timeout: Duration::from_secs(60),
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
            subscription_naming: fireemu_adapter_functions::events::SubscriptionNaming::default(),
            auth_context: fireemu_adapter_functions::events::AuthContextNaming::default(),
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
    let runtime = start_task_runtime_with_policy_and_env(
        &probe,
        4,
        |_| {
            (
                TaskRetryConfig {
                    max_attempts: 1,
                    ..TaskRetryConfig::default()
                },
                TaskRateLimits {
                    max_concurrent_dispatches: 1,
                    max_dispatches_per_second: 500.0,
                },
            )
        },
        vec![("FIREEMU_FAKE_HELLO_DELAY_MS".to_owned(), "3000".to_owned())],
    )
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
    let restart_deadline =
        tokio::time::Instant::now() + RUNNER_HELLO_TIMEOUT + Duration::from_secs(1);
    while !runtime.runner_alive() {
        assert_eq!(
            runtime.task_queue_stats()["queue:demo-app-us-central1-taskA"]["numberOfTasks"],
            1,
            "a task accepted during reset stays pending without spending a delivery attempt"
        );
        assert!(
            tokio::time::Instant::now() < restart_deadline,
            "the runner did not restart within its hello timeout"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let entries = wait_for_task_entries(&probe, 2).await;
    assert_eq!(entries.iter().filter(|entry| *entry == "taskA").count(), 2);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(runtime.status()["tasksInFlight"], 1);
    assert_eq!(
        runtime.task_queue_stats()["queue:demo-app-us-central1-taskA"]["failedTasks"],
        0.0
    );

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
async fn shutdown_closes_the_manual_and_the_clock_driven_schedule_paths() {
    use fireemu_adapter_functions::runtime::ScheduleRunError;
    let (runtime, clock) = start().await;
    runtime.shutdown().await;
    assert!(runtime.is_idle());

    // A manual run is refused like every other admission after shutdown began.
    let refused = runtime.run_schedule("tick");
    assert!(
        matches!(&refused, Err(ScheduleRunError::Refused(m)) if m.contains("shutting down")),
        "{refused:?}"
    );

    // A clock change enqueues no schedule run into a dispatcher that has stopped.
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(15 * 60))
        .unwrap();
    runtime.on_clock_changed();
    assert!(runtime.is_idle(), "{}", runtime.status());
    assert!(runtime.history().is_empty());
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
        hello_timeout: Duration::from_secs(60),
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
            subscription_naming: fireemu_adapter_functions::events::SubscriptionNaming::default(),
            auth_context: fireemu_adapter_functions::events::AuthContextNaming::default(),
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
        hello_timeout: Duration::from_secs(60),
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
        hello_timeout: Duration::from_secs(60),
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
        hello_timeout: Duration::from_secs(60),
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
async fn blocking_auth_token_policy_follows_an_explicit_target() {
    let (runtime, _clock) = start_with_policies_and_manifest(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        |manifest| {
            let mut blocking = parse_manifest(&json!({"functions": [{
                "name": "policyA",
                "trigger": {"type": "blockingAuth", "eventType": "beforeCreate"}
            }, {
                "name": "policyB",
                "trigger": {"type": "blockingAuth", "eventType": "beforeCreate", "accessToken": true}
            }]}))
            .unwrap();
            manifest.functions.append(&mut blocking.functions);
        },
    )
    .await;

    assert!(
        !runtime
            .blocking_auth_token_policy(BlockingAuthEvent::BeforeCreate)
            .access_token
    );
    assert!(
        !runtime
            .blocking_auth_token_policy_for(BlockingAuthEvent::BeforeCreate, Some("policyA"))
            .access_token
    );
    assert!(
        runtime
            .blocking_auth_token_policy_for(BlockingAuthEvent::BeforeCreate, Some("policyB"))
            .access_token
    );
    assert!(
        !runtime
            .blocking_auth_token_policy_for(BlockingAuthEvent::BeforeCreate, Some("missing"))
            .access_token
    );

    let (target, admission) = runtime
        .try_admit_blocking_auth_for(BlockingAuthEvent::BeforeCreate, Some("policyB"))
        .unwrap()
        .unwrap();
    assert_eq!(target.function, "policyB");
    assert!(target.token_policy.access_token);
    drop(admission);
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

    let deadline = tokio::time::Instant::now() + RUNNER_HELLO_TIMEOUT + Duration::from_secs(1);
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
            "the stuck runner was not replaced within its hello contract"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_blocking_auth_request_starts_recovery_of_an_idle_dead_runner() {
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
    runtime.runner().kill_now();
    assert!(runtime
        .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
        .is_err());
    tokio::time::timeout(Duration::from_secs(3), async {
        while !runtime.runner_alive() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the request starts runner recovery");
    let (_target, admission) = runtime
        .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
        .unwrap()
        .unwrap();
    drop(admission);
    runtime.shutdown().await;
}

#[tokio::test]
async fn failed_blocking_auth_respawn_releases_recovery_ownership() {
    let dir =
        std::env::temp_dir().join(format!("fireemu-auth-restart-fails-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("starts");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let probe_env = (
        "FIREEMU_FAKE_START_PROBE".to_owned(),
        probe.display().to_string(),
    );
    let initial_spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: vec![probe_env.clone()],
        hello_timeout: RUNNER_HELLO_TIMEOUT,
    };
    let runner = Arc::new(Runner::spawn_spec(&initial_spec).await.unwrap());
    let mut manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
    manifest.functions.extend(
        parse_manifest(&json!({"functions": [{
            "name": "beforeCreate", "generation": 2,
            "trigger": {"type": "blockingAuth", "eventType": "beforeCreate"}
        }]}))
        .unwrap()
        .functions,
    );
    let failing_spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: vec![
            probe_env,
            ("FIREEMU_FAKE_EXIT_BEFORE_HELLO".to_owned(), "1".to_owned()),
        ],
        hello_timeout: Duration::from_secs(10),
    };
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
            subscription_naming: fireemu_adapter_functions::events::SubscriptionNaming::default(),
            auth_context: fireemu_adapter_functions::events::AuthContextNaming::default(),
        },
        Arc::new(Mutex::new(VirtualClock::new(START))),
        runner,
        Some(failing_spec),
    );
    tokio::spawn(runtime.clone().dispatch_loop());
    let stale_http = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    let (blocking, admission) = runtime
        .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
        .unwrap()
        .unwrap();
    drop(admission);
    assert!(runtime.restart_runner_after_blocking_failure(&blocking));
    runtime.publish("crash-once", &[json!({"data": "YQ=="})]);
    tokio::time::timeout(Duration::from_secs(10), async {
        while std::fs::read_to_string(&probe).unwrap().lines().count() < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("queued work must wake after the failed Blocking Auth restart");
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        runtime.invoke_http(&stale_http, "GET", "/after-failed-auth-restart", &[], &[]),
    )
    .await
    .expect("a failed Blocking Auth respawn must release the shared recovery gate");
    assert!(
        result.is_err(),
        "a runner that cannot finish hello cannot serve HTTP"
    );
    runtime.shutdown().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn http_waits_for_an_existing_blocking_auth_runner_restart() {
    let dir = std::env::temp_dir().join(format!("fireemu-blocking-restart-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let probe = dir.join("starts");
    let (runtime, _clock) = start_with_runtime_options_and_env(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        true,
        vec![
            ("FIREEMU_FAKE_HELLO_DELAY_MS".to_owned(), "500".to_owned()),
            (
                "FIREEMU_FAKE_START_PROBE".to_owned(),
                probe.display().to_string(),
            ),
        ],
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
    let stale_http = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    let (blocking, admission) = runtime
        .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
        .unwrap()
        .unwrap();
    drop(admission);
    assert!(runtime.restart_runner_after_blocking_failure(&blocking));
    let response = runtime
        .invoke_http(&stale_http, "GET", "/during-blocking-restart", &[], &[])
        .await
        .expect("HTTP waits for the claimed Blocking Auth replacement");
    assert_eq!(response.status, 200);
    assert_eq!(std::fs::read_to_string(&probe).unwrap().lines().count(), 2);
    runtime.shutdown().await;
    std::fs::remove_dir_all(dir).unwrap();
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
        hello_timeout: Duration::from_secs(60),
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
            subscription_naming: fireemu_adapter_functions::events::SubscriptionNaming::default(),
            auth_context: fireemu_adapter_functions::events::AuthContextNaming::default(),
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
async fn a_crashed_event_retries_only_when_retry_is_enabled() {
    let dir = std::env::temp_dir().join(format!("fireemu-crash-once-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("crash-once");
    let (runtime, clock) = start_with_runtime_options_and_env(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        true,
        vec![(
            "FIREEMU_FAKE_CRASH_ONCE_MARKER".to_owned(),
            path.display().to_string(),
        )],
        |manifest| {
            manifest
                .functions
                .iter_mut()
                .find(|function| function.name == "crashOnce")
                .unwrap()
                .retry = true;
        },
    )
    .await;
    runtime.publish("crash-once", &[json!({"data": "YQ=="})]);
    let waiting = runtime.await_idle(Duration::from_millis(500)).await;
    assert!(
        waiting.is_err(),
        "the first crash waits for the retry clock"
    );
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(60))
        .unwrap();
    runtime.on_clock_changed();
    runtime
        .await_idle(Duration::from_secs(5))
        .await
        .expect("the policy retries after a replacement starts");
    let records: Vec<_> = runtime
        .history()
        .into_iter()
        .filter(|record| record.function == "crashOnce")
        .collect();
    assert_eq!(records.len(), 2);
    assert!(records[0].outcome.starts_with("runner gone:"));
    assert_eq!(records[0].attempt, 1);
    assert_eq!(records[1].outcome, "ok");
    assert_eq!(records[1].attempt, 2);
    assert!(runtime.runner_alive());
    runtime.shutdown().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_spontaneously_crashing_non_retry_event_terminates_after_one_delivery() {
    let dir = std::env::temp_dir().join(format!("fireemu-crash-always-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let starts = dir.join("starts");
    let (runtime, _clock) = start_with_runtime_options_and_env(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        true,
        vec![(
            "FIREEMU_FAKE_START_PROBE".to_owned(),
            starts.display().to_string(),
        )],
        |_| {},
    )
    .await;

    runtime.publish("crash-always", &[json!({"data": "YQ=="})]);
    let idle = runtime.await_idle(Duration::from_secs(4)).await;
    let records: Vec<_> = runtime
        .history()
        .into_iter()
        .filter(|record| record.function == "crashAlways")
        .collect();
    let status = runtime.status();
    runtime.shutdown().await;
    let start_count = std::fs::read_to_string(&starts).unwrap().lines().count();
    std::fs::remove_dir_all(dir).unwrap();

    assert!(
        idle.is_ok(),
        "the crashed event kept the session busy: {status}"
    );
    assert_eq!(records.len(), 1, "the event was redelivered: {records:?}");
    assert!(records[0].outcome.starts_with("runner gone:"));
    assert_eq!(status["deadLettered"], 1);
    assert!(
        start_count <= 2,
        "the runner was restarted {start_count} times"
    );
}

#[tokio::test]
async fn a_spontaneously_crashing_retry_event_exhausts_its_attempt_budget() {
    let (runtime, clock) = start_with_runtime_options_and_env(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        true,
        Vec::new(),
        |manifest| {
            manifest
                .functions
                .iter_mut()
                .find(|function| function.name == "crashAlways")
                .unwrap()
                .retry = true;
        },
    )
    .await;
    runtime.publish("crash-always", &[json!({"data": "YQ=="})]);
    for delivered in 1..=3 {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if runtime
                    .history()
                    .iter()
                    .filter(|record| record.function == "crashAlways")
                    .count()
                    >= delivered
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the crash is recorded before advancing the retry clock");
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(60))
            .unwrap();
        runtime.on_clock_changed();
    }
    let idle = runtime.await_idle(Duration::from_secs(5)).await;
    let records: Vec<_> = runtime
        .history()
        .into_iter()
        .filter(|record| record.function == "crashAlways")
        .collect();
    let status = runtime.status();
    runtime.shutdown().await;

    assert!(idle.is_ok(), "the retry budget did not terminate: {status}");
    assert_eq!(
        records
            .iter()
            .map(|record| record.attempt)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert_eq!(status["deadLettered"], 1);
}

#[tokio::test]
async fn http_recovery_uses_the_function_deadline() {
    let (runtime, _clock) = start_with_runtime_options_and_env(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        true,
        vec![("FIREEMU_FAKE_HELLO_DELAY_MS".to_owned(), "3000".to_owned())],
        |manifest| {
            manifest
                .functions
                .iter_mut()
                .find(|function| function.name == "echo")
                .unwrap()
                .timeout_seconds = 1;
        },
    )
    .await;
    let target = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    runtime.runner().kill_now();
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        runtime.invoke_http(&target, "GET", "/slow-recovery", &[], &[]),
    )
    .await
    .expect("the invocation returns within its recovery deadline");
    let response = result.expect("a timed-out recovery uses the function timeout response");
    assert_eq!(response.status, 500);
    assert_eq!(response.body, br#"{"code":"ECONNRESET"}"#);
    assert!(runtime
        .history()
        .iter()
        .any(|record| record.function == "echo" && record.outcome == "timeout"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn strict_http_recovery_returns_the_recorded_upstream_timeout() {
    let (runtime, _clock) = start_with_runtime_options_and_env(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        true,
        vec![("FIREEMU_FAKE_HELLO_DELAY_MS".to_owned(), "3000".to_owned())],
        |manifest| {
            manifest
                .functions
                .iter_mut()
                .find(|function| function.name == "echo")
                .unwrap()
                .timeout_seconds = 1;
        },
    )
    .await;
    let target = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    runtime.runner().kill_now();
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        runtime.invoke_http_with_profile(
            &target,
            "GET",
            "/slow-recovery",
            &[],
            &[],
            fireemu_adapter_functions::http::FunctionsHttpProfile::Strict,
        ),
    )
    .await
    .expect("the invocation returns within its recovery deadline")
    .expect("a timed-out recovery has an HTTP response");
    assert_eq!(response.status, 504);
    assert_eq!(
        response.headers,
        vec![("content-type".to_owned(), "text/plain".to_owned())]
    );
    assert_eq!(response.body, b"upstream request timeout");
    assert!(runtime
        .history()
        .iter()
        .any(|record| record.function == "echo" && record.outcome == "timeout"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn an_idle_runner_exit_is_replaced_for_the_next_http_invocation() {
    let (runtime, _clock) = start().await;
    let stale_target = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    runtime.runner().kill_now();

    let response = runtime
        .invoke_http(&stale_target, "GET", "/after-crash", &[], &[])
        .await
        .expect("the next invocation starts a new runner");
    assert_eq!(response.status, 200);
    assert!(runtime.runner_alive());
    let next = runtime
        .invoke_http(&stale_target, "GET", "/after-recovery", &[], &[])
        .await
        .expect("a retained target follows the replacement runner");
    assert_eq!(next.status, 200);
    runtime.shutdown().await;
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
    wait_for_runner(&runtime).await;
    let cursor = runtime.history_since(None).cursor;
    runtime.on_commit(&commit(vec![DocumentChange {
        path: doc("items/c", 1).path,
        before: None,
        after: Some(doc("items/c", 1).into()),
    }]));
    wait_for_ok_since(&runtime, cursor).await;
    runtime.runner().shutdown().await;
}

#[tokio::test]
async fn a_spontaneous_recovery_cannot_replace_a_newer_reload() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let fast = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: RUNNER_HELLO_TIMEOUT,
    };
    let mut slow = fast.clone();
    slow.env = vec![("FIREEMU_FAKE_HELLO_DELAY_MS".to_owned(), "1000".to_owned())];
    let initial = Arc::new(Runner::spawn_spec(&fast).await.unwrap());
    let manifest = parse_manifest(initial.hello().manifest.as_ref().unwrap()).unwrap();
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
            subscription_naming: fireemu_adapter_functions::events::SubscriptionNaming::default(),
            auth_context: fireemu_adapter_functions::events::AuthContextNaming::default(),
        },
        Arc::new(Mutex::new(VirtualClock::new(START))),
        initial.clone(),
        Some(slow),
    );
    let target = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    initial.kill_now();
    let recovering = {
        let runtime = runtime.clone();
        tokio::spawn(async move {
            runtime
                .invoke_http(&target, "GET", "/old-generation", &[], &[])
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !recovering.is_finished(),
        "recovery is in flight before reload"
    );
    let replacement = Arc::new(Runner::spawn_spec(&fast).await.unwrap());
    runtime
        .reload_codebase(CodebaseSpec {
            name: "default".to_owned(),
            manifest,
            runner: replacement.clone(),
            spawn: Some(fast),
            cleanup_dir: None,
        })
        .unwrap();
    assert_eq!(recovering.await.unwrap().unwrap().status, 200);
    assert!(Arc::ptr_eq(&runtime.runner(), &replacement));
    let current = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    assert_eq!(
        runtime
            .invoke_http(&current, "GET", "/new-generation", &[], &[])
            .await
            .unwrap()
            .status,
        200
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn reload_wakes_background_work_after_superseding_recovery() {
    let dir = std::env::temp_dir().join(format!("fireemu-reload-recovery-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("starts");
    let (runtime, _clock) = start_with_runtime_options_and_env(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        true,
        vec![
            (
                "FIREEMU_FAKE_START_PROBE".to_owned(),
                probe.display().to_string(),
            ),
            ("FIREEMU_FAKE_HELLO_DELAY_MS".to_owned(), "1000".to_owned()),
        ],
        |_| {},
    )
    .await;
    runtime.runner().kill_now();
    runtime.publish("jobs", &[json!({"data": "YQ=="})]);
    tokio::time::timeout(Duration::from_secs(2), async {
        while std::fs::read_to_string(&probe).unwrap().lines().count() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("background recovery starts before reload");
    let fast = SpawnSpec {
        command: vec![
            "python3".to_owned(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py").to_owned(),
        ],
        cwd: None,
        env: Vec::new(),
        hello_timeout: RUNNER_HELLO_TIMEOUT,
    };
    let replacement = Arc::new(Runner::spawn_spec(&fast).await.unwrap());
    runtime
        .reload_codebase(CodebaseSpec {
            name: "default".to_owned(),
            manifest: runtime.manifest().clone(),
            runner: replacement,
            spawn: Some(fast),
            cleanup_dir: None,
        })
        .unwrap();
    runtime.await_idle(Duration::from_secs(3)).await.unwrap();
    assert!(runtime
        .history()
        .iter()
        .any(|record| { record.function == "onJob" && record.outcome == "ok" }));
    runtime.shutdown().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn reload_generation_wins_over_an_older_reset_respawn() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let fast = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(60),
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
            subscription_naming: fireemu_adapter_functions::events::SubscriptionNaming::default(),
            auth_context: fireemu_adapter_functions::events::AuthContextNaming::default(),
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
        hello_timeout: Duration::from_secs(60),
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
            subscription_naming: fireemu_adapter_functions::events::SubscriptionNaming::default(),
            auth_context: fireemu_adapter_functions::events::AuthContextNaming::default(),
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
    // a second-generation schedule: a first-generation handler is never retried
    let (runtime, clock) = start_runtime(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        false,
        Vec::new(),
        1000,
        |manifest| {
            manifest
                .functions
                .iter_mut()
                .find(|f| f.name == "failSchedule")
                .unwrap()
                .generation = FunctionGeneration::Second;
        },
    )
    .await;
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

/// Recorded (run `156715222b86ea44`): a job with `maxRetryDuration: 30s`, no retry count, `minBackoff 4s` and
/// `maxBackoff 10s` was attempted at 0, 4.6, 13.2 and 23.7 seconds and then stopped, the next attempt being past the
/// window. That job targeted HTTP (second generation). The logical clock has no dispatch latency, so the attempts
/// are at 0, 4, 12 and 22.
#[tokio::test]
async fn a_second_generation_retry_window_without_a_count_retries_until_the_window_ends() {
    use fireemu_core_functions::manifest::{ScheduleRetryConfig, Trigger};
    let (runtime, clock) = start_runtime(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        false,
        Vec::new(),
        1000,
        |manifest| {
            let spec = manifest
                .functions
                .iter_mut()
                .find(|f| f.name == "failSchedule")
                .unwrap();
            let Trigger::Schedule {
                schedule,
                time_zone,
                ..
            } = spec.trigger.clone()
            else {
                panic!("failSchedule is scheduled");
            };
            spec.trigger = Trigger::Schedule {
                schedule,
                time_zone,
                retry: ScheduleRetryConfig {
                    retry_count: 0,
                    max_retry_seconds: 30,
                    max_backoff_seconds: 10,
                    max_doublings: 5,
                    min_backoff_seconds: 4,
                },
            };
            spec.retry = true;
            spec.generation = FunctionGeneration::Second;
        },
    )
    .await;
    let attempts = |runtime: &FunctionsRuntime| -> Vec<u32> {
        runtime
            .history()
            .iter()
            .filter(|record| record.function == "failSchedule")
            .map(|record| record.attempt)
            .collect()
    };
    runtime.run_schedule("failSchedule").unwrap();
    let _ = runtime.await_idle(Duration::from_millis(300)).await;
    assert_eq!(attempts(&runtime), vec![1]);
    // 4, 8 and then the 10 s cap: attempts 2, 3 and 4 at 4, 12 and 22 seconds.
    for (advance, expected) in [(3, 1), (1, 2), (7, 2), (1, 3), (9, 3), (1, 4)] {
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(advance))
            .unwrap();
        runtime.on_clock_changed();
        let _ = runtime.await_idle(Duration::from_millis(300)).await;
        assert_eq!(attempts(&runtime).len(), expected, "after +{advance}s");
    }
    // The fifth attempt would be at 32 seconds, past the 30 second window: none, however far the clock goes.
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(600))
        .unwrap();
    runtime.on_clock_changed();
    let _ = runtime.await_idle(Duration::from_millis(300)).await;
    assert_eq!(attempts(&runtime), vec![1, 2, 3, 4]);
    assert!(runtime
        .dead_letters()
        .iter()
        .any(|record| record.function == "failSchedule" && record.attempt == 4));
    runtime.runner().shutdown().await;
}

/// A retry window with no backoff at all (not recorded: production's answer to `minBackoffDuration: "0s"` is unknown) is
/// not a hot loop: one retry is released per clock change, so a failing handler is attempted once per clock move until
/// the window ends, and never after it.
#[tokio::test]
async fn a_zero_backoff_window_retries_once_per_clock_change_until_the_window_ends() {
    use fireemu_core_functions::manifest::{ScheduleRetryConfig, Trigger};
    let (runtime, clock) = start_runtime(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        false,
        Vec::new(),
        1000,
        |manifest| {
            let spec = manifest
                .functions
                .iter_mut()
                .find(|f| f.name == "failSchedule")
                .unwrap();
            let Trigger::Schedule {
                schedule,
                time_zone,
                ..
            } = spec.trigger.clone()
            else {
                panic!("failSchedule is scheduled");
            };
            spec.trigger = Trigger::Schedule {
                schedule,
                time_zone,
                retry: ScheduleRetryConfig {
                    retry_count: 0,
                    max_retry_seconds: 5,
                    max_backoff_seconds: 0,
                    max_doublings: 0,
                    min_backoff_seconds: 0,
                },
            };
            spec.retry = true;
            spec.generation = FunctionGeneration::Second;
        },
    )
    .await;
    let attempts = |runtime: &FunctionsRuntime| -> usize {
        runtime
            .history()
            .iter()
            .filter(|record| record.function == "failSchedule")
            .count()
    };
    runtime.run_schedule("failSchedule").unwrap();
    let _ = runtime.await_idle(Duration::from_millis(300)).await;
    assert_eq!(attempts(&runtime), 1);
    let mut counts = vec![1];
    for _ in 0..9 {
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(1))
            .unwrap();
        runtime.on_clock_changed();
        let _ = runtime.await_idle(Duration::from_millis(300)).await;
        counts.push(attempts(&runtime));
    }
    // One more attempt per one-second move, then none, however many moves follow. The retry that the attempt at 5 s
    // decides (5 + 0 <= 5, inside the window) is released by the next move, at 6 s; its failure decides none. Pins
    // today's behaviour, which is not necessarily the intended one: the last attempt runs one move past the window.
    assert_eq!(counts, vec![1, 2, 3, 4, 5, 6, 7, 7, 7, 7]);
    runtime.runner().shutdown().await;
}

/// A first-generation schedule's job targets Pub/Sub, so Cloud Scheduler's retry covers the publish, not the handler:
/// no handler retry was recorded for it (the window was recorded for an HTTP target only). A window alone is one
/// attempt, however far the clock goes.
#[tokio::test]
async fn a_first_generation_retry_window_without_a_count_is_one_attempt() {
    use fireemu_core_functions::manifest::{ScheduleRetryConfig, Trigger};
    let (runtime, clock) = start_runtime(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        false,
        Vec::new(),
        1000,
        |manifest| {
            let spec = manifest
                .functions
                .iter_mut()
                .find(|f| f.name == "failSchedule")
                .unwrap();
            let Trigger::Schedule {
                schedule,
                time_zone,
                ..
            } = spec.trigger.clone()
            else {
                panic!("failSchedule is scheduled");
            };
            spec.trigger = Trigger::Schedule {
                schedule,
                time_zone,
                retry: ScheduleRetryConfig {
                    retry_count: 0,
                    max_retry_seconds: 30,
                    max_backoff_seconds: 10,
                    max_doublings: 5,
                    min_backoff_seconds: 4,
                },
            };
            spec.retry = true;
            spec.generation = FunctionGeneration::First;
        },
    )
    .await;
    runtime.run_schedule("failSchedule").unwrap();
    let _ = runtime.await_idle(Duration::from_millis(300)).await;
    for advance in [5, 10, 600] {
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(advance))
            .unwrap();
        runtime.on_clock_changed();
        let _ = runtime.await_idle(Duration::from_millis(300)).await;
    }
    let attempts: Vec<u32> = runtime
        .history()
        .iter()
        .filter(|record| record.function == "failSchedule")
        .map(|record| record.attempt)
        .collect();
    assert_eq!(attempts, vec![1]);
    runtime.runner().shutdown().await;
}

/// A first-generation schedule's job targets Pub/Sub, so Cloud Scheduler's retry covers the publish, not the handler.
/// A count alone (here 3, no window) is one attempt, however far the clock goes: schedFailV1's handler ran once per
/// occurrence and its Scheduler attempts all finished without an error although the handler threw. (The window-only
/// case is `a_first_generation_retry_window_without_a_count_is_one_attempt`.)
#[tokio::test]
async fn a_first_generation_retry_count_is_one_attempt() {
    use fireemu_core_functions::manifest::{ScheduleRetryConfig, Trigger};
    let (runtime, clock) = start_runtime(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        false,
        Vec::new(),
        1000,
        |manifest| {
            let spec = manifest
                .functions
                .iter_mut()
                .find(|f| f.name == "failSchedule")
                .unwrap();
            let Trigger::Schedule {
                schedule,
                time_zone,
                ..
            } = spec.trigger.clone()
            else {
                panic!("failSchedule is scheduled");
            };
            spec.trigger = Trigger::Schedule {
                schedule,
                time_zone,
                retry: ScheduleRetryConfig {
                    retry_count: 3,
                    max_retry_seconds: 0,
                    max_backoff_seconds: 10,
                    max_doublings: 5,
                    min_backoff_seconds: 4,
                },
            };
            spec.retry = true;
            spec.generation = FunctionGeneration::First;
        },
    )
    .await;
    runtime.run_schedule("failSchedule").unwrap();
    let _ = runtime.await_idle(Duration::from_millis(300)).await;
    for advance in [5, 10, 600] {
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(advance))
            .unwrap();
        runtime.on_clock_changed();
        let _ = runtime.await_idle(Duration::from_millis(300)).await;
    }
    let attempts: Vec<u32> = runtime
        .history()
        .iter()
        .filter(|record| record.function == "failSchedule")
        .map(|record| record.attempt)
        .collect();
    assert_eq!(attempts, vec![1]);
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

/// Production's Firestore create event, recorded 2026-09-30 by an exploratory probe of a Gen1 and
/// a Gen2 handler on one document (`fe_events_primary/<id>`): a UUID `id`, the document's
/// `createTime` as the event `time` with a six-digit fraction, the document under `subject`,
/// and the Gen2 type. Only the identity and time forms are asserted here; the JSON keeps the
/// document resource name as `source` (see the divergence recorded in the contract).
#[test]
fn firestore_events_carry_the_production_id_and_time_forms() {
    let after = doc("fe_events_primary/fe011probe0001", 1);
    let time = LogicalInstant::from_nanos(1_790_769_798_846_431_000);
    let event = |seed: &str| {
        firestore_event(
            seed,
            "demo-project",
            fireemu_core_types::ids::DatabaseId::DEFAULT,
            "us-central1",
            "fe_events_primary/fe011probe0001",
            DocumentEvent::Created,
            None,
            Some(&after),
            time,
            None,
        )
    };
    let first = event("42-1");
    assert_eq!(first["time"], "2026-09-30T12:03:18.846431Z");
    assert_eq!(
        first["subject"],
        "documents/fe_events_primary/fe011probe0001"
    );
    assert_eq!(first["type"], "google.cloud.firestore.document.v1.created");
    let id = first["id"].as_str().unwrap();
    let parts: Vec<&str> = id.split('-').collect();
    assert_eq!(
        parts.iter().map(|part| part.len()).collect::<Vec<_>>(),
        [8, 4, 4, 4, 12],
        "{id}"
    );
    assert!(id
        .chars()
        .all(|c| c == '-' || c.is_ascii_digit() || ('a'..='f').contains(&c)));
    assert_eq!(&id[14..15], "4", "{id}");
    assert_eq!(event("42-1")["id"], first["id"], "replay keeps the id");
    assert_ne!(event("42-2")["id"], first["id"]);
}

/// The frames a production 1st and 2nd gen Firestore onCreate handler printed for one document
/// create (recorded 2026-09-30). Each field of the `CloudEvent` the runtime builds for the same
/// commit is compared with the recorded one, including the database `source`.
#[test]
fn a_firestore_create_event_matches_the_recorded_production_delivery() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/production-firestore-create-frames.json"
    ))
    .unwrap();
    let gen1 = &fixture["gen1"];
    let gen2 = &fixture["gen2"];
    let time = LogicalInstant::from_nanos(i128::from(fixture["commitTimeNanos"].as_i64().unwrap()));
    let mut after = doc("fe_events_primary/fe011probe0001", 1);
    (after.create_time, after.update_time) = (time, time);
    let event = firestore_event(
        "42-1",
        "demo-project",
        fireemu_core_types::ids::DatabaseId::DEFAULT,
        "us-central1",
        "fe_events_primary/fe011probe0001",
        DocumentEvent::Created,
        None,
        Some(&after),
        time,
        None,
    );
    // The fields production and the runtime agree on.
    for key in ["type", "subject", "time", "specversion"] {
        assert_eq!(event[key], gen2[key], "{key}");
    }
    assert_eq!(event["time"], gen1["context"]["timestamp"]);
    assert_eq!(
        event["subject"],
        format!("documents/{}", gen1["data"]["path"].as_str().unwrap())
    );
    // The production create and update times are the commit time, printed as the event time is.
    assert_eq!(event["data"]["value"]["createTime"], gen2["time"]);
    assert_eq!(event["data"]["value"]["updateTime"], gen2["time"]);
    // Production ids are random UUIDs; the recorded 1st gen id is the 2nd gen form plus `-0`.
    let production_id = gen2["id"].as_str().unwrap();
    let gen1_id = gen1["context"]["eventId"].as_str().unwrap();
    assert!(gen1_id.ends_with("-0"), "{gen1_id}");
    assert_eq!(gen1_id.split('-').count(), 6, "{gen1_id}");
    let shape = |id: &str| -> Vec<usize> { id.split('-').map(str::len).collect() };
    assert_eq!(shape(event["id"].as_str().unwrap()), shape(production_id));
    let local_id = event["id"].as_str().unwrap();
    assert_eq!(&local_id[14..15], &production_id[14..15], "version nibble");
    // Created snapshots carry their document name in the payload; source names the database.
    assert_eq!(
        gen2["source"],
        "//firestore.googleapis.com/projects/demo-project/databases/(default)"
    );
    assert_eq!(
        event["source"],
        "//firestore.googleapis.com/projects/demo-project/databases/(default)"
    );
}

/// The frames a production 1st and 2nd gen Cloud Storage onFinalize handler printed for one object
/// create (recorded 2026-10-01). Each field of the `CloudEvent` the runtime builds for an object
/// with the same bytes, name and times is compared with the recorded one; the `etag` and the
/// `generation` forms are the known divergences of the Storage surface, pinned here.
#[test]
fn a_storage_finalize_event_matches_the_recorded_production_delivery() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/production-storage-finalize-frames.json"
    ))
    .unwrap();
    let gen2 = &fixture["gen2"];
    let recorded = &gen2["data"];
    let created = LogicalInstant::parse_rfc3339(gen2["time"].as_str().unwrap()).unwrap();
    let delivered =
        LogicalInstant::parse_rfc3339(fixture["gen1"]["context"]["timestamp"].as_str().unwrap())
            .unwrap();
    let mut store = StorageState::new(1);
    let meta = store
        .put(
            &BucketName::try_new(recorded["bucket"].as_str().unwrap()).unwrap(),
            &ObjectName::try_new(recorded["name"].as_str().unwrap()).unwrap(),
            br#"{"probe":"fe-012-storage-probe"}"#.to_vec(),
            NewMetadata {
                content_type: Some("application/json".to_owned()),
                ..NewMetadata::default()
            },
            Precondition::default(),
            created,
        )
        .unwrap();
    let event = storage_event("42-1", ObjectEvent::Finalized, &meta, delivered, None);
    // The attributes production and the runtime agree on, the bucket extension included.
    for key in ["type", "subject", "source", "specversion"] {
        assert_eq!(event[key], gen2[key], "{key}");
    }
    // The CloudEvent carries the recorded members: the framework adds `context` and `object` on
    // the way to a handler. One known divergence: the delivery's `traceparent` (the runtime sends
    // none). Production's Storage event carries no `datacontenttype`, nor does the runtime's.
    let mut recorded_keys: Vec<String> = gen2["eventKeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key.as_str().unwrap().to_owned())
        .filter(|key| !["context", "object", "traceparent"].contains(&key.as_str()))
        .collect();
    recorded_keys.sort();
    let mut local_keys: Vec<String> = event.as_object().unwrap().keys().cloned().collect();
    local_keys.sort();
    assert_eq!(local_keys, recorded_keys);
    assert!(gen2["datacontenttype"].is_null());
    assert!(event.get("datacontenttype").is_none());
    assert_eq!(event["bucket"], gen2["extensionAttributes"]["bucket"]);
    // The event time is the object's creation instant with the microseconds production prints,
    // not the moment the runtime admitted the event.
    assert_eq!(event["time"], gen2["time"]);
    // Production ids are decimal strings of seventeen digits, a 1st gen one and a 2nd gen one
    // unrelated to each other; they are neither UUIDs nor `<session>-<n>`.
    let id = event["id"].as_str().unwrap();
    for production in [
        gen2["id"].as_str().unwrap(),
        fixture["gen1"]["context"]["eventId"].as_str().unwrap(),
    ] {
        assert_eq!(production.len(), 17, "{production}");
        assert!(
            production.bytes().all(|b| b.is_ascii_digit()),
            "{production}"
        );
    }
    assert_eq!(id.len(), 17, "{id}");
    assert!(id.bytes().all(|b| b.is_ascii_digit()), "{id}");
    // The object resource: the same members; the bytes-derived values are the recorded ones.
    let local = &event["data"];
    let keys = |value: &serde_json::Value| -> Vec<String> {
        value.as_object().unwrap().keys().cloned().collect()
    };
    assert_eq!(keys(local), keys(recorded));
    for key in [
        "bucket",
        "contentType",
        "crc32c",
        "kind",
        "md5Hash",
        "name",
        "size",
        "storageClass",
        "timeCreated",
        "timeStorageClassUpdated",
        "updated",
        "selfLink",
    ] {
        assert_eq!(local[key], recorded[key], "{key}");
    }
    // The resource id and the media link carry the generation; production's generation is a
    // microsecond timestamp, the local one a counter (known divergence of the Storage surface).
    assert_eq!(
        local["id"],
        format!(
            "{}/{}/{}",
            recorded["bucket"].as_str().unwrap(),
            recorded["name"].as_str().unwrap(),
            meta.generation
        )
    );
    assert!(local["mediaLink"]
        .as_str()
        .unwrap()
        .contains(&format!("generation={}", meta.generation)));
    // Production's etag is the base64 of the protobuf of the generation and the metageneration
    // (`CLuI7vG3mJcDEAE=`); the runtime encodes the same two numbers, its own generation here.
    assert_eq!(recorded["etag"], "CLuI7vG3mJcDEAE=");
    let recorded_generation: u64 = recorded["generation"].as_str().unwrap().parse().unwrap();
    assert_eq!(production_etag(recorded_generation, 1), recorded["etag"]);
    assert_eq!(
        local["etag"],
        production_etag(meta.generation, meta.metageneration)
    );
}

/// A Storage delivery's runner frame carries the instant the runtime admitted the event as
/// `admittedAt`, apart from the event's own `time` (a finalize event's `time` is the object's
/// creation instant). A 1st gen handler's `context.timestamp` is cut from `admittedAt`.
#[tokio::test]
async fn a_storage_delivery_frame_carries_the_admission_instant_apart_from_the_event_time() {
    let dir = std::env::temp_dir().join(format!("fireemu-storage-frame-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("frames");
    let (runtime, _clock) = start_with_runtime_options_and_env(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        4,
        true,
        vec![(
            "FIREEMU_FAKE_FRAME_LOG".to_owned(),
            log.display().to_string(),
        )],
        |_| {},
    )
    .await;
    wait_for_runner(&runtime).await;
    // The object was created 5.000123 s before the runtime admits its finalize event.
    let created = LogicalInstant::from_nanos(START.as_nanos() - 5_000_123_000);
    let mut store = StorageState::new(1);
    let meta = store
        .put(
            &BucketName::try_new("demo-app.appspot.com").unwrap(),
            &ObjectName::try_new("a.txt").unwrap(),
            b"x".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            created,
        )
        .unwrap();
    runtime.on_storage_event(&StorageEvent::Finalized(meta));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let frame = loop {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if let Some(line) = text.lines().find(|line| line.contains("\"slow\"")) {
            break serde_json::from_str::<serde_json::Value>(line).unwrap();
        }
        assert!(std::time::Instant::now() < deadline, "no frame: {text}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let parse = |value: &serde_json::Value| LogicalInstant::parse_rfc3339(value.as_str().unwrap());
    assert_eq!(parse(&frame["admittedAt"]).unwrap(), START);
    assert_eq!(parse(&frame["event"]["time"]).unwrap(), created);
    assert!(parse(&frame["admittedAt"]).unwrap() > parse(&frame["event"]["time"]).unwrap());
    runtime.shutdown().await;
    std::fs::remove_dir_all(&dir).unwrap();
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
        "//firestore.googleapis.com/projects/demo-app/databases/(default)"
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
    let s = storage_event("e3", ObjectEvent::Finalized, &meta, START, None);
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
fn gen2_firestore_source_is_database_for_all_document_events() {
    let before = doc("documents/one/databases/two", 1);
    let after = doc("documents/one/databases/two", 2);
    for (kind, old, new) in [
        (DocumentEvent::Created, None, Some(&after)),
        (DocumentEvent::Updated, Some(&before), Some(&after)),
        (DocumentEvent::Deleted, Some(&before), None),
        (DocumentEvent::Written, None, Some(&after)),
        (DocumentEvent::Written, Some(&before), None),
        (DocumentEvent::Written, Some(&before), Some(&after)),
    ] {
        let event = firestore_event(
            "source-gate",
            "documents",
            "databases",
            "nam5",
            "documents/one/databases/two",
            kind,
            old,
            new,
            START,
            Some(("system", Some("u1"))),
        );
        assert_eq!(
            event["source"], "//firestore.googleapis.com/projects/documents/databases/databases",
            "Gen2 source must identify only the database"
        );
        assert_eq!(event["subject"], "documents/documents/one/databases/two");
        assert_eq!(event["authtype"], "system");
        assert_eq!(event["authid"], "u1");
        assert_eq!(
            event["time"],
            fireemu_adapter_functions::events::firestore_time(START)
        );
    }
}

/// The real cached SDK is required: absence or version drift fails this adoption gate.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn real_sdk_rust_builder_framed_runner_handler_source_gate() {
    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let sdk = std::env::var("FE_SOURCE_SDK_ROOT").unwrap_or_else(|_| {
        root.join("conformance/node_modules/firebase-functions")
            .to_string_lossy()
            .into_owned()
    });
    let package: serde_json::Value = serde_json::from_slice(
        &std::fs::read(Path::new(&sdk).join("package.json"))
            .expect("cached real firebase-functions is required"),
    )
    .unwrap();
    assert_eq!(package["version"], "7.3.2");
    let dir =
        Fixture(std::env::temp_dir().join(format!("fireemu-source-sdk-{}", std::process::id())));
    std::fs::create_dir(&dir.0).unwrap();
    std::fs::write(
        dir.0.join("package.json"),
        r#"{"private":true,"main":"index.cjs"}"#,
    )
    .unwrap();
    let fixture = r"
const {appendFileSync}=require('node:fs');
const {join}=require('node:path');
const v1=require(join(SDK,'lib/v1/index.js'));
const v2=require(join(SDK,'lib/v2/providers/firestore.js'));
const snap=s=>({path:s.ref.path,id:s.id,exists:s.exists,data:s.data()??null,createTime:s.createTime?.toDate().toISOString()??null,updateTime:s.updateTime?.toDate().toISOString()??null});
const report=(name,d,e)=>{appendFileSync(join(__dirname,'observations.jsonl'),JSON.stringify({name,data:d.before?{before:snap(d.before),after:snap(d.after)}:snap(d),event:e,emulator:process.env.FUNCTIONS_EMULATOR})+'\n');return Promise.resolve();};
for(const [kind,method]of Object.entries({created:'onCreate',updated:'onUpdate',deleted:'onDelete',written:'onWrite'})){
 exports[kind+'V1']=v1.firestore.document('items/{id}')[method]((d,c)=>report(kind+'V1',d,c));
 exports[kind+'V2']=v2[{created:'onDocumentCreated',updated:'onDocumentUpdated',deleted:'onDocumentDeleted',written:'onDocumentWritten'}[kind]]('items/{id}',e=>report(kind+'V2',e.data,{...e,data:undefined}));
}
exports.authV2=v2.onDocumentCreatedWithAuthContext('items/{id}',e=>report('authV2',e.data,{...e,data:undefined}));
exports.authWrittenV2=v2.onDocumentWrittenWithAuthContext('items/{id}',e=>report('authWrittenV2',e.data,{...e,data:undefined}));
let wire;
const rich=v2.onDocumentWritten('items/{id}',e=>{
 appendFileSync(join(__dirname,'observations.jsonl'),JSON.stringify({name:'richV2',wire,data:{before:snap(e.data.before),after:snap(e.data.after)},event:{...e,data:undefined}})+'\n');
});
exports.richV2=Object.assign(async e=>{
 if(!Buffer.isBuffer(e.data))throw Error('expected actual protobuf bytes');
 const codec=require(join(SDK,'protos/compiledFirestore.js')).google.events.cloud.firestore.v1.DocumentEventData;
 wire=codec.toObject(codec.decode(e.data),{longs:String,bytes:String});
 return rich(e);
},rich);
let retried=false;
exports.retryV2=v2.onDocumentCreated({document:'items/{id}',retry:true},async e=>{
 await report('retryV2',e.data,{...e,data:undefined});
 if(!retried){retried=true;throw Error('intentional local retry');}
});
const raw=(name,e)=>{appendFileSync(join(__dirname,'observations.jsonl'),JSON.stringify({name,event:e,emulator:process.env.FUNCTIONS_EMULATOR})+'\n');return Promise.resolve();};
exports.topicV2=require(join(SDK,'lib/v2/providers/pubsub.js')).onMessagePublished('t',e=>raw('topicV2',e));
exports.customV2=require(join(SDK,'lib/v2/providers/eventarc.js')).onCustomEventPublished({eventType:'example.custom',channel:'locations/us-central1/channels/firebase'},e=>raw('customV2',e));
";
    std::fs::write(
        dir.0.join("index.cjs"),
        format!("const SDK={};\n{fixture}", json!(sdk)),
    )
    .unwrap();
    let mut command: Vec<String> = std::env::var("FE_SOURCE_RUNNER_PREFIX").map_or_else(
        |_| vec!["node".to_owned()],
        |s| serde_json::from_str(&s).unwrap(),
    );
    command.extend([
        root.join("tools/runner-node/index.mjs")
            .to_string_lossy()
            .into_owned(),
        "--source".into(),
        dir.0.to_string_lossy().into_owned(),
    ]);
    let mut env = vec![
        ("GCLOUD_PROJECT".into(), "demo-app".into()),
        (
            "NODE_PATH".into(),
            Path::new(&sdk)
                .parent()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        ),
    ];
    if let Ok(receipts) = std::env::var("FE_SOURCE_RECEIPTS") {
        env.push(("FE_SOURCE_RECEIPTS".into(), receipts));
    }
    let runner = Runner::spawn_spec(&SpawnSpec {
        command,
        cwd: Some(dir.0.to_string_lossy().into_owned()),
        env,
        hello_timeout: RUNNER_HELLO_TIMEOUT,
    })
    .await
    .unwrap();
    let before = doc("items/one", 1);
    let after = doc("items/one", 2);
    let cases = [
        (DocumentEvent::Created, "created", None, Some(&after)),
        (
            DocumentEvent::Updated,
            "updated",
            Some(&before),
            Some(&after),
        ),
        (DocumentEvent::Deleted, "deleted", Some(&before), None),
        (DocumentEvent::Written, "written", None, Some(&after)),
        (DocumentEvent::Written, "written", Some(&before), None),
        (
            DocumentEvent::Written,
            "written",
            Some(&before),
            Some(&after),
        ),
    ];
    let mut deliveries = Vec::new();
    for (kind, name, old, new) in cases {
        let mut event = firestore_event(
            "real-source",
            "demo-app",
            "(default)",
            "nam5",
            "items/one",
            kind,
            old,
            new,
            START,
            None,
        );
        event["params"] = json!({"id":"one"});
        for generation in [1, 2] {
            let function = format!("{name}V{generation}");
            let invocation = runner.invoke(json!({"type":"invoke","invocationId":format!("source-{}",deliveries.len()),"function":function,"entryPoint":function,"trigger":"firestore","event":event}), Duration::from_secs(10)).await;
            deliveries.push((
                invocation.outcome,
                generation,
                kind,
                old.map(|_| 1),
                new.map(|_| 2),
                event.clone(),
            ));
        }
    }
    let mut auth = firestore_event(
        "auth-source",
        "demo-app",
        "(default)",
        "nam5",
        "items/one",
        DocumentEvent::Created,
        None,
        Some(&after),
        START,
        Some(("system", Some("principal"))),
    );
    auth["params"] = json!({"id":"one"});
    let auth_outcome = runner.invoke(json!({"type":"invoke","invocationId":"auth-source","function":"authV2","entryPoint":"authV2","trigger":"firestore","event":auth}), Duration::from_secs(10)).await.outcome;
    // Replay the same immutable producer payload; this is not a production retry recording.
    let replay = &deliveries[0].5;
    let replay_outcome = runner.invoke(json!({"type":"invoke","invocationId":"source-replay","function":"createdV2","entryPoint":"createdV2","trigger":"firestore","event":replay}), Duration::from_secs(10)).await.outcome;
    let mut topic = fireemu_adapter_functions::events::pubsub_event(
        "topic-source",
        "demo-app",
        "us-central1",
        "topicFn",
        "t",
        &json!({"data":"aGVsbG8=","attributes":{"key":"value"}}),
        START,
    );
    // Typed Firestore-like extensions must not change another product's source.
    for key in ["project", "database", "document"] {
        topic[key] = replay[key].clone();
    }
    let custom = json!({"specversion":"1.0","id":"custom-id","type":"example.custom","source":"//example/custom-source","subject":"custom-subject","time":replay["time"],"data":{"v":3},"project":"demo-app","database":"(default)","document":"items/one"});
    let mut other_outcomes = Vec::new();
    for (function, trigger, event) in [
        ("topicV2", "pubsub", &topic),
        ("customV2", "eventarc", &custom),
    ] {
        other_outcomes.push(runner.invoke(json!({"type":"invoke","invocationId":function,"function":function,"entryPoint":function,"trigger":trigger,"event":event}), Duration::from_secs(10)).await.outcome);
    }
    let mut retry_outcomes = Vec::new();
    for attempt in [1, 2] {
        retry_outcomes.push(runner.invoke(json!({"type":"invoke","invocationId":format!("retry-{attempt}"),"function":"retryV2","entryPoint":"retryV2","trigger":"firestore","event":replay}), Duration::from_secs(10)).await.outcome);
    }
    let mut rich = after.clone();
    let nanosecond =
        fireemu_core_firestore::value::Timestamp::new(1_790_769_798, 846_431_123).unwrap();
    rich.fields
        .insert("large".into(), FsValue::Integer(i64::MAX));
    rich.fields
        .insert("small".into(), FsValue::Integer(i64::MIN));
    rich.fields
        .insert("bytes".into(), FsValue::Bytes(vec![0, 1, 255]));
    rich.fields.insert(
        "nested".into(),
        FsValue::Map(
            [(
                "arr".into(),
                FsValue::Array(vec![
                    FsValue::Timestamp(nanosecond),
                    FsValue::Bytes(vec![0, 1, 255]),
                ]),
            )]
            .into_iter()
            .collect(),
        ),
    );
    let mut rich_event = firestore_event(
        "rich",
        "demo-app",
        "(default)",
        "nam5",
        "items/one",
        DocumentEvent::Written,
        None,
        Some(&rich),
        START,
        None,
    );
    rich_event["params"] = json!({"id":"one"});
    let rich_outcome = runner.invoke(json!({"type":"invoke","invocationId":"rich","function":"richV2","entryPoint":"richV2","trigger":"firestore","event":rich_event}), Duration::from_secs(10)).await.outcome;
    let mut written_auth = firestore_event(
        "written-auth",
        "demo-app",
        "(default)",
        "nam5",
        "items/one",
        DocumentEvent::Written,
        Some(&rich),
        None,
        START,
        Some(("system", Some("principal"))),
    );
    written_auth["params"] = json!({"id":"one"});
    let written_auth_outcome = runner.invoke(json!({"type":"invoke","invocationId":"written-auth","function":"authWrittenV2","entryPoint":"authWrittenV2","trigger":"firestore","event":written_auth}), Duration::from_secs(10)).await.outcome;
    let bytes = std::fs::read_to_string(dir.0.join("observations.jsonl"));
    runner.shutdown().await;
    assert!(!runner.is_alive());
    for (outcome, ..) in &deliveries {
        assert_eq!(
            outcome,
            &fireemu_adapter_functions::runner::InvokeOutcome::Ok,
            "actual SDK decode must succeed"
        );
    }
    assert_eq!(
        auth_outcome,
        fireemu_adapter_functions::runner::InvokeOutcome::Ok
    );
    assert_eq!(
        replay_outcome,
        fireemu_adapter_functions::runner::InvokeOutcome::Ok
    );
    for outcome in other_outcomes {
        assert_eq!(
            outcome,
            fireemu_adapter_functions::runner::InvokeOutcome::Ok
        );
    }
    let observations: Vec<serde_json::Value> = bytes
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert!(
        matches!(&retry_outcomes[0], fireemu_adapter_functions::runner::InvokeOutcome::Failed(message) if message.contains("intentional local retry")),
        "actual retry outcomes: {retry_outcomes:?}"
    );
    assert_eq!(
        retry_outcomes[1],
        fireemu_adapter_functions::runner::InvokeOutcome::Ok
    );
    assert_eq!(
        rich_outcome,
        fireemu_adapter_functions::runner::InvokeOutcome::Ok
    );
    assert_eq!(
        written_auth_outcome,
        fireemu_adapter_functions::runner::InvokeOutcome::Ok
    );
    assert_eq!(observations.len(), 20);
    let document = "projects/demo-app/databases/(default)/documents/items/one";
    let database = "//firestore.googleapis.com/projects/demo-app/databases/(default)";
    for (observation, (_, generation, kind, old, new, event)) in
        observations.iter().zip(&deliveries)
    {
        let expected = |n: Option<i32>| json!({"path":"items/one","id":"one","exists":n.is_some(),"data":n.map(|v|json!({"v":v})),"createTime":n.map(|_|"2026-08-29T12:01:00.000Z"),"updateTime":n.map(|_|"2026-08-29T12:01:00.000Z")});
        let data = if matches!(kind, DocumentEvent::Updated | DocumentEvent::Written) {
            json!({"before":expected(*old),"after":expected(*new)})
        } else {
            expected(if *kind == DocumentEvent::Deleted {
                *old
            } else {
                *new
            })
        };
        assert_eq!(
            observation["data"], data,
            "snapshot path, values and timestamps"
        );
        assert_eq!(observation["event"]["params"], json!({"id":"one"}));
        assert_eq!(observation["emulator"], "true");
        if *generation == 1 {
            assert_eq!(
                observation["event"]["resource"],
                json!({"service":"firestore.googleapis.com","name":document}),
                "Gen1 typed document resource"
            );
            assert_eq!(
                observation["event"]["eventId"],
                format!("{}-0", event["id"].as_str().unwrap())
            );
            assert_eq!(observation["event"]["timestamp"], event["time"]);
        } else {
            assert_eq!(
                observation["event"]["source"], database,
                "Gen2 canonical database source for every document event"
            );
            for key in [
                "id", "subject", "time", "type", "project", "database", "document",
            ] {
                assert_eq!(observation["event"][key], event[key], "{key}");
            }
        }
    }
    assert_eq!(observations[12]["event"]["authType"], "system");
    assert_eq!(observations[12]["event"]["authId"], "principal");
    assert_eq!(
        observations[13]["event"], observations[1]["event"],
        "replay preserves the same identity and envelope"
    );
    assert_eq!(observations[13]["data"], observations[1]["data"]);
    assert_eq!(
        observations[14]["event"]["source"], topic["source"],
        "PubSub source remains the topic"
    );
    assert_eq!(
        observations[14]["event"]["data"]["message"]["data"],
        "aGVsbG8="
    );
    assert_eq!(
        observations[15]["event"], custom,
        "Eventarc retains the entire custom envelope"
    );
    assert_eq!(
        observations[16], observations[17],
        "actual failing and successful SDK retry callbacks retain identity and data"
    );
    let wire = &observations[18]["wire"];
    assert!(
        wire.get("oldValue").is_none(),
        "missing before stays omitted"
    );
    assert_eq!(
        wire["value"]["fields"]["large"]["integerValue"],
        i64::MAX.to_string()
    );
    assert_eq!(
        wire["value"]["fields"]["small"]["integerValue"],
        i64::MIN.to_string()
    );
    assert_eq!(wire["value"]["fields"]["bytes"]["bytesValue"], "AAH/");
    assert_eq!(
        wire["value"]["fields"]["nested"]["mapValue"]["fields"]["arr"]["arrayValue"]["values"][0]
            ["timestampValue"],
        json!({"seconds":"1790769798","nanos":846_431_123})
    );
    assert_eq!(observations[18]["data"]["before"]["exists"], false);
    assert_eq!(observations[18]["data"]["after"]["path"], "items/one");
    assert_eq!(observations[18]["event"]["source"], database);
    assert_eq!(observations[19]["data"]["after"]["exists"], false);
    assert_eq!(observations[19]["data"]["after"]["id"], "one");
    assert_eq!(observations[19]["event"]["authType"], "system");
    assert_eq!(observations[19]["event"]["authId"], "principal");
    assert_eq!(observations[19]["event"]["source"], database);
}

proptest::proptest! {
    #[test]
    fn firestore_source_projection_obeys_the_product_model(
        project in "[a-z][a-z0-9]{0,12}", database in "[a-z][a-z0-9]{0,12}",
        collection in "[a-z][a-z0-9]{0,12}", id in "[a-z][a-z0-9]{0,12}",
        kind in 0u8..4,
    ) {
        let path = format!("{collection}/{id}");
        let kinds = [DocumentEvent::Created, DocumentEvent::Updated, DocumentEvent::Deleted, DocumentEvent::Written];
        let event = firestore_event("property", &project, &database, "nam5", &path, kinds[usize::from(kind)], None, None, START, None);
        let expected = format!("//firestore.googleapis.com/projects/{project}/databases/{database}");
        proptest::prop_assert_eq!(&event["source"], &json!(expected));
        proptest::prop_assert_eq!(&event["subject"], &json!(format!("documents/{path}")));
        proptest::prop_assert_eq!(&event["data"], &json!({}));
    }
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

#[test]
fn invalid_iana_zone_error_does_not_claim_daylight_saving_is_unsupported() {
    let error = fireemu_adapter_functions::zone::resolve(Some("Mars/Olympus"))
        .err()
        .expect("the zone is not in the IANA database");
    assert_eq!(error, "unknown time zone \"Mars/Olympus\"");
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

/// A handler that is really still running (it never answers) makes its function busy, so
/// under `skip` and `reject` both a manual run and a clock-driven occurrence meet the policy.
#[tokio::test]
async fn a_really_running_handler_makes_skip_and_reject_refuse_the_next_run() {
    use fireemu_adapter_functions::runtime::{CatchUpPolicy, OverlapPolicy};
    for overlap in [OverlapPolicy::Skip, OverlapPolicy::Reject] {
        let (runtime, clock) = start_with_policies_and_manifest(overlap, CatchUpPolicy::All, |m| {
            let mut slow = parse_manifest(&json!({"functions": [{
                "name": "slowTick",
                "generation": 2,
                "trigger": {"type": "schedule", "schedule": "every 5 minutes"}
            }]}))
            .unwrap();
            m.functions.append(&mut slow.functions);
        })
        .await;
        runtime.run_schedule("slowTick").unwrap();
        for _ in 0..100 {
            if runtime.status()["running"].as_u64() >= Some(1) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            runtime.status()["running"],
            1,
            "{overlap:?}: the handler runs"
        );
        let refused = |runtime: &FunctionsRuntime| -> usize {
            let tag = match overlap {
                OverlapPolicy::Skip => "skipped: overlap",
                _ => "rejected: overlap",
            };
            runtime
                .history()
                .iter()
                .chain(runtime.dead_letters().iter())
                .filter(|r| r.function == "slowTick" && r.outcome == tag)
                .count()
        };
        // A manual run while the handler runs is refused and recorded.
        assert!(runtime.run_schedule("slowTick").is_err(), "{overlap:?}");
        assert_eq!(refused(&runtime), 1, "{overlap:?}: manual run");
        // So is the occurrence a clock move brings due.
        clock
            .lock()
            .unwrap()
            .advance(fireemu_core_types::time::LogicalDuration::from_seconds(300))
            .unwrap();
        runtime.on_clock_changed();
        assert_eq!(refused(&runtime), 2, "{overlap:?}: clock-driven occurrence");
        assert_eq!(
            runtime.status()["running"],
            1,
            "{overlap:?}: still one handler"
        );
        runtime.shutdown().await;
    }
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
    let e = pubsub_event(
        "m1",
        "demo-app",
        "us-central1",
        "onJob",
        "jobs",
        &msg,
        START,
    );
    assert_eq!(e["type"], "google.cloud.pubsub.topic.v1.messagePublished");
    assert_eq!(
        e["source"],
        "//pubsub.googleapis.com/projects/demo-app/topics/jobs"
    );
    assert_eq!(e["data"]["message"]["messageId"], "m1");
    assert_eq!(e["data"]["message"]["data"], "aGVsbG8=");
    assert_eq!(e["data"]["message"]["attributes"]["k"], "v");
    assert_eq!(e["data"]["message"]["orderingKey"], "o");
    // Eventarc's own subscription for the function, in the form production names it.
    let subscription = e["data"]["subscription"].as_str().unwrap();
    let id = subscription
        .strip_prefix("projects/demo-app/subscriptions/")
        .unwrap();
    assert!(id.starts_with("eventarc-us-central1-onjob-"), "{id}");
    assert!(id.ends_with(|c: char| c.is_ascii_digit()), "{id}");
    assert_eq!(
        id,
        fireemu_adapter_functions::events::eventarc_subscription_id(
            "demo-app",
            "us-central1",
            "onJob"
        )
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
    let cursor = runtime.history_since(None).cursor;
    store.delete_user_by_id(uid.as_str()).unwrap();
    for e in store.take_user_events() {
        runtime.on_user_event(&e);
    }
    let deadline = tokio::time::Instant::now()
        + RUNNER_HELLO_TIMEOUT
        + Duration::from_secs(u64::from(DEFAULT_TIMEOUT_SECONDS) + 1);
    loop {
        let delta = runtime.history_since(Some(cursor));
        assert!(!delta.resync, "the crash-retry cursor remains valid");
        let outcomes: Vec<&str> = delta
            .records
            .iter()
            .filter(|r| r.record.function == "onGone")
            .map(|r| r.record.outcome.as_str())
            .collect();
        if outcomes.iter().any(|o| o.starts_with("runner gone"))
            && outcomes.contains(&"ok")
            && runtime.is_idle()
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the crash retry did not complete within its spawn and invocation contracts: {outcomes:?}; {}",
            runtime.status()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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

fn advance(clock: &Mutex<VirtualClock>, seconds: i64) {
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(seconds))
        .unwrap();
}

fn count_function(runtime: &FunctionsRuntime, function: &str) -> usize {
    runtime
        .history()
        .iter()
        .filter(|r| r.function == function && r.outcome == "ok")
        .count()
}

#[tokio::test]
async fn full_catch_up_cap_still_releases_due_retries() {
    // Cap 1: the retry-waiting `fail` event fills the catch-up room, so the 10-minute jump
    // keeps one `tick` run pending. Due retries must still be released on every clock
    // change, and the pending run must follow once the room frees.
    let (runtime, clock) = start_with_catch_up_cap(1).await;
    runtime.on_commit(&commit(vec![DocumentChange {
        path: doc("items/a", 1).path,
        before: None,
        after: Some(doc("items/a", 1).into()),
    }]));
    let _ = runtime.await_idle(Duration::from_millis(300)).await;
    advance(&clock, 10 * 60);
    runtime.on_clock_changed();
    let _ = runtime.await_idle(Duration::from_millis(300)).await;
    for _ in 0..3 {
        advance(&clock, 60);
        runtime.on_clock_changed();
        let _ = runtime.await_idle(Duration::from_millis(300)).await;
    }
    assert!(
        runtime.await_idle(Duration::from_secs(3)).await.is_ok(),
        "{}",
        runtime.status()
    );
    let dead = runtime.dead_letters();
    assert_eq!(dead.len(), 1, "{dead:?}");
    assert_eq!((dead[0].function.as_str(), dead[0].attempt), ("fail", 4));
    // `every 5 minutes` runs on the five-minute marks: 12:05 and 12:10 by 12:14.
    assert_eq!(
        count_function(&runtime, "tick"),
        2,
        "{:?}",
        runtime.history()
    );
}

#[tokio::test]
async fn full_catch_up_cap_still_wakes_delayed_events() {
    use fireemu_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule, FaultState};
    // Cap 1: the first `tick` run is held by an hour-long `delay` fault while the rest of
    // the 10-minute jump stays pending. Passing the hold must wake the dispatcher.
    let (runtime, clock) = start_with_catch_up_cap(1).await;
    let faults = Arc::new(Mutex::new(FaultState::default()));
    faults.lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "functions.invoke".into(),
                nth: Some(1),
                function: Some("tick".into()),
                event_type: None,
            },
            action: FaultAction::Delay { seconds: 3600 },
        }],
    });
    runtime.set_faults(faults);
    advance(&clock, 10 * 60);
    runtime.on_clock_changed();
    assert!(
        runtime
            .await_idle(Duration::from_millis(300))
            .await
            .is_err(),
        "held by the delay"
    );
    assert_eq!(count_function(&runtime, "tick"), 0);
    // While the held run fills the room, a clock change inside the hold enqueues nothing
    // more: the backlog stays pending instead of exceeding the cap.
    advance(&clock, 60);
    runtime.on_clock_changed();
    let _ = runtime.await_idle(Duration::from_millis(300)).await;
    assert_eq!(count_function(&runtime, "tick"), 0, "{}", runtime.status());
    assert_eq!(runtime.status()["catchUpPending"], true);
    advance(&clock, 59 * 60);
    runtime.on_clock_changed();
    assert!(
        runtime.await_idle(Duration::from_secs(5)).await.is_ok(),
        "{}",
        runtime.status()
    );
    // 12:01 plus 70 minutes: the five-minute marks from 12:05 to 13:10.
    assert_eq!(
        count_function(&runtime, "tick"),
        14,
        "{:?}",
        runtime.history()
    );
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: 24,
        ..proptest::test_runner::Config::default()
    })]

    /// Model: with the `all` policy every `tick` occurrence in `(START, end]` runs exactly
    /// once (the five-minute marks; START is 60 s past one), and every failing event reaches
    /// its last attempt, whatever the catch-up cap and the sequence of clock jumps.
    #[test]
    fn catch_up_conserves_schedule_runs_and_releases_retries(
        cap in 1usize..=3,
        failing in 0usize..=2,
        jumps in proptest::collection::vec(
            proptest::prop_oneof![
                proptest::strategy::Just(30i64),
                proptest::strategy::Just(60),
                proptest::strategy::Just(300),
                proptest::strategy::Just(600),
            ],
            1..5,
        ),
    ) {
        let tokio = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        tokio.block_on(async {
            let (runtime, clock) = start_with_catch_up_cap(cap).await;
            for i in 0..failing {
                let path = format!("items/p{i}");
                runtime.on_commit(&commit(vec![DocumentChange {
                    path: doc(&path, 1).path,
                    before: None,
                    after: Some(doc(&path, 1).into()),
                }]));
            }
            let _ = runtime.await_idle(Duration::from_millis(150)).await;
            let mut elapsed = 0i64;
            // The jumps under test, then four minutes to drain the 10/20/40 s backoffs.
            for seconds in jumps.iter().copied().chain([60, 60, 60, 60]) {
                advance(&clock, seconds);
                elapsed += seconds;
                runtime.on_clock_changed();
                let _ = runtime.await_idle(Duration::from_millis(150)).await;
            }
            let idle = runtime.await_idle(Duration::from_secs(5)).await;
            let status = runtime.status();
            let ticks = count_function(&runtime, "tick");
            let oks = count_function(&runtime, "ok");
            let dead: Vec<(String, u32)> = runtime
                .dead_letters()
                .iter()
                .map(|d| (d.function.clone(), d.attempt))
                .collect();
            runtime.shutdown().await;
            assert!(idle.is_ok(), "{status}");
            assert_eq!(ticks, usize::try_from((60 + elapsed) / 300).unwrap());
            assert_eq!(oks, failing);
            assert_eq!(dead, vec![("fail".to_owned(), 4); failing]);
        });
    }
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
async fn http_completion_after_reset_keeps_only_current_epoch_records() {
    let (runtime, _clock) = start().await;
    let echo = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    assert_eq!(
        runtime
            .invoke_http(&echo, "POST", "/echo", &[], &[])
            .await
            .unwrap()
            .status,
        200
    );
    let hold = runtime
        .http_target("demo-app", "us-central1", "hold")
        .unwrap();
    let held_runtime = runtime.clone();
    let request = tokio::spawn(async move {
        held_runtime
            .invoke_http(&hold, "POST", "/hold", &[], &[])
            .await
    });
    for _ in 0..100 {
        if runtime.status()["running"].as_u64().unwrap_or(0) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        runtime.status()["running"].as_u64().unwrap_or(0) > 0,
        "the HTTP request did not enter: {}",
        runtime.status()
    );
    assert!(
        !request.is_finished(),
        "the HTTP request finished before reset"
    );

    runtime.reset();
    runtime.reset();
    let _ = tokio::time::timeout(Duration::from_secs(4), request)
        .await
        .expect("the old HTTP invocation settled after reset")
        .unwrap();
    wait_for_runner(&runtime).await;
    let echo = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    assert_eq!(
        runtime
            .invoke_http(&echo, "POST", "/echo", &[], &[])
            .await
            .unwrap()
            .status,
        200
    );
    let history = runtime.history();
    runtime.shutdown().await;
    assert_eq!(
        history
            .iter()
            .filter(|record| record.function == "echo")
            .count(),
        2,
        "the records before reset and from the current epoch survive: {history:?}"
    );
    assert!(
        history.iter().all(|record| record.function != "hold"),
        "the stale HTTP invocation appended a record: {history:?}"
    );
}

#[tokio::test]
async fn stream_start_failure_after_reset_does_not_record_the_old_invocation() {
    let (runtime, _clock) = start().await;
    let hold = runtime
        .http_target("demo-app", "us-central1", "hold")
        .unwrap();
    let held_runtime = runtime.clone();
    let request = tokio::spawn(async move {
        held_runtime
            .invoke_http_stream(&hold, "POST", "/hold", &[], &[])
            .await
    });
    for _ in 0..100 {
        if runtime.status()["running"].as_u64().unwrap_or(0) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        runtime.status()["running"].as_u64().unwrap_or(0) > 0,
        "the stream did not enter: {}",
        runtime.status()
    );
    assert!(!request.is_finished(), "the stream finished before reset");

    runtime.reset();
    let _ = tokio::time::timeout(Duration::from_secs(4), request)
        .await
        .expect("the old stream start settled after reset")
        .unwrap();
    let history = runtime.history();
    runtime.shutdown().await;
    assert!(
        history.iter().all(|record| record.function != "hold"),
        "the stale stream start appended a record: {history:?}"
    );
}

#[tokio::test]
async fn stream_body_completion_after_reset_does_not_record_the_old_invocation() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (runtime, _clock) = start().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        assert!(socket.read(&mut request).await.unwrap() > 0);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-type: text/event-stream\r\n\r\n")
            .await
            .unwrap();
        released.await.unwrap();
        socket.write_all(b"4\r\ntest\r\n0\r\n\r\n").await.unwrap();
    });
    let mut target = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    target.addr = addr.to_string();
    let started = runtime
        .invoke_http_stream(&target, "POST", "/echo", &[], &[])
        .await
        .unwrap();
    let fireemu_adapter_functions::runtime::HttpStreamStart::Streaming(mut response) = started
    else {
        panic!("the runner sent streaming headers");
    };
    assert_eq!(response.status, 200);

    runtime.reset();
    release.send(()).unwrap();
    assert_eq!(response.body.recv().await.unwrap().as_ref(), b"test");
    assert!(response.body.recv().await.is_none());
    response.terminal.await.unwrap().unwrap();
    server.await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let history = runtime.history();
    runtime.shutdown().await;
    assert!(
        history.iter().all(|record| record.function != "echo"),
        "the stale stream body appended a record: {history:?}"
    );
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
    wait_for_runner(&runtime).await;
    let cursor = runtime.history_since(None).cursor;
    runtime.on_commit(&commit(vec![DocumentChange {
        path: doc("items/z", 1).path,
        before: None,
        after: Some(doc("items/z", 1).into()),
    }]));
    wait_for_ok_since(&runtime, cursor).await;
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
async fn messages_published_through_the_runtime_get_seventeen_digit_decimal_ids() {
    // Production's message ids are seventeen-digit decimal strings, not counts or session
    // strings (FUNCTIONS-EVENTS formal record 2026-10-04, `messageId` of the 2nd gen frames
    // 6ac2a47f0000967f445e8b09 and 6ac2a51c000844422b7986d1).
    let (runtime, _clock) = start().await;
    let ids = runtime.publish(
        "jobs",
        &[
            serde_json::json!({"data": "YQ=="}),
            serde_json::json!({"data": "Yg=="}),
        ],
    );
    let silent = runtime.publish("nobody", &[serde_json::json!({"data": ""})]);
    let mut all: Vec<String> = ids.into_iter().chain(silent).collect();
    for id in &all {
        assert_eq!(id.len(), 17, "{id}");
        assert!(id.bytes().all(|byte| byte.is_ascii_digit()), "{id}");
    }
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 3, "the ids are all different");
    assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
}

#[tokio::test]
async fn messages_published_to_a_topic_nobody_listens_to_still_get_different_ids() {
    // Pub/Sub assigns ids even when nothing is subscribed; no delivery advances the counter here,
    // so the publish itself must.
    let (runtime, _clock) = start().await;
    let ids = runtime.publish(
        "nobody",
        &[
            serde_json::json!({"data": "YQ=="}),
            serde_json::json!({"data": "Yg=="}),
            serde_json::json!({"data": "Yw=="}),
        ],
    );
    let mut distinct = ids.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), 3, "{ids:?}");
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
    let idle = runtime.resources(RootBudget::DEFAULT).unwrap();
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
    let busy = runtime.resources(RootBudget::DEFAULT).unwrap();
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

#[tokio::test]
async fn an_await_idle_timeout_explains_the_outstanding_event_and_its_source() {
    let (runtime, _clock) = start().await;
    runtime.on_storage_event(&slow_object("held.txt"));
    let status = runtime
        .await_idle(Duration::from_millis(600))
        .await
        .expect_err("the slow handler keeps the runtime busy");
    let causality = &status["causality"];
    assert_eq!(causality["epoch"], runtime.status()["epoch"], "{status}");
    assert_eq!(causality["truncated"], false);
    assert_eq!(causality["evicted"], 0);
    assert_eq!(causality["resetGaps"], 0);
    let events = causality["events"].as_array().expect("events");
    let held = events
        .iter()
        .find(|e| e["function"] == "slow")
        .unwrap_or_else(|| panic!("the slow event is listed: {status}"));
    assert_eq!(held["source"], "storage");
    assert_eq!(
        held["eventType"],
        "google.cloud.storage.object.v1.finalized"
    );
    assert!(
        held["parent"]
            .as_str()
            .is_some_and(|p| p.starts_with("storage-generation:")),
        "{held}"
    );
    let phases: Vec<&str> = held["phases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["phase"].as_str().unwrap())
        .collect();
    assert_eq!(phases[0], "registered");
    assert!(phases.contains(&"running"), "{phases:?}");
    assert!(!phases.contains(&"completed"));
    assert_eq!(held["phases"][1]["attempt"], 1);
    assert!(
        !status.to_string().contains("held.txt"),
        "no payload or subject: {status}"
    );
    runtime.reset();
}

#[tokio::test]
async fn causality_records_retry_and_terminal_failure_and_the_idle_answer_is_unchanged() {
    let (runtime, clock) = start().await;
    runtime.on_commit(&commit(vec![DocumentChange {
        path: doc("items/a", 1).path,
        before: None,
        after: Some(doc("items/a", 1).into()),
    }]));
    let busy = runtime
        .await_idle(Duration::from_millis(800))
        .await
        .expect_err("the failing handler is retry-waiting");
    let events = busy["causality"]["events"].as_array().unwrap().clone();
    let failing = events.iter().find(|e| e["function"] == "fail").unwrap();
    let phases: Vec<&str> = failing["phases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["phase"].as_str().unwrap())
        .collect();
    assert_eq!(phases, ["registered", "running", "retry"], "{failing}");
    assert!(failing["parent"]
        .as_str()
        .is_some_and(|p| p.starts_with("firestore-commit:")));
    let ok = events.iter().find(|e| e["function"] == "ok").unwrap();
    assert!(ok["phases"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["phase"] == "completed"));

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
    let settled = runtime.status();
    let failing = settled["causality"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["function"] == "fail")
        .unwrap()
        .clone();
    let phases: Vec<&str> = failing["phases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["phase"].as_str().unwrap())
        .collect();
    assert_eq!(phases.last(), Some(&"failed"), "{phases:?}");
    assert_eq!(
        phases.iter().filter(|p| **p == "retry").count(),
        3,
        "{phases:?}"
    );
    assert_eq!(
        phases.iter().filter(|p| **p == "running").count(),
        4,
        "{phases:?}"
    );
}

#[tokio::test]
async fn the_causality_window_is_bounded_and_a_reset_is_a_gap_not_a_completion() {
    let (runtime, _clock) = start().await;
    runtime.set_causality_retention(2);
    for body in ["a", "b", "c"] {
        let ids = runtime.publish("jobs", &[json!({"json": {"job": body}})]);
        assert_eq!(ids.len(), 1);
        assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
    }
    let status = runtime.status();
    let causality = &status["causality"];
    assert_eq!(causality["retained"], 2, "{causality}");
    assert!(causality["evicted"].as_u64().unwrap() >= 1, "{causality}");
    assert_eq!(causality["events"].as_array().unwrap().len(), 2);

    runtime.on_storage_event(&slow_object("late.txt"));
    for _ in 0..200 {
        if runtime.status()["running"].as_u64().unwrap_or(0) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    runtime.reset();
    let after = runtime.status();
    assert_eq!(after["causality"]["resetGaps"], 1, "{after}");
    assert_eq!(after["causality"]["events"].as_array().unwrap().len(), 0);
    assert_eq!(after["causality"]["epoch"], after["epoch"]);
    // The old epoch's slow event is neither completed nor listed as still running.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        runtime.status()["causality"]["events"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn refused_source_admissions_are_counted_by_category_until_a_reset() {
    use fireemu_core_types::resources::RootBudget;
    let (runtime, _clock) = start().await;
    let refusals = |runtime: &Arc<FunctionsRuntime>| {
        runtime
            .resources(RootBudget::DEFAULT)
            .unwrap()
            .refusals
            .into_iter()
            .map(|r| (r.reason, r.count))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    assert_eq!(refusals(&runtime).get("admission.unavailable"), None);
    runtime.begin_shutdown();
    assert!(runtime
        .reserve_storage_event(&slow_object("late.txt"))
        .is_err());
    assert!(runtime
        .reserve_commit_events(&commit(vec![DocumentChange {
            path: doc("items/z", 1).path,
            before: None,
            after: Some(doc("items/z", 1).into()),
        }]))
        .is_err());
    assert_eq!(refusals(&runtime).get("admission.unavailable"), Some(&2));
    assert_eq!(refusals(&runtime).get("admission.capacity"), None);
    runtime.shutdown().await;
}

/// A manual run's refusal reads as its message, whichever kind it is (the control API and logs
/// show it as is).
#[test]
fn a_schedule_run_refusal_displays_its_message() {
    use fireemu_adapter_functions::runtime::ScheduleRunError;
    assert_eq!(
        ScheduleRunError::Capacity("the queue is full".to_owned()).to_string(),
        "the queue is full"
    );
    assert_eq!(
        ScheduleRunError::Refused("function \"ok\" is not scheduled".to_owned()).to_string(),
        "function \"ok\" is not scheduled"
    );
}

// ---------------------------------------------------------------------------------------------
// Manual schedule runs and the schedule across lifecycle boundaries.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_manual_run_of_an_unknown_or_unscheduled_function_is_refused_and_changes_nothing() {
    use fireemu_adapter_functions::runtime::ScheduleRunError;
    let (runtime, _clock) = start().await;
    assert_eq!(
        runtime.run_schedule("noSuchJob"),
        Err(ScheduleRunError::Refused(
            "unknown function \"noSuchJob\"".to_owned()
        ))
    );
    // `ok` is a registered function, but not a scheduled one.
    let unscheduled = runtime.run_schedule("ok");
    assert!(
        matches!(&unscheduled, Err(ScheduleRunError::Refused(m)) if m.contains("is not scheduled")),
        "{unscheduled:?}"
    );
    assert!(runtime.is_idle(), "nothing was enqueued");
    assert!(runtime.history().is_empty());
    assert_eq!(runtime.status()["pending"], 0);
    runtime.shutdown().await;
}

#[tokio::test]
async fn a_schedule_run_queued_while_the_runner_is_stopped_survives_a_reload_and_runs_once() {
    let (runtime, clock) = start().await;
    let guard = runtime
        .stop_runner_for_fixed_inspector_reload("default")
        .await
        .unwrap();
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(5 * 60))
        .unwrap();
    runtime.on_clock_changed();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!runtime.is_idle(), "the 12:05 run waits for a runner");
    assert!(runtime.history().is_empty());
    let spec = SpawnSpec {
        command: vec![
            "python3".to_owned(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py").to_owned(),
        ],
        cwd: None,
        env: Vec::new(),
        hello_timeout: RUNNER_HELLO_TIMEOUT,
    };
    let replacement = Arc::new(Runner::spawn_spec(&spec).await.unwrap());
    runtime
        .reload_codebase(CodebaseSpec {
            name: "default".to_owned(),
            manifest: runtime.manifest().clone(),
            runner: replacement,
            spawn: Some(spec),
            cleanup_dir: None,
        })
        .unwrap();
    drop(guard);
    runtime.await_idle(Duration::from_secs(3)).await.unwrap();
    let ticks = |runtime: &FunctionsRuntime| {
        runtime
            .history()
            .iter()
            .filter(|r| r.function == "tick" && r.outcome == "ok")
            .count()
    };
    assert_eq!(ticks(&runtime), 1, "the queued run was delivered once");
    // The reload kept the schedule's cursor: 12:05 is not run again, 12:10 is.
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(5 * 60))
        .unwrap();
    runtime.on_clock_changed();
    runtime.await_idle(Duration::from_secs(3)).await.unwrap();
    assert_eq!(ticks(&runtime), 2);
    runtime.shutdown().await;
}

#[tokio::test]
async fn a_schedule_run_is_delivered_once_after_the_runner_died_before_it() {
    let (runtime, clock) = start().await;
    runtime.runner().kill_now();
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(5 * 60))
        .unwrap();
    runtime.on_clock_changed();
    runtime.await_idle(Duration::from_secs(5)).await.unwrap();
    let ticks = runtime
        .history()
        .iter()
        .filter(|r| r.function == "tick" && r.outcome == "ok")
        .count();
    assert_eq!(ticks, 1);
    runtime.shutdown().await;
}

#[tokio::test]
async fn queue_runs_one_scheduled_invocation_at_a_time_where_allow_runs_several() {
    use fireemu_adapter_functions::runtime::{CatchUpPolicy, OverlapPolicy};
    for (overlap, running) in [(OverlapPolicy::Queue, 1u64), (OverlapPolicy::Allow, 2)] {
        let (runtime, _clock) =
            start_with_policies_and_manifest(overlap, CatchUpPolicy::All, |m| {
                // A function whose name contains "slow" never answers, so what runs at once is
                // exactly what dispatch admitted.
                let mut slow = parse_manifest(&json!({"functions": [{
                    "name": "slowTick",
                    "generation": 2,
                    "concurrency": 5,
                    "trigger": {"type": "schedule", "schedule": "every 5 minutes"}
                }]}))
                .unwrap();
                m.functions.append(&mut slow.functions);
            })
            .await;
        runtime.run_schedule("slowTick").unwrap();
        runtime.run_schedule("slowTick").unwrap();
        for _ in 0..100 {
            if runtime.status()["running"].as_u64() >= Some(running) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Let a second invocation start if the policy allows one.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let status = runtime.status();
        assert_eq!(status["running"], running, "{overlap:?}: {status}");
        assert_eq!(status["pending"], 2 - running, "{overlap:?}: {status}");
        runtime.shutdown().await;
    }
}

/// An Archived event (a generation of a versioned bucket became noncurrent) carries the time it
/// stopped being live: as `timeDeleted` in the object resource and as the `CloudEvent` time. The
/// shape is RECORDED (FE v5); the Archived event and the Deleted event of a noncurrent generation
/// are the only ones that carry `timeDeleted`.
#[test]
fn an_archived_event_carries_the_time_the_generation_stopped_being_live() {
    let mut store = StorageState::new(1);
    let bucket = BucketName::try_new("versioned-bucket").unwrap();
    store.set_versioning(&bucket, true);
    let put = |store: &mut StorageState, at: LogicalInstant| {
        store
            .put(
                &bucket,
                &ObjectName::try_new("o.txt").unwrap(),
                b"x".to_vec(),
                NewMetadata::default(),
                Precondition::default(),
                at,
            )
            .unwrap()
    };
    let first = put(&mut store, START);
    let deleted = START.checked_add(LogicalDuration::from_seconds(5)).unwrap();
    let second = put(&mut store, deleted);
    let archived = storage_event("e9", ObjectEvent::Archived, &first, START, Some(deleted));
    assert_eq!(archived["type"], "google.cloud.storage.object.v1.archived");
    assert_eq!(archived["subject"], "objects/o.txt");
    assert_eq!(archived["data"]["generation"], first.generation.to_string());
    // The instant the generation stopped being live is the instant of the overwrite: the
    // creation time of the generation that replaced it, in both places it is printed.
    let finalized = storage_event("e9", ObjectEvent::Finalized, &second, START, None);
    assert_eq!(archived["time"], finalized["time"]);
    assert_eq!(
        archived["data"]["timeDeleted"],
        finalized["data"]["timeCreated"]
    );
    // No other event carries timeDeleted, and the data otherwise is the object resource.
    assert!(finalized["data"].get("timeDeleted").is_none());
    let mut without = archived["data"].clone();
    without.as_object_mut().unwrap().remove("timeDeleted");
    assert_eq!(
        without,
        storage_event("e9", ObjectEvent::Finalized, &first, START, None)["data"]
    );
}

/// Archived events reach the functions that subscribed to them and only those; the Finalized
/// events of the same overwrite reach the finalize ones. The overwrite announces Finalized first
/// (the observed order, FE v5).
#[tokio::test]
async fn archived_events_reach_archived_functions_and_finalized_events_finalized_ones() {
    let (runtime, _clock) = start_with_policies_and_manifest(
        fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
        fireemu_adapter_functions::runtime::CatchUpPolicy::All,
        |manifest| {
            manifest.functions.extend(
                parse_manifest(&json!({"functions": [
                    {"name": "archivedObserver", "generation": 2, "trigger": {"type": "storage", "eventType": "google.cloud.storage.object.v1.archived", "bucket": "versioned-bucket"}},
                    {"name": "finalizedObserver", "generation": 2, "trigger": {"type": "storage", "eventType": "google.cloud.storage.object.v1.finalized", "bucket": "versioned-bucket"}},
                    {"name": "otherBucketArchived", "generation": 2, "trigger": {"type": "storage", "eventType": "google.cloud.storage.object.v1.archived", "bucket": "elsewhere"}},
                ]}))
                .unwrap()
                .functions,
            );
        },
    )
    .await;
    let mut store = StorageState::new(1);
    let bucket = BucketName::try_new("versioned-bucket").unwrap();
    store.set_versioning(&bucket, true);
    for (data, at) in [(&b"one"[..], START), (&b"two"[..], START)] {
        store
            .put(
                &bucket,
                &ObjectName::try_new("o.txt").unwrap(),
                data.to_vec(),
                NewMetadata::default(),
                Precondition::default(),
                at,
            )
            .unwrap();
    }
    let events = store.drain_events();
    assert_eq!(events.len(), 3, "{events:?}");
    for event in &events {
        runtime.on_storage_event(event);
    }
    assert!(runtime.await_idle(Duration::from_secs(10)).await.is_ok());
    let ran = |function: &str| {
        runtime
            .history()
            .iter()
            .filter(|record| record.function == function && record.outcome == "ok")
            .count()
    };
    assert_eq!(ran("archivedObserver"), 1, "one generation was archived");
    assert_eq!(
        ran("finalizedObserver"),
        2,
        "two generations were finalized"
    );
    assert_eq!(ran("otherBucketArchived"), 0, "another bucket's trigger");
    runtime.runner().shutdown().await;
}

/// The real `firebase-functions` 7.3.2 SDK's `onArchive` (v1) and `onObjectArchived` (v2) handlers
/// receive an Archived event with the object resource, `timeDeleted` included. The Archived event
/// shape is RECORDED in FE v5; this pins what the local runtime delivers to the real handlers.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn real_sdk_archived_handlers_receive_the_archived_event() {
    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let sdk = std::env::var("FE_SOURCE_SDK_ROOT").unwrap_or_else(|_| {
        root.join("conformance/node_modules/firebase-functions")
            .to_string_lossy()
            .into_owned()
    });
    let package: serde_json::Value = serde_json::from_slice(
        &std::fs::read(Path::new(&sdk).join("package.json"))
            .expect("cached real firebase-functions is required"),
    )
    .unwrap();
    assert_eq!(package["version"], "7.3.2");
    let dir =
        Fixture(std::env::temp_dir().join(format!("fireemu-archived-sdk-{}", std::process::id())));
    std::fs::create_dir(&dir.0).unwrap();
    std::fs::write(
        dir.0.join("package.json"),
        r#"{"private":true,"main":"index.cjs"}"#,
    )
    .unwrap();
    let fixture = r"
const {appendFileSync}=require('node:fs');
const {join}=require('node:path');
const v1=require(join(SDK,'lib/v1/index.js'));
const v2=require(join(SDK,'lib/v2/providers/storage.js'));
const seen=(name,object,event)=>{appendFileSync(join(__dirname,'observations.jsonl'),JSON.stringify({name,object,event})+'\n');return Promise.resolve();};
exports.archivedV1=v1.storage.bucket('versioned-bucket').object().onArchive((object,context)=>seen('archivedV1',object,context));
exports.archivedV2=v2.onObjectArchived({bucket:'versioned-bucket'},(event)=>seen('archivedV2',event.data,{...event,data:undefined}));
";
    std::fs::write(
        dir.0.join("index.cjs"),
        format!("const SDK={};\n{fixture}", json!(sdk)),
    )
    .unwrap();
    let mut command: Vec<String> = std::env::var("FE_SOURCE_RUNNER_PREFIX").map_or_else(
        |_| vec!["node".to_owned()],
        |s| serde_json::from_str(&s).unwrap(),
    );
    command.extend([
        root.join("tools/runner-node/index.mjs")
            .to_string_lossy()
            .into_owned(),
        "--source".into(),
        dir.0.to_string_lossy().into_owned(),
    ]);
    let runner = Runner::spawn_spec(&SpawnSpec {
        command,
        cwd: Some(dir.0.to_string_lossy().into_owned()),
        env: vec![
            ("GCLOUD_PROJECT".into(), "demo-app".into()),
            (
                "NODE_PATH".into(),
                Path::new(&sdk)
                    .parent()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            ),
        ],
        hello_timeout: RUNNER_HELLO_TIMEOUT,
    })
    .await
    .unwrap();
    let mut store = StorageState::new(1);
    let bucket = BucketName::try_new("versioned-bucket").unwrap();
    store.set_versioning(&bucket, true);
    let put = |store: &mut StorageState, data: &[u8], at: LogicalInstant| {
        store
            .put(
                &bucket,
                &ObjectName::try_new("dir/o.txt").unwrap(),
                data.to_vec(),
                NewMetadata::default(),
                Precondition::default(),
                at,
            )
            .unwrap()
    };
    let first = put(&mut store, b"one", START);
    let deleted = START.checked_add(LogicalDuration::from_seconds(5)).unwrap();
    put(&mut store, b"two", deleted);
    let event = storage_event(
        "77-1",
        ObjectEvent::Archived,
        &first,
        deleted,
        Some(deleted),
    );
    let mut outcomes = Vec::new();
    for (id, function) in [("v1", "archivedV1"), ("v2", "archivedV2")] {
        outcomes.push(
            runner
                .invoke(
                    json!({"type":"invoke","invocationId":format!("archived-{id}"),"function":function,"entryPoint":function,"trigger":"storage","event":event}),
                    Duration::from_secs(10),
                )
                .await
                .outcome,
        );
    }
    let bytes = std::fs::read_to_string(dir.0.join("observations.jsonl"));
    runner.shutdown().await;
    for outcome in &outcomes {
        assert_eq!(
            outcome,
            &fireemu_adapter_functions::runner::InvokeOutcome::Ok,
            "the real SDK decodes the Archived event"
        );
    }
    let text = bytes.unwrap();
    // The 2nd gen handler sees the members of an Archived event's data in the order production
    // sends them (RECORDED, FE v5, 44 v2 frames: `timeDeleted` follows `updated`). The order of a
    // 1st gen `object` was not recorded and is the runner's input order. `serde_json` sorts keys,
    // so the order is read from the text of the observation.
    for line in text.lines().filter(|line| line.contains("\"archivedV2\"")) {
        let object = &line[line.find("\"object\":").unwrap()..];
        let at = |member: &str| object.find(&format!("\"{member}\":")).unwrap();
        assert!(
            at("timeCreated") < at("updated")
                && at("updated") < at("timeDeleted")
                && at("timeDeleted") < at("storageClass"),
            "{line}"
        );
    }
    assert_eq!(
        text.lines()
            .filter(|l| l.contains("\"archivedV2\""))
            .count(),
        1
    );
    let observations: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(observations.len(), 2);
    for observation in &observations {
        let object = &observation["object"];
        assert_eq!(object["name"], "dir/o.txt");
        assert_eq!(object["bucket"], "versioned-bucket");
        assert_eq!(object["generation"], first.generation.to_string());
        assert_eq!(
            object["timeDeleted"], event["data"]["timeDeleted"],
            "{observation}"
        );
    }
    assert_eq!(
        observations[1]["event"]["type"],
        "google.cloud.storage.object.v1.archived"
    );
}
