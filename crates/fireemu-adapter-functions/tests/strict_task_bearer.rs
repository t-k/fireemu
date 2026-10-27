//! A task delivered to an export that the codebase's own discovery declares callable, but that a
//! configured `functions.manifest` serves as a task queue, passes the Bearer check a callable
//! request passes in the strict profile. Without it the only token check the callable wrapper
//! would apply is the Admin SDK's Auth-emulator verification (no signature check), where
//! production's wrapper verifies the ID token signature.
//!
//! The daemon marks such an entry (`PlatformOptions::strict_callable_ingress`) only in the strict
//! profile and only when App Check is not active (with App Check the manifest is refused
//! outright), so a real `onTaskDispatched` queue and the emulator profile are not touched.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
use fireemu_adapter_grpc::rules::RulesEnforcer;
use fireemu_core_auth::jwt::encode_unsigned;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, NewUser};
use fireemu_core_functions::manifest::{TaskRateLimits, TaskRetryConfig, Trigger};
use fireemu_core_rules::runtime::RulesetSlot;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::json;

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const PROJECT: &str = "demo-app";

struct Harness {
    runtime: Arc<FunctionsRuntime>,
    auth: Arc<Mutex<AuthStore>>,
    probe: std::path::PathBuf,
    dir: std::path::PathBuf,
}

/// A runtime with one task queue, `taskA`, served by the fake runner. `callable_in_code` marks
/// it the way the daemon does for a callable that a configured manifest presents as a queue.
async fn start(name: &str, callable_in_code: bool) -> Harness {
    let dir = std::env::temp_dir().join(format!(
        "fireemu-strict-task-bearer-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("entries");
    // The fake runner holds a task until its release file exists.
    std::fs::write(format!("{}.taskA.release", probe.display()), b"").unwrap();
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: vec![(
            "FIREEMU_FAKE_TASK_PROBE".to_owned(),
            probe.display().to_string(),
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
    function.platform_options.strict_callable_ingress = callable_in_code;
    manifest.functions.push(function);
    let clock = Arc::new(Mutex::new(VirtualClock::new(START)));
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            project: PROJECT.into(),
            functions_host: Some("127.0.0.1:5001".into()),
            ..FunctionsConfig::for_tests(1, "runner-secret".into())
        },
        clock.clone(),
        Arc::new(runner),
        Some(spec),
    );
    let auth = Arc::new(Mutex::new(AuthStore::new(
        PROJECT,
        SplitMix64::new(3),
        TotpPolicy::default(),
    )));
    runtime.set_callable_auth_verifier(Arc::new(RulesEnforcer::new(
        Arc::new(RulesetSlot::default()),
        auth.clone(),
        clock,
    )));
    tokio::spawn(runtime.clone().dispatch_loop());
    Harness {
        runtime,
        auth,
        probe,
        dir,
    }
}

impl Harness {
    fn user_bearer(&self, email: &str) -> String {
        let mut store = self.auth.lock().unwrap();
        let uid = store.create_user(NewUser::email(email), START).unwrap();
        let claims = store.id_token_claims(&uid, None, START).unwrap();
        format!("Bearer {}", encode_unsigned(&claims))
    }

    /// Enqueues a task carrying `authorization` (when given) and returns how many tasks the
    /// runner received once the queue is idle.
    async fn delivered(&self, id: &str, authorization: Option<&str>) -> usize {
        let before = entries(&self.probe);
        let mut http = json!({"url": "", "body": "eyJkYXRhIjp7fX0="});
        if let Some(authorization) = authorization {
            http["headers"] = json!({"Authorization": authorization});
        }
        let body = json!({"task": {
            "name": format!("projects/demo-app/locations/us-central1/queues/task/tasks/{id}"),
            "httpRequest": http,
        }});
        self.runtime
            .enqueue_task("demo-app", "us-central1", "taskA", &body)
            .unwrap();
        tokio::time::timeout(Duration::from_secs(4), async {
            while !self.runtime.is_idle() {
                self.runtime.idle_notify().notified().await;
            }
        })
        .await
        .expect("the task queue became idle");
        entries(&self.probe) - before
    }

    async fn stop(self) {
        self.runtime.shutdown().await;
        let _ = std::fs::remove_dir_all(self.dir);
    }
}

fn entries(probe: &Path) -> usize {
    std::fs::read_to_string(probe)
        .unwrap_or_default()
        .lines()
        .count()
}

#[tokio::test]
async fn a_task_to_a_callable_in_code_needs_a_bearer_a_callable_request_would_accept() {
    let h = start("callable", true).await;
    let valid = h.user_bearer("ada@example.com");
    // Refused before the runner, as a callable request is.
    assert_eq!(h.delivered("t1", Some("Bearer malformed")).await, 0);
    assert_eq!(h.delivered("t2", Some(&format!("{valid}x"))).await, 0);
    // What the callable route lets through: a verified user, no credential, and other schemes
    // or an empty token (left to the handler).
    assert_eq!(h.delivered("t3", Some(&valid)).await, 1);
    assert_eq!(h.delivered("t4", None).await, 1);
    assert_eq!(h.delivered("t5", Some("Basic YQ==")).await, 1);
    assert_eq!(h.delivered("t6", Some("Bearer ")).await, 1);
    h.stop().await;
}

#[tokio::test]
async fn a_real_task_queue_is_delivered_whatever_its_authorization_says() {
    let h = start("queue", false).await;
    assert_eq!(h.delivered("t1", Some("Bearer malformed")).await, 1);
    assert_eq!(h.delivered("t2", None).await, 1);
    h.stop().await;
}
