//! Real SDK handlers reached through the capability-protected local control action.
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use fireemu_adapter_functions::http::FunctionsHttpProfile;
use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{
    CodebaseSpec, FunctionsConfig, FunctionsRuntime, SourceEventAdmissionError,
};
use fireemu_adapter_http::control::{
    handle_with, ControlState, FunctionsHook, PublishEventError, RunScheduleError,
};
use fireemu_adapter_http::identity_toolkit::RequestHeaders;
use fireemu_core_rules::runtime::RulesetSlot;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_session::tenancy::Tenancy;
use fireemu_core_types::edition::FirestoreEdition;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};

struct Hook(Arc<FunctionsRuntime>);
impl FunctionsHook for Hook {
    fn on_clock_changed(&self) {
        self.0.on_clock_changed();
    }
    fn run_schedule(&self, _: &str) -> Result<(), RunScheduleError> {
        unreachable!()
    }
    fn is_idle(&self) -> bool {
        self.0.is_idle()
    }
    fn idle_notify(&self) -> Arc<tokio::sync::Notify> {
        self.0.idle_notify()
    }
    fn status(&self) -> Value {
        self.0.status()
    }
    fn publish(
        &self,
        _: &str,
        _: &[Value],
    ) -> Result<Vec<String>, fireemu_adapter_http::control::PublishMessagesError> {
        unreachable!()
    }
    fn project(&self) -> String {
        "demo-app".to_owned()
    }
    fn publish_remote_config(&self, body: &Value) -> Result<usize, PublishEventError> {
        self.0
            .publish_remote_config(body)
            .map_err(|error| match error {
                SourceEventAdmissionError::InvalidEvent => PublishEventError::Invalid,
                SourceEventAdmissionError::Capacity => PublishEventError::Capacity,
                SourceEventAdmissionError::Unavailable => PublishEventError::Unavailable,
            })
    }
}

fn control(runtime: Arc<FunctionsRuntime>, clock: Arc<Mutex<VirtualClock>>) -> ControlState {
    ControlState {
        clock,
        require_demo_prefix: true,
        edition: FirestoreEdition::Standard,
        capabilities: json!({"schemaVersion": 1}).into(),
        rules: Arc::new(RulesetSlot::default()),
        storage_rules: Arc::new(fireemu_adapter_http::storage::StorageRulesRegistry::default()),
        reset_hooks: vec![],
        functions: Some(Arc::new(Hook(runtime))),
        control_token: "fixture-capability".into(),
        app_check: None,
        firestore_listen_expiry: None,
        firestore_missing_indexes: None,
        require_control_token: false,
        barrier: None,
        snapshot_hooks: vec![],
        snapshots: Mutex::new(std::collections::BTreeMap::new()),
        faults: None,
        text_indexes: Arc::new(Mutex::new(
            fireemu_core_firestore::text_index::TextIndexCatalog::default(),
        )),
        default_project: "demo-app".into(),
        tenancy: Arc::new(RwLock::new(Tenancy::new("demo-app"))),
        sessions: Mutex::new(
            [
                ("default".into(), "demo-app".into()),
                ("other".into(), "demo-other".into()),
                ("alias".into(), "demo-app".into()),
            ]
            .into(),
        ),
        project_hooks: None,
        resource_hooks: vec![],
    }
}

fn body(metadata: &str, retry: bool) -> Value {
    let mut body = json!({
        "data": {"versionNumber": 7, "updateTime": "2026-01-02T03:04:05Z"},
        "v1Context": {"eventId": "caller-v1", "timestamp": "2026-01-02T03:04:06Z", "eventType": "google.firebase.remoteconfig.update", "resource": {"service": "firebaseremoteconfig.googleapis.com", "name": "projects/demo-app"}},
        "v2Context": {"specversion": "1.0", "id": "caller-v2", "time": "2026-01-02T03:04:07Z", "type": "google.firebase.remoteconfig.remoteConfig.v1.updated", "source": "//firebaseremoteconfig.googleapis.com/projects/demo-app"}
    });
    if metadata != "absent" {
        body["data"]["updateUser"] = json!({"email": "fixture-actor", "name": "Fixture", "imageUrl": "https://example.invalid/inert"});
        body["data"]["description"] = json!("fixture metadata");
        body["data"]["updateOrigin"] = json!("REST_API");
        body["data"]["updateType"] = json!(if metadata == "rollback" {
            "ROLLBACK"
        } else {
            "INCREMENTAL_UPDATE"
        });
    }
    if metadata == "rollback" {
        body["data"]["rollbackSource"] = json!(3);
    }
    if retry {
        body["data"]["description"] = json!("fail once");
    }
    body
}

fn observed(runtime: &FunctionsRuntime) -> Vec<Value> {
    runtime
        .runner()
        .logs_since(None)
        .lines
        .iter()
        .filter_map(|line| {
            line.message()
                .strip_prefix("REMOTE_CONFIG_EVENT ")
                .map(|text| serde_json::from_str(text).unwrap())
        })
        .collect()
}

async fn wait_rows(runtime: &FunctionsRuntime, count: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if observed(runtime).len() >= count {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("SDK handler records the event");
}

/// PICT rows may be supplied by the private verification run; default rows keep CI useful.
#[tokio::test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires own tools/sdk-smoke npm ci dependencies"]
async fn remote_config_control_delivers_real_sdk_events_in_both_profiles() {
    let rows = std::env::var("REMOTE_CONFIG_PICT").map_or_else(|_| {
        "Generation\tProfile\tMetadata\tCapability\tDelivery\tBackground\nboth\tstrict\tabsent\tvalid\tsuccess\tenabled\nboth\temulator\tfull\tvalid\tretry\tenabled\nv1\tstrict\trollback\tmissing\tsuccess\tenabled\nv2\temulator\tabsent\twrong\tsuccess\tenabled\nboth\tstrict\trollback\tvalid\tsuccess\tdisabled\nboth\tstrict\trollback\tvalid\tretry\tenabled\nboth\temulator\tabsent\tvalid\tsuccess\tenabled\nv1\temulator\tfull\tvalid\tsuccess\tenabled\nv1\tstrict\tabsent\tvalid\tsuccess\tenabled\n".to_owned()
    }, |path| std::fs::read_to_string(path).unwrap());
    for (index, row) in rows.lines().skip(1).enumerate() {
        let columns: Vec<_> = row.split('\t').collect();
        assert_eq!(columns.len(), 6);
        let [generation, profile, metadata, capability, delivery, background] =
            <[&str; 6]>::try_from(columns).unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let runner = Arc::new(
            Runner::spawn_spec(&SpawnSpec {
                command: vec![
                    "node".into(),
                    root.join("tools/runner-node/index.mjs")
                        .display()
                        .to_string(),
                    "--source".into(),
                    root.join("tools/sdk-smoke/functions-project/fixtures/remote-config")
                        .display()
                        .to_string(),
                ],
                cwd: None,
                env: vec![
                    ("GCLOUD_PROJECT".into(), "demo-app".into()),
                    ("FIREEMU_HTTP_PROFILE".into(), profile.into()),
                ],
                hello_timeout: Duration::from_secs(15),
            })
            .await
            .unwrap(),
        );
        let mut manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
        assert_eq!(manifest.functions.len(), 2, "SDK discovery row {index}");
        manifest.functions.retain(|spec| {
            generation == "both"
                || spec.name == format!("configV{}", if generation == "v1" { 1 } else { 2 })
        });
        for spec in &mut manifest.functions {
            if spec.generation == fireemu_core_functions::manifest::FunctionGeneration::Second {
                spec.concurrency = Some(1);
            }
        }
        let targets = manifest.functions.len();
        let clock = Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        )));
        let runtime = FunctionsRuntime::with_codebases(
            vec![CodebaseSpec {
                name: "default".into(),
                manifest,
                runner,
                spawn: None,
                cleanup_dir: None,
            }],
            FunctionsConfig::for_tests(1, "test-secret".into()),
            clock.clone(),
            if profile == "strict" {
                FunctionsHttpProfile::Strict
            } else {
                FunctionsHttpProfile::Emulator
            },
        )
        .unwrap();
        let state = control(runtime.clone(), clock.clone());
        runtime.set_background_triggers(background == "enabled");
        let headers = RequestHeaders {
            authorization: match capability {
                "valid" => Some("Bearer fixture-capability".into()),
                "wrong" => Some("Bearer wrong".into()),
                _ => None,
            },
            ..RequestHeaders::default()
        };
        let mut input = body(metadata, delivery == "retry");
        if generation == "v1" {
            input.as_object_mut().unwrap().remove("v2Context");
        }
        if generation == "v2" {
            input.as_object_mut().unwrap().remove("v1Context");
        }
        let response = handle_with(
            &state,
            "POST",
            "/v1/sessions/default/functions/remoteConfig:publish",
            &headers,
            &input,
        );
        let accepted = capability == "valid";
        assert_eq!(
            response.status,
            if accepted { 200 } else { 403 },
            "row {index}: {}",
            response.body
        );
        let expected = if accepted && background == "enabled" {
            targets
        } else {
            0
        };
        assert_eq!(
            runtime.source_event_accounting().unwrap().published_records,
            expected,
            "row {index}"
        );
        let dispatch = tokio::spawn(runtime.clone().dispatch_loop());
        if expected > 0 {
            wait_rows(&runtime, targets).await;
            if delivery == "retry" {
                // A log precedes failure acknowledgement; wait until all first attempts settle.
                tokio::time::timeout(Duration::from_secs(10), async {
                    while runtime.history().len() < targets {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();
                clock
                    .lock()
                    .unwrap()
                    .advance(LogicalDuration::from_seconds(20))
                    .unwrap();
                runtime.on_clock_changed();
            }
            runtime.await_idle(Duration::from_secs(10)).await.unwrap();
            let records = observed(&runtime);
            assert_eq!(
                records.len(),
                targets * if delivery == "retry" { 2 } else { 1 },
                "row {index}"
            );
            for record in &records {
                assert_eq!(record["data"], input["data"], "row {index}");
                let context = &record["context"];
                if record["generation"] == 1 {
                    for (key, value) in input["v1Context"].as_object().unwrap() {
                        assert_eq!(&context[key], value);
                    }
                } else {
                    // SDK 7.3.2 adds enumerable v1 compatibility accessors. These are
                    // SDK behavior, not fields manufactured by the emulator.
                    assert_eq!(context["version"], input["data"]);
                    assert_eq!(
                        context["context"],
                        json!({
                            "eventId": input["v2Context"]["id"],
                            "timestamp": input["v2Context"]["time"],
                            "eventType": "google.firebase.remoteconfig.update",
                            "resource": {"service": "firebaseremoteconfig.googleapis.com", "name": ""},
                            "params": {},
                        })
                    );
                    let mut envelope = context.clone();
                    envelope.as_object_mut().unwrap().remove("context");
                    envelope.as_object_mut().unwrap().remove("version");
                    assert_eq!(
                        envelope, input["v2Context"],
                        "no emulator-invented v2 fields"
                    );
                }
            }
            // Accepted publications use the ordinary per-function serial queue.
            for version in [8, 9] {
                let mut next = body("absent", false);
                next["data"]["versionNumber"] = json!(version);
                assert_eq!(runtime.publish_remote_config(&next), Ok(targets));
            }
            runtime.await_idle(Duration::from_secs(10)).await.unwrap();
            for gen in [1, 2] {
                let versions: Vec<_> = observed(&runtime)
                    .iter()
                    .filter(|row| {
                        row["generation"] == gen
                            && row["data"]["versionNumber"].as_u64().unwrap() >= 8
                    })
                    .map(|row| row["data"]["versionNumber"].as_u64().unwrap())
                    .collect();
                if generation == "both" || generation == format!("v{gen}") {
                    assert_eq!(versions, [8, 9]);
                }
            }
        } else {
            runtime.await_idle(Duration::from_secs(2)).await.unwrap();
            assert!(observed(&runtime).is_empty());
        }
        runtime.shutdown().await;
        dispatch.await.unwrap();
    }
}
