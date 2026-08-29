//! Functions runtime wiring: runner process, event subscriptions, control hooks.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ftd_adapter_functions::manifest_json::parse_manifest;
use ftd_adapter_functions::runner::Runner;
use ftd_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_http::control::FunctionsHook;
use ftd_core_session::clock::VirtualClock;
use ftd_core_storage::store::StorageEvent;
use ftd_core_types::ids::SessionId;

use crate::config::RuntimeConfig;

/// Addresses the runner's functions need to reach the daemon.
pub struct EmulatorHosts {
    /// Firestore gRPC / REST.
    pub firestore: String,
    /// Auth REST.
    pub auth: String,
    /// Storage.
    pub storage: String,
}

/// The bundled Node runner (overridable with `FTD_RUNNER_NODE`).
fn default_runner() -> Vec<String> {
    let script = std::env::var("FTD_RUNNER_NODE").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tools/runner-node/index.mjs"
        )
        .to_owned()
    });
    vec!["node".to_owned(), script]
}

/// Starts the runner and the runtime for `cfg.functions_source`, subscribing it to Firestore
/// commits and Storage events.
pub async fn start(
    cfg: &RuntimeConfig,
    clock: &Arc<Mutex<VirtualClock>>,
    backend: &Arc<LocalBackend>,
    hosts: &EmulatorHosts,
    storage_events: tokio::sync::mpsc::UnboundedReceiver<StorageEvent>,
) -> Result<Arc<FunctionsRuntime>, String> {
    let source = cfg
        .functions_source
        .clone()
        .ok_or_else(|| "functions.source is not configured".to_owned())?;
    if !Path::new(&source).is_dir() {
        return Err(format!("functions.source {source:?} is not a directory"));
    }
    let mut command = cfg.functions_runner.clone().unwrap_or_else(default_runner);
    command.push("--source".to_owned());
    command.push(source.clone());
    let default_bucket = format!("{}.appspot.com", cfg.auth_project);
    let env = vec![
        ("GCLOUD_PROJECT".to_owned(), cfg.auth_project.clone()),
        ("GOOGLE_CLOUD_PROJECT".to_owned(), cfg.auth_project.clone()),
        ("FUNCTIONS_EMULATOR".to_owned(), "true".to_owned()),
        (
            "FIRESTORE_EMULATOR_HOST".to_owned(),
            hosts.firestore.clone(),
        ),
        ("FIREBASE_AUTH_EMULATOR_HOST".to_owned(), hosts.auth.clone()),
        (
            "FIREBASE_STORAGE_EMULATOR_HOST".to_owned(),
            hosts.storage.clone(),
        ),
        (
            "STORAGE_EMULATOR_HOST".to_owned(),
            format!("http://{}", hosts.storage),
        ),
        (
            "FIREBASE_CONFIG".to_owned(),
            serde_json::json!({"projectId": cfg.auth_project, "storageBucket": default_bucket})
                .to_string(),
        ),
        ("FTD_RUNNER".to_owned(), "1".to_owned()),
    ];
    let runner = Runner::spawn(&command, None, &env, Duration::from_secs(60)).await?;
    let manifest_json = match &cfg.functions_manifest {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("functions manifest {path}: {e}"))?;
            serde_json::from_str(&text).map_err(|e| format!("functions manifest {path}: {e}"))?
        }
        None => runner
            .hello()
            .manifest
            .clone()
            .ok_or_else(|| "the functions runner did not discover a manifest".to_owned())?,
    };
    let manifest = parse_manifest(&manifest_json)?;
    let config = FunctionsConfig {
        project: cfg.auth_project.clone(),
        default_bucket,
        location: "nam5".to_owned(),
        session: SessionId::new(u128::from(cfg.seed)),
        max_running: cfg.functions_max_running,
    };
    let runtime = FunctionsRuntime::new(manifest, config, clock.clone(), Arc::new(runner));
    tokio::spawn(runtime.clone().dispatch_loop());
    {
        let runtime = runtime.clone();
        let mut commits = backend.subscribe();
        tokio::spawn(async move {
            loop {
                match commits.recv().await {
                    Ok(event) => runtime.on_commit(&event),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("[functions] {n} Firestore commit events were dropped (subscriber lagged)");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }
    {
        let runtime = runtime.clone();
        let mut storage_events = storage_events;
        tokio::spawn(async move {
            while let Some(event) = storage_events.recv().await {
                runtime.on_storage_event(&event);
            }
        });
    }
    Ok(runtime)
}

/// The runtime as the control API's hook.
pub struct Hook(pub Arc<FunctionsRuntime>);

impl FunctionsHook for Hook {
    fn on_clock_changed(&self) {
        self.0.on_clock_changed();
    }

    fn run_schedule(&self, function: &str) -> Result<(), String> {
        self.0.run_schedule(function)
    }

    fn is_idle(&self) -> bool {
        self.0.is_idle()
    }

    fn idle_notify(&self) -> Arc<tokio::sync::Notify> {
        self.0.idle_notify()
    }

    fn status(&self) -> serde_json::Value {
        self.0.status()
    }
}
