//! `firebase-testd` command-line entry point.
//!
//! ```text
//! firebase-testd up [--config firebase-testd.json] [--firestore-port 8080] [--http-port 9099] [--storage-port 9199]
//! firebase-testd doctor
//! firebase-testd capabilities
//! ```
//!
//! `up` serves the Firestore v1 gRPC API (local execution behind the strict gateway), the
//! Identity Toolkit REST subset and the control API on loopback until Ctrl-C.

mod config;
mod control;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, RwLock};

use ftd_adapter_grpc::gateway::Gateway;
use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_grpc::rest::RestState;
use ftd_adapter_grpc::rules::RulesEnforcer;
use ftd_adapter_grpc::serve::serve_multiplexed;
use ftd_adapter_grpc::service::GatewayService;
use ftd_adapter_http::identity_toolkit::AuthState;
use ftd_core_auth::mfa::TotpPolicy;
use ftd_core_auth::store::AuthStore;
use ftd_core_firestore::index::{IndexSet, PlanningContext};
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::SplitMix64;
use ftd_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;

use crate::config::RuntimeConfig;

fn usage() -> ExitCode {
    eprintln!("usage: firebase-testd up [--config <file>] [--firestore-port <n>] [--http-port <n>] [--storage-port <n>]\n       firebase-testd doctor\n       firebase-testd capabilities");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("up") => match parse_up(&args[1..]) {
            Ok(cfg) => run_up(cfg),
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
        Some("doctor") => {
            println!("firebase-testd {}", env!("CARGO_PKG_VERSION"));
            println!(
                "vendored googleapis commit: {}",
                ftd_proto_firestore::UPSTREAM_COMMIT.trim()
            );
            println!(
                "limit catalogs: {}",
                ftd_core_limits::catalogs::ALL_CATALOGS
                    .iter()
                    .map(|c| c.meta.id)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            ExitCode::SUCCESS
        }
        Some("capabilities") => {
            println!(
                "{}",
                serde_json::to_string_pretty(&control::capabilities_manifest()).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        _ => usage(),
    }
}

fn parse_up(args: &[String]) -> Result<RuntimeConfig, String> {
    let mut config_path: Option<PathBuf> = None;
    let mut firestore_port: Option<u16> = None;
    let mut http_port: Option<u16> = None;
    let mut storage_port: Option<u16> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                config_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or("--config needs a value")?,
                ));
                i += 2;
            }
            "--firestore-port" => {
                firestore_port = Some(
                    args.get(i + 1)
                        .ok_or("--firestore-port needs a value")?
                        .parse()
                        .map_err(|e| format!("--firestore-port: {e}"))?,
                );
                i += 2;
            }
            "--storage-port" => {
                storage_port = Some(
                    args.get(i + 1)
                        .ok_or("--storage-port needs a value")?
                        .parse()
                        .map_err(|e| format!("--storage-port: {e}"))?,
                );
                i += 2;
            }
            "--http-port" => {
                http_port = Some(
                    args.get(i + 1)
                        .ok_or("--http-port needs a value")?
                        .parse()
                        .map_err(|e| format!("--http-port: {e}"))?,
                );
                i += 2;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let mut cfg = match config_path {
        Some(p) => RuntimeConfig::from_file(&p).map_err(|e| e.to_string())?,
        None => RuntimeConfig::default(),
    };
    if let Some(p) = firestore_port {
        cfg.firestore_addr = format!("127.0.0.1:{p}");
    }
    if let Some(p) = http_port {
        cfg.http_addr = format!("127.0.0.1:{p}");
    }
    if let Some(p) = storage_port {
        cfg.storage_addr = format!("127.0.0.1:{p}");
    }
    Ok(cfg)
}

fn load_rules(cfg: &RuntimeConfig) -> Result<LoadedRules, String> {
    match &cfg.rules_file {
        Some(path) => {
            let source =
                std::fs::read_to_string(path).map_err(|e| format!("rules source {path}: {e}"))?;
            LoadedRules::from_source(&source)
                .map_err(|e| format!("rules source {path} does not parse: {e}"))
        }
        None => Ok(LoadedRules::default()),
    }
}

fn load_storage_rules(cfg: &RuntimeConfig) -> Result<LoadedRules, String> {
    match &cfg.storage_rules_file {
        Some(path) => {
            let source = std::fs::read_to_string(path)
                .map_err(|e| format!("storage rules source {path}: {e}"))?;
            LoadedRules::from_source(&source)
                .map_err(|e| format!("storage rules source {path} does not parse: {e}"))
        }
        None => Ok(LoadedRules::default()),
    }
}

fn storage_state(
    cfg: &RuntimeConfig,
    clock: &Arc<Mutex<VirtualClock>>,
    auth_store: &Arc<Mutex<AuthStore>>,
    storage_rules: &Arc<RwLock<LoadedRules>>,
) -> Arc<ftd_adapter_http::storage::StorageState> {
    Arc::new(ftd_adapter_http::storage::StorageState {
        store: Mutex::new(ftd_core_storage::store::StorageState::new(cfg.seed ^ 0x57)),
        clock: clock.clone(),
        auth: auth_store.clone(),
        rules: storage_rules.clone(),
        project: cfg.auth_project.clone(),
        events: None,
    })
}

async fn bind_listeners(
    cfg: &RuntimeConfig,
) -> Result<
    (
        tokio::net::TcpListener,
        tokio::net::TcpListener,
        tokio::net::TcpListener,
    ),
    String,
> {
    let bind = |addr: &str| {
        let addr = addr.to_owned();
        async move {
            tokio::net::TcpListener::bind(&addr)
                .await
                .map_err(|e| format!("bind {addr}: {e}"))
        }
    };
    Ok((
        bind(&cfg.firestore_addr).await?,
        bind(&cfg.http_addr).await?,
        bind(&cfg.storage_addr).await?,
    ))
}

fn print_banner(
    cfg: &RuntimeConfig,
    grpc_addr: std::net::SocketAddr,
    http_addr: std::net::SocketAddr,
    storage_addr: std::net::SocketAddr,
) {
    println!("firebase-testd up");
    println!("  firestore (gRPC + REST): {grpc_addr}   FIRESTORE_EMULATOR_HOST={grpc_addr}");
    println!("  auth (REST):      {http_addr}   FIREBASE_AUTH_EMULATOR_HOST={http_addr}");
    println!("  storage (HTTP):   {storage_addr}   FIREBASE_STORAGE_EMULATOR_HOST={storage_addr}   STORAGE_EMULATOR_HOST=http://{storage_addr}");
    println!("  control API:      http://{http_addr}/v1/  (health: /health/live)");
    println!("  edition: {}   clock: {}", cfg.edition, cfg.clock_start);
}

fn print_rules_status(cfg: &RuntimeConfig, loaded: bool) {
    match (cfg.rules_enforced, loaded) {
        (false, _) => println!("  rules: disabled by config (every request is allowed)"),
        (true, false) => println!(
            "  rules: none loaded; every request is allowed (PUT /v1/rules or rules.source)"
        ),
        (true, true) => println!(
            "  rules: enforced from {}",
            cfg.rules_file.as_deref().unwrap_or("config")
        ),
    }
}

fn control_state(
    cfg: &RuntimeConfig,
    clock: &Arc<Mutex<VirtualClock>>,
    rules: &Arc<RwLock<LoadedRules>>,
    storage_rules: &Arc<RwLock<LoadedRules>>,
    backend: &Arc<LocalBackend>,
    auth_store: &Arc<Mutex<AuthStore>>,
    storage: &Arc<ftd_adapter_http::storage::StorageState>,
) -> ftd_adapter_http::control::ControlState {
    let storage_reset = {
        let storage = storage.clone();
        Arc::new(move || {
            if let Ok(mut s) = storage.store.lock() {
                s.clear();
            }
        }) as Arc<dyn Fn() + Send + Sync>
    };
    let firestore_reset = {
        let backend = backend.clone();
        Arc::new(move || backend.reset()) as Arc<dyn Fn() + Send + Sync>
    };
    let auth_reset = {
        let auth_store = auth_store.clone();
        Arc::new(move || {
            if let Ok(mut s) = auth_store.lock() {
                s.clear();
            }
        }) as Arc<dyn Fn() + Send + Sync>
    };
    ftd_adapter_http::control::ControlState {
        clock: clock.clone(),
        require_demo_prefix: cfg.require_demo_prefix,
        edition: cfg.edition,
        capabilities: control::capabilities_manifest(),
        rules: rules.clone(),
        storage_rules: storage_rules.clone(),
        reset_hooks: vec![firestore_reset, auth_reset, storage_reset],
    }
}

fn run_up(cfg: RuntimeConfig) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async move {
        let clock = Arc::new(Mutex::new(VirtualClock::new(cfg.clock_start)));
        let gateway = Gateway {
            ctx: PlanningContext {
                edition: cfg.edition,
                api_mode: cfg.api_mode,
                policy: cfg.index_policy,
            },
            indexes: match &cfg.index_file {
                Some(path) => control::load_indexes(path)?,
                None => IndexSet::default(),
            },
        };
        let backend = Arc::new(LocalBackend::new(gateway.clone(), clock.clone(), cfg.seed));
        let auth_store = Arc::new(Mutex::new(AuthStore::new(
            &cfg.auth_project,
            SplitMix64::new(cfg.seed ^ 0xA0),
            TotpPolicy::default(),
        )));
        let auth = Arc::new(AuthState {
            store: auth_store.clone(),
            clock: clock.clone(),
        });
        let rules = Arc::new(RwLock::new(load_rules(&cfg)?));
        let storage_rules = Arc::new(RwLock::new(load_storage_rules(&cfg)?));
        let storage = storage_state(&cfg, &clock, &auth_store, &storage_rules);
        let control = Arc::new(control_state(
            &cfg,
            &clock,
            &rules,
            &storage_rules,
            &backend,
            &auth_store,
            &storage,
        ));

        let (grpc_listener, http_listener, storage_listener) = bind_listeners(&cfg).await?;
        let grpc_addr = grpc_listener.local_addr().map_err(|e| e.to_string())?;
        let http_addr = http_listener.local_addr().map_err(|e| e.to_string())?;
        let storage_addr = storage_listener.local_addr().map_err(|e| e.to_string())?;
        print_banner(&cfg, grpc_addr, http_addr, storage_addr);
        print_rules_status(&cfg, rules.read().is_ok_and(|r| r.is_loaded()));

        let enforcer = cfg.rules_enforced.then(|| {
            Arc::new(RulesEnforcer::new(
                rules.clone(),
                auth_store.clone(),
                clock.clone(),
            ))
        });
        let mut service = GatewayService::local(gateway.clone(), backend.clone());
        if let Some(e) = &enforcer {
            service = service.with_rules(e.clone());
        }
        let rest = Arc::new(RestState {
            local: backend.clone(),
            gateway: Arc::new(gateway),
            rules: enforcer,
        });
        let grpc = tokio::spawn(serve_multiplexed(
            grpc_listener,
            // Firestore's request size limit applies to the message (framing is separate).
            FirestoreServer::new(service)
                .max_decoding_message_size(10 * 1024 * 1024)
                .max_encoding_message_size(10 * 1024 * 1024),
            rest,
        ));
        let http = tokio::spawn(ftd_adapter_http::server::serve_with_control(
            http_listener,
            auth,
            control,
        ));
        let storage_server = tokio::spawn(ftd_adapter_http::storage_server::serve_storage(
            storage_listener,
            storage,
        ));
        tokio::select! {
            r = grpc => Err(format!("gRPC server stopped: {r:?}")),
            r = http => Err(format!("HTTP server stopped: {r:?}")),
            r = storage_server => Err(format!("Storage server stopped: {r:?}")),
            _ = tokio::signal::ctrl_c() => {
                println!("shutting down");
                Ok::<(), String>(())
            }
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
