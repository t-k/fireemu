//! `firebase-testd` command-line entry point.
//!
//! ```text
//! firebase-testd up [options]
//! firebase-testd exec [options] [--only auth,firestore,storage,functions] -- <command...>
//! firebase-testd doctor
//! firebase-testd capabilities
//!
//! options: [--config firebase-testd.json] [--firebase-json firebase.json] [--project <id>]
//!          [--firestore-port 8080] [--http-port 9099] [--storage-port 9199]
//!          [--functions-port 5001] [--functions <dir>]
//! ```
//!
//! `up` serves the Firestore v1 gRPC API (local execution behind the strict gateway), the
//! Identity Toolkit REST subset and the control API on loopback until Ctrl-C. `exec` is the
//! `firebase emulators:exec` equivalent: it serves the same, runs the command with the
//! emulator host variables once every listener is bound, stops everything when the command
//! exits and exits with its status (SIGINT / SIGTERM are forwarded to the command).

mod config;
mod control;
mod functions;
mod sessions;
mod snapshots;

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
use ftd_core_auth::jwt::IdTokenSigner;
use ftd_core_auth::mfa::TotpPolicy;
use ftd_core_auth::store::AuthStore;
use ftd_core_firestore::index::{IndexSet, PlanningContext};
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::SplitMix64;
use ftd_core_types::time::LogicalInstant;
use ftd_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;

use crate::config::{RuntimeConfig, Selection};

const OPTIONS_USAGE: &str = "[--config <file>] [--firebase-json <file>] [--project <id>] [--only auth,firestore,storage,functions] [--firestore-port <n>] [--http-port <n>] [--storage-port <n>] [--functions-port <n>] [--functions <dir>]";

fn usage() -> ExitCode {
    eprintln!("usage: firebase-testd up {OPTIONS_USAGE}\n       firebase-testd exec {OPTIONS_USAGE} -- <command...>\n       firebase-testd doctor\n       firebase-testd capabilities");
    ExitCode::from(2)
}

/// What `exec` runs once the services are up.
struct ExecPlan {
    /// Program and arguments.
    command: Vec<String>,
    /// Services whose host variables the command receives.
    only: Selection,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("up") => match parse_options(&args[1..]) {
            Ok((cfg, _)) => run(cfg, None),
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
        Some("exec") => match parse_exec(&args[1..]) {
            Ok((cfg, plan)) => run(cfg, Some(plan)),
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

/// `exec [options] -- <command...>`.
fn parse_exec(args: &[String]) -> Result<(RuntimeConfig, ExecPlan), String> {
    let split = args
        .iter()
        .position(|a| a == "--")
        .ok_or("exec needs `-- <command...>` after its options")?;
    let command = args[split + 1..].to_vec();
    if command.is_empty() {
        return Err("exec needs a command after --".to_owned());
    }
    let (cfg, only) = parse_options(&args[..split])?;
    Ok((cfg, ExecPlan { command, only }))
}

#[allow(clippy::too_many_lines)]
fn parse_options(args: &[String]) -> Result<(RuntimeConfig, Selection), String> {
    let mut config_path: Option<PathBuf> = None;
    let mut firebase_json: Option<PathBuf> = None;
    let mut project: Option<String> = None;
    let mut only = Selection::default();
    let mut firestore_port: Option<u16> = None;
    let mut http_port: Option<u16> = None;
    let mut storage_port: Option<u16> = None;
    let mut functions_port: Option<u16> = None;
    let mut functions_source: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                config_path = Some(PathBuf::from(
                    args.get(i + 1).ok_or("--config needs a value")?,
                ));
                i += 2;
            }
            "--firebase-json" => {
                firebase_json = Some(PathBuf::from(
                    args.get(i + 1).ok_or("--firebase-json needs a value")?,
                ));
                i += 2;
            }
            "--project" => {
                project = Some(args.get(i + 1).ok_or("--project needs a value")?.clone());
                i += 2;
            }
            "--only" => {
                only = Selection::parse(args.get(i + 1).ok_or("--only needs a list")?)
                    .map_err(|e| e.to_string())?;
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
            "--functions-port" => {
                functions_port = Some(
                    args.get(i + 1)
                        .ok_or("--functions-port needs a value")?
                        .parse()
                        .map_err(|e| format!("--functions-port: {e}"))?,
                );
                i += 2;
            }
            "--functions" => {
                functions_source = Some(
                    args.get(i + 1)
                        .ok_or("--functions needs a directory")?
                        .clone(),
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
    if let Some(path) = firebase_json {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("{} does not parse: {e}", path.display()))?;
        let base = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf);
        let ignored = cfg
            .apply_firebase_json(&json, &base, &only)
            .map_err(|e| e.to_string())?;
        if !ignored.is_empty() {
            eprintln!(
                "note: {} has no equivalent in firebase-testd and is ignored: {}",
                path.display(),
                ignored.join(", ")
            );
        }
    }
    if let Some(project) = project {
        cfg.auth_project = project;
    }
    if !only.functions {
        cfg.functions_source = None;
    }
    if let Some(p) = firestore_port {
        cfg.firestore_addr = format!("127.0.0.1:{p}");
    }
    if let Some(p) = http_port {
        cfg.http_addr = format!("127.0.0.1:{p}");
    }
    if let Some(p) = storage_port {
        cfg.storage_addr = format!("127.0.0.1:{p}");
    }
    if let Some(p) = functions_port {
        cfg.functions_addr = format!("127.0.0.1:{p}");
    }
    if let Some(dir) = functions_source {
        cfg.functions_source = Some(dir);
    }
    Ok((cfg, only))
}

/// The environment the `exec` command receives: the canonical emulator host variables of
/// the selected services, the project, and the control token / URL.
fn child_environment(
    cfg: &RuntimeConfig,
    only: &Selection,
    grpc_addr: std::net::SocketAddr,
    http_addr: std::net::SocketAddr,
    storage_addr: std::net::SocketAddr,
    functions_addr: Option<std::net::SocketAddr>,
    control_token: &str,
) -> Vec<(String, String)> {
    let mut env = vec![
        ("GOOGLE_CLOUD_PROJECT".to_owned(), cfg.auth_project.clone()),
        ("GCLOUD_PROJECT".to_owned(), cfg.auth_project.clone()),
        ("FTD_CONTROL_TOKEN".to_owned(), control_token.to_owned()),
        (
            "FTD_CONTROL_URL".to_owned(),
            format!("http://{http_addr}/v1/"),
        ),
    ];
    if only.firestore {
        env.push(("FIRESTORE_EMULATOR_HOST".to_owned(), grpc_addr.to_string()));
    }
    if only.auth {
        env.push((
            "FIREBASE_AUTH_EMULATOR_HOST".to_owned(),
            http_addr.to_string(),
        ));
    }
    if only.storage {
        env.push((
            "FIREBASE_STORAGE_EMULATOR_HOST".to_owned(),
            storage_addr.to_string(),
        ));
        env.push((
            "STORAGE_EMULATOR_HOST".to_owned(),
            format!("http://{storage_addr}"),
        ));
    }
    if let (true, Some(addr)) = (only.functions, functions_addr) {
        env.push(("FTD_FUNCTIONS_HOST".to_owned(), addr.to_string()));
    }
    env
}

/// The emulator variables `exec` owns: those not selected by `--only` are removed from the
/// command's environment, so a shell configured for other emulators cannot leak into it.
const OWNED_VARIABLES: [&str; 5] = [
    "FIRESTORE_EMULATOR_HOST",
    "FIREBASE_AUTH_EMULATOR_HOST",
    "FIREBASE_STORAGE_EMULATOR_HOST",
    "STORAGE_EMULATOR_HOST",
    "FTD_FUNCTIONS_HOST",
];

/// The command runs in its own process group when the supervisor is not on a terminal
/// (CI, a script), so a signal reaches its whole tree; on a terminal it stays in the
/// foreground group so it keeps the terminal and receives Ctrl-C itself.
fn own_process_group() -> bool {
    use std::io::IsTerminal as _;
    !std::io::stdin().is_terminal()
}

fn spawn_child(plan: &ExecPlan, env: &[(String, String)]) -> Result<tokio::process::Child, String> {
    let (program, args) = plan
        .command
        .split_first()
        .ok_or("exec needs a command after --")?;
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args).kill_on_drop(true);
    for name in OWNED_VARIABLES {
        cmd.env_remove(name);
    }
    cmd.envs(env.iter().cloned());
    if own_process_group() {
        cmd.process_group(0);
    }
    cmd.spawn()
        .map_err(|e| format!("cannot start {program}: {e}"))
}

/// Sends `signal` to the command (`pid` as spawned: `Child::id` is gone once the child was
/// reaped, but its group may still hold a background job): to its process group when it
/// leads one, else to it.
fn signal_child(pid: u32, signal: &str) {
    let target = if own_process_group() {
        format!("-{pid}")
    } else {
        pid.to_string()
    };
    let _ = std::process::Command::new("kill")
        .args([signal, "--", &target])
        .stderr(std::process::Stdio::null())
        .status();
}

/// Waits for the command when there is one; never resolves otherwise.
async fn wait_child(
    child: Option<&mut tokio::process::Child>,
) -> std::io::Result<std::process::ExitStatus> {
    match child {
        Some(child) => child.wait().await,
        None => std::future::pending().await,
    }
}

/// Stops the command after the supervisor received `signal` (`-INT` / `-TERM`): the signal
/// is forwarded with its identity (through `kill(1)`; the crate forbids unsafe code) unless
/// the terminal already delivered it to the command's own group, then SIGKILL to the whole
/// group after ten seconds. Returns the status the command reported.
async fn stop_child(child: &mut tokio::process::Child, pid: u32, signal: &str) -> i32 {
    let terminal_delivered = signal == "-INT" && !own_process_group();
    if !terminal_delivered {
        signal_child(pid, signal);
    }
    if let Ok(Ok(status)) =
        tokio::time::timeout(std::time::Duration::from_secs(10), child.wait()).await
    {
        signal_child(pid, "-KILL");
        exit_code(status)
    } else {
        signal_child(pid, "-KILL");
        let _ = child.kill().await;
        137
    }
}

/// The command's exit code, `128 + signal` when a signal ended it.
fn exit_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
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
    events: Option<ftd_adapter_http::storage::StorageEventSink>,
    backend: &Arc<LocalBackend>,
    faults: &ftd_core_session::fault::SharedFaults,
) -> Result<Arc<ftd_adapter_http::storage::StorageState>, String> {
    let parent = ftd_adapter_grpc::decode::Parent {
        project: ftd_core_types::ids::ProjectId::try_new(cfg.auth_project.clone())
            .map_err(|e| format!("project id: {e}"))?,
        database: ftd_core_types::ids::DatabaseId::try_new("(default)")
            .map_err(|e| format!("database id: {e}"))?,
        document: None,
    };
    Ok(Arc::new(ftd_adapter_http::storage::StorageState {
        store: Mutex::new(ftd_core_storage::store::StorageState::new(cfg.seed ^ 0x57)),
        clock: clock.clone(),
        auth: auth_store.clone(),
        rules: storage_rules.clone(),
        project: cfg.auth_project.clone(),
        events,
        barrier: Some(backend.barrier()),
        firestore: Some(Arc::new(ftd_adapter_grpc::rules::LatestReader {
            backend: backend.clone(),
            parent,
        })),
        faults: Some(faults.clone()),
    }))
}

async fn bind_listeners(
    cfg: &RuntimeConfig,
) -> Result<
    (
        tokio::net::TcpListener,
        tokio::net::TcpListener,
        tokio::net::TcpListener,
        Option<tokio::net::TcpListener>,
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
    let functions = if cfg.functions_source.is_some() {
        Some(bind(&cfg.functions_addr).await?)
    } else {
        None
    };
    Ok((
        bind(&cfg.firestore_addr).await?,
        bind(&cfg.http_addr).await?,
        bind(&cfg.storage_addr).await?,
        functions,
    ))
}

fn print_banner(
    cfg: &RuntimeConfig,
    verb: &str,
    grpc_addr: std::net::SocketAddr,
    http_addr: std::net::SocketAddr,
    storage_addr: std::net::SocketAddr,
    functions_addr: Option<std::net::SocketAddr>,
) {
    println!("firebase-testd {verb}");
    println!("  firestore (gRPC + REST): {grpc_addr}   FIRESTORE_EMULATOR_HOST={grpc_addr}");
    println!("  auth (REST):      {http_addr}   FIREBASE_AUTH_EMULATOR_HOST={http_addr}");
    println!("  storage (HTTP):   {storage_addr}   FIREBASE_STORAGE_EMULATOR_HOST={storage_addr}   STORAGE_EMULATOR_HOST=http://{storage_addr}");
    match functions_addr {
        Some(addr) => println!(
            "  functions (HTTP): {addr}   http://{addr}/{}/us-central1/{{function}}   (source: {})",
            cfg.auth_project,
            cfg.functions_source.as_deref().unwrap_or("")
        ),
        None => {
            println!("  functions:        not configured (functions.source or --functions <dir>)");
        }
    }
    println!("  control API:      http://{http_addr}/v1/  (health: /health/live)");
    println!(
        "  edition: {}   clock: {}{}",
        cfg.edition,
        cfg.clock_start,
        if cfg.clock_start_pinned {
            " (pinned by daemon.clockStart)"
        } else {
            " (wall clock at start; pin with daemon.clockStart)"
        }
    );
}

/// Resolves on SIGTERM (so a killed daemon still stops its runner); never on platforms
/// without it.
async fn terminate_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    }
    #[cfg(not(unix))]
    std::future::pending::<()>().await;
}

/// A 128-bit secret from the operating system's entropy source; the daemon refuses to start
/// without one (these values authorize control and runner access).
fn random_secret() -> Result<String, String> {
    use std::fmt::Write as _;
    use std::io::Read as _;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| format!("cannot read /dev/urandom for the control token: {e}"))?;
    Ok(bytes.iter().fold(String::with_capacity(32), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    }))
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

#[allow(clippy::too_many_arguments)]
fn control_state(
    cfg: &RuntimeConfig,
    clock: &Arc<Mutex<VirtualClock>>,
    rules: &Arc<RwLock<LoadedRules>>,
    storage_rules: &Arc<RwLock<LoadedRules>>,
    backend: &Arc<LocalBackend>,
    auth_store: &Arc<Mutex<AuthStore>>,
    storage: &Arc<ftd_adapter_http::storage::StorageState>,
    functions: Option<&Arc<ftd_adapter_functions::runtime::FunctionsRuntime>>,
    control_token: String,
    faults: ftd_core_session::fault::SharedFaults,
    text_indexes: Arc<Mutex<ftd_core_firestore::text_index::TextIndexSet>>,
    registry: &Arc<ftd_core_auth::store::AuthRegistry>,
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
    // Snapshot parts: Firestore databases, Storage objects, Auth users, the clock, both
    // rulesets; a restore also resets the functions runtime.
    let mut snapshot_hooks: Vec<Arc<dyn ftd_adapter_http::control::SnapshotHook>> = vec![
        Arc::new(snapshots::Firestore(backend.clone())),
        Arc::new(snapshots::Storage(storage.clone())),
        Arc::new(snapshots::Auth(auth_store.clone())),
        Arc::new(snapshots::SessionClock(clock.clone())),
        Arc::new(snapshots::Rules("firestore rules", rules.clone())),
        Arc::new(snapshots::Rules("storage rules", storage_rules.clone())),
    ];
    if let Some(runtime) = functions {
        snapshot_hooks.push(Arc::new(snapshots::Functions(runtime.clone())));
    }
    let mut reset_hooks = vec![firestore_reset, auth_reset, storage_reset];
    if let Some(runtime) = functions {
        let runtime = runtime.clone();
        reset_hooks.push(Arc::new(move || runtime.reset()) as Arc<dyn Fn() + Send + Sync>);
    }
    ftd_adapter_http::control::ControlState {
        clock: clock.clone(),
        require_demo_prefix: cfg.require_demo_prefix,
        edition: cfg.edition,
        capabilities: control::capabilities_manifest(),
        rules: rules.clone(),
        storage_rules: storage_rules.clone(),
        reset_hooks,
        snapshot_hooks,
        snapshots: Mutex::new(std::collections::BTreeMap::new()),
        faults: Some(faults),
        text_indexes,
        default_project: cfg.auth_project.clone(),
        sessions: Mutex::new(std::collections::BTreeMap::from([(
            "default".to_owned(),
            cfg.auth_project.clone(),
        )])),
        project_hooks: Some(Arc::new(sessions::Projects {
            backend: backend.clone(),
            storage: storage.clone(),
            registry: registry.clone(),
            seed: cfg.seed,
        })),
        functions: functions.map(|r| {
            Arc::new(functions::Hook(r.clone()))
                as Arc<dyn ftd_adapter_http::control::FunctionsHook>
        }),
        control_token,
        barrier: Some(backend.barrier()),
    }
}

#[allow(clippy::too_many_lines)]
fn run(mut cfg: RuntimeConfig, exec: Option<ExecPlan>) -> ExitCode {
    if !cfg.clock_start_pinned {
        // Unpinned: start at the wall clock (whole seconds) so ID tokens verify against
        // real time; daemon.clockStart pins it for reproducible runs.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
            .unwrap_or(0);
        cfg.clock_start = LogicalInstant::from_unix_seconds(now);
    }
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
        // Text Index definitions (FS-TEXT-VAL-1): validated at start, never executed.
        let text_indexes = Arc::new(Mutex::new(control::load_text_indexes(&cfg)?));
        // The session's fault plan (spec 18), shared by every adapter; empty until PUT.
        let faults: ftd_core_session::fault::SharedFaults =
            Arc::new(Mutex::new(ftd_core_session::fault::FaultState::default()));
        backend.set_faults(faults.clone());
        let auth_store = Arc::new(Mutex::new(AuthStore::new(
            &cfg.auth_project,
            SplitMix64::new(cfg.seed ^ 0xA0),
            TotpPolicy::default(),
        )));
        if cfg.id_token_signing == ftd_core_auth::jwt::SigningMode::SessionRsa {
            // Key generation is slow in a debug build; say so before it starts.
            println!("  generating the session RSA key for RS256 ID tokens ...");
            let signer = ftd_adapter_http::signing::RsaSigner::from_seed(cfg.seed ^ 0x2256)?;
            println!(
                "  id tokens:        RS256 (kid {})   JWKS: http://{}/.well-known/jwks.json",
                signer.kid(),
                cfg.http_addr
            );
            println!("  note: the Firebase Admin SDK verifies only unsigned tokens while FIREBASE_AUTH_EMULATOR_HOST is set; keep auth.idTokenSigning = \"unsigned-emulator\" when the Admin SDK calls verifyIdToken");
            if let Ok(mut store) = auth_store.lock() {
                store.set_signer(signer);
            }
        }
        let barrier = backend.barrier();
        // Session projects other than the default get their own Auth store (same signer).
        let registry = Arc::new(ftd_core_auth::store::AuthRegistry::new(
            &cfg.auth_project,
            auth_store.clone(),
        ));
        let rules = Arc::new(RwLock::new(load_rules(&cfg)?));
        let storage_rules = Arc::new(RwLock::new(load_storage_rules(&cfg)?));
        let (grpc_listener, http_listener, storage_listener, functions_listener) =
            bind_listeners(&cfg).await?;
        let grpc_addr = grpc_listener.local_addr().map_err(|e| e.to_string())?;
        let http_addr = http_listener.local_addr().map_err(|e| e.to_string())?;
        let storage_addr = storage_listener.local_addr().map_err(|e| e.to_string())?;
        let functions_addr = functions_listener
            .as_ref()
            .and_then(|l| l.local_addr().ok());
        // Random secrets: the control token browsers must present, and the secret that ties
        // the runner's HTTP server to this daemon's proxy.
        let control_token = random_secret()?;
        let runner_secret = random_secret()?;
        let functions_runtime = match functions_listener.as_ref() {
            Some(_) => Some(
                functions::start(
                    &cfg,
                    &clock,
                    &backend,
                    &functions::EmulatorHosts {
                        firestore: grpc_addr.to_string(),
                        auth: http_addr.to_string(),
                        storage: storage_addr.to_string(),
                    },
                    &runner_secret,
                )
                .await?,
            ),
            None => None,
        };
        // Auth user events reach the functions runtime after each Auth request.
        let auth = Arc::new(AuthState {
            store: auth_store.clone(),
            clock: clock.clone(),
            barrier: Some(barrier.clone()),
            events: functions_runtime.as_ref().map(functions::auth_sink),
            control_token: Some(control_token.clone()),
            registry: Some(registry.clone()),
        });
        let storage = storage_state(
            &cfg,
            &clock,
            &auth_store,
            &storage_rules,
            functions_runtime.as_ref().map(functions::storage_sink),
            &backend,
            &faults,
        )?;
        if let Some(runtime) = &functions_runtime {
            runtime.set_faults(faults.clone());
        }
        let control = Arc::new(control_state(
            &cfg,
            &clock,
            &rules,
            &storage_rules,
            &backend,
            &auth_store,
            &storage,
            functions_runtime.as_ref(),
            control_token.clone(),
            faults.clone(),
            text_indexes.clone(),
            &registry,
        ));
        print_banner(
            &cfg,
            if exec.is_some() { "exec" } else { "up" },
            grpc_addr,
            http_addr,
            storage_addr,
            functions_addr,
        );
        println!("  control token:    FTD_CONTROL_TOKEN={control_token}   (browser requests to privileged control routes must send Authorization: Bearer <token>)");
        print_rules_status(&cfg, rules.read().is_ok_and(|r| r.is_loaded()));
        if let Some(runtime) = &functions_runtime {
            let names: Vec<&str> = runtime
                .manifest()
                .functions
                .iter()
                .map(|f| f.name.as_str())
                .collect();
            println!("  functions loaded: {}", names.join(", "));
        }

        let enforcer = cfg.rules_enforced.then(|| {
            Arc::new(
                RulesEnforcer::new(rules.clone(), auth_store.clone(), clock.clone())
                    .with_registry(registry.clone()),
            )
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
        let functions_server = match (functions_listener, functions_runtime.clone()) {
            (Some(listener), Some(runtime)) => tokio::spawn(
                ftd_adapter_functions::http::serve_functions(listener, runtime),
            ),
            _ => tokio::spawn(std::future::pending()),
        };
        // Every listener is bound and served: the command may start.
        let mut child = match &exec {
            Some(plan) => {
                let env = child_environment(
                    &cfg,
                    &plan.only,
                    grpc_addr,
                    http_addr,
                    storage_addr,
                    functions_addr,
                    &control_token,
                );
                println!("  running: {}", plan.command.join(" "));
                Some(spawn_child(plan, &env)?)
            }
            None => None,
        };
        let child_pid = child.as_ref().and_then(tokio::process::Child::id);
        let mut terminated = false;
        let outcome = tokio::select! {
            r = grpc => Err(format!("gRPC server stopped: {r:?}")),
            r = http => Err(format!("HTTP server stopped: {r:?}")),
            r = storage_server => Err(format!("Storage server stopped: {r:?}")),
            r = functions_server => Err(format!("Functions server stopped: {r:?}")),
            status = wait_child(child.as_mut()) => match status {
                Ok(status) => Ok(Some(exit_code(status))),
                Err(e) => Err(format!("waiting for the command: {e}")),
            },
            _ = tokio::signal::ctrl_c() => {
                println!("shutting down");
                Ok::<Option<i32>, String>(None)
            }
            () = terminate_signal() => {
                println!("shutting down (SIGTERM)");
                terminated = true;
                Ok::<Option<i32>, String>(None)
            }
        };
        // The command stops before the services it uses. When it exited by itself its
        // group is still swept (a background job it left behind must not keep running).
        let code = match (&outcome, child.as_mut(), child_pid) {
            (Ok(Some(code)), _, Some(pid)) => {
                signal_child(pid, "-KILL");
                *code
            }
            (Ok(Some(code)), _, None) => *code,
            (_, Some(child), Some(pid)) => {
                stop_child(child, pid, if terminated { "-TERM" } else { "-INT" }).await
            }
            _ => 0,
        };
        if let Some(runtime) = functions_runtime {
            runtime.runner().shutdown().await;
        }
        outcome.map(|_| code)
    });
    match result {
        Ok(code) => ExitCode::from(u8::try_from(code.clamp(0, 255)).unwrap_or(1)),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
