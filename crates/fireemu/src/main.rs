//! `fireemu` command-line entry point.
//!
//! ```text
//! fireemu up | emulators:start   [options]
//! fireemu exec | emulators:exec  [options] -- <command...>
//! fireemu emulators:export <dir> [options]
//! fireemu doctor
//! fireemu capabilities
//!
//! options: [--config <file>] [--firebase-json firebase.json] [--project <id|alias>]
//!          [--only auth,firestore,storage,functions,pubsub,appcheck]
//!          [--firestore-port 8080] [--http-port 9099] [--storage-port 9199]
//!          [--functions-port 5001] [--functions <dir>] [--ui-port 4000] [--hub-port 4400]
//!          [--inspect-functions [port]] [--log-verbosity quiet|info|debug]
//!          [--import <dir>] [--export-on-exit [dir]]
//! ```
//!
//! `up` serves the Firestore v1 gRPC API (local execution behind the strict gateway), the
//! Identity Toolkit REST subset, the control API and the Emulator Hub on loopback until
//! Ctrl-C. `exec` is the `firebase emulators:exec` equivalent: it serves the same, runs the
//! command with the emulator host variables once every listener is bound, stops everything
//! when the command exits and exits with its status (SIGINT / SIGTERM are forwarded to the
//! command).
//!
//! `emulators:start`, `emulators:exec` and `emulators:export` are the official command
//! spellings; the first two are exact aliases of `up` and `exec`.
//!
//! # Exit codes
//!
//! | code | meaning |
//! | --- | --- |
//! | 0 | `exec`'s command succeeded, or `up` shut down on a signal |
//! | the command's own | `exec`'s command exited with it |
//! | `128 + signal` | `exec`'s command was ended by a signal |
//! | 1 | startup failed, the configuration was refused, or a requested feature is not supported yet; the command never ran |
//! | 2 | usage: an unknown argument, a missing value or a malformed `--only` |

mod config;
mod control;
mod doctor;
mod functions;
mod hub;
mod import_export;
mod sessions;
mod snapshots;
mod ui;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::RestState;
use fireemu_adapter_grpc::rules::RulesEnforcer;
use fireemu_adapter_grpc::serve::serve_multiplexed;
use fireemu_adapter_grpc::service::GatewayService;
use fireemu_adapter_http::identity_toolkit::AuthState;
use fireemu_core_auth::jwt::IdTokenSigner;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_firestore::index::{IndexSet, PlanningContext};
use fireemu_core_rules::runtime::LoadedRules;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;

use crate::config::{RuntimeConfig, Selection};

const OPTIONS_USAGE: &str = "[--config <file>] [--firebase-json <file>] [--project <id|alias>] [--only auth,firestore,storage,functions,pubsub,appcheck] [--firestore-port <n>] [--http-port <n>] [--storage-port <n>] [--functions-port <n>] [--pubsub-port <n>] [--functions <dir>] [--ui-port <n>] [--hub-port <n>] [--logging-port <n>] [--inspect-functions [port]] [--log-verbosity quiet|info|debug] [--import <dir>] [--export-on-exit [dir]]";

fn usage() -> ExitCode {
    eprintln!("usage: fireemu up|emulators:start {OPTIONS_USAGE}\n       fireemu exec|emulators:exec {OPTIONS_USAGE} -- <command...>\n       fireemu emulators:export <dir> [--project <id>] [--force]\n       fireemu doctor\n       fireemu capabilities");
    ExitCode::from(2)
}

/// A command-line or configuration failure and the exit code it produces: 2 for usage, 1 for
/// a configuration the daemon refuses or a feature it does not support yet. Both are decided
/// before anything binds, so neither can leave a partially started suite behind.
struct CliError {
    /// Process exit code.
    code: u8,
    /// The message printed after `error: `.
    message: String,
}

impl CliError {
    /// A usage failure (exit code 2).
    fn usage(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
        }
    }

    /// A configuration or unsupported-feature failure (exit code 1).
    fn refused(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
        }
    }
}

impl From<config::ConfigError> for CliError {
    fn from(e: config::ConfigError) -> Self {
        Self::refused(e.0)
    }
}

/// `--log-verbosity`, in the official spelling (case-insensitive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
enum Verbosity {
    /// Errors only: the banner, the notices and the readiness lines are suppressed.
    Quiet,
    /// The default: the banner, the notices and the readiness lines.
    #[default]
    Info,
    /// Everything `info` prints plus the resolved configuration.
    Debug,
}

impl Verbosity {
    fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "quiet" => Some(Self::Quiet),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            _ => None,
        }
    }
}

/// What `exec` runs once the services are up.
struct ExecPlan {
    /// Program and arguments.
    command: Vec<String>,
}

/// Everything the option parser produced.
struct Options {
    /// Effective daemon configuration.
    cfg: RuntimeConfig,
    /// Selected services.
    only: Selection,
    /// `--log-verbosity`.
    verbosity: Verbosity,
    /// The export directory to import at start (`--import`).
    import: Option<PathBuf>,
    /// The export directory to write at exit (`--export-on-exit`).
    export_on_exit: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("up" | "emulators:start") => match parse_options(&args[1..]) {
            Ok(options) => run(options, None),
            Err(e) => fail(&e),
        },
        Some("exec" | "emulators:exec") => match parse_exec(&args[1..]) {
            Ok((options, plan)) => run(options, Some(plan)),
            Err(e) => fail(&e),
        },
        Some("emulators:export") => match export_command(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e),
        },
        Some("doctor") => doctor::run(),
        // The manifest describes the behaviour of one profile, so the command takes the same
        // options the daemon does and reports the profile they resolve to.
        Some("capabilities") => match parse_options(&args[1..]) {
            Ok(options) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&control::capabilities_manifest(
                        options.cfg.profile
                    ))
                    .unwrap_or_default()
                );
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e),
        },
        _ => usage(),
    }
}

/// Prints the failure and returns its exit code.
fn fail(e: &CliError) -> ExitCode {
    eprintln!("error: {}", e.message);
    ExitCode::from(e.code)
}

/// `fireemu emulators:export <dir> [--project <id>] [--force]`.
///
/// Like the official command, this talks to a suite that is already running: it finds it
/// through the Emulator Hub locator file the daemon wrote (`<temp>/hub-<project>.json`) and
/// drives `POST /_admin/export`, so the export is written by the process that holds the
/// state rather than by a second one that would have none.
fn export_command(args: &[String]) -> Result<(), CliError> {
    let mut path: Option<PathBuf> = None;
    let mut project: Option<String> = None;
    let mut force = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--project" | "-P" => {
                project = Some(
                    args.get(i + 1)
                        .ok_or_else(|| CliError::usage("--project needs a value"))?
                        .clone(),
                );
                i += 2;
            }
            "--force" | "-f" => {
                force = true;
                i += 1;
            }
            other if other.starts_with('-') => {
                return Err(CliError::usage(format!("unknown argument {other}")))
            }
            other => {
                if path.is_some() {
                    return Err(CliError::usage("emulators:export takes one directory"));
                }
                path = Some(PathBuf::from(other));
                i += 1;
            }
        }
    }
    let path = path.ok_or_else(|| CliError::usage("emulators:export needs a directory"))?;
    if !force {
        import_export::may_overwrite(&path).map_err(CliError::refused)?;
    }
    let absolute = std::path::absolute(&path)
        .map_err(|e| CliError::refused(format!("{}: {e}", path.display())))?;

    let project = match project {
        Some(project) => project,
        None => resolve_project(Path::new("."), None)?
            .unwrap_or_else(|| config::RuntimeConfig::default().auth_project),
    };
    let locator = hub::Locator::path_for(&project);
    let text = std::fs::read_to_string(&locator).map_err(|_| {
        CliError::refused(format!(
            "no running fireemu suite for {project} was found: {} does not exist. Start one with `fireemu up --project {project}`, or name the project with --project.",
            locator.display()
        ))
    })?;
    let document: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| CliError::refused(format!("{} does not parse: {e}", locator.display())))?;
    let origin = document
        .get("origins")
        .and_then(|o| o.get(0))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CliError::refused(format!("{} names no Hub origin", locator.display())))?;
    let address = origin.trim_start_matches("http://");
    let body = serde_json::json!({
        "path": absolute.to_string_lossy(),
        "initiatedBy": "emulators:export",
    })
    .to_string();
    let (status, response) = post_json(address, "/_admin/export", &body)
        .map_err(|e| CliError::refused(format!("the export request to {origin} failed: {e}")))?;
    if status != 200 {
        let message = serde_json::from_str::<serde_json::Value>(&response)
            .ok()
            .and_then(|v| {
                v.get("message")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or(response);
        return Err(CliError::refused(format!("export failed: {message}")));
    }
    println!("exported {project} to {}", absolute.display());
    Ok(())
}

/// One `POST` against a loopback Hub, written by hand: the binary carries a server-side
/// hyper only, and the Hub's answers are small enough to read in one go.
fn post_json(address: &str, path: &str, body: &str) -> Result<(u16, String), String> {
    use std::io::{Read as _, Write as _};
    let mut stream = std::net::TcpStream::connect(address).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(120)))
        .map_err(|e| e.to_string())?;
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).map_err(|e| e.to_string())?;
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    Ok((status, body.to_owned()))
}

/// `exec [options] -- <command...>`.
fn parse_exec(args: &[String]) -> Result<(Options, ExecPlan), CliError> {
    let split = args
        .iter()
        .position(|a| a == "--")
        .ok_or_else(|| CliError::usage("exec needs `-- <command...>` after its options"))?;
    let command = args[split + 1..].to_vec();
    if command.is_empty() {
        return Err(CliError::usage("exec needs a command after --"));
    }
    let options = parse_options(&args[..split])?;
    Ok((options, ExecPlan { command }))
}

/// Replaces the port of a `host:port` address, keeping the configured host.
fn with_port(addr: &str, port: u16) -> String {
    match addr.rsplit_once(':') {
        Some((host, _)) => format!("{host}:{port}"),
        None => format!("127.0.0.1:{port}"),
    }
}

/// One `--*-port` value.
fn port_arg(args: &[String], i: usize, flag: &str) -> Result<u16, CliError> {
    let raw = args
        .get(i + 1)
        .ok_or_else(|| CliError::usage(format!("{flag} needs a value")))?;
    raw.parse()
        .map_err(|e| CliError::usage(format!("{flag}: {e}")))
}

/// Whether `args[i]` is a value rather than the next flag. `--export-on-exit` and
/// `--inspect-functions` take an optional one, exactly as the official CLI does.
fn optional_value(args: &[String], i: usize) -> Option<&String> {
    args.get(i).filter(|v| !v.starts_with('-'))
}

/// The parsed command line, before it is applied to a configuration.
#[derive(Default)]
struct RawOptions {
    config_path: Option<PathBuf>,
    firebase_json: Option<PathBuf>,
    project: Option<String>,
    only: Option<Selection>,
    firestore_port: Option<u16>,
    http_port: Option<u16>,
    storage_port: Option<u16>,
    functions_port: Option<u16>,
    pubsub_port: Option<u16>,
    hub_port: Option<u16>,
    ui_port: Option<u16>,
    logging_port: Option<u16>,
    functions_source: Option<String>,
    inspect_functions: Option<u16>,
    verbosity: Verbosity,
    /// `--import <dir>`.
    import: Option<PathBuf>,
    /// `--export-on-exit [dir]`.
    export_on_exit: Option<ExportOnExit>,
}

/// What `--export-on-exit` named, before it is resolved against `--import`.
#[derive(Debug, Clone)]
enum ExportOnExit {
    /// `--export-on-exit <dir>`.
    Directory(PathBuf),
    /// `--export-on-exit` with no value: the `--import` directory, as the official CLI
    /// resolves it.
    ImportDirectory,
}

/// The Node inspector port `--inspect-functions` defaults to, as in the official CLI.
const DEFAULT_INSPECT_PORT: u16 = 9229;

#[allow(clippy::too_many_lines)]
fn parse_raw_options(args: &[String]) -> Result<RawOptions, CliError> {
    let mut raw = RawOptions::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                raw.config_path = Some(PathBuf::from(
                    args.get(i + 1)
                        .ok_or_else(|| CliError::usage("--config needs a value"))?,
                ));
                i += 2;
            }
            "--firebase-json" => {
                raw.firebase_json =
                    Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                        CliError::usage("--firebase-json needs a value")
                    })?));
                i += 2;
            }
            "--project" | "-P" => {
                raw.project = Some(
                    args.get(i + 1)
                        .ok_or_else(|| CliError::usage("--project needs a value"))?
                        .clone(),
                );
                i += 2;
            }
            "--only" => {
                // A bad selection is a usage failure (exit 2), not a configuration one: the
                // list came from the command line.
                raw.only = Some(
                    Selection::parse(
                        args.get(i + 1)
                            .ok_or_else(|| CliError::usage("--only needs a list"))?,
                    )
                    .map_err(|e| CliError::usage(e.0))?,
                );
                i += 2;
            }
            "--firestore-port" => {
                raw.firestore_port = Some(port_arg(args, i, "--firestore-port")?);
                i += 2;
            }
            "--storage-port" => {
                raw.storage_port = Some(port_arg(args, i, "--storage-port")?);
                i += 2;
            }
            "--http-port" => {
                raw.http_port = Some(port_arg(args, i, "--http-port")?);
                i += 2;
            }
            "--pubsub-port" => {
                raw.pubsub_port = Some(port_arg(args, i, "--pubsub-port")?);
                i += 2;
            }
            "--functions-port" => {
                raw.functions_port = Some(port_arg(args, i, "--functions-port")?);
                i += 2;
            }
            "--ui-port" => {
                raw.ui_port = Some(port_arg(args, i, "--ui-port")?);
                i += 2;
            }
            "--hub-port" => {
                raw.hub_port = Some(port_arg(args, i, "--hub-port")?);
                i += 2;
            }
            "--logging-port" => {
                raw.logging_port = Some(port_arg(args, i, "--logging-port")?);
                i += 2;
            }
            "--functions" => {
                raw.functions_source = Some(
                    args.get(i + 1)
                        .ok_or_else(|| CliError::usage("--functions needs a directory"))?
                        .clone(),
                );
                i += 2;
            }
            "--inspect-functions" => {
                let (port, step) = match optional_value(args, i + 1) {
                    Some(v) => (
                        v.parse()
                            .map_err(|e| CliError::usage(format!("--inspect-functions: {e}")))?,
                        2,
                    ),
                    None => (DEFAULT_INSPECT_PORT, 1),
                };
                raw.inspect_functions = Some(port);
                i += step;
            }
            "--log-verbosity" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| CliError::usage("--log-verbosity needs a value"))?;
                raw.verbosity = Verbosity::parse(value).ok_or_else(|| {
                    CliError::usage(format!(
                        "--log-verbosity {value:?} is not one of quiet, info, debug"
                    ))
                })?;
                i += 2;
            }
            "--import" => {
                raw.import =
                    Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                        CliError::usage("--import needs a directory")
                    })?));
                i += 2;
            }
            "--export-on-exit" => {
                let (dir, step) = match optional_value(args, i + 1) {
                    Some(v) => (ExportOnExit::Directory(PathBuf::from(v)), 2),
                    None => (ExportOnExit::ImportDirectory, 1),
                };
                raw.export_on_exit = Some(dir);
                i += step;
            }
            other => return Err(CliError::usage(format!("unknown argument {other}"))),
        }
    }
    Ok(raw)
}

/// Reads the file `--config` names. A canonical fireemu configuration always carries
/// `schemaVersion`; anything else is a `firebase.json`, so `firebase emulators:exec --config
/// firebase.json` works verbatim while every existing `--config fireemu.json` keeps working.
fn read_config_file(path: &Path) -> Result<(serde_json::Value, bool), CliError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| CliError::refused(format!("cannot read {}: {e}", path.display())))?;
    let json: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| CliError::refused(format!("{} does not parse: {e}", path.display())))?;
    let canonical = json.get("schemaVersion").is_some();
    Ok((json, canonical))
}

/// The directory paths inside a `firebase.json` are relative to.
fn project_dir(path: &Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Resolves `--project` against the `.firebaserc` of a project directory, when there is one.
fn resolve_project(dir: &Path, requested: Option<&str>) -> Result<Option<String>, CliError> {
    let rc_path = dir.join(".firebaserc");
    let Ok(text) = std::fs::read_to_string(&rc_path) else {
        return Ok(requested.map(str::to_owned));
    };
    let rc: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| CliError::refused(format!("{} does not parse: {e}", rc_path.display())))?;
    Ok(config::resolve_project_alias(&rc, requested)?)
}

/// A port given on the command line overrides `firebase.json`, which overrides the canonical
/// configuration; the Hub and UI ports also remember that they were asked for explicitly.
fn apply_port_overrides(cfg: &mut RuntimeConfig, raw: &RawOptions) {
    if let Some(p) = raw.firestore_port {
        cfg.firestore_addr = with_port(&cfg.firestore_addr, p);
    }
    if let Some(p) = raw.http_port {
        cfg.http_addr = with_port(&cfg.http_addr, p);
    }
    if let Some(p) = raw.storage_port {
        cfg.storage_addr = with_port(&cfg.storage_addr, p);
    }
    if let Some(p) = raw.functions_port {
        cfg.functions_addr = with_port(&cfg.functions_addr, p);
    }
    if let Some(p) = raw.pubsub_port {
        cfg.pubsub_addr = with_port(&cfg.pubsub_addr, p);
        cfg.pubsub_enabled = true;
    }
    if let Some(p) = raw.hub_port {
        cfg.hub_addr = with_port(&cfg.hub_addr, p);
        cfg.hub_addr_explicit = true;
    }
    if let Some(p) = raw.ui_port {
        cfg.ui_addr = with_port(&cfg.ui_addr, p);
        cfg.ui_enabled = p != 0;
        cfg.ui_addr_explicit = true;
    }
    if let Some(p) = raw.logging_port {
        cfg.logging_addr = with_port(&cfg.logging_addr, p);
        cfg.logging_enabled = p != 0;
        cfg.logging_addr_explicit = true;
    }
}

fn parse_options(args: &[String]) -> Result<Options, CliError> {
    let raw = parse_raw_options(args)?;
    let only = raw.only.clone().unwrap_or_default();
    // `--config` carries either the canonical configuration or a firebase.json.
    let (mut cfg, firebase_from_config) = match &raw.config_path {
        Some(p) => {
            let (json, canonical) = read_config_file(p)?;
            if canonical {
                (RuntimeConfig::from_json(&json)?, None)
            } else {
                (RuntimeConfig::default(), Some((json, p.clone())))
            }
        }
        None => (RuntimeConfig::default(), None),
    };
    // A firebase.json from `--firebase-json` wins over one that reached `--config`.
    let firebase = match &raw.firebase_json {
        Some(p) => {
            let (json, canonical) = read_config_file(p)?;
            if canonical {
                return Err(CliError::refused(format!(
                    "{}: this is a fireemu canonical configuration (it has schemaVersion), not a firebase.json; pass it with --config",
                    p.display()
                )));
            }
            Some((json, p.clone()))
        }
        None => firebase_from_config,
    };
    let mut project_root = PathBuf::from(".");
    if let Some((json, path)) = &firebase {
        project_root = project_dir(path);
        let report = cfg.apply_firebase_json(json, &project_root, &only)?;
        if raw.verbosity > Verbosity::Quiet {
            for notice in &report.notices {
                eprintln!("note: {}: {notice}", path.display());
            }
        }
    }
    if let Some(project) = resolve_project(&project_root, raw.project.as_deref())? {
        // The alias, when `--project` named one, is what a codebase's `.env.<alias>` file is
        // keyed by (`findEnvfiles`). A `--project` value that is already a project ID is not
        // an alias, and neither is one that resolves to itself.
        cfg.functions_project_alias = raw
            .project
            .as_deref()
            .filter(|requested| *requested != project)
            .map(str::to_owned);
        cfg.auth_project = project;
    }
    if !only.functions {
        cfg.functions_source = None;
        cfg.functions_loaded.clear();
    }
    apply_port_overrides(&mut cfg, &raw);
    if let Some(dir) = raw.functions_source {
        // `--functions <dir>` names exactly one codebase, whatever `firebase.json` declares.
        cfg.functions_source = Some(dir);
        cfg.functions_loaded.clear();
    }
    if let Some(port) = raw.inspect_functions {
        apply_inspect_functions(&mut cfg, port)?;
    }
    // The UI listener is configured through its own module, and only when a port was asked
    // for: without one it keeps its best-effort default, where a busy 4000 disables the UI
    // instead of failing the run.
    if cfg.ui_addr_explicit {
        ui::set_port(if cfg.ui_enabled {
            cfg.ui_addr
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse().ok())
                .unwrap_or(config::DEFAULT_UI_PORT)
        } else {
            0
        });
    }
    // `--export-on-exit` without a directory means "where --import read from", exactly as
    // the official CLI resolves it (`commandUtils.ts` `setExportOnExitOptions`). A target
    // that is the working directory or one of its parents is refused there too, because an
    // export replaces what the directory holds.
    let export_on_exit = resolve_export_on_exit(raw.export_on_exit, raw.import.as_deref())?;
    if let Some(dir) = &raw.import {
        if !dir.is_dir() {
            return Err(CliError::refused(format!(
                "--import {}: no such directory",
                dir.display()
            )));
        }
    }
    Ok(Options {
        cfg,
        only,
        verbosity: raw.verbosity,
        import: raw.import,
        export_on_exit,
    })
}

/// Resolves `--export-on-exit` against `--import` and refuses a target that would replace
/// the working directory.
///
/// Without a directory of its own the flag means "where `--import` read from", exactly as
/// the official CLI resolves it (`commandUtils.ts` `setExportOnExitOptions`), and a target
/// that is the working directory or one of its parents is refused there too -- an export
/// replaces what the directory holds.
fn resolve_export_on_exit(
    requested: Option<ExportOnExit>,
    import: Option<&Path>,
) -> Result<Option<PathBuf>, CliError> {
    let dir = match requested {
        None => return Ok(None),
        Some(ExportOnExit::Directory(dir)) => dir,
        Some(ExportOnExit::ImportDirectory) => import
            .ok_or_else(|| {
                CliError::usage(
                    "--export-on-exit must be used with --import, or be given a directory of its own",
                )
            })?
            .to_path_buf(),
    };
    let absolute = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.starts_with(&absolute) {
            return Err(CliError::refused(format!(
                "--export-on-exit {}: that is the working directory or one of its parents, and an export replaces what the directory holds; choose a dedicated directory",
                dir.display()
            )));
        }
    }
    import_export::may_overwrite(&dir).map_err(CliError::refused)?;
    Ok(Some(dir))
}

/// `--inspect-functions [port]`: the bundled runner is a Node script, so the inspector is
/// Node's own `--inspect=<port>` flag placed before it. A configured `functions.runner`
/// that is not Node cannot be given one, and saying so is better than starting without it.
fn apply_inspect_functions(cfg: &mut RuntimeConfig, port: u16) -> Result<(), CliError> {
    let mut command = match cfg.functions_runner.clone() {
        Some(command) => command,
        None => functions::default_runner().map_err(CliError::refused)?,
    };
    let program = std::path::Path::new(&command[0])
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_owned();
    if program != "node" {
        return Err(CliError::refused(format!(
            "--inspect-functions: the configured functions.runner starts {:?}, not node, so it takes no --inspect flag; remove functions.runner or drop --inspect-functions",
            command[0]
        )));
    }
    command.insert(1, format!("--inspect={port}"));
    cfg.functions_runner = Some(command);
    Ok(())
}

/// The addresses the daemon actually bound, per service. `None` means the service was not
/// selected and nothing listens for it.
#[derive(Debug, Clone, Copy)]
struct BoundAddrs {
    /// Firestore gRPC + REST + `WebChannel`.
    firestore: Option<std::net::SocketAddr>,
    /// Identity Toolkit. `None` when `auth` was not selected; the control listener below is
    /// bound either way.
    auth: Option<std::net::SocketAddr>,
    /// Storage.
    storage: Option<std::net::SocketAddr>,
    /// Functions HTTP.
    functions: Option<std::net::SocketAddr>,
    /// Pub/Sub gRPC.
    pubsub: Option<std::net::SocketAddr>,
    /// The Emulator Hub, when its port could be bound.
    hub: Option<std::net::SocketAddr>,
    /// The Emulator UI, when it is enabled and its port could be bound.
    ui: Option<std::net::SocketAddr>,
    /// The Logging emulator WebSocket, when it is enabled and its port could be bound.
    logging: Option<std::net::SocketAddr>,
    /// The control API and App Check listener. Always bound: it is fireemu's own plane, not
    /// an emulated product, and the UI, the SDK smokes and `exec` all need it. It is the
    /// same socket as `auth` whenever `auth` is selected.
    control: std::net::SocketAddr,
}

/// The environment `exec` gives its command: the canonical emulator host variables of the
/// selected services and nothing else.
///
/// The names and formats are the ones `firebase-tools@15.28.2` writes in
/// `src/emulator/env.ts` (`setEnvVarsForEmulators`): `FIRESTORE_EMULATOR_HOST` and its
/// `FIREBASE_FIRESTORE_EMULATOR_ADDRESS` alias, `FIREBASE_AUTH_EMULATOR_HOST`,
/// `FIREBASE_STORAGE_EMULATOR_HOST` **without** a scheme next to `STORAGE_EMULATOR_HOST`
/// **with** one, and `FIREBASE_EMULATOR_HUB` as a bare `host:port`.
/// `FIREBASE_DATABASE_EMULATOR_HOST` is deliberately absent: it names a Realtime Database
/// emulator, and fireemu has none to point it at.
///
/// Two deliberate differences from the official CLI, both published:
///
/// - it also sets `GOOGLE_CLOUD_PROJECT` (the official CLI sets only `GCLOUD_PROJECT`),
///   because the Google client libraries read either and a test suite should not have to
///   care which;
/// - it *removes* the variables of unselected services from the command's environment. The
///   official CLI only adds, so a stale `FIRESTORE_EMULATOR_HOST` in the shell survives
///   `--only auth` and silently points the suite at whatever used to run there. Clearing is
///   the safe reading of "only these emulators are running".
fn child_environment(
    cfg: &RuntimeConfig,
    only: &Selection,
    addrs: &BoundAddrs,
    control_token: &str,
) -> Vec<(String, String)> {
    let mut env = vec![
        ("GOOGLE_CLOUD_PROJECT".to_owned(), cfg.auth_project.clone()),
        ("GCLOUD_PROJECT".to_owned(), cfg.auth_project.clone()),
        ("FIREEMU_CONTROL_TOKEN".to_owned(), control_token.to_owned()),
        (
            "FIREEMU_CONTROL_URL".to_owned(),
            format!("http://{}/v1/", addrs.control),
        ),
    ];
    if let Some(addr) = addrs.firestore {
        env.push(("FIRESTORE_EMULATOR_HOST".to_owned(), addr.to_string()));
        env.push((
            "FIREBASE_FIRESTORE_EMULATOR_ADDRESS".to_owned(),
            addr.to_string(),
        ));
    }
    if let Some(addr) = addrs.auth {
        env.push(("FIREBASE_AUTH_EMULATOR_HOST".to_owned(), addr.to_string()));
    }
    if let Some(addr) = addrs.storage {
        env.push((
            "FIREBASE_STORAGE_EMULATOR_HOST".to_owned(),
            addr.to_string(),
        ));
        env.push(("STORAGE_EMULATOR_HOST".to_owned(), format!("http://{addr}")));
    }
    if let Some(addr) = addrs.functions {
        env.push(("FIREEMU_FUNCTIONS_HOST".to_owned(), addr.to_string()));
        // Eventarc's publishEvents route is served on the functions port. The variable
        // carries the scheme, as `setEnvVarsForEmulators` gives it one; without it the Admin
        // SDK publishes to production, which is a network call a local run must never make.
        env.push((
            "CLOUD_EVENTARC_EMULATOR_HOST".to_owned(),
            format!("http://{addr}"),
        ));
        // Cloud Tasks' variable carries no scheme, unlike Eventarc's.
        env.push(("CLOUD_TASKS_EMULATOR_HOST".to_owned(), addr.to_string()));
    }
    if let Some(addr) = addrs.pubsub {
        // The canonical variable the Google client libraries read to reach a Pub/Sub emulator;
        // it carries host:port with no scheme (`emulator.ts` `PUBSUB_EMULATOR_HOST`).
        env.push(("PUBSUB_EMULATOR_HOST".to_owned(), addr.to_string()));
    }
    if let Some(addr) = addrs.hub {
        env.push(("FIREBASE_EMULATOR_HUB".to_owned(), addr.to_string()));
    }
    if let Some(addr) = addrs.logging {
        // `FIREBASE_LOGGING_EMULATOR_HOST` is a bare host:port, as `loggingEmulator.js` reads it.
        env.push((
            "FIREBASE_LOGGING_EMULATOR_HOST".to_owned(),
            addr.to_string(),
        ));
    }
    // App Check shares the control listener, so its variables name that address.
    if only.app_check_available(&cfg.app_check) {
        env.push((
            "FIREEMU_APP_CHECK_EMULATOR_HOST".to_owned(),
            addrs.control.to_string(),
        ));
        env.push((
            "FIREEMU_APP_CHECK_JWKS_URL".to_owned(),
            format!("http://{}/v1/jwks", addrs.control),
        ));
    }
    // `firebase emulators:exec` synthesises FIREBASE_CONFIG from the project when the
    // command does not already carry one (`commandUtils.ts` `runScript`).
    if std::env::var_os("FIREBASE_CONFIG").is_none() {
        env.push((
            "FIREBASE_CONFIG".to_owned(),
            functions::firebase_config(&cfg.auth_project),
        ));
    }
    env
}

/// The emulator variables `exec` owns: those not selected by `--only` are removed from the
/// command's environment, so a shell configured for other emulators cannot leak into it.
/// `FIREBASE_DATABASE_EMULATOR_HOST` is on the list although fireemu never sets it: an
/// inherited one would point a Realtime Database client at something fireemu does not serve.
const OWNED_VARIABLES: [&str; 14] = [
    "FIRESTORE_EMULATOR_HOST",
    "FIREBASE_FIRESTORE_EMULATOR_ADDRESS",
    "FIREBASE_AUTH_EMULATOR_HOST",
    "FIREBASE_STORAGE_EMULATOR_HOST",
    "STORAGE_EMULATOR_HOST",
    "FIREBASE_DATABASE_EMULATOR_HOST",
    "FIREBASE_EMULATOR_HUB",
    "FIREBASE_LOGGING_EMULATOR_HOST",
    "FIREEMU_FUNCTIONS_HOST",
    "CLOUD_EVENTARC_EMULATOR_HOST",
    "CLOUD_TASKS_EMULATOR_HOST",
    "PUBSUB_EMULATOR_HOST",
    "FIREEMU_APP_CHECK_EMULATOR_HOST",
    "FIREEMU_APP_CHECK_JWKS_URL",
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

fn watched_file_signature(path: &str) -> Result<u64, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    Ok(bytes
        .into_iter()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            hash.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte)
        }))
}

fn start_rules_reload_supervisor(
    path: String,
    label: &'static str,
    rules: &Arc<RwLock<LoadedRules>>,
) {
    let weak = Arc::downgrade(rules);
    let mut observed = watched_file_signature(&path).ok();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
            let Some(rules) = weak.upgrade() else {
                return;
            };
            let signature = match watched_file_signature(&path) {
                Ok(signature) if observed != Some(signature) => signature,
                Ok(_) => continue,
                Err(reason) => {
                    eprintln!("warning: {label} reload scan failed: {reason}");
                    continue;
                }
            };
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let source = match std::fs::read_to_string(&path) {
                Ok(source) => source,
                Err(error) => {
                    observed = Some(signature);
                    eprintln!(
                        "warning: {label} reload failed; keeping the last-known-good rules: {error}"
                    );
                    continue;
                }
            };
            observed = Some(watched_file_signature(&path).unwrap_or(signature));
            match LoadedRules::from_source(&source) {
                Ok(candidate) => {
                    if let Ok(mut current) = rules.write() {
                        *current = candidate;
                        eprintln!("note: reloaded {label} from {path}");
                    }
                }
                Err(error) => eprintln!(
                    "warning: {label} reload failed; keeping the last-known-good rules: {error}"
                ),
            }
        }
    });
}

fn start_index_reload_supervisor(path: String, database: String, backend: &Arc<LocalBackend>) {
    let weak = Arc::downgrade(backend);
    let mut observed = watched_file_signature(&path).ok();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
            let Some(backend) = weak.upgrade() else {
                return;
            };
            let signature = match watched_file_signature(&path) {
                Ok(signature) if observed != Some(signature) => signature,
                Ok(_) => continue,
                Err(reason) => {
                    eprintln!("warning: Firestore index reload scan failed: {reason}");
                    continue;
                }
            };
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            observed = Some(watched_file_signature(&path).unwrap_or(signature));
            match control::load_indexes(&path) {
                Ok(indexes) => {
                    backend.replace_database_indexes(&database, indexes);
                    eprintln!("note: reloaded Firestore indexes for {database} from {path}");
                }
                Err(error) => eprintln!(
                    "warning: Firestore index reload failed; keeping the last-known-good indexes: {error}"
                ),
            }
        }
    });
}

fn start_firestore_config_reload_supervisors(
    cfg: &RuntimeConfig,
    backend: &Arc<LocalBackend>,
    rules: &Arc<RwLock<LoadedRules>>,
    database_rules: &std::collections::BTreeMap<String, Arc<RwLock<LoadedRules>>>,
    storage_rules: &Arc<RwLock<LoadedRules>>,
) {
    for (database, files) in &cfg.firestore_databases {
        if let Some(path) = &files.rules {
            let slot = if database == "(default)" {
                Some(rules)
            } else {
                database_rules.get(database)
            };
            if let Some(slot) = slot {
                start_rules_reload_supervisor(path.clone(), "Firestore rules", slot);
            }
        }
    }
    if cfg.firestore_databases.is_empty() {
        if let Some(path) = &cfg.rules_file {
            start_rules_reload_supervisor(path.clone(), "Firestore rules", rules);
        }
    }
    if let Some(path) = &cfg.storage_rules_file {
        start_rules_reload_supervisor(path.clone(), "Storage rules", storage_rules);
    }
    for (database, files) in &cfg.firestore_databases {
        if let Some(path) = &files.indexes {
            start_index_reload_supervisor(path.clone(), database.clone(), backend);
        }
    }
    if cfg.firestore_databases.is_empty() {
        if let Some(path) = &cfg.index_file {
            start_index_reload_supervisor(path.clone(), "(default)".to_owned(), backend);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn storage_state(
    cfg: &RuntimeConfig,
    clock: &Arc<Mutex<VirtualClock>>,
    registry: &Arc<fireemu_core_auth::store::AuthRegistry>,
    tenancy: &fireemu_core_session::tenancy::SharedTenancy,
    storage_rules: &Arc<RwLock<LoadedRules>>,
    events: Option<fireemu_adapter_http::storage::StorageEventSink>,
    backend: &Arc<LocalBackend>,
    faults: &fireemu_core_session::fault::SharedFaultRegistry,
    clock_observer: Option<Arc<dyn Fn() + Send + Sync>>,
    app_check_policy: Option<Arc<fireemu_core_app_check::ServiceAdmission>>,
) -> Result<Arc<fireemu_adapter_http::storage::StorageState>, String> {
    let parent = fireemu_adapter_grpc::decode::Parent {
        project: fireemu_core_types::ids::ProjectId::try_new(cfg.auth_project.clone())
            .map_err(|e| format!("project id: {e}"))?,
        database: fireemu_core_types::ids::DatabaseId::try_new("(default)")
            .map_err(|e| format!("database id: {e}"))?,
        document: None,
    };
    Ok(Arc::new(fireemu_adapter_http::storage::StorageState {
        store: Mutex::new(fireemu_core_storage::store::StorageState::new(
            cfg.seed ^ 0x57,
        )),
        clock: clock.clone(),
        auth: registry.clone(),
        tenancy: Some(tenancy.clone()),
        rules: storage_rules.clone(),
        project: cfg.auth_project.clone(),
        events,
        barrier: Some(backend.barrier()),
        firestore: Some(Arc::new(fireemu_adapter_grpc::rules::LatestReader {
            backend: backend.clone(),
            parent,
        })),
        faults: Some(faults.clone()),
        clock_observer,
        app_check_policy,
        token_acceptance: cfg.token_acceptance,
    }))
}

/// The listeners `--only` asked for.
///
/// A service that was not selected binds nothing at all: its port stays free for whatever
/// else wants it, and no client can reach a product the run did not ask for. The control
/// listener is the exception and is always bound, because the control API, the App Check
/// exchange and the Emulator UI's API live on it and none of them is an emulated product.
/// When `auth` is selected the two are the same socket, so `--http-port` still names the
/// Identity Toolkit; when it is not, the control plane moves to an ephemeral port (printed
/// in the banner and exported as `FIREEMU_CONTROL_URL`) and the configured Auth port is
/// left alone.
struct Listeners {
    firestore: Option<tokio::net::TcpListener>,
    /// The Identity Toolkit + control socket, or the control-only one.
    control: tokio::net::TcpListener,
    /// Whether `control` also serves the Identity Toolkit.
    auth_selected: bool,
    storage: Option<tokio::net::TcpListener>,
    functions: Option<tokio::net::TcpListener>,
    pubsub: Option<tokio::net::TcpListener>,
    hub: Option<tokio::net::TcpListener>,
    /// The Logging emulator WebSocket, when its port could be bound. Best effort like the Hub
    /// and UI: it is not a `--only` service, so it is attempted on every run unless disabled.
    logging: Option<tokio::net::TcpListener>,
}

async fn bind_listeners(cfg: &RuntimeConfig, only: &Selection) -> Result<Listeners, String> {
    let bind = |addr: &str| {
        let addr = addr.to_owned();
        async move {
            tokio::net::TcpListener::bind(&addr)
                .await
                .map_err(|e| format!("bind {addr}: {e}"))
        }
    };
    let firestore = if only.firestore {
        Some(bind(&cfg.firestore_addr).await?)
    } else {
        None
    };
    let control = if only.auth {
        bind(&cfg.http_addr).await?
    } else {
        // Loopback, ephemeral: the configured Auth port belongs to whoever wants it.
        bind("127.0.0.1:0").await?
    };
    let storage = if only.storage {
        Some(bind(&cfg.storage_addr).await?)
    } else {
        None
    };
    let functions = if only.functions && cfg.functions_source.is_some() {
        Some(bind(&cfg.functions_addr).await?)
    } else {
        None
    };
    // Like the official suite, Pub/Sub starts only when it was configured or explicitly asked
    // for, rather than binding port 8085 on every run.
    let pubsub = if only.pubsub && (cfg.pubsub_enabled || only.explicit) {
        Some(bind(&cfg.pubsub_addr).await?)
    } else {
        None
    };
    let hub = hub::bind(&cfg.hub_addr, cfg.hub_addr_explicit).await?;
    // The Logging emulator is not a `--only` service (the official suite configures it through
    // `emulators.logging`), so it is bound on every run unless it was turned off. Best effort
    // like the Hub and UI: a busy default port only disables it, a busy explicit one is an error.
    let logging = if cfg.logging_enabled {
        bind_best_effort(&cfg.logging_addr, cfg.logging_addr_explicit).await?
    } else {
        None
    };
    Ok(Listeners {
        firestore,
        control,
        auth_selected: only.auth,
        storage,
        functions,
        pubsub,
        hub,
        logging,
    })
}

/// Binds a best-effort loopback listener: `port 0` is off, a busy default only disables the
/// service, and a busy explicit port is an error. Mirrors `hub::bind`.
async fn bind_best_effort(
    addr: &str,
    explicit: bool,
) -> Result<Option<tokio::net::TcpListener>, String> {
    let port = addr
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok());
    if port == Some(0) {
        return Ok(None);
    }
    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => Ok(Some(listener)),
        Err(e) if explicit => Err(format!("bind {addr}: {e}")),
        Err(_) => Ok(None),
    }
}

/// The entries `GET /emulators` publishes: every service that actually bound a listener,
/// plus the Hub and the UI, under their official names. An unselected service is absent, so
/// a discovery client is told the truth about what is running.
fn hub_emulators(addrs: &BoundAddrs) -> Vec<hub::EmulatorInfo> {
    let pid = std::process::id();
    [
        ("firestore", addrs.firestore),
        ("auth", addrs.auth),
        ("storage", addrs.storage),
        ("functions", addrs.functions),
        ("pubsub", addrs.pubsub),
        ("hub", addrs.hub),
        ("ui", addrs.ui),
        ("logging", addrs.logging),
    ]
    .into_iter()
    .filter_map(|(name, addr)| addr.map(|addr| hub::EmulatorInfo { name, addr, pid }))
    .collect()
}

/// Milliseconds since the Unix epoch on the daemon's virtual clock, for `EmulatorLog`
/// timestamps. Using the virtual clock (not the wall clock) keeps the log frames deterministic
/// under a pinned `daemon.clockStart`, so tests over the stream are stable.
fn clock_millis(clock: &Arc<Mutex<VirtualClock>>) -> i64 {
    use fireemu_core_types::determinism::Clock as _;
    let nanos = clock.lock().map_or(0, |c| c.now().as_nanos());
    i64::try_from(nanos / 1_000_000).unwrap_or(i64::MAX)
}

/// The lines of `current` that are new since `previous`, tolerating the runner's front-trim of
/// its bounded log buffer. Mirrors the UI SSE stream's `new_lines`; duplicated here so the
/// logging pump does not depend on the UI crate.
fn logging_new_lines<'a>(previous: &[String], current: &'a [String]) -> &'a [String] {
    if previous.is_empty() {
        return current;
    }
    if current.len() >= previous.len() && current[..previous.len()] == *previous {
        return &current[previous.len()..];
    }
    for window in (1..=previous.len().min(8)).rev() {
        let needle = &previous[previous.len() - window..];
        if current.len() < window {
            continue;
        }
        if let Some(start) = (0..=current.len() - window)
            .rev()
            .find(|&start| current[start..start + window] == *needle)
        {
            return &current[start + window..];
        }
    }
    current
}

fn print_banner(cfg: &RuntimeConfig, verb: &str, addrs: &BoundAddrs) {
    println!("fireemu {verb}");
    match addrs.firestore {
        Some(a) => println!("  firestore (gRPC + REST): {a}   FIRESTORE_EMULATOR_HOST={a}"),
        None => println!("  firestore:        not selected by --only (nothing is bound)"),
    }
    match addrs.auth {
        Some(a) => println!("  auth (REST):      {a}   FIREBASE_AUTH_EMULATOR_HOST={a}"),
        None => println!("  auth:             not selected by --only (nothing is bound)"),
    }
    match addrs.storage {
        Some(a) => println!(
            "  storage (HTTP):   {a}   FIREBASE_STORAGE_EMULATOR_HOST={a}   STORAGE_EMULATOR_HOST=http://{a}"
        ),
        None => println!("  storage:          not selected by --only (nothing is bound)"),
    }
    match addrs.functions {
        Some(addr) => println!(
            "  functions (HTTP): {addr}   http://{addr}/{}/us-central1/{{function}}   (source: {})",
            cfg.auth_project,
            cfg.functions_source.as_deref().unwrap_or("")
        ),
        None => {
            println!("  functions:        not configured (functions.source or --functions <dir>)");
        }
    }
    match addrs.pubsub {
        Some(a) => println!("  pubsub (gRPC):    {a}   PUBSUB_EMULATOR_HOST={a}"),
        None => println!(
            "  pubsub:           not started (configure emulators.pubsub / --pubsub-port, or --only pubsub)"
        ),
    }
    match addrs.hub {
        Some(a) => println!(
            "  emulator hub:     {a}   FIREBASE_EMULATOR_HUB={a}   (GET /emulators discovers the suite)"
        ),
        None => println!(
            "  emulator hub:     disabled (cannot bind {}; choose one with --hub-port <n>)",
            cfg.hub_addr
        ),
    }
    match addrs.logging {
        Some(a) => println!(
            "  logging (WS):     {a}   FIREBASE_LOGGING_EMULATOR_HOST={a}   (EmulatorLog stream)"
        ),
        None if !cfg.logging_enabled => println!(
            "  logging:          disabled (emulators.logging / daemon.loggingPort / --logging-port set to 0)"
        ),
        None => println!(
            "  logging:          disabled (cannot bind {}; choose one with --logging-port <n>)",
            cfg.logging_addr
        ),
    }
    println!(
        "  control API:      http://{}/v1/  (health: /health/live)",
        addrs.control
    );
    println!(
        "  profile: {} ({})",
        cfg.profile.as_str(),
        match cfg.profile {
            config::CompatibilityProfile::Firebase =>
                "reproduces the official emulators, including their documented limitations",
            config::CompatibilityProfile::Strict =>
                "adds fireemu's own validation on top of the official behaviour",
        }
    );
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

/// Everything an export reads, held for as long as the daemon runs.
///
/// The Emulator Hub route, `fireemu emulators:export` (through that route) and
/// `--export-on-exit` all go through this one object, so there is a single description of
/// what an export covers and a single place that decides the directory may be written.
struct Exporter {
    backend: Arc<LocalBackend>,
    auth: Arc<fireemu_core_auth::store::AuthRegistry>,
    storage: Arc<fireemu_adapter_http::storage::StorageState>,
    clock: Arc<Mutex<VirtualClock>>,
    project: String,
    products: import_export::Products,
}

impl Exporter {
    fn endpoints(&self) -> import_export::Endpoints<'_> {
        import_export::Endpoints {
            backend: &self.backend,
            auth: &self.auth,
            storage: &self.storage,
            clock: &self.clock,
            project: &self.project,
        }
    }
}

impl hub::ExportRunner for Exporter {
    fn export(&self, path: &Path, initiated_by: &str) -> Result<(), String> {
        import_export::may_overwrite(path)?;
        // The directory is emptied first, so a document that no longer exists cannot survive
        // in an export that is supposed to describe the current state.
        import_export::clear_export_dir(path)?;
        import_export::export(path, self.products, &self.endpoints(), initiated_by)
            .map_err(|e| e.to_string())
    }
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

/// An unpredictable 128-bit project session epoch from the operating system CSPRNG (spec 7.2).
fn random_epoch() -> Result<fireemu_core_app_check::ProjectEpoch, String> {
    let hex = random_secret()?;
    let value = u128::from_str_radix(&hex, 16)
        .map_err(|e| format!("cannot build an App Check epoch: {e}"))?;
    Ok(fireemu_core_app_check::ProjectEpoch::new(value))
}

/// Builds the App Check state from canonical configuration: the registry, a fresh epoch per
/// registered project, and the shell implementations of the core's cryptographic traits.
fn app_check_state(
    cfg: &RuntimeConfig,
    clock: &Arc<Mutex<VirtualClock>>,
    barrier: &Arc<fireemu_core_session::barrier::AdmissionBarrier>,
    control_token: &str,
    signer: Arc<fireemu_adapter_http::signing::AppCheckRsaSigner>,
) -> Result<Arc<fireemu_adapter_http::app_check::AppCheckState>, String> {
    let mut registry =
        fireemu_core_app_check::AppCheckRegistry::new(cfg.app_check.token_ttl_seconds)
            .map_err(|e| format!("appCheck.tokenTtlSeconds: {e}"))?;
    for registration in cfg.app_check.registrations().map_err(|e| e.to_string())? {
        registry
            .register_app(registration)
            .map_err(|e| format!("appCheck.apps: {e}"))?;
    }
    let projects: std::collections::BTreeSet<String> = cfg
        .app_check
        .apps
        .iter()
        .map(|a| a.project_id.clone())
        .collect();
    for project in &projects {
        registry.set_project_epoch(project, random_epoch()?);
    }
    Ok(Arc::new(fireemu_adapter_http::app_check::AppCheckState {
        registry: Arc::new(RwLock::new(registry)),
        signer,
        clock: clock.clone(),
        control_token: control_token.to_owned(),
        hasher: Arc::new(fireemu_adapter_http::signing::Sha256DebugTokenHasher),
        constant_time: Arc::new(fireemu_adapter_http::signing::SubtleConstantTimeEq),
        secrets: Arc::new(fireemu_adapter_http::signing::OsDebugSecrets),
        barrier: Some(barrier.clone()),
    }))
}

/// One product's App Check baseline policy, or `None` when its effective mode is `off`.
///
/// `off` is represented by the absence of a policy, so an adapter that holds `None` never
/// collects a header and never classifies anything (specification section 12.1).
fn service_admission(
    gate: Option<&fireemu_core_app_check::AppCheckGate>,
    service: &'static str,
    mode: fireemu_core_app_check::verify::BaselineMode,
) -> Option<Arc<fireemu_core_app_check::ServiceAdmission>> {
    fireemu_core_app_check::ServiceAdmission::new(gate?.clone(), service, mode).map(Arc::new)
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
    if cfg.rules_enforced {
        for (database, files) in &cfg.firestore_databases {
            if database == "(default)" {
                continue;
            }
            if let Some(path) = &files.rules {
                println!("  rules [{database}]: enforced from {path}");
            }
        }
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
    storage: &Arc<fireemu_adapter_http::storage::StorageState>,
    functions: Option<&Arc<fireemu_adapter_functions::runtime::FunctionsRuntime>>,
    control_token: String,
    faults: fireemu_core_session::fault::SharedFaultRegistry,
    text_indexes: Arc<Mutex<fireemu_core_firestore::text_index::TextIndexCatalog>>,
    registry: &Arc<fireemu_core_auth::store::AuthRegistry>,
    tenancy: fireemu_core_session::tenancy::SharedTenancy,
    app_check: Option<fireemu_core_app_check::AppCheckGate>,
) -> fireemu_adapter_http::control::ControlState {
    let _ = auth_store;
    // Snapshot parts: what the session owns (Firestore databases, buckets, users, fault
    // plan, text indexes) and, for the default session, the shared parts (clock, both
    // rulesets; a restore also resets the functions runtime).
    let mut snapshot_hooks: Vec<Arc<dyn fireemu_adapter_http::control::SnapshotHook>> = vec![
        Arc::new(snapshots::Firestore(backend.clone())),
        Arc::new(snapshots::Storage(storage.clone())),
        Arc::new(snapshots::Auth(registry.clone())),
        Arc::new(snapshots::Faults(faults.clone(), cfg.auth_project.clone())),
        Arc::new(snapshots::TextIndexes(text_indexes.clone())),
        Arc::new(snapshots::SessionClock(clock.clone())),
        Arc::new(snapshots::Rules("firestore rules", rules.clone())),
        Arc::new(snapshots::Rules("storage rules", storage_rules.clone())),
    ];
    if let Some(runtime) = functions {
        snapshot_hooks.push(Arc::new(snapshots::Functions(runtime.clone())));
    }
    if let Some(gate) = &app_check {
        snapshot_hooks.push(Arc::new(snapshots::AppCheck(gate.clone())));
    }
    // The default session's scope is wiped by the project hooks; the shared functions
    // runtime is reset afterwards.
    let mut reset_hooks: Vec<Arc<dyn Fn() + Send + Sync>> = Vec::new();
    if let Some(runtime) = functions {
        let runtime = runtime.clone();
        reset_hooks.push(Arc::new(move || runtime.reset()) as Arc<dyn Fn() + Send + Sync>);
    }
    fireemu_adapter_http::control::ControlState {
        clock: clock.clone(),
        require_demo_prefix: cfg.require_demo_prefix,
        edition: cfg.edition,
        capabilities: control::capabilities_manifest(cfg.profile),
        rules: rules.clone(),
        storage_rules: storage_rules.clone(),
        reset_hooks,
        snapshot_hooks,
        snapshots: Mutex::new(std::collections::BTreeMap::new()),
        faults: Some(faults),
        text_indexes,
        default_project: cfg.auth_project.clone(),
        tenancy,
        sessions: Mutex::new(std::collections::BTreeMap::from([(
            "default".to_owned(),
            cfg.auth_project.clone(),
        )])),
        project_hooks: Some(Arc::new(sessions::Projects {
            backend: backend.clone(),
            storage: storage.clone(),
            registry: registry.clone(),
            seed: cfg.seed,
            app_check: app_check.clone(),
        })),
        functions: functions.map(|r| {
            Arc::new(functions::Hook(r.clone()))
                as Arc<dyn fireemu_adapter_http::control::FunctionsHook>
        }),
        control_token,
        barrier: Some(backend.barrier()),
        app_check,
    }
}

#[allow(clippy::too_many_lines)]
fn run(options: Options, exec: Option<ExecPlan>) -> ExitCode {
    let Options {
        mut cfg,
        only,
        verbosity,
        import,
        export_on_exit,
    } = options;
    let quiet = verbosity == Verbosity::Quiet;
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
            enforce_limits: cfg.enforce_limits,
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
        for (database, files) in &cfg.firestore_databases {
            if database != "(default)" {
                if let Some(path) = &files.indexes {
                    backend.replace_database_indexes(database, control::load_indexes(path)?);
                }
            }
        }
        // Text Index definitions (FS-TEXT-VAL-1): validated at start, never executed.
        let text_indexes = Arc::new(Mutex::new(control::load_text_indexes(&cfg)?));
        // The sessions' fault plans (spec 18), shared by every adapter; empty until PUT.
        let faults: fireemu_core_session::fault::SharedFaultRegistry =
            Arc::new(fireemu_core_session::fault::FaultRegistry::new());
        backend.set_faults(faults.clone());
        // Which session owns which project, bucket and API key.
        let tenancy: fireemu_core_session::tenancy::SharedTenancy = Arc::new(RwLock::new(
            fireemu_core_session::tenancy::Tenancy::new(&cfg.auth_project),
        ));
        let auth_store = Arc::new(Mutex::new(AuthStore::new(
            &cfg.auth_project,
            SplitMix64::new(cfg.seed ^ 0xA0),
            TotpPolicy::default(),
        )));
        // Both keys are 2048-bit RSA and slow to generate in a debug build; when both are
        // wanted they are generated concurrently on blocking tasks. They are always separate
        // keys: the Auth key is derived from the session seed, the App Check key is drawn from
        // the operating system CSPRNG once per daemon instance (spec 7.2).
        let want_auth_key = cfg.id_token_signing == fireemu_core_auth::jwt::SigningMode::SessionRsa;
        let want_app_check = only.app_check_available(&cfg.app_check);
        if (want_auth_key || want_app_check) && !quiet {
            println!("  generating the RSA signing keys ...");
        }
        let auth_key = want_auth_key.then(|| {
            let seed = cfg.seed ^ 0x2256;
            tokio::task::spawn_blocking(move || fireemu_adapter_http::signing::RsaSigner::from_seed(seed))
        });
        let app_check_key = want_app_check.then(|| {
            tokio::task::spawn_blocking(|| {
                fireemu_adapter_http::signing::AppCheckRsaSigner::generate(
                    fireemu_adapter_http::signing::AppCheckKeySource::OperatingSystem,
                )
            })
        });
        if let Some(task) = auth_key {
            let signer = task.await.map_err(|e| format!("session RSA key: {e}"))??;
            if !quiet {
                println!(
                    "  id tokens:        RS256 (kid {})   JWKS: http://{}/.well-known/jwks.json",
                    signer.kid(),
                    cfg.http_addr
                );
                println!("  note: the Firebase Admin SDK verifies only unsigned tokens while FIREBASE_AUTH_EMULATOR_HOST is set; keep auth.idTokenSigning = \"unsigned-emulator\" when the Admin SDK calls verifyIdToken");
            }
            if let Ok(mut store) = auth_store.lock() {
                store.set_signer(signer);
            }
        }
        let app_check_signer = match app_check_key {
            Some(task) => Some(task.await.map_err(|e| format!("App Check RSA key: {e}"))??),
            None => None,
        };
        let barrier = backend.barrier();
        // Session projects other than the default get their own Auth store (same signer).
        let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
            &cfg.auth_project,
            auth_store.clone(),
        ));
        let rules = Arc::new(RwLock::new(load_rules(&cfg)?));
        let mut database_rules = std::collections::BTreeMap::new();
        for (database, files) in &cfg.firestore_databases {
            if database == "(default)" {
                continue;
            }
            let loaded = match &files.rules {
                Some(path) => {
                    let source = std::fs::read_to_string(path)
                        .map_err(|error| format!("rules source {path}: {error}"))?;
                    LoadedRules::from_source(&source)
                        .map_err(|error| format!("rules source {path} does not parse: {error}"))?
                }
                None => LoadedRules::default(),
            };
            database_rules.insert(database.clone(), Arc::new(RwLock::new(loaded)));
        }
        let storage_rules = Arc::new(RwLock::new(load_storage_rules(&cfg)?));
        start_firestore_config_reload_supervisors(
            &cfg,
            &backend,
            &rules,
            &database_rules,
            &storage_rules,
        );
        let Listeners {
            firestore: grpc_listener,
            control: http_listener,
            auth_selected,
            storage: storage_listener,
            functions: functions_listener,
            pubsub: pubsub_listener,
            hub: hub_listener,
            logging: logging_listener,
        } = bind_listeners(&cfg, &only).await?;
        let grpc_addr = match grpc_listener.as_ref() {
            Some(l) => Some(l.local_addr().map_err(|e| e.to_string())?),
            None => None,
        };
        let http_addr = http_listener.local_addr().map_err(|e| e.to_string())?;
        let storage_addr = match storage_listener.as_ref() {
            Some(l) => Some(l.local_addr().map_err(|e| e.to_string())?),
            None => None,
        };
        let functions_addr = functions_listener
            .as_ref()
            .and_then(|l| l.local_addr().ok());
        let pubsub_addr = pubsub_listener.as_ref().and_then(|l| l.local_addr().ok());
        let hub_addr = hub_listener.as_ref().and_then(|l| l.local_addr().ok());
        let logging_addr = logging_listener.as_ref().and_then(|l| l.local_addr().ok());
        let (ui_listener, ui_note) = match ui::bind().await? {
            ui::Ui::Bound(listener) => (Some(listener), None),
            ui::Ui::Disabled => (None, None),
            ui::Ui::Unavailable(note) => (None, Some(note)),
        };
        let ui_addr = ui_listener.as_ref().and_then(|l| l.local_addr().ok());
        let addrs = BoundAddrs {
            firestore: grpc_addr,
            auth: auth_selected.then_some(http_addr),
            storage: storage_addr,
            functions: functions_addr,
            pubsub: pubsub_addr,
            hub: hub_addr,
            ui: ui_addr,
            logging: logging_addr,
            control: http_addr,
        };
        // Random secrets: the control token browsers must present, and the secret that ties
        // the runner's HTTP server to this daemon's proxy.
        let control_token = random_secret()?;
        let runner_secret = random_secret()?;
        let app_check = match app_check_signer {
            Some(signer) => Some(app_check_state(
                &cfg,
                &clock,
                &barrier,
                &control_token,
                signer,
            )?),
            None => None,
        };
        // One gate for the whole daemon; one policy per product from appCheck.services.* and
        // the --only selection (the activation table of specification section 8).
        let app_check_gate = app_check.as_ref().map(|s| s.gate());
        // Row 4 of the activation table: selecting Functions selects its App Check dependency,
        // and the callable trusted protocol is then active for every callable -- including the
        // ones that do not enforce, so valid app context is available to them. The runner is
        // started only after this is known, because it decides whether the runner may run with
        // the `skipTokenVerification` debug feature at all.
        let callable_trusted_protocol = app_check_gate.is_some() && functions_listener.is_some();
        // The runner's functions see exactly the services this run selected: an unselected
        // one leaves its variable unset there too, so a handler cannot reach a product the
        // suite is not running.
        let functions_runtime = match functions_listener.as_ref() {
            Some(_) => Some(
                functions::start(
                    &cfg,
                    &clock,
                    &backend,
                    &functions::EmulatorHosts {
                        firestore: grpc_addr.map(|a| a.to_string()),
                        auth: addrs.auth.map(|a| a.to_string()),
                        storage: storage_addr.map(|a| a.to_string()),
                        functions: functions_addr.map(|a| a.to_string()),
                        logging: logging_addr.map(|a| a.to_string()),
                    },
                    &runner_secret,
                    callable_trusted_protocol,
                )
                .await?,
            ),
            None => None,
        };
        // The Pub/Sub broker: real topic/subscription state served over gRPC. Its seed is the
        // daemon seed with a fixed tag so its message and ack ids never coincide with another
        // subsystem's stream. A published message also reaches subscribed Cloud Functions
        // through the bridge (EVTINFRA-02), when a functions runtime is loaded.
        let pubsub_state = Arc::new(Mutex::new(fireemu_core_pubsub::PubSubState::new(
            cfg.seed ^ 0x5053_5542,
        )));
        let pubsub_bridge: Option<Arc<dyn fireemu_adapter_pubsub::TopicDelivery>> =
            functions_runtime.as_ref().map(|r| {
                Arc::new(functions::PubSubBridge::new(r.clone()))
                    as Arc<dyn fireemu_adapter_pubsub::TopicDelivery>
            });
        let pubsub_handle = fireemu_adapter_pubsub::PubSubHandle::new(
            pubsub_state.clone(),
            clock.clone(),
            pubsub_bridge,
        );
        let auth_policy = service_admission(
            app_check_gate.as_ref(),
            "auth",
            only.app_check_mode(&cfg.app_check, crate::config::AppCheckService::Auth),
        );
        let firestore_policy = service_admission(
            app_check_gate.as_ref(),
            "firestore",
            only.app_check_mode(&cfg.app_check, crate::config::AppCheckService::Firestore),
        );
        let storage_policy = service_admission(
            app_check_gate.as_ref(),
            "storage",
            only.app_check_mode(&cfg.app_check, crate::config::AppCheckService::Storage),
        );
        // Auth user events reach the functions runtime after each Auth request.
        let auth = Arc::new(AuthState {
            store: auth_store.clone(),
            clock: clock.clone(),
            barrier: Some(barrier.clone()),
            events: functions_runtime.as_ref().map(functions::auth_sink),
            blocking: functions_runtime.as_ref().map(|runtime| {
                Arc::new(functions::BlockingAuthBridge(runtime.clone()))
                    as Arc<dyn fireemu_adapter_http::identity_toolkit::AuthBlockingHook>
            }),
            operation_gate: Arc::new(Mutex::new(())),
            control_token: Some(control_token.clone()),
            registry: Some(registry.clone()),
            tenancy: Some(tenancy.clone()),
            app_check: app_check.clone(),
            app_check_policy: auth_policy,
        });
        // A fault plan that moves the clock wakes the functions runtime like the clock
        // route does.
        let clock_observer: Option<Arc<dyn Fn() + Send + Sync>> =
            functions_runtime.as_ref().map(|r| {
                let r = r.clone();
                Arc::new(move || r.on_clock_changed()) as Arc<dyn Fn() + Send + Sync>
            });
        if let Some(observer) = &clock_observer {
            backend.set_clock_observer(observer.clone());
        }
        let storage = storage_state(
            &cfg,
            &clock,
            &registry,
            &tenancy,
            &storage_rules,
            functions_runtime
                .as_ref()
                .map(|r| functions::storage_sink(r, &tenancy)),
            &backend,
            &faults,
            clock_observer,
            storage_policy,
        )?;
        if let Some(runtime) = &functions_runtime {
            runtime.set_faults(faults.for_project(runtime.project()));
            if let Some(gate) = &app_check_gate {
                // The callable baseline is `unenforced`: the daemon classifies and records
                // every callable token, and the callable's own `enforceAppCheck` decides
                // (specification section 13.4). The Auth verifier is a dedicated enforcer that
                // never evaluates a rule: it exists to verify the ID token against the target
                // project's users on the virtual clock, which is required whether or not
                // Security Rules are enforced at all.
                // The service label is the core's own constant: counters group callable
                // observations by function name for exactly this label (section 15).
                let policy = service_admission(
                    Some(gate),
                    fireemu_core_app_check::observe::FUNCTIONS_SERVICE,
                    fireemu_core_app_check::verify::BaselineMode::Unenforced,
                )
                .ok_or_else(|| "the callable App Check policy is unavailable".to_owned())?;
                let verifier = Arc::new(
                    RulesEnforcer::new(
                        Arc::new(RwLock::new(LoadedRules::default())),
                        auth_store.clone(),
                        clock.clone(),
                    )
                    .with_registry(registry.clone()),
                );
                runtime.set_callable_trust(Arc::new(
                    fireemu_adapter_functions::callable::CallableTrust::new(
                        policy,
                        verifier,
                        runtime.project(),
                    ),
                ));
            }
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
            tenancy.clone(),
            app_check_gate.clone(),
        ));
        // The Emulator Hub's locator file lives as long as this scope: dropping it removes
        // the file, so a clean exit on either signal path leaves no stale discovery behind.
        // The export seam: one object that owns everything an export reads, shared by the
        // Hub's route, `emulators:export` and `--export-on-exit`.
        let exporter = Arc::new(Exporter {
            backend: backend.clone(),
            auth: registry.clone(),
            storage: storage.clone(),
            clock: clock.clone(),
            project: cfg.auth_project.clone(),
            products: import_export::Products::from(&only),
        });
        // The import happens before the command starts and before the banner claims the
        // suite is ready: a run that cannot install its fixture must not run at all.
        if let Some(dir) = &import {
            let prepared = import_export::prepare(dir, exporter.products, &cfg.auth_project)
                .map_err(|e| format!("--import {}: {e}", dir.display()))?;
            if !quiet {
                for notice in &prepared.notices {
                    eprintln!("note: --import {}: {notice}", dir.display());
                }
            }
            import_export::apply(&prepared, &exporter.endpoints())
                .map_err(|e| format!("--import {}: {e}", dir.display()))?;
            if !quiet {
                println!("  imported: {} ({})", dir.display(), prepared.summary());
            }
        }
        let hub_state = Arc::new(hub::HubState {
            project: cfg.auth_project.clone(),
            addr: hub_addr.unwrap_or(http_addr),
            emulators: hub_emulators(&addrs),
            functions: functions_runtime.clone(),
            export: Some(exporter.clone() as Arc<dyn hub::ExportRunner>),
        });
        let _locator = hub_addr.map(|_| {
            let (locator, note) = hub::Locator::write(&hub_state);
            if let (Some(note), false) = (note, quiet) {
                eprintln!("note: {note}");
            }
            locator
        });
        if !quiet {
            print_banner(&cfg, if exec.is_some() { "exec" } else { "up" }, &addrs);
            println!("  control token:    FIREEMU_CONTROL_TOKEN={control_token}   (browser requests to privileged control routes must send Authorization: Bearer <token>)");
            if let Some(state) = &app_check {
                println!(
                    "  app check:        {} app(s)   FIREEMU_APP_CHECK_EMULATOR_HOST={http_addr}   JWKS: http://{http_addr}/v1/jwks (kid {})",
                    cfg.app_check.apps.len(),
                    state.signer.kid()
                );
                println!(
                    "  app check modes:  auth={} firestore={} storage={}   (Firestore covers unary gRPC, REST, Write/Listen streams and WebChannel; Storage covers resumable uploads too){}",
                    only.app_check_mode(&cfg.app_check, crate::config::AppCheckService::Auth),
                    only.app_check_mode(&cfg.app_check, crate::config::AppCheckService::Firestore),
                    only.app_check_mode(&cfg.app_check, crate::config::AppCheckService::Storage),
                    if callable_trusted_protocol {
                        "\n  app check callables: the trusted callable protocol is active; enforceAppCheck is honoured per function"
                    } else {
                        ""
                    },
                );
            }
            if let Some(addr) = ui_addr {
                println!("  ui:               http://{addr}/ui");
            }
            if let Some(note) = ui_note {
                println!("{note}");
            }
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
            if verbosity == Verbosity::Debug {
                println!("  resolved config:  {cfg:?}");
                println!("  selection:        {only:?}");
            }
        }

        let enforcer = cfg.rules_enforced.then(|| {
            Arc::new(
                RulesEnforcer::new(rules.clone(), auth_store.clone(), clock.clone())
                    .with_registry(registry.clone())
                    .with_database_rules(database_rules.clone())
                    .with_token_acceptance(cfg.token_acceptance),
            )
        });
        let mut service = GatewayService::local(gateway.clone(), backend.clone());
        if let Some(e) = &enforcer {
            service = service.with_rules(e.clone());
        }
        if let Some(policy) = &firestore_policy {
            service = service.with_app_check(policy.clone());
        }
        let rest = Arc::new(RestState {
            local: backend.clone(),
            gateway: Arc::new(gateway),
            rules: enforcer,
            app_check: firestore_policy,
        });
        let grpc = match grpc_listener {
            Some(listener) => tokio::spawn(serve_multiplexed(
                listener,
                // Firestore's request size limit applies to the message (framing is separate).
                FirestoreServer::new(service)
                    .max_decoding_message_size(10 * 1024 * 1024)
                    .max_encoding_message_size(10 * 1024 * 1024),
                rest.clone(),
            )),
            None => tokio::spawn(std::future::pending()),
        };
        let http = tokio::spawn(fireemu_adapter_http::server::serve_with_control(
            http_listener,
            auth.clone(),
            control.clone(),
        ));
        let storage_server = match storage_listener {
            Some(listener) => tokio::spawn(
                fireemu_adapter_http::storage_server::serve_storage(listener, storage.clone()),
            ),
            None => tokio::spawn(std::future::pending()),
        };
        let hub_server = match hub_listener {
            Some(listener) => tokio::spawn(hub::serve(listener, hub_state.clone())),
            None => tokio::spawn(std::future::pending()),
        };
        let functions_server = match (functions_listener, functions_runtime.clone()) {
            (Some(listener), Some(runtime)) => tokio::spawn(
                fireemu_adapter_functions::http::serve_functions(listener, runtime),
            ),
            _ => tokio::spawn(std::future::pending()),
        };
        let pubsub_server = match pubsub_listener {
            Some(listener) => {
                tokio::spawn(fireemu_adapter_pubsub::serve_pubsub(listener, pubsub_handle))
            }
            None => tokio::spawn(std::future::pending()),
        };
        // The Logging emulator: an `EmulatorLog` WebSocket the official UI's Logs page reads.
        // One bounded bus carries the lines; the daemon feeds it the functions runner's output
        // and the emulators' lifecycle notes. What is and is not fed is recorded as a precision
        // on the `logging` surface in the compatibility contract.
        let log_bus = fireemu_adapter_logging::LogBus::new();
        for (name, addr) in [
            ("firestore", addrs.firestore),
            ("auth", addrs.auth),
            ("storage", addrs.storage),
            ("functions", addrs.functions),
            ("pubsub", addrs.pubsub),
        ] {
            if let Some(addr) = addr {
                log_bus.publish(
                    &fireemu_adapter_logging::LogInput::plain(
                        "info",
                        format!("{name} emulator started on {addr}"),
                        clock_millis(&clock),
                    )
                    .for_emulator(name),
                );
            }
        }
        // Feed the functions runner's lines into the bus, tagged emulator=functions, by polling
        // its log accessor (the UI's SSE stream reads the same accessor). Function-name tagging
        // is best effort and currently absent: a runner line carries an invocation id, not a
        // function name, and only the first codebase's runner is polled (recorded as a
        // precision on the `logging` surface).
        let functions_log_pump = functions_runtime.clone().map(|runtime| {
            let bus = log_bus.clone();
            let clock = clock.clone();
            tokio::spawn(async move {
                let mut seen: Vec<String> = Vec::new();
                let mut poll = tokio::time::interval(std::time::Duration::from_millis(250));
                loop {
                    poll.tick().await;
                    let current = runtime.runner().logs();
                    for line in logging_new_lines(&seen, &current) {
                        bus.publish(
                            &fireemu_adapter_logging::LogInput::plain(
                                "info",
                                line.clone(),
                                clock_millis(&clock),
                            )
                            .for_emulator("functions"),
                        );
                    }
                    seen = current;
                }
            })
        });
        let logging_server = match logging_listener {
            Some(listener) => tokio::spawn(fireemu_adapter_logging::serve_logging(
                listener,
                log_bus.clone(),
            )),
            None => tokio::spawn(std::future::pending()),
        };
        let ui_server = match (ui_listener, ui_addr) {
            (Some(listener), Some(addr)) => {
                let state = ui::state(ui::Parts {
                    cfg: &cfg,
                    only: &only,
                    control_token: control_token.clone(),
                    rest: rest.clone(),
                    backend: backend.clone(),
                    auth: auth.clone(),
                    storage: storage.clone(),
                    control: control.clone(),
                    functions: functions_runtime.clone(),
                    app_check: app_check.clone(),
                    addrs: (
                        grpc_addr.unwrap_or(http_addr),
                        http_addr,
                        storage_addr.unwrap_or(http_addr),
                        functions_addr,
                        addr,
                    ),
                });
                tokio::spawn(fireemu_adapter_ui::server::serve_ui(listener, state))
            }
            _ => tokio::spawn(std::future::pending()),
        };
        // Every listener is bound and served: the command may start.
        let mut child = match &exec {
            Some(plan) => {
                let env = child_environment(&cfg, &only, &addrs, &control_token);
                if !quiet {
                    println!("  running: {}", plan.command.join(" "));
                }
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
            r = pubsub_server => Err(format!("Pub/Sub server stopped: {r:?}")),
            r = ui_server => Err(format!("UI server stopped: {r:?}")),
            r = hub_server => Err(format!("Emulator Hub stopped: {r:?}")),
            r = logging_server => Err(format!("Logging emulator stopped: {r:?}")),
            status = wait_child(child.as_mut()) => match status {
                Ok(status) => Ok(Some(exit_code(status))),
                Err(e) => Err(format!("waiting for the command: {e}")),
            },
            _ = tokio::signal::ctrl_c() => {
                if !quiet {
                    println!("shutting down");
                }
                Ok::<Option<i32>, String>(None)
            }
            () = terminate_signal() => {
                if !quiet {
                    println!("shutting down (SIGTERM)");
                }
                terminated = true;
                Ok::<Option<i32>, String>(None)
            }
        };
        // The functions log pump is a background poller with no shutdown signal of its own;
        // stop it explicitly so it does not outlive the run.
        if let Some(pump) = &functions_log_pump {
            pump.abort();
        }
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
        // `--export-on-exit` runs on every path that reached a served suite: a clean exit, a
        // command that failed, and SIGINT or SIGTERM. It runs before the runner is shut down
        // and while every store is still in memory, and a failure to write it is reported
        // without changing the exit code the run already earned (`DATA-04`).
        if let Some(dir) = &export_on_exit {
            use hub::ExportRunner as _;
            match exporter.export(dir, "exit") {
                Ok(()) => {
                    if !quiet {
                        println!("exported to {}", dir.display());
                    }
                }
                Err(e) => eprintln!("error: --export-on-exit {}: {e}", dir.display()),
            }
        }
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

#[cfg(test)]
mod config_reload_tests {
    use super::*;
    use fireemu_core_firestore::index::IndexValidationPolicy;
    use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};

    const RULES_ONE: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if true; } } }";
    const RULES_TWO: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow write: if false; } } }";

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fireemu-reload-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn rules_reload_publishes_only_a_valid_complete_generation() {
        let dir = scratch("rules");
        let path = dir.join("firestore.rules");
        std::fs::write(&path, RULES_ONE).unwrap();
        let rules = Arc::new(RwLock::new(LoadedRules::from_source(RULES_ONE).unwrap()));
        start_rules_reload_supervisor(path.display().to_string(), "Firestore rules", &rules);

        std::fs::write(&path, "not a rules program").unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1_300)).await;
        assert_eq!(rules.read().unwrap().source.as_deref(), Some(RULES_ONE));

        std::fs::write(&path, RULES_TWO).unwrap();
        for _ in 0..30 {
            if rules.read().unwrap().source.as_deref() == Some(RULES_TWO) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(rules.read().unwrap().source.as_deref(), Some(RULES_TWO));
        drop(rules);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn index_reload_replaces_the_query_planners_catalog() {
        let dir = scratch("indexes");
        let path = dir.join("firestore.indexes.json");
        std::fs::write(&path, r#"{"indexes":[],"fieldOverrides":[]}"#).unwrap();
        let gateway = Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::Conservative,
            },
            indexes: IndexSet::default(),
        };
        let backend = Arc::new(LocalBackend::new(
            gateway,
            Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH))),
            7,
        ));
        start_index_reload_supervisor(path.display().to_string(), "staging".to_owned(), &backend);
        std::fs::write(
            &path,
            r#"{"indexes":[{"collectionGroup":"items","queryScope":"COLLECTION","fields":[{"fieldPath":"a","order":"ASCENDING"},{"fieldPath":"b","order":"DESCENDING"}]}],"fieldOverrides":[]}"#,
        )
        .unwrap();
        for _ in 0..30 {
            if backend.indexes_for_database("staging").composites().len() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(backend.indexes().composites().is_empty());
        assert_eq!(
            backend.indexes_for_database("staging").composites().len(),
            1
        );
        drop(backend);
        let _ = std::fs::remove_dir_all(dir);
    }
}
