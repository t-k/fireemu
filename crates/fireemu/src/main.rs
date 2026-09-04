//! `fireemu` command-line entry point.
//!
//! ```text
//! fireemu init [options]
//! fireemu up | emulators:start   [options]
//! fireemu exec | emulators:exec  [options] "shell script"
//! fireemu exec | emulators:exec  [options] -- <command...>
//! fireemu emulators:export <dir> [options]
//! fireemu doctor
//! fireemu capabilities
//!
//! options: [--config <file>] [--firebase-json firebase.json] [--project <id|alias>]
//!          [--only auth,firestore,storage,functions,pubsub,appcheck]
//!          [--firestore-port 8080] [--http-port 9099] [--storage-port 9199]
//!          [--functions-port 5001] [--functions <dir>] [--ui-port 4000] [--hub-port 4400]
//!          [--inspect-functions [port]] [--log-verbosity quiet|silent|info|debug]
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
mod daemon;
mod doctor;
mod functions;
mod hub;
mod import_export;
mod init;
mod session_rsa_cache;
mod sessions;
mod snapshots;
mod ui;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;
#[cfg(windows)]
use process_wrap::tokio::{JobObject, KillOnDrop, TokioChildWrapper, TokioCommandWrap};

use crate::config::{RuntimeConfig, Selection};

const OPTIONS_USAGE: &str = "[--config <file>] [--firebase-json <file>] [--project <id|alias>] [--only auth,firestore,storage,functions,eventarc,tasks,pubsub,appcheck] [--firestore-port <n>] [--http-port <n>] [--storage-port <n>] [--functions-port <n>] [--eventarc-port <n>] [--tasks-port <n>] [--pubsub-port <n>] [--functions <dir>] [--ui-port <n>] [--hub-port <n>] [--logging-port <n>] [--inspect-functions [port]] [--log-verbosity quiet|silent|info|debug] [--import <dir>] [--export-on-exit [dir]]";

fn usage() -> ExitCode {
    eprintln!("usage: fireemu init [--profile strict|firebase] [--firebase-json <file>] [--interactive|--yes|--no-interactive] [--force]\n       fireemu up|emulators:start {OPTIONS_USAGE}\n       fireemu exec|emulators:exec {OPTIONS_USAGE} [--ui] \"shell script\"\n       fireemu exec|emulators:exec {OPTIONS_USAGE} [--ui] -- <command...>\n       fireemu emulators:export <dir> [--project <id>] [--force]\n       fireemu doctor\n       fireemu capabilities");
    ExitCode::from(2)
}

struct DiagnosticPath<'a>(&'a Path);

impl std::fmt::Display for DiagnosticPath<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_diagnostic_text(formatter, &self.0.to_string_lossy())
    }
}

const fn diagnostic_path(path: &Path) -> DiagnosticPath<'_> {
    DiagnosticPath(path)
}

struct DiagnosticText<'a>(&'a str);

impl std::fmt::Display for DiagnosticText<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_diagnostic_text(formatter, self.0)
    }
}

const fn diagnostic_text(text: &str) -> DiagnosticText<'_> {
    DiagnosticText(text)
}

fn write_diagnostic_text(formatter: &mut std::fmt::Formatter<'_>, text: &str) -> std::fmt::Result {
    for character in text.chars() {
        for escaped in character.escape_debug() {
            write!(formatter, "{escaped}")?;
        }
    }
    Ok(())
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
            "quiet" | "silent" => Some(Self::Quiet),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            _ => None,
        }
    }
}

struct RedactedRuntimeConfig<'a>(&'a RuntimeConfig);

impl std::fmt::Debug for RedactedRuntimeConfig<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let config = self.0;
        formatter
            .debug_struct("RuntimeConfig")
            .field("profile", &config.profile)
            .field("edition", &config.edition)
            .field("api_mode", &config.api_mode)
            .field("index_policy", &config.index_policy)
            .field("enforce_limits", &config.enforce_limits)
            .field("token_acceptance", &config.token_acceptance)
            .field("require_demo_prefix", &config.require_demo_prefix)
            .field("clock_start_pinned", &config.clock_start_pinned)
            .field("seed", &"[redacted]")
            .field("auth_project", &"[redacted]")
            .field("id_token_signing", &config.id_token_signing)
            .field("rules_enforced", &config.rules_enforced)
            .field("app_check_enabled", &config.app_check.enabled)
            .field("app_check_apps", &config.app_check.apps.len())
            .field("functions_codebases", &config.functions_codebases.len())
            .finish()
    }
}

/// What `exec` runs once the services are up.
struct ExecPlan {
    /// Direct argv or the official CLI's positional shell script.
    command: ExecCommand,
}

enum ExecCommand {
    /// The fireemu extension that preserves an exact program and argv.
    Argv(Vec<String>),
    /// The official `emulators:exec <script>` form.
    Shell(String),
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

const DEFAULT_MAX_RUNTIME_WORKERS: usize = 4;
const DEFAULT_MAX_BLOCKING_THREADS: usize = 64;
const MAX_RUNTIME_WORKERS: usize = 64;
const MAX_BLOCKING_THREADS: usize = 512;

fn runtime_thread_counts(
    available: usize,
    worker_override: Option<&str>,
    blocking_override: Option<&str>,
) -> Result<(usize, usize), String> {
    let parse = |name: &str, value: &str, maximum: usize| {
        value
            .parse::<usize>()
            .ok()
            .filter(|count| (1..=maximum).contains(count))
            .ok_or_else(|| format!("{name} must be an integer from 1 through {maximum}"))
    };
    let workers = match worker_override {
        Some(value) => parse("FIREEMU_WORKER_THREADS", value, MAX_RUNTIME_WORKERS)?,
        None => available.clamp(1, DEFAULT_MAX_RUNTIME_WORKERS),
    };
    let blocking = match blocking_override {
        Some(value) => parse("FIREEMU_MAX_BLOCKING_THREADS", value, MAX_BLOCKING_THREADS)?,
        None => DEFAULT_MAX_BLOCKING_THREADS,
    };
    Ok((workers, blocking))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("init") => match init::run(&args[1..]) {
            Ok(path) => {
                println!("created {}", diagnostic_path(&path));
                println!("next: fireemu up --config fireemu.json");
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e),
        },
        Some("up" | "emulators:start") => match parse_options(&args[1..], OptionContext::Start) {
            Ok((options, None)) => daemon::run(options, None),
            Ok((_, Some(_))) => unreachable!("start does not accept a positional argument"),
            Err(e) => fail(&e),
        },
        Some("exec" | "emulators:exec") => match parse_exec(&args[1..]) {
            Ok((options, plan)) => daemon::run(options, Some(plan)),
            Err(e) => fail(&e),
        },
        Some("emulators:export") => match export_command(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e),
        },
        Some("doctor") => doctor::run(),
        // The manifest describes the behaviour of one profile, so the command takes the same
        // options the daemon does and reports the profile they resolve to.
        Some("capabilities") => match parse_options(&args[1..], OptionContext::Start) {
            Ok((options, None)) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&control::capabilities_manifest(
                        options.cfg.profile
                    ))
                    .unwrap_or_default()
                );
                ExitCode::SUCCESS
            }
            Ok((_, Some(_))) => unreachable!("capabilities does not accept a positional argument"),
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

    let project = if let Some(project) = project {
        project
    } else {
        let rc = read_firebaserc(Path::new("."))?;
        resolve_project(rc.as_ref(), None)?
            .unwrap_or_else(|| config::RuntimeConfig::default().auth_project)
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
    let token = document
        .get("fireemuControlToken")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            CliError::refused(format!(
                "{} names no fireemu control capability",
                locator.display()
            ))
        })?;
    let body = serde_json::json!({
        "path": absolute.to_string_lossy(),
        "initiatedBy": "emulators:export",
    })
    .to_string();
    let (status, response) = post_json(address, "/_admin/export", &body, token)
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
fn post_json(
    address: &str,
    path: &str,
    body: &str,
    control_token: &str,
) -> Result<(u16, String), String> {
    use std::io::{Read as _, Write as _};
    let mut stream = std::net::TcpStream::connect(address).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(120)))
        .map_err(|e| e.to_string())?;
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {control_token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

/// `exec [options] <script>` or `exec [options] -- <command...>`.
fn parse_exec(args: &[String]) -> Result<(Options, ExecPlan), CliError> {
    if let Some(split) = args.iter().position(|arg| arg == "--") {
        let command = args[split + 1..].to_vec();
        if command.is_empty() {
            return Err(CliError::usage("exec needs a command after --"));
        }
        let (options, positional) = parse_options(&args[..split], OptionContext::Exec)?;
        if positional.is_some() {
            return Err(CliError::usage(
                "exec cannot combine a positional shell script with `-- <command...>`",
            ));
        }
        return Ok((
            options,
            ExecPlan {
                command: ExecCommand::Argv(command),
            },
        ));
    }

    let (options, script) = parse_options(args, OptionContext::Exec)?;
    let script = script.ok_or_else(|| {
        CliError::usage("exec needs a positional shell script or `-- <command...>`")
    })?;
    Ok((
        options,
        ExecPlan {
            command: ExecCommand::Shell(script),
        },
    ))
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
    /// The official `emulators:exec <script>` positional argument.
    positional_script: Option<String>,
    config_path: Option<PathBuf>,
    firebase_json: Option<PathBuf>,
    project: Option<String>,
    only: Option<Selection>,
    firestore_port: Option<u16>,
    http_port: Option<u16>,
    storage_port: Option<u16>,
    functions_port: Option<u16>,
    eventarc_port: Option<u16>,
    tasks_port: Option<u16>,
    pubsub_port: Option<u16>,
    hub_port: Option<u16>,
    ui_port: Option<u16>,
    /// The official `emulators:exec --ui` opt-in.
    ui: bool,
    logging_port: Option<u16>,
    functions_source: Option<String>,
    inspect_functions: Option<u16>,
    inspect_functions_dynamic: bool,
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

const MIN_INSPECT_PORT: u16 = 1024;

fn inspect_port_arg(raw: &str) -> Result<u16, CliError> {
    let invalid = || {
        CliError::usage(format!(
            "{raw:?} is not a valid port for debugging, please pass an integer between 1024 and 65535 or true for a dynamic port."
        ))
    };
    let port = raw.parse::<u16>().map_err(|_| invalid())?;
    if port < MIN_INSPECT_PORT {
        return Err(invalid());
    }
    Ok(port)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OptionContext {
    Start,
    Exec,
}

#[allow(clippy::too_many_lines)]
fn parse_raw_options(args: &[String], context: OptionContext) -> Result<RawOptions, CliError> {
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
            "--eventarc-port" => {
                raw.eventarc_port = Some(port_arg(args, i, "--eventarc-port")?);
                i += 2;
            }
            "--tasks-port" => {
                raw.tasks_port = Some(port_arg(args, i, "--tasks-port")?);
                i += 2;
            }
            "--ui-port" => {
                raw.ui_port = Some(port_arg(args, i, "--ui-port")?);
                i += 2;
            }
            "--ui" if context == OptionContext::Exec => {
                raw.ui = true;
                i += 1;
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
                let step = match optional_value(args, i + 1) {
                    Some(v) if v == "true" => {
                        raw.inspect_functions_dynamic = true;
                        2
                    }
                    Some(v) => {
                        raw.inspect_functions = Some(inspect_port_arg(v)?);
                        2
                    }
                    None => {
                        raw.inspect_functions_dynamic = true;
                        1
                    }
                };
                i += step;
            }
            "--log-verbosity" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| CliError::usage("--log-verbosity needs a value"))?;
                raw.verbosity = Verbosity::parse(value).ok_or_else(|| {
                    CliError::usage(format!(
                        "--log-verbosity {value:?} is not one of quiet, silent, info, debug"
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
            other if context == OptionContext::Exec && !other.starts_with('-') => {
                if raw.positional_script.replace(other.to_owned()).is_some() {
                    return Err(CliError::usage(
                        "emulators:exec takes exactly one positional shell script",
                    ));
                }
                i += 1;
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
        .map_err(|e| CliError::refused(format!("cannot read {}: {e}", diagnostic_path(path))))?;
    let json: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| CliError::refused(format!("{} does not parse: {e}", diagnostic_path(path))))?;
    let canonical = json.get("schemaVersion").is_some();
    Ok((json, canonical))
}

/// Reads a Firebase project configuration and refuses a canonical fireemu document.
fn read_firebase_json(path: &Path) -> Result<(serde_json::Value, PathBuf), CliError> {
    let (json, canonical) = read_config_file(path)?;
    if canonical {
        return Err(CliError::refused(format!(
            "{}: this is a fireemu canonical configuration (it has schemaVersion), not a firebase.json; pass it with --config",
            diagnostic_path(path)
        )));
    }
    if !json.is_object() {
        return Err(CliError::refused(format!(
            "{}: firebase.json must be an object",
            diagnostic_path(path)
        )));
    }
    Ok((json, path.to_path_buf()))
}

/// The directory paths inside a `firebase.json` are relative to.
fn project_dir(path: &Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Reads the `.firebaserc` of a project directory once for alias and deploy-target resolution.
fn read_firebaserc(dir: &Path) -> Result<Option<serde_json::Value>, CliError> {
    let rc_path = dir.join(".firebaserc");
    let Ok(text) = std::fs::read_to_string(&rc_path) else {
        return Ok(None);
    };
    let rc: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        CliError::refused(format!("{} does not parse: {e}", diagnostic_path(&rc_path)))
    })?;
    Ok(Some(rc))
}

/// Resolves `--project` against the already-read `.firebaserc`, when there is one.
fn resolve_project(
    rc: Option<&serde_json::Value>,
    requested: Option<&str>,
) -> Result<Option<String>, CliError> {
    match rc {
        Some(rc) => Ok(config::resolve_project_alias(rc, requested)?),
        None => Ok(requested.map(str::to_owned)),
    }
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
    if let Some(p) = raw.eventarc_port {
        cfg.eventarc_addr = with_port(&cfg.eventarc_addr, p);
    }
    if let Some(p) = raw.tasks_port {
        cfg.tasks_addr = with_port(&cfg.tasks_addr, p);
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

fn parse_options(
    args: &[String],
    context: OptionContext,
) -> Result<(Options, Option<String>), CliError> {
    let raw = parse_raw_options(args, context)?;
    let positional_script = raw.positional_script.clone();
    let only = raw.only.clone().unwrap_or_default();
    // `--config` carries either the canonical configuration or a firebase.json.
    let (mut cfg, firebase_from_config) = match &raw.config_path {
        Some(p) => {
            let (json, canonical) = read_config_file(p)?;
            if canonical {
                let config = RuntimeConfig::from_json(&json)?;
                let firebase = if raw.firebase_json.is_none() {
                    config::firebase_json_reference(&json)?
                        .map(|reference| project_dir(p).join(reference))
                        .map(|path| read_firebase_json(&path))
                        .transpose()?
                } else {
                    None
                };
                (config, firebase)
            } else {
                (RuntimeConfig::default(), Some((json, p.clone())))
            }
        }
        None => (RuntimeConfig::default(), None),
    };
    // A firebase.json from `--firebase-json` wins over one that reached `--config`.
    let firebase = match &raw.firebase_json {
        Some(p) => Some(read_firebase_json(p)?),
        None => firebase_from_config,
    };
    let mut project_root = PathBuf::from(".");
    if let Some((json, path)) = &firebase {
        project_root = project_dir(path);
        let report = cfg.apply_firebase_json(json, &project_root, &only)?;
        if raw.verbosity > Verbosity::Quiet {
            for notice in &report.notices {
                eprintln!("note: {}: {notice}", diagnostic_path(path));
            }
        }
    }
    let rc = read_firebaserc(&project_root)?;
    if let Some(project) = resolve_project(rc.as_ref(), raw.project.as_deref())? {
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
    if !cfg.storage_rules_by_target.is_empty() {
        let rc = rc.as_ref().ok_or_else(|| {
            CliError::refused(
                "firebase.json declares Storage targets but the project has no .firebaserc"
                    .to_owned(),
            )
        })?;
        let project = cfg.auth_project.clone();
        cfg.resolve_storage_rules_targets(rc, &project)?;
    }
    if !only.functions {
        cfg.functions_source = None;
        cfg.functions_loaded.clear();
    }
    apply_port_overrides(&mut cfg, &raw);
    // The official `emulators:exec` does not start the UI unless `--ui` is present. An
    // explicit fireemu `--ui-port` remains a stronger local override, including port zero.
    if context == OptionContext::Exec && raw.ui_port.is_none() {
        cfg.ui_enabled = raw.ui;
    }
    if let Some(dir) = raw.functions_source {
        // `--functions <dir>` names exactly one codebase, whatever `firebase.json` declares.
        cfg.functions_source = Some(dir);
        cfg.functions_loaded.clear();
    }
    if raw.inspect_functions.is_some() || raw.inspect_functions_dynamic {
        apply_inspect_functions(&mut cfg, raw.inspect_functions)?;
    }
    // The UI listener is configured through its own module when a port was asked for or when
    // exec must apply its official opt-in default. Start otherwise keeps the best-effort
    // default, where a busy 4000 disables the UI instead of failing the run.
    if cfg.ui_addr_explicit || context == OptionContext::Exec {
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
    Ok((
        Options {
            cfg,
            only,
            verbosity: raw.verbosity,
            import: raw.import,
            export_on_exit,
        },
        positional_script,
    ))
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
fn apply_inspect_functions(cfg: &mut RuntimeConfig, port: Option<u16>) -> Result<(), CliError> {
    if let Some(command) = &cfg.functions_runner {
        let program = std::path::Path::new(&command[0])
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if program != "node" {
            return Err(CliError::refused(format!(
                "--inspect-functions: the configured functions.runner starts {:?}, not node, so it takes no --inspect flag; remove functions.runner or drop --inspect-functions",
                command[0]
            )));
        }
    }
    cfg.functions_inspect_port = port;
    cfg.functions_inspect_dynamic = port.is_none();
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
    /// Eventarc HTTP, present only as a dependency of a loaded Functions runtime.
    eventarc: Option<std::net::SocketAddr>,
    /// Cloud Tasks HTTP, present only as a dependency of a loaded Functions runtime.
    tasks: Option<std::net::SocketAddr>,
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
    storage_admin_capability: &str,
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
        env.push((
            "STORAGE_EMULATOR_HOST".to_owned(),
            format!("http://fireemu:{storage_admin_capability}@{addr}"),
        ));
    }
    if let Some(addr) = addrs.functions {
        env.push(("FIREEMU_FUNCTIONS_HOST".to_owned(), addr.to_string()));
    }
    if let Some(addr) = addrs.eventarc {
        env.push((
            "CLOUD_EVENTARC_EMULATOR_HOST".to_owned(),
            format!("http://{addr}"),
        ));
    }
    if let Some(addr) = addrs.tasks {
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
#[cfg(not(windows))]
fn own_process_group() -> bool {
    use std::io::IsTerminal as _;
    !std::io::stdin().is_terminal()
}

#[cfg(unix)]
fn shell_child_command(script: &str) -> (tokio::process::Command, String) {
    let mut command = tokio::process::Command::new("/bin/sh");
    command.args(["-c", script]);
    (command, "/bin/sh".to_owned())
}

#[cfg(windows)]
fn shell_child_command(script: &str) -> (tokio::process::Command, String) {
    use std::os::windows::process::CommandExt as _;

    let shell = std::env::var_os("ComSpec")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "cmd.exe".into());
    let mut command = tokio::process::Command::new(&shell);
    let is_cmd = std::path::Path::new(&shell)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.eq_ignore_ascii_case("cmd") || name.eq_ignore_ascii_case("cmd.exe")
        });
    if is_cmd {
        command
            .as_std_mut()
            .raw_arg("/d")
            .raw_arg("/s")
            .raw_arg("/c")
            .raw_arg(format!("\"{script}\""));
    } else {
        command.args(["-c", script]);
    }
    (command, shell.to_string_lossy().into_owned())
}

#[cfg(not(windows))]
type ExecChild = tokio::process::Child;

#[cfg(windows)]
type ExecChild = Box<dyn TokioChildWrapper>;

fn spawn_child(plan: &ExecPlan, env: &[(String, String)]) -> Result<ExecChild, String> {
    let (mut cmd, program) = match &plan.command {
        ExecCommand::Argv(command) => {
            let (program, args) = command
                .split_first()
                .ok_or("exec needs a command after --")?;
            let mut cmd = tokio::process::Command::new(program);
            cmd.args(args);
            (cmd, program.clone())
        }
        ExecCommand::Shell(script) => shell_child_command(script),
    };
    cmd.kill_on_drop(true);
    for name in OWNED_VARIABLES {
        cmd.env_remove(name);
    }
    cmd.envs(env.iter().cloned());
    #[cfg(unix)]
    if own_process_group() {
        cmd.process_group(0);
    }
    #[cfg(not(windows))]
    {
        cmd.spawn()
            .map_err(|e| format!("cannot start {program}: {e}"))
    }
    #[cfg(windows)]
    {
        let mut wrapped = TokioCommandWrap::from(cmd);
        wrapped.wrap(JobObject).wrap(KillOnDrop);
        wrapped
            .spawn()
            .map_err(|e| format!("cannot start {program}: {e}"))
    }
}

#[cfg(not(windows))]
fn child_id(child: &ExecChild) -> Option<u32> {
    child.id()
}

#[cfg(windows)]
fn child_id(child: &ExecChild) -> Option<u32> {
    child.id()
}

/// Sends `signal` to the command (`pid` as spawned: `Child::id` is gone once the child was
/// reaped, but its group may still hold a background job): to its process group when it
/// leads one, else to it.
#[cfg(not(windows))]
fn signal_child(pid: u32, signal: &str) {
    #[cfg(unix)]
    {
        let Ok(pid) = i32::try_from(pid) else {
            return;
        };
        let Some(pid) = rustix::process::Pid::from_raw(pid) else {
            return;
        };
        let signal = match signal {
            "-INT" => rustix::process::Signal::INT,
            "-TERM" => rustix::process::Signal::TERM,
            "-KILL" => rustix::process::Signal::KILL,
            _ => return,
        };
        if own_process_group() {
            let _ = rustix::process::kill_process_group(pid, signal);
        } else {
            let _ = rustix::process::kill_process(pid, signal);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (pid, signal);
    }
}

/// Waits for the command when there is one; never resolves otherwise.
async fn wait_child(child: Option<&mut ExecChild>) -> std::io::Result<std::process::ExitStatus> {
    match child {
        #[cfg(not(windows))]
        Some(child) => child.wait().await,
        // Waiting through JobObjectChild also waits for every descendant. Observe only the
        // command leader here, then terminate and drain the job after retaining its status.
        #[cfg(windows)]
        Some(child) => child.inner_mut().wait().await,
        None => std::future::pending().await,
    }
}

/// Removes descendants left behind by a command that has already exited. On Unix this only
/// addresses the process group fireemu created; an interactive child PID is never signalled
/// after it has been reaped. On Windows the stable Job Object handle avoids PID reuse entirely.
#[cfg(not(windows))]
fn sweep_child_tree(child: &mut ExecChild, pid: u32) {
    #[cfg(unix)]
    {
        let _ = child;
        if own_process_group() {
            signal_child(pid, "-KILL");
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (child, pid);
    }
}

#[cfg(windows)]
async fn sweep_child_tree(child: &mut ExecChild, pid: u32) {
    let _ = pid;
    let _ = child.start_kill();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        Box::into_pin(child.wait()),
    )
    .await;
}

/// Stops the command after the supervisor received `signal` (`-INT` / `-TERM`): the signal
/// is forwarded with its identity (through `kill(1)`; the crate forbids unsafe code) unless
/// the terminal already delivered it to the command's own group, then SIGKILL to the whole
/// group after ten seconds. Returns the status the command reported.
#[cfg(not(windows))]
async fn stop_child(child: &mut ExecChild, pid: u32, signal: &str) -> i32 {
    let terminal_delivered = signal == "-INT" && !own_process_group();
    if !terminal_delivered {
        signal_child(pid, signal);
    }
    if let Ok(Ok(status)) =
        tokio::time::timeout(std::time::Duration::from_secs(10), child.wait()).await
    {
        if own_process_group() {
            signal_child(pid, "-KILL");
        }
        exit_code(status)
    } else {
        signal_child(pid, "-KILL");
        let _ = child.kill().await;
        137
    }
}

#[cfg(windows)]
async fn stop_child(child: &mut ExecChild, pid: u32, signal: &str) -> i32 {
    let _ = (pid, signal);
    let _ = child.start_kill();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        Box::into_pin(child.wait()),
    )
    .await;
    137
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

struct LoadedStorageRules {
    registry: Arc<fireemu_adapter_http::storage::StorageRulesRegistry>,
    watched: Vec<(String, Arc<RulesetSlot>)>,
}

fn read_storage_rules(path: &str) -> Result<LoadedRules, String> {
    let source =
        std::fs::read_to_string(path).map_err(|e| format!("storage rules source {path}: {e}"))?;
    LoadedRules::from_source(&source)
        .map_err(|e| format!("storage rules source {path} does not parse: {e}"))
}

fn load_storage_rules(cfg: &RuntimeConfig) -> Result<LoadedStorageRules, String> {
    if cfg.storage_rules_by_target.is_empty() {
        let loaded = match &cfg.storage_rules_file {
            Some(path) => read_storage_rules(path)?,
            None => LoadedRules::default(),
        };
        let slot = Arc::new(RulesetSlot::new(loaded));
        let watched = cfg
            .storage_rules_file
            .iter()
            .map(|path| (path.clone(), slot.clone()))
            .collect();
        return Ok(LoadedStorageRules {
            registry: Arc::new(fireemu_adapter_http::storage::StorageRulesRegistry::global(
                slot,
            )),
            watched,
        });
    }
    if cfg.storage_buckets_by_target.len() != cfg.storage_rules_by_target.len() {
        return Err("Storage rules targets were not resolved through .firebaserc".to_owned());
    }
    let mut by_bucket = std::collections::BTreeMap::new();
    let mut watched = Vec::new();
    for (target, path) in &cfg.storage_rules_by_target {
        let slot = Arc::new(RulesetSlot::new(read_storage_rules(path)?));
        let buckets = cfg.storage_buckets_by_target.get(target).ok_or_else(|| {
            format!("Storage rules target {target:?} has no resolved bucket mapping")
        })?;
        for bucket in buckets {
            by_bucket.insert(bucket.clone(), slot.clone());
        }
        watched.push((path.clone(), slot));
    }
    Ok(LoadedStorageRules {
        registry: Arc::new(
            fireemu_adapter_http::storage::StorageRulesRegistry::per_bucket(by_bucket),
        ),
        watched,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WatchedFileStamp {
    len: u64,
    modified_nanos: u128,
}

fn watched_file_stamp(path: &str) -> Result<WatchedFileStamp, String> {
    let metadata = std::fs::metadata(path).map_err(|e| format!("{path}: {e}"))?;
    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos());
    Ok(WatchedFileStamp {
        len: metadata.len(),
        modified_nanos,
    })
}

fn watched_file(path: &str) -> Result<(WatchedFileStamp, u64, Vec<u8>), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let signature = bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        hash.wrapping_mul(0x100_0000_01b3) ^ u64::from(*byte)
    });
    Ok((watched_file_stamp(path)?, signature, bytes))
}

async fn watched_file_stamp_off_thread(path: &str) -> Result<WatchedFileStamp, String> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || watched_file_stamp(&path))
        .await
        .map_err(|error| format!("watch worker failed: {error}"))?
}

async fn watched_file_off_thread(path: &str) -> Result<(WatchedFileStamp, u64, Vec<u8>), String> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || watched_file(&path))
        .await
        .map_err(|error| format!("watch worker failed: {error}"))?
}

fn start_rules_reload_supervisor(
    path: String,
    label: &'static str,
    rules: &Arc<RulesetSlot>,
    barrier: &Arc<fireemu_core_session::barrier::AdmissionBarrier>,
) {
    let weak = Arc::downgrade(rules);
    let barrier = barrier.clone();
    let initial = watched_file(&path).ok();
    let mut observed_stamp = initial.as_ref().map(|(stamp, _, _)| *stamp);
    let mut observed_signature = initial.as_ref().map(|(_, signature, _)| *signature);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
            let Some(rules) = weak.upgrade() else {
                return;
            };
            let stamp = match watched_file_stamp_off_thread(&path).await {
                Ok(stamp) if observed_stamp != Some(stamp) => stamp,
                Ok(_) => continue,
                Err(reason) => {
                    eprintln!("warning: {label} reload scan failed: {reason}");
                    continue;
                }
            };
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let (candidate_stamp, candidate_signature, bytes) =
                match watched_file_off_thread(&path).await {
                    Ok(candidate) => candidate,
                    Err(error) => {
                        eprintln!(
                        "warning: {label} reload failed; keeping the last-known-good rules: {error}"
                    );
                        continue;
                    }
                };
            if candidate_stamp != stamp {
                continue;
            }
            observed_stamp = Some(candidate_stamp);
            if observed_signature == Some(candidate_signature) {
                continue;
            }
            observed_signature = Some(candidate_signature);
            let source = match String::from_utf8(bytes) {
                Ok(source) => source,
                Err(error) => {
                    eprintln!(
                        "warning: {label} reload failed; keeping the last-known-good rules: {error}"
                    );
                    continue;
                }
            };
            match LoadedRules::from_source(&source) {
                Ok(candidate) => {
                    let _admitted = barrier.admit();
                    match rules.replace_loaded(candidate) {
                        Ok(_) => eprintln!("note: reloaded {label} from {path}"),
                        Err(error) => eprintln!(
                            "warning: {label} reload failed; keeping the last-known-good rules: {error}"
                        ),
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
    let initial = watched_file(&path).ok();
    let mut observed_stamp = initial.as_ref().map(|(stamp, _, _)| *stamp);
    let mut observed_signature = initial.as_ref().map(|(_, signature, _)| *signature);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
            let Some(backend) = weak.upgrade() else {
                return;
            };
            let stamp = match watched_file_stamp_off_thread(&path).await {
                Ok(stamp) if observed_stamp != Some(stamp) => stamp,
                Ok(_) => continue,
                Err(reason) => {
                    eprintln!("warning: Firestore index reload scan failed: {reason}");
                    continue;
                }
            };
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let (candidate_stamp, candidate_signature, bytes) = match watched_file_off_thread(&path)
                .await
            {
                Ok(candidate) => candidate,
                Err(error) => {
                    eprintln!(
                        "warning: Firestore index reload failed; keeping the last-known-good indexes: {error}"
                    );
                    continue;
                }
            };
            if candidate_stamp != stamp {
                continue;
            }
            observed_stamp = Some(candidate_stamp);
            if observed_signature == Some(candidate_signature) {
                continue;
            }
            observed_signature = Some(candidate_signature);
            let text = match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(error) => {
                    eprintln!(
                        "warning: Firestore index reload failed; keeping the last-known-good indexes: {error}"
                    );
                    continue;
                }
            };
            match control::parse_indexes(&path, &text) {
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
    rules: &Arc<RulesetSlot>,
    database_rules: &std::collections::BTreeMap<String, Arc<RulesetSlot>>,
    storage_rules: &LoadedStorageRules,
    barrier: &Arc<fireemu_core_session::barrier::AdmissionBarrier>,
) {
    for (database, files) in &cfg.firestore_databases {
        if let Some(path) = &files.rules {
            let slot = if database == fireemu_core_types::ids::DatabaseId::DEFAULT {
                Some(rules)
            } else {
                database_rules.get(database)
            };
            if let Some(slot) = slot {
                start_rules_reload_supervisor(path.clone(), "Firestore rules", slot, barrier);
            }
        }
    }
    if cfg.firestore_databases.is_empty() {
        if let Some(path) = &cfg.rules_file {
            start_rules_reload_supervisor(path.clone(), "Firestore rules", rules, barrier);
        }
    }
    for (path, slot) in &storage_rules.watched {
        start_rules_reload_supervisor(path.clone(), "Storage rules", slot, barrier);
    }
    for (database, files) in &cfg.firestore_databases {
        if let Some(path) = &files.indexes {
            start_index_reload_supervisor(path.clone(), database.clone(), backend);
        }
    }
    if cfg.firestore_databases.is_empty() {
        if let Some(path) = &cfg.index_file {
            start_index_reload_supervisor(
                path.clone(),
                fireemu_core_types::ids::DatabaseId::DEFAULT.to_owned(),
                backend,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn storage_state(
    cfg: &RuntimeConfig,
    clock: &Arc<Mutex<VirtualClock>>,
    registry: &Arc<fireemu_core_auth::store::AuthRegistry>,
    tenancy: &fireemu_core_session::tenancy::SharedTenancy,
    storage_rules: &Arc<fireemu_adapter_http::storage::StorageRulesRegistry>,
    events: Option<fireemu_adapter_http::storage::StorageEventSink>,
    backend: &Arc<LocalBackend>,
    faults: &fireemu_core_session::fault::SharedFaultRegistry,
    clock_observer: Option<Arc<dyn Fn() + Send + Sync>>,
    app_check_policy: Option<Arc<fireemu_core_app_check::ServiceAdmission>>,
    admin_capability: String,
) -> Result<Arc<fireemu_adapter_http::storage::StorageState>, String> {
    let parent = fireemu_adapter_grpc::decode::Parent {
        project: fireemu_core_types::ids::ProjectId::try_new(cfg.auth_project.clone())
            .map_err(|e| format!("project id: {e}"))?,
        database: fireemu_core_types::ids::DatabaseId::try_new(
            fireemu_core_types::ids::DatabaseId::DEFAULT,
        )
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
        admin_capability: Some(admin_capability),
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
    eventarc: Option<tokio::net::TcpListener>,
    tasks: Option<tokio::net::TcpListener>,
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
    // An explicit Hub address wins over every port-zero listener. The default remains late
    // and best effort: a selected product configured on 4400 must win and disable discovery.
    let prebound_hub = if cfg.hub_addr_explicit {
        hub::bind(&cfg.hub_addr, true).await?
    } else {
        None
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
    // The pinned Firebase CLI starts both support emulators whenever a Functions backend is
    // loaded, even if `--only` did not name them. Naming either one without Functions is an
    // accepted no-op and binds neither listener.
    let eventarc = if functions.is_some() {
        Some(bind(&cfg.eventarc_addr).await?)
    } else {
        None
    };
    let tasks = if functions.is_some() {
        Some(bind(&cfg.tasks_addr).await?)
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
    let hub = if cfg.hub_addr_explicit {
        prebound_hub
    } else {
        hub::bind(&cfg.hub_addr, false).await?
    };
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
        eventarc,
        tasks,
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
        ("eventarc", addrs.eventarc),
        ("tasks", addrs.tasks),
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

fn print_banner(
    cfg: &RuntimeConfig,
    verb: &str,
    addrs: &BoundAddrs,
    functions_runtime: Option<&fireemu_adapter_functions::runtime::FunctionsRuntime>,
) {
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
        Some(addr) => {
            println!(
                "  functions (HTTP): {addr}   (source: {})",
                cfg.functions_source.as_deref().unwrap_or("")
            );
            if let Some(runtime) = functions_runtime {
                for function in &runtime.manifest().functions {
                    if matches!(
                        function.trigger,
                        fireemu_core_functions::manifest::Trigger::Http { .. }
                    ) {
                        println!(
                            "  function URL: http://{addr}/{}/{}/{}",
                            runtime.project(),
                            function.region,
                            function.name
                        );
                    }
                }
            }
        }
        None => {
            println!("  functions:        not configured (functions.source or --functions <dir>)");
        }
    }
    match addrs.eventarc {
        Some(a) => println!("  eventarc (HTTP):  {a}   CLOUD_EVENTARC_EMULATOR_HOST=http://{a}"),
        None => println!("  eventarc:         not started (requires a Functions codebase)"),
    }
    match addrs.tasks {
        Some(a) => println!("  tasks (HTTP):     {a}   CLOUD_TASKS_EMULATOR_HOST={a}"),
        None => println!("  tasks:            not started (requires a Functions codebase)"),
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
            if database == fireemu_core_types::ids::DatabaseId::DEFAULT {
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
    rules: &Arc<RulesetSlot>,
    database_rules: &std::collections::BTreeMap<String, Arc<RulesetSlot>>,
    storage_rules: &Arc<fireemu_adapter_http::storage::StorageRulesRegistry>,
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
    pubsub: &Arc<Mutex<fireemu_core_pubsub::PubSubState>>,
    pubsub_resources: &[functions::FunctionPubSubResource],
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
    ];
    for slot in database_rules.values() {
        snapshot_hooks.push(Arc::new(snapshots::Rules(
            "named database rules",
            slot.clone(),
        )));
    }
    snapshot_hooks.push(Arc::new(snapshots::StorageRules(storage_rules.clone())));
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
    let pubsub = pubsub.clone();
    let pubsub_resources = pubsub_resources.to_vec();
    let pubsub_project = cfg.auth_project.clone();
    reset_hooks.push(Arc::new(move || {
        if let Ok(mut state) = pubsub.lock() {
            state.clear_project(&pubsub_project);
            functions::provision_function_pubsub_resources(&mut state, &pubsub_resources)
                .expect("validated Functions Pub/Sub resources reprovision after reset");
        }
    }));
    fireemu_adapter_http::control::ControlState {
        clock: clock.clone(),
        require_demo_prefix: cfg.require_demo_prefix,
        edition: cfg.edition,
        capabilities: fireemu_adapter_http::control::CapabilityManifest::lazy({
            let profile = cfg.profile;
            move || control::capabilities_manifest(profile)
        }),
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

fn logical_system_time(system_time: std::time::SystemTime) -> LogicalInstant {
    let nanos = system_time
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i128::try_from(duration.as_nanos()).unwrap_or(i128::MAX))
        .unwrap_or(0);
    LogicalInstant::from_nanos(nanos)
}

#[cfg(test)]
mod config_reload_tests {
    use super::*;
    use fireemu_adapter_grpc::gateway::Gateway;
    use fireemu_core_firestore::index::IndexValidationPolicy;
    use fireemu_core_firestore::index::{IndexSet, PlanningContext};
    use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};

    const RULES_ONE: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if true; } } }";
    const RULES_TWO: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow write: if false; } } }";
    const STORAGE_ALLOW: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read: if true; } } }";
    const STORAGE_DENY: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read: if false; } } }";
    const STORAGE_WRITE: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow write: if true; } } }";

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fireemu-reload-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn unpinned_clock_start_preserves_subsecond_wall_time() {
        let wall_time = std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::new(1_800_000_000, 123_456_789))
            .unwrap();

        assert_eq!(
            logical_system_time(wall_time),
            LogicalInstant::from_nanos(1_800_000_000_123_456_789)
        );
    }

    #[test]
    fn runtime_thread_counts_are_bounded_and_explicit_overrides_are_validated() {
        assert_eq!(runtime_thread_counts(32, None, None).unwrap(), (4, 64));
        assert_eq!(runtime_thread_counts(2, None, None).unwrap(), (2, 64));
        assert_eq!(
            runtime_thread_counts(32, Some("7"), Some("96")).unwrap(),
            (7, 96)
        );
        assert!(runtime_thread_counts(8, Some("0"), None).is_err());
        assert!(runtime_thread_counts(8, None, Some("513")).is_err());
        assert!(runtime_thread_counts(8, Some("many"), None).is_err());
    }

    #[tokio::test]
    async fn a_selected_product_wins_a_port_shared_with_the_default_hub() {
        let only = Selection {
            firestore: true,
            auth: false,
            storage: false,
            functions: false,
            pubsub: false,
            appcheck: false,
            explicit: true,
            functions_codebase: None,
        };
        let mut last_error = None;
        for _ in 0..32 {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = probe.local_addr().unwrap().to_string();
            drop(probe);
            let cfg = RuntimeConfig {
                firestore_addr: addr.clone(),
                hub_addr: addr,
                hub_addr_explicit: false,
                logging_enabled: false,
                ..RuntimeConfig::default()
            };
            match bind_listeners(&cfg, &only).await {
                Ok(listeners) => {
                    assert!(listeners.firestore.is_some());
                    assert!(listeners.hub.is_none());
                    return;
                }
                Err(error) => last_error = Some(error),
            }
        }
        panic!(
            "could not reacquire any freshly selected loopback port: {}",
            last_error.unwrap_or_else(|| "no bind attempt was made".to_owned())
        );
    }

    #[tokio::test]
    async fn rules_reload_publishes_only_a_valid_complete_generation() {
        let dir = scratch("rules");
        let path = dir.join("firestore.rules");
        std::fs::write(&path, RULES_ONE).unwrap();
        let rules = Arc::new(RulesetSlot::new(
            LoadedRules::from_source(RULES_ONE).unwrap(),
        ));
        let barrier = Arc::new(fireemu_core_session::barrier::AdmissionBarrier::new());
        start_rules_reload_supervisor(
            path.display().to_string(),
            "Firestore rules",
            &rules,
            &barrier,
        );

        std::fs::write(&path, "not a rules program").unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1_300)).await;
        assert_eq!(rules.snapshot().unwrap().source.as_deref(), Some(RULES_ONE));

        let hostile_condition = vec!["true"; 30_000].join(" && ");
        let hostile = format!(
            "rules_version = '2'; service cloud.firestore {{ match /databases/{{database}}/documents {{ match /{{document=**}} {{ allow read: if {hostile_condition}; }} }} }}"
        );
        std::fs::write(&path, hostile).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1_300)).await;
        assert_eq!(rules.snapshot().unwrap().source.as_deref(), Some(RULES_ONE));

        std::fs::write(&path, RULES_TWO).unwrap();
        for _ in 0..30 {
            if rules.snapshot().unwrap().source.as_deref() == Some(RULES_TWO) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(rules.snapshot().unwrap().source.as_deref(), Some(RULES_TWO));
        drop(rules);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn rules_reload_publishes_a_file_created_after_supervisor_start() {
        let dir = scratch("rules-created-later");
        let path = dir.join("firestore.rules");
        let rules = Arc::new(RulesetSlot::new(
            LoadedRules::from_source(RULES_ONE).unwrap(),
        ));
        let barrier = Arc::new(fireemu_core_session::barrier::AdmissionBarrier::new());
        start_rules_reload_supervisor(
            path.display().to_string(),
            "Firestore rules",
            &rules,
            &barrier,
        );

        std::fs::write(&path, RULES_TWO).unwrap();
        for _ in 0..30 {
            if rules.snapshot().unwrap().source.as_deref() == Some(RULES_TWO) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(rules.snapshot().unwrap().source.as_deref(), Some(RULES_TWO));
        drop(rules);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn storage_target_reload_changes_only_its_own_bucket_group() {
        let dir = scratch("storage-target-isolation");
        let public_path = dir.join("public.rules");
        let private_path = dir.join("private.rules");
        std::fs::write(&public_path, STORAGE_DENY).unwrap();
        std::fs::write(&private_path, STORAGE_DENY).unwrap();
        let public = Arc::new(RulesetSlot::new(
            LoadedRules::from_source(STORAGE_DENY).unwrap(),
        ));
        let private = Arc::new(RulesetSlot::new(
            LoadedRules::from_source(STORAGE_DENY).unwrap(),
        ));
        let loaded = LoadedStorageRules {
            registry: Arc::new(
                fireemu_adapter_http::storage::StorageRulesRegistry::per_bucket(
                    std::collections::BTreeMap::from([
                        ("public.example.test".to_owned(), public.clone()),
                        ("private.example.test".to_owned(), private.clone()),
                    ]),
                ),
            ),
            watched: vec![
                (public_path.to_string_lossy().into_owned(), public.clone()),
                (private_path.to_string_lossy().into_owned(), private.clone()),
            ],
        };
        let barrier = Arc::new(fireemu_core_session::barrier::AdmissionBarrier::new());
        start_firestore_config_reload_supervisors(
            &RuntimeConfig::default(),
            &Arc::new(LocalBackend::new(
                Gateway {
                    enforce_limits: true,
                    ctx: PlanningContext {
                        edition: FirestoreEdition::Standard,
                        api_mode: FirestoreApiMode::Native,
                        policy: IndexValidationPolicy::Conservative,
                    },
                    indexes: IndexSet::default(),
                },
                Arc::new(Mutex::new(VirtualClock::new(
                    LogicalInstant::from_unix_seconds(1_788_004_860),
                ))),
                7,
            )),
            &Arc::new(RulesetSlot::default()),
            &std::collections::BTreeMap::new(),
            &loaded,
            &barrier,
        );

        std::fs::write(&public_path, STORAGE_ALLOW).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                if public.snapshot().unwrap().source.as_deref() == Some(STORAGE_ALLOW) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the public target should reload");
        assert_eq!(
            private.snapshot().unwrap().source.as_deref(),
            Some(STORAGE_DENY)
        );
    }

    #[tokio::test]
    async fn global_storage_file_keeps_reloading_after_a_control_update() {
        let dir = scratch("storage-global-control-reload");
        let path = dir.join("storage.rules");
        std::fs::write(&path, STORAGE_DENY).unwrap();
        let slot = Arc::new(RulesetSlot::new(
            LoadedRules::from_source(STORAGE_DENY).unwrap(),
        ));
        let loaded = LoadedStorageRules {
            registry: Arc::new(fireemu_adapter_http::storage::StorageRulesRegistry::global(
                slot.clone(),
            )),
            watched: vec![(path.to_string_lossy().into_owned(), slot.clone())],
        };
        let barrier = Arc::new(fireemu_core_session::barrier::AdmissionBarrier::new());
        start_rules_reload_supervisor(
            path.to_string_lossy().into_owned(),
            "Storage rules",
            &slot,
            &barrier,
        );

        loaded.registry.replace_source(STORAGE_ALLOW).unwrap();
        assert_eq!(
            loaded
                .registry
                .global_snapshot()
                .unwrap()
                .unwrap()
                .source
                .as_deref(),
            Some(STORAGE_ALLOW)
        );
        std::fs::write(&path, STORAGE_WRITE).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                if slot.snapshot().unwrap().source.as_deref() == Some(STORAGE_WRITE) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the configured Storage file should keep reloading");
        assert_eq!(
            loaded
                .registry
                .global_snapshot()
                .unwrap()
                .unwrap()
                .source
                .as_deref(),
            Some(STORAGE_WRITE)
        );
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
