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
//! fireemu --help | -h | help [command]
//! fireemu <command> --help | -h
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
//! `--help` is answered before a command parses anything (see the `help` module); for `exec`
//! it only counts before `--`, so `fireemu exec -- cmd --help` runs `cmd --help`.
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
mod config_discovery;
mod config_shape;
mod control;
mod daemon;
mod database_rules;
mod doctor;
mod functions;
mod help;
mod hub;
mod import_export;
mod init;
mod managed_storage;
mod readiness;
mod resources;
mod session_rsa_cache;
mod sessions;
mod snapshots;
mod ui;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_rules::runtime::{LoadedRules, RulesCompilationCache, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;
#[cfg(windows)]
use process_wrap::tokio::{JobObject, KillOnDrop, TokioChildWrapper, TokioCommandWrap};

use crate::config::{RuntimeConfig, Selection};

const OPTIONS_USAGE: &str = "[--config <file>] [--firebase-json <file>] [--no-config-discovery] [--project <id|alias>] [--only auth,firestore,storage,functions,eventarc,tasks,pubsub,database,appcheck] [--firestore-port <n>] [--http-port <n>] [--storage-port <n>] [--functions-port <n>] [--eventarc-port <n>] [--tasks-port <n>] [--pubsub-port <n>] [--database-port <n>] [--functions <dir>] [--ui-port <n|auto>] [--hub-port <n|auto>] [--logging-port <n>] [--inspect-functions [port]] [--log-verbosity quiet|silent|info|debug] [--import <dir>] [--export-on-exit [dir]] [--ready-file <file>]";

fn usage() -> ExitCode {
    eprintln!("usage: fireemu init [--profile strict|emulator] [--firebase-json <file>] [--interactive|--yes|--no-interactive] [--force]\n       fireemu up|emulators:start {OPTIONS_USAGE}\n       fireemu exec|emulators:exec {OPTIONS_USAGE} [--ui] \"shell script\"\n       fireemu exec|emulators:exec {OPTIONS_USAGE} [--ui] -- <command...>\n       fireemu emulators:export <dir> [--project <id>] [--force]\n       fireemu doctor\n       fireemu capabilities\n       fireemu --version\n       fireemu --help | fireemu help <command>\n\nrun `fireemu --help` for the commands, or `fireemu <command> --help` for the options of one");
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
        if character.is_control()
            || matches!(
                character,
                '\u{ad}'
                    | '\u{600}'..='\u{605}'
                    | '\u{61c}'
                    | '\u{6dd}'
                    | '\u{70f}'
                    | '\u{890}'..='\u{891}'
                    | '\u{8e2}'
                    | '\u{180e}'
                    | '\u{200b}'..='\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2060}'..='\u{2064}'
                    | '\u{2066}'..='\u{206f}'
                    | '\u{feff}'
                    | '\u{fff9}'..='\u{fffb}'
                    | '\u{110bd}'
                    | '\u{110cd}'
                    | '\u{13430}'..='\u{1343f}'
                    | '\u{1bca0}'..='\u{1bca3}'
                    | '\u{1d173}'..='\u{1d17a}'
                    | '\u{e0001}'
                    | '\u{e0020}'..='\u{e007f}'
            )
        {
            for escaped in character.escape_debug() {
                write!(formatter, "{escaped}")?;
            }
        } else {
            write!(formatter, "{character}")?;
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
            .field("production_exact", &config.production_exact)
            .field("edition", &config.edition)
            .field("api_mode", &config.api_mode)
            .field("index_policy", &config.index_policy())
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
    /// Private endpoint descriptor for a supervised test world.
    ready_file: Option<PathBuf>,
    owner_stdin: bool,
    /// Which configuration files were loaded, for the start banner.
    config_origin: String,
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
    if let Some(code) = help_command(&args) {
        return code;
    }
    let command = args.first().map_or("", String::as_str);
    match args.first().map(String::as_str) {
        // Version is answered before anything else so tooling that records which build it
        // drove (benchmarks, packaging) never has to start a daemon to find out.
        Some("--version" | "-V" | "version") if args.len() == 1 => {
            println!("fireemu {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("--version" | "-V" | "version") => fail(&CliError::usage("usage: fireemu --version")),
        Some("init") => match init::run(&args[1..]) {
            Ok(path) => {
                println!("created {}", diagnostic_path(&path));
                let configuration = if path.with_file_name("fireemu.json").is_file() {
                    "fireemu.json"
                } else {
                    "fireemu.toml"
                };
                println!(
                    "next: fireemu up ({configuration} in this directory is loaded automatically)"
                );
                ExitCode::SUCCESS
            }
            Err(e) => fail_for(command, &e),
        },
        Some("config") => match config_show_command(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail_for(command, &e),
        },
        Some("__test-world-config") => match test_world_config_command(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail_for(command, &e),
        },
        Some("up" | "emulators:start") => match parse_options(&args[1..], OptionContext::Start) {
            Ok((options, None)) => daemon::run(options, None),
            Ok((_, Some(_))) => unreachable!("start does not accept a positional argument"),
            Err(e) => fail_for(command, &e),
        },
        #[cfg(windows)]
        Some("__test-world-command") => supervise_world_command(&args[1..]),
        Some("exec" | "emulators:exec") => match parse_exec(&args[1..]) {
            Ok((options, plan)) => daemon::run(options, Some(plan)),
            Err(e) => fail_for(command, &e),
        },
        Some("emulators:export") => match export_command(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail_for(command, &e),
        },
        Some("doctor") => match args.get(1).map(String::as_str) {
            None => doctor::run(),
            Some("--export-dir") => match args.get(2) {
                Some(path) if args.len() == 3 => doctor::run_export_dir(Path::new(path)),
                _ => fail(&doctor_usage()),
            },
            Some("--connect") => match args.get(2) {
                Some(url) if args.len() == 3 => doctor::run_connect(url),
                _ => fail(&doctor_usage()),
            },
            Some(_) => fail(&doctor_usage()),
        },
        // The manifest describes the behaviour of one profile, so the command takes the same
        // options the daemon does and reports the profile they resolve to.
        Some("capabilities") => match parse_options(&args[1..], OptionContext::Inspect) {
            Ok((options, None)) => {
                if let Err(warning) = options.cfg.validate_startup() {
                    eprintln!("warning: {warning}");
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&control::capabilities_manifest(
                        options.cfg.profile,
                        options.cfg.production_exact,
                        &options.cfg.development_defaults,
                    ))
                    .unwrap_or_default()
                );
                ExitCode::SUCCESS
            }
            Ok((_, Some(_))) => unreachable!("capabilities does not accept a positional argument"),
            Err(e) => fail_for(command, &e),
        },
        _ => usage(),
    }
}

/// Private bridge for the npm snapshot helper: parse without discovery, defaults or services.
fn test_world_config_command(args: &[String]) -> Result<(), CliError> {
    let [path] = args else {
        return Err(CliError::usage(
            "__test-world-config requires one config path",
        ));
    };
    let path = Path::new(path);
    let is_toml = path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"));
    let (document, _) = read_config_file(path, is_toml)?;
    println!("{document}");
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn config_show_command(args: &[String]) -> Result<(), CliError> {
    if args.first().map(String::as_str) != Some("show") {
        return Err(CliError::usage(
            "usage: fireemu config show [--config <path>] [--firebase-json <path>] [--json]",
        ));
    }
    let mut flags = Vec::new();
    let mut json = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                json = true;
                index += 1;
            }
            "--config" | "--firebase-json" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| CliError::usage(format!("{} needs a value", args[index])))?;
                flags.extend([args[index].clone(), value.clone()]);
                index += 2;
            }
            other => {
                return Err(CliError::usage(format!(
                    "unknown argument {}",
                    diagnostic_text(other)
                )))
            }
        }
    }
    let mut raw = parse_raw_options(&flags, OptionContext::Start)?;
    let origin = discover_project_config(&mut raw)?;
    let (mut cfg, project_root, sources) =
        load_project_config(&raw, &Selection::default()).map_err(note_discovered(&origin))?;
    let rc = if matches!(origin, ConfigOrigin::Discovered(_)) {
        discovered_firebaserc(&project_root).map_err(note_discovered(&origin))?
    } else {
        read_firebaserc(&project_root)?
    };
    let project = resolve_project(rc.as_ref(), None)?;
    if let Some(project) = &project {
        cfg.auth_project.clone_from(project);
    }
    if !cfg.storage_rules_by_target.is_empty() {
        let rc = rc.as_ref().ok_or_else(|| {
            CliError::refused(
                "firebase.json declares Storage targets but the project has no .firebaserc",
            )
        })?;
        let project = cfg.auth_project.clone();
        cfg.resolve_storage_rules_targets(rc, &project)?;
    }
    // firebase-tools resolves the rules targets only for a database it starts.
    if cfg.database_enabled {
        cfg.database_rules_resolved =
            cfg.database_rules_by_instance(rc.as_ref(), &cfg.auth_project)?;
    }
    let input = match &sources.canonical {
        Some(path) => config_document(&raw, path)?.0,
        None => serde_json::Value::Null,
    };
    let firebase = sources
        .firebase
        .as_ref()
        .map(|(path, _)| read_firebase_json(path).map(|(document, _)| document))
        .transpose()?;
    let mut rows = cfg.config_show(&input);
    for row in &mut rows {
        let key = row["key"].as_str().expect("key");
        let firebase_path = match key {
            "daemon.firestorePort" => "/emulators/firestore/port",
            "daemon.httpPort" => "/emulators/auth/port",
            "daemon.storagePort" => "/emulators/storage/port",
            "daemon.functionsPort" => "/emulators/functions/port",
            "daemon.eventarcPort" => "/emulators/eventarc/port",
            "daemon.tasksPort" => "/emulators/tasks/port",
            "daemon.pubsubPort" => "/emulators/pubsub/port",
            "daemon.databasePort" => "/emulators/database/port",
            "daemon.loggingPort" => "/emulators/logging/port",
            "rules.source" | "firestore.indexFile" => "/firestore",
            "storage.rules" => "/storage",
            "functions.source" => "/functions",
            _ => "",
        };
        if key == "firebaseJson" {
            // The file the daemon would actually read, not only the entry the canonical
            // configuration wrote (a --firebase-json, --config or discovered file wins).
            if let Some((path, via)) = &sources.firebase {
                row["value"] = diagnostic_path(path).to_string().into();
                row["source"] = match via {
                    FirebaseJsonVia::Reference => "explicit",
                    FirebaseJsonVia::ConfigFlag => "explicit (--config)",
                    FirebaseJsonVia::FirebaseJsonFlag
                        if matches!(origin, ConfigOrigin::Discovered(_)) =>
                    {
                        "discovered"
                    }
                    FirebaseJsonVia::FirebaseJsonFlag => "explicit (--firebase-json)",
                }
                .into();
            } else {
                row["value"] = serde_json::Value::Null;
                row["source"] = "unset".into();
            }
        } else if key == "daemon.authProject" && project.is_some() {
            // The project resolved from .firebaserc replaces whatever the configuration said.
            row["source"] = ".firebaserc".into();
        } else if !firebase_path.is_empty()
            && firebase
                .as_ref()
                .is_some_and(|f| f.pointer(firebase_path).is_some())
        {
            row["source"] = if row["value"].is_null() {
                "unset"
            } else {
                "explicit"
            }
            .into();
        }
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).expect("configuration rows")
        );
    } else {
        for row in rows {
            let value = if row["source"] == "unset"
                || (row["source"] == config::NO_EFFECT_SOURCE && row["value"].is_null())
            {
                "(unset)".to_owned()
            } else {
                row["value"].to_string()
            };
            println!(
                "{} = {} ({})",
                row["key"].as_str().expect("key"),
                value,
                row["source"].as_str().expect("source")
            );
        }
    }
    Ok(())
}

/// Prints the failure and returns its exit code.
fn fail(e: &CliError) -> ExitCode {
    eprintln!("error: {}", e.message);
    ExitCode::from(e.code)
}

/// The pointer to a command's options that an unknown argument is answered with.
fn options_hint(command: &str) -> String {
    format!("run `fireemu {command} --help` for the options")
}

/// Whether a usage failure is the parsers' "unknown argument" refusal.
fn is_unknown_argument(e: &CliError) -> bool {
    e.code == 2
        && (e.message.starts_with("unknown argument ")
            || e.message.starts_with("unknown init argument "))
}

/// [`fail`] for a failure of `command`: an unknown argument also says where the options are.
fn fail_for(command: &str, e: &CliError) -> ExitCode {
    if is_unknown_argument(e) {
        eprintln!("error: {} ({})", e.message, options_hint(command));
        ExitCode::from(e.code)
    } else {
        fail(e)
    }
}

fn doctor_usage() -> CliError {
    CliError::usage(format!(
        "usage: fireemu doctor [--connect http://127.0.0.1:<control port> | --export-dir <path>] ({})",
        options_hint("doctor")
    ))
}

/// Answers `--help`, `-h`, `help` and `<command> --help`; `None` when `args` ask for neither.
///
/// This runs before any command parses its arguments, so help is never delayed or replaced by
/// a configuration error, and nothing is started or written.
fn help_command(args: &[String]) -> Option<ExitCode> {
    let first = args.first()?.as_str();
    match first {
        "--help" | "-h" => {
            print!("{}", help::overall_help());
            Some(ExitCode::SUCCESS)
        }
        "help" => Some(
            match args[1..].iter().map(String::as_str).collect::<Vec<_>>()[..] {
                [] | ["--help" | "-h"] => {
                    print!("{}", help::overall_help());
                    ExitCode::SUCCESS
                }
                [name] => match help::Topic::for_command(name) {
                    Some(topic) => {
                        print!("{}", help::command_help(topic));
                        ExitCode::SUCCESS
                    }
                    None => fail(&CliError::usage(format!(
                        "unknown command {name}; the commands are {}",
                        help::command_names()
                    ))),
                },
                _ => fail(&CliError::usage("usage: fireemu help [command]")),
            },
        ),
        name => {
            let topic = help::Topic::for_command(name)?;
            if !help::requested(topic, &args[1..]) {
                return None;
            }
            print!("{}", help::command_help(topic));
            Some(ExitCode::SUCCESS)
        }
    }
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
        // The project `up` and `exec` would take from here, so a suite started from the same
        // directory is found.
        let rc = discovered_firebaserc(&discovered_project_dir())?;
        resolve_project(rc.as_ref(), None)?
            .unwrap_or_else(|| config::RuntimeConfig::default().auth_project)
    };
    let locator = hub::Locator::path_for(&project);
    // "Not there at all" is the ordinary case and says how to start a suite. Anything else the
    // locator might be -- a symlink, another user's file, a file anyone can write, a document
    // too large to be a locator -- is a refusal from the shared reader, because reaching the
    // origin this file names means presenting the run's control capability.
    if std::fs::symlink_metadata(&locator).is_err() {
        return Err(CliError::refused(format!(
            "no running fireemu suite for {project} was found: {} does not exist. Start one with `fireemu up --project {project}`, or name the project with --project.",
            locator.display()
        )));
    }
    let document = hub::read_locator(&locator).map_err(CliError::refused)?;
    let origin = document
        .get("origins")
        .and_then(|o| o.get(0))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CliError::refused(format!("{} names no Hub origin", locator.display())))?;
    let address = hub::loopback_authority(origin).map_err(CliError::refused)?;
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
    let (status, response) = post_json(&address, "/_admin/export", &body, token)
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
    for warning in serde_json::from_str::<serde_json::Value>(&response)
        .ok()
        .and_then(|v| {
            v.get("warnings")
                .and_then(serde_json::Value::as_array)
                .cloned()
        })
        .unwrap_or_default()
    {
        if let Some(warning) = warning.as_str() {
            eprintln!("warning: {warning}");
        }
    }
    println!("exported {project} to {}", absolute.display());
    Ok(())
}

/// Refuses a connection that did not land on this host's loopback interface.
///
/// The control capability is only ever presented to a peer whose address is loopback. A
/// locator naming `http://localhost:4400` passes the origin rule, but the name is resolved by
/// the host, so the address it resolved to is what decides.
fn refuse_non_loopback_peer(peer: std::net::SocketAddr) -> Result<(), String> {
    if peer.ip().is_loopback() {
        return Ok(());
    }
    Err(format!(
        "the Hub origin resolved to {}, which is not loopback; the control capability is not sent there",
        peer.ip()
    ))
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
    // `loopback_authority` has already refused every origin but a loopback one, and it accepts
    // the name `localhost` because that is what a locator usually spells. A name is resolved
    // by the host, and the host can be told to resolve it elsewhere (HOSTALIASES, /etc/hosts,
    // a search domain), so what the connection actually reached is checked before the control
    // capability is written to it.
    let peer = stream.peer_addr().map_err(|e| e.to_string())?;
    refuse_non_loopback_peer(peer)?;
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

/// An automatic auxiliary listener or the legacy numeric port selection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AuxiliaryPort {
    Auto,
    Fixed(u16),
}

/// The parsed command line, before it is applied to a configuration.
#[derive(Default)]
struct RawOptions {
    /// The official `emulators:exec <script>` positional argument.
    positional_script: Option<String>,
    config_path: Option<PathBuf>,
    ready_file: Option<PathBuf>,
    owner_stdin: bool,
    firebase_json: Option<PathBuf>,
    /// Whether the working directory is searched when neither `--config` nor `--firebase-json`
    /// is given (`--no-config-discovery` turns it off).
    config_discovery: ConfigDiscovery,
    /// The file the search found and the text read from the handle it was judged by.
    discovered_text: Option<(PathBuf, Result<String, String>)>,
    project: Option<String>,
    only: Option<Selection>,
    firestore_port: Option<u16>,
    http_port: Option<u16>,
    storage_port: Option<u16>,
    functions_port: Option<u16>,
    eventarc_port: Option<u16>,
    tasks_port: Option<u16>,
    pubsub_port: Option<u16>,
    database_port: Option<u16>,
    hub_port: Option<AuxiliaryPort>,
    context: OptionContext,
    ui_port: Option<AuxiliaryPort>,
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum OptionContext {
    Inspect,
    #[default]
    Start,
    Exec,
}

#[allow(clippy::too_many_lines)]
fn parse_raw_options(args: &[String], context: OptionContext) -> Result<RawOptions, CliError> {
    let mut raw = RawOptions {
        context,
        ..RawOptions::default()
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--owner-stdin" => {
                raw.owner_stdin = true;
                i += 1;
            }
            "--ready-file" => {
                raw.ready_file =
                    Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                        CliError::usage("--ready-file needs a value")
                    })?));
                i += 2;
            }
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
            "--no-config-discovery" => {
                raw.config_discovery = ConfigDiscovery::Off;
                i += 1;
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
            "--database-port" => {
                raw.database_port = Some(port_arg(args, i, "--database-port")?);
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
                raw.ui_port = Some(if args.get(i + 1).is_some_and(|value| value == "auto") {
                    AuxiliaryPort::Auto
                } else {
                    AuxiliaryPort::Fixed(port_arg(args, i, "--ui-port")?)
                });
                i += 2;
            }
            "--ui" if context == OptionContext::Exec => {
                raw.ui = true;
                i += 1;
            }
            "--hub-port" => {
                raw.hub_port = Some(if args.get(i + 1).is_some_and(|value| value == "auto") {
                    AuxiliaryPort::Auto
                } else {
                    AuxiliaryPort::Fixed(port_arg(args, i, "--hub-port")?)
                });
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

/// Reads the file `--config` names. TOML always requires `schemaVersion`; JSON without it is a `firebase.json` unless fireemu-only keys reveal a missing version. Shared product sections and unrelated Firebase deploy keys remain valid.
fn read_config_file(path: &Path, is_toml: bool) -> Result<(serde_json::Value, bool), CliError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| CliError::refused(format!("cannot read {}: {e}", diagnostic_path(path))))?;
    parse_config_text(path, &text, is_toml)
}

/// [`read_config_file`] for text already read: from the handle the search judged, when `path`
/// is the file it found.
#[allow(clippy::too_many_lines)]
fn parse_config_text(
    path: &Path,
    text: &str,
    is_toml: bool,
) -> Result<(serde_json::Value, bool), CliError> {
    let json: serde_json::Value = if is_toml {
        let value: toml::Value = toml::from_str(text).map_err(|error| {
            let position = error
                .span()
                .and_then(|span| text.get(..span.start))
                .map(|before| {
                    let line = before.bytes().filter(|byte| *byte == b'\n').count() + 1;
                    let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
                    format!(":{line}:{column}")
                })
                .unwrap_or_default();
            CliError::refused(format!(
                "{}{position}: {}",
                diagnostic_path(path),
                diagnostic_text(error.message())
            ))
        })?;
        if value.get("schemaVersion").is_none() {
            return Err(CliError::refused(format!(
                "{}: a TOML configuration must set schemaVersion = 1 (firebase.json is JSON only)",
                diagnostic_path(path)
            )));
        }
        let mut pending = vec![(String::new(), &value)];
        while let Some((key, value)) = pending.pop() {
            match value {
                toml::Value::Datetime(_) => {
                    return Err(CliError::refused(format!(
                        "{}: {}: TOML datetime values are not supported; use a quoted string",
                        diagnostic_path(path),
                        diagnostic_text(&key)
                    )))
                }
                toml::Value::Float(number) if !number.is_finite() => {
                    return Err(CliError::refused(format!(
                        "{}: {}: non-finite TOML numbers are not supported",
                        diagnostic_path(path),
                        diagnostic_text(&key)
                    )))
                }
                toml::Value::Table(table) => pending.extend(table.iter().map(|(name, value)| {
                    let name = if !name.is_empty()
                        && name
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                    {
                        name.clone()
                    } else {
                        toml::Value::String(name.clone()).to_string()
                    };
                    (
                        if key.is_empty() {
                            name
                        } else {
                            format!("{key}.{name}")
                        },
                        value,
                    )
                })),
                toml::Value::Array(array) => pending.extend(
                    array
                        .iter()
                        .enumerate()
                        .map(|(index, value)| (format!("{key}[{index}]"), value)),
                ),
                _ => {}
            }
        }
        serde_json::to_value(value)
            .map_err(|error| CliError::refused(format!("{}: {error}", diagnostic_path(path))))?
    } else {
        serde_json::from_str(text).map_err(|e| {
            CliError::refused(format!("{} does not parse: {e}", diagnostic_path(path)))
        })?
    };
    let canonical = json.get("schemaVersion").is_some();
    if !canonical {
        // Do not use the filename or reject arbitrary Firebase deployment extensions.
        const FIREEMU_ONLY_KEYS: &[&str] = &[
            "firebaseJson",
            "profile",
            "productionExact",
            "bind",
            "projects",
            "limits",
            "rules",
            "appCheck",
            "events",
            "eventarc",
            "scheduler",
            "trace",
            "daemon",
        ];
        let key = FIREEMU_ONLY_KEYS
            .iter()
            .copied()
            .find(|key| json.get(*key).is_some())
            .map(str::to_owned)
            .or_else(|| {
                let auth = json.get("auth")?;
                config::AUTH_KEYS
                    .iter()
                    // Firebase deployment configuration also uses auth.providers. Without schemaVersion it remains deployment data, never a Fireemu seed.
                    .find(|key| **key != "providers" && auth.get(**key).is_some())
                    .map(|key| format!("auth.{key}"))
            });
        if let Some(key) = key {
            return Err(CliError::refused(format!(
                "{}: {key} requires a fireemu canonical configuration; add \"schemaVersion\": 1 and pass it with --config",
                diagnostic_path(path)
            )));
        }
    }
    Ok((json, canonical))
}

/// Reads a Firebase project configuration and refuses a canonical fireemu document.
fn read_firebase_json(path: &Path) -> Result<(serde_json::Value, PathBuf), CliError> {
    firebase_json_document(path, read_config_file(path, false)?)
}

/// Refuses a canonical fireemu document or a non-object where a `firebase.json` belongs.
fn firebase_json_document(
    path: &Path,
    (json, canonical): (serde_json::Value, bool),
) -> Result<(serde_json::Value, PathBuf), CliError> {
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
    parse_firebaserc(&rc_path, &text).map(Some)
}

fn parse_firebaserc(rc_path: &Path, text: &str) -> Result<serde_json::Value, CliError> {
    serde_json::from_str(text)
        .map_err(|e| CliError::refused(format!("{} does not parse: {e}", diagnostic_path(rc_path))))
}

/// The project directory `up` and `exec` would find from the working directory: the directory
/// of the discovered `firebase.json`, else the working directory (firebase-tools' `loadRC` reads
/// the `.firebaserc` beside the `firebase.json` it finds).
fn discovered_project_dir() -> PathBuf {
    let found = std::env::current_dir().ok().map(|cwd| {
        config_discovery::discover(
            &cwd,
            &config_discovery::current_trust(),
            config_discovery::stat,
            config_discovery::open,
        )
        .found
    });
    match found {
        Some(config_discovery::Discovered::FirebaseJson(path, _)) => project_dir(&path),
        _ => PathBuf::from("."),
    }
}

/// Reads the `.firebaserc` of a directory the search reached, unless any user can write it (see
/// `config_discovery::read_firebaserc`); a refused one is reported and ignored.
fn discovered_firebaserc(dir: &Path) -> Result<Option<serde_json::Value>, CliError> {
    let absolute = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    match config_discovery::read_firebaserc(
        &absolute,
        config_discovery::stat,
        config_discovery::open,
    ) {
        Ok(None) => Ok(None),
        Ok(Some(text)) => {
            let rc_path = dir.join(config_discovery::FIREBASERC_FILE);
            let text = text.map_err(|e| {
                CliError::refused(format!("cannot read {}: {e}", diagnostic_path(&rc_path)))
            })?;
            parse_firebaserc(&rc_path, &text).map(Some)
        }
        Err(skipped) => {
            eprintln!(
                "{}",
                skipped_config_warning(
                    &skipped,
                    "the project is not taken from it (pass --project)"
                )
            );
            Ok(None)
        }
    }
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
        cfg.eventarc_enabled = true;
        cfg.eventarc_addr_explicit = true;
    }
    if let Some(p) = raw.tasks_port {
        cfg.tasks_addr = with_port(&cfg.tasks_addr, p);
        cfg.tasks_enabled = true;
        cfg.tasks_addr_explicit = true;
    }
    if let Some(p) = raw.pubsub_port {
        cfg.pubsub_addr = with_port(&cfg.pubsub_addr, p);
        cfg.pubsub_enabled = true;
    }
    if let Some(p) = raw.database_port {
        cfg.database_addr = with_port(&cfg.database_addr, p);
        cfg.database_enabled = true;
    }
    if let Some(selection) = raw.hub_port {
        let port = match selection {
            AuxiliaryPort::Auto => 0,
            AuxiliaryPort::Fixed(port) => port,
        };
        cfg.hub_auto_port = selection == AuxiliaryPort::Auto;
        cfg.hub_addr = with_port(&cfg.hub_addr, port);
        cfg.hub_addr_explicit = true;
    }
    if let Some(selection) = raw.ui_port {
        let (port, enabled) = match selection {
            AuxiliaryPort::Auto => (0, true),
            AuxiliaryPort::Fixed(port) => (port, port != 0),
        };
        cfg.ui_addr = with_port(&cfg.ui_addr, port);
        cfg.ui_enabled = enabled;
        cfg.ui_addr_explicit = true;
    }
    if let Some(p) = raw.logging_port {
        cfg.logging_addr = with_port(&cfg.logging_addr, p);
        cfg.logging_enabled = p != 0;
        cfg.logging_addr_explicit = true;
    }
}

/// Whether `up` and `exec` look for configuration files in the working directory.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum ConfigDiscovery {
    #[default]
    On,
    /// `--no-config-discovery`.
    Off,
}

/// How the configuration files were chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConfigOrigin {
    /// `--config` or `--firebase-json` named them.
    Flags,
    /// Neither flag: the working directory was searched (see `config_discovery`).
    Discovered(config_discovery::Discovery),
    /// `--no-config-discovery`.
    DiscoveryOff,
    /// Neither flag, and the working directory could not be read.
    NoWorkingDirectory,
}

/// When neither `--config` nor `--firebase-json` is given, fills the one the working directory
/// supplies: its `fireemu.toml` or `fireemu.json`, else the nearest `firebase.json` (see `config_discovery`).
fn discover_project_config(raw: &mut RawOptions) -> Result<ConfigOrigin, CliError> {
    if raw.config_path.is_some() || raw.firebase_json.is_some() {
        return Ok(ConfigOrigin::Flags);
    }
    if raw.config_discovery == ConfigDiscovery::Off {
        return Ok(ConfigOrigin::DiscoveryOff);
    }
    let Ok(cwd) = std::env::current_dir() else {
        return Ok(ConfigOrigin::NoWorkingDirectory);
    };
    let discovery = config_discovery::discover(
        &cwd,
        &config_discovery::current_trust(),
        config_discovery::stat,
        config_discovery::open,
    );
    match &discovery.found {
        config_discovery::Discovered::Canonical(path, text) => {
            raw.config_path = Some(path.clone());
            raw.discovered_text = Some((path.clone(), text.clone()));
        }
        config_discovery::Discovered::FirebaseJson(path, text) => {
            raw.firebase_json = Some(path.clone());
            raw.discovered_text = Some((path.clone(), text.clone()));
        }
        config_discovery::Discovered::Ambiguous => {
            return Err(CliError::refused("both fireemu.toml and fireemu.json exist; remove one or select a file with --config"));
        }
        config_discovery::Discovered::Nothing => {}
    }
    if let Some(skipped) = &discovery.skipped {
        // A refused candidate never fails the run, but it must not go unnoticed either.
        eprintln!(
            "{}",
            skipped_config_warning(skipped, "the built-in defaults apply")
        );
    }
    Ok(ConfigOrigin::Discovered(discovery))
}

/// The warning for a candidate the search refused to load, or a directory it did not search,
/// naming what happens instead and the remedies.
fn skipped_config_warning(skipped: &config_discovery::Skipped, instead: &str) -> String {
    format!(
        "warning: config discovery skipped {}: it {}, so it may have been put there by someone else; {instead}. Load a file explicitly with --config or --firebase-json, or pass --no-config-discovery to silence this warning",
        diagnostic_path(&skipped.path),
        diagnostic_text(&skipped.reason)
    )
}

/// The configuration document at `path`: from the text the search judged when `path` is the
/// file it found (so the check and the read see the same file), else read from disk.
fn config_document(raw: &RawOptions, path: &Path) -> Result<(serde_json::Value, bool), CliError> {
    match &raw.discovered_text {
        Some((found, text)) if found == path => {
            let text = text.as_ref().map_err(|e| {
                CliError::refused(format!("cannot read {}: {e}", diagnostic_path(path)))
            })?;
            parse_config_text(
                path,
                text,
                raw.config_path.as_deref() == Some(path)
                    && path
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("toml")),
            )
        }
        _ => read_config_file(
            path,
            raw.config_path.as_deref() == Some(path)
                && path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("toml")),
        ),
    }
}

/// The suffix of an error about a file the search found rather than one the user named.
const DISCOVERED_FILE_HINT: &str = "(this file was found by searching from the working directory, not named on the command line; pass --config or --firebase-json to choose the file, or --no-config-discovery to use none)";

/// Adds [`DISCOVERED_FILE_HINT`] to a failure while reading discovered configuration.
fn note_discovered(origin: &ConfigOrigin) -> impl Fn(CliError) -> CliError + '_ {
    move |mut error| {
        if matches!(origin, ConfigOrigin::Discovered(d) if d.found != config_discovery::Discovered::Nothing)
        {
            error.message = format!("{} {DISCOVERED_FILE_HINT}", error.message);
        }
        error
    }
}

/// How the loaded `firebase.json` was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirebaseJsonVia {
    /// `--firebase-json`, or found by the search.
    FirebaseJsonFlag,
    /// `--config` named a `firebase.json`.
    ConfigFlag,
    /// The canonical configuration's `firebaseJson` entry.
    Reference,
}

/// The files `load_project_config` read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ConfigSources {
    canonical: Option<PathBuf>,
    firebase: Option<(PathBuf, FirebaseJsonVia)>,
}

/// The start banner's account of which configuration files were loaded.
fn config_origin_line(origin: &ConfigOrigin, sources: &ConfigSources) -> String {
    use config_discovery::Discovered;
    const DEFAULTS: &str = "built-in defaults apply, so no Security Rules are loaded";
    let how = match origin {
        ConfigOrigin::Discovered(discovery) if discovery.found == Discovered::Nothing => {
            return match &discovery.skipped {
                Some(skipped) => format!(
                    "none loaded: {} was skipped because it {} (see the warning); {DEFAULTS}",
                    diagnostic_path(&skipped.path),
                    diagnostic_text(&skipped.reason)
                ),
                None => format!(
                    "none found (no fireemu.toml or fireemu.json in the working directory, no firebase.json in it or the parents the search may enter); {DEFAULTS}"
                ),
            }
        }
        ConfigOrigin::DiscoveryOff => return format!("none (--no-config-discovery); {DEFAULTS}"),
        ConfigOrigin::NoWorkingDirectory => {
            return format!("none (the working directory cannot be read); {DEFAULTS}")
        }
        ConfigOrigin::Discovered(discovery)
            if matches!(&discovery.found, Discovered::FirebaseJson(path, _) if path.is_absolute()) =>
        {
            "found in a parent of the working directory, as firebase-tools finds it"
        }
        ConfigOrigin::Discovered(_) => "found in the working directory",
        ConfigOrigin::Flags => "",
    };
    let mut parts = Vec::new();
    if let Some(path) = &sources.canonical {
        let how = if how.is_empty() { "--config" } else { how };
        parts.push(format!("{} ({how})", diagnostic_path(path)));
    }
    match &sources.firebase {
        Some((path, via)) => {
            let how = match via {
                FirebaseJsonVia::Reference => "its firebaseJson entry",
                FirebaseJsonVia::ConfigFlag if how.is_empty() => "--config",
                FirebaseJsonVia::FirebaseJsonFlag if how.is_empty() => "--firebase-json",
                FirebaseJsonVia::ConfigFlag | FirebaseJsonVia::FirebaseJsonFlag => how,
            };
            parts.push(format!("{} ({how})", diagnostic_path(path)));
        }
        None => {
            // A firebase.json next to (or above) a canonical configuration that does not
            // reference it is easy to mistake for a loaded one, for example after `init` in a
            // subdirectory of a Firebase project.
            if let Some(canonical) = &sources.canonical {
                if let Some(unloaded) = unreferenced_firebase_json(canonical) {
                    parts.push(unloaded);
                }
            }
        }
    }
    parts.join("; ")
}

/// The nearest `firebase.json` at or above a canonical configuration that does not reference
/// one, described for the banner.
fn unreferenced_firebase_json(canonical: &Path) -> Option<String> {
    let dir = std::path::absolute(project_dir(canonical)).ok()?;
    let (depth, found) = dir
        .ancestors()
        .map(|d| d.join(config_discovery::FIREBASE_FILE))
        .enumerate()
        .find(|(_, candidate)| candidate.is_file())?;
    Some(if depth == 0 {
        "firebase.json beside it is not loaded (the canonical configuration has no firebaseJson entry)"
            .to_owned()
    } else {
        format!(
            "{} in a parent directory is not loaded (the canonical configuration has no firebaseJson entry)",
            diagnostic_path(&found)
        )
    })
}

fn load_project_config(
    raw: &RawOptions,
    only: &Selection,
) -> Result<(RuntimeConfig, PathBuf, ConfigSources), CliError> {
    let mut sources = ConfigSources::default();
    // `--config` carries either the canonical configuration or a firebase.json.
    let (mut cfg, firebase_from_config) = match &raw.config_path {
        Some(path) => {
            let (json, canonical) = config_document(raw, path)?;
            if canonical {
                sources.canonical = Some(path.clone());
                let config = if raw.context == OptionContext::Inspect {
                    RuntimeConfig::inspect_json(&json)
                } else {
                    RuntimeConfig::from_json(&json)
                }
                .map_err(|error| {
                    CliError::refused(format!(
                        "{}: {}",
                        diagnostic_path(path),
                        diagnostic_text(&error.0)
                    ))
                })?;
                if raw.verbosity > Verbosity::Quiet {
                    for note in config::no_effect_notes(&json) {
                        eprintln!("note: {}: {note}", diagnostic_path(path));
                    }
                }
                let firebase = if raw.firebase_json.is_none() {
                    config::firebase_json_reference(&json)?
                        .map(|reference| project_dir(path).join(reference))
                        .map(|firebase_path| read_firebase_json(&firebase_path))
                        .transpose()?
                        .map(|firebase| (firebase, FirebaseJsonVia::Reference))
                } else {
                    None
                };
                (config, firebase)
            } else {
                (
                    RuntimeConfig::default(),
                    Some(((json, path.clone()), FirebaseJsonVia::ConfigFlag)),
                )
            }
        }
        None => (RuntimeConfig::default(), None),
    };
    // A firebase.json from `--firebase-json` wins over one that reached `--config`.
    let firebase = match &raw.firebase_json {
        Some(path) => Some((
            firebase_json_document(path, config_document(raw, path)?)?,
            FirebaseJsonVia::FirebaseJsonFlag,
        )),
        None => firebase_from_config,
    };
    let mut project_root = PathBuf::from(".");
    if let Some(((json, path), via)) = &firebase {
        sources.firebase = Some((path.clone(), *via));
        project_root = project_dir(path);
        let report = cfg.apply_firebase_json(json, &project_root, only)?;
        if raw.verbosity > Verbosity::Quiet {
            for notice in &report.notices {
                eprintln!("note: {}: {notice}", diagnostic_path(path));
            }
        }
    }
    Ok((cfg, project_root, sources))
}

fn parse_options(
    args: &[String],
    context: OptionContext,
) -> Result<(Options, Option<String>), CliError> {
    let mut raw = parse_raw_options(args, context)?;
    let positional_script = raw.positional_script.clone();
    let only = raw.only.clone().unwrap_or_default();
    let origin = discover_project_config(&mut raw)?;
    let (mut cfg, project_root, sources) =
        load_project_config(&raw, &only).map_err(note_discovered(&origin))?;
    let config_origin = config_origin_line(&origin, &sources);
    let rc = if matches!(origin, ConfigOrigin::Discovered(_)) {
        discovered_firebaserc(&project_root).map_err(note_discovered(&origin))?
    } else {
        read_firebaserc(&project_root)?
    };
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
    // firebase-tools resolves the rules targets only for a database it starts.
    if only.database && (cfg.database_enabled || only.explicit) {
        cfg.database_rules_resolved =
            cfg.database_rules_by_instance(rc.as_ref(), &cfg.auth_project)?;
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
    let primary_selected = only.firestore
        || only.auth
        || only.storage
        || only.functions
        || only.pubsub
        || only.database
        || only.appcheck;
    let configured_support_selected =
        (only.eventarc && cfg.eventarc_enabled) || (only.tasks && cfg.tasks_enabled);
    if only.explicit && !primary_selected && !configured_support_selected {
        return Err(CliError::refused(
            "No emulators to start: Eventarc and Cloud Tasks are support emulators and a standalone --only selection must name a configured emulators.eventarc or emulators.tasks entry"
                .to_owned(),
        ));
    }
    if raw.inspect_functions.is_some() || raw.inspect_functions_dynamic {
        apply_inspect_functions(&mut cfg, raw.inspect_functions)?;
    }
    // The UI listener is configured through its own module when a port was asked for or when
    // exec must apply its official opt-in default. Start otherwise keeps the best-effort
    // default, where a busy 4000 disables the UI instead of failing the run.
    if raw.ui_port == Some(AuxiliaryPort::Auto) {
        ui::set_auto_port();
    } else if cfg.ui_addr_explicit || context == OptionContext::Exec {
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
        // A missing directory that `--export-on-exit` writes is the first run of a persisted
        // directory: the daemon starts it with no data (`import_export::nothing_to_import`).
        let first_run = std::path::absolute(dir)
            .is_ok_and(|absolute| export_on_exit.as_deref() == Some(absolute.as_path()));
        if !dir.is_dir() && (!first_run || dir.exists()) {
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
            ready_file: raw.ready_file,
            owner_stdin: raw.owner_stdin,
            config_origin,
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
    // The directory is made absolute here, where the working directory is still the one the
    // user typed the flag in. A one-element relative name like `out` otherwise reaches the
    // publication stage with the empty path as its parent, and restricting the permissions of
    // "" fails with ENOENT at exit, after the command has already run: the export is lost and
    // the command's own exit status hides it. `emulators:export` absolutizes for this reason
    // too, and the official CLI resolves `--export-on-exit=out` against the working directory.
    let absolute = std::path::absolute(&dir)
        .map_err(|e| CliError::refused(format!("--export-on-exit {}: {e}", dir.display())))?;
    let resolved = std::fs::canonicalize(&absolute).unwrap_or_else(|_| absolute.clone());
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.starts_with(&resolved) {
            return Err(CliError::refused(format!(
                "--export-on-exit {}: that is the working directory or one of its parents, and an export replaces what the directory holds; choose a dedicated directory",
                dir.display()
            )));
        }
    }
    fireemu_export_publication::preflight(&absolute).map_err(CliError::refused)?;
    import_export::may_overwrite(&absolute).map_err(CliError::refused)?;
    Ok(Some(absolute))
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

/// The address a client on this host connects to for a listener bound to `addr`: the loopback
/// address of its family for an unspecified one (`0.0.0.0`, `::`), `addr` otherwise.
fn connectable(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => (Ipv4Addr::LOCALHOST, addr.port()).into(),
        IpAddr::V6(ip) if ip.is_unspecified() => (Ipv6Addr::LOCALHOST, addr.port()).into(),
        _ => addr,
    }
}

/// One warning per product listener that is reachable from other hosts: the emulators serve
/// without a credential, so a listener off loopback is worth a line at every start.
fn network_exposure_warnings(listeners: &[(&str, Option<std::net::SocketAddr>)]) -> Vec<String> {
    listeners
        .iter()
        .filter_map(|(name, addr)| addr.map(|addr| (name, addr)))
        .filter(|(_, addr)| !addr.ip().to_canonical().is_loopback())
        .map(|(name, addr)| {
            format!(
                "{name} listens on {addr}, reachable from other hosts without a credential (network.allowNonLoopbackHosts); the control API answers loopback peers only"
            )
        })
        .collect()
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
    /// Realtime Database (REST, WebSocket and long polling on one port).
    database: Option<std::net::SocketAddr>,
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
/// **with** one, `FIREBASE_DATABASE_EMULATOR_HOST` as a bare `host:port` when the Realtime
/// Database runs, and `FIREBASE_EMULATOR_HUB` as a bare `host:port`.
///
/// Like the official CLI, selected endpoints override inherited values; endpoints for other
/// emulators remain inherited so removing a routing variable cannot send a SDK to production.
/// fireemu additionally sets `GOOGLE_CLOUD_PROJECT` next to `GCLOUD_PROJECT`.
///
/// `STORAGE_EMULATOR_HOST` is the plain `http://host:port`, like the official CLI, except
/// while Storage App Check is `enforced` with `appCheck.storageServerRequests` set to
/// `capability`: then it also carries the per-run Admin Storage capability (see the comment at
/// the push).
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
        // The Admin Storage capability rides in the URL userinfo, the only channel the
        // unmodified Google client forwards to a custom endpoint, and only while Storage App
        // Check enforcement makes it necessary: `appCheck.storageServerRequests = "capability"`
        // under `enforced`. `@google-cloud/storage` 8.1 and later (`firebase-admin` 14.4 and
        // later) refuse a URL with embedded credentials, so every other run, `loopback`
        // included, gets the plain endpoint those versions can use.
        let endpoint = if only.app_check_mode(&cfg.app_check, config::AppCheckService::Storage)
            == fireemu_core_app_check::verify::BaselineMode::Enforced
            && cfg.app_check.storage_server_requests
                == fireemu_adapter_http::storage::StorageServerRequests::Capability
        {
            format!("http://fireemu:{storage_admin_capability}@{addr}")
        } else {
            format!("http://{addr}")
        };
        env.push(("STORAGE_EMULATOR_HOST".to_owned(), endpoint));
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
    if let Some(addr) = addrs.database {
        // A bare host:port, as `firebase emulators:exec` writes it and the SDKs read it.
        env.push((
            "FIREBASE_DATABASE_EMULATOR_HOST".to_owned(),
            addr.to_string(),
        ));
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

/// Observe the private owner pipe without retaining a Tokio blocking worker at shutdown.
async fn owner_input_closed(enabled: bool) {
    if !enabled {
        std::future::pending::<()>().await;
    }
    let (closed, receiver) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut input = std::io::stdin().lock();
        let mut bytes = [0; 512];
        while input.read(&mut bytes).is_ok_and(|count| count > 0) {}
        let _ = closed.send(());
    });
    let _ = receiver.await;
}

/// Package-private Windows command owner. Killing this supervisor closes its Job Object,
/// retiring the complete command tree even if the original command leader already exited.
#[cfg(windows)]
fn supervise_world_command(arguments: &[String]) -> ExitCode {
    let Some((program, args)) = arguments.split_first() else {
        return ExitCode::FAILURE;
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    runtime.block_on(async {
        let mut command = tokio::process::Command::new(program);
        command.args(args).stdin(std::process::Stdio::null());
        let mut wrapped = TokioCommandWrap::from(command);
        wrapped.wrap(JobObject).wrap(KillOnDrop);
        let Ok(mut child) = wrapped.spawn() else {
            return ExitCode::FAILURE;
        };
        let status = tokio::select! {
            status = child.inner_mut().wait() => status.ok(),
            () = owner_input_closed(true) => None,
        };
        let _ = child.start_kill();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            Box::into_pin(child.wait()),
        )
        .await;
        status
            .and_then(|value| value.code())
            .and_then(|value| u8::try_from(value).ok())
            .map_or(ExitCode::FAILURE, ExitCode::from)
    })
}

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

/// Wipes the default session's Pub/Sub project and recreates the resources the Functions
/// manifest owns.
///
/// Reprovisioning is not guaranteed to succeed. Topics are a daemon-wide budget that a
/// loopback gRPC client fills from any project, so the recreate can be refused with
/// `RESOURCE_EXHAUSTED` by state this session does not own. That refusal used to be an
/// `expect`, which panicked while both the publication gate and the Pub/Sub state lock were
/// held: both were poisoned and every later Pub/Sub request panicked on the poisoned lock, so
/// one reset took the service down for the life of the daemon. The reset is refused instead.
fn reset_function_pubsub_resources(
    pubsub: &Mutex<fireemu_core_pubsub::PubSubState>,
    project: &str,
    resources: &[functions::FunctionPubSubResource],
) -> Result<(), String> {
    let Ok(mut state) = pubsub.lock() else {
        return Err("the Pub/Sub state lock is poisoned".to_owned());
    };
    state.clear_project(project);
    functions::provision_function_pubsub_resources(&mut state, resources).map_err(|e| {
        format!("Functions Pub/Sub resources could not be reprovisioned after the reset: {e}")
    })
}

/// The process exit status fireemu reports for a child exit code.
///
/// A process exit status is one byte, but a child's reported code is not. Windows reports the
/// full 32-bit value that `ExitProcess` or a fatal NTSTATUS produced, and `std` hands it over
/// as a signed `i32`: `cmd /c exit -1` arrives as `-1`, an access violation as `-1073741819`
/// (0xC0000005), a Ctrl-C termination as `-1073741510` (0xC000013A). Truncating any of those
/// to a byte, or clamping them into `0..=255`, turns a crashed child into a success and lets a
/// CI job that trusts fireemu's exit code pass.
///
/// So only the codes that survive the byte intact are passed through. Every code outside
/// `0..=255` -- negative, or 256 and above -- becomes 1, the generic failure. Signal-terminated
/// children already arrive here as `128 + signal` from [`exit_code`] and pass through.
fn reportable_exit_code(code: i32) -> u8 {
    u8::try_from(code).unwrap_or(1)
}

fn load_rules(
    cfg: &RuntimeConfig,
    compilations: &mut RulesCompilationCache,
) -> Result<LoadedRules, String> {
    match &cfg.rules_file {
        Some(path) => {
            let source =
                std::fs::read_to_string(path).map_err(|e| format!("rules source {path}: {e}"))?;
            compilations
                .load(&source)
                .map_err(|e| format!("rules source {path} does not parse: {e}"))
        }
        None => Ok(LoadedRules::default()),
    }
}

struct LoadedStorageRules {
    registry: Arc<fireemu_adapter_http::storage::StorageRulesRegistry>,
    watched: Vec<(String, Arc<RulesetSlot>)>,
}

fn read_storage_rules(
    path: &str,
    compilations: &mut RulesCompilationCache,
) -> Result<LoadedRules, String> {
    let source =
        std::fs::read_to_string(path).map_err(|e| format!("storage rules source {path}: {e}"))?;
    compilations
        .load(&source)
        .map_err(|e| format!("storage rules source {path} does not parse: {e}"))
}

fn load_storage_rules(
    cfg: &RuntimeConfig,
    compilations: &mut RulesCompilationCache,
) -> Result<LoadedStorageRules, String> {
    let loaded = load_storage_rules_registry(cfg, compilations)?;
    loaded
        .registry
        .set_configured_buckets(cfg.storage_buckets.iter().cloned());
    loaded
        .registry
        .set_public_buckets(cfg.storage_public_buckets.iter().cloned());
    loaded
        .registry
        .set_default_buckets(cfg.storage_default_bucket);
    Ok(loaded)
}

fn load_storage_rules_registry(
    cfg: &RuntimeConfig,
    compilations: &mut RulesCompilationCache,
) -> Result<LoadedStorageRules, String> {
    if cfg.storage_rules_by_target.is_empty() {
        let loaded = match &cfg.storage_rules_file {
            Some(path) => read_storage_rules(path, compilations)?,
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
        let slot = Arc::new(RulesetSlot::new(read_storage_rules(path, compilations)?));
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

fn watched_file_changed(
    observed_stamp: Option<WatchedFileStamp>,
    observed_signature: Option<u64>,
    candidate_stamp: WatchedFileStamp,
    candidate_signature: u64,
) -> bool {
    observed_stamp != Some(candidate_stamp) || observed_signature != Some(candidate_signature)
}

async fn watched_file_off_thread(path: &str) -> Result<(WatchedFileStamp, u64, Vec<u8>), String> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || watched_file(&path))
        .await
        .map_err(|error| format!("watch worker failed: {error}"))?
}

#[cfg(test)]
fn rules_reload_scan_counts() -> &'static Mutex<std::collections::BTreeMap<String, u64>> {
    static SCANS: std::sync::OnceLock<Mutex<std::collections::BTreeMap<String, u64>>> =
        std::sync::OnceLock::new();
    SCANS.get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
}

#[cfg(test)]
fn note_rules_reload_scan(path: &str) {
    if let Ok(mut scans) = rules_reload_scan_counts().lock() {
        *scans.entry(path.to_owned()).or_default() += 1;
    }
}

#[cfg(test)]
fn rules_reload_scan_count(path: &str) -> u64 {
    rules_reload_scan_counts()
        .lock()
        .ok()
        .and_then(|scans| scans.get(path).copied())
        .unwrap_or_default()
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
    let initial_differs = initial
        .as_ref()
        .and_then(|(_, _, bytes)| std::str::from_utf8(bytes).ok())
        .is_some_and(|source| {
            rules
                .snapshot()
                .ok()
                .and_then(|snapshot| snapshot.source.clone())
                .as_deref()
                != Some(source)
        });
    let mut observed_stamp = initial
        .as_ref()
        .map(|(stamp, _, _)| *stamp)
        .filter(|_| !initial_differs);
    let mut observed_signature = initial
        .as_ref()
        .map(|(_, signature, _)| *signature)
        .filter(|_| !initial_differs);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
            let Some(rules) = weak.upgrade() else {
                return;
            };
            let (candidate_stamp, candidate_signature, _) =
                match watched_file_off_thread(&path).await {
                    Ok(candidate) => candidate,
                    Err(reason) => {
                        eprintln!("warning: {label} reload scan failed: {reason}");
                        continue;
                    }
                };
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let (stable_stamp, stable_signature, bytes) = match watched_file_off_thread(&path).await
            {
                Ok(candidate) => candidate,
                Err(error) => {
                    eprintln!(
                        "warning: {label} reload failed; keeping the last-known-good rules: {error}"
                    );
                    continue;
                }
            };
            if stable_stamp != candidate_stamp || stable_signature != candidate_signature {
                continue;
            }
            if !watched_file_changed(
                observed_stamp,
                observed_signature,
                stable_stamp,
                stable_signature,
            ) {
                continue;
            }
            #[cfg(test)]
            note_rules_reload_scan(&path);
            observed_stamp = Some(stable_stamp);
            if observed_signature == Some(stable_signature) {
                continue;
            }
            observed_signature = Some(stable_signature);
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

fn start_index_reload_supervisor(
    path: String,
    database: String,
    backend: &Arc<LocalBackend>,
    checks: control::IndexFileChecks,
) {
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
            let (candidate_stamp, candidate_signature, _) =
                match watched_file_off_thread(&path).await {
                    Ok(candidate) => candidate,
                    Err(reason) => {
                        eprintln!("warning: Firestore index reload scan failed: {reason}");
                        continue;
                    }
                };
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let (stable_stamp, stable_signature, bytes) = match watched_file_off_thread(&path).await
            {
                Ok(candidate) => candidate,
                Err(error) => {
                    eprintln!(
                        "warning: Firestore index reload failed; keeping the last-known-good indexes: {error}"
                    );
                    continue;
                }
            };
            if stable_stamp != candidate_stamp || stable_signature != candidate_signature {
                continue;
            }
            if !watched_file_changed(
                observed_stamp,
                observed_signature,
                stable_stamp,
                stable_signature,
            ) {
                continue;
            }
            let text = match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(error) => {
                    eprintln!(
                        "warning: Firestore index reload failed; keeping the last-known-good indexes: {error}"
                    );
                    continue;
                }
            };
            match control::parse_index_file(&path, &text, checks) {
                Ok((indexes, ttl_policies, notes)) => {
                    if backend.replace_database_indexes(&database, indexes) {
                        backend.replace_shared_ttl_catalog(&database, ttl_policies);
                        observed_stamp = Some(stable_stamp);
                        observed_signature = Some(stable_signature);
                        eprintln!("note: reloaded Firestore indexes for {database} from {path}");
                        for note in notes {
                            eprintln!("note: {note}");
                        }
                    } else {
                        eprintln!(
                            "warning: Firestore index reload failed; keeping the last-known-good indexes: index catalog lock poisoned"
                        );
                    }
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
    let checks = cfg.index_file_checks();
    for (database, files) in &cfg.firestore_databases {
        if let Some(path) = &files.indexes {
            start_index_reload_supervisor(path.clone(), database.clone(), backend, checks);
        }
    }
    if cfg.firestore_databases.is_empty() {
        if let Some(path) = &cfg.index_file {
            start_index_reload_supervisor(
                path.clone(),
                fireemu_core_types::ids::DatabaseId::DEFAULT.to_owned(),
                backend,
                checks,
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
    control_token: String,
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
    let state = Arc::new(fireemu_adapter_http::storage::StorageState {
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
        server_requests: cfg.app_check.storage_server_requests,
        token_acceptance: cfg.token_acceptance,
        allow_unsigned_id_tokens: cfg.auth_allow_unsigned_id_tokens,
        control_token: Some(control_token),
    });
    state
        .store
        .lock()
        .map_err(|_| "the Storage store lock is poisoned".to_owned())?
        .set_stored_bytes_limit(cfg.storage_max_stored_bytes);
    Ok(state)
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
    database: Option<tokio::net::TcpListener>,
    hub: Option<tokio::net::TcpListener>,
    /// The Logging emulator WebSocket, when its port could be bound. Best effort like the Hub
    /// and UI: it is not a `--only` service, so it is attempted on every run unless disabled.
    logging: Option<tokio::net::TcpListener>,
}

async fn bind_listener(addr: &str) -> Result<tokio::net::TcpListener, String> {
    tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|error| format!("bind {addr}: {error}"))
}

async fn bind_relocatable_listener(
    addr: &str,
    explicit: bool,
    service: &'static str,
) -> Result<tokio::net::TcpListener, String> {
    if explicit || addr.ends_with(":0") {
        return bind_listener(addr).await;
    }
    let (host, port) = addr
        .rsplit_once(':')
        .and_then(|(host, port)| port.parse::<u16>().ok().map(|port| (host, port)))
        .ok_or_else(|| format!("bind {addr}: invalid address"))?;
    for candidate in port..=u16::MAX {
        let candidate_addr = format!("{host}:{candidate}");
        match tokio::net::TcpListener::bind(&candidate_addr).await {
            Ok(listener) => {
                if candidate != port {
                    eprintln!(
                        "warning: {service} unable to start on port {port}, starting on {candidate} instead"
                    );
                }
                return Ok(listener);
            }
            Err(_) if candidate < u16::MAX => {}
            Err(error) => return Err(format!("bind {candidate_addr}: {error}")),
        }
    }
    Err(format!(
        "could not find an open {service} port in {port}-65535"
    ))
}

async fn bind_listeners(cfg: &RuntimeConfig, only: &Selection) -> Result<Listeners, String> {
    // An explicit Hub address wins over every port-zero listener. The default remains late
    // and best effort: a selected product configured on 4400 must win and disable discovery.
    let prebound_hub = if cfg.hub_addr_explicit {
        if cfg.hub_auto_port {
            Some(bind_listener(&cfg.hub_addr).await?)
        } else {
            hub::bind(&cfg.hub_addr, true).await?
        }
    } else {
        None
    };
    let firestore = if only.firestore {
        Some(bind_listener(&cfg.firestore_addr).await?)
    } else {
        None
    };
    let control = if only.auth {
        bind_listener(&cfg.http_addr).await?
    } else {
        // Loopback, ephemeral: the configured Auth port belongs to whoever wants it.
        bind_listener("127.0.0.1:0").await?
    };
    let storage = if only.storage {
        Some(bind_listener(&cfg.storage_addr).await?)
    } else {
        None
    };
    let functions = if only.functions && cfg.functions_source.is_some() {
        Some(bind_listener(&cfg.functions_addr).await?)
    } else {
        None
    };
    // The pinned Firebase CLI starts both support emulators whenever a Functions backend is
    // loaded, even if `--only` did not name them. Naming either one without Functions is an
    // accepted no-op and binds neither listener.
    let eventarc = if functions.is_some() {
        Some(
            bind_relocatable_listener(
                &cfg.eventarc_addr,
                cfg.eventarc_addr_explicit,
                "Eventarc emulator",
            )
            .await?,
        )
    } else {
        None
    };
    let tasks = if functions.is_some() {
        Some(
            bind_relocatable_listener(
                &cfg.tasks_addr,
                cfg.tasks_addr_explicit,
                "Cloud Tasks emulator",
            )
            .await?,
        )
    } else {
        None
    };
    // Like the official suite, Pub/Sub starts only when it was configured or explicitly asked
    // for, rather than binding port 8085 on every run.
    let pubsub = if only.pubsub && (cfg.pubsub_enabled || only.explicit) {
        Some(bind_listener(&cfg.pubsub_addr).await?)
    } else {
        None
    };
    // The Realtime Database follows the same rule as Pub/Sub: configured or asked for.
    let database = if only.database && (cfg.database_enabled || only.explicit) {
        Some(bind_listener(&cfg.database_addr).await?)
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
        database,
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
        ("database", addrs.database),
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

/// What the start banner says about dead-letter forwarding under the strict profile.
fn dead_letter_banner(cfg: &RuntimeConfig) -> String {
    match cfg.pubsub_dead_letter_authorization {
        config::DeadLetterAuthorization::Implicit => "forwarded without grants (pubsub.deadLetterAuthorization \"implicit\"); productionExact requires them".to_owned(),
        config::DeadLetterAuthorization::Iam => format!(
            "forwarded after roles/pubsub.subscriber on the source subscription and roles/pubsub.publisher on the dead-letter topic are granted to serviceAccount:service-{}@gcp-sa-pubsub.iam.gserviceaccount.com",
            pubsub_project_numbers(cfg)
                .get(&cfg.auth_project)
                .map_or("<project number>", String::as_str)
        ),
    }
}

/// The project numbers Pub/Sub derives its service agents from: the configured ones, and under
/// `pubsub.deadLetterAuthorization = "iam"` one for the default project when none is configured
/// (`daemon.authProjectNumbers`, else the number a local project gets elsewhere), so production's
/// grants can be written out by name.
fn pubsub_project_numbers(cfg: &RuntimeConfig) -> std::collections::BTreeMap<String, String> {
    let mut numbers = cfg.pubsub_project_numbers.clone();
    if cfg.pubsub_dead_letter_authorization == config::DeadLetterAuthorization::Iam
        && !numbers.contains_key(&cfg.auth_project)
    {
        let number = cfg
            .auth_project_numbers
            .get(&cfg.auth_project)
            .copied()
            .unwrap_or_else(|| {
                fireemu_adapter_functions::eventarc_channels::project_number(&cfg.auth_project)
            });
        numbers.insert(cfg.auth_project.clone(), number.to_string());
    }
    numbers
}

/// What a Realtime Database instance without rules allows, and why: `database.defaultAccess`
/// and where its value came from.
pub fn database_access(cfg: &RuntimeConfig) -> String {
    let source = cfg
        .development_defaults
        .iter()
        .find(|entry| entry["key"] == "database.defaultAccess")
        .and_then(|entry| entry["source"].as_str())
        .unwrap_or("default");
    match cfg.database_default_access {
        config::DatabaseDefaultAccess::Open => {
            format!("every request is allowed (database.defaultAccess = open, {source})")
        }
        config::DatabaseDefaultAccess::Locked => format!(
            "only the owner credential reads and writes (database.defaultAccess = locked, {source})"
        ),
    }
}

/// The rules files and their instances, then what the instances without rules allow.
fn database_rules_line(cfg: &RuntimeConfig) -> String {
    if cfg.database_rules_resolved.is_empty() {
        return format!("none in firebase.json, so {}", database_access(cfg));
    }
    let files: Vec<String> = cfg
        .database_rules_resolved
        .iter()
        .map(|(instance, file)| format!("{instance} <- {file}"))
        .collect();
    format!(
        "{}; another instance: {}",
        files.join(", "),
        database_access(cfg)
    )
}

/// The banner lines of the Realtime Database: where it listens, the rules files and their
/// instances, and what an instance without rules allows.
fn print_database_lines(cfg: &RuntimeConfig, addrs: &BoundAddrs) {
    match addrs.database {
        Some(a) => {
            println!("  database:         {a}   FIREBASE_DATABASE_EMULATOR_HOST={a}");
            println!("  database rules:   {}", database_rules_line(cfg));
        }
        None => println!(
            "  database:         not started (configure emulators.database / --database-port, or --only database)"
        ),
    }
}

#[allow(clippy::too_many_lines)]
fn print_banner(
    cfg: &RuntimeConfig,
    verb: &str,
    config_origin: &str,
    addrs: &BoundAddrs,
    functions_runtime: Option<&fireemu_adapter_functions::runtime::FunctionsRuntime>,
) {
    println!("fireemu {verb}");
    println!("  config:           {config_origin}");
    match addrs.firestore {
        Some(a) => println!("  firestore (gRPC + REST): {a}   FIRESTORE_EMULATOR_HOST={a}"),
        None => println!("  firestore:        not selected by --only (nothing is bound)"),
    }
    match addrs.auth {
        Some(a) => {
            println!("  auth (REST):      {a}   FIREBASE_AUTH_EMULATOR_HOST={a}");
            if let Some(note) = daemon::custom_token_signer_note(cfg) {
                println!("{note}");
            }
            if let Some(note) = daemon::idp_assertion_note(cfg) {
                println!("{note}");
            }
        }
        None => println!("  auth:             not selected by --only (nothing is bound)"),
    }
    match addrs.storage {
        Some(a) => {
            println!(
                "  storage (HTTP):   {a}   FIREBASE_STORAGE_EMULATOR_HOST={a}   STORAGE_EMULATOR_HOST=http://{a}"
            );
            // A run with no ruleset denies every end-user request, as production's default
            // rules do, except that the emulator profile gives a `demo-*` project the official
            // emulator's default open rules; say so, because the configuration that reaches it
            // is an omission. The banner names the default project's state: a bucket owned by
            // another registered project is decided per request by that project's name.
            if cfg.storage_rules_file.is_none() && cfg.storage_rules_by_target.is_empty() {
                if cfg.profile == config::CompatibilityProfile::Emulator
                    && cfg.auth_project.starts_with("demo-")
                {
                    println!(
                        "  storage rules:    none loaded, so the official emulator's open rules apply to this demo project and every request is allowed; set storage.rules in firebase.json to enforce rules"
                    );
                } else if cfg.profile == config::CompatibilityProfile::Strict {
                    println!(
                        "  storage rules:    none loaded, so every end-user request is refused with production's 400 \"bucket has not been set up\" answer; set storage.rules in firebase.json or fireemu.toml (the owner credential and the JSON API are unaffected)"
                    );
                } else {
                    println!(
                        "  storage rules:    none loaded, so every end-user request is denied with 403; set storage.rules in firebase.json or fireemu.toml (the owner credential and the JSON API are unaffected)"
                    );
                }
            }
        }
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
        Some(a) => {
            println!("  pubsub (gRPC):    {a}   PUBSUB_EMULATOR_HOST={a}");
            if cfg.profile == config::CompatibilityProfile::Strict {
                println!("  dead letters:     {}", dead_letter_banner(cfg));
            }
        }
        None => println!(
            "  pubsub:           not started (configure emulators.pubsub / --pubsub-port, or --only pubsub)"
        ),
    }
    print_database_lines(cfg, addrs);
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
            config::CompatibilityProfile::Emulator =>
                "reproduces the official emulators, including their documented limitations",
            config::CompatibilityProfile::Strict =>
                "behaves like production Firebase where the official emulators do not",
        }
    );
    println!("  productionExact: {}", cfg.production_exact);
    for setting in &cfg.development_defaults {
        println!(
            "    {}: {} ({})",
            setting["key"].as_str().unwrap_or_default(),
            setting["value"].as_str().unwrap_or_default(),
            setting["source"].as_str().unwrap_or_default()
        );
    }
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
    blocking: Option<Arc<dyn fireemu_adapter_http::identity_toolkit::AuthBlockingHook>>,
    auth_operation_gate: Arc<Mutex<()>>,
    /// Whether the Realtime Database is served, whose data no export carries yet.
    database_served: bool,
}

impl Exporter {
    fn endpoints(&self) -> import_export::Endpoints<'_> {
        import_export::Endpoints {
            backend: &self.backend,
            auth: &self.auth,
            storage: &self.storage,
            clock: &self.clock,
            project: &self.project,
            blocking: self.blocking.as_deref(),
            auth_operation_gate: Some(&self.auth_operation_gate),
        }
    }
}

impl hub::ExportRunner for Exporter {
    fn export(&self, path: &Path, initiated_by: &str) -> Result<Vec<String>, String> {
        let mut warnings = Vec::new();
        if self.database_served {
            let warning = format!(
                "Realtime Database data is not exported (an open gap): the export to {} leaves it out",
                path.display()
            );
            eprintln!("warning: {warning}");
            warnings.push(warning);
        }
        import_export::may_overwrite(path)?;
        import_export::export(path, self.products, &self.endpoints(), initiated_by)
            .map_err(|e| e.to_string())?;
        Ok(warnings)
    }
}

/// The stop signals, installed before the daemon advertises readiness.
///
/// Installing a handler is what replaces a signal's default disposition, and the default
/// disposition for SIGTERM terminates the process without running a single destructor.
/// Registering lazily inside the serving `select!` left a window that opened the moment the
/// readiness banner was printed: a SIGTERM arriving there killed the daemon outright, so the
/// Hub locator outlived the process that wrote it. The handlers therefore go up before the
/// suite is assembled; a signal that arrives before the `select!` first polls them is
/// buffered and delivered on that poll.
pub(crate) struct ShutdownSignals {
    /// SIGINT, which is also what Ctrl-C raises.
    pub(crate) interrupt: InterruptSignal,
    /// SIGTERM, so a killed daemon still stops its runner.
    pub(crate) terminate: TerminateSignal,
}

impl ShutdownSignals {
    /// Installs both handlers. Called from inside the runtime, before anything an operator
    /// or a test can observe as readiness. A handler that cannot be installed never
    /// resolves, which is what a platform without the signal already did.
    pub(crate) fn install() -> Self {
        Self {
            interrupt: InterruptSignal::install(),
            terminate: TerminateSignal::install(),
        }
    }
}

/// The installed SIGINT handler.
pub(crate) struct InterruptSignal {
    #[cfg(unix)]
    signal: Option<tokio::signal::unix::Signal>,
}

impl InterruptSignal {
    fn install() -> Self {
        Self {
            #[cfg(unix)]
            signal: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok(),
        }
    }

    /// Resolves on the first interrupt.
    pub(crate) async fn recv(&mut self) {
        #[cfg(unix)]
        {
            match &mut self.signal {
                Some(signal) => {
                    signal.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

/// The installed SIGTERM handler; never resolves on a platform without the signal.
pub(crate) struct TerminateSignal {
    #[cfg(unix)]
    signal: Option<tokio::signal::unix::Signal>,
}

impl TerminateSignal {
    fn install() -> Self {
        Self {
            #[cfg(unix)]
            signal: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok(),
        }
    }

    /// Resolves on the first termination request.
    pub(crate) async fn recv(&mut self) {
        #[cfg(unix)]
        {
            match &mut self.signal {
                Some(signal) => {
                    signal.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        }
        #[cfg(not(unix))]
        std::future::pending::<()>().await;
    }
}

/// A 128-bit secret from the operating system's entropy source; the daemon refuses to start
/// without one (these values authorize control and runner access).
fn random_secret() -> Result<String, String> {
    fireemu_adapter_support::entropy::hex_128()
        .map_err(|e| format!("cannot draw the control token: {e}"))
}

/// Installs the operating system CSPRNG as the Auth stores' credential entropy, so a daemon
/// run with a fixed seed still issues unpredictable action codes, verification sessions,
/// refresh tokens and TOTP secrets. The daemon refuses to start without one.
fn install_auth_credential_entropy() -> Result<(), String> {
    fireemu_adapter_support::entropy::fill(&mut [0_u8; 8])
        .map_err(|e| format!("cannot draw Auth credentials: {e}"))?;
    fireemu_core_auth::store::install_credential_entropy(|dest| {
        fireemu_adapter_support::entropy::fill(dest).is_ok()
    });
    Ok(())
}

#[cfg(test)]
mod credential_entropy_tests {
    use fireemu_core_auth::mfa::TotpPolicy;
    use fireemu_core_auth::store::{AuthStore, OobRequestType};
    use fireemu_core_types::determinism::SplitMix64;
    use fireemu_core_types::time::LogicalInstant;

    /// Two daemons with the same seed issue different action codes once the OS CSPRNG is
    /// installed, and the codes keep their shape.
    #[test]
    fn a_seeded_daemon_issues_unpredictable_action_codes() {
        super::install_auth_credential_entropy().unwrap();
        let code = || {
            AuthStore::new(
                "demo-app",
                SplitMix64::new(0x2A ^ 0xA0),
                TotpPolicy::default(),
            )
            .create_oob_code(
                OobRequestType::PasswordReset,
                "a@example.com",
                None,
                None,
                LogicalInstant::from_unix_seconds(1_788_004_860),
            )
            .unwrap()
        };
        let (first, second) = (code(), code());
        assert_ne!(first, second);
        for code in [first, second] {
            assert_eq!(code.len(), "oob-".len() + 16 + 4, "{code}");
            assert!(code.ends_with("0001"), "{code}");
        }
    }
}

/// An unpredictable 128-bit daemon-local incarnation from the operating system CSPRNG.
fn random_u128() -> Result<u128, String> {
    fireemu_adapter_support::entropy::u128_value()
        .map_err(|e| format!("cannot build a daemon incarnation: {e}"))
}

/// An unpredictable 128-bit project session epoch from the operating system CSPRNG (spec 7.2).
fn random_epoch() -> Result<fireemu_core_app_check::ProjectEpoch, String> {
    random_u128().map(fireemu_core_app_check::ProjectEpoch::new)
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
        open_debug_tokens: (cfg.app_check.debug_tokens == config::AppCheckDebugTokens::Any)
            .then(|| cfg.auth_project.clone()),
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

/// The Firestore Security Rules state of the default database, and the rules file of each named
/// database that has one.
fn print_rules_status(cfg: &RuntimeConfig, loaded: bool) {
    const HOW_TO_LOAD: &str =
        "set firestore.rules in firebase.json, rules.source in fireemu.toml, or PUT /v1/rules";
    match (cfg.rules_enforced, loaded) {
        (false, _) => {
            println!("  firestore rules:  disabled by config (every request is allowed)");
        }
        (true, false) if cfg.refuse_without_ruleset => println!(
            "  firestore rules:  none loaded, so every client request is refused with PERMISSION_DENIED, as production refuses it without a release; {HOW_TO_LOAD} (the owner credential and the Admin SDK are unaffected)"
        ),
        (true, false) => println!(
            "  firestore rules:  none loaded, so every request is allowed, as the official emulator allows it; {HOW_TO_LOAD} to enforce rules"
        ),
        (true, true) => println!(
            "  firestore rules:  enforced from {}",
            cfg.rules_file.as_deref().unwrap_or("config")
        ),
    }
    if cfg.rules_enforced {
        for (database, files) in &cfg.firestore_databases {
            if database == fireemu_core_types::ids::DatabaseId::DEFAULT {
                continue;
            }
            if let Some(path) = &files.rules {
                println!("  firestore rules [{database}]: enforced from {path}");
            }
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
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
    pubsub_handle: &fireemu_adapter_pubsub::PubSubHandle,
    pubsub_resources: &[functions::FunctionPubSubResource],
    realtime_database: &Arc<Mutex<fireemu_adapter_database::rest::Database>>,
    listen_expiry: Option<fireemu_adapter_grpc::rules::ListenExpiry>,
    missing_indexes_reported: bool,
) -> fireemu_adapter_http::control::ControlState {
    let _ = auth_store;
    // Snapshot parts: what the session owns (Firestore databases and their field
    // configuration, buckets, users, fault plan, text indexes) and, for the default session, the shared parts (clock, both
    // rulesets; a restore also resets the functions runtime).
    let mut snapshot_hooks: Vec<Arc<dyn fireemu_adapter_http::control::SnapshotHook>> = vec![
        Arc::new(snapshots::Firestore(backend.clone())),
        Arc::new(snapshots::FieldConfig(backend.clone())),
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
        snapshot_hooks.push(Arc::new(snapshots::Functions::new(
            runtime.clone(),
            pubsub_handle.publication_gate(),
        )));
    }
    if let Some(gate) = &app_check {
        snapshot_hooks.push(Arc::new(snapshots::AppCheck(gate.clone())));
    }
    // The default session's scope is wiped by the project hooks; the shared functions
    // runtime is reset afterwards.
    let mut reset_hooks: Vec<Arc<dyn Fn() -> Result<(), String> + Send + Sync>> = Vec::new();
    let pubsub_for_reset = pubsub.clone();
    let pubsub_handle_for_reset = pubsub_handle.clone();
    let functions_for_reset = functions.cloned();
    let pubsub_resources = pubsub_resources.to_vec();
    let pubsub_project = cfg.auth_project.clone();
    reset_hooks.push(Arc::new(move || {
        let _publication = pubsub_handle_for_reset.lock_publication()?;
        if let Some(runtime) = &functions_for_reset {
            runtime.reset();
        }
        reset_function_pubsub_resources(&pubsub_for_reset, &pubsub_project, &pubsub_resources)
    }));
    // Resource diagnostics, one hook per service (spec 15); collected one after another.
    let mut resource_hooks: Vec<Arc<dyn fireemu_adapter_http::control::ResourceHook>> = vec![
        Arc::new(resources::Firestore(backend.clone())),
        Arc::new(resources::Storage(storage.clone())),
        Arc::new(resources::Auth(registry.clone())),
        Arc::new(resources::PubSub(pubsub.clone())),
        Arc::new(resources::Process),
    ];
    if let Some(runtime) = functions {
        resource_hooks.push(Arc::new(resources::Functions(runtime.clone())));
    }
    fireemu_adapter_http::control::ControlState {
        clock: clock.clone(),
        require_demo_prefix: cfg.require_demo_prefix,
        edition: cfg.edition,
        capabilities: fireemu_adapter_http::control::CapabilityManifest::lazy({
            let profile = cfg.profile;
            let production_exact = cfg.production_exact;
            let development_defaults = cfg.development_defaults.clone();
            move || control::capabilities_manifest(profile, production_exact, &development_defaults)
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
        resource_hooks,
        project_hooks: Some(Arc::new(sessions::Projects {
            backend: backend.clone(),
            storage: storage.clone(),
            registry: registry.clone(),
            seed: cfg.seed,
            tenant_seeding: cfg
                .tenant_seeding()
                .expect("the tenants were validated when the configuration was read"),
            app_check: app_check.clone(),
            pubsub: pubsub.clone(),
            pubsub_handle: pubsub_handle.clone(),
            realtime_database: realtime_database.clone(),
        })),
        functions: functions.map(|r| {
            Arc::new(functions::Hook(r.clone()))
                as Arc<dyn fireemu_adapter_http::control::FunctionsHook>
        }),
        control_token,
        barrier: Some(backend.barrier()),
        app_check,
        // Exposed listeners can sit behind a forwarder that connects from loopback, so the peer
        // address alone does not prove a local caller: every control request needs the token.
        require_control_token: cfg.allow_non_loopback_hosts,
        firestore_listen_expiry: listen_expiry.map(|expiry| {
            Arc::new(move || expiry.expire()) as Arc<dyn Fn() -> usize + Send + Sync>
        }),
        firestore_missing_indexes: Some(Arc::new(control::MissingIndexReports {
            enabled: missing_indexes_reported,
        })),
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

    #[test]
    fn diagnostic_text_only_escapes_controls_and_format_characters() {
        assert_eq!(
            diagnostic_text("\"'\\e\u{301}\n\u{1b}\u{200b}\u{202e}\u{2066}").to_string(),
            "\"'\\e\u{301}\\n\\u{1b}\\u{200b}\\u{202e}\\u{2066}"
        );
    }

    #[test]
    fn toml_errors_without_a_span_have_no_position() {
        let text = format!("{} = 1", vec!["a"; 200].join("."));
        let error = parse_config_text(Path::new("deep.toml"), &text, true).unwrap_err();
        assert_eq!(error.message, "deep.toml: recursion limit");
    }

    proptest::proptest! {
        #[test]
        fn parse_config_text_never_panics_on_arbitrary_utf8(text in proptest::prelude::any::<String>()) {
            let _ = parse_config_text(Path::new("arbitrary.toml"), &text, true);
        }
    }

    /// The file discovery found is parsed from the text read on the handle it was judged by,
    /// never re-read; any other path is read from disk.
    #[test]
    fn a_discovered_file_is_parsed_from_the_judged_text() {
        let dir = scratch("judged-text");
        let found = dir.join("firebase.json");
        let other = dir.join("other.json");
        std::fs::write(&found, r#"{"hosting": {"public": "replaced"}}"#).unwrap();
        std::fs::write(&other, r#"{"hosting": {"public": "other"}}"#).unwrap();
        let raw = RawOptions {
            discovered_text: Some((
                found.clone(),
                Ok(r#"{"hosting": {"public": "judged"}}"#.to_owned()),
            )),
            ..RawOptions::default()
        };
        let (json, canonical) =
            config_document(&raw, &found).unwrap_or_else(|e| panic!("{}", e.message));
        assert!(!canonical);
        assert_eq!(json["hosting"]["public"], "judged");
        let (json, _) = config_document(&raw, &other).unwrap_or_else(|e| panic!("{}", e.message));
        assert_eq!(json["hosting"]["public"], "other");
        // A read failure on the judged handle is reported, not retried from disk.
        let raw = RawOptions {
            discovered_text: Some((
                found.clone(),
                Err("stream did not contain valid UTF-8".to_owned()),
            )),
            ..RawOptions::default()
        };
        let Err(error) = config_document(&raw, &found) else {
            panic!("a failed read on the judged handle must be reported");
        };
        assert!(
            error.message.contains("cannot read") && error.message.contains("UTF-8"),
            "{}",
            error.message
        );
    }
    use fireemu_adapter_grpc::gateway::Gateway;
    use fireemu_core_firestore::index::IndexValidationPolicy;
    use fireemu_core_firestore::index::{IndexSet, PlanningContext};
    use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};

    const RULES_ONE: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if true; } } }";
    const RULES_TWO: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow write: if false; } } }";
    const RULES_DENY_READ: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if false; } } }";
    const STORAGE_ALLOW: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read: if true; } } }";
    const STORAGE_DENY: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read: if false; } } }";
    const STORAGE_WRITE: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow write: if true; } } }";
    const INDEXES_ONE: &str = r#"{"indexes":[{"collectionGroup":"items","queryScope":"COLLECTION","fields":[{"fieldPath":"a","order":"ASCENDING"},{"fieldPath":"b","order":"DESCENDING"}]}],"fieldOverrides":[]}"#;
    const INDEXES_TWO: &str = r#"{"indexes":[{"collectionGroup":"other","queryScope":"COLLECTION","fields":[{"fieldPath":"c","order":"ASCENDING"},{"fieldPath":"d","order":"DESCENDING"}]}],"fieldOverrides":[]}"#;

    #[test]
    fn storage_startup_keeps_identical_targets_independent_and_reports_the_failing_path() {
        let dir = scratch("identical-storage-startup");
        let first_path = dir.join("first.rules").display().to_string();
        let second_path = dir.join("second.rules").display().to_string();
        std::fs::write(&first_path, STORAGE_DENY).unwrap();
        std::fs::write(&second_path, STORAGE_DENY).unwrap();
        let cfg = RuntimeConfig {
            storage_rules_by_target: std::collections::BTreeMap::from([
                ("first".to_owned(), first_path.clone()),
                ("second".to_owned(), second_path.clone()),
            ]),
            storage_buckets_by_target: std::collections::BTreeMap::from([
                ("first".to_owned(), vec!["first.test".to_owned()]),
                ("second".to_owned(), vec!["second.test".to_owned()]),
            ]),
            ..RuntimeConfig::default()
        };
        let loaded =
            load_storage_rules_registry(&cfg, &mut RulesCompilationCache::default()).unwrap();
        let first = &loaded.watched[0].1;
        let second = &loaded.watched[1].1;
        assert!(!Arc::ptr_eq(first, second));
        assert!(Arc::ptr_eq(
            first.snapshot().unwrap().ruleset.as_ref().unwrap(),
            second.snapshot().unwrap().ruleset.as_ref().unwrap(),
        ));
        assert_eq!(first.replace_source(STORAGE_ALLOW).unwrap(), 1);
        assert_eq!(
            second.snapshot().unwrap().source.as_deref(),
            Some(STORAGE_DENY)
        );
        assert_eq!(second.snapshot().unwrap().generation(), 0);

        std::fs::write(&second_path, "invalid rules").unwrap();
        let Err(error) = load_storage_rules_registry(&cfg, &mut RulesCompilationCache::default())
        else {
            panic!("invalid second target must fail startup");
        };
        assert_eq!(
            error,
            format!(
                "storage rules source {second_path} does not parse: {}",
                LoadedRules::from_source("invalid rules").unwrap_err()
            )
        );
        std::fs::remove_file(&second_path).unwrap();
        let Err(error) = load_storage_rules_registry(&cfg, &mut RulesCompilationCache::default())
        else {
            panic!("missing second target must fail startup");
        };
        assert!(error.starts_with(&format!("storage rules source {second_path}: ")));
    }

    /// A scratch directory removed when the test ends, also when an assertion fails first.
    struct Scratch(std::path::PathBuf);

    impl std::ops::Deref for Scratch {
        type Target = std::path::Path;

        fn deref(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl AsRef<std::path::Path> for Scratch {
        fn as_ref(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(name: &str) -> Scratch {
        let dir =
            std::env::temp_dir().join(format!("fireemu-reload-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn write_rules_generation(
        path: &std::path::Path,
        source: &str,
        modified: std::time::SystemTime,
    ) {
        std::fs::write(path, source).unwrap();
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
    }

    fn index_backend(indexes: &str) -> Arc<LocalBackend> {
        let gateway = Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::Production,
            },
            indexes: IndexSet::default(),
        };
        let backend = Arc::new(LocalBackend::new(
            gateway,
            Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH))),
            7,
        ));
        backend.replace_database_indexes(
            "staging",
            control::parse_indexes("indexes", indexes, control::IndexFileChecks::Deploy).unwrap(),
        );
        backend
    }

    fn write_index_generation(
        path: &std::path::Path,
        bytes: &[u8],
        modified: std::time::SystemTime,
    ) {
        std::fs::write(path, bytes).unwrap();
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
    }

    async fn wait_for_index_collection(backend: &Arc<LocalBackend>, collection: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                if backend
                    .indexes_for_database("staging")
                    .composites()
                    .first()
                    .is_some_and(|index| index.collection_group.as_str() == collection)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the valid index generation should reload");
    }

    #[test]
    fn rules_reload_checks_content_when_file_metadata_is_unchanged() {
        let stamp = WatchedFileStamp {
            len: 42,
            modified_nanos: 7,
        };

        assert!(watched_file_changed(Some(stamp), Some(1), stamp, 2));
        assert!(!watched_file_changed(Some(stamp), Some(1), stamp, 1));
    }

    #[test]
    fn config_without_schema_version_rejects_canonical_keys_on_every_input_path() {
        let dir = scratch("missing-schema-version");
        let source = dir.join("settings.json");
        let canonical = dir.join("fireemu.json");
        std::fs::write(
            &canonical,
            r#"{"schemaVersion":1,"firebaseJson":"settings.json"}"#,
        )
        .unwrap();
        let inputs = [
            RawOptions {
                config_path: Some(source.clone()),
                ..RawOptions::default()
            },
            RawOptions {
                firebase_json: Some(source.clone()),
                ..RawOptions::default()
            },
            RawOptions {
                config_path: Some(canonical),
                ..RawOptions::default()
            },
        ];
        let mut cases = vec![
            (
                serde_json::json!({"auth":{"logActionCodes":false}}),
                "auth.logActionCodes",
            ),
            (serde_json::json!({"auth":{"enabled":null}}), "auth.enabled"),
            (
                serde_json::json!({"auth":{"projectIssuer":null}}),
                "auth.projectIssuer",
            ),
            (
                serde_json::json!({"auth":{"idTokenSigning":null}}),
                "auth.idTokenSigning",
            ),
            (
                serde_json::json!({"auth":{"secretMaterialization":null}}),
                "auth.secretMaterialization",
            ),
            (
                serde_json::json!({"auth":{"forwardInboundCredentials":null}}),
                "auth.forwardInboundCredentials",
            ),
            (
                serde_json::json!({"auth":{"improvedEmailPrivacy":null}}),
                "auth.improvedEmailPrivacy",
            ),
            (
                serde_json::json!({"auth":{"totp":{"periodSeconds":30}}}),
                "auth.totp",
            ),
            (
                serde_json::json!({"auth":{"totp":{"bogusKey":1}}}),
                "auth.totp",
            ),
            (serde_json::json!({"auth":{"totp":null}}), "auth.totp"),
        ];
        for key in [
            "firebaseJson",
            "profile",
            "bind",
            "projects",
            "limits",
            "rules",
            "appCheck",
            "events",
            "eventarc",
            "scheduler",
            "trace",
            "daemon",
        ] {
            cases.push((serde_json::json!({key: null}), key));
        }
        for (json, key) in cases {
            std::fs::write(&source, json.to_string()).unwrap();
            for raw in &inputs {
                let err = load_project_config(raw, &Selection::default()).unwrap_err();
                assert_eq!(err.code, 1);
                let message = err.message;
                assert!(message.contains("settings.json"), "{message}");
                assert!(message.contains(key), "{message}");
                assert!(message.contains("add \"schemaVersion\": 1"), "{message}");
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn config_without_schema_version_preserves_firebase_sections_and_filenames() {
        let dir = scratch("firebase-schema-compatibility");
        // Format detection is based on content, even when the filename says fireemu.
        let source = dir.join("fireemu.json");
        let canonical = dir.join("canonical.json");
        std::fs::write(
            &canonical,
            r#"{"schemaVersion":1,"firebaseJson":"fireemu.json"}"#,
        )
        .unwrap();
        for providers in [
            serde_json::json!({"oidc":[{"name":"oidc.firebase-deploy","clientId":"deploy-client","issuer":"https://issuer.test"}]}),
            // firebase-tools 15.28.2 lib/deploy/auth/deploy.js reads these deployment fields.
            serde_json::json!({"anonymous":true,"emailPassword":true,"googleSignIn":{"oAuthBrandDisplayName":"Fixture","supportEmail":"support@example.test","authorizedRedirectUris":["https://fixture.test/__/auth/handler"]}}),
            serde_json::Value::Null,
            serde_json::json!("deployment-extension"),
        ] {
            std::fs::write(
                &source,
                serde_json::json!({
                    "$schema":"https://example.com/firebase.schema.json",
                    "emulators":{"auth":{"port":9199}},
                    "firestore":{"rules":"firestore.rules"},
                    "storage":{"rules":"storage.rules"},
                    "functions":{"source":"functions"},
                    "hosting":{"public":"dist"},
                    "auth":{"providers":providers},
                    "customMetadata":{"profile":"strict","auth":{"totp":{}}}
                })
                .to_string(),
            )
            .unwrap();
            for raw in [
                RawOptions {
                    config_path: Some(source.clone()),
                    ..RawOptions::default()
                },
                RawOptions {
                    firebase_json: Some(source.clone()),
                    ..RawOptions::default()
                },
                RawOptions {
                    config_path: Some(canonical.clone()),
                    ..RawOptions::default()
                },
            ] {
                let (cfg, _, _) = load_project_config(&raw, &Selection::default())
                    .unwrap_or_else(|e| panic!("{}", e.message));
                assert!(cfg.http_addr.ends_with(":9199"));
                assert_eq!(
                    cfg.auth_provider_seeds,
                    fireemu_core_auth::store::ProviderConfigSeeds::default()
                );
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn config_with_schema_version_still_uses_canonical_validation() {
        let dir = scratch("canonical-schema-validation");
        let source = dir.join("firebase.json");
        let raw = RawOptions {
            config_path: Some(source.clone()),
            ..RawOptions::default()
        };
        for version in [
            serde_json::json!(null),
            serde_json::json!(0),
            serde_json::json!("1"),
        ] {
            std::fs::write(
                &source,
                serde_json::json!({"schemaVersion":version,"profile":"strict"}).to_string(),
            )
            .unwrap();
            let err = load_project_config(&raw, &Selection::default()).unwrap_err();
            assert!(
                err.message.contains("schemaVersion must be 1"),
                "{}",
                err.message
            );
        }
        std::fs::write(
            &source,
            r#"{"schemaVersion":1,"auth":{"totp":{"bogusKey":1}}}"#,
        )
        .unwrap();
        let err = load_project_config(&raw, &Selection::default()).unwrap_err();
        assert!(
            err.message
                .contains("unknown config key auth.totp.bogusKey"),
            "{}",
            err.message
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unpinned_clock_start_preserves_subsecond_wall_time() {
        // A multiple of 100 ns: Windows keeps SystemTime in 100 ns ticks, so a finer instant
        // would already be truncated when the wall time is built, before the conversion runs.
        let wall_time = std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::new(1_800_000_000, 123_456_700))
            .unwrap();

        assert_eq!(
            logical_system_time(wall_time),
            LogicalInstant::from_nanos(1_800_000_000_123_456_700)
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

    proptest::proptest! {
        #[test]
        fn ui_port_selection_preserves_numeric_ports_and_last_flag_wins(port in proptest::prelude::any::<u16>()) {
            for context in [OptionContext::Start, OptionContext::Exec] {
                for (values, expected_port, enabled) in [
                    (vec!["auto".to_owned()], 0, true),
                    (vec!["auto".to_owned(), port.to_string()], port, port != 0),
                    (vec![port.to_string(), "auto".to_owned()], 0, true),
                    (vec!["auto".to_owned(), "0".to_owned()], 0, false),
                ] {
                    let args: Vec<String> = values.into_iter().flat_map(|value| ["--ui-port".to_owned(), value]).collect();
                    let raw = parse_raw_options(&args, context).unwrap_or_else(|error| panic!("{}", error.message));
                    let mut cfg = RuntimeConfig::default();
                    apply_port_overrides(&mut cfg, &raw);
                    proptest::prop_assert_eq!(cfg.ui_enabled, enabled);
                    proptest::prop_assert!(cfg.ui_addr_explicit);
                    proptest::prop_assert_eq!(cfg.ui_addr.rsplit_once(':').unwrap().1, expected_port.to_string());
                }
            }
        }
    }

    proptest::proptest! {
        #[test]
        fn hub_port_selection_preserves_numeric_zero_and_last_flag_wins(port in proptest::prelude::any::<u16>()) {
            for context in [OptionContext::Start, OptionContext::Exec, OptionContext::Inspect] {
                for (values, expected_port, automatic) in [
                    (vec!["auto".to_owned()], 0, true),
                    (vec!["auto".to_owned(), port.to_string()], port, false),
                    (vec![port.to_string(), "auto".to_owned()], 0, true),
                    (vec!["auto".to_owned(), "0".to_owned()], 0, false),
                ] {
                    let args: Vec<String> = values.into_iter().flat_map(|value| ["--hub-port".to_owned(), value]).collect();
                    let raw = parse_raw_options(&args, context).unwrap_or_else(|error| panic!("{}", error.message));
                    let mut cfg = RuntimeConfig::default();
                    apply_port_overrides(&mut cfg, &raw);
                    proptest::prop_assert_eq!(cfg.hub_auto_port, automatic);
                    proptest::prop_assert!(cfg.hub_addr_explicit);
                    proptest::prop_assert_eq!(cfg.hub_addr.rsplit_once(':').unwrap().1, expected_port.to_string());
                }
            }
        }
    }

    #[test]
    fn support_service_cli_ports_override_configured_addresses() {
        let mut cfg = RuntimeConfig {
            eventarc_addr: "localhost:9300".to_owned(),
            tasks_addr: "localhost:9500".to_owned(),
            ..RuntimeConfig::default()
        };
        let raw = RawOptions {
            eventarc_port: Some(9301),
            tasks_port: Some(9501),
            ..RawOptions::default()
        };

        apply_port_overrides(&mut cfg, &raw);

        assert_eq!(cfg.eventarc_addr, "localhost:9301");
        assert!(cfg.eventarc_enabled);
        assert!(cfg.eventarc_addr_explicit);
        assert_eq!(cfg.tasks_addr, "localhost:9501");
        assert!(cfg.tasks_enabled);
        assert!(cfg.tasks_addr_explicit);
    }

    #[tokio::test]
    async fn a_selected_product_wins_a_port_shared_with_the_default_hub() {
        let only = Selection {
            firestore: true,
            auth: false,
            storage: false,
            functions: false,
            eventarc: false,
            tasks: false,
            pubsub: false,
            database: false,
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
    async fn rules_reload_reconciles_file_changed_before_supervisor_start() {
        let dir = scratch("rules-before-supervisor");
        let path = dir.join("firestore.rules");
        std::fs::write(&path, RULES_TWO).unwrap();
        let rules = Arc::new(RulesetSlot::new(
            LoadedRules::from_source(RULES_ONE).unwrap(),
        ));
        let barrier = Arc::new(fireemu_core_session::barrier::AdmissionBarrier::new());
        start_rules_reload_supervisor(
            path.to_string_lossy().into_owned(),
            "Firestore rules",
            &rules,
            &barrier,
        );

        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                if rules.snapshot().unwrap().source.as_deref() == Some(RULES_TWO) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the file present before supervisor start should reconcile");
        drop(rules);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn canonical_rules_reload_when_firebase_declares_only_indexes() {
        let dir = scratch("canonical_rules_reload_when_firebase_declares_only_indexes");
        let path = dir.join("firestore.rules");
        std::fs::write(&path, RULES_ONE).unwrap();
        let mut cfg = RuntimeConfig::from_json(&serde_json::json!({
            "schemaVersion": 1, "rules": {"source": path}
        }))
        .unwrap();
        cfg.apply_firebase_json(
            &serde_json::json!({"firestore": {"indexes": "unused.indexes.json"}}),
            &dir,
            &Selection::default(),
        )
        .unwrap();
        let rules = Arc::new(RulesetSlot::new(
            LoadedRules::from_source(RULES_ONE).unwrap(),
        ));
        let backend = index_backend(INDEXES_ONE);
        let barrier = backend.barrier();
        let storage = LoadedStorageRules {
            registry: Arc::new(
                fireemu_adapter_http::storage::StorageRulesRegistry::per_bucket(
                    std::collections::BTreeMap::new(),
                ),
            ),
            watched: Vec::new(),
        };
        start_firestore_config_reload_supervisors(
            &cfg,
            &backend,
            &rules,
            &std::collections::BTreeMap::new(),
            &storage,
            &barrier,
        );
        std::fs::write(&path, RULES_TWO).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                if rules.snapshot().unwrap().source.as_deref() == Some(RULES_TWO) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the retained canonical file should reload after an edit");
    }

    #[tokio::test]
    async fn canonical_indexes_reload_when_firebase_declares_only_rules() {
        let dir = scratch("canonical_indexes_reload_when_firebase_declares_only_rules");
        let path = dir.join("firestore.indexes.json");
        std::fs::write(&path, INDEXES_ONE).unwrap();
        let mut cfg = RuntimeConfig::from_json(&serde_json::json!({
            "schemaVersion": 1, "firestore": {"indexFile": path}
        }))
        .unwrap();
        cfg.apply_firebase_json(
            &serde_json::json!({"firestore": {"rules": "unused.rules"}}),
            &dir,
            &Selection::default(),
        )
        .unwrap();
        let rules = Arc::new(RulesetSlot::new(
            LoadedRules::from_source(RULES_ONE).unwrap(),
        ));
        let backend = index_backend(INDEXES_ONE);
        let barrier = backend.barrier();
        let storage = LoadedStorageRules {
            registry: Arc::new(
                fireemu_adapter_http::storage::StorageRulesRegistry::per_bucket(
                    std::collections::BTreeMap::new(),
                ),
            ),
            watched: Vec::new(),
        };
        start_firestore_config_reload_supervisors(
            &cfg,
            &backend,
            &rules,
            &std::collections::BTreeMap::new(),
            &storage,
            &barrier,
        );
        std::fs::write(&path, INDEXES_TWO).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                if backend
                    .indexes_for_database("(default)")
                    .composites()
                    .first()
                    .is_some_and(|index| index.collection_group.as_str() == "other")
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the retained canonical file should reload after an edit");
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
                        policy: IndexValidationPolicy::Production,
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

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn named_firestore_rules_reload_isolated_from_default_database() {
        let dir = scratch("named-rules-isolation");
        let default_path = dir.join("default.rules");
        let named_path = dir.join("named.rules");
        std::fs::write(&default_path, RULES_ONE).unwrap();
        std::fs::write(&named_path, RULES_ONE).unwrap();

        let gateway = Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::Production,
            },
            indexes: IndexSet::default(),
        };
        let backend = Arc::new(LocalBackend::new(
            gateway,
            Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH))),
            7,
        ));
        let default_rules = Arc::new(RulesetSlot::new(
            LoadedRules::from_source(RULES_ONE).unwrap(),
        ));
        let named_rules = Arc::new(RulesetSlot::new(
            LoadedRules::from_source(RULES_ONE).unwrap(),
        ));
        let database_rules =
            std::collections::BTreeMap::from([("staging".to_owned(), named_rules.clone())]);
        let cfg = RuntimeConfig {
            firestore_databases: std::collections::BTreeMap::from([
                (
                    fireemu_core_types::ids::DatabaseId::DEFAULT.to_owned(),
                    crate::config::FirestoreDatabaseFiles {
                        rules: Some(default_path.display().to_string()),
                        indexes: None,
                    },
                ),
                (
                    "staging".to_owned(),
                    crate::config::FirestoreDatabaseFiles {
                        rules: Some(named_path.display().to_string()),
                        indexes: None,
                    },
                ),
            ]),
            ..RuntimeConfig::default()
        };
        let loaded_storage = LoadedStorageRules {
            registry: Arc::new(fireemu_adapter_http::storage::StorageRulesRegistry::global(
                Arc::new(RulesetSlot::default()),
            )),
            watched: Vec::new(),
        };
        let barrier = Arc::new(fireemu_core_session::barrier::AdmissionBarrier::new());
        start_firestore_config_reload_supervisors(
            &cfg,
            &backend,
            &default_rules,
            &database_rules,
            &loaded_storage,
            &barrier,
        );
        let auth = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            fireemu_core_types::determinism::SplitMix64::new(7),
            fireemu_core_auth::mfa::TotpPolicy::default(),
        )));
        let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
        let enforcer =
            fireemu_adapter_grpc::rules::RulesEnforcer::new(default_rules.clone(), auth, clock)
                .with_database_rules(database_rules);
        let project = fireemu_core_types::ids::ProjectId::try_new("demo-app").unwrap();
        let authorize = |database: &str| {
            let database_id = fireemu_core_types::ids::DatabaseId::try_new(database).unwrap();
            let path = fireemu_core_firestore::path::DocumentPath::parse(
                &project,
                &database_id,
                "items/a",
            )
            .unwrap();
            let reader = fireemu_adapter_grpc::rules::LatestReader {
                backend: backend.clone(),
                parent: fireemu_adapter_grpc::decode::Parent {
                    project: project.clone(),
                    database: database_id,
                    document: None,
                },
            };
            enforcer
                .authorize_get(
                    &fireemu_adapter_grpc::rules::Principal::Anonymous,
                    &path,
                    None,
                    &reader,
                )
                .is_ok()
        };

        assert!(authorize("(default)"));
        assert!(authorize("staging"));
        std::fs::write(&named_path, RULES_DENY_READ).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                if named_rules.snapshot().unwrap().source.as_deref() == Some(RULES_DENY_READ) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("named rules should reload");
        assert!(authorize("(default)"));
        assert!(!authorize("staging"));

        let deny_generation = named_rules.snapshot().unwrap().generation();
        let deny_mtime = std::fs::metadata(&named_path).unwrap().modified().unwrap();
        let named_path_string = named_path.display().to_string();
        let scans_before_malformed = rules_reload_scan_count(&named_path_string);
        std::fs::write(&named_path, "malformed rules").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&named_path)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(deny_mtime + std::time::Duration::from_secs(1)),
            )
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                if rules_reload_scan_count(&named_path_string) > scans_before_malformed {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the malformed named generation should be scanned");
        assert!(authorize("(default)"));
        assert!(!authorize("staging"));

        write_rules_generation(&named_path, RULES_DENY_READ, deny_mtime);
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                if named_rules.snapshot().unwrap().generation() > deny_generation {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the malformed named generation should be observed and retained");
        assert!(!authorize("staging"));

        std::fs::write(&named_path, RULES_ONE).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                if named_rules.snapshot().unwrap().source.as_deref() == Some(RULES_ONE) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("named rules should recover");
        assert!(authorize("(default)"));
        assert!(authorize("staging"));
        drop(enforcer);
        drop(default_rules);
        drop(named_rules);
        drop(backend);
        let _ = std::fs::remove_dir_all(dir);
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
    async fn index_reload_retries_equal_length_malformed_json_and_recovers() {
        assert_eq!(INDEXES_ONE.len(), INDEXES_TWO.len());
        let dir = scratch("indexes-equal-length-malformed-json");
        let path = dir.join("firestore.indexes.json");
        std::fs::write(&path, INDEXES_ONE).unwrap();
        let original_mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        let backend = index_backend(INDEXES_ONE);
        start_index_reload_supervisor(
            path.display().to_string(),
            "staging".to_owned(),
            &backend,
            control::IndexFileChecks::Deploy,
        );

        let mut malformed = INDEXES_TWO.as_bytes().to_vec();
        let array_start = malformed.iter().position(|byte| *byte == b'[').unwrap();
        malformed[array_start] = b'{';
        write_index_generation(&path, &malformed, original_mtime);
        tokio::time::sleep(std::time::Duration::from_millis(1_300)).await;
        assert_eq!(
            backend.indexes_for_database("staging").composites()[0]
                .collection_group
                .as_str(),
            "items"
        );

        write_index_generation(&path, INDEXES_TWO.as_bytes(), original_mtime);
        wait_for_index_collection(&backend, "other").await;
        drop(backend);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn index_reload_retries_equal_length_invalid_utf8_and_recovers() {
        assert_eq!(INDEXES_ONE.len(), INDEXES_TWO.len());
        let dir = scratch("indexes-equal-length-invalid-utf8");
        let path = dir.join("firestore.indexes.json");
        std::fs::write(&path, INDEXES_ONE).unwrap();
        let original_mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        let backend = index_backend(INDEXES_ONE);
        start_index_reload_supervisor(
            path.display().to_string(),
            "staging".to_owned(),
            &backend,
            control::IndexFileChecks::Deploy,
        );

        let mut invalid_utf8 = INDEXES_TWO.as_bytes().to_vec();
        invalid_utf8[0] = 0xff;
        write_index_generation(&path, &invalid_utf8, original_mtime);
        tokio::time::sleep(std::time::Duration::from_millis(1_300)).await;
        assert_eq!(
            backend.indexes_for_database("staging").composites()[0]
                .collection_group
                .as_str(),
            "items"
        );

        write_index_generation(&path, INDEXES_TWO.as_bytes(), original_mtime);
        wait_for_index_collection(&backend, "other").await;
        drop(backend);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A generation `firebase deploy` would refuse (a single-field composite index) is not loaded
    /// under the strict checks: the previous indexes stay in force and a later valid generation
    /// still reloads. The emulator profile's checks load it.
    #[tokio::test]
    async fn index_reload_keeps_the_previous_indexes_when_deploy_would_refuse_the_file() {
        const SINGLE_FIELD: &str = r#"{"indexes":[{"collectionGroup":"single","queryScope":"COLLECTION","fields":[{"fieldPath":"a","order":"ASCENDING"}]}],"fieldOverrides":[]}"#;
        for (checks, reloaded) in [
            (control::IndexFileChecks::Deploy, false),
            (control::IndexFileChecks::Emulator, true),
        ] {
            let dir = scratch(if reloaded {
                "indexes-refused-lenient"
            } else {
                "indexes-refused-strict"
            });
            let path = dir.join("firestore.indexes.json");
            std::fs::write(&path, INDEXES_ONE).unwrap();
            let backend = index_backend(INDEXES_ONE);
            start_index_reload_supervisor(
                path.display().to_string(),
                "staging".to_owned(),
                &backend,
                checks,
            );
            std::fs::write(&path, SINGLE_FIELD).unwrap();
            if reloaded {
                wait_for_index_collection(&backend, "single").await;
            } else {
                tokio::time::sleep(std::time::Duration::from_millis(1_800)).await;
                assert_eq!(
                    backend.indexes_for_database("staging").composites()[0]
                        .collection_group
                        .as_str(),
                    "items"
                );
                std::fs::write(&path, INDEXES_TWO).unwrap();
                wait_for_index_collection(&backend, "other").await;
            }
            drop(backend);
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[tokio::test]
    async fn index_reload_recovers_from_malformed_json_with_changed_metadata() {
        assert_eq!(INDEXES_ONE.len(), INDEXES_TWO.len());
        let dir = scratch("indexes-malformed-json");
        let path = dir.join("firestore.indexes.json");
        std::fs::write(&path, INDEXES_ONE).unwrap();
        let backend = index_backend(INDEXES_ONE);
        start_index_reload_supervisor(
            path.display().to_string(),
            "staging".to_owned(),
            &backend,
            control::IndexFileChecks::Deploy,
        );

        let mut malformed = INDEXES_TWO.as_bytes().to_vec();
        let array_start = malformed.iter().position(|byte| *byte == b'[').unwrap();
        malformed[array_start] = b'{';
        std::fs::write(&path, malformed).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1_300)).await;
        assert_eq!(
            backend.indexes_for_database("staging").composites()[0]
                .collection_group
                .as_str(),
            "items"
        );

        std::fs::write(&path, INDEXES_TWO).unwrap();
        wait_for_index_collection(&backend, "other").await;
        drop(backend);
        let _ = std::fs::remove_dir_all(dir);
    }

    async fn wait_for_ttl(backend: &Arc<LocalBackend>, collection: &str, present: bool) {
        let collection = fireemu_core_types::ids::CollectionId::try_new(collection).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                if backend
                    .ttl_policy("demo-app", "staging", &collection)
                    .is_some()
                    == present
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the index generation should reload its TTL policies");
    }

    #[tokio::test]
    async fn index_reload_follows_the_declared_ttl_policies_and_keeps_the_last_good_ones() {
        let dir = scratch("indexes-ttl");
        let path = dir.join("firestore.indexes.json");
        let declared = |ttl: &str| {
            format!(
                r#"{{"indexes":[],"fieldOverrides":[{{"collectionGroup":"sessions","fieldPath":"expireAt","ttl":{ttl},"indexes":[]}}]}}"#
            )
        };
        std::fs::write(&path, declared("false")).unwrap();
        let backend = index_backend(&declared("false"));
        start_index_reload_supervisor(
            path.display().to_string(),
            "staging".to_owned(),
            &backend,
            control::IndexFileChecks::Deploy,
        );
        wait_for_ttl(&backend, "sessions", false).await;

        std::fs::write(&path, declared("true")).unwrap();
        wait_for_ttl(&backend, "sessions", true).await;

        // A generation that names two TTL fields of one collection group is refused as a
        // whole, and the last good policies stay in force.
        std::fs::write(
            &path,
            r#"{"indexes":[],"fieldOverrides":[{"collectionGroup":"sessions","fieldPath":"a","ttl":true,"indexes":[]},{"collectionGroup":"sessions","fieldPath":"b","ttl":true,"indexes":[]}]}"#,
        )
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1_300)).await;
        let sessions = fireemu_core_types::ids::CollectionId::try_new("sessions").unwrap();
        assert_eq!(
            backend
                .ttl_policy("demo-app", "staging", &sessions)
                .unwrap()
                .field
                .canonical(),
            "expireAt"
        );

        // Removing the declaration removes the policy for a project that never patched.
        std::fs::write(&path, declared("false")).unwrap();
        wait_for_ttl(&backend, "sessions", false).await;
        drop(backend);
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
                policy: IndexValidationPolicy::Production,
            },
            indexes: IndexSet::default(),
        };
        let backend = Arc::new(LocalBackend::new(
            gateway,
            Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH))),
            7,
        ));
        start_index_reload_supervisor(
            path.display().to_string(),
            "staging".to_owned(),
            &backend,
            control::IndexFileChecks::Deploy,
        );
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

#[cfg(test)]
mod exit_code_tests {
    use super::reportable_exit_code;

    #[test]
    fn codes_that_fit_a_byte_are_reported_unchanged() {
        assert_eq!(reportable_exit_code(0), 0);
        assert_eq!(reportable_exit_code(1), 1);
        assert_eq!(reportable_exit_code(23), 23);
        assert_eq!(reportable_exit_code(255), 255);
    }

    #[test]
    fn signal_terminations_keep_their_unix_spelling() {
        // `exit_code` maps a signal to 128 + signal; SIGKILL is 137, SIGTERM 143, SIGSEGV 139.
        for code in [128 + 9, 128 + 15, 128 + 11] {
            assert_eq!(reportable_exit_code(code), u8::try_from(code).unwrap());
        }
    }

    #[test]
    fn windows_negative_status_codes_never_report_success() {
        // `cmd /c exit -1`, STATUS_ACCESS_VIOLATION, STATUS_CONTROL_C_EXIT, and the extreme.
        for code in [-1, -1_073_741_819, -1_073_741_510, i32::MIN] {
            assert_eq!(
                reportable_exit_code(code),
                1,
                "a negative child status must not be reported as success"
            );
        }
    }

    #[test]
    fn codes_above_a_byte_never_report_success_or_a_truncated_value() {
        // 256 and 512 truncate to 0 under a cast; 300 truncates to 44.
        for code in [256, 300, 512, 0x0100_0000, i32::MAX] {
            assert_eq!(reportable_exit_code(code), 1);
        }
    }
}

#[cfg(test)]
mod reset_pubsub_tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use fireemu_core_pubsub::{PubSubState, TopicName};

    use super::{functions, reset_function_pubsub_resources};

    fn manifest_resources(project: &str) -> Vec<functions::FunctionPubSubResource> {
        let manifest = fireemu_adapter_functions::manifest_json::parse_manifest(
            &serde_json::json!({"functions": [
                {"name": "worker", "trigger": {"type": "pubsub", "topic": "shared-jobs"}}
            ]}),
        )
        .expect("the manifest parses");
        functions::function_pubsub_resources(
            project,
            &manifest,
            fireemu_adapter_functions::events::SubscriptionNaming::default(),
            crate::config::CompatibilityProfile::Emulator,
        )
        .expect("the resources resolve")
    }

    /// RSTPS-2: topics are a daemon-wide budget that any project can fill, so recreating the
    /// Functions resources after a reset can be refused by state this session does not own.
    /// The refusal is reported; it must not panic while the Pub/Sub state lock is held,
    /// because that poisons the lock and every later Pub/Sub request panics on it in turn.
    #[test]
    fn a_refused_reprovision_is_reported_and_leaves_the_lock_usable() {
        let resources = manifest_resources("demo-app");
        let pubsub = Mutex::new(PubSubState::new(11));
        {
            let mut state = pubsub.lock().expect("the fresh lock is usable");
            // Another project fills the daemon-wide topic budget. Wiping `demo-app` frees
            // nothing, so the recreate below has nowhere to go.
            for index in 0..fireemu_core_pubsub::state::MAX_TOPICS {
                let name = TopicName::new("demo-other", format!("filler-{index}"))
                    .expect("the topic name is valid");
                state
                    .create_topic(name, BTreeMap::new())
                    .expect("the budget admits this topic");
            }
        }

        let error = reset_function_pubsub_resources(&pubsub, "demo-app", &resources)
            .expect_err("a reprovision with no room must be refused");

        assert!(error.contains("reprovisioned"), "{error}");
        assert!(error.contains("shared-jobs"), "{error}");
        // The lock is still usable, which a panic through the guard would have prevented.
        let mut state = pubsub
            .lock()
            .expect("the refusal must not poison the Pub/Sub state lock");
        assert!(state.list_topics("demo-app").is_empty());
        state.clear_project("demo-other");
        drop(state);

        // With the budget free, the same reset succeeds and the manifest's resources are back.
        reset_function_pubsub_resources(&pubsub, "demo-app", &resources)
            .expect("the reset succeeds once there is room");
        let state = pubsub.lock().expect("the lock is still usable");
        assert_eq!(state.list_topics("demo-app").len(), 1);
        assert_eq!(state.list_subscriptions("demo-app").len(), 1);
    }
}

#[cfg(test)]
mod loopback_peer_tests {
    use std::net::{SocketAddr, TcpListener, UdpSocket};

    use super::{post_json, refuse_non_loopback_peer};

    /// LOOPPEER-1: the origin rule accepts the name `localhost`, and a name is resolved by the
    /// host, which can be told to resolve it elsewhere. What the connection reached is what
    /// decides whether the control capability is written to it.
    #[test]
    fn only_a_peer_on_the_loopback_interface_is_trusted() {
        for loopback in ["127.0.0.1:4400", "127.0.0.2:4400", "[::1]:4400"] {
            let peer: SocketAddr = loopback.parse().expect("the address parses");
            assert_eq!(refuse_non_loopback_peer(peer), Ok(()), "{loopback}");
        }
        for routable in ["10.0.0.1:4400", "203.0.113.7:80", "[2001:db8::1]:4400"] {
            let peer: SocketAddr = routable.parse().expect("the address parses");
            let refusal =
                refuse_non_loopback_peer(peer).expect_err("a routable peer must be refused");
            assert!(refusal.contains("not loopback"), "{refusal}");
            assert!(refusal.contains(&peer.ip().to_string()), "{refusal}");
        }
    }

    /// The address this host would use to reach the outside world, when it has one. No packet
    /// is sent: a connected UDP socket only fixes the route so the local address can be read.
    fn outward_address() -> Option<std::net::IpAddr> {
        let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("203.0.113.1:80").ok()?;
        let address = socket.local_addr().ok()?.ip();
        (!address.is_loopback() && !address.is_unspecified()).then_some(address)
    }

    /// LOOPPEER-2: the same rule over a real connection. A Hub reached on this host's own
    /// non-loopback address is refused, and the socket it reached is left with nothing written
    /// to it, so the control capability never lands where other hosts can also connect.
    ///
    /// The refusal is the claim being fixed here. The check that nothing was written is
    /// best-effort by nature: connecting to an ephemeral port on this same host can produce a
    /// TCP simultaneous open, where the socket connects to itself and the listener never sees
    /// it. That case leaves nothing to inspect, and the test says so rather than hanging on an
    /// accept that will not arrive.
    #[test]
    fn a_hub_reached_off_the_loopback_interface_is_never_sent_the_capability() {
        let Some(address) = outward_address() else {
            // A host with no non-loopback address cannot exercise this; LOOPPEER-1 still does.
            return;
        };
        let Ok(listener) = TcpListener::bind((address, 0)) else {
            return;
        };
        let bound = listener.local_addr().expect("the listener has an address");
        listener
            .set_nonblocking(true)
            .expect("the listener accepts without blocking");

        let refusal = post_json(
            &bound.to_string(),
            "/_admin/export",
            "{}",
            "secret-control-token",
        )
        .expect_err("a non-loopback peer must be refused");

        assert!(refusal.contains("not loopback"), "{refusal}");
        assert!(refusal.contains(&address.to_string()), "{refusal}");

        // Whatever reached the listener, if anything did, carried no request.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    use std::io::Read as _;
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                        .expect("the timeout is set");
                    let mut received = Vec::new();
                    let _ = stream.read_to_end(&mut received);
                    assert!(
                        received.is_empty(),
                        "nothing may be written to a non-loopback peer, but it received {:?}",
                        String::from_utf8_lossy(&received)
                    );
                    return;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(_) => return,
            }
        }
    }
}

#[cfg(test)]
mod network_exposure_tests {
    use super::{connectable, network_exposure_warnings};
    use std::net::SocketAddr;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn an_unspecified_listener_is_advertised_at_the_loopback_address_of_its_family() {
        assert_eq!(connectable(addr("0.0.0.0:8080")), addr("127.0.0.1:8080"));
        assert_eq!(connectable(addr("[::]:9099")), addr("[::1]:9099"));
        for kept in ["127.0.0.1:1", "[::1]:2", "192.168.1.10:3", "[fe80::1]:4"] {
            assert_eq!(connectable(addr(kept)), addr(kept), "{kept}");
        }
    }

    #[test]
    fn only_listeners_off_loopback_are_warned_about() {
        let warnings = network_exposure_warnings(&[
            ("firestore", Some(addr("0.0.0.0:8080"))),
            ("auth", Some(addr("127.0.0.1:9099"))),
            ("storage", None),
            ("pubsub", Some(addr("[::]:8085"))),
            ("tasks", Some(addr("[::1]:9499"))),
        ]);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(
            warnings[0].starts_with("firestore listens on 0.0.0.0:8080"),
            "{warnings:?}"
        );
        assert!(
            warnings[1].starts_with("pubsub listens on [::]:8085"),
            "{warnings:?}"
        );
        assert!(warnings[0].contains("control API answers loopback peers only"));
    }
}

#[cfg(test)]
mod storage_endpoint_tests {
    use super::{child_environment, BoundAddrs, RuntimeConfig};
    use crate::config::Selection;
    use fireemu_adapter_http::storage::StorageServerRequests;
    use fireemu_core_app_check::verify::BaselineMode;

    const CAPABILITY: &str = "0123456789abcdef0123456789abcdef";

    fn addrs() -> BoundAddrs {
        let loopback = |port: u16| Some(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
        BoundAddrs {
            firestore: loopback(8080),
            auth: loopback(9099),
            storage: loopback(9199),
            functions: None,
            eventarc: None,
            tasks: None,
            pubsub: None,
            database: None,
            hub: None,
            ui: None,
            logging: None,
            control: std::net::SocketAddr::from(([127, 0, 0, 1], 9099)),
        }
    }

    fn storage_endpoint(cfg: &RuntimeConfig, only: &Selection) -> Option<String> {
        child_environment(cfg, only, &addrs(), "control-token", CAPABILITY)
            .into_iter()
            .find(|(name, _)| name == "STORAGE_EMULATOR_HOST")
            .map(|(_, value)| value)
    }

    fn config_with_storage(mode: BaselineMode) -> RuntimeConfig {
        let mut cfg = RuntimeConfig::default();
        cfg.app_check.enabled = true;
        cfg.app_check.storage = mode;
        cfg
    }

    fn capability_config(mode: BaselineMode) -> RuntimeConfig {
        let mut cfg = config_with_storage(mode);
        cfg.app_check.storage_server_requests = StorageServerRequests::Capability;
        cfg
    }

    /// `@google-cloud/storage` 8.1 and later refuse a URL with embedded credentials, so the
    /// Admin Storage endpoint is the plain `http://host:port` unless Storage App Check
    /// enforcement is the reason to carry the capability.
    #[test]
    fn the_admin_storage_endpoint_is_plain_unless_storage_app_check_is_enforced() {
        let plain = Some("http://127.0.0.1:9199".to_owned());
        let all = Selection::default();
        assert_eq!(storage_endpoint(&RuntimeConfig::default(), &all), plain);
        assert_eq!(
            storage_endpoint(&config_with_storage(BaselineMode::Off), &all),
            plain
        );
        assert_eq!(
            storage_endpoint(&config_with_storage(BaselineMode::Unenforced), &all),
            plain
        );
    }

    /// The default, `loopback`, needs no capability: the Storage adapter admits the server-side
    /// request by its shape, so the Admin SDK (any version) gets the plain endpoint even while
    /// Storage App Check is `enforced`.
    #[test]
    fn enforced_storage_app_check_exports_the_plain_endpoint_by_default() {
        let all = Selection::default();
        assert_eq!(
            RuntimeConfig::default().app_check.storage_server_requests,
            StorageServerRequests::Loopback
        );
        assert_eq!(
            storage_endpoint(&config_with_storage(BaselineMode::Enforced), &all),
            Some("http://127.0.0.1:9199".to_owned())
        );
    }

    #[test]
    fn capability_mode_keeps_the_admin_capability_in_the_endpoint_only_while_enforced() {
        let all = Selection::default();
        assert_eq!(
            storage_endpoint(&capability_config(BaselineMode::Enforced), &all),
            Some(format!("http://fireemu:{CAPABILITY}@127.0.0.1:9199"))
        );
        for mode in [BaselineMode::Off, BaselineMode::Unenforced] {
            assert_eq!(
                storage_endpoint(&capability_config(mode), &all),
                Some("http://127.0.0.1:9199".to_owned()),
                "{mode:?}"
            );
        }
    }

    fn any_mode() -> impl proptest::strategy::Strategy<Value = BaselineMode> {
        proptest::prop_oneof![
            proptest::strategy::Just(BaselineMode::Off),
            proptest::strategy::Just(BaselineMode::Unenforced),
            proptest::strategy::Just(BaselineMode::Enforced),
        ]
    }

    proptest::proptest! {
        /// Whatever the three products are set to, and whichever services `--only` leaves
        /// selected, the endpoint carries the capability exactly when the effective Storage
        /// mode is `enforced` and `storageServerRequests` is `capability`; it is always
        /// `http://host:port` otherwise, and never leaks the capability into the
        /// browser-facing `FIREBASE_STORAGE_EMULATOR_HOST`.
        #[test]
        fn the_capability_is_present_exactly_when_the_effective_storage_mode_is_enforced(
            auth in any_mode(),
            firestore in any_mode(),
            storage in any_mode(),
            capability_mode in proptest::bool::ANY,
            appcheck_selected in proptest::bool::ANY,
            functions_selected in proptest::bool::ANY,
        ) {
            let mut cfg = RuntimeConfig::default();
            cfg.app_check.enabled = true;
            cfg.app_check.auth = auth;
            cfg.app_check.firestore = firestore;
            cfg.app_check.storage = storage;
            if capability_mode {
                cfg.app_check.storage_server_requests = StorageServerRequests::Capability;
            }
            let only = Selection {
                appcheck: appcheck_selected,
                functions: functions_selected,
                ..Selection::default()
            };
            let env = child_environment(&cfg, &only, &addrs(), "control-token", CAPABILITY);
            let value = |name: &str| {
                env.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone())
            };
            let endpoint = value("STORAGE_EMULATOR_HOST").expect("storage is selected");
            if storage == BaselineMode::Enforced && capability_mode {
                // `enforces_selected` keeps the verifier whatever `--only` names.
                proptest::prop_assert_eq!(
                    endpoint,
                    format!("http://fireemu:{CAPABILITY}@127.0.0.1:9199")
                );
            } else {
                proptest::prop_assert_eq!(endpoint, "http://127.0.0.1:9199".to_owned());
            }
            proptest::prop_assert_eq!(
                value("FIREBASE_STORAGE_EMULATOR_HOST"),
                Some("127.0.0.1:9199".to_owned())
            );
            proptest::prop_assert!(env.iter().all(|(n, v)| n == "STORAGE_EMULATOR_HOST"
                || !v.contains(CAPABILITY)));
        }
    }

    /// The capability follows the policy the Storage adapter actually holds: another product's
    /// enforcement never adds it.
    #[test]
    fn only_the_effective_storage_mode_decides_the_capability() {
        let all = Selection::default();
        let mut firestore_only = RuntimeConfig::default();
        firestore_only.app_check.enabled = true;
        firestore_only.app_check.firestore = BaselineMode::Enforced;
        firestore_only.app_check.auth = BaselineMode::Enforced;
        assert_eq!(
            storage_endpoint(&firestore_only, &all).as_deref(),
            Some("http://127.0.0.1:9199")
        );
    }
}
