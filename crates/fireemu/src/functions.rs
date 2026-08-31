//! Functions runtime wiring: runner process, event subscriptions, control hooks.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_http::control::FunctionsHook;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::ids::SessionId;

use crate::config::RuntimeConfig;

fn ignored_reload_path(relative: &Path, configured: &[String]) -> bool {
    let text = relative.to_string_lossy().replace('\\', "/");
    if relative
        .components()
        .any(|part| matches!(part.as_os_str().to_str(), Some("node_modules" | ".git")))
    {
        return true;
    }
    configured.iter().any(|pattern| {
        let pattern = pattern.trim_start_matches("./").trim_start_matches("**/");
        if let Some(suffix) = pattern.strip_prefix('*') {
            text.ends_with(suffix)
        } else {
            text == pattern || text.starts_with(&format!("{pattern}/"))
        }
    })
}

fn functions_source_signature(root: &Path, ignores: &[String]) -> Result<u64, String> {
    fn visit(root: &Path, path: &Path, ignores: &[String], hash: &mut u64) -> Result<(), String> {
        let mut entries = std::fs::read_dir(path)
            .map_err(|e| format!("watch {}: {e}", path.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("watch {}: {e}", path.display()))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let child = entry.path();
            let relative = child.strip_prefix(root).unwrap_or(&child);
            if ignored_reload_path(relative, ignores) {
                continue;
            }
            let kind = entry
                .file_type()
                .map_err(|e| format!("watch {}: {e}", child.display()))?;
            if kind.is_dir() {
                visit(root, &child, ignores, hash)?;
            } else if kind.is_file() {
                for byte in relative.to_string_lossy().bytes().chain([0]) {
                    *hash = hash.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte);
                }
                let bytes =
                    std::fs::read(&child).map_err(|e| format!("watch {}: {e}", child.display()))?;
                for byte in bytes {
                    *hash = hash.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte);
                }
            }
        }
        Ok(())
    }

    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    visit(root, root, ignores, &mut hash)?;
    Ok(hash)
}

fn snapshot_functions_source(root: &Path, ignores: &[String]) -> Result<PathBuf, String> {
    fn copy_tree(
        root: &Path,
        source: &Path,
        destination: &Path,
        ignores: &[String],
    ) -> Result<(), String> {
        let mut entries = std::fs::read_dir(source)
            .map_err(|e| format!("snapshot {}: {e}", source.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("snapshot {}: {e}", source.display()))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap_or(&path);
            if ignored_reload_path(relative, ignores) {
                continue;
            }
            let kind = entry
                .file_type()
                .map_err(|e| format!("snapshot {}: {e}", path.display()))?;
            let target = destination.join(relative);
            if kind.is_dir() {
                std::fs::create_dir_all(&target)
                    .map_err(|e| format!("snapshot {}: {e}", target.display()))?;
                copy_tree(root, &path, destination, ignores)?;
            } else if kind.is_file() {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("snapshot {}: {e}", parent.display()))?;
                }
                std::fs::copy(&path, &target)
                    .map_err(|e| format!("snapshot {}: {e}", path.display()))?;
            }
        }
        Ok(())
    }

    static NEXT_SNAPSHOT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = NEXT_SNAPSHOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let destination = std::env::temp_dir().join(format!(
        "fireemu-functions-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir(&destination)
        .map_err(|e| format!("snapshot {}: {e}", destination.display()))?;
    let result = copy_tree(root, root, &destination, ignores).and_then(|()| {
        let dependencies = root
            .ancestors()
            .map(|ancestor| ancestor.join("node_modules"))
            .find(|candidate| candidate.is_dir());
        if let Some(dependencies) = dependencies {
            link_dependency_directory(&dependencies, &destination.join("node_modules"))?;
        }
        Ok(())
    });
    if let Err(reason) = result {
        let _ = std::fs::remove_dir_all(&destination);
        return Err(reason);
    }
    Ok(destination)
}

#[cfg(unix)]
fn link_dependency_directory(source: &Path, destination: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(source, destination)
        .map_err(|e| format!("snapshot {}: {e}", destination.display()))
}

#[cfg(windows)]
fn link_dependency_directory(source: &Path, destination: &Path) -> Result<(), String> {
    std::os::windows::fs::symlink_dir(source, destination)
        .map_err(|e| format!("snapshot {}: {e}", destination.display()))
}

fn start_reload_supervisors(
    runtime: &Arc<FunctionsRuntime>,
    cfg: &RuntimeConfig,
    hosts: &EmulatorHosts,
    runner_secret: &str,
    callable_trusted_protocol: bool,
) {
    for codebase in cfg.functions_to_load() {
        let root = PathBuf::from(&codebase.source);
        let mut observed = functions_source_signature(&root, &codebase.ignore).ok();
        let weak_runtime = Arc::downgrade(runtime);
        let cfg = cfg.clone();
        let hosts = hosts.clone();
        let secret = runner_secret.to_owned();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(750)).await;
                let Some(runtime) = weak_runtime.upgrade() else {
                    return;
                };
                let next = match functions_source_signature(&root, &codebase.ignore) {
                    Ok(signature) => signature,
                    Err(reason) => {
                        eprintln!(
                            "warning: functions[{}] reload scan failed: {reason}",
                            codebase.codebase
                        );
                        continue;
                    }
                };
                if observed == Some(next) {
                    continue;
                }
                // Build tools commonly replace several files in one burst. Wait for one quiet
                // interval and use the newest complete content signature as the candidate.
                tokio::time::sleep(Duration::from_millis(250)).await;
                let stable = functions_source_signature(&root, &codebase.ignore).unwrap_or(next);
                let snapshot = match snapshot_functions_source(&root, &codebase.ignore) {
                    Ok(snapshot) => snapshot,
                    Err(reason) => {
                        eprintln!(
                            "warning: functions[{}] reload snapshot failed: {reason}",
                            codebase.codebase
                        );
                        continue;
                    }
                };
                let snapshot_signature = functions_source_signature(&snapshot, &codebase.ignore);
                let current_signature = functions_source_signature(&root, &codebase.ignore);
                if snapshot_signature.as_ref() != Ok(&stable)
                    || current_signature.as_ref() != Ok(&stable)
                {
                    let _ = std::fs::remove_dir_all(&snapshot);
                    continue;
                }
                // The runner reads only this immutable generation. If the live source changes
                // again while Node starts, the next scan necessarily differs from `observed`
                // and schedules a corrective generation instead of hiding an A-to-B-to-A race.
                observed = Some(stable);
                let mut staged = codebase.clone();
                staged.source = snapshot.to_string_lossy().into_owned();
                match start_codebase(&cfg, &staged, &hosts, &secret, callable_trusted_protocol)
                    .await
                {
                    Ok(mut spec) => {
                        spec.cleanup_dir = Some(snapshot);
                        match runtime.reload_codebase(spec) {
                            Ok(generation) => eprintln!(
                                "note: functions[{}]: reloaded generation {generation}",
                                codebase.codebase
                            ),
                            Err(reason) => eprintln!(
                                "warning: functions[{}]: reload rejected: {reason}",
                                codebase.codebase
                            ),
                        }
                    }
                    Err(reason) => {
                        let _ = std::fs::remove_dir_all(snapshot);
                        eprintln!(
                            "warning: functions[{}]: reload failed; keeping the last-known-good generation: {reason}",
                            codebase.codebase
                        );
                    }
                }
            }
        });
    }
}

/// The debug feature the callable trusted protocol turns on, and nothing else.
///
/// `firebase-functions` reads `FIREBASE_DEBUG_MODE` once when it is first required and
/// re-reads `FIREBASE_DEBUG_FEATURES` per lookup. `skipTokenVerification` makes the callable
/// wrapper decode the App Check and Auth credentials locally instead of calling out to Google,
/// which is only safe because the daemon has already verified and re-inserted both
/// (specification section 13.4). No other feature is enabled: `enableCors`, in particular,
/// would change what the functions themselves answer.
const DEBUG_FEATURES: &str = r#"{"skipTokenVerification":true}"#;

/// `FIREBASE_CONFIG`, with the three members the official emulator puts in it
/// (`functionsEmulator.js:1010-1026` with `constructDefaultAdminSdkConfig`,
/// `adminSdkConfig.js:13`).
///
/// `databaseURL` is present even though fireemu serves no Realtime Database, and points where
/// the official emulator points it when no Database emulator is running:
/// `https://<project>.firebaseio.com`. It is not decoration. `firebase-functions/v1`
/// `database.ref(...)` reads it while the endpoint is being described and throws
/// `Missing expected firebase config value databaseURL` when it is absent, so omitting the
/// key turns a codebase with one v1 Realtime Database trigger into a runner that dies with a
/// stack trace instead of a codebase whose unserved trigger is named.
#[must_use]
pub fn firebase_config(project: &str) -> String {
    serde_json::json!({
        "storageBucket": format!("{project}.appspot.com"),
        "databaseURL": format!("https://{project}.firebaseio.com"),
        "projectId": project,
    })
    .to_string()
}

/// The user environment of one codebase: the dotenv chain, invocation-scoped local secrets
/// and the legacy runtime configuration, with the files each came from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserEnvironment {
    /// `.env` chain values, later files having overridden earlier ones.
    pub values: Vec<(String, String)>,
    /// `.secret.local` values. The runner withholds them during discovery and exposes each
    /// value only while a function that declared the corresponding secret is running.
    pub secrets: Vec<(String, String)>,
    /// `CLOUD_RUNTIME_CONFIG`, when the codebase carries a `.runtimeconfig.json`.
    pub runtime_config: Option<String>,
    /// The files that were read, in the order they were applied, for the startup line.
    pub files: Vec<String>,
}

impl UserEnvironment {
    /// Non-secret values applied while the codebase is loaded.
    #[must_use]
    pub fn applied(&self) -> Vec<(String, String)> {
        let mut out = self.values.clone();
        if let Some(config) = &self.runtime_config {
            out.push(("CLOUD_RUNTIME_CONFIG".to_owned(), config.clone()));
        }
        out
    }
}

/// Reads a codebase's `.env` chain, `.secret.local` and `.runtimeconfig.json`.
///
/// The chain and its refusals are the official ones (`fireemu_core_functions::env`); the two
/// files that are not dotenv chains follow `functionsEmulator.js`:
///
/// - `.secret.local` is parsed strictly and is the *only* source of `defineSecret` values here.
///   The official emulator falls back to Google Cloud Secret
///   Manager for a secret the file does not carry; fireemu has no credentials and never
///   reaches the network, so a missing secret stays missing and the parameter resolves the way
///   an unset environment variable resolves.
/// - `.runtimeconfig.json` becomes `CLOUD_RUNTIME_CONFIG`, as `getRuntimeConfig` makes it. An
///   unreadable or malformed file is reported and treated as absent, which is what that
///   function's empty `catch` does. Note that the pinned `firebase-functions@7.3.2` has
///   *removed* `functions.config()` -- calling it throws `functions.config() has been removed
///   in firebase-functions v7` -- so the variable is passed through for a codebase pinned to
///   v6 or reading it itself, and no supported SDK surface consumes it.
pub fn load_user_environment(
    dir: &Path,
    project_id: &str,
    alias: Option<&str>,
) -> Result<UserEnvironment, String> {
    use fireemu_core_functions::env;
    let mut out = UserEnvironment::default();
    let present = |name: &str| dir.join(name).is_file();
    if let Some(alias) = alias {
        if present(&format!(".env.{project_id}")) && present(&format!(".env.{alias}")) {
            return Err(env::both_project_files_error(project_id, alias));
        }
    }
    for name in env::env_file_order(project_id, alias) {
        let path = dir.join(&name);
        if !path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to load environment variables from {name}. ({e})"))?;
        let values = env::parse_strict(&text)
            .map_err(|e| format!("Failed to load environment variables from {name}. {e}"))?;
        for (k, v) in values {
            out.values.retain(|(existing, _)| existing != &k);
            out.values.push((k, v));
        }
        out.files.push(name);
    }
    let secrets = dir.join(env::LOCAL_SECRETS_FILE);
    if secrets.is_file() {
        let text = std::fs::read_to_string(&secrets).map_err(|e| {
            format!(
                "Failed to read local secrets file {}: {e}",
                secrets.display()
            )
        })?;
        out.secrets = env::parse_strict(&text)
            .map_err(|e| {
                format!(
                    "Failed to read local secrets file {}: {e}",
                    secrets.display()
                )
            })?
            .into_iter()
            .collect();
        out.values
            .retain(|(name, _)| !out.secrets.iter().any(|(secret, _)| secret == name));
    }
    let runtime_config = dir.join(env::RUNTIME_CONFIG_FILE);
    if runtime_config.is_file() {
        match std::fs::read_to_string(&runtime_config)
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        {
            Some(value) => out.runtime_config = Some(value.to_string()),
            // `Found .runtimeconfig.json but the JSON format is invalid.`
            // (`emulatorLogger.js:199`), and the runtime is started without it.
            None => eprintln!(
                "note: found {} but the JSON format is invalid; functions.config() will be empty",
                runtime_config.display()
            ),
        }
    }
    Ok(out)
}

/// What to do with an export whose trigger family belongs to a product fireemu does not
/// serve (`functions.unservedTriggers`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnservedTriggers {
    /// Fail discovery, naming every such function. The default: a project whose Realtime
    /// Database trigger will never run must not be told the emulator started.
    #[default]
    Refuse,
    /// Print one line per function and carry on, which is what the official emulator does
    /// with a trigger service it has no emulator for.
    Report,
}

impl UnservedTriggers {
    /// Parses the configuration spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "refuse" => Some(Self::Refuse),
            "report" => Some(Self::Report),
            _ => None,
        }
    }
}

/// The line the daemon prints for one ignored export, in the official emulator's shape
/// (`functions[<region>-<name>]: function ignored because ...`, `functionsEmulator.js:501`).
#[must_use]
pub fn ignored_line(f: &fireemu_core_functions::manifest::IgnoredFunction) -> String {
    format!(
        "functions[{}-{}]: function ignored ({}): {}",
        f.region, f.name, f.trigger_type, f.reason
    )
}

/// Applies `policy` to everything the runner discovered and could not serve.
///
/// Nothing is dropped in silence, in either outcome: an unrecognised shape is reported on
/// stderr the way the official emulator reports it and stays in the manifest inventory, while
/// a trigger family that belongs to a product fireemu does not serve fails discovery with
/// every such function named -- unless the configuration asked for it to be reported instead.
pub fn check_ignored(
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
    policy: UnservedTriggers,
) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let mut fatal = Vec::new();
    for f in &manifest.ignored {
        if f.scope.is_product_decision() && policy == UnservedTriggers::Refuse {
            fatal.push(format!("{} ({}): {}", f.name, f.trigger_type, f.reason));
        } else {
            lines.push(ignored_line(f));
        }
    }
    if fatal.is_empty() {
        return Ok(lines);
    }
    Err(format!(
        "the functions codebase exports {} trigger(s) that belong to a product fireemu does \
         not serve, so they would never run: {}. Remove them, or set \
         functions.unservedTriggers = \"report\" to start anyway with each one named",
        fatal.len(),
        fatal.join("; ")
    ))
}

/// Addresses the runner's functions need to reach the daemon. `None` means the service was
/// not selected by `--only`: its variable is then left unset in the runner, so a handler
/// cannot reach a product this run is not serving.
#[derive(Debug, Clone)]
pub struct EmulatorHosts {
    /// Firestore gRPC / REST.
    pub firestore: Option<String>,
    /// Auth REST.
    pub auth: Option<String>,
    /// Storage.
    pub storage: Option<String>,
    /// The functions port itself, which also serves the Eventarc `publishEvents` route. The
    /// official suite gives Eventarc a port of its own; a custom event has nowhere to go
    /// without functions, so fireemu serves it here and points the variable the Admin SDK
    /// reads (`CLOUD_EVENTARC_EMULATOR_HOST`, which carries an `http://` prefix) at this
    /// listener.
    pub functions: Option<String>,
    /// The Logging emulator WebSocket (`FIREBASE_LOGGING_EMULATOR_HOST`), a bare host:port. The
    /// runner's functions inherit it so any Firebase tooling they load can find the log stream.
    pub logging: Option<String>,
}

/// Where a located runner script came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerSource {
    /// `FIREEMU_RUNNER_NODE` named it.
    Environment,
    /// A `runner-node/` directory shipped beside the binary: the release layout, in which the
    /// platform package holds `bin/fireemu` next to `bin/runner-node/index.mjs`.
    BesideBinary,
    /// `tools/runner-node/` in the workspace this binary was built from (development builds).
    WorkspaceSource,
}

impl RunnerSource {
    /// A short phrase for `doctor` and for error messages.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Environment => "FIREEMU_RUNNER_NODE",
            Self::BesideBinary => "bundled beside the binary",
            Self::WorkspaceSource => "workspace source tree",
        }
    }
}

/// The bundled Node runner as located on this host.
#[derive(Debug, Clone)]
pub struct RunnerScript {
    /// Absolute (or as-given, for the environment override) path of `index.mjs`.
    pub path: PathBuf,
    /// Where it was found.
    pub source: RunnerSource,
}

/// Every place the runner is looked for, in the order they are tried.
///
/// `FIREEMU_RUNNER_NODE` wins outright so a consumer can point the daemon at a runner of its
/// own. Otherwise the release layout is preferred over the source tree: a packaged binary must
/// never reach back into the machine that built it. Two shapes are accepted beside the binary,
/// `<exe dir>/runner-node/` and `<exe dir>/../runner-node/`, so the script can sit either next
/// to the executable or one level up in a package root.
#[must_use]
pub fn runner_candidates() -> Vec<(RunnerSource, PathBuf)> {
    let mut out = Vec::new();
    if let Some(script) = std::env::var_os("FIREEMU_RUNNER_NODE") {
        out.push((RunnerSource::Environment, PathBuf::from(script)));
    }
    if let Ok(exe) = std::env::current_exe() {
        // The executable may be reached through a symlink (npm's `node_modules/.bin`), and the
        // runner lives beside the real file, not beside the link.
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        if let Some(dir) = exe.parent() {
            out.push((
                RunnerSource::BesideBinary,
                dir.join("runner-node").join("index.mjs"),
            ));
            if let Some(up) = dir.parent() {
                out.push((
                    RunnerSource::BesideBinary,
                    up.join("runner-node").join("index.mjs"),
                ));
            }
        }
    }
    out.push((
        RunnerSource::WorkspaceSource,
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tools/runner-node/index.mjs"
        )),
    ));
    out
}

/// Locates the bundled Node runner, or explains every place that was tried.
///
/// The environment override is reported as missing rather than silently skipped: a consumer
/// that named a runner meant that one, and falling back to another would run different code
/// than it asked for.
pub fn locate_runner() -> Result<RunnerScript, String> {
    let candidates = runner_candidates();
    if let Some((source, path)) = candidates.first() {
        if *source == RunnerSource::Environment && !path.is_file() {
            return Err(format!(
                "FIREEMU_RUNNER_NODE names {}, which is not a readable file",
                path.display()
            ));
        }
    }
    for (source, path) in &candidates {
        if path.is_file() {
            return Ok(RunnerScript {
                path: path.clone(),
                source: *source,
            });
        }
    }
    Err(format!(
        "the bundled Node runner (runner-node/index.mjs) was not found; tried {}. Set \
         FIREEMU_RUNNER_NODE to an index.mjs, or reinstall the platform package that ships it",
        candidates
            .iter()
            .map(|(_, p)| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// The bundled Node runner as a command (overridable wholesale with `functions.runner`).
pub fn default_runner() -> Result<Vec<String>, String> {
    let script = locate_runner()?;
    Ok(vec!["node".to_owned(), script.path.display().to_string()])
}

/// Starts one runner process per configured codebase and the runtime that multiplexes them,
/// and installs it as the backend's synchronous commit observer (Storage events are wired by
/// the caller through [`storage_sink`]).
pub async fn start(
    cfg: &RuntimeConfig,
    clock: &Arc<Mutex<VirtualClock>>,
    backend: &Arc<LocalBackend>,
    hosts: &EmulatorHosts,
    runner_secret: &str,
    callable_trusted_protocol: bool,
) -> Result<Arc<FunctionsRuntime>, String> {
    let codebases = cfg.functions_to_load();
    if codebases.is_empty() {
        return Err("functions.source is not configured".to_owned());
    }
    if codebases.len() > 1 && cfg.functions_manifest.is_some() {
        return Err(format!(
            "functions.manifest replaces discovery for one codebase, and this run loads {} \
             ({}); name the one to load with --only functions:<codebase> or drop \
             functions.manifest",
            codebases.len(),
            codebases
                .iter()
                .map(|c| c.codebase.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let mut started: Vec<fireemu_adapter_functions::runtime::CodebaseSpec> = Vec::new();
    for codebase in &codebases {
        match start_codebase(
            cfg,
            codebase,
            hosts,
            runner_secret,
            callable_trusted_protocol,
        )
        .await
        {
            Ok(spec) => started.push(spec),
            Err(e) => {
                // A codebase that fails takes nothing with it but the runners this call
                // already spawned; none of them may outlive the refusal.
                for spec in &started {
                    spec.runner.kill_now();
                }
                return Err(e);
            }
        }
    }
    let config = FunctionsConfig {
        project: cfg.auth_project.clone(),
        default_bucket: format!("{}.appspot.com", cfg.auth_project),
        location: "nam5".to_owned(),
        session: SessionId::new(u128::from(cfg.seed)),
        max_running: cfg.functions_max_running,
        retry_attempts: cfg.events_max_attempts,
        max_catch_up_runs: cfg.scheduler_max_catch_up_runs,
        runner_secret: runner_secret.to_owned(),
        overlap: fireemu_adapter_functions::runtime::OverlapPolicy::parse(&cfg.scheduler_overlap)
            .unwrap_or_default(),
        catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::parse(&cfg.scheduler_catch_up)
            .unwrap_or_default(),
        functions_host: hosts.functions.clone(),
    };
    // A function name two codebases both export is fatal here. The runners it collided
    // between are killed rather than left behind a daemon that refuses to serve them.
    let spawned: Vec<Arc<Runner>> = started.iter().map(|c| c.runner.clone()).collect();
    let runtime = match FunctionsRuntime::with_codebases(started, config, clock.clone()) {
        Ok(runtime) => runtime,
        Err(e) => {
            for runner in &spawned {
                runner.kill_now();
            }
            return Err(e);
        }
    };
    tokio::spawn(runtime.clone().dispatch_loop());
    // Commits reach the runtime inside the database critical section: in order, never
    // dropped, and enqueued before the write returns to its caller.
    let sink_runtime = runtime.clone();
    backend.set_change_sink(Arc::new(move |event| sink_runtime.on_commit(event)));
    start_reload_supervisors(
        &runtime,
        cfg,
        hosts,
        runner_secret,
        callable_trusted_protocol,
    );
    Ok(runtime)
}

/// Starts one codebase's runner, reads its environment and validates what it discovered.
///
/// Every codebase gets its own process, its own dotenv chain (the files live next to its
/// `source`) and its own HTTP server; nothing about one codebase can be observed from another.
#[allow(clippy::too_many_lines)]
async fn start_codebase(
    cfg: &RuntimeConfig,
    codebase: &crate::config::FunctionsCodebase,
    hosts: &EmulatorHosts,
    runner_secret: &str,
    callable_trusted_protocol: bool,
) -> Result<fireemu_adapter_functions::runtime::CodebaseSpec, String> {
    let source = codebase.source.clone();
    let label = &codebase.codebase;
    if !Path::new(&source).is_dir() {
        return Err(format!(
            "the Functions codebase {label:?}: source {source:?} is not a directory"
        ));
    }
    let mut command = match cfg.functions_runner.clone() {
        Some(command) => command,
        None => default_runner()?,
    };
    command.push("--source".to_owned());
    command.push(source.clone());
    command.push("--codebase".to_owned());
    command.push(label.clone());
    // The user environment goes in first: the emulator's own variables override it, exactly as
    // `getRuntimeEnvs` spreads `{...userEnvs, ...systemEnvs, ...emulatorEnvs, FIREBASE_CONFIG}`
    // (`functionsEmulator.js:1027`). The dotenv dialect refuses every reserved key outright, so
    // this ordering is a second line rather than the only one.
    let user_env = load_user_environment(
        Path::new(&source),
        &cfg.auth_project,
        cfg.functions_project_alias.as_deref(),
    )
    .map_err(|e| format!("the Functions codebase {label:?}: {e}"))?;
    if !user_env.files.is_empty() {
        eprintln!(
            "note: functions[{label}]: loaded environment variables from {}",
            user_env.files.join(", ")
        );
    }
    let mut env = user_env.applied();
    if !user_env.secrets.is_empty() {
        let secrets: serde_json::Map<String, serde_json::Value> = user_env
            .secrets
            .iter()
            .map(|(name, value)| (name.clone(), serde_json::Value::String(value.clone())))
            .collect();
        env.push((
            "FIREEMU_LOCAL_SECRETS_JSON".to_owned(),
            serde_json::Value::Object(secrets).to_string(),
        ));
    }
    env.extend([
        // A runner must never reach a metadata server: the official emulator sets this on the
        // child too (`functionsEmulator.js:1117`).
        ("METADATA_SERVER_DETECTION".to_owned(), "none".to_owned()),
        ("GCLOUD_PROJECT".to_owned(), cfg.auth_project.clone()),
        ("GOOGLE_CLOUD_PROJECT".to_owned(), cfg.auth_project.clone()),
        (
            "GOOGLE_CLOUD_QUOTA_PROJECT".to_owned(),
            cfg.auth_project.clone(),
        ),
        ("FUNCTIONS_EMULATOR".to_owned(), "true".to_owned()),
        (
            "FIREBASE_CONFIG".to_owned(),
            firebase_config(&cfg.auth_project),
        ),
        // The official emulator's process-wide Cloud Run identity fields
        // (`functionsEmulator.js:980-987`). `FUNCTION_TARGET`, `FUNCTION_SIGNATURE_TYPE` and
        // `K_SERVICE` name one function, and the official emulator can set them at spawn
        // because it starts one runtime process per trigger; fireemu serves a whole codebase
        // from one runner, so the runner sets those three per invocation instead.
        ("K_REVISION".to_owned(), "1".to_owned()),
        ("PORT".to_owned(), "80".to_owned()),
        ("TZ".to_owned(), "UTC".to_owned()),
        ("FIREEMU_RUNNER".to_owned(), "1".to_owned()),
        ("FIREEMU_RUNNER_SECRET".to_owned(), runner_secret.to_owned()),
    ]);
    if let Some(host) = &hosts.firestore {
        env.push(("FIRESTORE_EMULATOR_HOST".to_owned(), host.clone()));
        env.push((
            "FIREBASE_FIRESTORE_EMULATOR_ADDRESS".to_owned(),
            host.clone(),
        ));
    }
    if let Some(host) = &hosts.auth {
        env.push(("FIREBASE_AUTH_EMULATOR_HOST".to_owned(), host.clone()));
    }
    if let Some(host) = &hosts.storage {
        env.push(("FIREBASE_STORAGE_EMULATOR_HOST".to_owned(), host.clone()));
        env.push(("STORAGE_EMULATOR_HOST".to_owned(), format!("http://{host}")));
    }
    if let Some(host) = &hosts.functions {
        env.push((
            "CLOUD_EVENTARC_EMULATOR_HOST".to_owned(),
            format!("http://{host}"),
        ));
        // Cloud Tasks' variable carries no scheme, unlike Eventarc's (`env.js:34-39`).
        env.push(("CLOUD_TASKS_EMULATOR_HOST".to_owned(), host.clone()));
        env.push(("FIREEMU_FUNCTIONS_HOST".to_owned(), host.clone()));
    }
    if let Some(host) = &hosts.logging {
        env.push(("FIREBASE_LOGGING_EMULATOR_HOST".to_owned(), host.clone()));
    }
    // Debug mode is granted only when the daemon is the sole source of both callable
    // credentials. The runner inherits an allowlist that does not contain these names, and
    // `SpawnSpec::env` is applied last, so neither can be shadowed from the host environment.
    if callable_trusted_protocol {
        env.push(("FIREBASE_DEBUG_MODE".to_owned(), "true".to_owned()));
        env.push((
            "FIREBASE_DEBUG_FEATURES".to_owned(),
            DEBUG_FEATURES.to_owned(),
        ));
    }
    let spec = SpawnSpec {
        command,
        cwd: None,
        env,
        hello_timeout: Duration::from_secs(60),
    };
    let runner = Runner::spawn_spec(&spec)
        .await
        .map_err(|e| format!("the Functions codebase {label:?}: {e}"))?;
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
    let mut manifest_json = manifest_json;
    if let Some(tz) = &cfg.scheduler_default_time_zone {
        // Schedules without a zone use the configured default.
        if let Some(functions) = manifest_json
            .get_mut("functions")
            .and_then(serde_json::Value::as_array_mut)
        {
            for f in functions {
                if let Some(trigger) = f.get_mut("trigger") {
                    if trigger.get("type").and_then(serde_json::Value::as_str) == Some("schedule")
                        && trigger
                            .get("timeZone")
                            .is_none_or(serde_json::Value::is_null)
                    {
                        trigger["timeZone"] = serde_json::Value::String(tz.clone());
                    }
                }
            }
        }
    }
    let manifest = parse_manifest(&manifest_json)?;
    // Before anything is served: every export the runner could not serve is either named in a
    // refusal or printed, one line each.
    let policy = UnservedTriggers::parse(&cfg.functions_unserved_triggers).unwrap_or_default();
    for line in check_ignored(&manifest, policy).inspect_err(|_| {
        // A refusal kills the runner it just started rather than leaving it parented to a
        // daemon that is about to exit.
        runner.kill_now();
    })? {
        eprintln!("note: {line}");
    }
    if callable_trusted_protocol && cfg.functions_manifest.is_some() {
        // A configured manifest replaces discovery outright, and the callable flag is what
        // decides whether a request goes through the trust boundary at all: a file that calls
        // a real `onCall` an `onRequest` would have the proxy forward the raw `Authorization`
        // and App Check fields to a runner that decodes them without verifying
        // (`INV-APPCHECK-010`). The runner still discovered the truth, so the two are
        // reconciled instead of trusted blindly.
        let discovered = runner
            .hello()
            .manifest
            .clone()
            .ok_or_else(|| "the functions runner did not discover a manifest".to_owned())?;
        check_manifest_agrees_on_callables(&manifest, &parse_manifest(&discovered)?)?;
    }
    check_callable_app_check(
        &manifest,
        runner.hello().app_check.as_ref(),
        callable_trusted_protocol,
    )?;
    Ok(fireemu_adapter_functions::runtime::CodebaseSpec {
        name: label.clone(),
        manifest,
        runner: Arc::new(runner),
        spawn: Some(spec),
        cleanup_dir: None,
    })
}

/// Refuses a configured manifest that disagrees with discovery about which HTTP functions are
/// callable.
///
/// Only the callable flag is reconciled. Everything else a manifest file overrides -- regions,
/// timeouts, schedules -- is deployment shape, but the callable flag decides which side of the
/// trust boundary a request lands on, and the runner is the only thing that actually knows.
fn check_manifest_agrees_on_callables(
    configured: &fireemu_core_functions::manifest::FunctionManifest,
    discovered: &fireemu_core_functions::manifest::FunctionManifest,
) -> Result<(), String> {
    use fireemu_core_functions::manifest::Trigger;
    let callable_in = |m: &fireemu_core_functions::manifest::FunctionManifest, name: &str| {
        m.functions
            .iter()
            .find(|f| f.name == name)
            .map(|f| matches!(f.trigger, Trigger::Http { callable: true, .. }))
    };
    // The App Check options of a callable are what the runner observed in the code; a
    // manifest may not weaken them (a `consumeAppCheckToken: true` callable written as
    // disabled would run without replay protection, an `enforceAppCheck: true` one as open).
    let app_check_in = |m: &fireemu_core_functions::manifest::FunctionManifest, name: &str| {
        m.functions
            .iter()
            .find(|f| f.name == name)
            .and_then(|f| match &f.trigger {
                Trigger::Http {
                    callable: true,
                    enforce_app_check,
                    consume_app_check_token,
                } => Some((*enforce_app_check, *consume_app_check_token)),
                _ => None,
            })
    };
    for f in &configured.functions {
        if !matches!(f.trigger, Trigger::Http { .. }) {
            continue;
        }
        if let (Some(configured_options), Some(discovered_options)) = (
            app_check_in(configured, &f.name),
            app_check_in(discovered, &f.name),
        ) {
            if configured_options != discovered_options {
                return Err(format!(
                    "the configured functions manifest gives callable {:?} App Check options \
                     (enforceAppCheck / consumeAppCheckToken) that differ from what the \
                     codebase declares; the manifest cannot override them",
                    f.name
                ));
            }
        }
        match callable_in(discovered, &f.name) {
            Some(discovered_callable)
                if discovered_callable
                    == matches!(f.trigger, Trigger::Http { callable: true, .. }) => {}
            Some(_) => {
                return Err(format!(
                    "the configured functions manifest calls {:?} {}, but the codebase declares \
                     the opposite; App Check for callables cannot trust a manifest that \
                     disagrees with the code",
                    f.name,
                    if matches!(f.trigger, Trigger::Http { callable: true, .. }) {
                        "callable"
                    } else {
                        "an onRequest function"
                    }
                ))
            }
            None => {
                return Err(format!(
                    "the configured functions manifest declares the HTTP function {:?}, which \
                     the codebase does not export",
                    f.name
                ))
            }
        }
    }
    Ok(())
}

/// Fails startup when the callable App Check contract cannot be honoured (specification
/// section 13.4).
///
/// Three separate things have to hold, and each of them is fatal in its own way:
///
/// - a callable that declares `consumeAppCheckToken: true` fails discovery outright, whatever
///   else is configured, because replay protection is unimplemented and running such a callable
///   would hand it `alreadyConsumed: false` -- a silently wrong answer;
/// - with App Check enabled, a callable whose value could not be observed fails startup. The
///   value is never guessed as `false`;
/// - with App Check enabled, the runner must have proved that the installed
///   `firebase-functions` reads the debug switches the way the trusted protocol relies on. The
///   daemon turns `skipTokenVerification` on; if that flag does not mean what it is expected to
///   mean, the runner is decoding credentials under rules nobody checked.
fn check_callable_app_check(
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
    report: Option<&serde_json::Value>,
    callable_trusted_protocol: bool,
) -> Result<(), String> {
    use fireemu_core_functions::manifest::{ConsumeAppCheckToken, Trigger};
    let mut undetermined: Vec<&str> = Vec::new();
    for f in &manifest.functions {
        let Trigger::Http {
            callable: true,
            consume_app_check_token,
            ..
        } = &f.trigger
        else {
            continue;
        };
        match consume_app_check_token {
            ConsumeAppCheckToken::Enabled => {
                return Err(format!(
                    "callable {:?} declares consumeAppCheckToken: true, which needs limited-use \
                     token consumption (APP_CHECK_REPLAY_UNSUPPORTED); it is not implemented",
                    f.name
                ))
            }
            ConsumeAppCheckToken::Undetermined => undetermined.push(&f.name),
            ConsumeAppCheckToken::Disabled => {}
        }
    }
    if !callable_trusted_protocol {
        return Ok(());
    }
    let report = report.ok_or_else(|| {
        "the functions runner did not report its callable App Check support; App Check cannot \
         be enabled for callables"
            .to_owned()
    })?;
    let text = |key: &str| {
        report
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("missing")
            .to_owned()
    };
    let instrumentation = text("instrumentation");
    if instrumentation != "ok" {
        return Err(format!(
            "the functions runner could not read the callable App Check options: {instrumentation}"
        ));
    }
    let debug_features = text("debugFeatures");
    if debug_features != "verified" {
        return Err(format!(
            "the installed firebase-functions debug-feature semantics differ from what the \
             trusted callable protocol requires: {debug_features}"
        ));
    }
    // The auth-override fields by their actual values. The proxy strips them by name, so a
    // renamed one would leave the daemon forwarding a channel that overrides v1 callable auth
    // context (`INV-APPCHECK-010`). Refusing to start is the only safe answer: the names are
    // not something the daemon can discover at request time.
    let honoured = report
        .get("authHeaders")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            "the functions runner did not report which auth-override headers the installed \
             firebase-functions honours"
                .to_owned()
        })?;
    for field in honoured {
        let name = field.as_str().unwrap_or_default();
        if name.is_empty()
            || !fireemu_adapter_functions::callable::ALWAYS_STRIPPED
                .iter()
                .any(|stripped| stripped.eq_ignore_ascii_case(name))
        {
            return Err(format!(
                "the installed firebase-functions honours the auth-override header {name:?}, \
                 which the callable proxy does not strip"
            ));
        }
    }
    if !undetermined.is_empty() {
        return Err(format!(
            "consumeAppCheckToken could not be determined for callable(s) {}; App Check for \
             callables fails closed rather than assuming false",
            undetermined.join(", ")
        ));
    }
    Ok(())
}

/// The Storage event observer for `runtime` (called inside the store's critical section).
pub fn storage_sink(
    runtime: &Arc<FunctionsRuntime>,
    tenancy: &fireemu_core_session::tenancy::SharedTenancy,
) -> Arc<dyn Fn(&fireemu_core_storage::store::StorageEvent) + Send + Sync> {
    let runtime = runtime.clone();
    let tenancy = tenancy.clone();
    Arc::new(move |event| {
        use fireemu_core_storage::store::StorageEvent;
        let bucket = match event {
            StorageEvent::Finalized(m)
            | StorageEvent::Deleted(m)
            | StorageEvent::MetadataUpdated(m) => m.bucket.as_str(),
        };
        // The runtime belongs to the default session: other sessions' buckets do not
        // trigger its functions.
        let owned = tenancy
            .read()
            .is_ok_and(|t| t.project_of_bucket(bucket) == runtime.project());
        if owned {
            runtime.on_storage_event(event);
        }
    })
}

/// The Auth user event observer for `runtime` (called after each Auth request).
pub fn auth_sink(
    runtime: &Arc<FunctionsRuntime>,
) -> fireemu_adapter_http::identity_toolkit::AuthEventSink {
    let runtime = runtime.clone();
    Arc::new(move |event| runtime.on_user_event(event))
}

/// Identity Platform's synchronous bridge to before-create and before-sign-in functions.
pub struct BlockingAuthBridge(pub Arc<FunctionsRuntime>);

impl fireemu_adapter_http::identity_toolkit::AuthBlockingHook for BlockingAuthBridge {
    fn invoke(
        &self,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<serde_json::Value, String> {
        let Some(target) = self.0.blocking_auth_target(event) else {
            return Ok(serde_json::json!({}));
        };
        let project = self.0.project();
        let user_json = serde_json::json!({
            "uid": user.local_id.as_str(),
            "email": user.email,
            "email_verified": user.email_verified,
            "display_name": user.display_name,
            "photo_url": user.photo_url,
            "phone_number": user.phone_number,
            "disabled": user.disabled,
            "custom_claims": serde_json::from_str::<serde_json::Value>(&user.custom_claims.canonical_json()).unwrap_or_else(|_| serde_json::json!({})),
            "metadata": {
                "creation_time": fireemu_core_types::time::LogicalInstant::to_rfc3339(user.created_at).unwrap_or_default(),
                "last_sign_in_time": user.last_sign_in_at.and_then(|instant| instant.to_rfc3339().ok()),
            },
            "provider_data": [],
        });
        let body = serde_json::json!({
            "data": {
                "user": user_json,
                "context": {
                    "eventId": format!("fireemu-blocking-{}", self.0.trigger_generation()),
                    "eventType": event.as_str(),
                    "resource": {"service": "identitytoolkit.googleapis.com", "name": format!("projects/{project}")},
                    "timestamp": fireemu_core_types::time::LogicalInstant::to_rfc3339(self.0.now()).unwrap_or_default(),
                    "params": {},
                }
            }
        })
        .to_string();
        let path = format!(
            "/{}/{}/{}",
            self.0.project(),
            target.region,
            target.function
        );
        let mut stream = TcpStream::connect(&target.addr)
            .map_err(|e| format!("BLOCKING_FUNCTION_ERROR_RESPONSE : connect failed: {e}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| format!("BLOCKING_FUNCTION_ERROR_RESPONSE : timeout setup failed: {e}"))?;
        write!(
            stream,
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nX-Fireemu-Runner-Secret: {}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
            target.addr,
            target.secret,
            body.len(),
            body
        )
        .map_err(|e| format!("BLOCKING_FUNCTION_ERROR_RESPONSE : write failed: {e}"))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| format!("BLOCKING_FUNCTION_ERROR_RESPONSE : read failed: {e}"))?;
        let response = fireemu_adapter_functions::http::parse_response(&response, "POST")
            .map_err(|e| format!("BLOCKING_FUNCTION_ERROR_RESPONSE : {e}"))?;
        let value: serde_json::Value = serde_json::from_slice(&response.body)
            .map_err(|e| format!("BLOCKING_FUNCTION_ERROR_RESPONSE : invalid JSON: {e}"))?;
        if response.status >= 300 {
            let message = value
                .get("error")
                .and_then(|error| error.get("message"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("blocking function rejected the request");
            return Err(format!("BLOCKING_FUNCTION_ERROR_RESPONSE : {message}"));
        }
        if !value.is_object() {
            return Err("BLOCKING_FUNCTION_ERROR_RESPONSE : response must be an object".to_owned());
        }
        Ok(value)
    }
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

    fn publish(&self, topic: &str, messages: &[serde_json::Value]) -> Result<Vec<String>, String> {
        if topic.is_empty() || topic.len() > 255 {
            return Err("topic must be 1..=255 characters".to_owned());
        }
        Ok(self.0.publish(topic, messages))
    }

    fn project(&self) -> String {
        self.0.project().to_owned()
    }
}

/// Bridges the real Pub/Sub broker to the Functions runtime: a message published through the
/// `google.pubsub.v1` wire surface is also delivered to any Cloud Function subscribed to that
/// topic (EVTINFRA-02), through the same `FunctionsRuntime::publish` path the control publish
/// route uses, so the topic-trigger behaviour is unchanged and the new broker state is purely
/// additive.
pub struct PubSubBridge(Arc<FunctionsRuntime>);

impl PubSubBridge {
    /// Wraps the functions runtime.
    #[must_use]
    pub fn new(runtime: Arc<FunctionsRuntime>) -> Self {
        Self(runtime)
    }
}

impl fireemu_adapter_pubsub::TopicDelivery for PubSubBridge {
    fn deliver(&self, topic: &str, messages: &[fireemu_adapter_pubsub::BridgeMessage]) {
        // The runtime consumes the same `{data: <base64>, attributes, orderingKey}` message
        // shape the control publish route produces (`pubsub_event` reads `data` verbatim as the
        // CloudEvent body).
        let values: Vec<serde_json::Value> = messages
            .iter()
            .map(|m| {
                let mut value = serde_json::json!({
                    "data": base64_encode(&m.data),
                    "attributes": m.attributes,
                });
                if !m.ordering_key.is_empty() {
                    value["orderingKey"] = serde_json::Value::String(m.ordering_key.clone());
                }
                value
            })
            .collect();
        let _ = self.0.publish(topic, &values);
    }
}

/// Standard base64 with padding (the encoding the `PubSub` `CloudEvent` `data` field carries).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{check_callable_app_check, functions_source_signature, snapshot_functions_source};
    use fireemu_adapter_functions::manifest_json::parse_manifest;
    use serde_json::json;

    #[test]
    fn reload_signature_tracks_build_and_env_files_but_ignores_configured_paths() {
        let root =
            std::env::temp_dir().join(format!("fireemu-functions-watch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("lib")).unwrap();
        std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        std::fs::write(root.join("lib/index.js"), "export const value = 1;").unwrap();
        std::fs::write(root.join(".env"), "VALUE=one\n").unwrap();
        std::fs::write(root.join("node_modules/pkg/index.js"), "ignored").unwrap();
        let first = functions_source_signature(&root, &[]).unwrap();

        std::fs::write(root.join("node_modules/pkg/index.js"), "still ignored").unwrap();
        assert_eq!(functions_source_signature(&root, &[]).unwrap(), first);
        std::fs::write(root.join("lib/index.js"), "export const value = 2;").unwrap();
        let build_changed = functions_source_signature(&root, &[]).unwrap();
        assert_ne!(build_changed, first);
        std::fs::write(root.join(".env"), "VALUE=two\n").unwrap();
        assert_ne!(
            functions_source_signature(&root, &[]).unwrap(),
            build_changed
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reload_snapshot_keeps_one_exact_source_generation() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-functions-snapshot-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("lib")).unwrap();
        std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        std::fs::write(root.join("lib/index.js"), "export const value = 'before';").unwrap();
        std::fs::write(root.join("node_modules/pkg/index.js"), "dependency").unwrap();
        let expected = functions_source_signature(&root, &[]).unwrap();

        let snapshot = snapshot_functions_source(&root, &[]).unwrap();
        assert_eq!(
            functions_source_signature(&snapshot, &[]).unwrap(),
            expected
        );
        std::fs::write(root.join("lib/index.js"), "export const value = 'after';").unwrap();
        assert_eq!(
            functions_source_signature(&snapshot, &[]).unwrap(),
            expected
        );
        assert_ne!(functions_source_signature(&root, &[]).unwrap(), expected);

        std::fs::remove_dir_all(snapshot).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    /// One callable with the given `consumeAppCheckToken` spelling, or none at all when
    /// `consume` is `None` (an older manifest that does not mention the field).
    fn manifest(consume: Option<&str>) -> fireemu_core_functions::manifest::FunctionManifest {
        let mut trigger = json!({"type": "http", "callable": true, "enforceAppCheck": true});
        if let Some(consume) = consume {
            trigger["consumeAppCheckToken"] = json!(consume);
        }
        parse_manifest(&json!({"functions": [{"name": "guarded", "trigger": trigger}]}))
            .expect("the fixture manifest parses")
    }

    fn report(instrumentation: &str, debug_features: &str) -> serde_json::Value {
        report_with(
            instrumentation,
            debug_features,
            &["x-callable-context-auth", "x-original-auth"],
        )
    }

    fn report_with(
        instrumentation: &str,
        debug_features: &str,
        auth_headers: &[&str],
    ) -> serde_json::Value {
        json!({
            "firebaseFunctionsVersion": "7.3.2",
            "instrumentation": instrumentation,
            "debugFeatures": debug_features,
            "debugMode": true,
            "authHeaders": auth_headers,
        })
    }

    /// Functions scenario 6: `consumeAppCheckToken: true` fails discovery outright, whether or
    /// not App Check is enabled -- replay protection is unimplemented, and the callable would
    /// otherwise run with `alreadyConsumed: false`.
    #[test]
    fn consume_app_check_token_fails_function_discovery_while_replay_support_is_unavailable() {
        for trusted in [true, false] {
            let e = check_callable_app_check(
                &manifest(Some("enabled")),
                Some(&report("ok", "verified")),
                trusted,
            )
            .expect_err("a callable that consumes tokens cannot be served");
            assert!(e.contains("APP_CHECK_REPLAY_UNSUPPORTED"), "{e}");
            assert!(e.contains("guarded"), "{e}");
        }
    }

    /// An undeterminable value is never guessed as `false`: it fails startup, but only when
    /// App Check is actually enabled for callables.
    #[test]
    fn an_undeterminable_consume_app_check_token_fails_only_with_app_check_enabled() {
        for absent in [None, Some("undetermined")] {
            let e =
                check_callable_app_check(&manifest(absent), Some(&report("ok", "verified")), true)
                    .expect_err("an unobserved option fails closed");
            assert!(e.contains("could not be determined"), "{e}");
            check_callable_app_check(&manifest(absent), None, false)
                .expect("without App Check the callable protocol is inactive");
        }
    }

    /// A configured manifest cannot weaken what the runner observed: writing a token-consuming
    /// callable as disabled would run it without replay protection.
    #[test]
    fn a_manifest_cannot_override_the_app_check_options_the_runner_observed() {
        let e = super::check_manifest_agrees_on_callables(
            &manifest(Some("disabled")),
            &manifest(Some("enabled")),
        )
        .expect_err("the manifest disagrees with the code");
        assert!(e.contains("cannot override"), "{e}");
        super::check_manifest_agrees_on_callables(
            &manifest(Some("enabled")),
            &manifest(Some("enabled")),
        )
        .expect("agreeing manifests reconcile");
    }

    #[test]
    fn a_runner_that_could_not_instrument_the_sdk_fails_startup() {
        let e = check_callable_app_check(
            &manifest(Some("disabled")),
            Some(&report(
                "firebase-functions 9.0.0 is outside the supported range",
                "verified",
            )),
            true,
        )
        .expect_err("the callable options cannot be trusted");
        assert!(e.contains("outside the supported range"), "{e}");
    }

    /// The daemon turns `skipTokenVerification` on. If that flag does not mean what it is
    /// expected to mean, the runner would be decoding credentials under rules nobody checked.
    #[test]
    fn unexpected_debug_feature_semantics_fail_startup() {
        let e = check_callable_app_check(
            &manifest(Some("disabled")),
            Some(&report(
                "ok",
                "the installed firebase-functions reads skipTokenVerification differently",
            )),
            true,
        )
        .expect_err("the debug switch semantics are part of the trust boundary");
        assert!(e.contains("debug-feature semantics differ"), "{e}");
    }

    /// The proxy strips the auth-override fields by name. A supported minor release that
    /// renamed one would leave the daemon forwarding a channel that overrides v1 callable auth
    /// context, so the mismatch has to be fatal rather than silent (`INV-APPCHECK-010`).
    #[test]
    fn an_auth_override_header_the_proxy_does_not_strip_fails_startup() {
        for honoured in [
            vec!["x-callable-context-auth", "x-firebase-callable-auth"],
            vec!["x-callable-context-auth"],
            vec![],
        ] {
            let e = check_callable_app_check(
                &manifest(Some("disabled")),
                Some(&report_with("ok", "verified", &honoured)),
                true,
            );
            if honoured.iter().all(|h| {
                fireemu_adapter_functions::callable::ALWAYS_STRIPPED
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(h))
            }) {
                // A shorter list is not a mismatch: everything it names is stripped.
                e.expect("every honoured field is stripped");
            } else {
                let e = e.expect_err("an unstripped auth-override field is fatal");
                assert!(e.contains("auth-override header"), "{e}");
            }
        }
    }

    #[test]
    fn a_runner_that_does_not_report_its_auth_override_headers_fails_startup() {
        let mut report = report("ok", "verified");
        report
            .as_object_mut()
            .expect("an object")
            .remove("authHeaders");
        let e = check_callable_app_check(&manifest(Some("disabled")), Some(&report), true)
            .expect_err("no report is no evidence");
        assert!(e.contains("auth-override headers"), "{e}");
    }

    #[test]
    fn a_runner_without_an_app_check_report_fails_startup() {
        let e = check_callable_app_check(&manifest(Some("disabled")), None, true)
            .expect_err("no report is no evidence");
        assert!(e.contains("did not report"), "{e}");
    }

    /// A configured manifest replaces discovery outright, and the callable flag decides which
    /// side of the trust boundary a request lands on. A file that calls a real `onCall` an
    /// `onRequest` would have the proxy forward the raw credentials to a runner that decodes
    /// them without verifying.
    #[test]
    fn a_configured_manifest_that_hides_a_callable_fails_startup() {
        let discovered = manifest(Some("disabled"));
        let hidden = parse_manifest(&json!({
            "functions": [{"name": "guarded", "trigger": {"type": "http", "callable": false}}]
        }))
        .expect("the fixture manifest parses");
        let e = super::check_manifest_agrees_on_callables(&hidden, &discovered)
            .expect_err("a manifest may not reclassify a callable");
        assert!(e.contains("guarded"), "{e}");
        assert!(e.contains("disagrees with the code"), "{e}");

        let invented = parse_manifest(&json!({
            "functions": [{"name": "ghost", "trigger": {"type": "http", "callable": true}}]
        }))
        .expect("the fixture manifest parses");
        let e = super::check_manifest_agrees_on_callables(&invented, &discovered)
            .expect_err("a manifest may not invent an HTTP function");
        assert!(e.contains("does not export"), "{e}");

        super::check_manifest_agrees_on_callables(&discovered, &discovered)
            .expect("an agreeing manifest starts");
    }

    /// A manifest whose only ignored export is an unrecognised shape starts, with a line
    /// naming it -- the official emulator's carry-on. A product decision does not.
    #[test]
    fn a_product_decision_is_fatal_and_an_unrecognised_shape_is_a_line() {
        let manifest = parse_manifest(&json!({
            "functions": [{"name": "api", "trigger": {"type": "http", "callable": false}}],
            "ignored": [
                {"name": "onRef", "region": "europe-west1", "triggerType": "database",
                 "scope": "deferred", "reason": "deferred: no Realtime Database"},
                {"name": "weird", "region": "us-central1", "triggerType": "unknown",
                 "scope": "unsupported", "reason": "the endpoint declares no trigger"}
            ]
        }))
        .expect("the fixture manifest parses");

        let e = super::check_ignored(&manifest, super::UnservedTriggers::Refuse)
            .expect_err("a deferred product is fatal");
        assert!(e.contains("onRef (database)"), "{e}");
        assert!(!e.contains("weird"), "{e}");

        let lines = super::check_ignored(&manifest, super::UnservedTriggers::Report)
            .expect("reporting starts");
        assert_eq!(
            lines,
            vec![
                "functions[europe-west1-onRef]: function ignored (database): deferred: no \
                 Realtime Database"
                    .to_owned(),
                "functions[us-central1-weird]: function ignored (unknown): the endpoint \
                 declares no trigger"
                    .to_owned(),
            ]
        );
    }

    /// Nothing is dropped in either direction: an ignored export survives the manifest's
    /// round trip through JSON with its scope and its reason.
    #[test]
    fn the_ignored_inventory_round_trips_through_the_manifest_json() {
        let json = json!({
            "functions": [],
            "ignored": [{"name": "onRef", "region": "us-central1", "triggerType": "database",
                         "scope": "notPlanned", "reason": "not planned"}]
        });
        let manifest = parse_manifest(&json).expect("parses");
        assert_eq!(
            fireemu_adapter_functions::manifest_json::manifest_to_json(&manifest)["ignored"],
            json["ignored"]
        );
        let bad = parse_manifest(&json!({
            "functions": [],
            "ignored": [{"name": "onRef", "scope": "invented", "reason": "x"}]
        }))
        .expect_err("an unknown scope is refused rather than guessed");
        assert!(bad.contains("unknown scope"), "{bad}");
    }

    #[test]
    fn a_fully_reported_disabled_callable_starts() {
        check_callable_app_check(
            &manifest(Some("disabled")),
            Some(&report("ok", "verified")),
            true,
        )
        .expect("a callable that does not consume tokens is servable");
    }
}
