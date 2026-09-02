//! Functions runtime wiring: runner process, event subscriptions, control hooks.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
#[cfg(not(windows))]
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_http::control::FunctionsHook;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::ids::SessionId;

use crate::config::{CompatibilityProfile, RuntimeConfig};

/// One Pub/Sub topic and emulator subscription required by a loaded function manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionPubSubResource {
    /// The canonical topic name.
    pub topic: fireemu_core_pubsub::TopicName,
    /// The canonical emulator subscription name.
    pub subscription: fireemu_core_pubsub::SubscriptionName,
}

/// Derives the unique Pub/Sub resources required by Pub/Sub and scheduled functions.
pub fn function_pubsub_resources(
    project: &str,
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
) -> Result<Vec<FunctionPubSubResource>, String> {
    use fireemu_core_functions::manifest::Trigger;

    let mut topics: BTreeSet<(String, String)> = BTreeSet::new();
    for function in &manifest.functions {
        match &function.trigger {
            Trigger::PubSub { topic } => {
                topics.insert((topic.clone(), format!("function {:?}", function.name)));
            }
            Trigger::Schedule { .. } => {
                topics.insert((
                    format!("firebase-schedule-{}", function.name),
                    format!("scheduled function {:?}", function.name),
                ));
            }
            _ => {}
        }
    }

    // The same topic may be declared by more than one function. Resource names, not the
    // diagnostics attached to them, define uniqueness.
    let mut seen = BTreeSet::new();
    let mut resources = Vec::new();
    for (topic_id, owner) in topics {
        if !seen.insert(topic_id.clone()) {
            continue;
        }
        let topic = fireemu_core_pubsub::TopicName::new(project, &topic_id).map_err(|error| {
            format!("{owner} requires invalid Pub/Sub topic {topic_id:?}: {error}")
        })?;
        let subscription_id = format!("emulator-sub-{topic_id}");
        let subscription = fireemu_core_pubsub::SubscriptionName::new(project, &subscription_id)
            .map_err(|error| {
                format!(
                    "{owner} requires invalid Pub/Sub subscription {subscription_id:?}: {error}"
                )
            })?;
        resources.push(FunctionPubSubResource {
            topic,
            subscription,
        });
    }
    Ok(resources)
}

/// Creates missing manifest-owned Pub/Sub resources without changing existing compatible ones.
pub fn provision_function_pubsub_resources(
    state: &mut fireemu_core_pubsub::PubSubState,
    resources: &[FunctionPubSubResource],
) -> Result<(), String> {
    use fireemu_core_pubsub::subscription::DEFAULT_ACK_DEADLINE_SECONDS;
    use fireemu_core_pubsub::{Filter, PushConfig, SubscriptionConfig};

    // Check every existing subscription before creating anything. A stale subscription with
    // the expected name but another topic is configuration drift, not an idempotent match.
    for resource in resources {
        if let Ok(existing) = state.subscription_config(&resource.subscription) {
            if existing.topic != resource.topic {
                return Err(format!(
                    "Functions requires subscription {} to target {}, but it already targets {}",
                    resource.subscription.to_full(),
                    resource.topic.to_full(),
                    existing.topic.to_full()
                ));
            }
        }
    }

    for resource in resources {
        if !state.topic_exists(&resource.topic) {
            state
                .create_topic(resource.topic.clone(), BTreeMap::new())
                .map_err(|error| {
                    format!(
                        "could not provision topic {}: {error}",
                        resource.topic.to_full()
                    )
                })?;
        }
        if state.subscription_config(&resource.subscription).is_err() {
            state
                .create_subscription(SubscriptionConfig {
                    name: resource.subscription.clone(),
                    topic: resource.topic.clone(),
                    ack_deadline_seconds: DEFAULT_ACK_DEADLINE_SECONDS,
                    enable_message_ordering: false,
                    filter: Filter::always(),
                    dead_letter_policy: None,
                    retry_policy: None,
                    push_config: PushConfig::default(),
                })
                .map_err(|error| {
                    format!(
                        "could not provision subscription {}: {error}",
                        resource.subscription.to_full()
                    )
                })?;
        }
        state
            .mark_function_subscription(&resource.subscription)
            .map_err(|error| {
                format!(
                    "could not provision subscription {}: {error}",
                    resource.subscription.to_full()
                )
            })?;
    }
    Ok(())
}

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
            } else if kind.is_symlink() {
                return Err(format!(
                    "watch {}: symbolic links outside node_modules are not supported",
                    child.display()
                ));
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
            } else if kind.is_symlink() {
                return Err(format!(
                    "snapshot {}: symbolic links outside node_modules are not supported",
                    path.display()
                ));
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
    secure_snapshot_directory(&destination)?;
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
fn secure_snapshot_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("snapshot {}: {e}", path.display()))
}

#[cfg(windows)]
fn secure_snapshot_directory(_path: &Path) -> Result<(), String> {
    Ok(())
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

/// Parent variables the official CLI would leave on the Functions child, excluding names
/// owned by the emulator and ambient Google credentials. Function code is trusted local code,
/// but these exclusions keep the callable trust boundary and the no-ADC guarantee intact.
fn inheritable_parent_environment() -> Vec<(String, String)> {
    use fireemu_core_functions::env;

    std::env::vars()
        .filter(|(name, _)| {
            env::validate_key(name).is_ok()
                && name != "GOOGLE_APPLICATION_CREDENTIALS"
                && !name.starts_with("CLOUDSDK_")
                && !name.starts_with("FIREEMU_")
        })
        .collect()
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(not(windows), test))]
struct NodeInstallation {
    program: PathBuf,
    version: String,
    major: u32,
    minor: u32,
    patch: u32,
    require_module: bool,
}

#[cfg(any(not(windows), test))]
fn parse_node_version(text: &str) -> Option<(String, u32, u32, u32)> {
    let version = text.trim().strip_prefix('v').unwrap_or(text.trim());
    let core = version.split_once('-').map_or(version, |(core, _)| core);
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((version.to_owned(), major, minor, patch))
}

#[cfg(any(not(windows), test))]
fn requirement_parts(text: &str) -> Option<Vec<Option<u32>>> {
    let text = text.trim().trim_start_matches('v');
    if text.is_empty() {
        return None;
    }
    text.split('.')
        .map(|part| match part {
            "x" | "X" | "*" => Some(None),
            _ => part.parse().ok().map(Some),
        })
        .collect()
}

#[cfg(any(not(windows), test))]
fn version_floor(parts: &[Option<u32>]) -> Option<(u32, u32, u32)> {
    Some((
        parts.first().copied().flatten()?,
        parts.get(1).copied().flatten().unwrap_or(0),
        parts.get(2).copied().flatten().unwrap_or(0),
    ))
}

#[cfg(any(not(windows), test))]
fn node_engine_token_matches(token: &str, actual: (u32, u32, u32)) -> Option<bool> {
    for operator in [">=", "<=", ">", "<"] {
        if let Some(version) = token.strip_prefix(operator) {
            let parts = requirement_parts(version)?;
            if parts.first().is_some_and(Option::is_none) {
                return Some(matches!(operator, ">=" | "<="));
            }
            let expected = version_floor(&parts)?;
            let partial_at = parts
                .iter()
                .position(Option::is_none)
                .or((parts.len() < 3).then_some(parts.len()));
            let next_partial = match partial_at {
                Some(1) => Some((expected.0.checked_add(1)?, 0, 0)),
                Some(2) => Some((expected.0, expected.1.checked_add(1)?, 0)),
                _ => None,
            };
            return Some(match operator {
                ">=" => actual >= expected,
                "<=" => next_partial.map_or(actual <= expected, |upper| actual < upper),
                ">" => next_partial.map_or(actual > expected, |upper| actual >= upper),
                "<" => actual < expected,
                _ => unreachable!(),
            });
        }
    }

    if let Some(version) = token.strip_prefix('^') {
        let lower = version_floor(&requirement_parts(version)?)?;
        let upper = if lower.0 > 0 {
            (lower.0.checked_add(1)?, 0, 0)
        } else if lower.1 > 0 {
            (0, lower.1.checked_add(1)?, 0)
        } else {
            (0, 0, lower.2.checked_add(1)?)
        };
        return Some(actual >= lower && actual < upper);
    }
    if let Some(version) = token.strip_prefix('~') {
        let parts = requirement_parts(version)?;
        let lower = version_floor(&parts)?;
        let upper = if parts.len() >= 2 && parts[1].is_some() {
            (lower.0, lower.1.checked_add(1)?, 0)
        } else {
            (lower.0.checked_add(1)?, 0, 0)
        };
        return Some(actual >= lower && actual < upper);
    }

    let token = token.strip_prefix('=').unwrap_or(token);
    let parts = requirement_parts(token)?;
    if parts.first().is_some_and(Option::is_none) {
        return Some(true);
    }
    let lower = version_floor(&parts)?;
    if parts.len() == 1 || parts.get(1).is_some_and(Option::is_none) {
        return Some(actual >= lower && actual < (lower.0.checked_add(1)?, 0, 0));
    }
    if parts.len() == 2 || parts.get(2).is_some_and(Option::is_none) {
        return Some(actual >= lower && actual < (lower.0, lower.1.checked_add(1)?, 0));
    }
    Some(actual == lower)
}

#[cfg(any(not(windows), test))]
fn node_engine_matches(expression: &str, actual: (u32, u32, u32)) -> Result<bool, String> {
    let expression = expression.trim();
    if expression.is_empty() {
        return Err("package.json engines.node is empty".to_owned());
    }
    for alternative in expression.split("||") {
        let normalized = alternative.replace(',', " ");
        let tokens: Vec<&str> = normalized.split_whitespace().collect();
        if tokens.is_empty() {
            return Err(format!(
                "package.json engines.node {expression:?} is not a supported semver expression"
            ));
        }
        if let [lower, "-", upper] = tokens.as_slice() {
            let lower_parts = requirement_parts(lower).ok_or_else(|| {
                format!("package.json engines.node {expression:?} is not supported")
            })?;
            let lower = if lower_parts.first().is_some_and(Option::is_none) {
                None
            } else {
                Some(version_floor(&lower_parts).ok_or_else(|| {
                    format!("package.json engines.node {expression:?} is not supported")
                })?)
            };
            let upper_parts = requirement_parts(upper).ok_or_else(|| {
                format!("package.json engines.node {expression:?} is not supported")
            })?;
            let below_upper = if upper_parts.first().is_some_and(Option::is_none) {
                true
            } else {
                let upper = version_floor(&upper_parts).ok_or_else(|| {
                    format!("package.json engines.node {expression:?} is not supported")
                })?;
                let partial_at = upper_parts
                    .iter()
                    .position(Option::is_none)
                    .or((upper_parts.len() < 3).then_some(upper_parts.len()));
                if partial_at == Some(1) {
                    actual
                        < (
                            upper.0.checked_add(1).ok_or_else(|| {
                                format!("package.json engines.node {expression:?} overflows")
                            })?,
                            0,
                            0,
                        )
                } else if partial_at == Some(2) {
                    actual
                        < (
                            upper.0,
                            upper.1.checked_add(1).ok_or_else(|| {
                                format!("package.json engines.node {expression:?} overflows")
                            })?,
                            0,
                        )
                } else {
                    actual <= upper
                }
            };
            if lower.is_none_or(|lower| actual >= lower) && below_upper {
                return Ok(true);
            }
            continue;
        }
        let mut matches = true;
        for token in tokens {
            let Some(token_matches) = node_engine_token_matches(token, actual) else {
                return Err(format!(
                    "package.json engines.node {expression:?} is not a supported semver expression"
                ));
            };
            matches &= token_matches;
        }
        if matches {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(any(not(windows), test))]
fn package_node_engine(source: &Path) -> Result<Option<String>, String> {
    let path = source.join("package.json");
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let package: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("could not parse {}: {error}", path.display()))?;
    match package.pointer("/engines/node") {
        None => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(format!("{}: engines.node must be a string", path.display())),
    }
}

fn push_node_candidate(out: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !node_candidate_is_executable(&candidate) {
        return;
    }
    let canonical = std::fs::canonicalize(&candidate).unwrap_or(candidate);
    if !out.contains(&canonical) {
        out.push(canonical);
    }
}

fn node_candidate_is_executable(candidate: &Path) -> bool {
    if !candidate.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(candidate)
            .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn path_node_candidates(path: &std::ffi::OsStr) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    for directory in std::env::split_paths(path)
        .filter(|directory| directory.is_absolute())
        .take(64)
    {
        #[cfg(not(windows))]
        let candidate = directory.join("node");
        #[cfg(windows)]
        let candidate = directory.join("node.exe");
        if node_candidate_is_executable(&candidate) {
            push_node_candidate(&mut candidates, candidate);
            break;
        }
    }
    candidates
}

fn node_candidates() -> Result<(Vec<PathBuf>, bool), String> {
    if let Some(program) = std::env::var_os("FIREEMU_NODE") {
        let program = PathBuf::from(program);
        if !program.is_absolute() || !node_candidate_is_executable(&program) {
            return Err(format!(
                "FIREEMU_NODE names {}, which is not an executable file",
                program.display()
            ));
        }
        let mut candidates = Vec::new();
        push_node_candidate(&mut candidates, program);
        return Ok((candidates, true));
    }

    let mut candidates = std::env::var_os("PATH")
        .map(|path| path_node_candidates(&path))
        .unwrap_or_default();
    if let Some(home) = std::env::var_os("VOLTA_HOME") {
        let root = PathBuf::from(home).join("tools/image/node");
        if root.is_absolute() {
            if let Ok(entries) = std::fs::read_dir(root) {
                let mut entries: Vec<_> = entries.filter_map(Result::ok).take(64).collect();
                entries.sort_by_key(std::fs::DirEntry::file_name);
                for entry in entries {
                    #[cfg(not(windows))]
                    push_node_candidate(&mut candidates, entry.path().join("bin/node"));
                    #[cfg(windows)]
                    push_node_candidate(&mut candidates, entry.path().join("node.exe"));
                }
            }
        }
    }
    candidates.truncate(16);
    Ok((candidates, false))
}

#[cfg(not(windows))]
fn run_node_probe(program: &Path, arguments: &[&str], label: &str) -> Result<Vec<u8>, String> {
    const MAX_OUTPUT_BYTES: usize = 256;
    const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start Node {label}: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("Node {label} stdout unavailable"))?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take(257).read_to_end(&mut bytes);
        let _ = sender.send(bytes);
    });
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("could not wait for Node {label}: {error}"))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            #[cfg(unix)]
            let _ = Command::new("/bin/kill")
                .args(["-KILL", "--", &format!("-{}", child.id())])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("Node {label} timed out"));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    let output = receiver.recv_timeout(remaining).map_err(|_| {
        #[cfg(unix)]
        let _ = Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        format!("Node {label} timed out")
    })?;
    if !status.success() {
        return Err(format!("Node {label} exited with {status}"));
    }
    if output.len() > MAX_OUTPUT_BYTES {
        return Err(format!("Node {label} output exceeded 256 bytes"));
    }
    Ok(output)
}

#[cfg(not(windows))]
fn probe_node(program: &Path) -> Result<NodeInstallation, String> {
    let output = run_node_probe(program, &["--version"], "--version")?;
    let text = String::from_utf8_lossy(&output);
    let (version, major, minor, patch) = parse_node_version(&text)
        .ok_or_else(|| "Node --version returned an unrecognised version".to_owned())?;
    let feature = run_node_probe(
        program,
        &["-p", "String(process.features?.require_module === true)"],
        "loader feature probe",
    )?;
    let require_module = match String::from_utf8_lossy(&feature).trim() {
        "true" => true,
        "false" => false,
        _ => return Err("Node loader feature probe returned an unrecognised value".to_owned()),
    };
    Ok(NodeInstallation {
        program: program.to_path_buf(),
        version,
        major,
        minor,
        patch,
        require_module,
    })
}

#[cfg(any(not(windows), test))]
fn request_prefers_require_module(
    runtime_major: Option<u32>,
    engines: Option<&str>,
    installations: &[NodeInstallation],
) -> Result<bool, String> {
    if let Some(runtime_major) = runtime_major {
        return Ok(runtime_major >= 20);
    }
    let Some(engines) = engines else {
        return Ok(false);
    };
    for installation in installations {
        if installation.major >= 20
            && node_engine_matches(
                engines,
                (installation.major, installation.minor, installation.patch),
            )?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(any(not(windows), test))]
fn select_node_installation(
    runtime_major: Option<u32>,
    engines: Option<&str>,
    installations: &[NodeInstallation],
) -> Result<usize, String> {
    if installations.is_empty() {
        return Err("no usable Node executable was found on PATH or in VOLTA_HOME".to_owned());
    }
    let engine_matches = installations
        .iter()
        .map(|installation| {
            engines.map_or(Ok(true), |expression| {
                node_engine_matches(
                    expression,
                    (installation.major, installation.minor, installation.patch),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let prefer_require_module =
        request_prefers_require_module(runtime_major, engines, installations)?;
    let candidates = installations
        .iter()
        .enumerate()
        .map(
            |(index, installation)| fireemu_adapter_functions::node_selection::NodeCandidate {
                require_module: installation.require_module,
                runtime_matches: runtime_major.is_none_or(|major| installation.major == major),
                engine_matches: engine_matches[index],
            },
        )
        .collect::<Vec<_>>();
    fireemu_adapter_functions::node_selection::select_node_candidate(
        false,
        prefer_require_module,
        &candidates,
    )
    .ok_or_else(|| "no usable Node executable was found on PATH or in VOLTA_HOME".to_owned())
}

#[cfg(windows)]
fn default_runner_for_codebase(
    _codebase: &crate::config::FunctionsCodebase,
) -> Result<Vec<String>, String> {
    let script = locate_runner()?;
    let (candidates, _) = node_candidates()?;
    let program = candidates.first().ok_or_else(|| {
        "no Node executable was found in an absolute PATH directory; set FIREEMU_NODE to an absolute executable or configure functions.runner explicitly".to_owned()
    })?;
    Ok(vec![
        program.display().to_string(),
        script.path.display().to_string(),
    ])
}

#[cfg(not(windows))]
fn default_runner_for_codebase(
    codebase: &crate::config::FunctionsCodebase,
) -> Result<Vec<String>, String> {
    let script = locate_runner()?;
    let engines = package_node_engine(Path::new(&codebase.source))?;
    if let Some(expression) = engines.as_deref() {
        let _ = node_engine_matches(expression, (0, 0, 0))?;
    }
    let (candidates, explicit_node) = node_candidates()?;
    let runtime_major = codebase.runtime.as_deref().and_then(|runtime| {
        runtime
            .strip_prefix("nodejs")
            .and_then(|major| major.parse::<u32>().ok())
    });
    let mut installations = Vec::new();
    let mut probe_errors = Vec::new();
    for candidate in candidates {
        match probe_node(&candidate) {
            Ok(installation) => {
                installations.push(installation);
                if explicit_node {
                    break;
                }
            }
            Err(error) => probe_errors.push(error),
        }
    }
    if installations.is_empty() {
        let detail = if probe_errors.is_empty() {
            "no Node executable was found".to_owned()
        } else {
            probe_errors.join("; ")
        };
        return Err(format!(
            "the Functions codebase {:?}: {detail}; install Node, set FIREEMU_NODE, or configure functions.runner explicitly",
            codebase.codebase
        ));
    }
    let selected = if explicit_node {
        0
    } else {
        select_node_installation(runtime_major, engines.as_deref(), &installations)?
    };
    let installation = &installations[selected];
    let prefer_require_module =
        request_prefers_require_module(runtime_major, engines.as_deref(), &installations)?;
    if let Some(engines) = &engines {
        let matches_engine = node_engine_matches(
            engines,
            (installation.major, installation.minor, installation.patch),
        )?;
        if matches_engine {
            eprintln!(
                "note: functions[{}]: selected Node v{} for package.json engines.node {:?}{}",
                codebase.codebase,
                installation.version,
                engines,
                runtime_major
                    .filter(|major| *major != installation.major)
                    .map_or_else(String::new, |major| format!(
                        " (firebase runtime nodejs{major} is deployment metadata)"
                    ))
            );
        } else {
            eprintln!(
                "note: functions[{}]: selected Node v{} as a loader-capable local fallback; package.json engines.node {:?}{} does not include it",
                codebase.codebase,
                installation.version,
                engines,
                runtime_major.map_or_else(String::new, |major| format!(
                    " and firebase runtime nodejs{major}"
                ))
            );
        }
    } else if let Some(major) = runtime_major {
        if major != installation.major {
            eprintln!(
                "note: functions[{}]: firebase runtime nodejs{major} differs from local Node v{}; the local emulator uses the first usable Node on PATH",
                codebase.codebase, installation.version
            );
        }
    }
    if !installation.require_module && prefer_require_module {
        eprintln!(
            "note: functions[{}]: Node v{} cannot synchronously require ES modules from CommonJS; install Node 20.19+, Node 22.12+, or a newer release if module loading fails",
            codebase.codebase, installation.version
        );
    }
    Ok(vec![
        installation.program.display().to_string(),
        script.path.display().to_string(),
    ])
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
        None => default_runner_for_codebase(codebase)
            .map_err(|error| format!("the Functions codebase {label:?}: {error}"))?,
    };
    if let Some(port) = cfg.functions_inspect_port {
        command.insert(1, format!("--inspect={port}"));
    }
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
    // The official Functions emulator inherits the Firebase CLI process environment before
    // applying dotenv, system and emulator values. The firebase profile preserves that
    // behavior so wrappers such as `dotenv -- firebase emulators:exec` reach function code.
    // The strict profile keeps the runner isolated and receives only the explicit values
    // below. In both profiles, later entries override parent values in the official order.
    let mut env: Vec<(String, String)> = if cfg.profile == CompatibilityProfile::Firebase {
        inheritable_parent_environment()
    } else {
        Vec::new()
    };
    env.extend(user_env.applied());
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
    let runner = Arc::new(
        Runner::spawn_spec(&spec)
            .await
            .map_err(|e| format!("the Functions codebase {label:?}: {e}"))?,
    );
    let configured = (|| {
        let manifest_json = match &cfg.functions_manifest {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("functions manifest {path}: {e}"))?;
                serde_json::from_str(&text)
                    .map_err(|e| format!("functions manifest {path}: {e}"))?
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
                        if trigger.get("type").and_then(serde_json::Value::as_str)
                            == Some("schedule")
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
        for line in check_ignored(&manifest, policy)? {
            eprintln!("note: {line}");
        }
        if cfg.functions_manifest.is_some() {
            // A configured manifest replaces discovery outright. Security-sensitive trigger
            // classifications still come from code, so the replacement must reconcile with
            // what the runner discovered instead of being trusted blindly.
            let discovered = runner
                .hello()
                .manifest
                .clone()
                .ok_or_else(|| "the functions runner did not discover a manifest".to_owned())?;
            let discovered = parse_manifest(&discovered)?;
            check_manifest_agrees_on_blocking_auth(&manifest, &discovered)?;
            if callable_trusted_protocol {
                check_manifest_agrees_on_callables(&manifest, &discovered)?;
            }
        }
        check_callable_app_check(
            &manifest,
            runner.hello().app_check.as_ref(),
            callable_trusted_protocol,
        )?;
        Ok(fireemu_adapter_functions::runtime::CodebaseSpec {
            name: label.clone(),
            manifest,
            runner: runner.clone(),
            spawn: Some(spec),
            cleanup_dir: None,
        })
    })();
    if configured.is_err() {
        runner.kill_now();
    }
    configured
}

/// Refuses a configured manifest that removes or changes any discovered Blocking Auth hook.
///
/// Unlike an omitted HTTP endpoint, an omitted blocking hook makes authentication continue
/// without policy. Function name, region and event therefore form a bidirectional ordered
/// contract owned by discovery, even when a custom manifest controls other local options.
/// Order is significant because the runtime selects the first hook for an event.
fn check_manifest_agrees_on_blocking_auth(
    configured: &fireemu_core_functions::manifest::FunctionManifest,
    discovered: &fireemu_core_functions::manifest::FunctionManifest,
) -> Result<(), String> {
    use fireemu_core_functions::manifest::Trigger;

    let contract = |manifest: &fireemu_core_functions::manifest::FunctionManifest| {
        manifest
            .functions
            .iter()
            .filter_map(|function| match function.trigger {
                Trigger::BlockingAuth { event } => Some((
                    function.name.clone(),
                    function.region.clone(),
                    event.as_str(),
                )),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let configured = contract(configured);
    let discovered = contract(discovered);
    if configured != discovered {
        let mismatch = (0..configured.len().max(discovered.len()))
            .find(|index| configured.get(*index) != discovered.get(*index))
            .unwrap_or(0);
        return Err(match (discovered.get(mismatch), configured.get(mismatch)) {
            (Some((name, region, event)), None) => format!(
                "the configured functions manifest omits discovered Blocking Auth hook {name:?} \
                 in {region} for {event} at position {mismatch}; blocking policy cannot be \
                 bypassed by a custom manifest"
            ),
            (None, Some((name, region, event))) => format!(
                "the configured functions manifest invents Blocking Auth hook {name:?} in \
                 {region} for {event} at position {mismatch}; it must match codebase discovery"
            ),
            (Some(discovered), Some(configured)) => format!(
                "the configured functions manifest changes Blocking Auth hook order or identity \
                 at position {mismatch}: codebase discovery has {:?} in {} for {}, configured \
                 manifest has {:?} in {} for {}; blocking policy selection must match exactly",
                discovered.0, discovered.1, discovered.2, configured.0, configured.1, configured.2,
            ),
            (None, None) => unreachable!("different contracts have a mismatching position"),
        });
    }
    Ok(())
}

/// Refuses a configured manifest that disagrees with discovery about which HTTP functions are
/// callable.
///
/// Only the callable flag is reconciled. Other configured fields deliberately control local
/// routing and admission, but the callable flag decides which side of the trust boundary a
/// request lands on, and the runner is the only thing that actually knows.
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

const BLOCKING_AUTH_DEADLINE: Duration = Duration::from_secs(7);
const MAX_BLOCKING_AUTH_RESPONSE_BYTES: u64 = 64 * 1024;

fn blocking_auth_user_json(
    user: &fireemu_core_auth::store::UserRecord,
    tenant: Option<&str>,
) -> serde_json::Value {
    let provider_data = user
        .federated
        .iter()
        .map(|identity| {
            serde_json::json!({
                "uid": identity.raw_id,
                "displayName": identity.display_name,
                "email": identity.email,
                "photoURL": identity.photo_url,
                "providerId": identity.provider_id,
                "phoneNumber": null,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "uid": user.local_id.as_str(),
        "email": user.email,
        "emailVerified": user.email_verified,
        "displayName": user.display_name,
        "photoURL": user.photo_url,
        "phoneNumber": user.phone_number,
        "disabled": user.disabled,
        "customClaims": serde_json::from_str::<serde_json::Value>(&user.custom_claims.canonical_json()).unwrap_or_else(|_| serde_json::json!({})),
        "tenantId": tenant,
        "metadata": {
            "creationTime": fireemu_core_types::time::LogicalInstant::to_rfc3339(user.created_at).unwrap_or_default(),
            "lastSignInTime": user.last_sign_in_at.and_then(|instant| instant.to_rfc3339().ok()),
        },
        "providerData": provider_data,
    })
}

fn blocking_auth_resource_name(project: &str, tenant: Option<&str>) -> String {
    tenant.map_or_else(
        || format!("projects/{project}"),
        |tenant| format!("projects/{project}/tenants/{tenant}"),
    )
}

fn with_blocking_auth_project<T, E>(
    runtime_project: &str,
    request_project: &str,
    forward: impl FnOnce() -> Result<Option<T>, E>,
) -> Result<Option<T>, E> {
    if runtime_project != request_project {
        return Ok(None);
    }
    forward()
}

fn blocking_auth_io_failure(
    error: &std::io::Error,
) -> fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure::timeout()
    } else {
        fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure::unhandled()
    }
}

fn blocking_auth_remaining(
    deadline: Instant,
) -> Result<Duration, fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure::timeout)
}

fn blocking_auth_write_request(
    stream: &mut TcpStream,
    mut request: &[u8],
    deadline: Instant,
) -> Result<(), fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure> {
    use fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure;

    while !request.is_empty() {
        let remaining = blocking_auth_remaining(deadline)?;
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|_| BlockingFunctionFailure::unhandled())?;
        let written = stream
            .write(request)
            .map_err(|error| blocking_auth_io_failure(&error))?;
        if written == 0 {
            return Err(BlockingFunctionFailure::unhandled());
        }
        request = &request[written..];
    }
    Ok(())
}

fn blocking_auth_read_response(
    stream: &mut TcpStream,
    deadline: Instant,
) -> Result<Vec<u8>, fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure> {
    use fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure;

    let mut response = Vec::new();
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let remaining = blocking_auth_remaining(deadline)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| BlockingFunctionFailure::unhandled())?;
        let read = stream
            .read(&mut chunk)
            .map_err(|error| blocking_auth_io_failure(&error))?;
        if Instant::now() >= deadline {
            return Err(BlockingFunctionFailure::timeout());
        }
        if read == 0 {
            return Ok(response);
        }
        if response.len().saturating_add(read) as u64 > MAX_BLOCKING_AUTH_RESPONSE_BYTES {
            return Err(BlockingFunctionFailure::unhandled());
        }
        response.extend_from_slice(&chunk[..read]);
    }
}

fn blocking_auth_response_failure(
    status: u16,
    value: &serde_json::Value,
) -> fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure {
    use fireemu_adapter_http::identity_toolkit::{BlockingFunctionCode, BlockingFunctionFailure};

    let parsed = value
        .get("error")
        .and_then(serde_json::Value::as_object)
        .and_then(|error| {
            let code = error
                .get("status")
                .and_then(serde_json::Value::as_str)
                .and_then(BlockingFunctionCode::from_canonical_name)
                .filter(|code| code.function_status() == status)?;
            let message = error.get("message").and_then(serde_json::Value::as_str)?;
            BlockingFunctionFailure::from_function(code, message).ok()
        });
    parsed.unwrap_or_else(BlockingFunctionFailure::unhandled)
}

impl BlockingAuthBridge {
    fn invoke_for_namespace(
        &self,
        project: &str,
        tenant: Option<&str>,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<
        Option<serde_json::Value>,
        fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure,
    > {
        with_blocking_auth_project(self.0.project(), project, || {
            self.invoke_matching_namespace(project, tenant, event, user)
        })
    }

    fn invoke_matching_namespace(
        &self,
        project: &str,
        tenant: Option<&str>,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<
        Option<serde_json::Value>,
        fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure,
    > {
        use fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure;

        let Some(target) = self.0.blocking_auth_target(event) else {
            return Ok(None);
        };
        let user_json = blocking_auth_user_json(user, tenant);
        let resource_name = blocking_auth_resource_name(project, tenant);
        let body = serde_json::json!({
            "data": {
                "user": user_json,
                "context": {
                    "eventId": format!("fireemu-blocking-{}", self.0.trigger_generation()),
                    "eventType": event.as_str(),
                    "resource": {"service": "identitytoolkit.googleapis.com", "name": resource_name},
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
        let deadline = Instant::now() + BLOCKING_AUTH_DEADLINE;
        let address = target
            .addr
            .parse()
            .map_err(|_| BlockingFunctionFailure::unhandled())?;
        let mut stream = TcpStream::connect_timeout(&address, blocking_auth_remaining(deadline)?)
            .map_err(|error| blocking_auth_io_failure(&error))?;
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nX-Fireemu-Runner-Secret: {}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
            target.addr,
            target.secret,
            body.len(),
            body
        );
        blocking_auth_write_request(&mut stream, request.as_bytes(), deadline)?;
        let response = blocking_auth_read_response(&mut stream, deadline)?;
        let response = fireemu_adapter_functions::http::parse_response(&response, "POST")
            .map_err(|_| BlockingFunctionFailure::unhandled())?;
        let value: serde_json::Value = serde_json::from_slice(&response.body)
            .map_err(|_| BlockingFunctionFailure::unhandled())?;
        if response.status != 200 {
            return Err(blocking_auth_response_failure(response.status, &value));
        }
        if !value.is_object() {
            return Err(BlockingFunctionFailure::unhandled());
        }
        Ok(Some(value))
    }
}

impl fireemu_adapter_http::identity_toolkit::AuthBlockingHook for BlockingAuthBridge {
    fn invoke(
        &self,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<serde_json::Value, fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure>
    {
        self.invoke_for_namespace(self.0.project(), None, event, user)
            .map(|value| value.unwrap_or_else(|| serde_json::json!({})))
    }

    fn invoke_for(
        &self,
        project: &str,
        tenant: Option<&str>,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<
        Option<serde_json::Value>,
        fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure,
    > {
        self.invoke_for_namespace(project, tenant, event, user)
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
    use std::collections::BTreeMap;
    #[cfg(unix)]
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::path_node_candidates;
    #[cfg(unix)]
    use super::probe_node;
    use super::{
        blocking_auth_io_failure, blocking_auth_read_response, blocking_auth_response_failure,
        blocking_auth_write_request, check_callable_app_check, function_pubsub_resources,
        functions_source_signature, node_engine_matches, package_node_engine, parse_node_version,
        provision_function_pubsub_resources, select_node_installation, snapshot_functions_source,
        NodeInstallation, BLOCKING_AUTH_DEADLINE, MAX_BLOCKING_AUTH_RESPONSE_BYTES,
    };
    use fireemu_adapter_functions::manifest_json::parse_manifest;
    use fireemu_core_pubsub::{
        Filter, PubSubState, PushConfig, SubscriptionConfig, SubscriptionName, TopicName,
    };
    use serde_json::json;

    #[test]
    fn blocking_auth_user_uses_the_functions_sdk_record_shape() {
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthStore, NewUser};
        use fireemu_core_types::determinism::SplitMix64;
        use fireemu_core_types::time::LogicalInstant;

        let now = LogicalInstant::from_unix_seconds(1_788_004_860);
        let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let uid = store
            .create_user(NewUser::email("person@example.test"), now)
            .unwrap();

        let value = super::blocking_auth_user_json(
            store.user_by_id(uid.as_str()).unwrap(),
            Some("customer"),
        );

        assert_eq!(value["emailVerified"], false);
        assert!(value.get("email_verified").is_none());
        assert!(value.get("displayName").is_some());
        assert!(value.get("photoURL").is_some());
        assert!(value.get("phoneNumber").is_some());
        assert_eq!(value["customClaims"], json!({}));
        assert_eq!(value["tenantId"], "customer");
        assert!(value.get("providerData").is_some());
        assert_eq!(value["metadata"]["creationTime"], "2026-08-29T12:01:00Z");
        assert!(value["metadata"].get("lastSignInTime").is_some());
        assert_eq!(
            super::blocking_auth_resource_name("demo-app", Some("customer")),
            "projects/demo-app/tenants/customer"
        );
        let forwarded = std::cell::Cell::new(false);
        let value = super::with_blocking_auth_project("demo-app", "demo-worker", || {
            forwarded.set(true);
            Ok::<_, ()>(Some(json!({})))
        })
        .unwrap();
        assert!(value.is_none());
        assert!(!forwarded.get());

        let value = super::with_blocking_auth_project("demo-app", "demo-app", || {
            forwarded.set(true);
            Ok::<_, ()>(Some(json!({"accepted": true})))
        })
        .unwrap();
        assert_eq!(value, Some(json!({"accepted": true})));
        assert!(forwarded.get());
    }

    #[test]
    fn blocking_auth_transport_bounds_and_failure_pairs_are_production_bounded() {
        assert_eq!(BLOCKING_AUTH_DEADLINE, Duration::from_secs(7));
        assert_eq!(MAX_BLOCKING_AUTH_RESPONSE_BYTES, 64 * 1024);
        assert_eq!(
            blocking_auth_io_failure(&std::io::Error::from(std::io::ErrorKind::TimedOut))
                .identity_status(),
            503
        );
        assert_eq!(
            blocking_auth_io_failure(&std::io::Error::from(std::io::ErrorKind::ConnectionReset))
                .identity_status(),
            503
        );

        let permission = json!({
            "error": {"status": "PERMISSION_DENIED", "message": "policy rejected"}
        });
        assert_eq!(
            blocking_auth_response_failure(403, &permission).identity_status(),
            400
        );
        let explicit_deadline = json!({
            "error": {"status": "DEADLINE_EXCEEDED", "message": "explicit deadline"}
        });
        assert_eq!(
            blocking_auth_response_failure(504, &explicit_deadline).identity_status(),
            504
        );

        for (status, value) in [
            (
                418,
                json!({"error": {"status": "PERMISSION_DENIED", "message": "marker"}}),
            ),
            (
                403,
                json!({"error": {"status": "permission_denied", "message": "marker"}}),
            ),
            (
                403,
                json!({"error": {"status": "PERMISSION_DENIED", "message": 1}}),
            ),
            (
                403,
                json!({"error": {"status": "PERMISSION_DENIED", "message": "line\nmarker"}}),
            ),
            (
                403,
                json!({"error": {"status": "PERMISSION_DENIED", "message": "x".repeat(4_097)}}),
            ),
            (
                600,
                json!({"error": {"status": "UNAVAILABLE", "message": "marker"}}),
            ),
            (503, json!({"error": []})),
        ] {
            assert_eq!(
                blocking_auth_response_failure(status, &value).identity_status(),
                503,
                "status={status}, value={value}"
            );
        }
    }

    #[test]
    fn blocking_auth_response_uses_one_absolute_deadline_during_slow_drip() {
        use std::io::Write as _;
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let started = Instant::now();
        let failure = blocking_auth_read_response(&mut stream, started + Duration::from_millis(75))
            .unwrap_err();
        let elapsed = started.elapsed();
        drop(stream);
        writer.join().unwrap();

        assert_eq!(
            failure,
            fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure::timeout()
        );
        assert!(elapsed >= Duration::from_millis(60), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(300), "{elapsed:?}");
    }

    #[test]
    fn blocking_auth_request_writes_every_byte_before_the_deadline() {
        use std::io::Read as _;
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .unwrap();
            let mut received = [0_u8; 18];
            stream.read_exact(&mut received).map(|()| received)
        });
        let mut stream = TcpStream::connect(address).unwrap();

        blocking_auth_write_request(
            &mut stream,
            b"blocking-auth-body",
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(
            &receiver.join().unwrap().expect("request bytes must arrive"),
            b"blocking-auth-body"
        );
    }

    fn installed_node(version: &str, require_module: bool) -> NodeInstallation {
        let (_, major, minor, patch) = parse_node_version(version).unwrap();
        NodeInstallation {
            program: std::path::PathBuf::from(format!("/opt/node-{major}/bin/node")),
            version: version.trim_start_matches('v').to_owned(),
            major,
            minor,
            patch,
            require_module,
        }
    }

    #[test]
    fn loader_capability_precedes_runtime_and_engine_preferences() {
        let installations = vec![
            installed_node("v22.11.0", false),
            installed_node("v20.19.5", true),
            installed_node("v22.12.0", true),
        ];
        assert_eq!(
            select_node_installation(Some(22), Some("22"), &installations).unwrap(),
            2
        );
        assert_eq!(
            select_node_installation(None, Some("20"), &installations).unwrap(),
            1
        );
        assert_eq!(
            select_node_installation(None, Some(">=20.0.0 <21.0.0"), &installations).unwrap(),
            1
        );
        assert_eq!(
            select_node_installation(Some(22), Some("22"), &installations[..2]).unwrap(),
            1,
            "a capable local fallback wins over an incapable requested major"
        );

        let legacy = vec![
            installed_node("v20.19.5", true),
            installed_node("v18.20.0", false),
        ];
        assert_eq!(
            select_node_installation(Some(18), Some("18"), &legacy).unwrap(),
            1,
            "Node 18 requests retain their runtime semantics"
        );
        assert_eq!(
            select_node_installation(None, Some("18"), &legacy).unwrap(),
            1,
            "a legacy engine constraint does not inherit capability requirements from newer nodes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn automatic_path_discovery_trusts_only_the_first_node_executable() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "fireemu-node-path-discovery-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let non_executable = root.join("non-executable/node");
        let first = root.join("first/node");
        let second = root.join("second/node");
        for program in [&non_executable, &first, &second] {
            std::fs::create_dir_all(program.parent().unwrap()).unwrap();
            std::fs::write(program, "#!/bin/sh\nexit 0\n").unwrap();
        }
        std::fs::set_permissions(&non_executable, std::fs::Permissions::from_mode(0o600)).unwrap();
        for program in [&first, &second] {
            std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = std::env::join_paths([
            root.join("missing"),
            non_executable.parent().unwrap().to_owned(),
            first.parent().unwrap().to_owned(),
            second.parent().unwrap().to_owned(),
        ])
        .unwrap();

        assert_eq!(
            path_node_candidates(&path),
            vec![std::fs::canonicalize(&first).unwrap()]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn node_engine_parser_checks_ranges_and_alternatives() {
        for expression in [
            "*",
            "x",
            "20",
            "20.x",
            "^20.0.0",
            "~20",
            ">=20 <21",
            "18 || 20",
            "20.0.0 - 22.11.0",
        ] {
            assert!(
                node_engine_matches(expression, (20, 19, 5)).unwrap(),
                "{expression}"
            );
        }
        assert!(node_engine_matches(">=18", (22, 11, 0)).unwrap());
        assert!(!node_engine_matches("20.20.x", (20, 19, 5)).unwrap());
        assert!(node_engine_matches("20.19.5", (20, 19, 5)).unwrap());
        assert!(!node_engine_matches("20.19.5", (20, 19, 6)).unwrap());
        assert!(node_engine_matches("^0.2.3", (0, 2, 9)).unwrap());
        assert!(node_engine_matches("~20.19.0", (20, 19, 5)).unwrap());
        assert!(node_engine_matches("<=20", (20, 19, 5)).unwrap());
        assert!(!node_engine_matches(">20", (20, 19, 5)).unwrap());
        assert!(node_engine_matches("20 - 22", (22, 11, 0)).unwrap());
        assert!(node_engine_matches("<=20.x", (20, 19, 5)).unwrap());
        assert!(!node_engine_matches(">20.x", (20, 19, 5)).unwrap());
        assert!(node_engine_matches("20 - 22.x", (22, 11, 0)).unwrap());
        assert!(node_engine_matches("20 - x", (99, 0, 0)).unwrap());
        assert!(node_engine_matches("x - 22", (1, 0, 0)).unwrap());
        assert!(node_engine_matches("", (20, 19, 5)).is_err());
        assert!(node_engine_matches("not-semver", (20, 19, 5)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn node_probe_times_out_when_a_descendant_keeps_stdout_open() {
        use std::os::unix::fs::PermissionsExt;

        let root =
            std::env::temp_dir().join(format!("fireemu-node-probe-timeout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let program = root.join("node");
        let pid_file = root.join("descendant.pid");
        let script = format!(
            "#!/bin/sh\n(/bin/sleep 30) &\necho $! > '{}'\necho v22.11.0\n",
            pid_file.display()
        );
        std::fs::write(&program, script).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();

        let started = Instant::now();
        let error = probe_node(&program).unwrap_err();
        assert!(error.contains("timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(3));
        let pid = std::fs::read_to_string(&pid_file).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(!Command::new("/bin/kill")
            .args(["-0", pid.trim()])
            .status()
            .unwrap()
            .success());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_node_discovery_uses_only_absolute_path_candidates() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-windows-node-discovery-{}",
            std::process::id()
        ));
        let current = root.join("current");
        let bin = root.join("bin");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&current).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        let current_node = current.join("node.exe");
        let path_node = bin.join("node.exe");
        std::fs::write(&current_node, b"current directory executable").unwrap();
        std::fs::write(&path_node, b"PATH executable").unwrap();
        let path = std::env::join_paths([&bin]).unwrap();

        let candidates = path_node_candidates(&path);

        assert_eq!(candidates, vec![std::fs::canonicalize(path_node).unwrap()]);
        assert!(!candidates.contains(&std::fs::canonicalize(current_node).unwrap()));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn package_node_engine_is_read_without_treating_it_as_an_executable() {
        let root =
            std::env::temp_dir().join(format!("fireemu-node-engine-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"engines":{"node":"20"},"scripts":{"node":"/tmp/not-an-executable"}}"#,
        )
        .unwrap();
        assert_eq!(package_node_engine(&root).unwrap().as_deref(), Some("20"));
        std::fs::remove_dir_all(root).unwrap();
    }

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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&snapshot).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
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
        assert!(root.join("node_modules/pkg/index.js").is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn reload_snapshot_rejects_source_symlinks_instead_of_silently_omitting_them() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "fireemu-functions-snapshot-symlink-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("lib")).unwrap();
        std::fs::write(root.join("lib/index.js"), "export const value = 1;").unwrap();
        symlink("index.js", root.join("lib/alias.js")).unwrap();

        let error = snapshot_functions_source(&root, &[]).unwrap_err();
        assert!(error.contains("symbolic link"), "unexpected error: {error}");
        assert!(error.contains("lib/alias.js"), "unexpected error: {error}");

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

    #[test]
    fn pubsub_resources_cover_shared_topics_and_schedules_once() {
        let manifest = parse_manifest(&json!({"functions": [
            {"name": "workerOne", "trigger": {"type": "pubsub", "topic": "shared-jobs"}},
            {"name": "workerTwo", "trigger": {"type": "pubsub", "topic": "shared-jobs"}, "region": "europe-west1"},
            {"name": "dailyReport", "trigger": {"type": "schedule", "schedule": "0 0 * * *"}},
            {"name": "health", "trigger": {"type": "http"}}
        ]})).unwrap();

        let resources = function_pubsub_resources("demo-app", &manifest).unwrap();
        let actual: Vec<(String, String)> = resources
            .iter()
            .map(|resource| (resource.topic.to_full(), resource.subscription.to_full()))
            .collect();
        assert_eq!(
            actual,
            vec![
                (
                    "projects/demo-app/topics/firebase-schedule-dailyReport".to_owned(),
                    "projects/demo-app/subscriptions/emulator-sub-firebase-schedule-dailyReport"
                        .to_owned(),
                ),
                (
                    "projects/demo-app/topics/shared-jobs".to_owned(),
                    "projects/demo-app/subscriptions/emulator-sub-shared-jobs".to_owned(),
                ),
            ]
        );
    }

    #[test]
    fn provisioning_function_pubsub_resources_is_idempotent_and_checks_existing_links() {
        let manifest = parse_manifest(&json!({"functions": [
            {"name": "worker", "trigger": {"type": "pubsub", "topic": "shared-jobs"}}
        ]}))
        .unwrap();
        let resources = function_pubsub_resources("demo-app", &manifest).unwrap();
        let mut state = PubSubState::new(7);

        provision_function_pubsub_resources(&mut state, &resources).unwrap();
        provision_function_pubsub_resources(&mut state, &resources).unwrap();
        assert_eq!(state.list_topics("demo-app").len(), 1);
        assert_eq!(state.list_subscriptions("demo-app").len(), 1);

        let mut conflicting = PubSubState::new(8);
        let expected_topic = TopicName::new("demo-app", "shared-jobs").unwrap();
        let other_topic = TopicName::new("demo-app", "other-jobs").unwrap();
        conflicting
            .create_topic(expected_topic, BTreeMap::new())
            .unwrap();
        conflicting
            .create_topic(other_topic.clone(), BTreeMap::new())
            .unwrap();
        conflicting
            .create_subscription(SubscriptionConfig {
                name: SubscriptionName::new("demo-app", "emulator-sub-shared-jobs").unwrap(),
                topic: other_topic,
                ack_deadline_seconds:
                    fireemu_core_pubsub::subscription::DEFAULT_ACK_DEADLINE_SECONDS,
                enable_message_ordering: false,
                filter: Filter::always(),
                dead_letter_policy: None,
                retry_policy: None,
                push_config: PushConfig::default(),
            })
            .unwrap();

        let error = provision_function_pubsub_resources(&mut conflicting, &resources).unwrap_err();
        assert!(error.contains("emulator-sub-shared-jobs"), "{error}");
        assert!(error.contains("other-jobs"), "{error}");
        assert_eq!(conflicting.list_topics("demo-app").len(), 2);
        assert_eq!(conflicting.list_subscriptions("demo-app").len(), 1);
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

    #[test]
    fn a_configured_manifest_cannot_bypass_or_reclassify_blocking_auth() {
        let discovered = parse_manifest(&json!({
            "functions": [
                {"name": "guardCreate", "region": "us-central1", "trigger": {
                    "type": "blockingAuth", "eventType": "beforeCreate"
                }},
                {"name": "guardSignIn", "region": "europe-west1", "trigger": {
                    "type": "blockingAuth", "eventType": "beforeSignIn"
                }}
            ]
        }))
        .unwrap();
        for (configured, expected) in [
            (
                json!({"functions": [{"name": "guardCreate", "region": "us-central1", "trigger": {
                    "type": "blockingAuth", "eventType": "beforeCreate"
                }}]}),
                "guardSignIn",
            ),
            (
                json!({"functions": [
                    {"name": "guardCreate", "region": "us-central1", "trigger": {
                        "type": "http", "callable": false
                    }},
                    {"name": "guardSignIn", "region": "europe-west1", "trigger": {
                        "type": "blockingAuth", "eventType": "beforeSignIn"
                    }}
                ]}),
                "guardCreate",
            ),
            (
                json!({"functions": [
                    {"name": "guardCreate", "region": "us-central1", "trigger": {
                        "type": "blockingAuth", "eventType": "beforeSignIn"
                    }},
                    {"name": "guardSignIn", "region": "europe-west1", "trigger": {
                        "type": "blockingAuth", "eventType": "beforeCreate"
                    }}
                ]}),
                "beforeCreate",
            ),
            (
                json!({"functions": [
                    {"name": "guardCreate", "region": "asia-northeast1", "trigger": {
                        "type": "blockingAuth", "eventType": "beforeCreate"
                    }},
                    {"name": "guardSignIn", "region": "europe-west1", "trigger": {
                        "type": "blockingAuth", "eventType": "beforeSignIn"
                    }}
                ]}),
                "us-central1",
            ),
        ] {
            let configured = parse_manifest(&configured).unwrap();
            let error = super::check_manifest_agrees_on_blocking_auth(&configured, &discovered)
                .expect_err("a custom manifest must preserve every discovered blocking hook");
            assert!(error.contains(expected), "{error}");
        }

        super::check_manifest_agrees_on_blocking_auth(&discovered, &discovered)
            .expect("an exact Blocking Auth contract starts");

        let duplicate_event = parse_manifest(&json!({
            "functions": [
                {"name": "firstCreateGuard", "trigger": {
                    "type": "blockingAuth", "eventType": "beforeCreate"
                }},
                {"name": "secondCreateGuard", "trigger": {
                    "type": "blockingAuth", "eventType": "beforeCreate"
                }}
            ]
        }))
        .unwrap();
        let reordered = parse_manifest(&json!({
            "functions": [
                {"name": "secondCreateGuard", "trigger": {
                    "type": "blockingAuth", "eventType": "beforeCreate"
                }},
                {"name": "firstCreateGuard", "trigger": {
                    "type": "blockingAuth", "eventType": "beforeCreate"
                }}
            ]
        }))
        .unwrap();
        let error = super::check_manifest_agrees_on_blocking_auth(&reordered, &duplicate_event)
            .expect_err("custom manifest ordering must not select a different first hook");
        assert!(error.contains("firstCreateGuard"), "{error}");
        assert!(error.contains("secondCreateGuard"), "{error}");
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
