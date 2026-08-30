//! Runtime configuration: the canonical JSON config (spec 17) plus command-line overrides.
//!
//! Only the keys the daemon currently honours are read; unknown keys are still rejected so
//! that typos never silently change behaviour (the JSON schema in `spec/config` is the
//! authority; this loader enforces the same rule on the subset it understands).

use std::path::Path;

use ftd_core_firestore::index::IndexValidationPolicy;
use ftd_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use ftd_core_types::time::LogicalInstant;
use serde_json::Value;

/// Effective daemon configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// Firestore gRPC bind address.
    pub firestore_addr: String,
    /// HTTP (Auth REST + control API) bind address.
    pub http_addr: String,
    /// Storage bind address.
    pub storage_addr: String,
    /// Firestore edition.
    pub edition: FirestoreEdition,
    /// API mode.
    pub api_mode: FirestoreApiMode,
    /// Index validation policy.
    pub index_policy: IndexValidationPolicy,
    /// Only `demo-` project IDs are accepted.
    pub require_demo_prefix: bool,
    /// Initial virtual clock instant.
    pub clock_start: LogicalInstant,
    /// Whether `daemon.clockStart` pinned it. Without it the daemon starts its virtual
    /// clock at the wall-clock time, so tokens it issues are valid for SDKs that check
    /// expiry against real time (the Admin SDK's `verifyIdToken`); a pinned start keeps
    /// runs reproducible.
    pub clock_start_pinned: bool,
    /// Deterministic seed.
    pub seed: u64,
    /// Project ID used for Auth token issuance.
    pub auth_project: String,
    /// Path of `firestore.indexes.json`, if configured.
    pub index_file: Option<String>,
    /// Path of `firestore.text-indexes.json`, if configured.
    pub text_index_file: Option<String>,
    /// Path of the Security Rules source, if configured.
    pub rules_file: Option<String>,
    /// Path of the Storage Security Rules source, if configured.
    pub storage_rules_file: Option<String>,
    /// Whether Security Rules are enforced on the Firestore surface.
    pub rules_enforced: bool,
    /// Functions HTTP bind address.
    pub functions_addr: String,
    /// Functions codebase directory (`functions.source`); `None` = no functions runtime.
    pub functions_source: Option<String>,
    /// Runner command (`functions.runner`); default: the bundled Node runner.
    pub functions_runner: Option<Vec<String>>,
    /// Explicit manifest path (`functions.manifest`); default: runner discovery.
    pub functions_manifest: Option<String>,
    /// Maximum invocations running at once (`functions.maxGlobalConcurrency`).
    pub functions_max_running: usize,
    /// Attempts per event for functions declared with `retry` (`events.maxAttempts`).
    pub events_max_attempts: u32,
    /// Schedule runs enqueued per clock change and job (`scheduler.maxCatchUpRuns`).
    pub scheduler_max_catch_up_runs: usize,
    /// Default time zone of schedules without one (`scheduler.defaultTimeZone`).
    pub scheduler_default_time_zone: Option<String>,
    /// Catch-up policy of schedules (`scheduler.catchUp`: all, latest, none).
    pub scheduler_catch_up: String,
    /// Overlap policy of schedules (`scheduler.overlap`).
    pub scheduler_overlap: String,
    /// ID token signing (`auth.idTokenSigning`): `unsigned-emulator` or `session-rsa`.
    pub id_token_signing: ftd_core_auth::jwt::SigningMode,
    /// App Check (`appCheck`); disabled by default.
    pub app_check: AppCheckConfig,
}

/// `appCheck.tokenSigning`. Only `instance-rsa` exists: the App Check key belongs to the
/// daemon instance, not to the reproducible session seed, and unsigned modes are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppCheckSigning {
    /// A dedicated RSA key per daemon instance, drawn from the operating system CSPRNG.
    #[default]
    InstanceRsa,
}

impl AppCheckSigning {
    /// Parses the canonical configuration value.
    #[must_use]
    pub fn parse_config(text: &str) -> Option<Self> {
        match text {
            "instance-rsa" => Some(Self::InstanceRsa),
            _ => None,
        }
    }
}

/// One `appCheck.apps[]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppCheckApp {
    /// `projectId`.
    pub project_id: String,
    /// `projectNumber`.
    pub project_number: String,
    /// `appId`.
    pub app_id: String,
    /// `enabled`, defaulting to true.
    pub enabled: bool,
    /// `debugTokenSha256`: lowercase 64-character SHA-256 digests. Raw secrets are forbidden.
    pub debug_token_sha256: Vec<String>,
}

/// The products whose baseline mode `appCheck.services` configures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppCheckService {
    /// End-user Identity Toolkit and Secure Token operations.
    Auth,
    /// Cloud Firestore.
    Firestore,
    /// Cloud Storage for Firebase.
    Storage,
}

/// The `appCheck` section.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AppCheckConfig {
    /// `enabled`; false keeps every existing configuration behaving as it does today.
    pub enabled: bool,
    /// `tokenSigning`.
    pub token_signing: AppCheckSigning,
    /// `tokenTtlSeconds`.
    pub token_ttl_seconds: i64,
    /// `apps`.
    pub apps: Vec<AppCheckApp>,
    /// `services.auth`.
    pub auth: ftd_core_app_check::verify::BaselineMode,
    /// `services.firestore`.
    pub firestore: ftd_core_app_check::verify::BaselineMode,
    /// `services.storage`.
    pub storage: ftd_core_app_check::verify::BaselineMode,
}

impl AppCheckConfig {
    /// The disabled default: no exchange, no JWKS, every product baseline `off`.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            token_signing: AppCheckSigning::InstanceRsa,
            token_ttl_seconds: ftd_core_app_check::limits::DEFAULT_TOKEN_TTL_SECONDS,
            apps: Vec::new(),
            auth: ftd_core_app_check::verify::BaselineMode::Off,
            firestore: ftd_core_app_check::verify::BaselineMode::Off,
            storage: ftd_core_app_check::verify::BaselineMode::Off,
        }
    }

    /// The configured mode of one product, before service selection is applied.
    #[must_use]
    pub const fn configured_mode(
        &self,
        service: AppCheckService,
    ) -> ftd_core_app_check::verify::BaselineMode {
        match service {
            AppCheckService::Auth => self.auth,
            AppCheckService::Firestore => self.firestore,
            AppCheckService::Storage => self.storage,
        }
    }

    /// The registrations the runtime registry is built from. Every binding rule of section 8
    /// is checked by the core registry, so the loader and the runtime cannot disagree.
    pub fn registrations(&self) -> Result<Vec<ftd_core_app_check::AppRegistration>, ConfigError> {
        let mut out = Vec::with_capacity(self.apps.len());
        for app in &self.apps {
            let mut digests = Vec::with_capacity(app.debug_token_sha256.len());
            for text in &app.debug_token_sha256 {
                digests.push(
                    ftd_core_app_check::DebugTokenDigest::parse_hex(text).map_err(|e| {
                        ConfigError(format!(
                            "appCheck.apps[{}].debugTokenSha256: {e}",
                            app.app_id
                        ))
                    })?,
                );
            }
            out.push(ftd_core_app_check::AppRegistration {
                project_id: app.project_id.clone(),
                project_number: app.project_number.clone(),
                app_id: app.app_id.clone(),
                enabled: app.enabled,
                debug_token_digests: digests,
            });
        }
        Ok(out)
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            firestore_addr: "127.0.0.1:8080".to_owned(),
            http_addr: "127.0.0.1:9099".to_owned(),
            storage_addr: "127.0.0.1:9199".to_owned(),
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            index_policy: IndexValidationPolicy::Conservative,
            require_demo_prefix: true,
            clock_start: LogicalInstant::from_unix_seconds(1_788_004_860),
            clock_start_pinned: false,
            seed: 42,
            auth_project: "demo-app".to_owned(),
            index_file: None,
            text_index_file: None,
            rules_file: None,
            storage_rules_file: None,
            rules_enforced: true,
            functions_addr: "127.0.0.1:5001".to_owned(),
            functions_source: None,
            functions_runner: None,
            functions_manifest: None,
            functions_max_running: 8,
            events_max_attempts: 4,
            scheduler_max_catch_up_runs: 1000,
            scheduler_default_time_zone: None,
            scheduler_overlap: "allow".to_owned(),
            scheduler_catch_up: "all".to_owned(),
            id_token_signing: ftd_core_auth::jwt::SigningMode::UnsignedEmulator,
            app_check: AppCheckConfig::disabled(),
        }
    }
}

/// The keys of the `auth` section (spec/config/firebase-testd.schema.json).
const AUTH_KEYS: [&str; 5] = [
    "enabled",
    "projectIssuer",
    "idTokenSigning",
    "totp",
    "secretMaterialization",
];

/// Configuration errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

/// The services `exec` exports to its child
/// (`--only auth,firestore,storage,functions,appcheck`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one flag per service, read independently
pub struct Selection {
    /// `FIRESTORE_EMULATOR_HOST`.
    pub firestore: bool,
    /// `FIREBASE_AUTH_EMULATOR_HOST`.
    pub auth: bool,
    /// `FIREBASE_STORAGE_EMULATOR_HOST` / `STORAGE_EMULATOR_HOST`.
    pub storage: bool,
    /// The functions codebase is loaded and `FTD_FUNCTIONS_HOST` exported.
    pub functions: bool,
    /// App Check: a logical selection, because the exchange and the JWKS share the
    /// Auth/control listener. Exports `FTD_APP_CHECK_EMULATOR_HOST` and
    /// `FTD_APP_CHECK_JWKS_URL`.
    pub appcheck: bool,
}

impl Default for Selection {
    fn default() -> Self {
        Self {
            firestore: true,
            auth: true,
            storage: true,
            functions: true,
            appcheck: true,
        }
    }
}

impl Selection {
    /// Parses the `--only` list (`firebase emulators:exec --only` names, plus `appcheck`).
    pub fn parse(list: &str) -> Result<Self, ConfigError> {
        let mut sel = Self {
            firestore: false,
            auth: false,
            storage: false,
            functions: false,
            appcheck: false,
        };
        for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
            match name {
                "firestore" => sel.firestore = true,
                "auth" => sel.auth = true,
                "storage" => sel.storage = true,
                "functions" => sel.functions = true,
                "appcheck" => sel.appcheck = true,
                other => {
                    return Err(ConfigError(format!(
                        "--only: unknown service {other:?} (firestore, auth, storage, functions, appcheck)"
                    )))
                }
            }
        }
        Ok(sel)
    }

    /// Whether the App Check exchange and JWKS routes are served (the activation table of
    /// section 8). Selecting `functions` implicitly selects its App Check dependency.
    #[must_use]
    pub const fn app_check_available(&self, cfg: &AppCheckConfig) -> bool {
        cfg.enabled && (self.appcheck || self.functions)
    }

    /// The effective baseline mode of one product: a configured mode applies only while App
    /// Check is available and the product itself is selected. Everything else is `off`.
    #[must_use]
    pub const fn app_check_mode(
        &self,
        cfg: &AppCheckConfig,
        service: AppCheckService,
    ) -> ftd_core_app_check::verify::BaselineMode {
        if !self.app_check_available(cfg) {
            return ftd_core_app_check::verify::BaselineMode::Off;
        }
        let selected = match service {
            AppCheckService::Auth => self.auth,
            AppCheckService::Firestore => self.firestore,
            AppCheckService::Storage => self.storage,
        };
        if selected {
            cfg.configured_mode(service)
        } else {
            ftd_core_app_check::verify::BaselineMode::Off
        }
    }
}

impl RuntimeConfig {
    /// Applies the parts of a `firebase.json` the daemon can honour: `firestore.rules`,
    /// `firestore.indexes` (also the `index` spelling), `storage.rules`, `emulators.*.port`
    /// and, when functions are selected, `functions.source` (the first codebase). Paths are
    /// relative to `base`. Returns the emulator entries it ignored, for a notice.
    pub fn apply_firebase_json(
        &mut self,
        json: &Value,
        base: &std::path::Path,
        only: &Selection,
    ) -> Result<Vec<String>, ConfigError> {
        let obj = json
            .as_object()
            .ok_or_else(|| ConfigError("firebase.json must be an object".to_owned()))?;
        let file = |v: &Value, key: &str| -> Result<String, ConfigError> {
            let p = v
                .as_str()
                .ok_or_else(|| ConfigError(format!("firebase.json: {key} must be a string")))?;
            Ok(base.join(p).to_string_lossy().into_owned())
        };
        if let Some(fs) = obj.get("firestore") {
            let fs = fs.as_object().ok_or_else(|| {
                ConfigError("firebase.json: firestore must be an object".to_owned())
            })?;
            if let Some(v) = fs.get("rules") {
                self.rules_file = Some(file(v, "firestore.rules")?);
            }
            if let Some(v) = fs.get("indexes").or_else(|| fs.get("index")) {
                self.index_file = Some(file(v, "firestore.indexes")?);
            }
        }
        if let Some(v) = obj.get("storage").and_then(|s| s.get("rules")) {
            self.storage_rules_file = Some(file(v, "storage.rules")?);
        }
        if only.functions {
            let source = match obj.get("functions") {
                Some(Value::Object(f)) => f.get("source"),
                Some(Value::Array(codebases)) => codebases.first().and_then(|c| c.get("source")),
                _ => None,
            };
            if let Some(v) = source {
                self.functions_source = Some(file(v, "functions.source")?);
            }
        }
        let mut ignored = Vec::new();
        if let Some(emulators) = obj.get("emulators").and_then(Value::as_object) {
            for (name, entry) in emulators {
                let port = entry.get("port").and_then(Value::as_u64);
                let port = match port {
                    Some(p) => u16::try_from(p).map_err(|_| {
                        ConfigError(format!("firebase.json: emulators.{name}.port out of range"))
                    })?,
                    None => continue,
                };
                let addr = format!("127.0.0.1:{port}");
                match name.as_str() {
                    "firestore" => self.firestore_addr = addr,
                    "auth" => self.http_addr = addr,
                    "storage" => self.storage_addr = addr,
                    "functions" => self.functions_addr = addr,
                    _ => ignored.push(format!("emulators.{name}")),
                }
            }
        }
        Ok(ignored)
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

const KNOWN_TOP_LEVEL: &[&str] = &[
    "schemaVersion",
    "profile",
    "bind",
    "projects",
    "limits",
    "firestore",
    "rules",
    "auth",
    "appCheck",
    "storage",
    "events",
    "scheduler",
    "functions",
    "trace",
    "daemon",
];

impl RuntimeConfig {
    /// Loads the canonical JSON config file.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError(format!("{}: {e}", path.display())))?;
        let json: Value = serde_json::from_str(&text)
            .map_err(|e| ConfigError(format!("{}: {e}", path.display())))?;
        Self::from_json(&json)
    }

    fn parse_daemon(d: &serde_json::Map<String, Value>, cfg: &mut Self) -> Result<(), ConfigError> {
        for key in d.keys() {
            if ![
                "firestorePort",
                "storagePort",
                "httpPort",
                "functionsPort",
                "clockStart",
                "seed",
                "authProject",
            ]
            .contains(&key.as_str())
            {
                return Err(ConfigError(format!("unknown config key daemon.{key}")));
            }
        }
        if let Some(port) = d.get("storagePort").and_then(Value::as_u64) {
            cfg.storage_addr = format!("127.0.0.1:{port}");
        }
        if let Some(port) = d.get("firestorePort").and_then(Value::as_u64) {
            cfg.firestore_addr = format!("127.0.0.1:{port}");
        }
        if let Some(port) = d.get("httpPort").and_then(Value::as_u64) {
            cfg.http_addr = format!("127.0.0.1:{port}");
        }
        if let Some(port) = d.get("functionsPort").and_then(Value::as_u64) {
            cfg.functions_addr = format!("127.0.0.1:{port}");
        }
        if let Some(start) = d.get("clockStart").and_then(Value::as_str) {
            cfg.clock_start_pinned = true;
            cfg.clock_start = LogicalInstant::parse_rfc3339(start)
                .map_err(|e| ConfigError(format!("daemon.clockStart: {e}")))?;
        }
        if let Some(seed) = d.get("seed").and_then(Value::as_u64) {
            cfg.seed = seed;
        }
        if let Some(p) = d.get("authProject").and_then(Value::as_str) {
            p.clone_into(&mut cfg.auth_project);
        }

        Ok(())
    }

    fn parse_rules(
        rules: &serde_json::Map<String, Value>,
        cfg: &mut Self,
    ) -> Result<(), ConfigError> {
        if let Some(source) = rules.get("source").and_then(Value::as_str) {
            cfg.rules_file = Some(source.to_owned());
        }
        match rules.get("executionMode").and_then(Value::as_str) {
            None | Some("native" | "admin-bypass") => Ok(()),
            Some("disabled") => {
                cfg.rules_enforced = false;
                Ok(())
            }
            Some(other) => Err(ConfigError(format!(
                "rules.executionMode {other:?} is declared but not implemented; use \"native\" or \"disabled\""
            ))),
        }
    }

    fn parse_events(e: &serde_json::Map<String, Value>, cfg: &mut Self) -> Result<(), ConfigError> {
        for key in e.keys() {
            if !["delivery", "maxAttempts"].contains(&key.as_str()) {
                return Err(ConfigError(format!("unknown config key events.{key}")));
            }
        }
        match e.get("delivery").and_then(Value::as_str) {
            None | Some("exactly-once-test") => {}
            Some(other) => {
                return Err(ConfigError(format!(
                    "events.delivery {other:?} is declared but not implemented; use \"exactly-once-test\""
                )))
            }
        }
        if let Some(n) = e.get("maxAttempts").and_then(Value::as_u64) {
            cfg.events_max_attempts = u32::try_from(n).unwrap_or(u32::MAX).max(1);
        }
        Ok(())
    }

    fn parse_scheduler(
        s: &serde_json::Map<String, Value>,
        cfg: &mut Self,
    ) -> Result<(), ConfigError> {
        for key in s.keys() {
            if ![
                "clock",
                "defaultTimeZone",
                "catchUp",
                "maxCatchUpRuns",
                "overlap",
            ]
            .contains(&key.as_str())
            {
                return Err(ConfigError(format!("unknown config key scheduler.{key}")));
            }
        }
        if let Some(v) = s.get("overlap") {
            let text = v.as_str().unwrap_or("");
            if !["allow", "skip", "queue", "reject"].contains(&text) {
                return Err(ConfigError(
                    "scheduler.overlap must be one of allow, skip, queue, reject".into(),
                ));
            }
            text.clone_into(&mut cfg.scheduler_overlap);
        }
        if let Some(v) = s.get("catchUp") {
            let text = v.as_str().unwrap_or("");
            if !["all", "latest", "none"].contains(&text) {
                return Err(ConfigError(
                    "scheduler.catchUp must be one of all, latest, none".into(),
                ));
            }
            text.clone_into(&mut cfg.scheduler_catch_up);
        }
        match s.get("clock").and_then(Value::as_str) {
            None | Some("virtual") => {}
            Some(other) => {
                return Err(ConfigError(format!(
                    "scheduler.clock {other:?} is declared but not implemented; use \"virtual\""
                )))
            }
        }
        if let Some(v) = s.get("maxCatchUpRuns") {
            let n = v
                .as_u64()
                .filter(|n| (1..=100_000).contains(n))
                .ok_or_else(|| {
                    ConfigError(
                        "scheduler.maxCatchUpRuns must be an integer from 1 to 100000".into(),
                    )
                })?;
            cfg.scheduler_max_catch_up_runs = usize::try_from(n).unwrap_or(1000);
        }
        if let Some(tz) = s.get("defaultTimeZone").and_then(Value::as_str) {
            ftd_adapter_functions::zone::resolve(Some(tz))
                .map_err(|e| ConfigError(format!("scheduler.defaultTimeZone: {e}")))?;
            cfg.scheduler_default_time_zone = Some(tz.to_owned());
        }
        Ok(())
    }

    fn parse_functions(
        f: &serde_json::Map<String, Value>,
        cfg: &mut Self,
    ) -> Result<(), ConfigError> {
        for key in f.keys() {
            if !["manifest", "source", "runner", "maxGlobalConcurrency"].contains(&key.as_str()) {
                return Err(ConfigError(format!("unknown config key functions.{key}")));
            }
        }
        if let Some(m) = f.get("manifest").and_then(Value::as_str) {
            cfg.functions_manifest = Some(m.to_owned());
        }
        if let Some(src) = f.get("source").and_then(Value::as_str) {
            cfg.functions_source = Some(src.to_owned());
        }
        if let Some(runner) = f.get("runner") {
            let parts: Option<Vec<String>> = runner.as_array().map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            });
            match parts {
                Some(p) if !p.is_empty() => cfg.functions_runner = Some(p),
                _ => {
                    return Err(ConfigError(
                        "functions.runner must be a non-empty array of strings".into(),
                    ))
                }
            }
        }
        if let Some(n) = f.get("maxGlobalConcurrency").and_then(Value::as_u64) {
            cfg.functions_max_running = usize::try_from(n).unwrap_or(8).max(1);
        }
        Ok(())
    }

    /// The `appCheck` section (spec `firebase-app-check.md` section 8). Unknown keys fail
    /// closed at every level, and the binding rules are checked by building the registry the
    /// runtime will use, so the loader and the runtime can never disagree.
    #[allow(clippy::too_many_lines)]
    fn parse_app_check(
        section: &serde_json::Map<String, Value>,
    ) -> Result<AppCheckConfig, ConfigError> {
        const KEYS: [&str; 5] = [
            "enabled",
            "tokenSigning",
            "tokenTtlSeconds",
            "apps",
            "services",
        ];
        const APP_KEYS: [&str; 5] = [
            "projectId",
            "projectNumber",
            "appId",
            "enabled",
            "debugTokenSha256",
        ];
        const SERVICES: [&str; 3] = ["auth", "firestore", "storage"];

        for key in section.keys() {
            if !KEYS.contains(&key.as_str()) {
                return Err(ConfigError(format!("unknown config key appCheck.{key}")));
            }
        }
        let mut cfg = AppCheckConfig::disabled();
        cfg.enabled = match section.get("enabled") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(ConfigError("appCheck.enabled must be a boolean".into())),
        };
        if let Some(mode) = section.get("tokenSigning") {
            let text = mode
                .as_str()
                .ok_or_else(|| ConfigError("appCheck.tokenSigning must be a string".to_owned()))?;
            cfg.token_signing = AppCheckSigning::parse_config(text).ok_or_else(|| {
                ConfigError(format!(
                    "appCheck.tokenSigning {text:?} is not supported; only \"instance-rsa\" is"
                ))
            })?;
        }
        if let Some(ttl) = section.get("tokenTtlSeconds") {
            let seconds = ttl.as_i64().ok_or_else(|| {
                ConfigError("appCheck.tokenTtlSeconds must be an integer".to_owned())
            })?;
            if !(ftd_core_app_check::limits::MIN_TOKEN_TTL_SECONDS
                ..=ftd_core_app_check::limits::MAX_TOKEN_TTL_SECONDS)
                .contains(&seconds)
            {
                return Err(ConfigError(
                    "appCheck.tokenTtlSeconds must be between 1800 and 604800 seconds inclusive"
                        .into(),
                ));
            }
            cfg.token_ttl_seconds = seconds;
        }
        if let Some(apps) = section.get("apps") {
            let apps = apps
                .as_array()
                .ok_or_else(|| ConfigError("appCheck.apps must be an array".to_owned()))?;
            if apps.len() > ftd_core_app_check::limits::MAX_APPS {
                return Err(ConfigError(
                    "appCheck.apps: at most 1024 apps may be configured".into(),
                ));
            }
            for (i, app) in apps.iter().enumerate() {
                let app = app
                    .as_object()
                    .ok_or_else(|| ConfigError(format!("appCheck.apps[{i}] must be an object")))?;
                for key in app.keys() {
                    if !APP_KEYS.contains(&key.as_str()) {
                        return Err(ConfigError(format!(
                            "unknown config key appCheck.apps[{i}].{key}"
                        )));
                    }
                }
                let text = |key: &str| -> Result<String, ConfigError> {
                    app.get(key)
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            ConfigError(format!(
                                "appCheck.apps[{i}].{key} is required and must be a string"
                            ))
                        })
                };
                let enabled = match app.get("enabled") {
                    None => true,
                    Some(Value::Bool(b)) => *b,
                    Some(_) => {
                        return Err(ConfigError(format!(
                            "appCheck.apps[{i}].enabled must be a boolean"
                        )))
                    }
                };
                let mut digests = Vec::new();
                if let Some(list) = app.get("debugTokenSha256") {
                    let list = list.as_array().ok_or_else(|| {
                        ConfigError(format!(
                            "appCheck.apps[{i}].debugTokenSha256 must be an array"
                        ))
                    })?;
                    for digest in list {
                        let digest = digest.as_str().ok_or_else(|| {
                            ConfigError(format!(
                                "appCheck.apps[{i}].debugTokenSha256 entries must be strings"
                            ))
                        })?;
                        ftd_core_app_check::DebugTokenDigest::parse_hex(digest).map_err(|e| {
                            ConfigError(format!("appCheck.apps[{i}].debugTokenSha256: {e}"))
                        })?;
                        digests.push(digest.to_owned());
                    }
                }
                cfg.apps.push(AppCheckApp {
                    project_id: text("projectId")?,
                    project_number: text("projectNumber")?,
                    app_id: text("appId")?,
                    enabled,
                    debug_token_sha256: digests,
                });
            }
        }
        if let Some(services) = section.get("services") {
            let services = services
                .as_object()
                .ok_or_else(|| ConfigError("appCheck.services must be an object".to_owned()))?;
            for (name, value) in services {
                if !SERVICES.contains(&name.as_str()) {
                    return Err(ConfigError(format!(
                        "unknown config key appCheck.services.{name}"
                    )));
                }
                let text = value.as_str().unwrap_or("");
                let mode = ftd_core_app_check::verify::BaselineMode::parse_config(text)
                    .ok_or_else(|| {
                        ConfigError(format!(
                            "appCheck.services.{name} must be one of off, unenforced, enforced"
                        ))
                    })?;
                match name.as_str() {
                    "auth" => cfg.auth = mode,
                    "firestore" => cfg.firestore = mode,
                    _ => cfg.storage = mode,
                }
            }
        }
        // A non-off service mode is meaningless, and dangerously misleading, while App Check
        // is disabled.
        if !cfg.enabled {
            for (name, mode) in [
                ("auth", cfg.auth),
                ("firestore", cfg.firestore),
                ("storage", cfg.storage),
            ] {
                if mode != ftd_core_app_check::verify::BaselineMode::Off {
                    return Err(ConfigError(format!(
                        "appCheck.services.{name} is {mode} while appCheck.enabled is false"
                    )));
                }
            }
        }
        // The binding rules live in the core registry; building it here makes the loader and
        // the runtime agree by construction.
        let mut registry = ftd_core_app_check::AppCheckRegistry::new(cfg.token_ttl_seconds)
            .map_err(|e| ConfigError(format!("appCheck.tokenTtlSeconds: {e}")))?;
        for registration in cfg.registrations()? {
            let app_id = registration.app_id.clone();
            registry
                .register_app(registration)
                .map_err(|e| ConfigError(format!("appCheck.apps ({app_id}): {e}")))?;
        }
        Ok(cfg)
    }

    /// Builds the runtime config from parsed JSON.
    #[allow(clippy::too_many_lines)]
    pub fn from_json(json: &Value) -> Result<Self, ConfigError> {
        let obj = json
            .as_object()
            .ok_or_else(|| ConfigError("config must be a JSON object".into()))?;
        for key in obj.keys() {
            if !KNOWN_TOP_LEVEL.contains(&key.as_str()) {
                return Err(ConfigError(format!("unknown config key {key:?}")));
            }
        }
        if obj.get("schemaVersion").and_then(Value::as_i64) != Some(1) {
            return Err(ConfigError("schemaVersion must be 1".into()));
        }
        let mut cfg = Self::default();
        if let Some(bind) = obj.get("bind").and_then(Value::as_str) {
            if bind != "127.0.0.1" && bind != "localhost" && bind != "::1" {
                return Err(ConfigError(format!(
                    "bind {bind:?}: only loopback binds are supported without a control token"
                )));
            }
        }
        if let Some(fs) = obj.get("firestore").and_then(Value::as_object) {
            if let Some(e) = fs.get("edition").and_then(Value::as_str) {
                cfg.edition = FirestoreEdition::parse_config_str(e)
                    .ok_or_else(|| ConfigError(format!("unknown firestore.edition {e:?}")))?;
            }
            if let Some(m) = fs.get("apiMode").and_then(Value::as_str) {
                cfg.api_mode = FirestoreApiMode::parse_config_str(m)
                    .ok_or_else(|| ConfigError(format!("unknown firestore.apiMode {m:?}")))?;
            }
            if let Some(p) = fs.get("indexValidationPolicy").and_then(Value::as_str) {
                cfg.index_policy = match p {
                    "firebase" => IndexValidationPolicy::Firebase,
                    "conservative" => IndexValidationPolicy::Conservative,
                    "emulator" => IndexValidationPolicy::Emulator,
                    other => {
                        return Err(ConfigError(format!(
                            "unknown firestore.indexValidationPolicy {other:?}"
                        )))
                    }
                };
            }
            if let Some(f) = fs.get("textIndexDefinitionFile").and_then(Value::as_str) {
                cfg.text_index_file = Some(f.to_owned());
            }
            if let Some(f) = fs.get("indexFile").and_then(Value::as_str) {
                cfg.index_file = Some(f.to_owned());
            }
        }
        if cfg.edition == FirestoreEdition::Standard
            && cfg.api_mode == FirestoreApiMode::MongoDbCompatible
        {
            return Err(ConfigError(
                "standard edition cannot use the mongodb-compatible API mode".into(),
            ));
        }
        if let Some(p) = obj.get("projects").and_then(Value::as_object) {
            if let Some(b) = p.get("requireDemoPrefix").and_then(Value::as_bool) {
                cfg.require_demo_prefix = b;
            }
        }
        if let Some(d) = obj.get("daemon").and_then(Value::as_object) {
            Self::parse_daemon(d, &mut cfg)?;
        }
        if let Some(rules) = obj.get("rules").and_then(Value::as_object) {
            Self::parse_rules(rules, &mut cfg)?;
        }
        if let Some(storage) = obj.get("storage").and_then(Value::as_object) {
            if let Some(source) = storage.get("rules").and_then(Value::as_str) {
                cfg.storage_rules_file = Some(source.to_owned());
            }
        }
        if let Some(functions) = obj.get("functions").and_then(Value::as_object) {
            Self::parse_functions(functions, &mut cfg)?;
        }
        if let Some(events) = obj.get("events").and_then(Value::as_object) {
            Self::parse_events(events, &mut cfg)?;
        }
        if let Some(scheduler) = obj.get("scheduler").and_then(Value::as_object) {
            Self::parse_scheduler(scheduler, &mut cfg)?;
        }
        if let Some(auth) = obj.get("auth") {
            let auth = auth
                .as_object()
                .ok_or_else(|| ConfigError("auth must be an object".to_owned()))?;
            for key in auth.keys() {
                if !AUTH_KEYS.contains(&key.as_str()) {
                    return Err(ConfigError(format!("unknown config key auth.{key}")));
                }
            }
            if let Some(mode) = auth.get("idTokenSigning") {
                let mode = mode.as_str().ok_or_else(|| {
                    ConfigError("auth.idTokenSigning must be a string".to_owned())
                })?;
                let m = ftd_core_auth::jwt::SigningMode::parse_config(mode)
                    .ok_or_else(|| ConfigError(format!("unknown auth.idTokenSigning {mode:?}")))?;
                if !m.supported() {
                    return Err(ConfigError(format!(
                        "auth.idTokenSigning {mode:?} is not implemented"
                    )));
                }
                cfg.id_token_signing = m;
            }
        }
        if let Some(app_check) = obj.get("appCheck") {
            let app_check = app_check
                .as_object()
                .ok_or_else(|| ConfigError("appCheck must be an object".to_owned()))?;
            cfg.app_check = Self::parse_app_check(app_check)?;
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn parse(auth: &Value) -> Result<RuntimeConfig, ConfigError> {
        RuntimeConfig::from_json(&json!({
            "schemaVersion": 1,
            "profile": "deterministic",
            "firestore": {"edition": "standard", "apiMode": "native"},
            "auth": auth,
        }))
    }

    // ----------------------------------------------------------------------------------
    // App Check (docs/specifications/firebase-app-check.md section 8)
    // ----------------------------------------------------------------------------------

    const DIGEST: &str = "db8055e0e0307d5a016bec4dc338d69875eb0fb7e614a8b125b08fb082095d98";

    fn app_check(section: &Value) -> Result<AppCheckConfig, ConfigError> {
        RuntimeConfig::from_json(&json!({
            "schemaVersion": 1,
            "profile": "deterministic",
            "firestore": {"edition": "standard", "apiMode": "native"},
            "appCheck": section,
        }))
        .map(|cfg| cfg.app_check)
    }

    fn one_app() -> Value {
        json!({
            "projectId": "demo-app",
            "projectNumber": "1234567890",
            "appId": "1:1234567890:web:local-test-app",
            "debugTokenSha256": [DIGEST],
        })
    }

    #[test]
    fn app_check_defaults_to_off_and_preserves_current_behaviour() {
        let cfg = RuntimeConfig::default();
        assert!(!cfg.app_check.enabled);
        assert_eq!(cfg.app_check.token_ttl_seconds, 3600);
        assert!(cfg.app_check.apps.is_empty());
        for service in [
            AppCheckService::Auth,
            AppCheckService::Firestore,
            AppCheckService::Storage,
        ] {
            assert_eq!(
                cfg.app_check.configured_mode(service),
                ftd_core_app_check::verify::BaselineMode::Off
            );
        }
        // A configuration without the section is exactly the default.
        let parsed = RuntimeConfig::from_json(&json!({
            "schemaVersion": 1,
            "profile": "deterministic",
            "firestore": {"edition": "standard", "apiMode": "native"},
        }))
        .unwrap();
        assert_eq!(parsed.app_check, AppCheckConfig::disabled());
    }

    #[test]
    fn the_canonical_configuration_example_passes_loader_validation() {
        // The same file `config-schema-check` validates against the JSON Schema.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../spec/config/examples/app-check-enforced.json");
        let cfg = RuntimeConfig::from_file(&path).expect("the canonical example loads");
        assert!(cfg.app_check.enabled);
        assert_eq!(cfg.app_check.token_signing, AppCheckSigning::InstanceRsa);
        assert_eq!(cfg.app_check.token_ttl_seconds, 3600);
        assert_eq!(cfg.app_check.apps.len(), 2);
        assert!(cfg.app_check.apps[0].enabled);
        assert!(!cfg.app_check.apps[1].enabled);
        assert_eq!(
            cfg.app_check.firestore,
            ftd_core_app_check::verify::BaselineMode::Unenforced
        );
        assert_eq!(
            cfg.app_check.storage,
            ftd_core_app_check::verify::BaselineMode::Enforced
        );
        assert_eq!(cfg.app_check.registrations().unwrap().len(), 2);
    }

    #[test]
    fn only_instance_rsa_signing_is_accepted_and_unsigned_modes_are_refused() {
        assert_eq!(
            app_check(&json!({"enabled": true, "tokenSigning": "instance-rsa"}))
                .unwrap()
                .token_signing,
            AppCheckSigning::InstanceRsa
        );
        for bad in ["unsigned", "session-rsa", "none", ""] {
            assert!(
                app_check(&json!({"enabled": true, "tokenSigning": bad})).is_err(),
                "{bad:?} must be refused"
            );
        }
        assert!(app_check(&json!({"enabled": true, "tokenSigning": 1})).is_err());
    }

    #[test]
    fn the_token_ttl_is_bounded_and_defaults_to_one_hour() {
        assert_eq!(
            app_check(&json!({"enabled": true}))
                .unwrap()
                .token_ttl_seconds,
            3600
        );
        for good in [1800, 3600, 604_800] {
            assert_eq!(
                app_check(&json!({"enabled": true, "tokenTtlSeconds": good}))
                    .unwrap()
                    .token_ttl_seconds,
                good
            );
        }
        for bad in [0, 1799, 604_801, -1] {
            assert!(
                app_check(&json!({"enabled": true, "tokenTtlSeconds": bad})).is_err(),
                "{bad} must be refused"
            );
        }
        assert!(app_check(&json!({"enabled": true, "tokenTtlSeconds": "3600"})).is_err());
    }

    #[test]
    fn a_non_off_service_mode_is_invalid_while_app_check_is_disabled() {
        for mode in ["unenforced", "enforced"] {
            let refusal = app_check(&json!({"enabled": false, "services": {"firestore": mode}}));
            assert_eq!(
                refusal,
                Err(ConfigError(format!(
                    "appCheck.services.firestore is {mode} while appCheck.enabled is false"
                )))
            );
        }
        assert!(app_check(&json!({"enabled": false, "services": {"firestore": "off"}})).is_ok());
        // Every omitted service member is off.
        let cfg = app_check(&json!({"enabled": true, "services": {"auth": "enforced"}})).unwrap();
        assert_eq!(cfg.auth, ftd_core_app_check::verify::BaselineMode::Enforced);
        assert_eq!(cfg.firestore, ftd_core_app_check::verify::BaselineMode::Off);
        assert_eq!(cfg.storage, ftd_core_app_check::verify::BaselineMode::Off);
    }

    #[test]
    fn unknown_app_check_keys_services_and_modes_fail_closed() {
        assert_eq!(
            app_check(&json!({"enabled": true, "tokenTtl": 3600})),
            Err(ConfigError(
                "unknown config key appCheck.tokenTtl".to_owned()
            ))
        );
        assert_eq!(
            app_check(&json!({"enabled": true, "services": {"database": "off"}})),
            Err(ConfigError(
                "unknown config key appCheck.services.database".to_owned()
            ))
        );
        assert!(app_check(&json!({"enabled": true, "services": {"auth": "audit"}})).is_err());
        let mut app = one_app();
        app["debugToken"] = json!("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
        assert_eq!(
            app_check(&json!({"enabled": true, "apps": [app]})),
            Err(ConfigError(
                "unknown config key appCheck.apps[0].debugToken".to_owned()
            ))
        );
        assert_eq!(
            RuntimeConfig::from_json(&json!({
                "schemaVersion": 1,
                "profile": "deterministic",
                "firestore": {"edition": "standard", "apiMode": "native"},
                "appCheck": true,
            })),
            Err(ConfigError("appCheck must be an object".to_owned()))
        );
    }

    #[test]
    fn app_entries_bind_project_ids_numbers_and_app_ids_exactly_once() {
        let ok = app_check(&json!({"enabled": true, "apps": [one_app()]})).unwrap();
        assert_eq!(ok.apps[0].project_number, "1234567890");
        assert!(ok.apps[0].enabled, "an app entry defaults to enabled");

        let duplicate = json!({"enabled": true, "apps": [one_app(), one_app()]});
        assert!(app_check(&duplicate).is_err());

        let mut second = one_app();
        second["projectNumber"] = json!("9876543210");
        second["appId"] = json!("1:9876543210:web:other");
        assert!(
            app_check(&json!({"enabled": true, "apps": [one_app(), second]})).is_err(),
            "one project ID may not take a second project number"
        );

        let mut foreign = one_app();
        foreign["projectId"] = json!("demo-other");
        foreign["appId"] = json!("1:1234567890:web:other");
        assert!(
            app_check(&json!({"enabled": true, "apps": [one_app(), foreign]})).is_err(),
            "one project number may not belong to a second project ID"
        );

        let mut reused = one_app();
        reused["projectId"] = json!("demo-other");
        reused["projectNumber"] = json!("9876543210");
        assert!(
            app_check(&json!({"enabled": true, "apps": [one_app(), reused]})).is_err(),
            "one app ID may not be reused across projects"
        );
    }

    #[test]
    fn project_numbers_digests_and_embedded_app_id_numbers_are_validated() {
        for bad in ["", "0", "01234", "12a4", "-1"] {
            let mut app = one_app();
            app["projectNumber"] = json!(bad);
            app["appId"] = json!("custom-app-id");
            assert!(
                app_check(&json!({"enabled": true, "apps": [app]})).is_err(),
                "project number {bad:?} must be refused"
            );
        }
        let mut mismatch = one_app();
        mismatch["appId"] = json!("1:9876543210:web:local-test-app");
        assert!(app_check(&json!({"enabled": true, "apps": [mismatch]})).is_err());

        for bad in [
            DIGEST.to_uppercase(),
            "zz".to_owned(),
            DIGEST[..63].to_owned(),
        ] {
            let mut app = one_app();
            app["debugTokenSha256"] = json!([bad]);
            assert!(
                app_check(&json!({"enabled": true, "apps": [app]})).is_err(),
                "digest {bad:?} must be refused"
            );
        }
        // A raw debug secret is never a digest.
        let mut raw = one_app();
        raw["debugTokenSha256"] = json!(["a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"]);
        assert!(app_check(&json!({"enabled": true, "apps": [raw]})).is_err());
    }

    #[test]
    fn the_selection_table_decides_availability_and_the_product_baselines() {
        use ftd_core_app_check::verify::BaselineMode::{Enforced, Off, Unenforced};
        let enabled = app_check(&json!({
            "enabled": true,
            "services": {"firestore": "unenforced", "storage": "enforced"},
        }))
        .unwrap();
        let disabled = AppCheckConfig::disabled();

        // Row 1: the section is absent or disabled.
        let all = Selection::default();
        assert!(!all.app_check_available(&disabled));
        assert_eq!(
            all.app_check_mode(&disabled, AppCheckService::Firestore),
            Off
        );

        // Row 2: enabled, but neither appcheck nor functions is selected.
        let neither = Selection::parse("auth,firestore,storage").unwrap();
        assert!(!neither.app_check_available(&enabled));
        assert_eq!(
            neither.app_check_mode(&enabled, AppCheckService::Firestore),
            Off
        );

        // Row 3: enabled and appcheck selected, Functions not.
        let with_appcheck = Selection::parse("appcheck,firestore,storage").unwrap();
        assert!(with_appcheck.app_check_available(&enabled));
        assert_eq!(
            with_appcheck.app_check_mode(&enabled, AppCheckService::Firestore),
            Unenforced
        );
        assert_eq!(
            with_appcheck.app_check_mode(&enabled, AppCheckService::Storage),
            Enforced
        );
        // A product that is not selected stays off whatever the configured mode says.
        assert_eq!(
            Selection::parse("appcheck")
                .unwrap()
                .app_check_mode(&enabled, AppCheckService::Storage),
            Off
        );

        // Row 4: functions selects its App Check dependency implicitly.
        let functions_only = Selection::parse("functions").unwrap();
        assert!(functions_only.app_check_available(&enabled));
        assert_eq!(
            functions_only.app_check_mode(&enabled, AppCheckService::Storage),
            Off,
            "a non-Functions product applies its mode only when explicitly selected"
        );

        // No --only at all: everything is selected, so the configured modes apply.
        assert!(all.app_check_available(&enabled));
        assert_eq!(
            all.app_check_mode(&enabled, AppCheckService::Storage),
            Enforced
        );
        assert!(all.appcheck);
        assert!(Selection::parse("appcheck").unwrap().appcheck);
        assert!(!Selection::parse("auth").unwrap().appcheck);
    }

    #[test]
    fn firebase_json_maps_rules_indexes_ports_and_the_selected_functions() {
        let json = json!({
            "firestore": {"rules": "firestore.rules", "index": "firestore.indexes.json"},
            "storage": {"rules": "storage.rules"},
            "functions": [{"source": "functions", "codebase": "default"}],
            "emulators": {
                "firestore": {"port": 8081},
                "auth": {"port": 9100},
                "storage": {"port": 9200},
                "functions": {"port": 5002},
                "pubsub": {"port": 8085},
                "ui": {"enabled": true}
            }
        });
        let base = std::path::Path::new("/proj");
        let mut cfg = RuntimeConfig::default();
        let ignored = cfg
            .apply_firebase_json(&json, base, &Selection::default())
            .unwrap();
        assert_eq!(cfg.rules_file.as_deref(), Some("/proj/firestore.rules"));
        assert_eq!(
            cfg.index_file.as_deref(),
            Some("/proj/firestore.indexes.json")
        );
        assert_eq!(
            cfg.storage_rules_file.as_deref(),
            Some("/proj/storage.rules")
        );
        assert_eq!(cfg.functions_source.as_deref(), Some("/proj/functions"));
        assert_eq!(cfg.firestore_addr, "127.0.0.1:8081");
        assert_eq!(cfg.http_addr, "127.0.0.1:9100");
        assert_eq!(cfg.storage_addr, "127.0.0.1:9200");
        assert_eq!(cfg.functions_addr, "127.0.0.1:5002");
        assert_eq!(ignored, vec!["emulators.pubsub".to_owned()]);
        // Functions are loaded only when selected; the `indexes` spelling works too.
        let mut cfg = RuntimeConfig::default();
        let only = Selection::parse("auth,firestore,storage").unwrap();
        cfg.apply_firebase_json(
            &json!({"firestore": {"indexes": "idx.json"}, "functions": {"source": "fn"}}),
            base,
            &only,
        )
        .unwrap();
        assert_eq!(cfg.index_file.as_deref(), Some("/proj/idx.json"));
        assert_eq!(cfg.functions_source, None);
        assert!(!only.functions);
        assert!(Selection::parse("auth,database").is_err());
        assert_eq!(
            cfg.apply_firebase_json(&json!({"firestore": {"rules": 1}}), base, &only),
            Err(ConfigError(
                "firebase.json: firestore.rules must be a string".to_owned()
            ))
        );
    }

    #[test]
    fn the_auth_section_never_downgrades_silently() {
        assert_eq!(
            parse(&json!({"idTokenSigning": "session-rsa"}))
                .unwrap()
                .id_token_signing,
            ftd_core_auth::jwt::SigningMode::SessionRsa
        );
        assert_eq!(
            parse(&json!({"idTokenSingning": "session-rsa"})),
            Err(ConfigError(
                "unknown config key auth.idTokenSingning".to_owned()
            ))
        );
        assert_eq!(
            parse(&json!({"idTokenSigning": true})),
            Err(ConfigError(
                "auth.idTokenSigning must be a string".to_owned()
            ))
        );
        assert_eq!(
            parse(&json!("session-rsa")),
            Err(ConfigError("auth must be an object".to_owned()))
        );
        assert!(parse(&json!({"idTokenSigning": "hs256"})).is_err());
    }
}
