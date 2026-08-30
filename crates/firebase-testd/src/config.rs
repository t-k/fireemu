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
    /// Deterministic seed.
    pub seed: u64,
    /// Project ID used for Auth token issuance.
    pub auth_project: String,
    /// Path of `firestore.indexes.json`, if configured.
    pub index_file: Option<String>,
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
    /// Overlap policy of schedules (`scheduler.overlap`).
    pub scheduler_overlap: String,
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
            seed: 42,
            auth_project: "demo-app".to_owned(),
            index_file: None,
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
        }
    }
}

/// Configuration errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

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
        for (key, allowed) in [("clock", "virtual"), ("catchUp", "all")] {
            match s.get(key).and_then(Value::as_str) {
                None => {}
                Some(v) if v == allowed => {}
                Some(other) => {
                    return Err(ConfigError(format!(
                        "scheduler.{key} {other:?} is declared but not implemented; use {allowed:?}"
                    )))
                }
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

    /// Builds the runtime config from parsed JSON.
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
                    other => {
                        return Err(ConfigError(format!(
                            "unknown firestore.indexValidationPolicy {other:?}"
                        )))
                    }
                };
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
        if let Some(auth) = obj.get("auth").and_then(Value::as_object) {
            if let Some(mode) = auth.get("idTokenSigning").and_then(Value::as_str) {
                let m = ftd_core_auth::jwt::SigningMode::parse_config(mode)
                    .ok_or_else(|| ConfigError(format!("unknown auth.idTokenSigning {mode:?}")))?;
                if !m.supported() {
                    return Err(ConfigError(format!("auth.idTokenSigning {mode:?} is declared but not implemented; use \"unsigned-emulator\"")));
                }
            }
        }
        Ok(cfg)
    }
}
