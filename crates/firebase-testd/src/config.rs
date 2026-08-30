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

/// The services `exec` exports to its child (`--only auth,firestore,storage,functions`).
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
}

impl Default for Selection {
    fn default() -> Self {
        Self {
            firestore: true,
            auth: true,
            storage: true,
            functions: true,
        }
    }
}

impl Selection {
    /// Parses the `--only` list (`firebase emulators:exec --only` names).
    pub fn parse(list: &str) -> Result<Self, ConfigError> {
        let mut sel = Self {
            firestore: false,
            auth: false,
            storage: false,
            functions: false,
        };
        for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
            match name {
                "firestore" => sel.firestore = true,
                "auth" => sel.auth = true,
                "storage" => sel.storage = true,
                "functions" => sel.functions = true,
                other => {
                    return Err(ConfigError(format!(
                        "--only: unknown service {other:?} (firestore, auth, storage, functions)"
                    )))
                }
            }
        }
        Ok(sel)
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
                    "emulator" => IndexValidationPolicy::Emulator,
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
