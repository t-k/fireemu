//! Runtime configuration: the canonical JSON config (spec 17) plus command-line overrides.
//!
//! Only the keys the daemon currently honours are read; unknown keys are still rejected so
//! that typos never silently change behaviour (the JSON schema in `spec/config` is the
//! authority; this loader enforces the same rule on the subset it understands).

use fireemu_core_auth::jwt::TokenAcceptance;
use fireemu_core_firestore::index::IndexValidationPolicy;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::Value;

/// The compatibility profile (`profile`), the one switch that decides whether fireemu
/// reproduces the pinned official emulators or adds its own validation.
///
/// The two profiles are declared in `spec/compatibility/contract.json`; this enum is the
/// half the daemon executes. The keys a profile only *declares* stay declared: what the
/// runtime derives from it is [`Self::index_policy`], [`Self::enforce_limits`] and
/// [`Self::token_acceptance`], and an explicit configuration key always wins over all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompatibilityProfile {
    /// Reproduce the behaviour the pinned Local Emulator Suite ships, including its
    /// documented limitations. This is the profile the README's compatibility claim is made
    /// under, so it is the default: a project that installs fireemu instead of the official
    /// suite gets the official suite's behaviour without configuring anything.
    #[default]
    Firebase,
    /// Add fireemu's own validation on top. Every difference it makes may only refuse more
    /// than the official emulator, never less.
    Strict,
}

impl CompatibilityProfile {
    /// Parses the canonical configuration value.
    #[must_use]
    pub fn parse_config(text: &str) -> Option<Self> {
        match text {
            "firebase" => Some(Self::Firebase),
            "strict" => Some(Self::Strict),
            _ => None,
        }
    }

    /// The canonical configuration value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Firebase => "firebase",
            Self::Strict => "strict",
        }
    }

    /// The default of `firestore.indexValidationPolicy`.
    ///
    /// The pinned official Firestore emulator does not check composite indexes at all, so
    /// the profile that reproduces it assumes them (`emulator`) and reports each one it
    /// assumed. `strict` refuses the query instead, with the `firestore.indexes.json`
    /// fragment production would need. `firebase` remains available as an explicit value for
    /// a run whose oracle is the Firebase backend rather than the emulator.
    #[must_use]
    pub const fn index_policy(self) -> IndexValidationPolicy {
        match self {
            Self::Firebase => IndexValidationPolicy::Emulator,
            Self::Strict => IndexValidationPolicy::Conservative,
        }
    }

    /// The default of `firestore.enforceLimits`: whether a Standard query limit violation
    /// refuses the query or is only reported.
    #[must_use]
    pub const fn enforce_limits(self) -> bool {
        matches!(self, Self::Strict)
    }

    /// How a caller's ID token is verified on the Security Rules surfaces.
    #[must_use]
    pub const fn token_acceptance(self) -> TokenAcceptance {
        match self {
            Self::Firebase => TokenAcceptance::EmulatorMock,
            Self::Strict => TokenAcceptance::Verified,
        }
    }
}

/// The Emulator Hub's official default port (`firebase-tools` `Constants.getDefaultPort`).
pub const DEFAULT_HUB_PORT: u16 = 4400;

/// The Emulator UI's official default port.
pub const DEFAULT_UI_PORT: u16 = 4000;

/// Effective daemon configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent switches, each read on its own
pub struct RuntimeConfig {
    /// Compatibility profile (`profile`). It sets the defaults of [`Self::index_policy`],
    /// [`Self::enforce_limits`] and [`Self::token_acceptance`]; an explicit key wins.
    pub profile: CompatibilityProfile,
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
    /// Index validation policy (`firestore.indexValidationPolicy`; profile default).
    pub index_policy: IndexValidationPolicy,
    /// Whether a Standard query limit violation refuses the query
    /// (`firestore.enforceLimits`; profile default). When it does not, each violation is
    /// reported as an `FS_LIMIT_OBSERVED:<id>` warning and the query runs.
    pub enforce_limits: bool,
    /// How a caller's ID token is verified on the Firestore and Storage Rules surfaces
    /// (profile-derived; there is no key of its own).
    pub token_acceptance: TokenAcceptance,
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
    /// Emulator Hub bind address (`emulators.hub`, `--hub-port`). The official default port
    /// is 4400; binding it is best effort unless it was asked for explicitly.
    pub hub_addr: String,
    /// Whether `--hub-port` or `emulators.hub` pinned the Hub address. A busy default port
    /// only disables the Hub; a busy explicit one is an error.
    pub hub_addr_explicit: bool,
    /// Emulator UI bind address (`emulators.ui`). Only the port is honoured; the UI listener
    /// binds loopback.
    pub ui_addr: String,
    /// `emulators.ui.enabled`.
    pub ui_enabled: bool,
    /// Whether `--ui-port`, `emulators.ui` or `daemon.uiPort` pinned the UI address. Like
    /// the Hub's, a busy default port only disables the UI; a busy explicit one is an error.
    pub ui_addr_explicit: bool,
    /// `emulators.singleProjectMode`. fireemu isolates every project into its own session, so
    /// this is recorded and published rather than enforced separately.
    pub single_project_mode: bool,
    /// Functions codebase directory (`functions.source`); `None` = no functions runtime.
    pub functions_source: Option<String>,
    /// Every codebase `firebase.json` declares, in file order.
    pub functions_codebases: Vec<FunctionsCodebase>,
    /// The codebases this run actually loads, one runner process each. Empty when the
    /// codebase came from `functions.source` or `--functions <dir>` instead.
    pub functions_loaded: Vec<FunctionsCodebase>,
    /// Runner command (`functions.runner`); default: the bundled Node runner.
    pub functions_runner: Option<Vec<String>>,
    /// Explicit manifest path (`functions.manifest`); default: runner discovery.
    pub functions_manifest: Option<String>,
    /// Maximum invocations running at once (`functions.maxGlobalConcurrency`).
    pub functions_max_running: usize,
    /// What to do with an exported trigger that belongs to a product fireemu does not serve
    /// (`functions.unservedTriggers`): `refuse` (default) or `report`.
    pub functions_unserved_triggers: String,
    /// The `.firebaserc` alias `--project` resolved through, when the project was named by an
    /// alias. It is the only reason a codebase may carry a `.env.<alias>` file, and having
    /// both that and `.env.<projectId>` is refused, as `loadUserEnvs` refuses it.
    pub functions_project_alias: Option<String>,
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
    pub id_token_signing: fireemu_core_auth::jwt::SigningMode,
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
    pub auth: fireemu_core_app_check::verify::BaselineMode,
    /// `services.firestore`.
    pub firestore: fireemu_core_app_check::verify::BaselineMode,
    /// `services.storage`.
    pub storage: fireemu_core_app_check::verify::BaselineMode,
}

impl AppCheckConfig {
    /// The disabled default: no exchange, no JWKS, every product baseline `off`.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            token_signing: AppCheckSigning::InstanceRsa,
            token_ttl_seconds: fireemu_core_app_check::limits::DEFAULT_TOKEN_TTL_SECONDS,
            apps: Vec::new(),
            auth: fireemu_core_app_check::verify::BaselineMode::Off,
            firestore: fireemu_core_app_check::verify::BaselineMode::Off,
            storage: fireemu_core_app_check::verify::BaselineMode::Off,
        }
    }

    /// The configured mode of one product, before service selection is applied.
    #[must_use]
    pub const fn configured_mode(
        &self,
        service: AppCheckService,
    ) -> fireemu_core_app_check::verify::BaselineMode {
        match service {
            AppCheckService::Auth => self.auth,
            AppCheckService::Firestore => self.firestore,
            AppCheckService::Storage => self.storage,
        }
    }

    /// The registrations the runtime registry is built from. Every binding rule of section 8
    /// is checked by the core registry, so the loader and the runtime cannot disagree.
    pub fn registrations(
        &self,
    ) -> Result<Vec<fireemu_core_app_check::AppRegistration>, ConfigError> {
        let mut out = Vec::with_capacity(self.apps.len());
        for app in &self.apps {
            let mut digests = Vec::with_capacity(app.debug_token_sha256.len());
            for text in &app.debug_token_sha256 {
                digests.push(
                    fireemu_core_app_check::DebugTokenDigest::parse_hex(text).map_err(|e| {
                        ConfigError(format!(
                            "appCheck.apps[{}].debugTokenSha256: {e}",
                            app.app_id
                        ))
                    })?,
                );
            }
            out.push(fireemu_core_app_check::AppRegistration {
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
        let profile = CompatibilityProfile::default();
        Self {
            profile,
            firestore_addr: "127.0.0.1:8080".to_owned(),
            http_addr: "127.0.0.1:9099".to_owned(),
            storage_addr: "127.0.0.1:9199".to_owned(),
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            index_policy: profile.index_policy(),
            enforce_limits: profile.enforce_limits(),
            token_acceptance: profile.token_acceptance(),
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
            hub_addr: format!("127.0.0.1:{DEFAULT_HUB_PORT}"),
            hub_addr_explicit: false,
            ui_addr: format!("127.0.0.1:{DEFAULT_UI_PORT}"),
            ui_enabled: true,
            ui_addr_explicit: false,
            single_project_mode: false,
            functions_source: None,
            functions_codebases: Vec::new(),
            functions_loaded: Vec::new(),
            functions_runner: None,
            functions_manifest: None,
            functions_max_running: 8,
            functions_unserved_triggers: "refuse".to_owned(),
            functions_project_alias: None,
            events_max_attempts: 4,
            scheduler_max_catch_up_runs: 1000,
            scheduler_default_time_zone: None,
            scheduler_overlap: "allow".to_owned(),
            scheduler_catch_up: "all".to_owned(),
            id_token_signing: fireemu_core_auth::jwt::SigningMode::UnsignedEmulator,
            app_check: AppCheckConfig::disabled(),
        }
    }
}

/// The keys of the `auth` section (spec/config/fireemu.schema.json).
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

/// The service emulators fireemu serves, in `--only` spelling.
pub const SERVED_SERVICES: [&str; 5] = ["auth", "firestore", "storage", "functions", "appcheck"];

/// Official Local Emulator Suite service emulators fireemu does not serve, each with the
/// scope decision that explains it. Selecting one is an error rather than a silent no-op:
/// a test suite that asks for Realtime Database must not be told the suite started.
///
/// `deferred` products have an open compatibility issue and no implementation; `planned`
/// products are on the active list; `not planned` is a closed product decision.
pub const UNSERVED_OFFICIAL_SERVICES: [(&str, &str); 8] = [
    (
        "database",
        "deferred: the Realtime Database emulator is not in the active supported surface",
    ),
    (
        "hosting",
        "deferred: the Firebase Hosting emulator is not in the active supported surface",
    ),
    (
        "apphosting",
        "deferred: the App Hosting emulator is not in the active supported surface",
    ),
    ("pubsub", "planned: the Pub/Sub emulator is not implemented yet (fireemu publishes to Pub/Sub triggers through its control API instead)"),
    (
        "eventarc",
        "planned: the Eventarc emulator is not implemented yet",
    ),
    (
        "tasks",
        "planned: the Cloud Tasks emulator is not implemented yet",
    ),
    (
        "dataconnect",
        "planned: the Data Connect emulator is not implemented yet",
    ),
    (
        "extensions",
        "not planned: managed Firebase Extensions is deprecated and shuts down on 2027-03-31",
    ),
];

/// Official emulator names that are not service emulators: `--only` never names them and
/// `emulators.<name>` configures them instead.
pub const NON_SERVICE_EMULATORS: [&str; 3] = ["hub", "ui", "logging"];

/// The status sentence of an official service fireemu does not serve.
#[must_use]
pub fn unserved_official_service(name: &str) -> Option<&'static str> {
    UNSERVED_OFFICIAL_SERVICES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, why)| *why)
}

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
    /// The functions codebase is loaded and `FIREEMU_FUNCTIONS_HOST` exported.
    pub functions: bool,
    /// App Check: a logical selection, because the exchange and the JWKS share the
    /// Auth/control listener. Exports `FIREEMU_APP_CHECK_EMULATOR_HOST` and
    /// `FIREEMU_APP_CHECK_JWKS_URL`.
    pub appcheck: bool,
    /// Whether `--only` was given. Without it every served service is selected and an
    /// `emulators.<name>` entry for a product fireemu does not serve is a notice, not an
    /// error: only naming that product in `--only` asks for it.
    pub explicit: bool,
    /// `--only functions:<codebase>`: the single codebase to load out of a multi-codebase
    /// `firebase.json`. `None` selects the only codebase there is.
    pub functions_codebase: Option<String>,
}

impl Default for Selection {
    fn default() -> Self {
        Self {
            firestore: true,
            auth: true,
            storage: true,
            functions: true,
            appcheck: true,
            explicit: false,
            functions_codebase: None,
        }
    }
}

impl Selection {
    /// Parses the `--only` list (`firebase emulators:exec --only` names, plus `appcheck`).
    ///
    /// An official service fireemu does not serve is refused with its scope status, and a
    /// non-service emulator name (`hub`, `ui`, `logging`) is refused as not selectable, both
    /// before anything binds.
    pub fn parse(list: &str) -> Result<Self, ConfigError> {
        let mut sel = Self {
            firestore: false,
            auth: false,
            storage: false,
            functions: false,
            appcheck: false,
            explicit: true,
            functions_codebase: None,
        };
        for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
            // `firebase emulators:exec --only functions:codebase` selects one codebase; the
            // service name is what selects the emulator.
            let (service, codebase) = match name.split_once(':') {
                Some((head, tail)) => (head, Some(tail)),
                None => (name, None),
            };
            if let (Some(codebase), true) = (codebase, service == "functions") {
                if codebase.is_empty() {
                    return Err(ConfigError(
                        "--only functions:: needs a codebase name after the colon".to_owned(),
                    ));
                }
                sel.functions_codebase = Some(codebase.to_owned());
            } else if let Some(codebase) = codebase {
                return Err(ConfigError(format!(
                    "--only: {service:?} takes no `:{codebase}` qualifier; only `functions:<codebase>` does"
                )));
            }
            match service {
                "firestore" => sel.firestore = true,
                "auth" => sel.auth = true,
                "storage" => sel.storage = true,
                "functions" => sel.functions = true,
                "appcheck" => sel.appcheck = true,
                other => {
                    if let Some(why) = unserved_official_service(other) {
                        return Err(ConfigError(format!(
                            "--only: {other:?} is an official Local Emulator Suite service that fireemu does not serve ({why}); fireemu serves {}",
                            SERVED_SERVICES.join(", ")
                        )));
                    }
                    if NON_SERVICE_EMULATORS.contains(&other) {
                        return Err(ConfigError(format!(
                            "--only: {other:?} is not a service emulator and cannot be selected; fireemu serves {}",
                            SERVED_SERVICES.join(", ")
                        )));
                    }
                    return Err(ConfigError(format!(
                        "--only: unknown service {other:?} ({})",
                        SERVED_SERVICES.join(", ")
                    )));
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
    ) -> fireemu_core_app_check::verify::BaselineMode {
        if !self.app_check_available(cfg) {
            return fireemu_core_app_check::verify::BaselineMode::Off;
        }
        let selected = match service {
            AppCheckService::Auth => self.auth,
            AppCheckService::Firestore => self.firestore,
            AppCheckService::Storage => self.storage,
        };
        if selected {
            cfg.configured_mode(service)
        } else {
            fireemu_core_app_check::verify::BaselineMode::Off
        }
    }
}

/// One Functions codebase declared in `firebase.json` (`functions` in object or array form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionsCodebase {
    /// `codebase`, defaulting to `default`.
    pub codebase: String,
    /// `source`, resolved against the `firebase.json` directory.
    pub source: String,
    /// `runtime` (`nodejs20`, ...), recorded and reported; the bundled runner is Node.
    pub runtime: Option<String>,
    /// `ignore` globs, recorded; the runner loads the codebase itself.
    pub ignore: Vec<String>,
}

/// What applying a `firebase.json` produced besides the effective configuration: the
/// notices to print once, in file order. Anything fireemu cannot honour is either an error
/// (a selected product it does not serve) or exactly one of these lines; nothing is silent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FirebaseJsonReport {
    /// One line per configuration fragment that was not applied in full.
    pub notices: Vec<String>,
}

/// The `firebase.json` keys that name a Firestore database entry.
const FIRESTORE_ENTRY_KEYS: [&str; 4] = ["database", "rules", "indexes", "index"];

/// The `firebase.json` keys of one Functions codebase that fireemu reads; the deploy hooks
/// (`predeploy`, `postdeploy`) belong to `firebase deploy` and are not emulator settings.
const FUNCTIONS_ENTRY_KEYS: [&str; 6] = [
    "source",
    "codebase",
    "runtime",
    "ignore",
    "predeploy",
    "postdeploy",
];

/// The only host values a listener may take: the daemon serves loopback without a control
/// token, so a `firebase.json` that asks for a routable address is refused rather than
/// exposing Firestore, Auth and Storage to the network.
fn loopback_host(host: &str, path: &str) -> Result<String, ConfigError> {
    match host {
        "127.0.0.1" | "localhost" => Ok(host.to_owned()),
        "::1" | "[::1]" => Ok("[::1]".to_owned()),
        other => Err(ConfigError(format!(
            "firebase.json: {path} {other:?}: only loopback binds are supported (127.0.0.1, localhost, ::1) without a control token"
        ))),
    }
}

/// Reads `host` and `port` of one `emulators.<name>` entry onto the current address.
fn emulator_addr(entry: &Value, name: &str, current: &str) -> Result<String, ConfigError> {
    let obj = entry
        .as_object()
        .ok_or_else(|| ConfigError(format!("firebase.json: emulators.{name} must be an object")))?;
    let (current_host, current_port) = current
        .rsplit_once(':')
        .ok_or_else(|| ConfigError(format!("firebase.json: emulators.{name}: bad address")))?;
    let host = match obj.get("host") {
        None => current_host.to_owned(),
        Some(v) => {
            let text = v.as_str().ok_or_else(|| {
                ConfigError(format!(
                    "firebase.json: emulators.{name}.host must be a string"
                ))
            })?;
            loopback_host(text, &format!("emulators.{name}.host"))?
        }
    };
    let port = match obj.get("port") {
        None => current_port.to_owned(),
        Some(v) => {
            let p = v
                .as_u64()
                .filter(|p| u16::try_from(*p).is_ok())
                .ok_or_else(|| {
                    ConfigError(format!(
                        "firebase.json: emulators.{name}.port must be an integer from 0 to 65535"
                    ))
                })?;
            p.to_string()
        }
    };
    Ok(format!("{host}:{port}"))
}

impl RuntimeConfig {
    /// Applies the parts of a `firebase.json` the daemon can honour. Paths are relative to
    /// `base`.
    ///
    /// - `firestore` in object or array form: `rules` and `indexes` (also the legacy `index`
    ///   spelling) of the `(default)` database; a named database is reported, never silently
    ///   merged into the default one;
    /// - `storage` in object or array form: the `rules` of the entry without a `target`, or
    ///   of the first one;
    /// - `functions` in object or array form: every codebase is parsed and validated, and the
    ///   selected one (`--only functions:<codebase>`, or the only one there is) is loaded;
    /// - `emulators.<name>.host` / `.port` for every served product plus `hub` and `ui`, and
    ///   `emulators.singleProjectMode`.
    ///
    /// An `emulators.<name>` entry for an official product fireemu does not serve is an error
    /// when `--only` named that product, and a notice otherwise.
    #[allow(clippy::too_many_lines)]
    pub fn apply_firebase_json(
        &mut self,
        json: &Value,
        base: &std::path::Path,
        only: &Selection,
    ) -> Result<FirebaseJsonReport, ConfigError> {
        let obj = json
            .as_object()
            .ok_or_else(|| ConfigError("firebase.json must be an object".to_owned()))?;
        let mut report = FirebaseJsonReport::default();
        let file = |v: &Value, key: &str| -> Result<String, ConfigError> {
            let p = v
                .as_str()
                .ok_or_else(|| ConfigError(format!("firebase.json: {key} must be a string")))?;
            Ok(base.join(p).to_string_lossy().into_owned())
        };
        self.apply_firestore(obj.get("firestore"), &file, &mut report)?;
        self.apply_storage(obj.get("storage"), &file, &mut report)?;
        self.apply_functions(obj.get("functions"), base, only, &mut report)?;
        if let Some(emulators) = obj.get("emulators") {
            let emulators = emulators.as_object().ok_or_else(|| {
                ConfigError("firebase.json: emulators must be an object".to_owned())
            })?;
            for (name, entry) in emulators {
                match name.as_str() {
                    "singleProjectMode" => {
                        self.single_project_mode = entry.as_bool().ok_or_else(|| {
                            ConfigError(
                                "firebase.json: emulators.singleProjectMode must be a boolean"
                                    .to_owned(),
                            )
                        })?;
                    }
                    "firestore" => {
                        self.firestore_addr = emulator_addr(entry, name, &self.firestore_addr)?;
                    }
                    "auth" => self.http_addr = emulator_addr(entry, name, &self.http_addr)?,
                    "storage" => {
                        self.storage_addr = emulator_addr(entry, name, &self.storage_addr)?;
                    }
                    "functions" => {
                        self.functions_addr = emulator_addr(entry, name, &self.functions_addr)?;
                    }
                    "hub" => {
                        self.hub_addr = emulator_addr(entry, name, &self.hub_addr)?;
                        self.hub_addr_explicit = true;
                    }
                    "ui" => {
                        let addr = emulator_addr(entry, name, &self.ui_addr)?;
                        let enabled = entry.get("enabled").map_or(Ok(true), |v| {
                            v.as_bool().ok_or_else(|| {
                                ConfigError(
                                    "firebase.json: emulators.ui.enabled must be a boolean"
                                        .to_owned(),
                                )
                            })
                        })?;
                        self.ui_addr = addr;
                        self.ui_enabled = enabled;
                        self.ui_addr_explicit = true;
                    }
                    "logging" => report.notices.push(
                        "emulators.logging: the Logging emulator stream is out of scope for this release; nothing is served on that port".to_owned(),
                    ),
                    other => {
                        let selected = only.explicit && only_names(only, other);
                        if let Some(why) = unserved_official_service(other) {
                            if selected {
                                return Err(ConfigError(format!(
                                    "firebase.json: emulators.{other} configures an official Local Emulator Suite service that fireemu does not serve ({why}), and --only asked for it"
                                )));
                            }
                            report.notices.push(format!(
                                "emulators.{other}: fireemu does not serve this official service ({why}); it is not started"
                            ));
                        } else {
                            report.notices.push(format!(
                                "emulators.{other}: unknown emulator name; it is ignored"
                            ));
                        }
                    }
                }
            }
        }
        Ok(report)
    }

    /// `firestore`, in object or array (named-database) form.
    fn apply_firestore(
        &mut self,
        section: Option<&Value>,
        file: &dyn Fn(&Value, &str) -> Result<String, ConfigError>,
        report: &mut FirebaseJsonReport,
    ) -> Result<(), ConfigError> {
        let entries: Vec<(&serde_json::Map<String, Value>, String)> = match section {
            None => Vec::new(),
            Some(Value::Object(o)) => vec![(o, "firestore".to_owned())],
            Some(Value::Array(a)) => {
                let mut out = Vec::with_capacity(a.len());
                for (i, e) in a.iter().enumerate() {
                    let o = e.as_object().ok_or_else(|| {
                        ConfigError(format!("firebase.json: firestore[{i}] must be an object"))
                    })?;
                    out.push((o, format!("firestore[{i}]")));
                }
                out
            }
            Some(_) => {
                return Err(ConfigError(
                    "firebase.json: firestore must be an object or an array".to_owned(),
                ))
            }
        };
        let mut seen: Vec<String> = Vec::new();
        for (entry, path) in entries {
            for key in entry.keys() {
                if !FIRESTORE_ENTRY_KEYS.contains(&key.as_str()) {
                    return Err(ConfigError(format!(
                        "firebase.json: unknown key {path}.{key}"
                    )));
                }
            }
            let database = entry
                .get("database")
                .map(|v| {
                    v.as_str().map(str::to_owned).ok_or_else(|| {
                        ConfigError(format!("firebase.json: {path}.database must be a string"))
                    })
                })
                .transpose()?
                .unwrap_or_else(|| "(default)".to_owned());
            if seen.contains(&database) {
                return Err(ConfigError(format!(
                    "firebase.json: firestore declares the database {database} twice"
                )));
            }
            seen.push(database.clone());
            if database == "(default)" {
                if let Some(v) = entry.get("rules") {
                    self.rules_file = Some(file(v, &format!("{path}.rules"))?);
                }
                if let Some(v) = entry.get("indexes").or_else(|| entry.get("index")) {
                    self.index_file = Some(file(v, &format!("{path}.indexes"))?);
                }
            } else {
                report.notices.push(format!(
                    "{path}: the named Firestore database {database} is served, but its own rules and indexes are not loaded; only the (default) database's are"
                ));
            }
        }
        Ok(())
    }

    /// `storage`, in object or array (multi-bucket) form.
    fn apply_storage(
        &mut self,
        section: Option<&Value>,
        file: &dyn Fn(&Value, &str) -> Result<String, ConfigError>,
        report: &mut FirebaseJsonReport,
    ) -> Result<(), ConfigError> {
        let entries: Vec<(&serde_json::Map<String, Value>, String)> = match section {
            None => Vec::new(),
            Some(Value::Object(o)) => vec![(o, "storage".to_owned())],
            Some(Value::Array(a)) => {
                let mut out = Vec::with_capacity(a.len());
                for (i, e) in a.iter().enumerate() {
                    let o = e.as_object().ok_or_else(|| {
                        ConfigError(format!("firebase.json: storage[{i}] must be an object"))
                    })?;
                    out.push((o, format!("storage[{i}]")));
                }
                out
            }
            Some(_) => {
                return Err(ConfigError(
                    "firebase.json: storage must be an object or an array".to_owned(),
                ))
            }
        };
        // The daemon evaluates one Storage ruleset for every bucket, so the entry without a
        // deploy target (the project-wide one) wins, and the rest are named in a notice.
        let mut chosen: Option<usize> = None;
        for (i, (entry, _)) in entries.iter().enumerate() {
            let targeted = entry.contains_key("target") || entry.contains_key("bucket");
            if !targeted {
                chosen = Some(i);
                break;
            }
        }
        let chosen = chosen.unwrap_or(0);
        for (i, (entry, path)) in entries.iter().enumerate() {
            let label = entry
                .get("bucket")
                .or_else(|| entry.get("target"))
                .and_then(Value::as_str)
                .unwrap_or("the project's buckets");
            if i == chosen {
                if let Some(v) = entry.get("rules") {
                    self.storage_rules_file = Some(file(v, &format!("{path}.rules"))?);
                }
            } else if entry.contains_key("rules") {
                report.notices.push(format!(
                    "{path}.rules: fireemu evaluates one Storage ruleset for every bucket, so the rules of {label} are not loaded"
                ));
            }
        }
        Ok(())
    }

    /// `functions`, in object or array (multi-codebase) form.
    #[allow(clippy::too_many_lines)]
    fn apply_functions(
        &mut self,
        section: Option<&Value>,
        base: &std::path::Path,
        only: &Selection,
        report: &mut FirebaseJsonReport,
    ) -> Result<(), ConfigError> {
        let entries: Vec<(&serde_json::Map<String, Value>, String)> = match section {
            None => Vec::new(),
            Some(Value::Object(o)) => vec![(o, "functions".to_owned())],
            Some(Value::Array(a)) => {
                let mut out = Vec::with_capacity(a.len());
                for (i, e) in a.iter().enumerate() {
                    let o = e.as_object().ok_or_else(|| {
                        ConfigError(format!("firebase.json: functions[{i}] must be an object"))
                    })?;
                    out.push((o, format!("functions[{i}]")));
                }
                out
            }
            Some(_) => {
                return Err(ConfigError(
                    "firebase.json: functions must be an object or an array".to_owned(),
                ))
            }
        };
        let mut codebases: Vec<FunctionsCodebase> = Vec::with_capacity(entries.len());
        for (entry, path) in entries {
            for key in entry.keys() {
                if !FUNCTIONS_ENTRY_KEYS.contains(&key.as_str()) {
                    return Err(ConfigError(format!(
                        "firebase.json: unknown key {path}.{key}"
                    )));
                }
            }
            let source = entry.get("source").and_then(Value::as_str).ok_or_else(|| {
                ConfigError(format!(
                    "firebase.json: {path}.source is required and must be a string"
                ))
            })?;
            let codebase = entry
                .get("codebase")
                .map(|v| {
                    v.as_str().map(str::to_owned).ok_or_else(|| {
                        ConfigError(format!("firebase.json: {path}.codebase must be a string"))
                    })
                })
                .transpose()?
                .unwrap_or_else(|| "default".to_owned());
            let runtime = entry
                .get("runtime")
                .map(|v| {
                    v.as_str().map(str::to_owned).ok_or_else(|| {
                        ConfigError(format!("firebase.json: {path}.runtime must be a string"))
                    })
                })
                .transpose()?;
            let mut ignore = Vec::new();
            if let Some(list) = entry.get("ignore") {
                let list = list.as_array().ok_or_else(|| {
                    ConfigError(format!("firebase.json: {path}.ignore must be an array"))
                })?;
                for g in list {
                    ignore.push(
                        g.as_str()
                            .ok_or_else(|| {
                                ConfigError(format!(
                                    "firebase.json: {path}.ignore entries must be strings"
                                ))
                            })?
                            .to_owned(),
                    );
                }
            }
            if codebases.iter().any(|c| c.codebase == codebase) {
                return Err(ConfigError(format!(
                    "firebase.json: functions declares the codebase {codebase:?} twice"
                )));
            }
            codebases.push(FunctionsCodebase {
                codebase,
                source: base.join(source).to_string_lossy().into_owned(),
                runtime,
                ignore,
            });
        }
        self.functions_codebases = codebases;
        if !only.functions {
            return Ok(());
        }
        // `--only functions:<codebase>` picks one out of a multi-codebase project, as the
        // official CLI spells it; without it every declared codebase is loaded, each on its
        // own runner process.
        let chosen: Vec<FunctionsCodebase> = match &only.functions_codebase {
            Some(name) => vec![self
                .functions_codebases
                .iter()
                .find(|c| &c.codebase == name)
                .ok_or_else(|| {
                    ConfigError(format!(
                        "--only functions:{name}: firebase.json declares no such codebase ({})",
                        self.functions_codebases
                            .iter()
                            .map(|c| c.codebase.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                })?
                .clone()],
            None => self.functions_codebases.clone(),
        };
        for c in &chosen {
            check_codebase_runtime(c)?;
        }
        // `functions.source` stays the first codebase's directory, which is what every
        // single-codebase project has and what the banner prints.
        self.functions_source = chosen.first().map(|c| c.source.clone());
        if chosen.len() > 1 {
            report.notices.push(format!(
                "functions: {} codebases are loaded ({}), one runner process each",
                chosen.len(),
                chosen
                    .iter()
                    .map(|c| c.codebase.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        self.functions_loaded = chosen;
        Ok(())
    }
}

impl RuntimeConfig {
    /// The codebases this run loads, one runner process each.
    ///
    /// A `firebase.json` `functions` array gives them all directly; `functions.source` and
    /// `--functions <dir>` give one, named `default`. `--functions` wins over the file, so a
    /// command-line override of a multi-codebase project loads exactly the directory it named.
    #[must_use]
    pub fn functions_to_load(&self) -> Vec<FunctionsCodebase> {
        if !self.functions_loaded.is_empty() {
            return self.functions_loaded.clone();
        }
        self.functions_source
            .iter()
            .map(|source| FunctionsCodebase {
                codebase: "default".to_owned(),
                source: source.clone(),
                runtime: None,
                ignore: Vec::new(),
            })
            .collect()
    }
}

/// Refuses a codebase whose declared `runtime` is not one the bundled runner can execute.
///
/// The official emulator has three loader paths -- Node, Python (`functions-framework` in a
/// virtual environment) and an experimental Dart one -- and picks by this field. fireemu ships
/// the Node runner and nothing else, so a Python or Dart codebase is refused by name rather
/// than handed to `node`, which would fail later with a syntax error from a file the project
/// never meant Node to read.
fn check_codebase_runtime(c: &FunctionsCodebase) -> Result<(), ConfigError> {
    let Some(runtime) = &c.runtime else {
        return Ok(());
    };
    if runtime.starts_with("nodejs") {
        return Ok(());
    }
    let language = if runtime.starts_with("python") {
        "Python"
    } else if runtime.starts_with("dart") {
        "Dart"
    } else {
        "that"
    };
    Err(ConfigError(format!(
        "firebase.json: the Functions codebase {:?} declares runtime {runtime}; fireemu ships \
         one loader, the bundled Node runner, and does not execute {language} functions. \
         Remove the codebase from the emulator run (--only functions:<another codebase>) or \
         run it under the Firebase CLI",
        c.codebase
    )))
}

/// Whether `--only` named `service`.
fn only_names(only: &Selection, service: &str) -> bool {
    match service {
        "firestore" => only.firestore,
        "auth" => only.auth,
        "storage" => only.storage,
        "functions" => only.functions,
        "appcheck" => only.appcheck,
        // A product fireemu does not serve can never be selected: `Selection::parse` refuses
        // the name outright, so reaching here means it was not named.
        _ => false,
    }
}

/// Resolves `--project` through the `.firebaserc` aliases of a project directory.
///
/// `projects.<alias>` maps an alias to a project ID. With a `--project` value the alias wins
/// when one is defined and the value is otherwise taken as a project ID, which is what
/// `firebase --project` does; without one the `default` alias is used.
pub fn resolve_project_alias(
    rc: &Value,
    requested: Option<&str>,
) -> Result<Option<String>, ConfigError> {
    let projects = match rc.get("projects") {
        None => return Ok(requested.map(str::to_owned)),
        Some(Value::Object(p)) => p,
        Some(_) => {
            return Err(ConfigError(
                ".firebaserc: projects must be an object".to_owned(),
            ))
        }
    };
    let alias = requested.unwrap_or("default");
    match projects.get(alias) {
        Some(Value::String(id)) => Ok(Some(id.clone())),
        Some(_) => Err(ConfigError(format!(
            ".firebaserc: projects.{alias} must be a string"
        ))),
        None => Ok(requested.map(str::to_owned)),
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
    /// Selects the compatibility profile and rewrites the settings it derives. Every key the
    /// profile decides is written here and nowhere else, so an explicit key parsed afterwards
    /// simply overwrites it.
    pub fn set_profile(&mut self, profile: CompatibilityProfile) {
        self.profile = profile;
        self.index_policy = profile.index_policy();
        self.enforce_limits = profile.enforce_limits();
        self.token_acceptance = profile.token_acceptance();
    }

    fn parse_daemon(d: &serde_json::Map<String, Value>, cfg: &mut Self) -> Result<(), ConfigError> {
        for key in d.keys() {
            if ![
                "firestorePort",
                "storagePort",
                "httpPort",
                "functionsPort",
                "hubPort",
                "uiPort",
                "clockStart",
                "seed",
                "authProject",
            ]
            .contains(&key.as_str())
            {
                return Err(ConfigError(format!("unknown config key daemon.{key}")));
            }
        }
        if let Some(port) = d.get("hubPort").and_then(Value::as_u64) {
            cfg.hub_addr = format!("127.0.0.1:{port}");
            cfg.hub_addr_explicit = true;
        }
        if let Some(port) = d.get("uiPort").and_then(Value::as_u64) {
            cfg.ui_addr = format!("127.0.0.1:{port}");
            cfg.ui_enabled = port != 0;
            cfg.ui_addr_explicit = true;
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
            fireemu_adapter_functions::zone::resolve(Some(tz))
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
            if ![
                "manifest",
                "source",
                "runner",
                "maxGlobalConcurrency",
                "unservedTriggers",
            ]
            .contains(&key.as_str())
            {
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
        if let Some(v) = f.get("unservedTriggers") {
            let text = v.as_str().unwrap_or_default();
            if !["refuse", "report"].contains(&text) {
                return Err(ConfigError(
                    "functions.unservedTriggers must be \"refuse\" or \"report\"".into(),
                ));
            }
            text.clone_into(&mut cfg.functions_unserved_triggers);
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
            if !(fireemu_core_app_check::limits::MIN_TOKEN_TTL_SECONDS
                ..=fireemu_core_app_check::limits::MAX_TOKEN_TTL_SECONDS)
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
            if apps.len() > fireemu_core_app_check::limits::MAX_APPS {
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
                        fireemu_core_app_check::DebugTokenDigest::parse_hex(digest).map_err(
                            |e| ConfigError(format!("appCheck.apps[{i}].debugTokenSha256: {e}")),
                        )?;
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
                let mode = fireemu_core_app_check::verify::BaselineMode::parse_config(text)
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
                if mode != fireemu_core_app_check::verify::BaselineMode::Off {
                    return Err(ConfigError(format!(
                        "appCheck.services.{name} is {mode} while appCheck.enabled is false"
                    )));
                }
            }
        }
        // The binding rules live in the core registry; building it here makes the loader and
        // the runtime agree by construction.
        let mut registry = fireemu_core_app_check::AppCheckRegistry::new(cfg.token_ttl_seconds)
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
        // The profile is read first: it only moves the defaults every explicit key below
        // then overrides, so the order of the keys in the file never changes the result.
        if let Some(p) = obj.get("profile") {
            let p = p
                .as_str()
                .ok_or_else(|| ConfigError("profile must be a string".to_owned()))?;
            cfg.set_profile(
                CompatibilityProfile::parse_config(p)
                    .ok_or_else(|| ConfigError(format!("unknown profile {p:?}")))?,
            );
        }
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
            if let Some(b) = fs.get("enforceLimits").and_then(Value::as_bool) {
                cfg.enforce_limits = b;
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
                let m = fireemu_core_auth::jwt::SigningMode::parse_config(mode)
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
            "profile": "strict",
            "firestore": {"edition": "standard", "apiMode": "native"},
            "auth": auth,
        }))
    }

    // ----------------------------------------------------------------------------------
    // The compatibility profile (spec/compatibility/contract.json)
    // ----------------------------------------------------------------------------------

    fn with_profile(extra: Value) -> Result<RuntimeConfig, ConfigError> {
        let mut json = json!({
            "schemaVersion": 1,
            "firestore": {"edition": "standard", "apiMode": "native"},
        });
        let (Value::Object(base), Value::Object(extra)) = (&mut json, extra) else {
            unreachable!("both literals are objects")
        };
        for (k, v) in extra {
            base.insert(k, v);
        }
        RuntimeConfig::from_json(&json)
    }

    #[test]
    fn the_profile_sets_the_defaults_it_owns_and_firebase_is_the_default_profile() {
        // The claim in README.md is made under the firebase profile, so a configuration that
        // names no profile at all runs under it: installing fireemu instead of the official
        // suite reproduces the official suite.
        let default = with_profile(json!({})).unwrap();
        assert_eq!(default.profile, CompatibilityProfile::Firebase);
        assert_eq!(RuntimeConfig::default().profile, default.profile);

        // firebase: the pinned official Firestore emulator checks no composite index, does
        // not refuse a query over a Standard limit, and admits the mock tokens
        // @firebase/rules-unit-testing mints.
        let firebase = with_profile(json!({"profile": "firebase"})).unwrap();
        assert_eq!(firebase.index_policy, IndexValidationPolicy::Emulator);
        assert!(!firebase.enforce_limits);
        assert_eq!(firebase.token_acceptance, TokenAcceptance::EmulatorMock);

        // strict: every one of those becomes a refusal.
        let strict = with_profile(json!({"profile": "strict"})).unwrap();
        assert_eq!(strict.index_policy, IndexValidationPolicy::Conservative);
        assert!(strict.enforce_limits);
        assert_eq!(strict.token_acceptance, TokenAcceptance::Verified);
    }

    #[test]
    fn an_explicit_key_wins_over_the_profile_whichever_order_it_is_written_in() {
        // The profile only moves defaults, so a key that names a value keeps it. Both keys
        // sit in sections parsed after the profile and one (firestore) is parsed before the
        // profile appears in the file, which is why the loader reads the profile first.
        let cfg = with_profile(json!({
            "profile": "firebase",
            "firestore": {
                "edition": "standard",
                "apiMode": "native",
                "indexValidationPolicy": "conservative",
                "enforceLimits": true,
            },
        }))
        .unwrap();
        assert_eq!(cfg.profile, CompatibilityProfile::Firebase);
        assert_eq!(cfg.index_policy, IndexValidationPolicy::Conservative);
        assert!(cfg.enforce_limits);

        let cfg = with_profile(json!({
            "profile": "strict",
            "firestore": {
                "edition": "standard",
                "apiMode": "native",
                "indexValidationPolicy": "emulator",
                "enforceLimits": false,
            },
        }))
        .unwrap();
        assert_eq!(cfg.profile, CompatibilityProfile::Strict);
        assert_eq!(cfg.index_policy, IndexValidationPolicy::Emulator);
        assert!(!cfg.enforce_limits);
        // The token semantics have no key of their own: the profile is the only way to ask
        // for them, so an explicit index policy never quietly loosens them.
        assert_eq!(cfg.token_acceptance, TokenAcceptance::Verified);
    }

    #[test]
    fn an_unknown_profile_is_refused_rather_than_ignored() {
        // The names are the contract's; a typo must not silently select the default, which
        // is what "accepted and not interpreted" used to do.
        let e = with_profile(json!({"profile": "compat"})).unwrap_err();
        assert!(e.0.contains("unknown profile"), "{}", e.0);
        let e = with_profile(json!({"profile": true})).unwrap_err();
        assert!(e.0.contains("profile must be a string"), "{}", e.0);
    }

    // ----------------------------------------------------------------------------------
    // App Check (docs/specifications/firebase-app-check.md section 8)
    // ----------------------------------------------------------------------------------

    const DIGEST: &str = "db8055e0e0307d5a016bec4dc338d69875eb0fb7e614a8b125b08fb082095d98";

    fn app_check(section: &Value) -> Result<AppCheckConfig, ConfigError> {
        RuntimeConfig::from_json(&json!({
            "schemaVersion": 1,
            "profile": "strict",
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
                fireemu_core_app_check::verify::BaselineMode::Off
            );
        }
        // A configuration without the section is exactly the default.
        let parsed = RuntimeConfig::from_json(&json!({
            "schemaVersion": 1,
            "profile": "strict",
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
        let text = std::fs::read_to_string(&path).expect("the canonical example is readable");
        let json: Value = serde_json::from_str(&text).expect("the canonical example parses");
        let cfg = RuntimeConfig::from_json(&json).expect("the canonical example loads");
        assert!(cfg.app_check.enabled);
        assert_eq!(cfg.app_check.token_signing, AppCheckSigning::InstanceRsa);
        assert_eq!(cfg.app_check.token_ttl_seconds, 3600);
        assert_eq!(cfg.app_check.apps.len(), 2);
        assert!(cfg.app_check.apps[0].enabled);
        assert!(!cfg.app_check.apps[1].enabled);
        assert_eq!(
            cfg.app_check.firestore,
            fireemu_core_app_check::verify::BaselineMode::Unenforced
        );
        assert_eq!(
            cfg.app_check.storage,
            fireemu_core_app_check::verify::BaselineMode::Enforced
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
        assert_eq!(
            cfg.auth,
            fireemu_core_app_check::verify::BaselineMode::Enforced
        );
        assert_eq!(
            cfg.firestore,
            fireemu_core_app_check::verify::BaselineMode::Off
        );
        assert_eq!(
            cfg.storage,
            fireemu_core_app_check::verify::BaselineMode::Off
        );
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
                "profile": "strict",
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
        use fireemu_core_app_check::verify::BaselineMode::{Enforced, Off, Unenforced};
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
        let report = cfg
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
        assert_eq!(report.notices.len(), 1);
        assert!(
            report.notices[0].starts_with("emulators.pubsub: fireemu does not serve"),
            "{:?}",
            report.notices
        );
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

    /// Every `firebase.json` in the corpus `tools/config-schema-check` validates is loaded
    /// by the real loader too, and every invalid one is refused by it. Without this the two
    /// could drift: a file the schema accepts but the daemon refuses would only be found by
    /// a user.
    #[test]
    fn the_firebase_json_corpus_agrees_with_the_loader() {
        let spec = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/config");
        let read = |dir: &str| -> Vec<(String, Value)> {
            let mut out = Vec::new();
            let entries = std::fs::read_dir(spec.join(dir))
                .unwrap_or_else(|e| panic!("{dir} is readable: {e}"));
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|x| x == "json") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    let json: Value = serde_json::from_str(&text)
                        .unwrap_or_else(|e| panic!("{} parses: {e}", path.display()));
                    out.push((
                        path.file_name().unwrap().to_string_lossy().into_owned(),
                        json,
                    ));
                }
            }
            out.sort_by(|a, b| a.0.cmp(&b.0));
            out
        };
        let base = std::path::Path::new("/proj");
        // Functions are left out: a codebase is chosen by `--only functions:<codebase>`, which
        // is a selection question rather than a validity one, and every codebase is parsed and
        // validated either way.
        let only = Selection::parse("firestore,auth,storage").unwrap();

        let valid = read("firebase-json-examples");
        assert!(valid.len() >= 4, "the corpus must not silently shrink");
        for (name, json) in &valid {
            let mut cfg = RuntimeConfig::default();
            let report = cfg.apply_firebase_json(json, base, &only);
            assert!(report.is_ok(), "{name} must load: {report:?}");
        }

        let invalid = read("firebase-json-invalid-examples");
        assert!(invalid.len() >= 8, "the corpus must not silently shrink");
        for (name, json) in &invalid {
            let mut cfg = RuntimeConfig::default();
            // The functions corpus needs functions selected for the codebase rules to run.
            let selection = if name.starts_with("functions-") {
                Selection::default()
            } else {
                only.clone()
            };
            assert!(
                cfg.apply_firebase_json(json, base, &selection).is_err(),
                "{name} must be refused by the loader, not only by the schema"
            );
        }
    }

    #[test]
    fn every_declared_codebase_is_loaded_and_only_functions_picks_one() {
        let json = json!({
            "functions": [
                {"source": "fn/api", "codebase": "api", "runtime": "nodejs20"},
                {"source": "fn/workers", "codebase": "workers", "ignore": ["node_modules"]}
            ]
        });
        let base = std::path::Path::new("/proj");

        let mut cfg = RuntimeConfig::default();
        let report = cfg
            .apply_firebase_json(&json, base, &Selection::default())
            .expect("a multi-codebase project loads every codebase");
        assert_eq!(cfg.functions_codebases.len(), 2);
        assert_eq!(cfg.functions_codebases[0].codebase, "api");
        assert_eq!(cfg.functions_codebases[0].source, "/proj/fn/api");
        assert_eq!(
            cfg.functions_codebases[0].runtime.as_deref(),
            Some("nodejs20")
        );
        assert_eq!(cfg.functions_codebases[1].ignore, vec!["node_modules"]);
        // Both are loaded, one runner process each, and the run says so.
        assert_eq!(
            cfg.functions_to_load()
                .iter()
                .map(|c| c.codebase.clone())
                .collect::<Vec<_>>(),
            vec!["api".to_owned(), "workers".to_owned()]
        );
        assert!(
            report
                .notices
                .iter()
                .any(|n| n.contains("2 codebases are loaded (api, workers)")),
            "{:?}",
            report.notices
        );

        // Naming one loads it and nothing else.
        let mut cfg = RuntimeConfig::default();
        let only = Selection::parse("functions:workers").unwrap();
        cfg.apply_firebase_json(&json, base, &only).unwrap();
        assert_eq!(cfg.functions_source.as_deref(), Some("/proj/fn/workers"));
        assert_eq!(cfg.functions_to_load().len(), 1);

        // A single codebase needs no name at all, in either spelling.
        for section in [
            json!({"functions": {"source": "functions"}}),
            json!({"functions": [{"source": "functions", "codebase": "default"}]}),
        ] {
            let mut cfg = RuntimeConfig::default();
            cfg.apply_firebase_json(&section, base, &Selection::default())
                .unwrap();
            assert_eq!(cfg.functions_source.as_deref(), Some("/proj/functions"));
            assert_eq!(cfg.functions_to_load().len(), 1);
        }

        // A runtime the bundled Node runner cannot execute is refused by name.
        let mut cfg = RuntimeConfig::default();
        let python = json!({"functions": [{"source": "fn", "runtime": "python312"}]});
        let message = cfg
            .apply_firebase_json(&python, base, &Selection::default())
            .unwrap_err()
            .0;
        assert!(message.contains("python312"), "{message}");
        assert!(message.contains("Python"), "{message}");
    }

    #[test]
    fn emulator_entries_configure_the_served_products_the_hub_and_the_ui() {
        let json = json!({
            "emulators": {
                "singleProjectMode": true,
                "firestore": {"host": "localhost", "port": 8081},
                "auth": {"port": 9100},
                "storage": {"port": 9200},
                "functions": {"port": 5002},
                "hub": {"port": 4401},
                "ui": {"port": 4001, "enabled": false}
            }
        });
        let mut cfg = RuntimeConfig::default();
        let report = cfg
            .apply_firebase_json(&json, std::path::Path::new("/proj"), &Selection::default())
            .unwrap();
        assert!(report.notices.is_empty(), "{:?}", report.notices);
        assert_eq!(cfg.firestore_addr, "localhost:8081");
        assert_eq!(cfg.http_addr, "127.0.0.1:9100");
        assert_eq!(cfg.storage_addr, "127.0.0.1:9200");
        assert_eq!(cfg.functions_addr, "127.0.0.1:5002");
        assert_eq!(cfg.hub_addr, "127.0.0.1:4401");
        assert!(
            cfg.hub_addr_explicit,
            "a configured hub port must be honoured exactly"
        );
        assert_eq!(cfg.ui_addr, "127.0.0.1:4001");
        assert!(!cfg.ui_enabled);
        assert!(cfg.single_project_mode);
    }

    #[test]
    fn firebaserc_aliases_resolve_the_project() {
        let rc = json!({"projects": {"default": "demo-a", "staging": "demo-b"}});
        assert_eq!(
            resolve_project_alias(&rc, None).unwrap().as_deref(),
            Some("demo-a")
        );
        assert_eq!(
            resolve_project_alias(&rc, Some("staging"))
                .unwrap()
                .as_deref(),
            Some("demo-b")
        );
        // A value that is not an alias is a project ID, as `firebase --project` treats it.
        assert_eq!(
            resolve_project_alias(&rc, Some("demo-literal"))
                .unwrap()
                .as_deref(),
            Some("demo-literal")
        );
        // Without a `default` alias and without --project nothing is resolved, so the
        // configured project stands.
        assert_eq!(
            resolve_project_alias(&json!({"projects": {"staging": "demo-b"}}), None).unwrap(),
            None
        );
        assert!(resolve_project_alias(&json!({"projects": []}), None).is_err());
        assert!(resolve_project_alias(&json!({"projects": {"default": 1}}), None).is_err());
    }

    #[test]
    fn the_only_list_names_services_and_at_most_one_functions_codebase() {
        let sel = Selection::parse("firestore,functions:api").unwrap();
        assert!(sel.firestore && sel.functions && sel.explicit);
        assert_eq!(sel.functions_codebase.as_deref(), Some("api"));
        assert!(!sel.auth && !sel.storage && !sel.appcheck);
        // Without --only everything served is selected and nothing is explicit.
        let all = Selection::default();
        assert!(all.firestore && all.auth && all.storage && all.functions && all.appcheck);
        assert!(!all.explicit);
        // A qualifier belongs to functions alone.
        assert!(Selection::parse("firestore:default").is_err());
        assert!(Selection::parse("functions:").is_err());
        // Every official service fireemu does not serve is refused with its status.
        for (name, status) in UNSERVED_OFFICIAL_SERVICES {
            let message = Selection::parse(&format!("firestore,{name}"))
                .unwrap_err()
                .0;
            assert!(message.contains(name), "{name}: {message}");
            assert!(message.contains(status), "{name}: {message}");
        }
        for name in NON_SERVICE_EMULATORS {
            assert!(
                Selection::parse(name)
                    .unwrap_err()
                    .0
                    .contains("not a service emulator"),
                "{name}"
            );
        }
    }

    #[test]
    fn the_auth_section_never_downgrades_silently() {
        assert_eq!(
            parse(&json!({"idTokenSigning": "session-rsa"}))
                .unwrap()
                .id_token_signing,
            fireemu_core_auth::jwt::SigningMode::SessionRsa
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
