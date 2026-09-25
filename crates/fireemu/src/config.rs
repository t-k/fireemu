//! Runtime configuration: the canonical JSON config (spec 17) plus command-line overrides.
//!
//! Only the keys the daemon currently honours are read; unknown keys are still rejected so
//! that typos never silently change behaviour (the JSON schema in `spec/config` is the
//! authority; this loader enforces the same rule on the subset it understands).

use std::collections::{BTreeMap, BTreeSet};

use fireemu_core_auth::jwt::TokenAcceptance;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_firestore::index::IndexValidationPolicy;
use fireemu_core_pubsub::subscription::MAX_PUSH_MINIMUM_REDELIVERY_INTERVAL_MILLIS;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{Map, Value};

/// The compatibility profile (`profile`), the one switch that decides whether fireemu
/// reproduces the pinned official emulators or production Firebase.
///
/// The two profiles are declared in `spec/compatibility/contract.json`; this enum is the
/// half the daemon executes. The keys a profile only *declares* stay declared: what the
/// runtime derives from it is [`Self::index_policy`], [`Self::enforce_limits`],
/// [`Self::token_acceptance`] and [`Self::implicit_database_creation`]. The index policy has
/// no configuration key of its own and follows the profile; `firestore.enforceLimits` may
/// still override its default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompatibilityProfile {
    /// Reproduce the behaviour the pinned Local Emulator Suite ships, including its
    /// documented limitations. This is the profile the README's compatibility claim is made
    /// under; choose it explicitly when matching the official suite matters more than
    /// matching production.
    Emulator,
    /// Behave like production Firebase where the official emulator does not: composite
    /// indexes are checked with production's rules, Standard query limits refuse the query,
    /// and ID tokens are verified. Every difference it makes may only refuse more than the
    /// official emulator, never less. This is the default: fireemu exists to expose locally
    /// what production would refuse, so a configuration that names no profile runs under it,
    /// and `fireemu init` writes the same choice down.
    #[default]
    Strict,
}

/// Rules and index files declared for one Firestore database in `firebase.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FirestoreDatabaseFiles {
    /// Security Rules source.
    pub rules: Option<String>,
    /// Composite and single-field index configuration.
    pub indexes: Option<String>,
}

/// Password policy configured for one Auth namespace. This is a local configuration
/// contract; the Identity Toolkit adapter projects it into its public API separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicyConfig {
    /// `OFF` or `ENFORCE`.
    pub enforcement_state: String,
    /// Whether a non-compliant existing password must be upgraded at sign-in.
    pub force_upgrade_on_signin: bool,
    /// Password strength constraints.
    pub constraints: PasswordPolicyConstraints,
}

/// Password strength constraints from `auth.passwordPolicy.constraints`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct PasswordPolicyConstraints {
    /// Minimum UTF-16 code units accepted by the local policy evaluator.
    pub min_length: u32,
    /// Optional custom maximum. `None` is distinct from an explicit maximum.
    pub max_length: Option<u32>,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numeric: bool,
    pub require_non_alphanumeric: bool,
}

/// An explicit project/tenant password policy override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicyOverride {
    pub project_id: String,
    pub tenant_id: Option<String>,
    pub password_policy: PasswordPolicyConfig,
}

/// The sign-in providers from `auth.signIn` (`email`, `anonymous`, `phoneNumber`). Each
/// unset member keeps fireemu's default, where every provider is enabled in both profiles
/// (owner decision K14, AUTH-CONFIG-SDK; a new production project enables none).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthSignInSettings {
    /// `auth.signIn.email.enabled`.
    pub email_enabled: Option<bool>,
    /// `auth.signIn.email.passwordRequired` (email-link sign-in is off while set).
    pub password_required: Option<bool>,
    /// `auth.signIn.anonymous.enabled`.
    pub anonymous_enabled: Option<bool>,
    /// `auth.signIn.phoneNumber.enabled`.
    pub phone_enabled: Option<bool>,
    /// `auth.signIn.phoneNumber.testPhoneNumbers`: E.164 number to its code.
    pub test_phone_numbers: Option<BTreeMap<String, String>>,
}

/// End-user account creation and deletion switches from `auth.client.permissions`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthClientPermissions {
    /// When true, end-user account creation is refused. Administrative creation remains
    /// available; the runtime owner for this switch is tracked separately from this loader.
    pub disabled_user_signup: bool,
    /// When true, end-user account deletion is refused. Administrative deletion remains
    /// available; the runtime owner for this switch is tracked separately from this loader.
    pub disabled_user_deletion: bool,
}

/// Settings that may be overridden for one project/tenant namespace.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthNamespaceConfig {
    /// An explicitly configured client permission group.
    pub client_permissions: Option<AuthClientPermissions>,
    /// An explicitly configured email privacy switch.
    pub improved_email_privacy: Option<bool>,
}

/// An explicit project/tenant Auth configuration override. Password policies use their own
/// override list because their public and local schemas are different.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfigOverride {
    pub project_id: String,
    pub tenant_id: Option<String>,
    pub config: AuthNamespaceConfig,
}

/// One locally selected blocking Auth function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockingFunctionTrigger {
    pub function: String,
    pub region: Option<String>,
}

/// Explicit trigger selection. `None` for a trigger means it is disabled when `triggers` was
/// explicitly supplied; an omitted `triggers` object is represented by `None` on the parent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockingFunctionTriggers {
    pub before_create: Option<BlockingFunctionTrigger>,
    pub before_sign_in: Option<BlockingFunctionTrigger>,
}

/// Per-token forwarding switches for blocking functions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockingInboundCredentials {
    pub id_token: bool,
    pub access_token: bool,
    pub refresh_token: bool,
}

/// Local blocking-function selection and forwarding policy. This is intentionally a typed
/// local contract; resolving a function to a running Functions instance belongs to the
/// Functions/Auth adapter owner.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockingFunctionsConfig {
    /// `None` means discovery-based selection; `Some` means the two trigger names are the
    /// complete explicit selection, including explicit null/omission as disabled.
    pub triggers: Option<BlockingFunctionTriggers>,
    /// `None` preserves the legacy global switch plus per-function policy behavior.
    pub forward_inbound_credentials: Option<BlockingInboundCredentials>,
}

/// The official-shaped temporary sign-up quota configuration. `quota` remains a decimal
/// string so the local representation cannot accidentally lose int64 precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSignUpQuotaConfig {
    pub quota: String,
    pub start_time: LogicalInstant,
    pub quota_duration: LogicalDuration,
}

/// Local deterministic quota simulation. It is not a claim about Google's private abuse
/// controls or production's complete quota algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthQuotaSimulationMode {
    Off,
    Observe,
    Enforce,
}

impl AuthQuotaSimulationMode {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "off" => Some(Self::Off),
            "observe" => Some(Self::Observe),
            "enforce" => Some(Self::Enforce),
            _ => None,
        }
    }
}

/// Bounded fixed-window quota simulation settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthQuotaSimulationConfig {
    pub mode: AuthQuotaSimulationMode,
    pub algorithm: String,
    pub default_quota_per_hour: u64,
    pub max_tracked_buckets: usize,
}

impl Default for AuthQuotaSimulationConfig {
    fn default() -> Self {
        Self {
            mode: AuthQuotaSimulationMode::Off,
            algorithm: "fixed-window-v1".to_owned(),
            default_quota_per_hour: 100,
            max_tracked_buckets: 4096,
        }
    }
}

impl PasswordPolicyConfig {
    /// Converts the validated file representation into the Auth runtime representation.
    #[must_use]
    pub fn to_auth_policy(&self) -> fireemu_core_auth::password_policy::PasswordPolicy {
        let state = match self.enforcement_state.as_str() {
            "ENFORCE" => fireemu_core_auth::password_policy::EnforcementState::Enforce,
            _ => fireemu_core_auth::password_policy::EnforcementState::Off,
        };
        fireemu_core_auth::password_policy::PasswordPolicy::try_new(
            state,
            self.force_upgrade_on_signin,
            self.constraints.min_length as usize,
            self.constraints.max_length.map(|value| value as usize),
            self.constraints.require_uppercase,
            self.constraints.require_lowercase,
            self.constraints.require_numeric,
            self.constraints.require_non_alphanumeric,
            fireemu_core_auth::password_policy::default_allowed_non_alphanumeric(),
        )
        .expect("validated password policy configuration")
    }
}

impl CompatibilityProfile {
    /// Parses the canonical configuration value.
    #[must_use]
    pub fn parse_config(text: &str) -> Option<Self> {
        match text {
            "emulator" => Some(Self::Emulator),
            "strict" => Some(Self::Strict),
            _ => None,
        }
    }

    /// The canonical configuration value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Emulator => "emulator",
            Self::Strict => "strict",
        }
    }

    /// The index validation policy; it has no configuration key of its own.
    ///
    /// The pinned official Firestore emulator does not check composite indexes at all, so
    /// the profile that reproduces it assumes them and reports each one it assumed. `strict`
    /// applies production's rules, verified against a real project: a query without a
    /// supporting index is refused with the `firestore.indexes.json` fragment production
    /// would need, and the index merges production performs are accepted.
    #[must_use]
    pub const fn index_policy(self) -> IndexValidationPolicy {
        match self {
            Self::Emulator => IndexValidationPolicy::Emulator,
            Self::Strict => IndexValidationPolicy::Production,
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
            Self::Emulator => TokenAcceptance::EmulatorMock,
            Self::Strict => TokenAcceptance::Verified,
        }
    }

    /// Whether a Firestore data-plane request against a database nothing created materializes
    /// it. The official emulator serves any syntactically valid database id without a
    /// `databases.create`, so the profile that reproduces it does too; production answers
    /// `NOT_FOUND` until the database is created, which is what `strict` answers. The default
    /// database and the databases the configuration declares exist under both.
    #[must_use]
    pub const fn implicit_database_creation(self) -> bool {
        matches!(self, Self::Emulator)
    }
}

/// The Emulator Hub's official default port (`firebase-tools` `Constants.getDefaultPort`).
pub const DEFAULT_HUB_PORT: u16 = 4400;

/// The Emulator UI's official default port.
pub const DEFAULT_UI_PORT: u16 = 4000;

/// The Logging emulator's official default port (`firebase-tools` `Constants.getDefaultPort`).
pub const DEFAULT_LOGGING_PORT: u16 = 4500;

const LIMIT_KEYS: [&str; 9] = [
    "catalog",
    "queryCatalog",
    "rulesCatalog",
    "enforcement",
    "warningThresholds",
    "perLimitWarningThresholds",
    "warningsAsErrors",
    "quotaAccounting",
    "firestorePlan",
];

const FIRESTORE_PLAN_KEYS: [&str; 4] = [
    "billingEnabled",
    "compositeIndexLimitOverride",
    "singleFieldConfigLimitOverride",
    "enterpriseIndexLimitOverride",
];

const FIRESTORE_PLAN_OVERRIDE_KEYS: [&str; 3] = [
    "compositeIndexLimitOverride",
    "singleFieldConfigLimitOverride",
    "enterpriseIndexLimitOverride",
];

const PASSWORD_POLICY_KEYS: [&str; 3] = ["enforcementState", "forceUpgradeOnSignin", "constraints"];
const PASSWORD_CONSTRAINT_KEYS: [&str; 6] = [
    "minLength",
    "maxLength",
    "requireUppercase",
    "requireLowercase",
    "requireNumeric",
    "requireNonAlphanumeric",
];

fn parse_password_policy(value: &Value, path: &str) -> Result<PasswordPolicyConfig, ConfigError> {
    let object = value
        .as_object()
        .ok_or_else(|| ConfigError(format!("{path} must be an object")))?;
    for key in object.keys() {
        if !PASSWORD_POLICY_KEYS.contains(&key.as_str()) {
            return Err(ConfigError(format!("unknown config key {path}.{key}")));
        }
    }
    let enforcement_state = object
        .get("enforcementState")
        .and_then(Value::as_str)
        .ok_or_else(|| ConfigError(format!("{path}.enforcementState must be OFF or ENFORCE")))?;
    if !matches!(enforcement_state, "OFF" | "ENFORCE") {
        return Err(ConfigError(format!(
            "{path}.enforcementState must be OFF or ENFORCE"
        )));
    }
    let force_upgrade_on_signin = match object.get("forceUpgradeOnSignin") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| ConfigError(format!("{path}.forceUpgradeOnSignin must be a boolean")))?,
    };
    let constraints = match object.get("constraints") {
        None => PasswordPolicyConstraints::default(),
        Some(value) => parse_password_constraints(value, &format!("{path}.constraints"))?,
    };
    Ok(PasswordPolicyConfig {
        enforcement_state: enforcement_state.to_owned(),
        force_upgrade_on_signin,
        constraints,
    })
}

fn parse_password_constraints(
    value: &Value,
    path: &str,
) -> Result<PasswordPolicyConstraints, ConfigError> {
    let object = value
        .as_object()
        .ok_or_else(|| ConfigError(format!("{path} must be an object")))?;
    for key in object.keys() {
        if !PASSWORD_CONSTRAINT_KEYS.contains(&key.as_str()) {
            return Err(ConfigError(format!("unknown config key {path}.{key}")));
        }
    }
    let integer = |key: &str, default: u32| -> Result<u32, ConfigError> {
        match object.get(key) {
            None => Ok(default),
            Some(value) => value
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| ConfigError(format!("{path}.{key} must be an integer"))),
        }
    };
    let boolean = |key: &str| -> Result<bool, ConfigError> {
        match object.get(key) {
            None => Ok(false),
            Some(value) => value
                .as_bool()
                .ok_or_else(|| ConfigError(format!("{path}.{key} must be a boolean"))),
        }
    };
    let min_length = integer("minLength", 6)?;
    if !(6..=30).contains(&min_length) {
        return Err(ConfigError(format!(
            "{path}.minLength must be between 6 and 30"
        )));
    }
    let max_length = match object.get("maxLength") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| {
                    ConfigError(format!("{path}.maxLength must be an integer or null"))
                })?,
        ),
    };
    if let Some(max) = max_length {
        if !(min_length..=4096).contains(&max) {
            return Err(ConfigError(format!(
                "{path}.maxLength must be between minLength and 4096"
            )));
        }
    }
    Ok(PasswordPolicyConstraints {
        min_length,
        max_length,
        require_uppercase: boolean("requireUppercase")?,
        require_lowercase: boolean("requireLowercase")?,
        require_numeric: boolean("requireNumeric")?,
        require_non_alphanumeric: boolean("requireNonAlphanumeric")?,
    })
}

impl Default for PasswordPolicyConstraints {
    fn default() -> Self {
        Self {
            min_length: 6,
            max_length: None,
            require_uppercase: false,
            require_lowercase: false,
            require_numeric: false,
            require_non_alphanumeric: false,
        }
    }
}

fn valid_policy_namespace_id(value: &str, path: &str) -> Result<String, ConfigError> {
    if value.is_empty() || value.contains('/') {
        return Err(ConfigError(format!(
            "{path} must be a non-empty project or tenant ID"
        )));
    }
    Ok(value.to_owned())
}

fn parse_strict_bool(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
    default: bool,
) -> Result<bool, ConfigError> {
    match object.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| ConfigError(format!("{path}.{key} must be a boolean"))),
    }
}

fn parse_auth_client_permissions(
    value: &Value,
    path: &str,
) -> Result<AuthClientPermissions, ConfigError> {
    let object = value
        .as_object()
        .ok_or_else(|| ConfigError(format!("{path} must be an object")))?;
    for key in object.keys() {
        if !["disabledUserSignup", "disabledUserDeletion"].contains(&key.as_str()) {
            return Err(ConfigError(format!("unknown config key {path}.{key}")));
        }
    }
    Ok(AuthClientPermissions {
        disabled_user_signup: parse_strict_bool(object, "disabledUserSignup", path, false)?,
        disabled_user_deletion: parse_strict_bool(object, "disabledUserDeletion", path, false)?,
    })
}

fn parse_auth_config_override_value(
    value: &Value,
    path: &str,
) -> Result<AuthNamespaceConfig, ConfigError> {
    let object = value
        .as_object()
        .ok_or_else(|| ConfigError(format!("{path} must be an object")))?;
    for key in object.keys() {
        if !["client", "improvedEmailPrivacy"].contains(&key.as_str()) {
            return Err(ConfigError(format!("unknown config key {path}.{key}")));
        }
    }
    let client_permissions = match object.get("client") {
        None => None,
        Some(value) => {
            let client = value
                .as_object()
                .ok_or_else(|| ConfigError(format!("{path}.client must be an object")))?;
            for key in client.keys() {
                if key != "permissions" {
                    return Err(ConfigError(format!(
                        "unknown config key {path}.client.{key}"
                    )));
                }
            }
            match client.get("permissions") {
                None => None,
                Some(value) => Some(parse_auth_client_permissions(
                    value,
                    &format!("{path}.client.permissions"),
                )?),
            }
        }
    };
    let improved_email_privacy = match object.get("improvedEmailPrivacy") {
        None => None,
        Some(value) => Some(value.as_bool().ok_or_else(|| {
            ConfigError(format!("{path}.improvedEmailPrivacy must be a boolean"))
        })?),
    };
    if client_permissions.is_none() && improved_email_privacy.is_none() {
        return Err(ConfigError(format!(
            "{path} must specify client.permissions or improvedEmailPrivacy"
        )));
    }
    Ok(AuthNamespaceConfig {
        client_permissions,
        improved_email_privacy,
    })
}

fn parse_auth_config_overrides(
    value: &Value,
    path: &str,
    default_project: &str,
    root_client_configured: bool,
    root_privacy_configured: bool,
) -> Result<Vec<AuthConfigOverride>, ConfigError> {
    let entries = value
        .as_array()
        .ok_or_else(|| ConfigError(format!("{path} must be an array")))?;
    let mut seen = BTreeSet::new();
    let mut overrides = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let entry_path = format!("{path}[{index}]");
        let object = entry
            .as_object()
            .ok_or_else(|| ConfigError(format!("{entry_path} must be an object")))?;
        for key in object.keys() {
            if !["projectId", "tenantId", "config"].contains(&key.as_str()) {
                return Err(ConfigError(format!(
                    "unknown config key {entry_path}.{key}"
                )));
            }
        }
        let project_id = object
            .get("projectId")
            .and_then(Value::as_str)
            .ok_or_else(|| ConfigError(format!("{entry_path}.projectId must be a string")))
            .and_then(|id| valid_policy_namespace_id(id, &format!("{entry_path}.projectId")))?;
        let tenant_id = match object.get("tenantId") {
            None => None,
            Some(value) => Some(valid_policy_namespace_id(
                value.as_str().ok_or_else(|| {
                    ConfigError(format!("{entry_path}.tenantId must be a non-empty string"))
                })?,
                &format!("{entry_path}.tenantId"),
            )?),
        };
        let namespace = (project_id.clone(), tenant_id.clone());
        if !seen.insert(namespace) {
            return Err(ConfigError(format!(
                "duplicate Auth config namespace at {entry_path}"
            )));
        }
        let config_value = object
            .get("config")
            .ok_or_else(|| ConfigError(format!("{entry_path}.config is required")))?;
        let config =
            parse_auth_config_override_value(config_value, &format!("{entry_path}.config"))?;
        if tenant_id.is_none()
            && project_id == default_project
            && ((root_client_configured && config.client_permissions.is_some())
                || (root_privacy_configured && config.improved_email_privacy.is_some()))
        {
            return Err(ConfigError(format!(
                "auth config override at {entry_path} duplicates explicitly configured default-project settings"
            )));
        }
        overrides.push(AuthConfigOverride {
            project_id,
            tenant_id,
            config,
        });
    }
    Ok(overrides)
}

fn parse_blocking_trigger(
    value: &Value,
    path: &str,
) -> Result<Option<BlockingFunctionTrigger>, ConfigError> {
    if value.is_null() {
        return Ok(None);
    }
    let object = value
        .as_object()
        .ok_or_else(|| ConfigError(format!("{path} must be an object or null")))?;
    for key in object.keys() {
        if !["function", "region"].contains(&key.as_str()) {
            return Err(ConfigError(format!("unknown config key {path}.{key}")));
        }
    }
    let function = object
        .get("function")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| ConfigError(format!("{path}.function must be a non-empty string")))?
        .to_owned();
    let region = match object.get("region") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .filter(|region| !region.is_empty())
                .ok_or_else(|| ConfigError(format!("{path}.region must be a non-empty string")))?
                .to_owned(),
        ),
    };
    Ok(Some(BlockingFunctionTrigger { function, region }))
}

fn parse_blocking_functions(
    value: &Value,
    path: &str,
    global_forwarding: bool,
) -> Result<BlockingFunctionsConfig, ConfigError> {
    let object = value
        .as_object()
        .ok_or_else(|| ConfigError(format!("{path} must be an object")))?;
    for key in object.keys() {
        if !["triggers", "forwardInboundCredentials"].contains(&key.as_str()) {
            return Err(ConfigError(format!("unknown config key {path}.{key}")));
        }
    }
    let triggers = match object.get("triggers") {
        None => None,
        Some(value) => {
            let trigger_object = value
                .as_object()
                .ok_or_else(|| ConfigError(format!("{path}.triggers must be an object")))?;
            for key in trigger_object.keys() {
                if !["beforeCreate", "beforeSignIn"].contains(&key.as_str()) {
                    return Err(ConfigError(format!(
                        "unknown config key {path}.triggers.{key}"
                    )));
                }
            }
            Some(BlockingFunctionTriggers {
                before_create: trigger_object
                    .get("beforeCreate")
                    .map(|value| {
                        parse_blocking_trigger(value, &format!("{path}.triggers.beforeCreate"))
                    })
                    .transpose()?
                    .flatten(),
                before_sign_in: trigger_object
                    .get("beforeSignIn")
                    .map(|value| {
                        parse_blocking_trigger(value, &format!("{path}.triggers.beforeSignIn"))
                    })
                    .transpose()?
                    .flatten(),
            })
        }
    };
    let forward_inbound_credentials = match object.get("forwardInboundCredentials") {
        None => None,
        Some(value) => {
            let forwarding = value.as_object().ok_or_else(|| {
                ConfigError(format!(
                    "{path}.forwardInboundCredentials must be an object"
                ))
            })?;
            for key in forwarding.keys() {
                if !["idToken", "accessToken", "refreshToken"].contains(&key.as_str()) {
                    return Err(ConfigError(format!(
                        "unknown config key {path}.forwardInboundCredentials.{key}"
                    )));
                }
            }
            let forwarding_path = format!("{path}.forwardInboundCredentials");
            let config = BlockingInboundCredentials {
                id_token: parse_strict_bool(forwarding, "idToken", &forwarding_path, false)?,
                access_token: parse_strict_bool(
                    forwarding,
                    "accessToken",
                    &forwarding_path,
                    false,
                )?,
                refresh_token: parse_strict_bool(
                    forwarding,
                    "refreshToken",
                    &forwarding_path,
                    false,
                )?,
            };
            if !global_forwarding
                && (config.id_token || config.access_token || config.refresh_token)
            {
                return Err(ConfigError(format!(
                    "{path}.forwardInboundCredentials cannot enable a token while auth.forwardInboundCredentials is false"
                )));
            }
            Some(config)
        }
    };
    Ok(BlockingFunctionsConfig {
        triggers,
        forward_inbound_credentials,
    })
}

fn parse_protobuf_duration(value: &Value, path: &str) -> Result<LogicalDuration, ConfigError> {
    let text = value
        .as_str()
        .ok_or_else(|| ConfigError(format!("{path} must be a protobuf duration string")))?;
    let body = text
        .strip_suffix('s')
        .filter(|body| !body.is_empty() && !body.starts_with(['+', '-']))
        .ok_or_else(|| ConfigError(format!("{path} must be a positive protobuf duration")))?;
    let (seconds_text, fraction_text) = match body.split_once('.') {
        Some((seconds, fraction)) if !fraction.is_empty() => (seconds, fraction),
        Some(_) => {
            return Err(ConfigError(format!(
                "{path} must use a decimal protobuf duration such as 86400s"
            )));
        }
        None => (body, ""),
    };
    if seconds_text.is_empty()
        || !seconds_text.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction_text.bytes().all(|byte| byte.is_ascii_digit())
        || fraction_text.len() > 9
    {
        return Err(ConfigError(format!(
            "{path} must use a decimal protobuf duration such as 86400s"
        )));
    }
    let seconds = seconds_text
        .parse::<i128>()
        .map_err(|_| ConfigError(format!("{path} seconds are outside the supported range")))?;
    let fraction = if fraction_text.is_empty() {
        0
    } else {
        let nanos = fraction_text
            .parse::<i128>()
            .map_err(|_| ConfigError(format!("{path} fraction is outside the supported range")))?;
        let exponent = u32::try_from(9 - fraction_text.len())
            .expect("validated protobuf fraction length is at most nine");
        nanos * 10_i128.pow(exponent)
    };
    let nanos = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(fraction))
        .ok_or_else(|| ConfigError(format!("{path} is outside the supported range")))?;
    if nanos <= 0 {
        return Err(ConfigError(format!("{path} must be positive")));
    }
    Ok(LogicalDuration::from_nanos(nanos))
}

fn parse_auth_quota(
    value: &Value,
    path: &str,
) -> Result<Option<AuthSignUpQuotaConfig>, ConfigError> {
    let object = value
        .as_object()
        .ok_or_else(|| ConfigError(format!("{path} must be an object")))?;
    for key in object.keys() {
        if key != "signUpQuotaConfig" {
            return Err(ConfigError(format!("unknown config key {path}.{key}")));
        }
    }
    let Some(value) = object.get("signUpQuotaConfig") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let quota_path = format!("{path}.signUpQuotaConfig");
    let quota = value
        .as_object()
        .ok_or_else(|| ConfigError(format!("{quota_path} must be an object or null")))?;
    for key in quota.keys() {
        if !["quota", "startTime", "quotaDuration"].contains(&key.as_str()) {
            return Err(ConfigError(format!(
                "unknown config key {quota_path}.{key}"
            )));
        }
    }
    let quota_value = quota
        .get("quota")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.bytes().all(|byte| byte.is_ascii_digit())
                && value
                    .parse::<u64>()
                    .is_ok_and(|number| i64::try_from(number).is_ok())
        })
        .ok_or_else(|| {
            ConfigError(format!(
                "{quota_path}.quota must be a non-negative decimal int64 string"
            ))
        })?
        .to_owned();
    let start_text = quota
        .get("startTime")
        .and_then(Value::as_str)
        .ok_or_else(|| ConfigError(format!("{quota_path}.startTime must be an RFC3339 string")))?;
    let start_time = LogicalInstant::parse_rfc3339(start_text)
        .map_err(|error| ConfigError(format!("{quota_path}.startTime: {error}")))?;
    let quota_duration = parse_protobuf_duration(
        quota
            .get("quotaDuration")
            .ok_or_else(|| ConfigError(format!("{quota_path}.quotaDuration is required")))?,
        &format!("{quota_path}.quotaDuration"),
    )?;
    Ok(Some(AuthSignUpQuotaConfig {
        quota: quota_value,
        start_time,
        quota_duration,
    }))
}

fn parse_auth_quota_simulation(
    value: &Value,
    path: &str,
) -> Result<AuthQuotaSimulationConfig, ConfigError> {
    let object = value
        .as_object()
        .ok_or_else(|| ConfigError(format!("{path} must be an object")))?;
    for key in object.keys() {
        if ![
            "mode",
            "algorithm",
            "defaultQuotaPerHour",
            "maxTrackedBuckets",
        ]
        .contains(&key.as_str())
        {
            return Err(ConfigError(format!("unknown config key {path}.{key}")));
        }
    }
    let defaults = AuthQuotaSimulationConfig::default();
    let mode = match object.get("mode") {
        None => defaults.mode,
        Some(value) => {
            let text = value
                .as_str()
                .ok_or_else(|| ConfigError(format!("{path}.mode must be a string")))?;
            AuthQuotaSimulationMode::parse(text).ok_or_else(|| {
                ConfigError(format!("{path}.mode must be off, observe, or enforce"))
            })?
        }
    };
    let algorithm = match object.get("algorithm") {
        None => defaults.algorithm,
        Some(value) => {
            let text = value
                .as_str()
                .ok_or_else(|| ConfigError(format!("{path}.algorithm must be a string")))?;
            if text != "fixed-window-v1" {
                return Err(ConfigError(format!(
                    "{path}.algorithm must be \"fixed-window-v1\""
                )));
            }
            text.to_owned()
        }
    };
    let default_quota_per_hour = match object.get("defaultQuotaPerHour") {
        None => defaults.default_quota_per_hour,
        Some(value) => value
            .as_u64()
            .filter(|value| *value <= 1_000_000)
            .ok_or_else(|| {
                ConfigError(format!(
                    "{path}.defaultQuotaPerHour must be an integer from 0 through 1000000"
                ))
            })?,
    };
    let max_tracked_buckets = match object.get("maxTrackedBuckets") {
        None => defaults.max_tracked_buckets,
        Some(value) => value
            .as_u64()
            .filter(|value| (1..=65_536).contains(value))
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| {
                ConfigError(format!(
                    "{path}.maxTrackedBuckets must be an integer from 1 through 65536"
                ))
            })?,
    };
    Ok(AuthQuotaSimulationConfig {
        mode,
        algorithm,
        default_quota_per_hour,
        max_tracked_buckets,
    })
}

/// Effective daemon configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent switches, each read on its own
pub struct RuntimeConfig {
    /// Compatibility profile (`profile`). It sets the defaults of [`Self::index_policy`],
    /// [`Self::enforce_limits`], [`Self::token_acceptance`] and
    /// [`Self::implicit_database_creation`]; an explicit key wins.
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
    /// Index validation policy, derived from the profile (no key of its own).
    pub index_policy: IndexValidationPolicy,
    /// Whether a Standard query limit violation refuses the query
    /// (`firestore.enforceLimits`; profile default). When it does not, each violation is
    /// reported as an `FS_LIMIT_OBSERVED:<id>` warning and the query runs.
    pub enforce_limits: bool,
    /// How a caller's ID token is verified on the Firestore and Storage Rules surfaces
    /// (profile-derived; there is no key of its own).
    pub token_acceptance: TokenAcceptance,
    /// Whether a Firestore data-plane request materializes a database nothing created, the
    /// way the official emulator does, or is refused with production's `NOT_FOUND`
    /// (profile-derived; there is no key of its own).
    pub implicit_database_creation: bool,
    /// How long a document whose time-to-live field has expired stays readable before the
    /// expiry sweep deletes it (`firestore.ttlSweepIntervalSeconds`). Production deletes
    /// typically within 24 hours and within 72 hours at worst, so the default is 24 hours
    /// and the accepted range ends at the documented outer bound.
    pub ttl_sweep_interval: LogicalDuration,
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
    /// Explicit project ID to number mappings for Auth response metadata.
    pub auth_project_numbers: BTreeMap<String, u64>,
    /// fireemu-only TOTP policy. Absence preserves the official Auth emulator's rejection
    /// of TOTP enrollment; declaring `auth.totp` explicitly enables the extension.
    pub auth_totp: Option<TotpPolicy>,
    /// Whether the Functions blocking Auth bridge may receive raw inbound `IdP` credentials.
    /// This is disabled by default because those values are sensitive and are not needed by
    /// ordinary blocking handlers.
    pub auth_forward_inbound_credentials: bool,
    /// `auth.improvedEmailPrivacy`: production's email enumeration protection, on by default
    /// for every new Firebase project and so under the strict profile. Sign-in with a wrong
    /// password or an unknown address answers `INVALID_LOGIN_CREDENTIALS`, and a password reset
    /// for an unknown address is acknowledged. The emulator profile starts with it off, with the
    /// official Auth emulator's revealing answers.
    pub auth_improved_email_privacy: bool,
    /// Whether auth.improvedEmailPrivacy was explicitly present in the input.
    pub auth_improved_email_privacy_explicit: bool,
    /// `auth.signIn`'s providers.
    pub auth_sign_in: AuthSignInSettings,
    /// `auth.logActionCodes`: print every email action link and SMS code to the daemon's
    /// standard output as the official Auth emulator does, on by default. `false` keeps the
    /// codes off the console; they stay readable from the emulator inspection routes.
    pub auth_log_action_codes: bool,
    /// Optional default-project password policy from `auth.passwordPolicy`.
    pub auth_password_policy: Option<PasswordPolicyConfig>,
    /// Explicit project/tenant password policy overrides.
    pub auth_password_policy_overrides: Vec<PasswordPolicyOverride>,
    /// `auth.signIn.allowDuplicateEmails`, with the existing Auth default preserved when the
    /// section is omitted.
    pub auth_allow_duplicate_emails: bool,
    /// Whether auth.signIn.allowDuplicateEmails was explicitly present in the input.
    pub auth_allow_duplicate_emails_explicit: bool,
    /// `auth.client.permissions` for the default Auth namespace.
    pub auth_client_permissions: AuthClientPermissions,
    /// Whether auth.client.permissions was explicitly present in the input.
    pub auth_client_permissions_explicit: bool,
    /// Explicit project/tenant overrides for the non-password Auth settings.
    pub auth_config_overrides: Vec<AuthConfigOverride>,
    /// Explicit blocking function selection and per-token forwarding settings.
    pub auth_blocking_functions: Option<BlockingFunctionsConfig>,
    /// Official-shaped temporary sign-up quota configuration.
    pub auth_signup_quota: Option<AuthSignUpQuotaConfig>,
    /// Whether `auth.quota` was explicitly present in the startup file, including an explicit
    /// null `signUpQuotaConfig` that clears an imported temporary override.
    pub auth_signup_quota_explicit: bool,
    /// fireemu-local deterministic sign-up quota simulation.
    pub auth_quota_simulation: AuthQuotaSimulationConfig,
    /// Whether `auth.quotaSimulation` was explicitly present in the startup file.
    pub auth_quota_simulation_explicit: bool,
    /// Path of `firestore.indexes.json`, if configured.
    pub index_file: Option<String>,
    /// Path of `firestore.text-indexes.json`, if configured.
    pub text_index_file: Option<String>,
    /// Path of the Security Rules source, if configured.
    pub rules_file: Option<String>,
    /// Per-database Firestore files, including `(default)` when declared by `firebase.json`.
    pub firestore_databases: BTreeMap<String, FirestoreDatabaseFiles>,
    /// Path of the Storage Security Rules source, if configured.
    pub storage_rules_file: Option<String>,
    /// Rules files declared by a target-based Storage array, before `.firebaserc` expansion.
    pub storage_rules_by_target: BTreeMap<String, String>,
    /// Rules files selected by concrete bucket after `.firebaserc` expansion.
    pub storage_rules_by_bucket: BTreeMap<String, String>,
    /// Concrete buckets grouped by target, preserving one hot-reload slot per target.
    pub storage_buckets_by_target: BTreeMap<String, Vec<String>>,
    /// Whether Security Rules are enforced on the Firestore surface.
    pub rules_enforced: bool,
    /// Functions HTTP bind address.
    pub functions_addr: String,
    /// Eventarc HTTP bind address. The pinned official suite starts this dependency only
    /// when a Functions codebase is loaded; its default port is 9299.
    pub eventarc_addr: String,
    /// Whether an Eventarc emulator entry or port was configured independently of Functions.
    pub eventarc_enabled: bool,
    /// Whether the Eventarc port is fixed rather than dynamically relocatable.
    pub eventarc_addr_explicit: bool,
    /// Cloud Tasks HTTP bind address. The pinned official suite starts this dependency only
    /// when a Functions codebase is loaded; its default port is 9499.
    pub tasks_addr: String,
    /// Whether a Cloud Tasks emulator entry or port was configured independently of Functions.
    pub tasks_enabled: bool,
    /// Whether the Cloud Tasks port is fixed rather than dynamically relocatable.
    pub tasks_addr_explicit: bool,
    /// Pub/Sub gRPC bind address (`emulators.pubsub`, `daemon.pubsubPort`). The official
    /// emulator default port is 8085.
    pub pubsub_addr: String,
    /// Whether Pub/Sub was configured (`emulators.pubsub`, `daemon.pubsubPort`, `--pubsub-port`).
    /// Like the official suite, the Pub/Sub emulator starts only when it is configured or when
    /// `--only pubsub` asks for it, rather than binding port 8085 on every run.
    pub pubsub_enabled: bool,
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
    /// Logging emulator WebSocket bind address (`emulators.logging`, `daemon.loggingPort`,
    /// `--logging-port`). The official default port is 4500.
    pub logging_addr: String,
    /// Whether the Logging emulator is served. Unlike the official emulator, which starts it
    /// only when the UI starts or `START_LOGGING_EMULATOR=true`, fireemu serves it best effort
    /// by default; setting the port to 0 turns it off.
    pub logging_enabled: bool,
    /// Whether `--logging-port`, `emulators.logging` or `daemon.loggingPort` pinned the address.
    /// Like the Hub's and UI's, a busy default port only disables logging; a busy explicit one
    /// is an error.
    pub logging_addr_explicit: bool,
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
    /// Node inspector port requested by `--inspect-functions`; applied after executable selection.
    pub functions_inspect_port: Option<u16>,
    /// Whether `--inspect-functions` requested one dynamic inspector port per codebase.
    pub functions_inspect_dynamic: bool,
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
    /// Minimum interval kept between two push deliveries of the same Pub/Sub message while the
    /// subscription has no retry policy (`pubsub.pushMinimumRedeliveryIntervalMillis`). The
    /// default is `0`, which follows production: without a retry policy the service redelivers as
    /// soon as possible. A non-zero interval is an opt-in emulator protection against re-requesting
    /// a failing push endpoint with no interval at all. A retry policy always decides its own
    /// backoff.
    pub pubsub_push_minimum_redelivery_interval_millis: i64,
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
    /// Service accounts whose signed custom tokens are accepted, each with its public JWK set
    /// (`auth.customTokenSigners`). When set, only tokens they signed are accepted, as in
    /// production; when absent, the unsigned tokens of the Admin SDK's emulator mode are.
    pub auth_custom_token_signers: Option<serde_json::Map<String, Value>>,
    /// The default project's API keys (`auth.apiKeys`). When any is declared, client requests
    /// with another key are refused as production's API front end refuses them; when none is,
    /// any key is accepted, as by the official emulator.
    pub auth_api_keys: Vec<String>,
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
            implicit_database_creation: profile.implicit_database_creation(),
            ttl_sweep_interval: fireemu_core_firestore::ttl::DEFAULT_SWEEP_INTERVAL,
            require_demo_prefix: true,
            clock_start: LogicalInstant::from_unix_seconds(1_788_004_860),
            clock_start_pinned: false,
            seed: 42,
            auth_project: "demo-app".to_owned(),
            auth_project_numbers: BTreeMap::new(),
            auth_totp: None,
            auth_forward_inbound_credentials: false,
            auth_improved_email_privacy: true,
            auth_improved_email_privacy_explicit: false,
            auth_sign_in: AuthSignInSettings::default(),
            auth_log_action_codes: true,
            auth_password_policy: None,
            auth_password_policy_overrides: Vec::new(),
            auth_allow_duplicate_emails: false,
            auth_allow_duplicate_emails_explicit: false,
            auth_client_permissions: AuthClientPermissions::default(),
            auth_client_permissions_explicit: false,
            auth_config_overrides: Vec::new(),
            auth_blocking_functions: None,
            auth_signup_quota: None,
            auth_signup_quota_explicit: false,
            auth_quota_simulation: AuthQuotaSimulationConfig::default(),
            auth_quota_simulation_explicit: false,
            index_file: None,
            text_index_file: None,
            rules_file: None,
            firestore_databases: BTreeMap::new(),
            storage_rules_file: None,
            storage_rules_by_target: BTreeMap::new(),
            storage_rules_by_bucket: BTreeMap::new(),
            storage_buckets_by_target: BTreeMap::new(),
            rules_enforced: true,
            functions_addr: "127.0.0.1:5001".to_owned(),
            eventarc_addr: "127.0.0.1:9299".to_owned(),
            eventarc_enabled: false,
            eventarc_addr_explicit: false,
            tasks_addr: "127.0.0.1:9499".to_owned(),
            tasks_enabled: false,
            tasks_addr_explicit: false,
            pubsub_addr: "127.0.0.1:8085".to_owned(),
            pubsub_enabled: false,
            hub_addr: format!("127.0.0.1:{DEFAULT_HUB_PORT}"),
            hub_addr_explicit: false,
            ui_addr: format!("127.0.0.1:{DEFAULT_UI_PORT}"),
            ui_enabled: true,
            ui_addr_explicit: false,
            logging_addr: format!("127.0.0.1:{DEFAULT_LOGGING_PORT}"),
            logging_enabled: true,
            logging_addr_explicit: false,
            single_project_mode: false,
            functions_source: None,
            functions_codebases: Vec::new(),
            functions_loaded: Vec::new(),
            functions_runner: None,
            functions_inspect_port: None,
            functions_inspect_dynamic: false,
            functions_manifest: None,
            functions_max_running: 8,
            functions_unserved_triggers: "refuse".to_owned(),
            functions_project_alias: None,
            events_max_attempts: 4,
            pubsub_push_minimum_redelivery_interval_millis:
                fireemu_core_pubsub::subscription::DEFAULT_PUSH_MINIMUM_REDELIVERY_INTERVAL_MILLIS,
            scheduler_max_catch_up_runs: 1000,
            scheduler_default_time_zone: None,
            scheduler_overlap: "allow".to_owned(),
            scheduler_catch_up: "all".to_owned(),
            id_token_signing: fireemu_core_auth::jwt::SigningMode::UnsignedEmulator,
            auth_custom_token_signers: None,
            auth_api_keys: Vec::new(),
            app_check: AppCheckConfig::disabled(),
        }
    }
}

/// The keys of the `auth` section (spec/config/fireemu.schema.json).
pub(crate) const AUTH_KEYS: [&str; 18] = [
    "enabled",
    "apiKeys",
    "projectIssuer",
    "idTokenSigning",
    "customTokenSigners",
    "totp",
    "secretMaterialization",
    "forwardInboundCredentials",
    "improvedEmailPrivacy",
    "logActionCodes",
    "passwordPolicy",
    "passwordPolicyOverrides",
    "signIn",
    "client",
    "configOverrides",
    "blockingFunctions",
    "quota",
    "quotaSimulation",
];

/// Configuration errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

/// The service emulators fireemu serves, in `--only` spelling.
pub const SERVED_SERVICES: [&str; 8] = [
    "auth",
    "firestore",
    "storage",
    "functions",
    "eventarc",
    "tasks",
    "pubsub",
    "appcheck",
];

/// Official Local Emulator Suite service emulators fireemu does not serve, each with the
/// scope decision that explains it. Selecting one is an error rather than a silent no-op:
/// a test suite that asks for Realtime Database must not be told the suite started.
///
/// `deferred` products have an open compatibility issue and no implementation; `planned`
/// products are on the active list; `not planned` is a closed product decision.
pub const UNSERVED_OFFICIAL_SERVICES: [(&str, &str); 5] = [
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
    (
        "dataconnect",
        "deferred: the Data Connect emulator is not in the active supported surface",
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
    /// Whether `--only` named the Eventarc support emulator.
    pub eventarc: bool,
    /// Whether `--only` named the Cloud Tasks support emulator.
    pub tasks: bool,
    /// The Pub/Sub gRPC emulator is served and `PUBSUB_EMULATOR_HOST` exported.
    pub pubsub: bool,
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
            eventarc: false,
            tasks: false,
            pubsub: true,
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
            eventarc: false,
            tasks: false,
            pubsub: false,
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
            } else if let (Some(target), true) = (codebase, service == "storage") {
                if target.is_empty() {
                    return Err(ConfigError(
                        "--only storage:: needs a target name after the colon".to_owned(),
                    ));
                }
                // firebase-tools uses the qualifier for deploy selection, but the emulator
                // controller starts Storage with every configured target. Retaining it here
                // would incorrectly narrow the rules registry.
            } else if let Some(codebase) = codebase {
                return Err(ConfigError(format!(
                    "--only: {service:?} takes no `:{codebase}` qualifier; only `functions:<codebase>` and `storage:<target>` do"
                )));
            }
            match service {
                "firestore" => sel.firestore = true,
                "auth" => sel.auth = true,
                "storage" => sel.storage = true,
                "functions" => sel.functions = true,
                // The official controller accepts these names but creates both listeners
                // only when at least one Functions backend is loaded. They therefore do not
                // select Functions or carry independent Selection flags.
                "eventarc" => sel.eventarc = true,
                "tasks" => sel.tasks = true,
                "pubsub" => sel.pubsub = true,
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

    /// Whether a selected surface can consume a Firebase Auth identity.
    ///
    /// Firestore and Storage rules inspect Auth tokens, while callable Functions verify them
    /// before invocation. App Check and Pub/Sub alone do not need an Auth signing key.
    #[must_use]
    pub const fn uses_auth_identity(&self) -> bool {
        self.auth || self.firestore || self.storage || self.functions
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

/// Maximum number of Node runner processes fireemu starts for one invocation.
///
/// `firebase-tools@15.28.2` does not impose a Functions codebase-count limit. This is a
/// fireemu-local safety budget: selecting one codebase with `--only functions:<codebase>` keeps
/// large Firebase projects usable without allowing an untrusted configuration to exhaust local
/// process and memory limits.
pub const MAX_SELECTED_FUNCTIONS_CODEBASES: usize = 32;

/// Maximum deploy targets loaded into one Storage rules registry.
pub const MAX_STORAGE_RULE_TARGETS: usize = 64;
/// Maximum concrete buckets loaded into one Storage rules registry.
pub const MAX_STORAGE_RULE_BUCKETS: usize = 1024;

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

/// The official keys of one Cloud Storage configuration entry.
const STORAGE_ENTRY_KEYS: [&str; 2] = ["target", "rules"];

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

/// The only host values a listener may take, whichever file names them (`emulators.<name>.host`
/// of a `firebase.json`, `bind` of the canonical configuration): the daemon serves loopback
/// without a credential on the products and its privileged control routes trust a loopback
/// origin, so a routable address -- `0.0.0.0`, `::` or a LAN address, which `firebase-tools`
/// binds as given -- is refused rather than exposing the suite to the network. The
/// restriction is published as a fireemu divergence of the CLI lifecycle claim in
/// `spec/compatibility/contract.json`; `tools/config-schema-check` rejects the same spellings.
fn loopback_host(host: &str, key: &str) -> Result<String, ConfigError> {
    match host {
        "127.0.0.1" | "localhost" => Ok(host.to_owned()),
        "::1" | "[::1]" => Ok("[::1]".to_owned()),
        other => Err(ConfigError(format!(
            "{key} {other:?}: only loopback hosts are accepted (127.0.0.1, localhost, ::1); fireemu serves without a credential on loopback, so a routable host such as 0.0.0.0 or :: is refused rather than exposing the suite to the network"
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
            loopback_host(text, &format!("firebase.json: emulators.{name}.host"))?
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
    fn valid_catalog_id(value: &str, prefix: &str) -> bool {
        let Some(date) = value.strip_prefix(prefix) else {
            return false;
        };
        date.len() == 10
            && date.as_bytes()[4] == b'-'
            && date.as_bytes()[7] == b'-'
            && date
                .bytes()
                .enumerate()
                .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
    }

    fn parse_limit_catalog(
        limits: &serde_json::Map<String, Value>,
        key: &str,
        prefixes: &[&str],
        nullable: bool,
    ) -> Result<(), ConfigError> {
        let Some(value) = limits.get(key) else {
            return Ok(());
        };
        if nullable && value.is_null() {
            return Ok(());
        }
        let value = value
            .as_str()
            .ok_or_else(|| ConfigError(format!("limits.{key} must be a string")))?;
        if prefixes
            .iter()
            .any(|prefix| Self::valid_catalog_id(value, prefix))
        {
            Ok(())
        } else {
            Err(ConfigError(format!(
                "limits.{key} has an invalid catalog id"
            )))
        }
    }

    fn parse_limit_thresholds(value: &Value, path: &str) -> Result<bool, ConfigError> {
        let thresholds = value
            .as_array()
            .ok_or_else(|| ConfigError(format!("{path} must be an array")))?;
        for (index, threshold) in thresholds.iter().enumerate() {
            let threshold = threshold
                .as_object()
                .ok_or_else(|| ConfigError(format!("{path}[{index}] must be an object")))?;
            for key in threshold.keys() {
                if !["basisPoints", "severity"].contains(&key.as_str()) {
                    return Err(ConfigError(format!(
                        "unknown config key {path}[{index}].{key}"
                    )));
                }
            }
            let basis_points = threshold
                .get("basisPoints")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    ConfigError(format!("{path}[{index}].basisPoints must be an integer"))
                })?;
            if !(1..=10_000).contains(&basis_points) {
                return Err(ConfigError(format!(
                    "{path}[{index}].basisPoints must be an integer from 1 through 10000"
                )));
            }
            let severity = threshold
                .get("severity")
                .and_then(Value::as_str)
                .ok_or_else(|| ConfigError(format!("{path}[{index}].severity must be a string")))?;
            if !["notice", "warning", "critical"].contains(&severity) {
                return Err(ConfigError(format!(
                    "{path}[{index}].severity has an unsupported value {severity:?}"
                )));
            }
        }
        Ok(!thresholds.is_empty())
    }

    fn parse_limit_enforcement(limits: &Map<String, Value>) -> Result<(), ConfigError> {
        let Some(value) = limits.get("enforcement") else {
            return Ok(());
        };
        let value = value
            .as_str()
            .ok_or_else(|| ConfigError("limits.enforcement must be a string".to_owned()))?;
        match value {
            "observe" => Ok(()),
            "strict" => Err(ConfigError(
                "limits.enforcement is not implemented; use \"observe\"".to_owned(),
            )),
            _ => Err(ConfigError(format!(
                "limits.enforcement has an unsupported value {value:?}"
            ))),
        }
    }

    fn parse_warning_thresholds(limits: &Map<String, Value>) -> Result<(), ConfigError> {
        let Some(value) = limits.get("warningThresholds") else {
            return Ok(());
        };
        if Self::parse_limit_thresholds(value, "limits.warningThresholds")? {
            return Err(ConfigError(
                "limits.warningThresholds is not implemented; use an empty array".to_owned(),
            ));
        }
        Ok(())
    }

    fn parse_per_limit_warning_thresholds(limits: &Map<String, Value>) -> Result<(), ConfigError> {
        let Some(value) = limits.get("perLimitWarningThresholds") else {
            return Ok(());
        };
        let per_limit = value.as_object().ok_or_else(|| {
            ConfigError("limits.perLimitWarningThresholds must be an object".to_owned())
        })?;
        for (key, thresholds) in per_limit {
            if key.is_empty()
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(ConfigError(format!(
                    "limits.perLimitWarningThresholds has an invalid limit id {key:?}"
                )));
            }
            if Self::parse_limit_thresholds(
                thresholds,
                &format!("limits.perLimitWarningThresholds.{key}"),
            )? {
                return Err(ConfigError(
                    "limits.perLimitWarningThresholds is not implemented; use an empty object"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn parse_warnings_as_errors(limits: &Map<String, Value>) -> Result<(), ConfigError> {
        let Some(value) = limits.get("warningsAsErrors") else {
            return Ok(());
        };
        let values = value
            .as_array()
            .ok_or_else(|| ConfigError("limits.warningsAsErrors must be an array".to_owned()))?;
        for (index, item) in values.iter().enumerate() {
            let item = item.as_str().ok_or_else(|| {
                ConfigError(format!("limits.warningsAsErrors[{index}] must be a string"))
            })?;
            if !["notice", "warning", "critical"].contains(&item)
                && (item.is_empty()
                    || !item.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-'
                    }))
            {
                return Err(ConfigError(format!(
                    "limits.warningsAsErrors[{index}] has an unsupported value {item:?}"
                )));
            }
        }
        if values.is_empty() {
            return Ok(());
        }
        Err(ConfigError(
            "limits.warningsAsErrors is not implemented; use an empty array".to_owned(),
        ))
    }

    fn parse_quota_accounting(limits: &Map<String, Value>) -> Result<(), ConfigError> {
        let Some(value) = limits.get("quotaAccounting") else {
            return Ok(());
        };
        let value = value
            .as_str()
            .ok_or_else(|| ConfigError("limits.quotaAccounting must be a string".to_owned()))?;
        match value {
            "off" => Ok(()),
            "observe" | "enforce" => Err(ConfigError(
                "limits.quotaAccounting is not implemented; use \"off\"".to_owned(),
            )),
            _ => Err(ConfigError(format!(
                "limits.quotaAccounting has an unsupported value {value:?}"
            ))),
        }
    }

    fn parse_firestore_plan(limits: &Map<String, Value>) -> Result<(), ConfigError> {
        let Some(value) = limits.get("firestorePlan") else {
            return Ok(());
        };
        let plan = value
            .as_object()
            .ok_or_else(|| ConfigError("limits.firestorePlan must be an object".to_owned()))?;
        for key in plan.keys() {
            if !FIRESTORE_PLAN_KEYS.contains(&key.as_str()) {
                return Err(ConfigError(format!(
                    "unknown config key limits.firestorePlan.{key}"
                )));
            }
        }
        if let Some(value) = plan.get("billingEnabled") {
            let enabled = value.as_bool().ok_or_else(|| {
                ConfigError("limits.firestorePlan.billingEnabled must be a boolean".to_owned())
            })?;
            if enabled {
                return Err(ConfigError(
                    "limits.firestorePlan.billingEnabled is not implemented; use false".to_owned(),
                ));
            }
        }
        for key in FIRESTORE_PLAN_OVERRIDE_KEYS {
            let Some(value) = plan.get(key) else {
                continue;
            };
            if value.is_null() {
                continue;
            }
            if value.as_u64().is_none() {
                return Err(ConfigError(format!(
                    "limits.firestorePlan.{key} must be a non-negative integer or null"
                )));
            }
            return Err(ConfigError(format!(
                "limits.firestorePlan.{key} is not implemented; use null"
            )));
        }
        Ok(())
    }

    fn parse_limits(limits: &Value) -> Result<(), ConfigError> {
        let limits = limits
            .as_object()
            .ok_or_else(|| ConfigError("limits must be an object".to_owned()))?;
        for key in limits.keys() {
            if !LIMIT_KEYS.contains(&key.as_str()) {
                return Err(ConfigError(format!("unknown config key limits.{key}")));
            }
        }
        Self::parse_limit_catalog(
            limits,
            "catalog",
            &["firestore-standard-", "firestore-enterprise-native-"],
            false,
        )?;
        Self::parse_limit_catalog(limits, "queryCatalog", &["firestore-standard-query-"], true)?;
        Self::parse_limit_catalog(limits, "rulesCatalog", &["firebase-rules-"], false)?;
        Self::parse_limit_enforcement(limits)?;
        Self::parse_warning_thresholds(limits)?;
        Self::parse_per_limit_warning_thresholds(limits)?;
        Self::parse_warnings_as_errors(limits)?;
        Self::parse_quota_accounting(limits)?;
        Self::parse_firestore_plan(limits)
    }

    /// Applies the parts of a `firebase.json` the daemon can honour. Paths are relative to
    /// `base`.
    ///
    /// - `firestore` in object or array form: per-database `rules` and `indexes` (also the legacy
    ///   `index` spelling), with named databases isolated from `(default)`;
    /// - `storage` in object form: one rules file for every bucket; array form: every entry
    ///   names a deploy target which is resolved through `.firebaserc` before startup;
    /// - `functions` in object or array form: every codebase is parsed, validated and loaded;
    ///   `--only functions:<codebase>` narrows the run to one codebase;
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
                    "eventarc" => {
                        self.eventarc_addr = emulator_addr(entry, name, &self.eventarc_addr)?;
                        self.eventarc_enabled = true;
                        self.eventarc_addr_explicit = entry
                            .as_object()
                            .is_some_and(|entry| entry.contains_key("port"));
                    }
                    "tasks" => {
                        self.tasks_addr = emulator_addr(entry, name, &self.tasks_addr)?;
                        self.tasks_enabled = true;
                        self.tasks_addr_explicit = entry
                            .as_object()
                            .is_some_and(|entry| entry.contains_key("port"));
                    }
                    "pubsub" => {
                        self.pubsub_addr = emulator_addr(entry, name, &self.pubsub_addr)?;
                        self.pubsub_enabled = true;
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
                    "logging" => {
                        self.logging_addr = emulator_addr(entry, name, &self.logging_addr)?;
                        self.logging_enabled = !self.logging_addr.ends_with(":0");
                        self.logging_addr_explicit = true;
                    }
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
        _report: &mut FirebaseJsonReport,
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
                .unwrap_or_else(|| fireemu_core_types::ids::DatabaseId::DEFAULT.to_owned());
            if seen.contains(&database) {
                return Err(ConfigError(format!(
                    "firebase.json: firestore declares the database {database} twice"
                )));
            }
            seen.push(database.clone());
            let files = FirestoreDatabaseFiles {
                rules: entry
                    .get("rules")
                    .map(|value| file(value, &format!("{path}.rules")))
                    .transpose()?,
                indexes: entry
                    .get("indexes")
                    .or_else(|| entry.get("index"))
                    .map(|value| file(value, &format!("{path}.indexes")))
                    .transpose()?,
            };
            if database == fireemu_core_types::ids::DatabaseId::DEFAULT {
                self.rules_file.clone_from(&files.rules);
                self.index_file.clone_from(&files.indexes);
            }
            self.firestore_databases.insert(database, files);
        }
        Ok(())
    }

    /// `storage`, in object or array (multi-bucket) form.
    fn apply_storage(
        &mut self,
        section: Option<&Value>,
        file: &dyn Fn(&Value, &str) -> Result<String, ConfigError>,
        _report: &mut FirebaseJsonReport,
    ) -> Result<(), ConfigError> {
        let entries: Vec<(&serde_json::Map<String, Value>, String)> = match section {
            None => Vec::new(),
            Some(Value::Object(o)) => vec![(o, "storage".to_owned())],
            Some(Value::Array(a)) => {
                if a.is_empty() {
                    return Err(ConfigError(
                        "firebase.json: storage must contain at least one target".to_owned(),
                    ));
                }
                if a.len() > MAX_STORAGE_RULE_TARGETS {
                    return Err(ConfigError(format!(
                        "firebase.json has {} Storage rules targets, exceeding fireemu's local safety budget of {MAX_STORAGE_RULE_TARGETS}",
                        a.len()
                    )));
                }
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
        self.storage_rules_file = None;
        self.storage_rules_by_target.clear();
        self.storage_rules_by_bucket.clear();
        self.storage_buckets_by_target.clear();
        let array_form = section.is_some_and(Value::is_array);
        for (entry, path) in entries {
            for key in entry.keys() {
                if !STORAGE_ENTRY_KEYS.contains(&key.as_str()) {
                    return Err(ConfigError(format!(
                        "firebase.json: unknown key {path}.{key}"
                    )));
                }
            }
            let rules = entry
                .get("rules")
                .ok_or_else(|| ConfigError(format!("firebase.json: {path}.rules is required")))?;
            let rules = file(rules, &format!("{path}.rules"))?;
            if array_form {
                let target = entry
                    .get("target")
                    .and_then(Value::as_str)
                    .filter(|target| !target.is_empty())
                    .ok_or_else(|| {
                        ConfigError(format!(
                            "firebase.json: {path}.target is required and must be a non-empty string"
                        ))
                    })?;
                if self
                    .storage_rules_by_target
                    .insert(target.to_owned(), rules)
                    .is_some()
                {
                    return Err(ConfigError(format!(
                        "firebase.json: storage declares target {target:?} twice"
                    )));
                }
            } else {
                if entry.contains_key("target") {
                    return Err(ConfigError(
                        "firebase.json: storage.target is valid only when storage is an array"
                            .to_owned(),
                    ));
                }
                self.storage_rules_file = Some(rules);
            }
        }
        Ok(())
    }

    /// Expands target-based Storage rules through `.firebaserc.targets[project].storage`.
    ///
    /// This runs only after the effective project alias has been resolved. Missing or malformed
    /// mappings are refused before any listener binds; target mode never falls back to a global
    /// ruleset because doing so could authorize a bucket with another bucket's policy.
    pub fn resolve_storage_rules_targets(
        &mut self,
        rc: &Value,
        project: &str,
    ) -> Result<(), ConfigError> {
        if self.storage_rules_by_target.is_empty() {
            return Ok(());
        }
        let targets = rc
            .get("targets")
            .and_then(Value::as_object)
            .ok_or_else(|| ConfigError(".firebaserc: targets must be an object".to_owned()))?;
        let project_targets = targets
            .get(project)
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ConfigError(format!(
                    ".firebaserc: targets.{project}.storage is required by firebase.json"
                ))
            })?;
        let storage = project_targets
            .get("storage")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ConfigError(format!(
                    ".firebaserc: targets.{project}.storage must be an object"
                ))
            })?;
        let mut by_bucket = BTreeMap::new();
        let mut buckets_by_target = BTreeMap::new();
        for (target, path) in &self.storage_rules_by_target {
            let resources = storage
                .get(target)
                .and_then(Value::as_array)
                .filter(|resources| !resources.is_empty())
                .ok_or_else(|| {
                    ConfigError(format!(
                        ".firebaserc: targets.{project}.storage.{target} must be a non-empty array"
                    ))
                })?;
            let mut target_buckets = Vec::with_capacity(resources.len());
            for (index, resource) in resources.iter().enumerate() {
                let bucket = resource.as_str().filter(|bucket| !bucket.is_empty()).ok_or_else(
                    || {
                        ConfigError(format!(
                            ".firebaserc: targets.{project}.storage.{target}[{index}] must be a non-empty string"
                        ))
                    },
                )?;
                fireemu_core_storage::name::BucketName::try_new(bucket.to_owned()).map_err(
                    |reason| {
                        ConfigError(format!(
                            ".firebaserc: targets.{project}.storage.{target}[{index}] is not a valid bucket name: {reason}"
                        ))
                    },
                )?;
                if by_bucket.len() >= MAX_STORAGE_RULE_BUCKETS {
                    return Err(ConfigError(format!(
                        ".firebaserc has more than {MAX_STORAGE_RULE_BUCKETS} Storage buckets selected for project {project}"
                    )));
                }
                if by_bucket.insert(bucket.to_owned(), path.clone()).is_some() {
                    return Err(ConfigError(format!(
                        ".firebaserc: Storage bucket {bucket:?} belongs to more than one target"
                    )));
                }
                target_buckets.push(bucket.to_owned());
            }
            buckets_by_target.insert(target.clone(), target_buckets);
        }
        self.storage_rules_by_bucket = by_bucket;
        self.storage_buckets_by_target = buckets_by_target;
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
            check_codebase_name(&codebase, &path)?;
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
        if chosen.len() > MAX_SELECTED_FUNCTIONS_CODEBASES {
            return Err(ConfigError(format!(
                "firebase.json has {} selected Functions codebases, exceeding fireemu's local safety budget of {MAX_SELECTED_FUNCTIONS_CODEBASES}; use --only functions:<codebase> to start one runner",
                chosen.len()
            )));
        }
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

fn check_codebase_name(codebase: &str, path: &str) -> Result<(), ConfigError> {
    if !(1..=63).contains(&codebase.len())
        || !codebase
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
    {
        return Err(ConfigError(format!(
            "firebase.json: {path}.codebase must be 1 to 63 characters of lowercase letters, digits, underscores or dashes"
        )));
    }
    Ok(())
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
    if runtime
        .strip_prefix("nodejs")
        .is_some_and(|major| !major.is_empty() && major.bytes().all(|byte| byte.is_ascii_digit()))
    {
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
    "$schema",
    "schemaVersion",
    "firebaseJson",
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
    "pubsub",
    "scheduler",
    "functions",
    "trace",
    "daemon",
];

pub const CANONICAL_SCHEMA_URL: &str = "https://fireemu.dev/spec/config/fireemu.schema.json";

/// The Firebase project configuration composed by a canonical fireemu configuration.
/// Its path is resolved by the CLI because that layer knows which file contained this JSON.
pub fn firebase_json_reference(json: &Value) -> Result<Option<&str>, ConfigError> {
    match json.get("firebaseJson") {
        None => Ok(None),
        Some(Value::String(path)) if !path.is_empty() => Ok(Some(path)),
        Some(Value::String(_)) => Err(ConfigError("firebaseJson must not be empty".into())),
        Some(_) => Err(ConfigError("firebaseJson must be a string".into())),
    }
}

/// `auth.signIn`'s provider members; `allowDuplicateEmails` is read by the caller.
fn parse_sign_in_providers(
    sign_in: &serde_json::Map<String, Value>,
) -> Result<AuthSignInSettings, ConfigError> {
    let member = |name: &str,
                  keys: &[&str]|
     -> Result<Option<&serde_json::Map<String, Value>>, ConfigError> {
        let Some(value) = sign_in.get(name) else {
            return Ok(None);
        };
        let object = value
            .as_object()
            .ok_or_else(|| ConfigError(format!("auth.signIn.{name} must be an object")))?;
        if let Some(key) = object.keys().find(|key| !keys.contains(&key.as_str())) {
            return Err(ConfigError(format!(
                "unknown config key auth.signIn.{name}.{key}"
            )));
        }
        Ok(Some(object))
    };
    let flag = |object: Option<&serde_json::Map<String, Value>>, name: &str, key: &str| {
        object
            .and_then(|object| object.get(key))
            .map(|value| {
                value.as_bool().ok_or_else(|| {
                    ConfigError(format!("auth.signIn.{name}.{key} must be a boolean"))
                })
            })
            .transpose()
    };
    let email = member("email", &["enabled", "passwordRequired"])?;
    let anonymous = member("anonymous", &["enabled"])?;
    let phone = member("phoneNumber", &["enabled", "testPhoneNumbers"])?;
    let test_phone_numbers = phone
        .and_then(|phone| phone.get("testPhoneNumbers"))
        .map(|numbers| {
            let path = "auth.signIn.phoneNumber.testPhoneNumbers";
            let numbers = numbers
                .as_object()
                .ok_or_else(|| ConfigError(format!("{path} must be an object")))?;
            if numbers.len() > 10 {
                return Err(ConfigError(format!("{path} holds at most ten numbers")));
            }
            numbers
                .iter()
                .map(|(number, code)| {
                    let e164 = number.strip_prefix('+').is_some_and(|digits| {
                        (2..=15).contains(&digits.len())
                            && !digits.starts_with('0')
                            && digits.bytes().all(|b| b.is_ascii_digit())
                    });
                    if !e164 {
                        return Err(ConfigError(format!(
                            "{path}: {number} is not an E.164 number"
                        )));
                    }
                    // Any text, as production's Admin config takes a test number's code.
                    match code.as_str() {
                        Some(code) => Ok((number.clone(), code.to_owned())),
                        None => Err(ConfigError(format!(
                            "{path}: the code of {number} is not text"
                        ))),
                    }
                })
                .collect::<Result<BTreeMap<_, _>, _>>()
        })
        .transpose()?;
    Ok(AuthSignInSettings {
        email_enabled: flag(email, "email", "enabled")?,
        password_required: flag(email, "email", "passwordRequired")?,
        anonymous_enabled: flag(anonymous, "anonymous", "enabled")?,
        phone_enabled: flag(phone, "phoneNumber", "enabled")?,
        test_phone_numbers,
    })
}

impl RuntimeConfig {
    /// Selects the compatibility profile and rewrites the settings it derives. Every key the
    /// profile decides is written here and nowhere else, so an explicit key parsed afterwards
    /// simply overwrites it.
    pub fn set_profile(&mut self, profile: CompatibilityProfile) {
        self.profile = profile;
        self.index_policy = profile.index_policy();
        self.enforce_limits = profile.enforce_limits();
        self.token_acceptance = profile.token_acceptance();
        self.implicit_database_creation = profile.implicit_database_creation();
        // A new production project protects against email enumeration; the official Auth
        // emulator starts with it off (owner decision K3, AUTH-CONFIG-SDK).
        if !self.auth_improved_email_privacy_explicit {
            self.auth_improved_email_privacy = profile == CompatibilityProfile::Strict;
        }
    }

    fn parse_daemon(d: &serde_json::Map<String, Value>, cfg: &mut Self) -> Result<(), ConfigError> {
        for key in d.keys() {
            if ![
                "firestorePort",
                "storagePort",
                "httpPort",
                "functionsPort",
                "eventarcPort",
                "tasksPort",
                "pubsubPort",
                "hubPort",
                "uiPort",
                "loggingPort",
                "clockStart",
                "seed",
                "authProject",
                "authProjectNumbers",
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
        if let Some(port) = d.get("loggingPort").and_then(Value::as_u64) {
            cfg.logging_addr = format!("127.0.0.1:{port}");
            cfg.logging_enabled = port != 0;
            cfg.logging_addr_explicit = true;
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
        if let Some(port) = d.get("eventarcPort").and_then(Value::as_u64) {
            cfg.eventarc_addr = format!("127.0.0.1:{port}");
            cfg.eventarc_enabled = true;
            cfg.eventarc_addr_explicit = true;
        }
        if let Some(port) = d.get("tasksPort").and_then(Value::as_u64) {
            cfg.tasks_addr = format!("127.0.0.1:{port}");
            cfg.tasks_enabled = true;
            cfg.tasks_addr_explicit = true;
        }
        if let Some(port) = d.get("pubsubPort").and_then(Value::as_u64) {
            cfg.pubsub_addr = format!("127.0.0.1:{port}");
            cfg.pubsub_enabled = true;
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
        if let Some(value) = d.get("authProjectNumbers") {
            Self::parse_auth_project_numbers(value, &mut cfg.auth_project_numbers)?;
        }

        Ok(())
    }

    fn parse_auth_project_numbers(
        value: &Value,
        numbers: &mut BTreeMap<String, u64>,
    ) -> Result<(), ConfigError> {
        let mappings = value
            .as_object()
            .ok_or_else(|| ConfigError("daemon.authProjectNumbers must be an object".into()))?;
        for (project, value) in mappings {
            if project.is_empty()
                || !project
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(ConfigError(
                    "invalid Auth project ID in number mapping".into(),
                ));
            }
            let number = value
                .as_str()
                .filter(|s| !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse::<u64>().ok())
                .filter(|n| *n != 0)
                .ok_or_else(|| {
                    ConfigError(
                        "Auth project number must be a positive decimal string within u64".into(),
                    )
                })?;
            numbers.insert(project.clone(), number);
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

    fn parse_pubsub(p: &serde_json::Map<String, Value>, cfg: &mut Self) -> Result<(), ConfigError> {
        for key in p.keys() {
            if !["pushMinimumRedeliveryIntervalMillis"].contains(&key.as_str()) {
                return Err(ConfigError(format!("unknown config key pubsub.{key}")));
            }
        }
        if let Some(value) = p.get("pushMinimumRedeliveryIntervalMillis") {
            let millis = value
                .as_i64()
                .filter(|millis| *millis >= 0)
                .ok_or_else(|| {
                    ConfigError(
                        "pubsub.pushMinimumRedeliveryIntervalMillis must be a non-negative integer"
                            .to_owned(),
                    )
                })?;
            if millis > MAX_PUSH_MINIMUM_REDELIVERY_INTERVAL_MILLIS {
                return Err(ConfigError(format!(
                    "pubsub.pushMinimumRedeliveryIntervalMillis must not exceed {MAX_PUSH_MINIMUM_REDELIVERY_INTERVAL_MILLIS}"
                )));
            }
            cfg.pubsub_push_minimum_redelivery_interval_millis = millis;
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
        if let Some(schema) = obj.get("$schema") {
            if schema.as_str() != Some(CANONICAL_SCHEMA_URL) {
                return Err(ConfigError(format!(
                    "$schema must be {CANONICAL_SCHEMA_URL:?}"
                )));
            }
        }
        let _ = firebase_json_reference(json)?;
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
            cfg.set_profile(CompatibilityProfile::parse_config(p).ok_or_else(|| {
                if p == "firebase" {
                    ConfigError(
                        "profile \"firebase\" was renamed to \"emulator\" in fireemu 0.7.0; \
                         the profiles are \"strict\" (production behaviour, the default) and \
                         \"emulator\" (the pinned official emulators)"
                            .to_owned(),
                    )
                } else {
                    ConfigError(format!("unknown profile {p:?}"))
                }
            })?);
        }
        if let Some(limits) = obj.get("limits") {
            Self::parse_limits(limits)?;
        }
        if let Some(bind) = obj.get("bind").and_then(Value::as_str) {
            loopback_host(bind, "bind")?;
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
            if fs.get("indexValidationPolicy").is_some() {
                return Err(ConfigError(
                    "firestore.indexValidationPolicy was removed in fireemu 0.7.0: the index \
                     policy follows the profile (strict checks composite indexes with \
                     production's rules, emulator assumes them)"
                        .to_owned(),
                ));
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
            if let Some(value) = fs.get("ttlSweepIntervalSeconds") {
                let seconds = value.as_u64().ok_or_else(|| {
                    ConfigError(
                        "firestore.ttlSweepIntervalSeconds must be a whole number of seconds"
                            .to_owned(),
                    )
                })?;
                let maximum = u64::try_from(
                    fireemu_core_firestore::ttl::MAX_SWEEP_INTERVAL
                        .as_nanos()
                        .div_euclid(1_000_000_000),
                )
                .unwrap_or(u64::MAX);
                if seconds == 0 || seconds > maximum {
                    return Err(ConfigError(format!(
                        "firestore.ttlSweepIntervalSeconds must be between 1 and {maximum}, \
                         the documented outer bound on how long an expired document survives"
                    )));
                }
                cfg.ttl_sweep_interval =
                    LogicalDuration::from_seconds(i64::try_from(seconds).unwrap_or(i64::MAX));
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
        if let Some(pubsub) = obj.get("pubsub").and_then(Value::as_object) {
            Self::parse_pubsub(pubsub, &mut cfg)?;
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
            if let Some(keys) = auth.get("apiKeys") {
                let keys = keys
                    .as_array()
                    .filter(|keys| !keys.is_empty())
                    .ok_or_else(|| {
                        ConfigError("auth.apiKeys must be a non-empty array of keys".to_owned())
                    })?;
                cfg.auth_api_keys = keys
                    .iter()
                    .map(|key| {
                        key.as_str()
                            .filter(|key| {
                                !key.is_empty()
                                    && key.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                            })
                            .map(str::to_owned)
                            .ok_or_else(|| {
                                ConfigError(
                                    "auth.apiKeys entries must be non-empty strings of [A-Za-z0-9._-]"
                                        .to_owned(),
                                )
                            })
                    })
                    .collect::<Result<_, _>>()?;
            }
            if let Some(signers) = auth.get("customTokenSigners") {
                let signers = signers.as_object().ok_or_else(|| {
                    ConfigError("auth.customTokenSigners must be an object".to_owned())
                })?;
                fireemu_adapter_http::identity_toolkit::CustomTokenTrust::from_jwks(signers)
                    .map_err(|e| ConfigError(format!("auth.customTokenSigners: {e}")))?;
                cfg.auth_custom_token_signers = Some(signers.clone());
            }
            if let Some(forward) = auth.get("forwardInboundCredentials") {
                cfg.auth_forward_inbound_credentials = forward.as_bool().ok_or_else(|| {
                    ConfigError("auth.forwardInboundCredentials must be a boolean".to_owned())
                })?;
            }
            if let Some(privacy) = auth.get("improvedEmailPrivacy") {
                cfg.auth_improved_email_privacy = privacy.as_bool().ok_or_else(|| {
                    ConfigError("auth.improvedEmailPrivacy must be a boolean".to_owned())
                })?;
                cfg.auth_improved_email_privacy_explicit = true;
            }
            if let Some(log) = auth.get("logActionCodes") {
                cfg.auth_log_action_codes = log.as_bool().ok_or_else(|| {
                    ConfigError("auth.logActionCodes must be a boolean".to_owned())
                })?;
            }
            let root_client_configured = if let Some(client) = auth.get("client") {
                let client = client
                    .as_object()
                    .ok_or_else(|| ConfigError("auth.client must be an object".to_owned()))?;
                for key in client.keys() {
                    if key != "permissions" {
                        return Err(ConfigError(format!("unknown config key auth.client.{key}")));
                    }
                }
                match client.get("permissions") {
                    None => false,
                    Some(value) => {
                        cfg.auth_client_permissions =
                            parse_auth_client_permissions(value, "auth.client.permissions")?;
                        cfg.auth_client_permissions_explicit = true;
                        true
                    }
                }
            } else {
                false
            };
            if let Some(sign_in) = auth.get("signIn") {
                let sign_in = sign_in
                    .as_object()
                    .ok_or_else(|| ConfigError("auth.signIn must be an object".to_owned()))?;
                for key in sign_in.keys() {
                    if !["allowDuplicateEmails", "email", "anonymous", "phoneNumber"]
                        .contains(&key.as_str())
                    {
                        return Err(ConfigError(format!("unknown config key auth.signIn.{key}")));
                    }
                }
                cfg.auth_sign_in = parse_sign_in_providers(sign_in)?;
                cfg.auth_allow_duplicate_emails =
                    parse_strict_bool(sign_in, "allowDuplicateEmails", "auth.signIn", false)?;
                cfg.auth_allow_duplicate_emails_explicit =
                    sign_in.contains_key("allowDuplicateEmails");
            }
            if let Some(overrides) = auth.get("configOverrides") {
                cfg.auth_config_overrides = parse_auth_config_overrides(
                    overrides,
                    "auth.configOverrides",
                    &cfg.auth_project,
                    root_client_configured,
                    auth.contains_key("improvedEmailPrivacy"),
                )?;
            }
            if let Some(blocking) = auth.get("blockingFunctions") {
                cfg.auth_blocking_functions = Some(parse_blocking_functions(
                    blocking,
                    "auth.blockingFunctions",
                    cfg.auth_forward_inbound_credentials,
                )?);
            }
            if let Some(quota) = auth.get("quota") {
                cfg.auth_signup_quota_explicit = true;
                cfg.auth_signup_quota = parse_auth_quota(quota, "auth.quota")?;
            }
            if let Some(simulation) = auth.get("quotaSimulation") {
                cfg.auth_quota_simulation_explicit = true;
                cfg.auth_quota_simulation =
                    parse_auth_quota_simulation(simulation, "auth.quotaSimulation")?;
            }
            if let Some(policy) = auth.get("passwordPolicy") {
                if policy.is_null() {
                    return Err(ConfigError(
                        "auth.passwordPolicy must be an object when specified".to_owned(),
                    ));
                }
                cfg.auth_password_policy =
                    Some(parse_password_policy(policy, "auth.passwordPolicy")?);
            }
            if let Some(overrides) = auth.get("passwordPolicyOverrides") {
                let overrides = overrides.as_array().ok_or_else(|| {
                    ConfigError("auth.passwordPolicyOverrides must be an array".to_owned())
                })?;
                let mut seen = BTreeSet::new();
                for (index, item) in overrides.iter().enumerate() {
                    let path = format!("auth.passwordPolicyOverrides[{index}]");
                    let item = item
                        .as_object()
                        .ok_or_else(|| ConfigError(format!("{path} must be an object")))?;
                    for key in item.keys() {
                        if !["projectId", "tenantId", "passwordPolicy"].contains(&key.as_str()) {
                            return Err(ConfigError(format!("unknown config key {path}.{key}")));
                        }
                    }
                    let project_id = item
                        .get("projectId")
                        .and_then(Value::as_str)
                        .ok_or_else(|| ConfigError(format!("{path}.projectId must be a string")))
                        .and_then(|id| {
                            valid_policy_namespace_id(id, &format!("{path}.projectId"))
                        })?;
                    let tenant_id = match item.get("tenantId") {
                        None => None,
                        Some(value) => Some(valid_policy_namespace_id(
                            value.as_str().ok_or_else(|| {
                                ConfigError(format!("{path}.tenantId must be a non-empty string"))
                            })?,
                            &format!("{path}.tenantId"),
                        )?),
                    };
                    let key = (project_id.clone(), tenant_id.clone());
                    if !seen.insert(key) {
                        return Err(ConfigError(format!(
                            "duplicate password policy namespace at {path}"
                        )));
                    }
                    if tenant_id.is_none()
                        && cfg.auth_password_policy.is_some()
                        && project_id == cfg.auth_project
                    {
                        return Err(ConfigError(
                            "auth.passwordPolicy and a default-project passwordPolicyOverrides entry are ambiguous"
                                .to_owned(),
                        ));
                    }
                    let policy = item
                        .get("passwordPolicy")
                        .ok_or_else(|| ConfigError(format!("{path}.passwordPolicy is required")))?;
                    cfg.auth_password_policy_overrides
                        .push(PasswordPolicyOverride {
                            project_id,
                            tenant_id,
                            password_policy: parse_password_policy(
                                policy,
                                &format!("{path}.passwordPolicy"),
                            )?,
                        });
                }
            }
            if let Some(totp) = auth.get("totp") {
                const TOTP_KEYS: [&str; 4] = [
                    "periodSeconds",
                    "digits",
                    "windowSteps",
                    "enrollmentSessionTtlSeconds",
                ];
                let totp = totp
                    .as_object()
                    .ok_or_else(|| ConfigError("auth.totp must be an object".to_owned()))?;
                for key in totp.keys() {
                    if !TOTP_KEYS.contains(&key.as_str()) {
                        return Err(ConfigError(format!("unknown config key auth.totp.{key}")));
                    }
                }
                let positive = |key: &str, default: u64| -> Result<u64, ConfigError> {
                    match totp.get(key) {
                        None => Ok(default),
                        Some(value) => value.as_u64().filter(|value| *value > 0).ok_or_else(|| {
                            ConfigError(format!("auth.totp.{key} must be a positive integer"))
                        }),
                    }
                };
                let bounded = |key: &str,
                               default: u64,
                               minimum: u64,
                               maximum: u64|
                 -> Result<u64, ConfigError> {
                    match totp.get(key) {
                        None => Ok(default),
                        Some(value) => value
                            .as_u64()
                            .filter(|value| (minimum..=maximum).contains(value))
                            .ok_or_else(|| {
                                ConfigError(format!(
                                    "auth.totp.{key} must be an integer from {minimum} through {maximum}"
                                ))
                            }),
                    }
                };
                let defaults = TotpPolicy::default();
                let period_seconds = u32::try_from(positive(
                    "periodSeconds",
                    u64::from(defaults.period_seconds),
                )?)
                .map_err(|_| ConfigError("auth.totp.periodSeconds is too large".to_owned()))?;
                let digits = u8::try_from(bounded("digits", u64::from(defaults.digits), 6, 8)?)
                    .expect("the validated digit range fits u8");
                let window_steps = u8::try_from(bounded(
                    "windowSteps",
                    u64::from(defaults.window_steps),
                    0,
                    10,
                )?)
                .expect("the validated window range fits u8");
                let ttl_seconds = i64::try_from(positive(
                    "enrollmentSessionTtlSeconds",
                    u64::try_from(defaults.enrollment_session_ttl.as_seconds())
                        .expect("the default TOTP TTL is positive"),
                )?)
                .map_err(|_| {
                    ConfigError("auth.totp.enrollmentSessionTtlSeconds is too large".to_owned())
                })?;
                cfg.auth_totp = Some(TotpPolicy {
                    period_seconds,
                    digits,
                    window_steps,
                    enrollment_session_ttl: LogicalDuration::from_seconds(ttl_seconds),
                    ..defaults
                });
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
    fn the_profile_sets_the_defaults_it_owns_and_strict_is_the_default_profile() {
        // fireemu exists to match production, so a configuration that names no profile at
        // all runs under the strict validation, the same profile `fireemu init` recommends.
        let default = with_profile(json!({})).unwrap();
        assert_eq!(default.profile, CompatibilityProfile::Strict);
        assert_eq!(RuntimeConfig::default().profile, default.profile);

        // emulator: the pinned official Firestore emulator checks no composite index, does
        // not refuse a query over a Standard limit, admits the mock tokens
        // @firebase/rules-unit-testing mints, and serves any syntactically valid database id
        // without a create.
        let emulator = with_profile(json!({"profile": "emulator"})).unwrap();
        assert_eq!(emulator.profile, CompatibilityProfile::Emulator);
        assert_eq!(emulator.index_policy, IndexValidationPolicy::Emulator);
        assert!(!emulator.enforce_limits);
        assert_eq!(emulator.token_acceptance, TokenAcceptance::EmulatorMock);
        assert!(emulator.implicit_database_creation);

        // strict: every one of those becomes production's refusal.
        let strict = with_profile(json!({"profile": "strict"})).unwrap();
        assert_eq!(strict.index_policy, IndexValidationPolicy::Production);
        assert!(strict.enforce_limits);
        assert_eq!(strict.token_acceptance, TokenAcceptance::Verified);
        assert!(!strict.implicit_database_creation);
    }

    #[test]
    fn sign_in_providers_are_configurable_and_start_enabled() {
        // Every provider starts enabled in both profiles (owner decision K14); a production
        // project's providers can be carried over.
        let defaults = with_profile(json!({})).unwrap();
        assert_eq!(defaults.auth_sign_in, AuthSignInSettings::default());
        let cfg = with_profile(json!({"auth": {"signIn": {
            "allowDuplicateEmails": true,
            "email": {"enabled": true, "passwordRequired": false},
            "anonymous": {"enabled": false},
            "phoneNumber": {"enabled": true, "testPhoneNumbers": {"+16505550101": "123456"}},
        }}}))
        .unwrap();
        assert!(cfg.auth_allow_duplicate_emails);
        assert_eq!(
            cfg.auth_sign_in,
            AuthSignInSettings {
                email_enabled: Some(true),
                password_required: Some(false),
                anonymous_enabled: Some(false),
                phone_enabled: Some(true),
                test_phone_numbers: Some([("+16505550101".to_owned(), "123456".to_owned())].into()),
            }
        );
        for (invalid, message) in [
            (
                json!({"email": {"enabled": "yes"}}),
                "auth.signIn.email.enabled must be a boolean",
            ),
            (
                json!({"email": {"other": true}}),
                "unknown config key auth.signIn.email.other",
            ),
            (
                json!({"anonymous": true}),
                "auth.signIn.anonymous must be an object",
            ),
            (
                json!({"phoneNumber": {"testPhoneNumbers": {"16505550101": "123456"}}}),
                "auth.signIn.phoneNumber.testPhoneNumbers: 16505550101 is not an E.164 number",
            ),
            (
                json!({"phoneNumber": {"testPhoneNumbers": {"+16505550101": 123_456}}}),
                "auth.signIn.phoneNumber.testPhoneNumbers: the code of +16505550101 is not text",
            ),
        ] {
            assert_eq!(
                with_profile(json!({"auth": {"signIn": invalid}})).map(|_| ()),
                Err(ConfigError(message.to_owned())),
                "{message}"
            );
        }
        // A code is taken as production's Admin config takes it: any text (AUTH-CONFIG-SDK
        // sandbox recording 2026-09-25 took "12345" and "abc").
        let cfg = with_profile(
            json!({"auth": {"signIn": {"phoneNumber": {"testPhoneNumbers": {
                "+16505550101": "12345",
                "+16505550102": "abc",
            }}}}}),
        )
        .unwrap();
        assert_eq!(
            cfg.auth_sign_in.test_phone_numbers,
            Some(
                [
                    ("+16505550101".to_owned(), "12345".to_owned()),
                    ("+16505550102".to_owned(), "abc".to_owned()),
                ]
                .into()
            )
        );
    }

    #[test]
    fn email_enumeration_protection_defaults_by_profile_and_yields_to_the_key() {
        // A new production project turns improved email privacy on; the official emulator
        // starts with it off (owner decision K3, AUTH-CONFIG-SDK).
        assert!(with_profile(json!({})).unwrap().auth_improved_email_privacy);
        assert!(
            !with_profile(json!({"profile": "emulator"}))
                .unwrap()
                .auth_improved_email_privacy
        );
        for (profile, value) in [("emulator", true), ("strict", false)] {
            let cfg = with_profile(json!({
                "profile": profile,
                "auth": {"improvedEmailPrivacy": value},
            }))
            .unwrap();
            assert_eq!(cfg.auth_improved_email_privacy, value, "{profile}");
        }
    }

    #[test]
    fn the_renamed_profile_and_the_removed_index_policy_key_are_refused_with_guidance() {
        // A 0.6 configuration must not start under a profile it did not ask for: the old
        // name and the removed key are refused with the new spelling in the message.
        let err = with_profile(json!({"profile": "firebase"})).unwrap_err();
        assert!(err.to_string().contains("renamed to \"emulator\""), "{err}");
        let err = with_profile(json!({
            "profile": "strict",
            "firestore": {
                "edition": "standard",
                "apiMode": "native",
                "indexValidationPolicy": "conservative",
            },
        }))
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("indexValidationPolicy was removed"),
            "{err}"
        );
        let err = with_profile(json!({"profile": "lenient"})).unwrap_err();
        assert!(err.to_string().contains("unknown profile"), "{err}");
    }

    #[test]
    fn the_contract_sets_exactly_what_the_profile_derives() {
        // spec/compatibility/contract.json lists under each profile's `sets` the keys the
        // daemon derives from it and nothing else (every other key is `declared`, with a
        // status). This test is the drift gate between that list and `set_profile`: a key
        // derived here and not written there, or written there and not derived here, fails.
        let contract: Value = serde_json::from_str(
            &std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../spec/compatibility/contract.json"),
            )
            .expect("the compatibility contract is in the repository"),
        )
        .expect("the contract is JSON");
        let profiles = contract["profiles"]
            .as_object()
            .expect("the contract declares profiles");
        assert_eq!(profiles.len(), 2, "two profiles are declared");
        for (name, profile) in profiles {
            let parsed = CompatibilityProfile::parse_config(name)
                .unwrap_or_else(|| panic!("profile {name} is not one the loader accepts"));
            let sets = profile["sets"].as_object().expect("a profile has sets");
            let mut keys: Vec<&str> = sets.keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                ["firestore.enforceLimits"],
                "profile {name} sets a key the loader does not derive, or misses one it does"
            );
            assert_eq!(
                sets["firestore.enforceLimits"],
                json!(parsed.enforce_limits()),
                "profile {name}: firestore.enforceLimits"
            );
            // A declared key is one the loader does not derive: none of them may be one of the
            // derived fields under another spelling.
            for key in profile["declared"]
                .as_object()
                .expect("a profile declares its hand-written keys")
                .keys()
            {
                assert!(
                    !sets.contains_key(key),
                    "profile {name} both sets and declares {key}"
                );
            }
        }
    }

    #[test]
    fn an_explicit_key_wins_over_the_profile_whichever_order_it_is_written_in() {
        // The profile only moves defaults, so a key that names a value keeps it. Both keys
        // sit in sections parsed after the profile and one (firestore) is parsed before the
        // profile appears in the file, which is why the loader reads the profile first.
        let cfg = with_profile(json!({
            "profile": "emulator",
            "firestore": {
                "edition": "standard",
                "apiMode": "native",
                "enforceLimits": true,
            },
        }))
        .unwrap();
        assert_eq!(cfg.profile, CompatibilityProfile::Emulator);
        assert_eq!(cfg.index_policy, IndexValidationPolicy::Emulator);
        assert!(cfg.enforce_limits);

        let cfg = with_profile(json!({
            "profile": "strict",
            "firestore": {
                "edition": "standard",
                "apiMode": "native",
                "enforceLimits": false,
            },
        }))
        .unwrap();
        assert_eq!(cfg.profile, CompatibilityProfile::Strict);
        assert_eq!(cfg.index_policy, IndexValidationPolicy::Production);
        assert!(!cfg.enforce_limits);
        // The token semantics and the index policy have no key of their own: the profile is
        // the only way to ask for them, so an explicit limit switch never quietly loosens them.
        assert_eq!(cfg.token_acceptance, TokenAcceptance::Verified);
    }

    /// The minimum push redelivery interval is configurable and bounded, and it defaults to zero
    /// so an unconfigured emulator redelivers as soon as possible, as production does.
    #[test]
    fn pubsub_push_minimum_redelivery_interval_is_parsed_bounded_and_defaults_to_immediate() {
        let default = with_profile(json!({})).expect("a config without a pubsub section");
        assert_eq!(
            default.pubsub_push_minimum_redelivery_interval_millis, 0,
            "the default must follow production, which redelivers as soon as possible"
        );
        assert_eq!(
            fireemu_core_pubsub::subscription::DEFAULT_PUSH_MINIMUM_REDELIVERY_INTERVAL_MILLIS,
            0
        );

        let configured = with_profile(json!({
            "pubsub": {"pushMinimumRedeliveryIntervalMillis": 0}
        }))
        .expect("zero restores unthrottled redelivery");
        assert_eq!(configured.pubsub_push_minimum_redelivery_interval_millis, 0);

        let configured = with_profile(json!({
            "pubsub": {"pushMinimumRedeliveryIntervalMillis": 2_500}
        }))
        .expect("an explicit interval");
        assert_eq!(
            configured.pubsub_push_minimum_redelivery_interval_millis,
            2_500
        );

        for (pubsub, expected) in [
            (
                json!({"pushMinimumRedeliveryIntervalMillis": -1}),
                "pubsub.pushMinimumRedeliveryIntervalMillis must be a non-negative integer",
            ),
            (
                json!({"pushMinimumRedeliveryIntervalMillis": "100"}),
                "pubsub.pushMinimumRedeliveryIntervalMillis must be a non-negative integer",
            ),
            (
                json!({"pushMinimumRedeliveryIntervalMillis":
                    MAX_PUSH_MINIMUM_REDELIVERY_INTERVAL_MILLIS + 1}),
                "pubsub.pushMinimumRedeliveryIntervalMillis must not exceed",
            ),
            (
                json!({"pushMinRedeliveryIntervalMillis": 100}),
                "unknown config key pubsub.pushMinRedeliveryIntervalMillis",
            ),
        ] {
            let error = with_profile(json!({"pubsub": pubsub})).expect_err("malformed pubsub");
            assert!(
                error.0.contains(expected),
                "expected {expected}, got {}",
                error.0
            );
        }
    }

    #[test]
    fn limits_metadata_is_accepted_without_overriding_firestore_enforcement() {
        let cfg = with_profile(json!({
            "profile": "strict",
            "limits": {
                "catalog": "firestore-enterprise-native-2026-08-27",
                "queryCatalog": null,
                "rulesCatalog": "firebase-rules-2026-08-25",
                "enforcement": "observe",
                "warningThresholds": [],
                "perLimitWarningThresholds": {},
                "warningsAsErrors": [],
                "quotaAccounting": "off",
                "firestorePlan": {
                    "billingEnabled": false,
                    "compositeIndexLimitOverride": null,
                    "singleFieldConfigLimitOverride": null,
                    "enterpriseIndexLimitOverride": null
                }
            },
            "firestore": {
                "edition": "standard",
                "apiMode": "native",
                "enforceLimits": false
            }
        }))
        .expect("neutral limits metadata is valid");
        assert!(!cfg.enforce_limits);
    }

    #[test]
    fn unsupported_limits_values_are_rejected_with_their_paths() {
        let cases = [
            (json!({"enforcement": "strict"}), "limits.enforcement"),
            (
                json!({"warningThresholds": [{"basisPoints": 9000, "severity": "warning"}]}),
                "limits.warningThresholds",
            ),
            (
                json!({
                    "perLimitWarningThresholds": {
                        "RULES-SOURCE-SIZE": [{"basisPoints": 9000, "severity": "warning"}]
                    }
                }),
                "limits.perLimitWarningThresholds",
            ),
            (
                json!({"warningsAsErrors": ["warning"]}),
                "limits.warningsAsErrors",
            ),
            (
                json!({"quotaAccounting": "observe"}),
                "limits.quotaAccounting",
            ),
            (
                json!({"firestorePlan": {"billingEnabled": true}}),
                "limits.firestorePlan.billingEnabled",
            ),
            (
                json!({"firestorePlan": {"compositeIndexLimitOverride": 100}}),
                "limits.firestorePlan.compositeIndexLimitOverride",
            ),
        ];
        for (value, path) in cases {
            let error = with_profile(json!({"limits": value})).expect_err("unsupported value");
            assert!(error.0.contains(path), "{path}: {}", error.0);
            assert!(error.0.contains("not implemented"), "{}", error.0);
        }
    }

    #[test]
    fn malformed_limits_are_rejected_before_runtime_configuration_is_built() {
        for (limits, expected) in [
            (json!(true), "limits must be an object"),
            (
                json!({"enforcement": true}),
                "limits.enforcement must be a string",
            ),
            (
                json!({"warningThresholds": {}}),
                "limits.warningThresholds must be an array",
            ),
            (
                json!({"perLimitWarningThresholds": []}),
                "limits.perLimitWarningThresholds must be an object",
            ),
            (
                json!({"warningsAsErrors": {}}),
                "limits.warningsAsErrors must be an array",
            ),
            (
                json!({"quotaAccounting": true}),
                "limits.quotaAccounting must be a string",
            ),
            (
                json!({"firestorePlan": []}),
                "limits.firestorePlan must be an object",
            ),
            (
                json!({"firestorePlan": {"billingEnabled": "yes"}}),
                "limits.firestorePlan.billingEnabled must be a boolean",
            ),
            (
                json!({"unknown": null}),
                "unknown config key limits.unknown",
            ),
        ] {
            let error = with_profile(json!({"limits": limits})).expect_err("malformed limits");
            assert!(
                error.0.contains(expected),
                "expected {expected}, got {}",
                error.0
            );
        }
    }

    #[test]
    fn bind_follows_the_same_loopback_policy_as_a_firebase_json_host() {
        for host in ["127.0.0.1", "localhost", "::1", "[::1]"] {
            RuntimeConfig::from_json(&json!({"schemaVersion": 1, "bind": host}))
                .unwrap_or_else(|e| panic!("bind {host:?} is loopback and must load: {e}"));
        }
        for host in ["0.0.0.0", "::", "192.168.1.10", "example.com"] {
            let err = RuntimeConfig::from_json(&json!({"schemaVersion": 1, "bind": host}))
                .expect_err("a routable bind is refused");
            let text = err.to_string();
            assert!(text.starts_with("bind "), "{text}");
            assert!(text.contains("only loopback hosts are accepted"), "{text}");
        }
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
    fn canonical_support_service_ports_are_loaded_as_explicit_addresses() {
        let cfg = RuntimeConfig::from_json(&json!({
            "schemaVersion": 1,
            "daemon": {"eventarcPort": 9300, "tasksPort": 9500}
        }))
        .unwrap();
        assert_eq!(cfg.eventarc_addr, "127.0.0.1:9300");
        assert!(cfg.eventarc_enabled);
        assert!(cfg.eventarc_addr_explicit);
        assert_eq!(cfg.tasks_addr, "127.0.0.1:9500");
        assert!(cfg.tasks_enabled);
        assert!(cfg.tasks_addr_explicit);
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
    fn every_surface_that_consumes_auth_identity_requires_the_configured_signer() {
        for service in ["auth", "firestore", "storage", "functions"] {
            assert!(
                Selection::parse(service).unwrap().uses_auth_identity(),
                "{service} consumes Firebase Auth identities"
            );
        }
        for service in ["appcheck", "pubsub"] {
            assert!(
                !Selection::parse(service).unwrap().uses_auth_identity(),
                "{service} alone does not consume Firebase Auth identities"
            );
        }
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
                "pubsub": {"port": 8090},
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
            cfg.firestore_databases[fireemu_core_types::ids::DatabaseId::DEFAULT]
                .rules
                .as_deref(),
            Some("/proj/firestore.rules")
        );
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
        // Pub/Sub is now a served service: its port is applied and no notice is raised.
        assert_eq!(cfg.pubsub_addr, "127.0.0.1:8090");
        assert!(report.notices.is_empty(), "{:?}", report.notices);
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

        let mut cfg = RuntimeConfig::default();
        let report = cfg
            .apply_firebase_json(
                &json!({"firestore": [
                    {"database": fireemu_core_types::ids::DatabaseId::DEFAULT, "rules": "default.rules"},
                    {"database": "staging", "rules": "staging.rules", "indexes": "staging.indexes.json"}
                ]}),
                base,
                &Selection::default(),
            )
            .unwrap();
        assert!(report.notices.is_empty(), "{:?}", report.notices);
        assert_eq!(
            cfg.firestore_databases["staging"].rules.as_deref(),
            Some("/proj/staging.rules")
        );
        assert_eq!(
            cfg.firestore_databases["staging"].indexes.as_deref(),
            Some("/proj/staging.indexes.json")
        );
        assert!(Selection::parse("auth,database").is_err());
        assert_eq!(
            cfg.apply_firebase_json(&json!({"firestore": {"rules": 1}}), base, &only),
            Err(ConfigError(
                "firebase.json: firestore.rules must be a string".to_owned()
            ))
        );
    }

    #[test]
    fn storage_targets_resolve_to_bucket_specific_rule_files() {
        let mut cfg = RuntimeConfig::default();
        cfg.apply_firebase_json(
            &json!({
                "storage": [
                    {"target": "public", "rules": "public.rules"},
                    {"target": "private", "rules": "private.rules"}
                ]
            }),
            std::path::Path::new("/proj"),
            &Selection::default(),
        )
        .unwrap();

        cfg.resolve_storage_rules_targets(
            &json!({
                "targets": {
                    "demo-app": {
                        "storage": {
                            "public": ["demo-app.appspot.com", "assets.example.test"],
                            "private": ["private.example.test"]
                        }
                    }
                }
            }),
            "demo-app",
        )
        .unwrap();

        assert_eq!(
            cfg.storage_rules_by_bucket,
            BTreeMap::from([
                (
                    "assets.example.test".to_owned(),
                    "/proj/public.rules".to_owned()
                ),
                (
                    "demo-app.appspot.com".to_owned(),
                    "/proj/public.rules".to_owned()
                ),
                (
                    "private.example.test".to_owned(),
                    "/proj/private.rules".to_owned()
                ),
            ])
        );
        assert_eq!(cfg.storage_rules_file, None);
    }

    #[test]
    fn storage_target_configuration_is_complete_and_unambiguous() {
        let base = std::path::Path::new("/proj");
        for malformed in [
            json!({"storage": []}),
            json!({"storage": [{"rules": "storage.rules"}]}),
            json!({"storage": [{"target": "uploads"}]}),
            json!({"storage": [
                {"target": "uploads", "rules": "one.rules"},
                {"target": "uploads", "rules": "two.rules"}
            ]}),
        ] {
            assert!(
                RuntimeConfig::default()
                    .apply_firebase_json(&malformed, base, &Selection::default())
                    .is_err(),
                "{malformed}"
            );
        }

        let mut cfg = RuntimeConfig::default();
        cfg.apply_firebase_json(
            &json!({"storage": [{"target": "uploads", "rules": "storage.rules"}]}),
            base,
            &Selection::default(),
        )
        .unwrap();
        for malformed in [
            json!({}),
            json!({"targets": []}),
            json!({"targets": {"demo-app": {"storage": {"uploads": []}}}}),
            json!({"targets": {"demo-app": {"storage": {"uploads": [1]}}}}),
            json!({"targets": {"demo-app": {"storage": {"uploads": ["Uppercase.example.test"]}}}}),
        ] {
            assert!(
                cfg.clone()
                    .resolve_storage_rules_targets(&malformed, "demo-app")
                    .is_err(),
                "{malformed}"
            );
        }
        let too_many = (0..=MAX_STORAGE_RULE_BUCKETS)
            .map(|index| Value::String(format!("bucket-{index}.example.test")))
            .collect::<Vec<_>>();
        assert!(cfg
            .resolve_storage_rules_targets(
                &json!({"targets": {"demo-app": {"storage": {"uploads": too_many}}}}),
                "demo-app",
            )
            .is_err());
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

        let mut cfg = RuntimeConfig::default();
        let malformed = json!({"functions": [{"source": "fn", "runtime": "nodejs-latest"}]});
        let message = cfg
            .apply_firebase_json(&malformed, base, &Selection::default())
            .unwrap_err()
            .0;
        assert!(message.contains("nodejs-latest"), "{message}");
    }

    #[test]
    fn functions_codebase_budget_applies_to_the_selected_runners() {
        let entries = (0..33)
            .map(|index| {
                json!({
                    "source": format!("functions/codebase-{index}"),
                    "codebase": format!("codebase-{index}")
                })
            })
            .collect::<Vec<_>>();
        let base = std::path::Path::new("/proj");

        let mut at_limit = RuntimeConfig::default();
        at_limit
            .apply_firebase_json(
                &json!({"functions": &entries[..32]}),
                base,
                &Selection::default(),
            )
            .expect("the local runner budget includes its exact boundary");
        assert_eq!(at_limit.functions_to_load().len(), 32);

        let mut over_limit = RuntimeConfig::default();
        let error = over_limit
            .apply_firebase_json(&json!({"functions": &entries}), base, &Selection::default())
            .unwrap_err()
            .0;
        assert!(error.contains("33 selected Functions codebases"), "{error}");
        assert!(error.contains("local safety budget of 32"), "{error}");

        let mut selected = RuntimeConfig::default();
        selected
            .apply_firebase_json(
                &json!({"functions": &entries}),
                base,
                &Selection::parse("functions:codebase-32").unwrap(),
            )
            .expect("--only starts one runner even when the file declares more codebases");
        assert_eq!(selected.functions_to_load().len(), 1);
        assert_eq!(selected.functions_to_load()[0].codebase, "codebase-32");
    }

    #[test]
    fn codebase_names_follow_the_firebase_deploy_contract() {
        let base = std::path::Path::new("/proj");
        for name in [
            "a",
            "api-2_workers",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let mut cfg = RuntimeConfig::default();
            cfg.apply_firebase_json(
                &json!({"functions": {"source": "functions", "codebase": name}}),
                base,
                &Selection::default(),
            )
            .unwrap_or_else(|error| panic!("valid codebase {name:?} was refused: {error}"));
        }

        for name in [
            "",
            "Team-API",
            "api.backend",
            "api/backend",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let mut cfg = RuntimeConfig::default();
            let error = cfg
                .apply_firebase_json(
                    &json!({"functions": {"source": "functions", "codebase": name}}),
                    base,
                    &Selection::default(),
                )
                .expect_err("the official Firebase codebase-name bounds must be enforced")
                .0;
            assert!(error.contains("functions.codebase"), "{error}");
            assert!(error.contains("1 to 63"), "{error}");
        }
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
                "eventarc": {"port": 9300},
                "tasks": {"port": 9500},
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
        assert_eq!(cfg.eventarc_addr, "127.0.0.1:9300");
        assert!(cfg.eventarc_enabled);
        assert!(cfg.eventarc_addr_explicit);
        assert_eq!(cfg.tasks_addr, "127.0.0.1:9500");
        assert!(cfg.tasks_enabled);
        assert!(cfg.tasks_addr_explicit);
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
        // Functions uses the qualifier to select one codebase. The official emulator accepts
        // a Storage deploy-target qualifier but starts Storage with every configured rules
        // target, so no Storage filter is retained here.
        assert!(Selection::parse("firestore:default").is_err());
        assert!(Selection::parse("functions:").is_err());
        let storage = Selection::parse("storage:uploads").unwrap();
        assert!(storage.storage);
        assert_eq!(storage.functions_codebase, None);
        // Eventarc and Tasks are valid official service names, but the pinned CLI starts
        // their listeners only as Functions dependencies. Naming either alone is therefore
        // accepted without selecting Functions or another product.
        for service in ["eventarc", "tasks"] {
            let selected = Selection::parse(service).unwrap();
            assert!(selected.explicit, "{service}");
            assert!(!selected.functions, "{service}");
            assert!(!selected.firestore, "{service}");
            assert!(!selected.auth, "{service}");
            assert!(!selected.storage, "{service}");
            assert!(!selected.pubsub, "{service}");
        }
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

    #[test]
    fn custom_token_signers_are_validated_when_the_configuration_is_read() {
        // A public 2048-bit modulus; the key it belongs to was discarded.
        let modulus = "0lwNtQWMVy0QqgEvrBmoFqwky_dcMx8CgS-o2rTesEV7QbG4cvNigTcDV7b_u0twRkJdonkMPjbUs0b8NKe_0_UOZ5vE_kILFG4TtPdeZWub8xnqhETc7WifXhEfqcB8xFbRyIxU9V0d_epsuNnQ-Nd7NlnFsH-aaq6f1HKp55_BVNxudwmHwT49P6JhNDDh7FWyoYBBBFtQ0St8dky4MFQTd2swZP4pEA8xGp-q-1mxbn0g9gfbq5voYWtOaDW9a2lsC_S_d6DecsrNWn4YYJ7Qc5xcx4pI70a23zftkVBj_I-Eip2hcvNUEsZJA4LlR4BgDLsNWu3ZWQxe08fOew";
        let jwks = json!({"keys": [{"kty": "RSA", "alg": "RS256", "kid": "k", "n": modulus, "e": "AQAB"}]});
        let account = "firebase-adminsdk-x@demo-project.iam.gserviceaccount.com";
        let parsed = parse(&json!({"customTokenSigners": {account: jwks.clone()}})).unwrap();
        assert_eq!(
            parsed.auth_custom_token_signers,
            Some(json!({account: jwks}).as_object().unwrap().clone())
        );
        assert_eq!(parse(&json!({})).unwrap().auth_custom_token_signers, None);
        assert_eq!(
            parse(&json!({"customTokenSigners": []})),
            Err(ConfigError(
                "auth.customTokenSigners must be an object".to_owned()
            ))
        );
        assert_eq!(
            parse(&json!({"apiKeys": ["fake-api-key", "AIza.x_y"]}))
                .unwrap()
                .auth_api_keys,
            ["fake-api-key", "AIza.x_y"]
        );
        assert!(parse(&json!({})).unwrap().auth_api_keys.is_empty());
        for bad in [
            json!([]),
            json!("k"),
            json!([""]),
            json!(["a b"]),
            json!([1]),
        ] {
            assert!(parse(&json!({"apiKeys": bad})).is_err(), "{bad}");
        }
        let refused = parse(&json!({"customTokenSigners": {"a@example.com": {"keys": []}}}));
        assert!(
            matches!(&refused, Err(ConfigError(m)) if m.contains("not a service-account address")),
            "{refused:?}"
        );
    }

    #[test]
    fn raw_auth_credentials_require_an_explicit_forwarding_flag() {
        assert!(!parse(&json!({})).unwrap().auth_forward_inbound_credentials);
        assert!(
            parse(&json!({"forwardInboundCredentials": true}))
                .unwrap()
                .auth_forward_inbound_credentials
        );
        assert!(parse(&json!({"forwardInboundCredentials": "yes"})).is_err());
    }

    #[test]
    fn email_enumeration_protection_follows_production_unless_switched_off() {
        assert!(parse(&json!({})).unwrap().auth_improved_email_privacy);
        assert!(
            !parse(&json!({"improvedEmailPrivacy": false}))
                .unwrap()
                .auth_improved_email_privacy
        );
        assert_eq!(
            parse(&json!({"improvedEmailPrivacy": "off"})),
            Err(ConfigError(
                "auth.improvedEmailPrivacy must be a boolean".to_owned()
            ))
        );
    }

    #[test]
    fn action_code_logging_matches_the_official_emulator_unless_switched_off() {
        assert!(parse(&json!({})).unwrap().auth_log_action_codes);
        assert!(
            !parse(&json!({"logActionCodes": false}))
                .unwrap()
                .auth_log_action_codes
        );
        assert_eq!(
            parse(&json!({"logActionCodes": "no"})),
            Err(ConfigError(
                "auth.logActionCodes must be a boolean".to_owned()
            ))
        );
    }

    #[test]
    fn totp_is_an_explicit_auth_extension_with_strict_bounds() {
        assert!(parse(&json!({})).unwrap().auth_totp.is_none());

        let configured = parse(&json!({
            "totp": {
                "periodSeconds": 45,
                "digits": 8,
                "windowSteps": 2,
                "enrollmentSessionTtlSeconds": 600
            }
        }))
        .unwrap()
        .auth_totp
        .expect("the TOTP object explicitly enables the extension");
        assert_eq!(configured.period_seconds, 45);
        assert_eq!(configured.digits, 8);
        assert_eq!(configured.window_steps, 2);
        assert_eq!(configured.enrollment_session_ttl.as_seconds(), 600);

        for invalid in [
            json!({"totp": true}),
            json!({"totp": {"periodSeconds": 0}}),
            json!({"totp": {"digits": 5}}),
            json!({"totp": {"digits": 9}}),
            json!({"totp": {"windowSteps": 11}}),
            json!({"totp": {"enrollmentSessionTtlSeconds": 0}}),
            json!({"totp": {"unknown": 1}}),
        ] {
            assert!(
                parse(&invalid).is_err(),
                "accepted invalid Auth config: {invalid}"
            );
        }
    }
    #[test]
    fn auth_project_numbers_are_explicit_validated_namespace_mappings() {
        let cfg = RuntimeConfig::from_json(&json!({"schemaVersion":1,"daemon":{"authProjectNumbers":{"demo-one":"111111111111","demo-two":"222222222222","demo-max":"18446744073709551615"}}})).unwrap();
        assert_eq!(
            cfg.auth_project_numbers.get("demo-one"),
            Some(&111_111_111_111)
        );
        assert_eq!(
            cfg.auth_project_numbers.get("demo-two"),
            Some(&222_222_222_222)
        );
        assert_eq!(cfg.auth_project_numbers.get("demo-max"), Some(&u64::MAX));
        assert_eq!(cfg.auth_project_numbers.get("demo-unset"), None);
        for invalid in [
            json!(0),
            json!("0"),
            json!("-1"),
            json!("x"),
            json!("18446744073709551616"),
        ] {
            assert!(RuntimeConfig::from_json(
                &json!({"schemaVersion":1,"daemon":{"authProjectNumbers":{"demo-one":invalid}}})
            )
            .is_err());
        }
    }

    #[test]
    fn password_policy_config_is_strict_and_preserves_unset_maximum() {
        let cfg = RuntimeConfig::from_json(&json!({
            "schemaVersion": 1,
            "auth": {
                "passwordPolicy": {
                    "enforcementState": "ENFORCE",
                    "forceUpgradeOnSignin": true,
                    "constraints": {
                        "minLength": 12,
                        "requireUppercase": true,
                        "requireNumeric": true
                    }
                },
                "passwordPolicyOverrides": [{
                    "projectId": "demo-other",
                    "tenantId": "tenant-a",
                    "passwordPolicy": {"enforcementState": "OFF"}
                }]
            }
        }))
        .unwrap();
        let policy = cfg.auth_password_policy.unwrap();
        assert_eq!(policy.enforcement_state, "ENFORCE");
        assert!(policy.force_upgrade_on_signin);
        assert_eq!(policy.constraints.min_length, 12);
        assert_eq!(policy.constraints.max_length, None);
        assert_eq!(cfg.auth_password_policy_overrides.len(), 1);
        assert_eq!(
            cfg.auth_password_policy_overrides[0].tenant_id.as_deref(),
            Some("tenant-a")
        );

        for invalid in [
            json!({"enforcementState":"NOTIFY"}),
            json!({"enforcementState":"ENFORCE","constraints":{"minLength":5}}),
            json!({"enforcementState":"ENFORCE","constraints":{"maxLength":5}}),
            json!({"enforcementState":"ENFORCE","forceUpgradeOnSignin":"true"}),
            json!({"enforcementState":"ENFORCE","constraints":{"requireNumeric":null}}),
            json!({"enforcementState":"ENFORCE","unknown":true}),
        ] {
            assert!(
                RuntimeConfig::from_json(&json!({
                    "schemaVersion": 1,
                    "auth": {"passwordPolicy": invalid}
                }))
                .is_err(),
                "accepted invalid password policy: {invalid}"
            );
        }
    }

    #[test]
    fn password_policy_overrides_reject_duplicate_or_ambiguous_namespaces() {
        let duplicate = json!({
            "schemaVersion": 1,
            "auth": {"passwordPolicyOverrides": [
                {"projectId":"demo-app","passwordPolicy":{"enforcementState":"OFF"}},
                {"projectId":"demo-app","passwordPolicy":{"enforcementState":"ENFORCE"}}
            ]}
        });
        assert!(RuntimeConfig::from_json(&duplicate).is_err());
        let ambiguous = json!({
            "schemaVersion": 1,
            "auth": {
                "passwordPolicy": {"enforcementState":"OFF"},
                "passwordPolicyOverrides": [{"projectId":"demo-app","passwordPolicy":{"enforcementState":"OFF"}}]
            }
        });
        assert!(RuntimeConfig::from_json(&ambiguous).is_err());
        let null_tenant = json!({
            "schemaVersion": 1,
            "auth": {"passwordPolicyOverrides": [{"projectId":"demo-app","tenantId":null,"passwordPolicy":{"enforcementState":"OFF"}}]}
        });
        assert!(RuntimeConfig::from_json(&null_tenant).is_err());
    }

    #[test]
    fn auth_client_settings_are_strict_and_keep_legacy_defaults() {
        let defaults = parse(&json!({})).unwrap();
        assert!(!defaults.auth_allow_duplicate_emails);
        assert_eq!(
            defaults.auth_client_permissions,
            AuthClientPermissions::default()
        );
        assert!(defaults.auth_improved_email_privacy);

        let configured = parse(&json!({
            "signIn": {"allowDuplicateEmails": true},
            "client": {"permissions": {
                "disabledUserSignup": true,
                "disabledUserDeletion": false
            }},
            "improvedEmailPrivacy": false
        }))
        .unwrap();
        assert!(configured.auth_allow_duplicate_emails);
        assert_eq!(
            configured.auth_client_permissions,
            AuthClientPermissions {
                disabled_user_signup: true,
                disabled_user_deletion: false,
            }
        );
        assert!(!configured.auth_improved_email_privacy);

        for invalid in [
            json!({"signIn": {"allowDuplicateEmails": "true"}}),
            json!({"signIn": {"allowDuplicateEmails": null}}),
            json!({"client": {"permissions": {"disabledUserSignup": 1}}}),
            json!({"client": {"permissions": {"disabledUserDeletion": null}}}),
            json!({"improvedEmailPrivacy": null}),
            json!({"client": {"unknown": false}}),
            json!({"signIn": {"unknown": false}}),
        ] {
            assert!(
                parse(&invalid).is_err(),
                "accepted invalid Auth config: {invalid}"
            );
        }
    }

    #[test]
    fn auth_config_overrides_are_namespace_scoped_and_strict() {
        let cfg = parse(&json!({
            "configOverrides": [
                {
                    "projectId": "demo-other",
                    "config": {
                        "client": {"permissions": {"disabledUserSignup": true}}
                    }
                },
                {
                    "projectId": "demo-app",
                    "tenantId": "tenant-a",
                    "config": {"improvedEmailPrivacy": false}
                }
            ]
        }))
        .unwrap();
        assert_eq!(cfg.auth_config_overrides.len(), 2);
        assert_eq!(
            cfg.auth_config_overrides[0].config.client_permissions,
            Some(AuthClientPermissions {
                disabled_user_signup: true,
                disabled_user_deletion: false,
            })
        );
        assert_eq!(
            cfg.auth_config_overrides[1].tenant_id.as_deref(),
            Some("tenant-a")
        );
        assert_eq!(
            cfg.auth_config_overrides[1].config.improved_email_privacy,
            Some(false)
        );

        let duplicate = json!({
            "configOverrides": [
                {"projectId": "demo-other", "config": {"improvedEmailPrivacy": true}},
                {"projectId": "demo-other", "config": {"improvedEmailPrivacy": false}}
            ]
        });
        assert!(parse(&duplicate).is_err());
        let ambiguous = json!({
            "client": {"permissions": {"disabledUserSignup": true}},
            "configOverrides": [{
                "projectId": "demo-app",
                "config": {"client": {"permissions": {"disabledUserSignup": false}}}
            }]
        });
        assert!(parse(&ambiguous).is_err());
        for invalid in [
            json!({"configOverrides": true}),
            json!({"configOverrides": [{"tenantId": "tenant-a", "config": {}}]}),
            json!({"configOverrides": [{"projectId": "demo-app", "tenantId": "", "config": {"improvedEmailPrivacy": true}}]}),
            json!({"configOverrides": [{"projectId": "demo-app", "tenantId": null, "config": {"improvedEmailPrivacy": true}}]}),
            json!({"configOverrides": [{"projectId": "demo-app", "config": {"client": {"permissions": {"disabledUserSignup": "yes"}}}}]}),
            json!({"configOverrides": [{"projectId": "demo-app", "config": {"unknown": true}}]}),
        ] {
            assert!(
                parse(&invalid).is_err(),
                "accepted invalid override: {invalid}"
            );
        }
    }

    #[test]
    fn blocking_function_and_forwarding_settings_have_explicit_defaults_and_guards() {
        assert!(parse(&json!({})).unwrap().auth_blocking_functions.is_none());
        let cfg = parse(&json!({
            "forwardInboundCredentials": true,
            "blockingFunctions": {
                "triggers": {
                    "beforeCreate": {"function": "checkRegistration", "region": "us-central1"},
                    "beforeSignIn": null
                },
                "forwardInboundCredentials": {
                    "idToken": true,
                    "accessToken": false,
                    "refreshToken": true
                }
            }
        }))
        .unwrap();
        let blocking = cfg.auth_blocking_functions.unwrap();
        assert_eq!(
            blocking.triggers.unwrap().before_create,
            Some(BlockingFunctionTrigger {
                function: "checkRegistration".to_owned(),
                region: Some("us-central1".to_owned())
            })
        );
        assert!(blocking.forward_inbound_credentials.unwrap().id_token);

        for invalid in [
            json!({"blockingFunctions": true}),
            json!({"blockingFunctions": {"triggers": []}}),
            json!({"blockingFunctions": {"triggers": {"beforeCreate": {"function": ""}}}}),
            json!({"blockingFunctions": {"triggers": {"beforeCreate": {"function": "f", "unknown": true}}}}),
            json!({"blockingFunctions": {"forwardInboundCredentials": {"idToken": true}}}),
            json!({"forwardInboundCredentials": false, "blockingFunctions": {"forwardInboundCredentials": {"idToken": true}}}),
        ] {
            assert!(
                parse(&invalid).is_err(),
                "accepted invalid blocking config: {invalid}"
            );
        }
    }

    #[test]
    fn auth_quota_config_and_simulation_are_strictly_typed_and_bounded() {
        let cfg = parse(&json!({
            "quota": {
                "signUpQuotaConfig": {
                    "quota": "200",
                    "startTime": "2030-01-01T00:00:00Z",
                    "quotaDuration": "86400s"
                }
            },
            "quotaSimulation": {
                "mode": "enforce",
                "algorithm": "fixed-window-v1",
                "defaultQuotaPerHour": 1000,
                "maxTrackedBuckets": 16
            }
        }))
        .unwrap();
        let quota = cfg.auth_signup_quota.unwrap();
        assert_eq!(quota.quota, "200");
        assert_eq!(
            quota.start_time.to_rfc3339().unwrap(),
            "2030-01-01T00:00:00Z"
        );
        assert_eq!(quota.quota_duration.as_seconds(), 86_400);
        assert_eq!(
            cfg.auth_quota_simulation.mode,
            AuthQuotaSimulationMode::Enforce
        );
        assert_eq!(cfg.auth_quota_simulation.default_quota_per_hour, 1000);
        assert_eq!(cfg.auth_quota_simulation.max_tracked_buckets, 16);

        for invalid in [
            json!({"quota": {"signUpQuotaConfig": {"quota": 200, "startTime": "2030-01-01T00:00:00Z", "quotaDuration": "1s"}}}),
            json!({"quota": {"signUpQuotaConfig": {"quota": "1", "startTime": "bad", "quotaDuration": "1s"}}}),
            json!({"quota": {"signUpQuotaConfig": {"quota": "1", "startTime": "2030-01-01T00:00:00Z", "quotaDuration": "0s"}}}),
            json!({"quota": {"signUpQuotaConfig": {"quota": "1", "startTime": "2030-01-01T00:00:00Z", "quotaDuration": "1m"}}}),
            json!({"quota": {"signUpQuotaConfig": {"quota": "9223372036854775808", "startTime": "2030-01-01T00:00:00Z", "quotaDuration": "1s"}}}),
            json!({"quotaSimulation": {"mode": "strict"}}),
            json!({"quotaSimulation": {"algorithm": "sliding-window-v1"}}),
            json!({"quotaSimulation": {"defaultQuotaPerHour": -1}}),
            json!({"quotaSimulation": {"maxTrackedBuckets": 0}}),
        ] {
            assert!(
                parse(&invalid).is_err(),
                "accepted invalid quota config: {invalid}"
            );
        }
        assert!(parse(&json!({"quota": {"signUpQuotaConfig": null}}))
            .unwrap()
            .auth_signup_quota
            .is_none());
    }
}
