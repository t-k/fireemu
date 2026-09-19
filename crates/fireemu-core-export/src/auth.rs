//! `auth_export/`: the accounts and configuration documents.
//!
//! The official CLI writes the Auth section by streaming two Identity Toolkit responses to
//! disk verbatim (`hubExport.ts` `exportAuth`):
//!
//! - `accounts.json` -- the body of `GET /identitytoolkit.googleapis.com/v1/projects/{p}/
//!   accounts:batchGet?maxResults=-1`, an `identitytoolkit#DownloadAccountResponse`;
//! - `accounts-<tenant>.json` -- the same for each tenant of the project;
//! - `config.json` -- the body of `GET /emulator/v1/projects/{p}/config`.
//!
//! Import feeds them back through `accounts:batchCreate` and a `PATCH` of the config
//! (`auth/index.ts` `importData`), so the file *is* the API shape and nothing else.
//!
//! Every documented member is modelled; a member this crate does not know is kept in
//! [`UserRecord::extra`] and written out again unchanged. The CLI currently rejects such
//! records because the live Auth store cannot retain unknown members across an import.
//!
//! # Sensitive material
//!
//! `passwordHash`, `salt`, the MFA enrollments (phone numbers and, for fireemu, TOTP shared
//! secrets) and `customAttributes` are all credentials or personal data. The emulator's own
//! hashes are the reversible `fakeHash:salt=<salt>:password=<plaintext>` convention, so an
//! accounts file is equivalent to a plaintext password list and must never be world
//! readable; `fireemu` writes the whole export directory with owner-only permissions.

use fireemu_core_types::json::{parse, JsonValue};
use std::collections::BTreeSet;

use crate::json::Json;

/// The file name of the default tenant's accounts.
pub const ACCOUNTS_FILE: &str = "accounts.json";
/// The file name of the project configuration.
pub const CONFIG_FILE: &str = "config.json";
/// The fireemu-only Auth policy sidecar. It is kept separate from the official `config.json`
/// document so an export remains importable by the official Local Emulator Suite.
pub const PASSWORD_POLICIES_FILE: &str = "fireemu-password-policies.json";
/// The fireemu-only Auth runtime settings sidecar. It carries settings which are not part of
/// the official `config.json`, such as the local sign-up quota simulator.
pub const AUTH_SETTINGS_FILE: &str = "fireemu-auth-settings.json";
/// Version of the fireemu-only Auth runtime settings sidecar format.
///
/// Version 2 records whether a tenant config is an explicit override. Version 1 remains
/// readable, but its ambiguous effective tenant configs are migrated as inherited.
pub const AUTH_SETTINGS_VERSION: i64 = 2;
/// Version of the fireemu-only Auth password policy sidecar format.
pub const PASSWORD_POLICIES_VERSION: i64 = 1;
/// The `kind` member the Identity Toolkit answers with.
pub const DOWNLOAD_KIND: &str = "identitytoolkit#DownloadAccountResponse";

const KNOWN_CONFIG_MEMBERS: [&str; 3] = ["signIn", "emailPrivacyConfig", "client"];
const KNOWN_SIGN_IN_MEMBERS: [&str; 1] = ["allowDuplicateEmails"];
const KNOWN_PRIVACY_MEMBERS: [&str; 1] = ["enableImprovedEmailPrivacy"];
const KNOWN_CLIENT_MEMBERS: [&str; 1] = ["permissions"];
const KNOWN_PERMISSION_MEMBERS: [&str; 2] = ["disabledUserSignup", "disabledUserDeletion"];
const KNOWN_PROVIDER_MEMBERS: [&str; 8] = [
    "providerId",
    "rawId",
    "federatedId",
    "email",
    "displayName",
    "photoUrl",
    "phoneNumber",
    "screenName",
];
const KNOWN_MFA_MEMBERS: [&str; 6] = [
    "mfaEnrollmentId",
    "displayName",
    "phoneInfo",
    "unobfuscatedPhoneInfo",
    "enrolledAt",
    "totpInfo",
];
const KNOWN_TOTP_MEMBERS: [&str; 1] = ["sharedSecretKey"];
const KNOWN_PASSWORD_POLICIES_MEMBERS: [&str; 4] =
    ["version", "projectId", "project", "namespaces"];
const KNOWN_PASSWORD_NAMESPACE_MEMBERS: [&str; 2] = ["tenantId", "policy"];
const KNOWN_PASSWORD_POLICY_MEMBERS: [&str; 9] = [
    "enforcementState",
    "forceUpgradeOnSignin",
    "minLength",
    "maxLength",
    "requireUppercase",
    "requireLowercase",
    "requireNumeric",
    "requireNonAlphanumeric",
    "allowedNonAlphanumericCharacters",
];
const KNOWN_AUTH_SETTINGS_MEMBERS: [&str; 4] = ["version", "projectId", "project", "namespaces"];
const KNOWN_AUTH_SETTINGS_NAMESPACE_MEMBERS: [&str; 4] =
    ["tenantId", "settings", "metadata", "configExplicit"];
const KNOWN_AUTH_SETTINGS_RECORD_MEMBERS: [&str; 3] = ["config", "quota", "blocking"];
const KNOWN_TENANT_METADATA_MEMBERS: [&str; 8] = [
    "displayName",
    "allowPasswordSignup",
    "enableEmailLinkSignin",
    "enableAnonymousUser",
    "disableAuth",
    "disabledUserSignup",
    "disabledUserDeletion",
    "enableImprovedEmailPrivacy",
];
const BLOCKING_DISCOVERY_EVENTS_MEMBER: &str = "__fireemuDiscoveryEvents";
const KNOWN_QUOTA_MEMBERS: [&str; 5] = [
    "mode",
    "algorithm",
    "defaultQuotaPerHour",
    "maxTrackedBuckets",
    "temporary",
];
const KNOWN_TEMPORARY_QUOTA_MEMBERS: [&str; 3] = ["quota", "startTime", "quotaDuration"];

/// One validated password policy in the fireemu export extension.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct PasswordPolicyRecord {
    /// `OFF` or `ENFORCE`.
    pub enforcement_state: String,
    /// Whether a non-compliant existing password is rejected at sign-in.
    pub force_upgrade_on_signin: bool,
    /// Inclusive minimum length in UTF-16 code units.
    pub min_length: i64,
    /// Optional custom maximum length. `None` is distinct from an explicit maximum.
    pub max_length: Option<i64>,
    /// Require at least one ASCII uppercase character.
    pub require_uppercase: bool,
    /// Require at least one ASCII lowercase character.
    pub require_lowercase: bool,
    /// Require at least one ASCII digit.
    pub require_numeric: bool,
    /// Require a character from the configured set.
    pub require_non_alphanumeric: bool,
    /// Explicit allowed non-alphanumeric characters.
    pub allowed_non_alphanumeric_characters: BTreeSet<char>,
}

/// A namespace policy entry in the fireemu export extension. `tenant_id: None` is the project
/// namespace represented by `project_id` on [`PasswordPolicies`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicyNamespace {
    /// Tenant ID, or `None` for the project namespace.
    pub tenant_id: Option<String>,
    /// Effective policy for this namespace.
    pub policy: PasswordPolicyRecord,
}

/// Explicit password policies retained by an Auth export. This is deliberately a fireemu
/// extension: the official Auth export format has no password-policy sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicies {
    /// Source project ID. Policies are only installed when it matches the import target.
    pub project_id: String,
    /// Policy of the project namespace.
    pub project: PasswordPolicyRecord,
    /// Explicit tenant policies; unlisted tenants do not inherit the project policy.
    pub namespaces: Vec<PasswordPolicyNamespace>,
}

impl PasswordPolicies {
    /// Parses the fireemu-only sidecar.
    pub fn parse(text: &str) -> Result<Self, AuthExportError> {
        let value = parse(text).map_err(|e| AuthExportError(e.to_string()))?;
        reject_unknown(
            &value,
            &KNOWN_PASSWORD_POLICIES_MEMBERS,
            "password policy sidecar",
        )?;
        let version = value
            .get("version")
            .and_then(JsonValue::as_i64)
            .ok_or_else(|| {
                AuthExportError("password policy sidecar has no integer version".to_owned())
            })?;
        if version != PASSWORD_POLICIES_VERSION {
            return refuse(format!(
                "unsupported password policy sidecar version {version}"
            ));
        }
        let project_id = value
            .get("projectId")
            .and_then(JsonValue::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| AuthExportError("password policy sidecar has no projectId".to_owned()))?
            .to_owned();
        let project = parse_password_policy(
            value.get("project").ok_or_else(|| {
                AuthExportError("password policy sidecar has no project".to_owned())
            })?,
            "password policy sidecar project",
        )?;
        let mut namespaces = Vec::new();
        if let Some(value) = value.get("namespaces") {
            let JsonValue::Array(entries) = value else {
                return refuse("password policy sidecar namespaces is not an array");
            };
            let mut tenants = BTreeSet::new();
            for (index, entry) in entries.iter().enumerate() {
                reject_unknown(
                    entry,
                    &KNOWN_PASSWORD_NAMESPACE_MEMBERS,
                    "password policy namespace",
                )?;
                let tenant_id = match entry.get("tenantId") {
                    None | Some(JsonValue::Null) => None,
                    Some(JsonValue::String(value)) if !value.is_empty() => Some(value.clone()),
                    Some(_) => {
                        return refuse(format!(
                            "password policy namespace {index} has an invalid tenantId"
                        ))
                    }
                };
                let key = tenant_id.clone().unwrap_or_default();
                if !tenants.insert(key) {
                    return refuse(format!(
                        "password policy sidecar has duplicate tenant namespace at index {index}"
                    ));
                }
                let policy = parse_password_policy(
                    entry.get("policy").ok_or_else(|| {
                        AuthExportError("password policy namespace has no policy".to_owned())
                    })?,
                    "password policy namespace policy",
                )?;
                namespaces.push(PasswordPolicyNamespace { tenant_id, policy });
            }
        }
        if namespaces.iter().any(|entry| entry.tenant_id.is_none()) {
            return refuse("password policy sidecar cannot repeat the project namespace");
        }
        Ok(Self {
            project_id,
            project,
            namespaces,
        })
    }

    /// Serializes the sidecar with stable namespace ordering.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut doc = Json::object();
        doc.insert("version", Json::Int(PASSWORD_POLICIES_VERSION));
        doc.insert("projectId", Json::string(&self.project_id));
        doc.insert("project", write_password_policy(&self.project));
        let mut namespaces = self.namespaces.clone();
        namespaces.sort_by(|left, right| left.tenant_id.cmp(&right.tenant_id));
        doc.insert(
            "namespaces",
            Json::Array(
                namespaces
                    .iter()
                    .map(|entry| {
                        let mut namespace = Json::object();
                        namespace
                            .insert_some("tenantId", entry.tenant_id.as_ref().map(Json::string));
                        namespace.insert("policy", write_password_policy(&entry.policy));
                        namespace
                    })
                    .collect(),
            ),
        );
        doc.to_pretty()
    }
}

/// The local sign-up quota configuration retained by a fireemu Auth export.
///
/// Usage buckets are deliberately absent: they are runtime state, and restoring an account
/// export must not silently restore or reset quota history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaSettingsRecord {
    /// `off`, `observe`, or `enforce`.
    pub mode: String,
    /// The local algorithm identifier.
    pub algorithm: String,
    /// Default quota for a UTC-aligned hourly window.
    pub default_quota_per_hour: i64,
    /// Maximum number of retained project/IP/window buckets.
    pub max_tracked_buckets: i64,
    /// Optional absolute temporary quota interval.
    pub temporary: Option<TemporaryQuotaRecord>,
}

/// A serializable temporary quota interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporaryQuotaRecord {
    /// Maximum successful reservations in the interval.
    pub quota: i64,
    /// RFC 3339 UTC start time.
    pub start_time: String,
    /// Positive protobuf duration, for example `86400s`.
    pub quota_duration: String,
}

/// Settings which are not safely represented by the official Auth export shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSettingsRecord {
    /// Optional namespace configuration. Project config normally lives in `config.json`; tenant
    /// settings use this field because official tenant account files have no config document.
    pub config: Option<AuthConfig>,
    /// Optional local quota configuration. Usage is intentionally not retained.
    pub quota: Option<QuotaSettingsRecord>,
    /// Logical project-level Blocking Auth selection. Runner addresses and secrets are never
    /// part of an export.
    pub blocking: Option<BlockingAuthSettingsRecord>,
}

/// One logical Blocking Auth trigger selection, resolved again against an owned Functions
/// manifest when an artifact is imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockingAuthSelectionRecord {
    /// Use the discovered target for this event.
    Discovery,
    /// Explicitly disable this event.
    Disabled,
    /// Select the stable logical fireemu URI for one owned function.
    Explicit {
        /// Stable logical URI for the selected owned function.
        function_uri: String,
    },
}

/// Project-level logical Blocking Auth settings retained by the fireemu sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockingAuthSettingsRecord {
    /// Selection for `beforeCreate`.
    pub before_create: BlockingAuthSelectionRecord,
    /// Selection for `beforeSignIn`.
    pub before_sign_in: BlockingAuthSelectionRecord,
    /// Whether the project-level forwarding restriction was explicitly configured.
    pub forwarding: Option<BlockingAuthForwardingRecord>,
}

/// Raw credential forwarding restriction for a Blocking Auth function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockingAuthForwardingRecord {
    /// Forward provider ID tokens.
    pub id_token: bool,
    /// Forward provider access tokens.
    pub access_token: bool,
    /// Forward provider refresh tokens.
    pub refresh_token: bool,
}

/// A settings entry scoped to one Auth namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSettingsNamespace {
    /// Tenant ID, or `None` for the project namespace.
    pub tenant_id: Option<String>,
    /// Settings for that namespace.
    pub settings: AuthSettingsRecord,
    /// Whether the namespace `settings.config` is an explicit override rather than an
    /// effective inherited snapshot. Version 1 artifacts omit this marker and are migrated as
    /// inherited to avoid freezing project settings based on ambiguous historical output.
    pub config_is_explicit: bool,
    /// Complete tenant authorization metadata, when captured by fireemu.
    ///
    /// This is optional so an older artifact without the extension keeps the legacy import
    /// behavior. When present, all boolean members are serialized, including explicit `false`
    /// values.
    pub metadata: Option<TenantMetadataRecord>,
}

/// Complete authorization metadata for one Identity Platform tenant.
///
/// The project ID is carried by the enclosing [`AuthSettings`] record. Keeping this DTO in the
/// export crate avoids coupling the artifact format to the live Auth registry implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct TenantMetadataRecord {
    /// Human-readable tenant name, if configured.
    pub display_name: Option<String>,
    /// Whether password sign-up and sign-in are enabled.
    pub allow_password_signup: bool,
    /// Whether email-link sign-in is enabled.
    pub enable_email_link_signin: bool,
    /// Whether anonymous sign-in is enabled.
    pub enable_anonymous_user: bool,
    /// Whether all authentication is disabled.
    pub disable_auth: bool,
    /// Whether end-user account creation is disabled in this tenant.
    pub disabled_user_signup: bool,
    /// Whether end-user self-deletion is disabled in this tenant.
    pub disabled_user_deletion: bool,
    /// Whether email enumeration protection is enabled in this tenant.
    pub enable_improved_email_privacy: bool,
}

/// fireemu-only Auth settings retained next to the official export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSettings {
    /// Source project ID. Settings are only installed when it matches the import target.
    pub project_id: String,
    /// Optional project settings. The project config itself is in `config.json`; this entry is
    /// still present when a project quota simulator is configured.
    pub project: AuthSettingsRecord,
    /// Explicit tenant settings. Unlisted tenants do not inherit these values on import.
    pub namespaces: Vec<AuthSettingsNamespace>,
}

impl AuthSettings {
    /// Rejects tenant metadata from a different Auth project while preserving the historical
    /// behavior for older sidecars that carry no tenant metadata extension.
    pub fn validate_tenant_metadata_project(
        &self,
        target_project: &str,
    ) -> Result<(), AuthExportError> {
        if self.project_id != target_project
            && self
                .namespaces
                .iter()
                .any(|namespace| namespace.metadata.is_some())
        {
            return refuse(format!(
                "tenant metadata belongs to project {:?}, not the import target {:?}",
                self.project_id, target_project
            ));
        }
        Ok(())
    }

    /// Parses the fireemu-only settings sidecar.
    pub fn parse(text: &str) -> Result<Self, AuthExportError> {
        let value = parse(text).map_err(|e| AuthExportError(e.to_string()))?;
        reject_unknown(
            &value,
            &KNOWN_AUTH_SETTINGS_MEMBERS,
            "Auth settings sidecar",
        )?;
        let version = value
            .get("version")
            .and_then(JsonValue::as_i64)
            .ok_or_else(|| {
                AuthExportError("Auth settings sidecar has no integer version".to_owned())
            })?;
        if version != 1 && version != AUTH_SETTINGS_VERSION {
            return refuse(format!(
                "unsupported Auth settings sidecar version {version}"
            ));
        }
        let project_id = value
            .get("projectId")
            .and_then(JsonValue::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| AuthExportError("Auth settings sidecar has no projectId".to_owned()))?
            .to_owned();
        let project = parse_auth_settings_record(
            value.get("project").ok_or_else(|| {
                AuthExportError("Auth settings sidecar has no project".to_owned())
            })?,
            "Auth settings sidecar project",
        )?;
        let mut namespaces = Vec::new();
        if let Some(JsonValue::Array(entries)) = value.get("namespaces") {
            let mut tenants = BTreeSet::new();
            for (index, entry) in entries.iter().enumerate() {
                reject_unknown(
                    entry,
                    &KNOWN_AUTH_SETTINGS_NAMESPACE_MEMBERS,
                    "Auth settings namespace",
                )?;
                let tenant_id = entry
                    .get("tenantId")
                    .and_then(JsonValue::as_str)
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| {
                        AuthExportError(format!(
                            "Auth settings namespace {index} has no non-empty tenantId"
                        ))
                    })?
                    .to_owned();
                if !tenants.insert(tenant_id.clone()) {
                    return refuse(format!(
                        "Auth settings sidecar has duplicate tenant namespace at index {index}"
                    ));
                }
                let settings = parse_auth_settings_record(
                    entry.get("settings").ok_or_else(|| {
                        AuthExportError("Auth settings namespace has no settings".to_owned())
                    })?,
                    "Auth settings namespace settings",
                )?;
                let metadata = match entry.get("metadata") {
                    None | Some(JsonValue::Null) => None,
                    Some(value) => Some(parse_tenant_metadata(
                        value,
                        &format!("Auth settings namespace {index}.metadata"),
                    )?),
                };
                let config_is_explicit = if version == 1 {
                    if entry.get("configExplicit").is_some() {
                        return refuse(format!(
                            "Auth settings namespace {index} uses configExplicit with version 1"
                        ));
                    }
                    false
                } else {
                    entry
                        .get("configExplicit")
                        .and_then(JsonValue::as_bool)
                        .ok_or_else(|| {
                            AuthExportError(format!(
                                "Auth settings namespace {index} has no boolean configExplicit"
                            ))
                        })?
                };
                namespaces.push(AuthSettingsNamespace {
                    tenant_id: Some(tenant_id),
                    settings,
                    metadata,
                    config_is_explicit,
                });
            }
        } else if let Some(value) = value.get("namespaces") {
            return refuse(format!(
                "Auth settings sidecar namespaces is not an array ({value:?})"
            ));
        }
        Ok(Self {
            project_id,
            project,
            namespaces,
        })
    }

    /// Serializes the sidecar with stable tenant ordering.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut doc = Json::object();
        doc.insert("version", Json::Int(AUTH_SETTINGS_VERSION));
        doc.insert("projectId", Json::string(&self.project_id));
        doc.insert("project", write_auth_settings_record(&self.project));
        let mut namespaces = self.namespaces.clone();
        namespaces.sort_by(|left, right| left.tenant_id.cmp(&right.tenant_id));
        doc.insert(
            "namespaces",
            Json::Array(
                namespaces
                    .iter()
                    .map(|entry| {
                        let mut namespace = Json::object();
                        namespace
                            .insert_some("tenantId", entry.tenant_id.as_ref().map(Json::string));
                        namespace.insert("settings", write_auth_settings_record(&entry.settings));
                        namespace.insert("configExplicit", Json::Bool(entry.config_is_explicit));
                        namespace.insert_some(
                            "metadata",
                            entry.metadata.as_ref().map(write_tenant_metadata),
                        );
                        namespace
                    })
                    .collect(),
            ),
        );
        doc.to_pretty()
    }
}

fn parse_tenant_metadata(
    value: &JsonValue,
    subject: &str,
) -> Result<TenantMetadataRecord, AuthExportError> {
    reject_unknown(value, &KNOWN_TENANT_METADATA_MEMBERS, subject)?;
    let optional_string = match value.get("displayName") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::String(value)) => Some(value.clone()),
        Some(_) => return refuse(format!("{subject}.displayName is not a string or null")),
    };
    let boolean = |key: &str| {
        value
            .get(key)
            .and_then(JsonValue::as_bool)
            .ok_or_else(|| AuthExportError(format!("{subject}.{key} is not a boolean")))
    };
    Ok(TenantMetadataRecord {
        display_name: optional_string,
        allow_password_signup: boolean("allowPasswordSignup")?,
        enable_email_link_signin: boolean("enableEmailLinkSignin")?,
        enable_anonymous_user: boolean("enableAnonymousUser")?,
        disable_auth: boolean("disableAuth")?,
        disabled_user_signup: boolean("disabledUserSignup")?,
        disabled_user_deletion: boolean("disabledUserDeletion")?,
        enable_improved_email_privacy: boolean("enableImprovedEmailPrivacy")?,
    })
}

fn parse_auth_settings_record(
    value: &JsonValue,
    subject: &str,
) -> Result<AuthSettingsRecord, AuthExportError> {
    reject_unknown(value, &KNOWN_AUTH_SETTINGS_RECORD_MEMBERS, subject)?;
    let config = match value.get("config") {
        None | Some(JsonValue::Null) => None,
        Some(config) => Some(AuthConfig::parse(&Json::from_value(config).to_pretty())?),
    };
    let quota = match value.get("quota") {
        None | Some(JsonValue::Null) => None,
        Some(quota) => Some(parse_quota_settings(quota, &format!("{subject}.quota"))?),
    };
    let blocking = match value.get("blocking") {
        None | Some(JsonValue::Null) => None,
        Some(blocking) => Some(parse_blocking_settings(
            blocking,
            &format!("{subject}.blocking"),
        )?),
    };
    Ok(AuthSettingsRecord {
        config,
        quota,
        blocking,
    })
}

fn parse_blocking_discovery_events(
    value: &JsonValue,
    subject: &str,
) -> Result<BTreeSet<String>, AuthExportError> {
    let JsonValue::Array(events) = value else {
        return refuse(format!(
            "{subject}.{BLOCKING_DISCOVERY_EVENTS_MEMBER} is not an array"
        ));
    };
    let mut discovery = BTreeSet::new();
    for event in events {
        let Some(event) = event.as_str() else {
            return refuse(format!(
                "{subject}.{BLOCKING_DISCOVERY_EVENTS_MEMBER} contains a non-string event"
            ));
        };
        if !matches!(event, "beforeCreate" | "beforeSignIn") {
            return refuse(format!(
                "{subject}.{BLOCKING_DISCOVERY_EVENTS_MEMBER} contains unsupported event {event:?}"
            ));
        }
        if !discovery.insert(event.to_owned()) {
            return refuse(format!(
                "{subject}.{BLOCKING_DISCOVERY_EVENTS_MEMBER} contains duplicate event {event:?}"
            ));
        }
    }
    Ok(discovery)
}

fn parse_blocking_settings(
    value: &JsonValue,
    subject: &str,
) -> Result<BlockingAuthSettingsRecord, AuthExportError> {
    reject_unknown(
        value,
        &[
            "triggers",
            "forwardInboundCredentials",
            BLOCKING_DISCOVERY_EVENTS_MEMBER,
        ],
        subject,
    )?;
    let discovery = value.get(BLOCKING_DISCOVERY_EVENTS_MEMBER).map_or_else(
        || Ok(BTreeSet::new()),
        |value| parse_blocking_discovery_events(value, subject),
    )?;
    if !discovery.is_empty() && value.get("triggers").is_none() {
        return refuse(format!(
            "{subject}.{BLOCKING_DISCOVERY_EVENTS_MEMBER} requires a triggers object"
        ));
    }
    let selection = |event: &str| -> Result<BlockingAuthSelectionRecord, AuthExportError> {
        let Some(triggers) = value.get("triggers") else {
            return Ok(BlockingAuthSelectionRecord::Discovery);
        };
        let JsonValue::Object(triggers) = triggers else {
            return Err(AuthExportError(format!(
                "{subject}.triggers is not an object"
            )));
        };
        if discovery.contains(event) {
            if triggers.contains_key(event) {
                return Err(AuthExportError(format!(
                    "{subject}.{BLOCKING_DISCOVERY_EVENTS_MEMBER} conflicts with triggers.{event}"
                )));
            }
            return Ok(BlockingAuthSelectionRecord::Discovery);
        }
        let Some(entry) = triggers.get(event) else {
            return Ok(BlockingAuthSelectionRecord::Disabled);
        };
        if matches!(entry, JsonValue::Null) {
            return Ok(BlockingAuthSelectionRecord::Disabled);
        }
        reject_unknown(
            entry,
            &["functionUri"],
            &format!("{subject}.triggers.{event}"),
        )?;
        let uri = entry
            .get("functionUri")
            .and_then(JsonValue::as_str)
            .filter(|uri| !uri.is_empty())
            .ok_or_else(|| {
                AuthExportError(format!("{subject}.triggers.{event}.functionUri is missing"))
            })?;
        Ok(BlockingAuthSelectionRecord::Explicit {
            function_uri: uri.to_owned(),
        })
    };
    let forwarding = match value.get("forwardInboundCredentials") {
        None | Some(JsonValue::Null) => None,
        Some(forwarding) => {
            reject_unknown(
                forwarding,
                &["idToken", "accessToken", "refreshToken"],
                &format!("{subject}.forwardInboundCredentials"),
            )?;
            let boolean = |key: &str| {
                forwarding
                    .get(key)
                    .and_then(JsonValue::as_bool)
                    .ok_or_else(|| {
                        AuthExportError(format!(
                            "{subject}.forwardInboundCredentials.{key} is not a boolean"
                        ))
                    })
            };
            Some(BlockingAuthForwardingRecord {
                id_token: boolean("idToken")?,
                access_token: boolean("accessToken")?,
                refresh_token: boolean("refreshToken")?,
            })
        }
    };
    Ok(BlockingAuthSettingsRecord {
        before_create: selection("beforeCreate")?,
        before_sign_in: selection("beforeSignIn")?,
        forwarding,
    })
}

fn parse_quota_settings(
    value: &JsonValue,
    subject: &str,
) -> Result<QuotaSettingsRecord, AuthExportError> {
    reject_unknown(value, &KNOWN_QUOTA_MEMBERS, subject)?;
    let string = |key: &str| {
        value
            .get(key)
            .and_then(JsonValue::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AuthExportError(format!("{subject} has no non-empty {key}")))
            .map(ToOwned::to_owned)
    };
    let integer = |key: &str| {
        value
            .get(key)
            .and_then(JsonValue::as_i64)
            .ok_or_else(|| AuthExportError(format!("{subject} has no integer {key}")))
    };
    let temporary = match value.get("temporary") {
        None | Some(JsonValue::Null) => None,
        Some(value) => {
            reject_unknown(
                value,
                &KNOWN_TEMPORARY_QUOTA_MEMBERS,
                &format!("{subject}.temporary"),
            )?;
            let quota = value
                .get("quota")
                .and_then(JsonValue::as_i64)
                .filter(|quota| *quota >= 0)
                .ok_or_else(|| AuthExportError(format!("{subject}.temporary.quota is invalid")))?;
            let start_time = value
                .get("startTime")
                .and_then(JsonValue::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    AuthExportError(format!("{subject}.temporary.startTime is invalid"))
                })?
                .to_owned();
            let quota_duration = value
                .get("quotaDuration")
                .and_then(JsonValue::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    AuthExportError(format!("{subject}.temporary.quotaDuration is invalid"))
                })?
                .to_owned();
            Some(TemporaryQuotaRecord {
                quota,
                start_time,
                quota_duration,
            })
        }
    };
    Ok(QuotaSettingsRecord {
        mode: string("mode")?,
        algorithm: string("algorithm")?,
        default_quota_per_hour: integer("defaultQuotaPerHour")?,
        max_tracked_buckets: integer("maxTrackedBuckets")?,
        temporary,
    })
}

fn write_auth_settings_record(settings: &AuthSettingsRecord) -> Json {
    let mut doc = Json::object();
    doc.insert_some(
        "config",
        settings.config.as_ref().map(|config| {
            Json::from_value(&parse(&config.to_json()).expect("AuthConfig writer emits JSON"))
        }),
    );
    doc.insert_some("quota", settings.quota.as_ref().map(write_quota_settings));
    doc.insert_some(
        "blocking",
        settings.blocking.as_ref().map(write_blocking_settings),
    );
    doc
}

fn write_tenant_metadata(metadata: &TenantMetadataRecord) -> Json {
    let mut doc = Json::object();
    doc.insert_some(
        "displayName",
        metadata.display_name.as_ref().map(Json::string),
    );
    doc.insert(
        "allowPasswordSignup",
        Json::Bool(metadata.allow_password_signup),
    );
    doc.insert(
        "enableEmailLinkSignin",
        Json::Bool(metadata.enable_email_link_signin),
    );
    doc.insert(
        "enableAnonymousUser",
        Json::Bool(metadata.enable_anonymous_user),
    );
    doc.insert("disableAuth", Json::Bool(metadata.disable_auth));
    doc.insert(
        "disabledUserSignup",
        Json::Bool(metadata.disabled_user_signup),
    );
    doc.insert(
        "disabledUserDeletion",
        Json::Bool(metadata.disabled_user_deletion),
    );
    doc.insert(
        "enableImprovedEmailPrivacy",
        Json::Bool(metadata.enable_improved_email_privacy),
    );
    doc
}

fn write_blocking_settings(settings: &BlockingAuthSettingsRecord) -> Json {
    let mut doc = Json::object();
    let mut triggers = Json::object();
    let mut discovery = Vec::new();
    let mut has_trigger = false;
    let mut write_selection = |name: &str, selection: &BlockingAuthSelectionRecord| match selection
    {
        BlockingAuthSelectionRecord::Discovery => {
            discovery.push(Json::string(name));
        }
        BlockingAuthSelectionRecord::Disabled => {
            triggers.insert(name, Json::Null);
            has_trigger = true;
        }
        BlockingAuthSelectionRecord::Explicit { function_uri } => {
            let mut value = Json::object();
            value.insert("functionUri", Json::string(function_uri));
            triggers.insert(name, value);
            has_trigger = true;
        }
    };
    write_selection("beforeCreate", &settings.before_create);
    write_selection("beforeSignIn", &settings.before_sign_in);
    if has_trigger {
        doc.insert("triggers", triggers);
        if !discovery.is_empty() {
            doc.insert(BLOCKING_DISCOVERY_EVENTS_MEMBER, Json::Array(discovery));
        }
    }
    if let Some(forwarding) = settings.forwarding {
        let mut value = Json::object();
        value.insert("idToken", Json::Bool(forwarding.id_token));
        value.insert("accessToken", Json::Bool(forwarding.access_token));
        value.insert("refreshToken", Json::Bool(forwarding.refresh_token));
        doc.insert("forwardInboundCredentials", value);
    }
    doc
}

fn write_quota_settings(settings: &QuotaSettingsRecord) -> Json {
    let mut doc = Json::object();
    doc.insert("mode", Json::string(&settings.mode));
    doc.insert("algorithm", Json::string(&settings.algorithm));
    doc.insert(
        "defaultQuotaPerHour",
        Json::Int(settings.default_quota_per_hour),
    );
    doc.insert("maxTrackedBuckets", Json::Int(settings.max_tracked_buckets));
    doc.insert_some(
        "temporary",
        settings.temporary.as_ref().map(|temporary| {
            let mut value = Json::object();
            value.insert("quota", Json::Int(temporary.quota));
            value.insert("startTime", Json::string(&temporary.start_time));
            value.insert("quotaDuration", Json::string(&temporary.quota_duration));
            value
        }),
    );
    doc
}

fn parse_password_policy(
    value: &JsonValue,
    subject: &str,
) -> Result<PasswordPolicyRecord, AuthExportError> {
    reject_unknown(value, &KNOWN_PASSWORD_POLICY_MEMBERS, subject)?;
    let enforcement_state = value
        .get("enforcementState")
        .and_then(JsonValue::as_str)
        .filter(|value| matches!(*value, "OFF" | "ENFORCE"))
        .ok_or_else(|| AuthExportError(format!("{subject} has an invalid enforcementState")))?
        .to_owned();
    let force_upgrade_on_signin = value
        .get("forceUpgradeOnSignin")
        .and_then(JsonValue::as_bool)
        .ok_or_else(|| AuthExportError(format!("{subject} has no boolean forceUpgradeOnSignin")))?;
    let min_length = value
        .get("minLength")
        .and_then(JsonValue::as_i64)
        .filter(|value| (6..=30).contains(value))
        .ok_or_else(|| AuthExportError(format!("{subject} has an invalid minLength")))?;
    let max_length = match value.get("maxLength") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::Int(value)) if (min_length..=4096).contains(value) => Some(*value),
        Some(_) => return refuse(format!("{subject} has an invalid maxLength")),
    };
    let boolean = |key: &str| {
        value
            .get(key)
            .and_then(JsonValue::as_bool)
            .ok_or_else(|| AuthExportError(format!("{subject} has no boolean {key}")))
    };
    let allowed_non_alphanumeric_characters = match value.get("allowedNonAlphanumericCharacters") {
        None => default_allowed_non_alphanumeric_characters(),
        Some(JsonValue::Array(values)) => {
            let mut allowed = BTreeSet::new();
            for item in values {
                let character = item
                    .as_str()
                    .and_then(|text| {
                        let mut chars = text.chars();
                        let character = chars.next()?;
                        chars.next().is_none().then_some(character)
                    })
                    .filter(|character| {
                        character.is_ascii()
                            && !character.is_ascii_alphanumeric()
                            && !character.is_control()
                    })
                    .ok_or_else(|| {
                        AuthExportError(format!(
                            "{subject} has an invalid allowedNonAlphanumericCharacters entry"
                        ))
                    })?;
                allowed.insert(character);
            }
            allowed
        }
        Some(_) => {
            return refuse(format!(
                "{subject} allowedNonAlphanumericCharacters is not an array"
            ))
        }
    };
    Ok(PasswordPolicyRecord {
        enforcement_state,
        force_upgrade_on_signin,
        min_length,
        max_length,
        require_uppercase: boolean("requireUppercase")?,
        require_lowercase: boolean("requireLowercase")?,
        require_numeric: boolean("requireNumeric")?,
        require_non_alphanumeric: boolean("requireNonAlphanumeric")?,
        allowed_non_alphanumeric_characters,
    })
}

fn default_allowed_non_alphanumeric_characters() -> BTreeSet<char> {
    "~!@#$%^&*_-+=[]{}|\\:;'<>,.?/`\"()".chars().collect()
}

fn write_password_policy(policy: &PasswordPolicyRecord) -> Json {
    let mut doc = Json::object();
    doc.insert("enforcementState", Json::string(&policy.enforcement_state));
    doc.insert(
        "forceUpgradeOnSignin",
        Json::Bool(policy.force_upgrade_on_signin),
    );
    doc.insert("minLength", Json::Int(policy.min_length));
    doc.insert_some("maxLength", policy.max_length.map(Json::Int));
    doc.insert("requireUppercase", Json::Bool(policy.require_uppercase));
    doc.insert("requireLowercase", Json::Bool(policy.require_lowercase));
    doc.insert("requireNumeric", Json::Bool(policy.require_numeric));
    doc.insert(
        "requireNonAlphanumeric",
        Json::Bool(policy.require_non_alphanumeric),
    );
    doc.insert(
        "allowedNonAlphanumericCharacters",
        Json::Array(
            policy
                .allowed_non_alphanumeric_characters
                .iter()
                .map(|character| Json::string(character.to_string()))
                .collect(),
        ),
    );
    doc
}

/// Why an Auth document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthExportError(pub String);

impl core::fmt::Display for AuthExportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AuthExportError {}

fn refuse<T>(message: impl Into<String>) -> Result<T, AuthExportError> {
    Err(AuthExportError(message.into()))
}

/// One entry of `providerUserInfo`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderUserInfo {
    /// `password`, `phone`, `google.com`, ...
    pub provider_id: String,
    /// The identifier at the provider.
    pub raw_id: String,
    /// The federated identifier, when the provider has one.
    pub federated_id: Option<String>,
    /// The email at the provider.
    pub email: Option<String>,
    /// The display name at the provider.
    pub display_name: Option<String>,
    /// The photo URL at the provider.
    pub photo_url: Option<String>,
    /// The phone number, for the `phone` provider.
    pub phone_number: Option<String>,
    /// The screen name, for providers that have one.
    pub screen_name: Option<String>,
}

/// One entry of `mfaInfo`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MfaEnrollment {
    /// The enrollment identifier.
    pub mfa_enrollment_id: String,
    /// The label the account gave the factor.
    pub display_name: Option<String>,
    /// The phone number, possibly obfuscated.
    pub phone_info: Option<String>,
    /// The phone number in full (output only in the API, always written by the emulator).
    pub unobfuscated_phone_info: Option<String>,
    /// When the factor was enrolled, RFC 3339.
    pub enrolled_at: Option<String>,
    /// The TOTP shared secret. The official Auth emulator has no TOTP second factor at all,
    /// so this is fireemu's own extension: the member is written only for an account that
    /// really has one, and an official import ignores what it does not know.
    pub totp_shared_secret_key: Option<String>,
}

impl MfaEnrollment {
    /// Whether the enrollment is a TOTP factor.
    #[must_use]
    pub fn is_totp(&self) -> bool {
        self.totp_shared_secret_key.is_some()
    }
}

/// One account of `accounts.json`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UserRecord {
    /// The account identifier.
    pub local_id: String,
    /// The account's email address.
    pub email: Option<String>,
    /// Whether the email address is verified.
    pub email_verified: bool,
    /// The display name.
    pub display_name: Option<String>,
    /// The photo URL (`photoUrl`, not `photoURL`).
    pub photo_url: Option<String>,
    /// The phone number.
    pub phone_number: Option<String>,
    /// Whether the account is disabled.
    pub disabled: bool,
    /// Whether this password-shaped provider is an email-link sign-in account.
    pub email_link_signin: bool,
    /// The stored password hash.
    pub password_hash: Option<String>,
    /// The salt the hash was produced with.
    pub salt: Option<String>,
    /// When the password was last set, in milliseconds since the epoch.
    pub password_updated_at: Option<f64>,
    /// Tokens minted before this second are refused, as a decimal string of seconds.
    pub valid_since: Option<String>,
    /// When the account was created, in milliseconds since the epoch, as a decimal string.
    pub created_at: Option<String>,
    /// When the account last signed in, in milliseconds since the epoch, as a string.
    pub last_login_at: Option<String>,
    /// When an ID token was last minted, RFC 3339.
    pub last_refresh_at: Option<String>,
    /// The custom claims, as the JSON text the API carries them in.
    pub custom_attributes: Option<String>,
    /// The tenant the account belongs to, when it is not the default one.
    pub tenant_id: Option<String>,
    /// The account's linked providers.
    pub provider_user_info: Vec<ProviderUserInfo>,
    /// The account's second factors.
    pub mfa_info: Vec<MfaEnrollment>,
    /// Members this crate does not model, kept so an import cannot lose them.
    pub extra: Vec<(String, Json)>,
}

/// A parsed `accounts.json` (or `accounts-<tenant>.json`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AccountsFile {
    /// The accounts, in file order.
    pub users: Vec<UserRecord>,
}

/// A parsed `config.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthConfig {
    /// `signIn.allowDuplicateEmails`; `None` when the artifact does not declare it, so an
    /// import keeps the running namespace setting instead of silently applying the default.
    pub allow_duplicate_emails: Option<bool>,
    /// `emailPrivacyConfig.enableImprovedEmailPrivacy`; `None` when the artifact does not
    /// declare it, so an import keeps the running configuration instead of switching the
    /// protection off.
    pub enable_improved_email_privacy: Option<bool>,
    /// `client.permissions.disabledUserSignup`; `None` when the artifact does not declare it.
    pub disabled_user_signup: Option<bool>,
    /// `client.permissions.disabledUserDeletion`; `None` when the artifact does not declare it.
    pub disabled_user_deletion: Option<bool>,
}

impl AuthConfig {
    /// Parses `config.json`.
    pub fn parse(text: &str) -> Result<Self, AuthExportError> {
        let value = parse(text).map_err(|e| AuthExportError(e.to_string()))?;
        if !matches!(value, JsonValue::Object(_)) {
            return refuse("the Auth config document is not a JSON object");
        }
        reject_unknown(&value, &KNOWN_CONFIG_MEMBERS, "Auth config")?;
        if let Some(sign_in) = value.get("signIn") {
            reject_unknown(sign_in, &KNOWN_SIGN_IN_MEMBERS, "Auth config signIn")?;
        }
        if let Some(privacy) = value.get("emailPrivacyConfig") {
            reject_unknown(
                privacy,
                &KNOWN_PRIVACY_MEMBERS,
                "Auth config emailPrivacyConfig",
            )?;
        }
        if let Some(client) = value.get("client") {
            reject_unknown(client, &KNOWN_CLIENT_MEMBERS, "Auth config client")?;
            if let Some(permissions) = client.get("permissions") {
                reject_unknown(
                    permissions,
                    &KNOWN_PERMISSION_MEMBERS,
                    "Auth config client.permissions",
                )?;
            }
        }
        Ok(Self {
            allow_duplicate_emails: bool_member(&value, "signIn", "allowDuplicateEmails")?,
            enable_improved_email_privacy: bool_member(
                &value,
                "emailPrivacyConfig",
                "enableImprovedEmailPrivacy",
            )?,
            disabled_user_signup: nested_bool_member(
                &value,
                &["client", "permissions"],
                "disabledUserSignup",
            )?,
            disabled_user_deletion: nested_bool_member(
                &value,
                &["client", "permissions"],
                "disabledUserDeletion",
            )?,
        })
    }

    /// Writes `config.json`, in the shape the emulator's config route answers with.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut doc = Json::object();
        if let Some(allow_duplicate_emails) = self.allow_duplicate_emails {
            let mut sign_in = Json::object();
            sign_in.insert("allowDuplicateEmails", Json::Bool(allow_duplicate_emails));
            doc.insert("signIn", sign_in);
        }
        // An undeclared setting stays undeclared: writing `false` would switch the protection
        // off on the next import.
        if let Some(enabled) = self.enable_improved_email_privacy {
            let mut privacy = Json::object();
            privacy.insert("enableImprovedEmailPrivacy", Json::Bool(enabled));
            doc.insert("emailPrivacyConfig", privacy);
        }
        if self.disabled_user_signup.is_some() || self.disabled_user_deletion.is_some() {
            let mut permissions = Json::object();
            permissions.insert_some(
                "disabledUserSignup",
                self.disabled_user_signup.map(Json::Bool),
            );
            permissions.insert_some(
                "disabledUserDeletion",
                self.disabled_user_deletion.map(Json::Bool),
            );
            let mut client = Json::object();
            client.insert("permissions", permissions);
            doc.insert("client", client);
        }
        doc.to_pretty()
    }
}

/// The members [`UserRecord`] models; anything else lands in [`UserRecord::extra`].
const KNOWN_USER_MEMBERS: [&str; 19] = [
    "localId",
    "email",
    "emailVerified",
    "displayName",
    "photoUrl",
    "phoneNumber",
    "disabled",
    "emailLinkSignin",
    "passwordHash",
    "salt",
    "passwordUpdatedAt",
    "validSince",
    "createdAt",
    "lastLoginAt",
    "lastRefreshAt",
    "customAttributes",
    "tenantId",
    "providerUserInfo",
    "mfaInfo",
];

impl AccountsFile {
    /// Parses an accounts document.
    pub fn parse(text: &str) -> Result<Self, AuthExportError> {
        let value = parse(text).map_err(|e| AuthExportError(e.to_string()))?;
        if !matches!(value, JsonValue::Object(_)) {
            return refuse("the Auth accounts document is not a JSON object");
        }
        let users = match value.get("users") {
            None => Vec::new(),
            Some(JsonValue::Array(items)) => {
                let mut users = Vec::with_capacity(items.len());
                for item in items {
                    users.push(parse_user(item)?);
                }
                users
            }
            Some(_) => return refuse("\"users\" in the Auth accounts document is not an array"),
        };
        Ok(Self { users })
    }

    /// Writes an accounts document in the Identity Toolkit shape.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut doc = Json::object();
        doc.insert("kind", Json::string(DOWNLOAD_KIND));
        doc.insert(
            "users",
            Json::Array(self.users.iter().map(write_user).collect()),
        );
        doc.to_pretty()
    }
}

fn parse_user(value: &JsonValue) -> Result<UserRecord, AuthExportError> {
    let JsonValue::Object(members) = value else {
        return refuse("an account in the Auth accounts document is not an object");
    };
    let local_id = value
        .get("localId")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| AuthExportError("an account has no string \"localId\"".to_owned()))?
        .to_owned();
    let mut provider_user_info = Vec::new();
    if value
        .get("providerUserInfo")
        .is_some_and(|v| !matches!(v, JsonValue::Array(_)))
    {
        return refuse(format!(
            "the providerUserInfo member of account {local_id:?} is not an array"
        ));
    }
    if let Some(JsonValue::Array(items)) = value.get("providerUserInfo") {
        for item in items {
            provider_user_info.push(parse_provider(&local_id, item)?);
        }
    }
    let mut mfa_info = Vec::new();
    if value
        .get("mfaInfo")
        .is_some_and(|v| !matches!(v, JsonValue::Array(_)))
    {
        return refuse(format!(
            "the mfaInfo member of account {local_id:?} is not an array"
        ));
    }
    if let Some(JsonValue::Array(items)) = value.get("mfaInfo") {
        for item in items {
            mfa_info.push(parse_enrollment(&local_id, item)?);
        }
    }
    let extra = members
        .iter()
        .filter(|(k, _)| !KNOWN_USER_MEMBERS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), Json::from_value(v)))
        .collect();
    Ok(UserRecord {
        local_id,
        email: string_member(value, "email")?,
        email_verified: bool_member(value, "", "emailVerified")?.unwrap_or(false),
        display_name: string_member(value, "displayName")?,
        photo_url: string_member(value, "photoUrl")?,
        phone_number: string_member(value, "phoneNumber")?,
        disabled: bool_member(value, "", "disabled")?.unwrap_or(false),
        email_link_signin: bool_member(value, "", "emailLinkSignin")?.unwrap_or(false),
        password_hash: string_member(value, "passwordHash")?,
        salt: string_member(value, "salt")?,
        password_updated_at: number_member(value, "passwordUpdatedAt")?,
        valid_since: string_member(value, "validSince")?,
        created_at: string_member(value, "createdAt")?,
        last_login_at: string_member(value, "lastLoginAt")?,
        last_refresh_at: string_member(value, "lastRefreshAt")?,
        custom_attributes: string_member(value, "customAttributes")?,
        tenant_id: string_member(value, "tenantId")?,
        provider_user_info,
        mfa_info,
        extra,
    })
}

fn parse_provider(local_id: &str, value: &JsonValue) -> Result<ProviderUserInfo, AuthExportError> {
    if !matches!(value, JsonValue::Object(_)) {
        return refuse(format!(
            "a providerUserInfo entry of the account {local_id:?} is not an object"
        ));
    }
    reject_unknown(value, &KNOWN_PROVIDER_MEMBERS, "providerUserInfo entry")?;
    let provider_id = value
        .get("providerId")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            AuthExportError(format!(
                "a providerUserInfo entry of the account {local_id:?} has no \"providerId\""
            ))
        })?
        .to_owned();
    Ok(ProviderUserInfo {
        provider_id,
        raw_id: string_member(value, "rawId")?.unwrap_or_default(),
        federated_id: string_member(value, "federatedId")?,
        email: string_member(value, "email")?,
        display_name: string_member(value, "displayName")?,
        photo_url: string_member(value, "photoUrl")?,
        phone_number: string_member(value, "phoneNumber")?,
        screen_name: string_member(value, "screenName")?,
    })
}

fn parse_enrollment(local_id: &str, value: &JsonValue) -> Result<MfaEnrollment, AuthExportError> {
    if !matches!(value, JsonValue::Object(_)) {
        return refuse(format!(
            "an mfaInfo entry of the account {local_id:?} is not an object"
        ));
    }
    reject_unknown(value, &KNOWN_MFA_MEMBERS, "mfaInfo entry")?;
    Ok(MfaEnrollment {
        mfa_enrollment_id: string_member(value, "mfaEnrollmentId")?.unwrap_or_default(),
        display_name: string_member(value, "displayName")?,
        phone_info: string_member(value, "phoneInfo")?,
        unobfuscated_phone_info: string_member(value, "unobfuscatedPhoneInfo")?,
        enrolled_at: string_member(value, "enrolledAt")?,
        totp_shared_secret_key: match value.get("totpInfo") {
            None => None,
            Some(JsonValue::Object(_)) => {
                let totp = value.get("totpInfo").unwrap();
                reject_unknown(totp, &KNOWN_TOTP_MEMBERS, "mfaInfo.totpInfo")?;
                string_member(totp, "sharedSecretKey")?
            }
            Some(_) => {
                return refuse(format!(
                    "the totpInfo member of account {local_id:?} is not an object"
                ))
            }
        },
    })
}

fn reject_unknown(value: &JsonValue, known: &[&str], subject: &str) -> Result<(), AuthExportError> {
    let JsonValue::Object(members) = value else {
        return refuse(format!("the {subject} is not an object"));
    };
    if let Some((key, _)) = members
        .iter()
        .find(|(key, _)| !known.contains(&key.as_str()))
    {
        return refuse(format!("the {subject} contains unsupported member {key:?}"));
    }
    Ok(())
}

fn string_member(value: &JsonValue, key: &str) -> Result<Option<String>, AuthExportError> {
    match value.get(key) {
        None => Ok(None),
        Some(JsonValue::String(s)) => Ok(Some(s.clone())),
        Some(_) => refuse(format!("the Auth account member {key:?} is not a string")),
    }
}

fn number_member(value: &JsonValue, key: &str) -> Result<Option<f64>, AuthExportError> {
    match value.get(key) {
        // A millisecond timestamp is far inside the exactly representable range, so the
        // widening never rounds in practice; a hypothetical larger one is only ever written
        // back out again.
        #[allow(clippy::cast_precision_loss)]
        Some(JsonValue::Int(i)) => Ok(Some(*i as f64)),
        Some(JsonValue::Float(f)) => Ok(Some(*f)),
        None => Ok(None),
        Some(_) => refuse(format!("the Auth account member {key:?} is not a number")),
    }
}

fn bool_member(
    value: &JsonValue,
    parent: &str,
    key: &str,
) -> Result<Option<bool>, AuthExportError> {
    let Some(container) = (if parent.is_empty() {
        Some(value)
    } else {
        value.get(parent)
    }) else {
        return Ok(None);
    };
    if !matches!(container, JsonValue::Object(_)) {
        return refuse(format!(
            "the Auth config member {parent:?} is not an object"
        ));
    }
    let Some(member) = container.get(key) else {
        return Ok(None);
    };
    match member {
        JsonValue::Bool(value) => Ok(Some(*value)),
        _ => refuse(format!(
            "the Auth config/account member {key:?} is not a boolean"
        )),
    }
}

fn nested_bool_member(
    value: &JsonValue,
    parents: &[&str],
    key: &str,
) -> Result<Option<bool>, AuthExportError> {
    let mut current = value;
    for parent in parents {
        let Some(next) = current.get(parent) else {
            return Ok(None);
        };
        if !matches!(next, JsonValue::Object(_)) {
            return refuse(format!(
                "the Auth config member {parent:?} is not an object"
            ));
        }
        current = next;
    }
    match current.get(key) {
        None => Ok(None),
        Some(JsonValue::Bool(value)) => Ok(Some(*value)),
        Some(_) => refuse(format!(
            "the Auth config/account member {key:?} is not a boolean"
        )),
    }
}

fn write_user(user: &UserRecord) -> Json {
    let mut doc = Json::object();
    doc.insert("localId", Json::string(&user.local_id));
    doc.insert_some("email", user.email.as_ref().map(Json::string));
    doc.insert("emailVerified", Json::Bool(user.email_verified));
    doc.insert_some("displayName", user.display_name.as_ref().map(Json::string));
    doc.insert_some("photoUrl", user.photo_url.as_ref().map(Json::string));
    doc.insert_some("phoneNumber", user.phone_number.as_ref().map(Json::string));
    doc.insert("disabled", Json::Bool(user.disabled));
    if user.email_link_signin {
        doc.insert("emailLinkSignin", Json::Bool(true));
    }
    doc.insert_some(
        "passwordHash",
        user.password_hash.as_ref().map(Json::string),
    );
    doc.insert_some("salt", user.salt.as_ref().map(Json::string));
    doc.insert_some(
        "passwordUpdatedAt",
        user.password_updated_at.map(write_millis),
    );
    doc.insert_some("validSince", user.valid_since.as_ref().map(Json::string));
    doc.insert_some("createdAt", user.created_at.as_ref().map(Json::string));
    doc.insert_some("lastLoginAt", user.last_login_at.as_ref().map(Json::string));
    doc.insert_some(
        "lastRefreshAt",
        user.last_refresh_at.as_ref().map(Json::string),
    );
    doc.insert_some(
        "customAttributes",
        user.custom_attributes.as_ref().map(Json::string),
    );
    doc.insert_some("tenantId", user.tenant_id.as_ref().map(Json::string));
    if !user.provider_user_info.is_empty() {
        doc.insert(
            "providerUserInfo",
            Json::Array(user.provider_user_info.iter().map(write_provider).collect()),
        );
    }
    if !user.mfa_info.is_empty() {
        doc.insert(
            "mfaInfo",
            Json::Array(user.mfa_info.iter().map(write_enrollment).collect()),
        );
    }
    for (key, value) in &user.extra {
        doc.insert(key.clone(), value.clone());
    }
    doc
}

/// Milliseconds since the epoch, written without a fraction when there is none: the official
/// emulator writes `passwordUpdatedAt` as a whole number.
fn write_millis(value: f64) -> Json {
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 9.007_199_254_740_992e15 {
        // Guarded above: finite, whole and inside the exactly representable range.
        #[allow(clippy::cast_possible_truncation)]
        return Json::Int(value as i64);
    }
    Json::Float(value)
}

fn write_provider(provider: &ProviderUserInfo) -> Json {
    let mut doc = Json::object();
    doc.insert("providerId", Json::string(&provider.provider_id));
    doc.insert("rawId", Json::string(&provider.raw_id));
    doc.insert_some(
        "federatedId",
        provider.federated_id.as_ref().map(Json::string),
    );
    doc.insert_some("email", provider.email.as_ref().map(Json::string));
    doc.insert_some(
        "displayName",
        provider.display_name.as_ref().map(Json::string),
    );
    doc.insert_some("photoUrl", provider.photo_url.as_ref().map(Json::string));
    doc.insert_some(
        "phoneNumber",
        provider.phone_number.as_ref().map(Json::string),
    );
    doc.insert_some(
        "screenName",
        provider.screen_name.as_ref().map(Json::string),
    );
    doc
}

fn write_enrollment(enrollment: &MfaEnrollment) -> Json {
    let mut doc = Json::object();
    doc.insert(
        "mfaEnrollmentId",
        Json::string(&enrollment.mfa_enrollment_id),
    );
    doc.insert_some(
        "displayName",
        enrollment.display_name.as_ref().map(Json::string),
    );
    doc.insert_some(
        "phoneInfo",
        enrollment.phone_info.as_ref().map(Json::string),
    );
    doc.insert_some(
        "unobfuscatedPhoneInfo",
        enrollment
            .unobfuscated_phone_info
            .as_ref()
            .map(Json::string),
    );
    doc.insert_some(
        "enrolledAt",
        enrollment.enrolled_at.as_ref().map(Json::string),
    );
    if let Some(secret) = &enrollment.totp_shared_secret_key {
        let mut totp = Json::object();
        totp.insert("sharedSecretKey", Json::string(secret));
        doc.insert("totpInfo", totp);
    }
    doc
}

/// The emulator's reversible password hash convention.
///
/// The Auth emulator never hashes anything: it stores
/// `fakeHash:salt=<salt>:password=<plaintext>` with a `fakeSalt<random>` salt, so that a
/// sign-in can compare the plaintext. An export therefore carries the passwords themselves.
/// fireemu reads and writes the same convention, so a fixture recorded with the official
/// suite signs in against fireemu with the passwords it was seeded with, and the other way
/// round.
pub mod fake_hash {
    /// The prefix of every hash the emulator writes.
    pub const HASH_PREFIX: &str = "fakeHash:salt=";
    /// The prefix of every salt the emulator generates.
    pub const SALT_PREFIX: &str = "fakeSalt";

    /// The hash string for `salt` and `password`.
    #[must_use]
    pub fn encode(salt: &str, password: &str) -> String {
        format!("{HASH_PREFIX}{salt}:password={password}")
    }

    /// The salt and plaintext a hash carries, when it uses the convention.
    #[must_use]
    pub fn decode(hash: &str) -> Option<(String, String)> {
        let rest = hash.strip_prefix(HASH_PREFIX)?;
        let (salt, password) = rest.split_once(":password=")?;
        // The convention has no escaping: a salt holding a colon is ambiguous, so it is
        // refused rather than split at a guessed place.
        if salt.contains(':') {
            return None;
        }
        Some((salt.to_owned(), password.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        fake_hash, AccountsFile, AuthConfig, AuthSettings, AuthSettingsNamespace,
        AuthSettingsRecord, BlockingAuthForwardingRecord, BlockingAuthSelectionRecord,
        BlockingAuthSettingsRecord, MfaEnrollment, PasswordPolicies, PasswordPolicyNamespace,
        PasswordPolicyRecord, ProviderUserInfo, QuotaSettingsRecord, TemporaryQuotaRecord,
        TenantMetadataRecord, UserRecord,
    };
    use std::collections::BTreeSet;

    const OFFICIAL: &str = r#"{
      "kind": "identitytoolkit#DownloadAccountResponse",
      "users": [
        {
          "localId": "user-mfa",
          "lastLoginAt": "1788105513121",
          "emailVerified": true,
          "phoneNumber": "+15555550101",
          "email": "dave@example.com",
          "salt": "fakeSalt3lKZOy2WtiItaZiMH5ag",
          "passwordHash": "fakeHash:salt=fakeSalt3lKZOy2WtiItaZiMH5ag:password=mfa-password",
          "passwordUpdatedAt": 1788105513121,
          "validSince": "1788105513",
          "mfaInfo": [
            {
              "displayName": "personal phone",
              "phoneInfo": "+15555550102",
              "mfaEnrollmentId": "Ems7pfXzwMzGndKOP1ji3FiKlm2m",
              "unobfuscatedPhoneInfo": "+15555550102"
            }
          ],
          "createdAt": "1788105513121",
          "providerUserInfo": [
            {
              "providerId": "password",
              "email": "dave@example.com",
              "federatedId": "dave@example.com",
              "rawId": "dave@example.com"
            },
            { "providerId": "phone", "phoneNumber": "+15555550101", "rawId": "+15555550101" }
          ],
          "customAttributes": "{\"role\":\"admin\"}",
          "somethingNewer": { "kept": true }
        }
      ]
    }"#;

    #[test]
    fn a_recorded_official_account_parses_into_every_modelled_member() {
        let file = AccountsFile::parse(OFFICIAL).expect("the accounts file parses");
        assert_eq!(file.users.len(), 1);
        let user = &file.users[0];
        assert_eq!(user.local_id, "user-mfa");
        assert_eq!(user.email.as_deref(), Some("dave@example.com"));
        assert!(user.email_verified);
        assert!(!user.disabled);
        assert_eq!(user.phone_number.as_deref(), Some("+15555550101"));
        assert_eq!(user.salt.as_deref(), Some("fakeSalt3lKZOy2WtiItaZiMH5ag"));
        assert_eq!(user.password_updated_at, Some(1_788_105_513_121.0));
        assert_eq!(user.created_at.as_deref(), Some("1788105513121"));
        assert_eq!(user.valid_since.as_deref(), Some("1788105513"));
        assert_eq!(
            user.custom_attributes.as_deref(),
            Some(r#"{"role":"admin"}"#)
        );
        assert_eq!(user.provider_user_info.len(), 2);
        assert_eq!(user.provider_user_info[0].provider_id, "password");
        assert_eq!(user.provider_user_info[1].raw_id, "+15555550101");
        assert_eq!(user.mfa_info.len(), 1);
        assert_eq!(
            user.mfa_info[0].mfa_enrollment_id,
            "Ems7pfXzwMzGndKOP1ji3FiKlm2m"
        );
        assert_eq!(
            user.mfa_info[0].unobfuscated_phone_info.as_deref(),
            Some("+15555550102")
        );
        assert!(!user.mfa_info[0].is_totp());
    }

    #[test]
    fn a_member_the_model_does_not_know_survives_the_round_trip() {
        let file = AccountsFile::parse(OFFICIAL).expect("the accounts file parses");
        let again = AccountsFile::parse(&file.to_json()).expect("the written file parses");
        assert_eq!(file, again);
        assert!(file.to_json().contains("somethingNewer"));
    }

    #[test]
    fn a_totp_second_factor_is_written_under_totp_info_and_read_back() {
        let file = AccountsFile {
            users: vec![UserRecord {
                local_id: "u".to_owned(),
                mfa_info: vec![MfaEnrollment {
                    mfa_enrollment_id: "e1".to_owned(),
                    totp_shared_secret_key: Some("JBSWY3DPEHPK3PXP".to_owned()),
                    ..MfaEnrollment::default()
                }],
                ..UserRecord::default()
            }],
        };
        let text = file.to_json();
        assert!(text.contains("\"sharedSecretKey\": \"JBSWY3DPEHPK3PXP\""));
        let again = AccountsFile::parse(&text).expect("the written file parses");
        assert_eq!(again, file);
        assert!(again.users[0].mfa_info[0].is_totp());
    }

    #[test]
    fn a_provider_only_account_round_trips() {
        let file = AccountsFile {
            users: vec![UserRecord {
                local_id: "user-federated".to_owned(),
                email: Some("carol@example.com".to_owned()),
                email_verified: true,
                provider_user_info: vec![ProviderUserInfo {
                    provider_id: "google.com".to_owned(),
                    raw_id: "google-carol".to_owned(),
                    email: Some("carol@example.com".to_owned()),
                    ..ProviderUserInfo::default()
                }],
                ..UserRecord::default()
            }],
        };
        let again = AccountsFile::parse(&file.to_json()).expect("the written file parses");
        assert_eq!(again, file);
    }

    #[test]
    fn an_email_link_account_preserves_the_explicit_signin_marker() {
        let input = r#"{
          "kind": "identitytoolkit#DownloadAccountResponse",
          "users": [{
            "localId": "user-email-link",
            "email": "link@example.com",
            "emailVerified": true,
            "emailLinkSignin": true,
            "providerUserInfo": [{
              "providerId": "password",
              "rawId": "link@example.com",
              "federatedId": "link@example.com",
              "email": "link@example.com"
            }]
          }]
        }"#;
        let file = AccountsFile::parse(input).expect("the email-link account parses");
        assert!(file.users[0].email_link_signin);
        let written = file.to_json();
        assert!(written.contains("\"emailLinkSignin\": true"));
        assert_eq!(
            AccountsFile::parse(&written).expect("the written file parses"),
            file
        );
    }

    #[test]
    fn an_empty_accounts_file_round_trips() {
        let file = AccountsFile::default();
        let text = file.to_json();
        assert!(text.contains("\"users\": []"));
        assert_eq!(AccountsFile::parse(&text).expect("it parses"), file);
    }

    #[test]
    fn an_account_without_a_local_id_is_refused() {
        assert!(AccountsFile::parse(r#"{"users":[{"email":"a@b.c"}]}"#).is_err());
    }

    #[test]
    fn an_accounts_document_that_is_not_an_object_is_refused() {
        assert!(AccountsFile::parse("[]").is_err());
        assert!(AccountsFile::parse(r#"{"users":{}}"#).is_err());
        assert!(AccountsFile::parse("not json").is_err());
    }

    #[test]
    fn a_provider_entry_without_a_provider_id_is_refused() {
        assert!(
            AccountsFile::parse(r#"{"users":[{"localId":"u","providerUserInfo":[{}]}]}"#).is_err()
        );
    }

    #[test]
    fn unsupported_nested_auth_members_are_refused() {
        assert!(AccountsFile::parse(
            r#"{"users":[{"localId":"u","providerUserInfo":[{"providerId":"google.com","future":true}]}]}"#
        )
        .is_err());
        assert!(AccountsFile::parse(
            r#"{"users":[{"localId":"u","mfaInfo":[{"mfaEnrollmentId":"f","totpInfo":{"future":true}}]}]}"#
        )
        .is_err());
        assert!(
            AuthConfig::parse(r#"{"signIn":{"allowDuplicateEmails":false,"future":true}}"#)
                .is_err()
        );
    }

    #[test]
    fn the_recorded_official_config_parses_and_round_trips() {
        let text = r#"{"signIn":{"allowDuplicateEmails":false},"emailPrivacyConfig":{"enableImprovedEmailPrivacy":false}}"#;
        let config = AuthConfig::parse(text).expect("the config parses");
        assert_eq!(
            config,
            AuthConfig {
                allow_duplicate_emails: Some(false),
                enable_improved_email_privacy: Some(false),
                disabled_user_signup: None,
                disabled_user_deletion: None,
            }
        );
        assert_eq!(
            AuthConfig::parse(&config.to_json()).expect("it parses"),
            config
        );
        let enabled = AuthConfig {
            allow_duplicate_emails: Some(true),
            enable_improved_email_privacy: Some(true),
            disabled_user_signup: None,
            disabled_user_deletion: None,
        };
        assert_eq!(
            AuthConfig::parse(&enabled.to_json()).expect("it parses"),
            enabled
        );
        // An undeclared privacy setting survives a round trip undeclared.
        let undeclared = AuthConfig {
            allow_duplicate_emails: None,
            enable_improved_email_privacy: None,
            disabled_user_signup: None,
            disabled_user_deletion: None,
        };
        assert!(!undeclared.to_json().contains("signIn"));
        assert!(!undeclared.to_json().contains("emailPrivacyConfig"));
        assert_eq!(
            AuthConfig::parse(&undeclared.to_json()).expect("it parses"),
            undeclared
        );
    }

    #[test]
    fn duplicate_email_setting_distinguishes_omitted_from_explicit_false() {
        let omitted = AuthConfig::parse("{}").expect("empty config parses");
        assert_eq!(omitted.allow_duplicate_emails, None);
        assert!(!omitted.to_json().contains("allowDuplicateEmails"));

        let disabled = AuthConfig::parse(r#"{"signIn":{"allowDuplicateEmails":false}}"#)
            .expect("explicit false parses");
        assert_eq!(disabled.allow_duplicate_emails, Some(false));
        assert!(disabled.to_json().contains("allowDuplicateEmails"));
    }

    #[test]
    fn client_permissions_are_optional_and_round_trip_without_affecting_official_config() {
        let config = AuthConfig {
            allow_duplicate_emails: Some(true),
            enable_improved_email_privacy: Some(true),
            disabled_user_signup: Some(true),
            disabled_user_deletion: Some(false),
        };
        let encoded = config.to_json();
        let decoded = AuthConfig::parse(&encoded).expect("client permissions parse");
        assert_eq!(decoded, config);
        assert!(
            AuthConfig::parse(r#"{"client":{"permissions":{"disabledUserSignup":"true"}}}"#)
                .is_err()
        );
        assert!(AuthConfig::parse(r#"{"client":{"permissions":{"future":true}}}"#).is_err());
    }

    #[test]
    fn a_config_document_that_is_not_an_object_is_refused() {
        assert!(AuthConfig::parse("[]").is_err());
    }

    #[test]
    fn fireemu_password_policy_sidecar_round_trips_project_and_tenant_state() {
        let policy = PasswordPolicyRecord {
            enforcement_state: "ENFORCE".to_owned(),
            force_upgrade_on_signin: true,
            min_length: 12,
            max_length: None,
            require_uppercase: true,
            require_lowercase: true,
            require_numeric: true,
            require_non_alphanumeric: true,
            allowed_non_alphanumeric_characters: BTreeSet::from(['!', '@']),
        };
        let policies = PasswordPolicies {
            project_id: "demo-app".to_owned(),
            project: policy.clone(),
            namespaces: vec![PasswordPolicyNamespace {
                tenant_id: Some("tenant-a".to_owned()),
                policy,
            }],
        };
        let encoded = policies.to_json();
        assert_eq!(PasswordPolicies::parse(&encoded).unwrap(), policies);
    }

    #[test]
    fn password_policy_sidecar_rejects_duplicate_tenants_and_unknown_members() {
        let policy = r#"{
          "enforcementState":"OFF",
          "forceUpgradeOnSignin":false,
          "minLength":6,
          "requireUppercase":false,
          "requireLowercase":false,
          "requireNumeric":false,
          "requireNonAlphanumeric":false,
          "allowedNonAlphanumericCharacters":["!"]
        }"#;
        let duplicate = format!(
            r#"{{"version":1,"projectId":"demo-app","project":{policy},"namespaces":[{{"tenantId":"a","policy":{policy}}},{{"tenantId":"a","policy":{policy}}}]}}"#
        );
        assert!(PasswordPolicies::parse(&duplicate).is_err());
        let unknown =
            format!(r#"{{"version":1,"projectId":"demo-app","project":{policy},"future":true}}"#);
        assert!(PasswordPolicies::parse(&unknown).is_err());
    }

    #[test]
    fn auth_settings_sidecar_round_trips_namespace_quota_without_usage() {
        let settings = AuthSettings {
            project_id: "demo-app".to_owned(),
            project: AuthSettingsRecord {
                config: None,
                quota: Some(QuotaSettingsRecord {
                    mode: "enforce".to_owned(),
                    algorithm: "fixed-window-v1".to_owned(),
                    default_quota_per_hour: 100,
                    max_tracked_buckets: 4096,
                    temporary: Some(TemporaryQuotaRecord {
                        quota: 200,
                        start_time: "2030-01-01T00:00:00.000Z".to_owned(),
                        quota_duration: "86400s".to_owned(),
                    }),
                }),
                blocking: Some(BlockingAuthSettingsRecord {
                    before_create: BlockingAuthSelectionRecord::Explicit {
                        function_uri: "fireemu://functions/demo-app/us-central1/checkRegistration"
                            .to_owned(),
                    },
                    before_sign_in: BlockingAuthSelectionRecord::Disabled,
                    forwarding: Some(BlockingAuthForwardingRecord {
                        id_token: false,
                        access_token: true,
                        refresh_token: false,
                    }),
                }),
            },
            namespaces: vec![AuthSettingsNamespace {
                tenant_id: Some("tenant-a".to_owned()),
                settings: AuthSettingsRecord {
                    config: Some(AuthConfig {
                        allow_duplicate_emails: Some(false),
                        enable_improved_email_privacy: Some(true),
                        disabled_user_signup: Some(true),
                        disabled_user_deletion: Some(true),
                    }),
                    quota: None,
                    blocking: None,
                },
                config_is_explicit: true,
                metadata: Some(TenantMetadataRecord {
                    display_name: Some("Tenant A".to_owned()),
                    allow_password_signup: false,
                    enable_email_link_signin: true,
                    enable_anonymous_user: false,
                    disable_auth: true,
                    disabled_user_signup: true,
                    disabled_user_deletion: false,
                    enable_improved_email_privacy: true,
                }),
            }],
        };
        let encoded = settings.to_json();
        assert_eq!(
            AuthSettings::parse(&encoded).expect("settings parse"),
            settings
        );
        for forbidden_member in ["passwordHash", "password", "oobCode", "clientSecret"] {
            assert!(
                !encoded.contains(&format!("\"{forbidden_member}\"")),
                "Auth settings sidecar contains sensitive member {forbidden_member}"
            );
        }
        assert!(encoded.contains("fireemu://functions/demo-app/us-central1/checkRegistration"));
        assert!(!encoded.contains("127.0.0.1"));
    }

    #[test]
    fn tenant_metadata_requires_all_boolean_controls_and_preserves_explicit_false() {
        let settings = r#"{
          "version": 1,
          "projectId": "demo-app",
          "project": {},
          "namespaces": [{
            "tenantId": "tenant-a",
            "settings": {},
            "metadata": {
              "displayName": null,
              "allowPasswordSignup": false,
              "enableEmailLinkSignin": false,
              "enableAnonymousUser": true,
              "disableAuth": false,
              "disabledUserSignup": true,
              "disabledUserDeletion": false,
              "enableImprovedEmailPrivacy": true
            }
          }]
        }"#;
        let parsed = AuthSettings::parse(settings).expect("tenant metadata parses");
        let metadata = parsed.namespaces[0]
            .metadata
            .as_ref()
            .expect("metadata is present");
        assert_eq!(metadata.display_name, None);
        assert!(!metadata.allow_password_signup);
        assert!(!metadata.enable_email_link_signin);
        assert!(metadata.enable_anonymous_user);
        assert!(!metadata.disable_auth);
        assert!(metadata.disabled_user_signup);
        assert!(!metadata.disabled_user_deletion);
        assert!(metadata.enable_improved_email_privacy);
        let encoded = parsed.to_json();
        assert!(encoded.contains("\"allowPasswordSignup\": false"));
        assert!(encoded.contains("\"enableEmailLinkSignin\": false"));
        assert!(encoded.contains("\"disableAuth\": false"));
        assert_eq!(AuthSettings::parse(&encoded).unwrap(), parsed);
    }

    #[test]
    fn tenant_metadata_is_optional_for_legacy_settings_artifacts() {
        let settings = AuthSettings::parse(
            r#"{
              "version": 1,
              "projectId": "demo-app",
              "project": {},
              "namespaces": [{"tenantId": "tenant-a", "settings": {}}]
            }"#,
        )
        .expect("legacy settings parse");
        assert_eq!(settings.namespaces[0].metadata, None);
    }

    #[test]
    fn tenant_metadata_rejects_incomplete_or_unknown_members() {
        let missing = r#"{
          "version": 1, "projectId": "demo-app", "project": {},
          "namespaces": [{"tenantId": "tenant-a", "settings": {}, "metadata": {
            "allowPasswordSignup": false,
            "enableEmailLinkSignin": false,
            "enableAnonymousUser": false,
            "disabledUserSignup": false,
            "disabledUserDeletion": false,
            "enableImprovedEmailPrivacy": false
          }}]
        }"#;
        assert!(AuthSettings::parse(missing).is_err());
        let unknown = r#"{
          "version": 1, "projectId": "demo-app", "project": {},
          "namespaces": [{"tenantId": "tenant-a", "settings": {}, "metadata": {
            "displayName": null,
            "allowPasswordSignup": false,
            "enableEmailLinkSignin": false,
            "enableAnonymousUser": false,
            "disableAuth": false,
            "disabledUserSignup": false,
            "disabledUserDeletion": false,
            "enableImprovedEmailPrivacy": false,
            "future": true
          }}]
        }"#;
        assert!(AuthSettings::parse(unknown).is_err());
    }

    #[test]
    fn tenant_metadata_from_another_project_is_refused() {
        let settings = AuthSettings::parse(
            r#"{
              "version": 1,
              "projectId": "source-project",
              "project": {},
              "namespaces": [{
                "tenantId": "tenant-a",
                "settings": {},
                "metadata": {
                  "displayName": null,
                  "allowPasswordSignup": false,
                  "enableEmailLinkSignin": false,
                  "enableAnonymousUser": false,
                  "disableAuth": false,
                  "disabledUserSignup": false,
                  "disabledUserDeletion": false,
                  "enableImprovedEmailPrivacy": false
                }
              }]
            }"#,
        )
        .expect("settings parse");
        assert!(settings
            .validate_tenant_metadata_project("destination-project")
            .is_err());
        assert!(settings
            .validate_tenant_metadata_project("source-project")
            .is_ok());
    }

    #[test]
    fn auth_settings_sidecar_round_trips_mixed_blocking_discovery() {
        let settings = AuthSettings {
            project_id: "demo-app".to_owned(),
            project: AuthSettingsRecord {
                config: None,
                quota: None,
                blocking: Some(BlockingAuthSettingsRecord {
                    before_create: BlockingAuthSelectionRecord::Discovery,
                    before_sign_in: BlockingAuthSelectionRecord::Explicit {
                        function_uri: "fireemu://functions/demo-app/us-central1/checkSignIn"
                            .to_owned(),
                    },
                    forwarding: None,
                }),
            },
            namespaces: Vec::new(),
        };

        let encoded = settings.to_json();
        assert_eq!(
            AuthSettings::parse(&encoded).expect("settings parse"),
            settings
        );
    }

    #[test]
    fn auth_settings_sidecar_distinguishes_absent_triggers_from_absent_events() {
        let discovery = AuthSettings::parse(
            r#"{
              "version": 1,
              "projectId": "demo-app",
              "project": {"blocking": {}}
            }"#,
        )
        .expect("an absent triggers object selects discovery for both events");
        let blocking = discovery.project.blocking.expect("blocking settings");
        assert_eq!(
            blocking.before_create,
            BlockingAuthSelectionRecord::Discovery
        );
        assert_eq!(
            blocking.before_sign_in,
            BlockingAuthSelectionRecord::Discovery
        );

        let disabled = AuthSettings::parse(
            r#"{
              "version": 1,
              "projectId": "demo-app",
              "project": {"blocking": {"triggers": {}}}
            }"#,
        )
        .expect("an empty triggers object disables both events");
        let blocking = disabled.project.blocking.expect("blocking settings");
        assert_eq!(
            blocking.before_create,
            BlockingAuthSelectionRecord::Disabled
        );
        assert_eq!(
            blocking.before_sign_in,
            BlockingAuthSelectionRecord::Disabled
        );
    }

    #[test]
    fn legacy_auth_settings_do_not_promote_effective_tenant_config_to_an_override() {
        let legacy = AuthSettings::parse(
            r#"{
              "version": 1,
              "projectId": "demo-app",
              "project": {},
              "namespaces": [{
                "tenantId": "tenant-a",
                "settings": {"config": {"signIn": {"allowDuplicateEmails": true}}}
              }]
            }"#,
        )
        .expect("legacy settings parse");
        assert!(!legacy.namespaces[0].config_is_explicit);
        assert!(legacy.to_json().contains("\"configExplicit\": false"));
        assert!(AuthSettings::parse(
            r#"{
              "version": 2,
              "projectId": "demo-app",
              "project": {},
              "namespaces": [{"tenantId": "tenant-a", "settings": {}, "configExplicit": true}]
            }"#
        )
        .is_ok());
        assert!(AuthSettings::parse(
            r#"{
              "version": 2,
              "projectId": "demo-app",
              "project": {},
              "namespaces": [{"tenantId": "tenant-a", "settings": {}}]
            }"#
        )
        .is_err());
    }

    #[test]
    fn auth_settings_sidecar_rejects_duplicate_tenants_and_unknown_members() {
        let settings = r#"{
          "version": 1,
          "projectId": "demo-app",
          "project": {},
          "namespaces": [
            {"tenantId": "tenant-a", "settings": {}},
            {"tenantId": "tenant-a", "settings": {}}
          ]
        }"#;
        assert!(AuthSettings::parse(settings).is_err());
        assert!(AuthSettings::parse(
            r#"{"version":1,"projectId":"demo-app","project":{"future":true}}"#
        )
        .is_err());
    }

    #[test]
    fn the_emulator_password_hash_convention_round_trips() {
        let hash = fake_hash::encode("fakeSaltAbc", "s3cret-password");
        assert_eq!(hash, "fakeHash:salt=fakeSaltAbc:password=s3cret-password");
        assert_eq!(
            fake_hash::decode(&hash),
            Some(("fakeSaltAbc".to_owned(), "s3cret-password".to_owned()))
        );
        assert_eq!(fake_hash::decode("scrypt$whatever"), None);
    }
}
