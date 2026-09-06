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
//! [`UserRecord::extra`] and written out again unchanged, so an import followed by an export
//! never silently drops what a newer emulator wrote.
//!
//! # Sensitive material
//!
//! `passwordHash`, `salt`, the MFA enrollments (phone numbers and, for fireemu, TOTP shared
//! secrets) and `customAttributes` are all credentials or personal data. The emulator's own
//! hashes are the reversible `fakeHash:salt=<salt>:password=<plaintext>` convention, so an
//! accounts file is equivalent to a plaintext password list and must never be world
//! readable; `fireemu` writes the whole export directory with owner-only permissions.

use fireemu_core_types::json::{parse, JsonValue};

use crate::json::Json;

/// The file name of the default tenant's accounts.
pub const ACCOUNTS_FILE: &str = "accounts.json";
/// The file name of the project configuration.
pub const CONFIG_FILE: &str = "config.json";
/// The `kind` member the Identity Toolkit answers with.
pub const DOWNLOAD_KIND: &str = "identitytoolkit#DownloadAccountResponse";

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
    /// `signIn.allowDuplicateEmails`.
    pub allow_duplicate_emails: bool,
    /// `emailPrivacyConfig.enableImprovedEmailPrivacy`; `None` when the artifact does not
    /// declare it, so an import keeps the running configuration instead of switching the
    /// protection off.
    pub enable_improved_email_privacy: Option<bool>,
}

impl AuthConfig {
    /// Parses `config.json`.
    pub fn parse(text: &str) -> Result<Self, AuthExportError> {
        let value = parse(text).map_err(|e| AuthExportError(e.to_string()))?;
        if !matches!(value, JsonValue::Object(_)) {
            return refuse("the Auth config document is not a JSON object");
        }
        Ok(Self {
            allow_duplicate_emails: value
                .get("signIn")
                .and_then(|s| s.get("allowDuplicateEmails"))
                .and_then(JsonValue::as_bool)
                .unwrap_or(false),
            enable_improved_email_privacy: value
                .get("emailPrivacyConfig")
                .and_then(|s| s.get("enableImprovedEmailPrivacy"))
                .and_then(JsonValue::as_bool),
        })
    }

    /// Writes `config.json`, in the shape the emulator's config route answers with.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut doc = Json::object();
        let mut sign_in = Json::object();
        sign_in.insert(
            "allowDuplicateEmails",
            Json::Bool(self.allow_duplicate_emails),
        );
        doc.insert("signIn", sign_in);
        // An undeclared setting stays undeclared: writing `false` would switch the protection
        // off on the next import.
        if let Some(enabled) = self.enable_improved_email_privacy {
            let mut privacy = Json::object();
            privacy.insert("enableImprovedEmailPrivacy", Json::Bool(enabled));
            doc.insert("emailPrivacyConfig", privacy);
        }
        doc.to_pretty()
    }
}

/// The members [`UserRecord`] models; anything else lands in [`UserRecord::extra`].
const KNOWN_USER_MEMBERS: [&str; 18] = [
    "localId",
    "email",
    "emailVerified",
    "displayName",
    "photoUrl",
    "phoneNumber",
    "disabled",
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
    if let Some(JsonValue::Array(items)) = value.get("providerUserInfo") {
        for item in items {
            provider_user_info.push(parse_provider(&local_id, item)?);
        }
    }
    let mut mfa_info = Vec::new();
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
        email: string_member(value, "email"),
        email_verified: value
            .get("emailVerified")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false),
        display_name: string_member(value, "displayName"),
        photo_url: string_member(value, "photoUrl"),
        phone_number: string_member(value, "phoneNumber"),
        disabled: value
            .get("disabled")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false),
        password_hash: string_member(value, "passwordHash"),
        salt: string_member(value, "salt"),
        password_updated_at: number_member(value, "passwordUpdatedAt"),
        valid_since: string_member(value, "validSince"),
        created_at: string_member(value, "createdAt"),
        last_login_at: string_member(value, "lastLoginAt"),
        last_refresh_at: string_member(value, "lastRefreshAt"),
        custom_attributes: string_member(value, "customAttributes"),
        tenant_id: string_member(value, "tenantId"),
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
        raw_id: string_member(value, "rawId").unwrap_or_default(),
        federated_id: string_member(value, "federatedId"),
        email: string_member(value, "email"),
        display_name: string_member(value, "displayName"),
        photo_url: string_member(value, "photoUrl"),
        phone_number: string_member(value, "phoneNumber"),
        screen_name: string_member(value, "screenName"),
    })
}

fn parse_enrollment(local_id: &str, value: &JsonValue) -> Result<MfaEnrollment, AuthExportError> {
    if !matches!(value, JsonValue::Object(_)) {
        return refuse(format!(
            "an mfaInfo entry of the account {local_id:?} is not an object"
        ));
    }
    Ok(MfaEnrollment {
        mfa_enrollment_id: string_member(value, "mfaEnrollmentId").unwrap_or_default(),
        display_name: string_member(value, "displayName"),
        phone_info: string_member(value, "phoneInfo"),
        unobfuscated_phone_info: string_member(value, "unobfuscatedPhoneInfo"),
        enrolled_at: string_member(value, "enrolledAt"),
        totp_shared_secret_key: value
            .get("totpInfo")
            .and_then(|t| t.get("sharedSecretKey"))
            .and_then(JsonValue::as_str)
            .map(str::to_owned),
    })
}

fn string_member(value: &JsonValue, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
}

fn number_member(value: &JsonValue, key: &str) -> Option<f64> {
    match value.get(key) {
        // A millisecond timestamp is far inside the exactly representable range, so the
        // widening never rounds in practice; a hypothetical larger one is only ever written
        // back out again.
        #[allow(clippy::cast_precision_loss)]
        Some(JsonValue::Int(i)) => Some(*i as f64),
        Some(JsonValue::Float(f)) => Some(*f),
        _ => None,
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
    use super::{fake_hash, AccountsFile, AuthConfig, MfaEnrollment, ProviderUserInfo, UserRecord};

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
    fn the_recorded_official_config_parses_and_round_trips() {
        let text = r#"{"signIn":{"allowDuplicateEmails":false},"emailPrivacyConfig":{"enableImprovedEmailPrivacy":false}}"#;
        let config = AuthConfig::parse(text).expect("the config parses");
        assert_eq!(
            config,
            AuthConfig {
                allow_duplicate_emails: false,
                enable_improved_email_privacy: Some(false),
            }
        );
        assert_eq!(
            AuthConfig::parse(&config.to_json()).expect("it parses"),
            config
        );
        let enabled = AuthConfig {
            allow_duplicate_emails: true,
            enable_improved_email_privacy: Some(true),
        };
        assert_eq!(
            AuthConfig::parse(&enabled.to_json()).expect("it parses"),
            enabled
        );
        // An undeclared privacy setting survives a round trip undeclared.
        let undeclared = AuthConfig {
            allow_duplicate_emails: false,
            enable_improved_email_privacy: None,
        };
        assert!(!undeclared.to_json().contains("emailPrivacyConfig"));
        assert_eq!(
            AuthConfig::parse(&undeclared.to_json()).expect("it parses"),
            undeclared
        );
    }

    #[test]
    fn a_config_document_that_is_not_an_object_is_refused() {
        assert!(AuthConfig::parse("[]").is_err());
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
