//! The Admin v2 project configuration document (`admin/v2/projects/{p}/config`), as each
//! compatibility profile answers it (owner decision K3, AUTH-CONFIG-SDK):
//!
//! - strict answers what production answers for a project initialized with Identity Platform
//!   (sandbox reads 2026-09-23 and 2026-09-25): every member production reports, read-only ones
//!   included, and no member whose value is unset; a `false` switch is left out, as production
//!   leaves it out;
//! - the emulator profile answers the official Auth emulator's document
//!   (`signIn.allowDuplicateEmails`, `blockingFunctions`, `emailPrivacyConfig`) and adds only the
//!   members that were written.
//!
//! The written members fireemu keeps without interpreting them all live in
//! [`fireemu_core_auth::config_members`]; this module supplies their initial values.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha512};

use super::JsonResponse;

/// Config members stored as written ([`fireemu_core_auth::config_members`]).
pub(super) const STORED_MEMBERS: &[&str] = &[
    "notification",
    "mobileLinksConfig",
    "smsRegionConfig",
    "recaptchaConfig",
    "monitoring",
    "autodeleteAnonymousUsers",
];

const RESET_BODY: &str = "<p>Hello,</p>\n<p>Follow this link to reset your %APP_NAME% password for your %EMAIL% account.</p>\n<p><a href='%LINK%'>%LINK%</a></p>\n<p>If you didn\u{2019}t ask to reset your password, you can ignore this email.</p>\n<p>Thanks,</p>\n<p>Your %APP_NAME% team</p>";
const VERIFY_BODY: &str = "<p>Hello %DISPLAY_NAME%,</p>\n<p>Follow this link to verify your email address.</p>\n<p><a href='%LINK%'>%LINK%</a></p>\n<p>If you didn\u{2019}t ask to verify this address, you can ignore this email.</p>\n<p>Thanks,</p>\n<p>Your %APP_NAME% team</p>";
const CHANGE_BODY: &str = "<p>Hello %DISPLAY_NAME%,</p>\n<p>Your sign-in email for %APP_NAME% was changed to %NEW_EMAIL%.</p>\n<p>If you didn\u{2019}t ask to change your email, follow this link to reset your sign-in email.</p>\n<p><a href='%LINK%'>%LINK%</a></p>\n<p>Thanks,</p>\n<p>Your %APP_NAME% team</p>";
const REVERT_BODY: &str = "<p>Hello %DISPLAY_NAME%,</p>\n<p>Your account in %APP_NAME% has been updated with %SECOND_FACTOR% for 2-step verification.</p>\n<p>If you didn't add this 2-step verification, click the link below to remove it.</p>\n<p><a href='%LINK%'>%LINK%</a></p>\n<p>Thanks,</p>\n<p>Your %APP_NAME% team</p>";

/// Production's Japanese templates (`defaultLocale` `ja`, sandbox recording 2026-09-25).
const JA_TEMPLATES: &[(&str, &str, &str)] = &[
    (
        "resetPasswordTemplate",
        "%APP_NAME% のパスワードを再設定してください",
        "<p>お客様</p>\n<p>%APP_NAME% の %EMAIL% アカウントのパスワードをリセットするには、次のリンクをクリックしてください。</p>\n<p><a href='%LINK%'>%LINK%</a></p>\n<p>パスワードのリセットを依頼していない場合は、このメールを無視してください。</p>\n<p>よろしくお願いいたします。</p>\n<p>%APP_NAME% チーム</p>",
    ),
    (
        "verifyEmailTemplate",
        "%APP_NAME% のメールアドレスの確認",
        "<p>%DISPLAY_NAME% 様</p>\n<p>メールアドレスを確認するには、次のリンクをクリックしてください。</p>\n<p><a href='%LINK%'>%LINK%</a></p>\n<p>このアドレスの確認を依頼していない場合は、このメールを無視してください。</p>\n<p>よろしくお願いいたします。</p>\n<p>%APP_NAME% チーム</p>",
    ),
    (
        "changeEmailTemplate",
        "%APP_NAME% のログイン用メールアドレスが変更されました",
        "<p>%DISPLAY_NAME% 様</p>\n<p>%APP_NAME% のログイン用メールアドレスが %NEW_EMAIL% に変更されました。</p>\n<p>メールの変更を依頼していない場合は、次のリンクをクリックして、ログイン用メールアドレスをリセットしてください。</p>\n<p><a href='%LINK%'>%LINK%</a></p>\n<p>よろしくお願いいたします。</p>\n<p>%APP_NAME% チーム</p>",
    ),
    (
        "revertSecondFactorAdditionTemplate",
        "%APP_NAME% アカウントに 2 段階認証プロセスを追加しました。",
        "<p>%DISPLAY_NAME% 様</p>\n<p>2 段階認証プロセスの %SECOND_FACTOR% で %APP_NAME% のアカウントが更新されました。</p>\n<p>この 2 段階認証プロセスを追加していない場合は、下のリンクをクリックして削除してください。</p>\n<p><a href='%LINK%'>%LINK%</a></p>\n<p>よろしくお願いいたします。</p>\n<p>%APP_NAME% チーム</p>",
    ),
];
const JA_SMS: &str = "%APP_NAME% の確認コードは %LOGIN_CODE% です。";

/// Production's English templates, the ones a new project reports.
const EN_TEMPLATES: &[(&str, &str, &str)] = &[
    (
        "resetPasswordTemplate",
        "Reset your password for %APP_NAME%",
        RESET_BODY,
    ),
    (
        "verifyEmailTemplate",
        "Verify your email for %APP_NAME%",
        VERIFY_BODY,
    ),
    (
        "changeEmailTemplate",
        "Your sign-in email was changed for %APP_NAME%",
        CHANGE_BODY,
    ),
    (
        "revertSecondFactorAdditionTemplate",
        "You've added 2 step verification to your %APP_NAME% account.",
        REVERT_BODY,
    ),
];
const EN_SMS: &str = "%LOGIN_CODE% is your verification code for %APP_NAME%.";

fn template(subject: &str, body: &str) -> Value {
    json!({
        "senderLocalPart": "noreply",
        "subject": subject,
        "body": body,
        "bodyFormat": "HTML",
        "replyTo": "noreply",
    })
}

/// Production's `notification` of a new project: the default email and SMS templates. They are
/// configuration only; nothing is mailed or texted with them (AUTH-ACTION E1, K8).
fn initial_notification(project: &str) -> Value {
    json!({
        "sendEmail": {
            "method": "DEFAULT",
            "resetPasswordTemplate": template(EN_TEMPLATES[0].1, EN_TEMPLATES[0].2),
            "verifyEmailTemplate": template(EN_TEMPLATES[1].1, EN_TEMPLATES[1].2),
            "changeEmailTemplate": template(EN_TEMPLATES[2].1, EN_TEMPLATES[2].2),
            "callbackUri": format!("https://{project}.firebaseapp.com/__/auth/action"),
            "dnsInfo": {
                "customDomainState": "NOT_STARTED",
                "domainVerificationRequestTime": "1970-01-01T00:00:00Z",
            },
            "revertSecondFactorAdditionTemplate": template(EN_TEMPLATES[3].1, EN_TEMPLATES[3].2),
        },
        "sendSms": {"smsTemplate": {"content": EN_SMS}},
        "defaultLocale": "en",
    })
}

/// A stored member's value before any write: production's initial value, or `None` for the
/// members a new project does not report (`recaptchaConfig`, `autodeleteAnonymousUsers`).
pub(super) fn initial_member(member: &str, project: &str) -> Option<Value> {
    match member {
        "notification" => Some(initial_notification(project)),
        "mobileLinksConfig" => Some(json!({"domain": "HOSTING_DOMAIN"})),
        "smsRegionConfig" => Some(json!({"allowlistOnly": {}})),
        "monitoring" => Some(json!({"requestLogging": {}})),
        _ => None,
    }
}

/// A stored member's current value: as written, else its initial value.
pub(super) fn member_value(
    members: &fireemu_core_auth::config_members::StoredConfigMembers,
    member: &str,
    project: &str,
) -> Option<Value> {
    let value = members
        .get(member)
        .and_then(|text| serde_json::from_str(text).ok())
        .or_else(|| initial_member(member, project));
    if member == "notification" {
        return value.map(localized_notification);
    }
    value
}

/// The project's default locale (`notification.defaultLocale`), `en` until one is written.
pub(super) fn default_locale(
    members: &fireemu_core_auth::config_members::StoredConfigMembers,
) -> String {
    members
        .get("notification")
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .and_then(|notification| {
            notification
                .get("defaultLocale")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "en".to_owned())
}

/// The templates production reports for the default locale: they are not writable
/// (`EMAIL_TEMPLATE_UPDATE_NOT_ALLOWED`) and follow the locale (sandbox recording 2026-09-25).
/// Only English and Japanese are modelled; any other locale reports the English ones.
fn localized_notification(mut notification: Value) -> Value {
    let (templates, sms) = match notification.get("defaultLocale").and_then(Value::as_str) {
        Some("ja") => (JA_TEMPLATES, JA_SMS),
        _ => (EN_TEMPLATES, EN_SMS),
    };
    if let Some(send_email) = notification
        .pointer_mut("/sendEmail")
        .and_then(Value::as_object_mut)
    {
        for (name, subject, body) in templates {
            if let Some(template) = send_email.get_mut(*name).and_then(Value::as_object_mut) {
                template.insert("subject".to_owned(), json!(subject));
                template.insert("body".to_owned(), json!(body));
            }
        }
    }
    if let Some(content) = notification.pointer_mut("/sendSms/smsTemplate/content") {
        *content = json!(sms);
    }
    notification
}

/// The project's Firebase scrypt parameters as production reports them. fireemu hashes
/// passwords its own way; the key is derived from the project id so that it is stable, and
/// comparisons treat it as key material (K12).
fn hash_config(project: &str) -> Value {
    let b64 = fireemu_core_types::hash::base64_standard;
    let key = Sha512::digest(format!("fireemu scrypt signer key {project}").as_bytes());
    json!({
        "algorithm": "SCRYPT",
        "signerKey": b64(&key),
        "saltSeparator": b64(&[7u8]),
        "rounds": 8,
        "memoryCost": 14,
    })
}

/// Leaves out every `false` switch, as production's answers do.
pub(super) fn without_false(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .filter(|(_, v)| *v != Value::Bool(false))
                .map(|(k, v)| (k, without_false(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(without_false).collect()),
        other => other,
    }
}

/// The stored member holding when the project's password policy was last written: kept with
/// the written members but never reported as a member of its own.
pub(super) const POLICY_UPDATE_TIME: &str = "_passwordPolicyLastUpdateTime";

/// The stored member holding the names of the password strength options last written, so a
/// written false option is reported as production reports it.
pub(super) const POLICY_WRITTEN_OPTIONS: &str = "_passwordPolicyWrittenOptions";

/// The strength options a written policy names, when the write replaced its versions.
pub(super) fn written_policy_options(body: &Value) -> Option<Vec<String>> {
    body.pointer("/passwordPolicyConfig/passwordPolicyVersions/0/customStrengthOptions")
        .and_then(Value::as_object)
        .map(|options| options.keys().cloned().collect())
}

/// The sign-in provider objects production reports once written: each object with its
/// switches, a false one left out by the document's false omission.
pub(super) fn sign_in_providers(config: &fireemu_core_auth::store::SignInConfig) -> Value {
    let mut phone = json!({"enabled": config.phone_enabled});
    if !config.test_phone_numbers.is_empty() {
        phone["testPhoneNumbers"] = json!(config.test_phone_numbers);
    }
    json!({
        "email": {"enabled": config.email_enabled, "passwordRequired": config.password_required},
        "anonymous": {"enabled": config.anonymous_enabled},
        "phoneNumber": phone,
    })
}

/// The stored member holding the written sign-up quota as production reports it.
pub(super) const SIGN_UP_QUOTA: &str = "_signUpQuotaConfig";

/// A written `quota.signUpQuotaConfig` as production stores it: a zero quota left out, a
/// missing start as the epoch, a missing duration as zero; `None` when cleared.
pub(super) fn normalized_sign_up_quota(body: &Value) -> Option<Value> {
    let written = body
        .pointer("/quota/signUpQuotaConfig")
        .filter(|v| !v.is_null())?;
    let mut quota = Map::new();
    if let Some(number) = written
        .get("quota")
        .and_then(|q| {
            q.as_str()
                .map(str::to_owned)
                .or_else(|| q.as_i64().map(|n| n.to_string()))
        })
        .filter(|q| q != "0")
    {
        quota.insert("quota".to_owned(), json!(number));
    }
    quota.insert(
        "startTime".to_owned(),
        written
            .get("startTime")
            .cloned()
            .unwrap_or_else(|| json!("1970-01-01T00:00:00Z")),
    );
    quota.insert(
        "quotaDuration".to_owned(),
        written
            .get("quotaDuration")
            .cloned()
            .unwrap_or_else(|| json!("0s")),
    );
    Some(Value::Object(quota))
}

/// A PATCH answer as production gives it: the configuration without the email templates.
pub(super) fn patch_answer(mut document: Value) -> Value {
    if let Some(send_email) = document
        .pointer_mut("/notification/sendEmail")
        .and_then(Value::as_object_mut)
    {
        for template in TEMPLATES {
            send_email.remove(*template);
        }
    }
    document
}

/// What the document is assembled from: the members' switches as they are stored.
#[allow(clippy::struct_excessive_bools)]
pub(super) struct ConfigSources<'a> {
    pub project: &'a str,
    pub project_number: Option<u64>,
    pub api_key: Option<&'a str>,
    /// `signIn` with the providers and `allowDuplicateEmails`, as the adapter projects them.
    pub sign_in: Value,
    /// Every provider object ([`sign_in_providers`]), as strict reports them.
    pub providers: Value,
    /// When the configured password policy was last written (RFC 3339).
    pub policy_update_time: Option<String>,
    /// Whether the sign-in providers were ever written (the emulator profile's document shows
    /// them only then).
    pub sign_in_written: bool,
    pub allow_duplicate_emails: bool,
    pub improved_email_privacy: bool,
    pub disabled_user_signup: bool,
    pub disabled_user_deletion: bool,
    /// The configured password policy's member, or `None` while none is configured.
    pub password_policy: Option<Value>,
    /// `quota.signUpQuotaConfig`, when set.
    pub sign_up_quota: Option<Value>,
    /// fireemu's own `quota.quotaSimulation`, shown only by the emulator profile.
    pub quota_simulation: Option<Value>,
    pub authorized_domains: Vec<String>,
    pub authorized_domains_written: bool,
    pub blocking_functions: Option<Value>,
    pub members: &'a fireemu_core_auth::config_members::StoredConfigMembers,
}

/// Production's document (strict profile).
pub(super) fn strict_document(sources: &ConfigSources<'_>) -> Value {
    let project = sources.project;
    let mut sign_in = sources.providers.clone();
    sign_in["allowDuplicateEmails"] = json!(sources.allow_duplicate_emails);
    sign_in["hashConfig"] = hash_config(project);
    let mut quota = Map::new();
    if let Some(value) = &sources.sign_up_quota {
        quota.insert("signUpQuotaConfig".to_owned(), value.clone());
    }
    let mut client = Map::new();
    if let Some(key) = sources.api_key {
        client.insert("apiKey".to_owned(), json!(key));
    }
    client.insert(
        "permissions".to_owned(),
        json!({
            "disabledUserSignup": sources.disabled_user_signup,
            "disabledUserDeletion": sources.disabled_user_deletion,
        }),
    );
    client.insert("firebaseSubdomain".to_owned(), json!(project));
    let name = sources
        .project_number
        .map_or_else(|| project.to_owned(), |number| number.to_string());
    let mut document = json!({
        "name": format!("projects/{name}/config"),
        "signIn": sign_in,
        "quota": quota,
        "multiTenant": {},
        "authorizedDomains": sources.authorized_domains,
        "subtype": "IDENTITY_PLATFORM",
        "client": client,
        "mfa": {"state": "DISABLED"},
        "blockingFunctions": sources.blocking_functions.clone().unwrap_or_else(|| json!({})),
        "emailPrivacyConfig": {"enableImprovedEmailPrivacy": sources.improved_email_privacy},
        "defaultHostingSite": project,
    });
    if let Some(policy) = &sources.password_policy {
        let mut policy = policy.clone();
        for version in policy
            .get_mut("passwordPolicyVersions")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            version["schemaVersion"] = json!(1);
        }
        if let Some(time) = &sources.policy_update_time {
            policy["lastUpdateTime"] = json!(time);
        }
        document["passwordPolicyConfig"] = policy;
    }
    // A false switch of the members fireemu models is left out; a written member keeps what
    // was written, false switches included, as production does for them.
    let mut document = without_false(document);
    let written_options: Vec<String> = sources
        .members
        .get(POLICY_WRITTEN_OPTIONS)
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or_default();
    if let Some(options) = document
        .pointer_mut("/passwordPolicyConfig/passwordPolicyVersions/0/customStrengthOptions")
        .and_then(Value::as_object_mut)
    {
        for name in &written_options {
            options.entry(name.clone()).or_insert(Value::Bool(false));
        }
    }
    for member in STORED_MEMBERS {
        if let Some(value) = member_value(sources.members, member, project) {
            document[*member] = value;
        }
    }
    document
}

/// The official Auth emulator's document, with the members written since (emulator profile).
pub(super) fn emulator_document(sources: &ConfigSources<'_>) -> Value {
    let mut sign_in = if sources.sign_in_written {
        sources.sign_in.clone()
    } else {
        json!({})
    };
    sign_in["allowDuplicateEmails"] = json!(sources.allow_duplicate_emails);
    let mut document = json!({
        "signIn": sign_in,
        "blockingFunctions": sources.blocking_functions.clone().unwrap_or_else(|| json!({})),
        "emailPrivacyConfig": {"enableImprovedEmailPrivacy": sources.improved_email_privacy},
    });
    if sources.disabled_user_signup || sources.disabled_user_deletion {
        document["client"] = json!({"permissions": {
            "disabledUserSignup": sources.disabled_user_signup,
            "disabledUserDeletion": sources.disabled_user_deletion,
        }});
    }
    if let Some(policy) = &sources.password_policy {
        document["passwordPolicyConfig"] = policy.clone();
    }
    let mut quota = Map::new();
    if let Some(value) = &sources.sign_up_quota {
        quota.insert("signUpQuotaConfig".to_owned(), value.clone());
    }
    if let Some(value) = &sources.quota_simulation {
        quota.insert("quotaSimulation".to_owned(), value.clone());
    }
    if !quota.is_empty() {
        document["quota"] = Value::Object(quota);
    }
    if sources.authorized_domains_written {
        document["authorizedDomains"] = json!(sources.authorized_domains);
    }
    for (member, text) in sources
        .members
        .iter()
        .filter(|(member, _)| !member.starts_with('_'))
    {
        if let Ok(value) = serde_json::from_str::<Value>(text) {
            document[member] = value;
        }
    }
    document
}

/// Whether `field` is a mask path of a stored member.
pub(super) fn stored_member_field(field: &str) -> bool {
    STORED_MEMBERS
        .iter()
        .any(|member| field == *member || field.starts_with(&format!("{member}.")))
}

fn lookup<'v>(value: &'v Value, path: &[&str]) -> Option<&'v Value> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .filter(|found| !found.is_null())
}

/// Writes `new` at `path`, creating missing parents; `false` when a parent on the way is a
/// value that is not an object, which a path cannot go below.
fn put(value: &mut Value, path: &[&str], new: Option<Value>) -> bool {
    let Some((last, parents)) = path.split_last() else {
        return true;
    };
    let mut current = value;
    for key in parents {
        let Some(object) = current.as_object_mut() else {
            return false;
        };
        let child = object.entry((*key).to_owned()).or_insert_with(|| json!({}));
        if child.is_null() {
            *child = json!({});
        }
        current = child;
    }
    let Some(object) = current.as_object_mut() else {
        return false;
    };
    match new {
        Some(new) => {
            object.insert((*last).to_owned(), new);
        }
        None => {
            object.remove(*last);
        }
    }
    true
}

/// The stored members after a PATCH's masked stored-member paths, or `Err` when a resulting
/// member is not valid. A member masked whole takes the body's value (absent: cleared); a masked
/// leaf takes the body's leaf, or a new project's leaf when the body leaves it out. A member that
/// ends up equal to a new project's value is stored as unwritten.
pub(super) fn apply_stored_members(
    current: &fireemu_core_auth::config_members::StoredConfigMembers,
    body: &Value,
    fields: &[String],
    project: &str,
) -> Result<Option<fireemu_core_auth::config_members::StoredConfigMembers>, ()> {
    let mut next = current.clone();
    let mut changed = false;
    for member in STORED_MEMBERS {
        let paths: Vec<&str> = fields
            .iter()
            .map(String::as_str)
            .filter(|field| *field == *member || field.starts_with(&format!("{member}.")))
            .collect();
        if paths.is_empty() {
            continue;
        }
        changed = true;
        let initial = initial_member(member, project);
        let mut value = if paths.contains(member) {
            match lookup(body, &[member]).cloned() {
                // Production's masked clear of the reCAPTCHA config keeps its phone side.
                None if *member == "recaptchaConfig" => {
                    member_value(current, member, project).map(recaptcha_phone_side)
                }
                written => written,
            }
        } else {
            member_value(current, member, project)
        };
        for path in paths.iter().filter(|path| **path != *member) {
            let segments: Vec<&str> = path.split('.').skip(1).collect();
            let written = lookup(body, &path.split('.').collect::<Vec<_>>()).cloned();
            let fallback = initial.as_ref().and_then(|v| lookup(v, &segments)).cloned();
            let target = value.get_or_insert_with(|| json!({}));
            // Writing one member of a oneof clears the others, as production's proto does.
            if written.is_some() {
                if let (Some(first), Some(fields)) = (segments.first(), target.as_object_mut()) {
                    for sibling in oneof_siblings(member, first) {
                        fields.remove(*sibling);
                    }
                }
            }
            // A false account defender written through a deep mask is not stored.
            let unset = *member == "recaptchaConfig"
                && segments == ["useAccountDefender"]
                && written == Some(Value::Bool(false));
            if !put(
                target,
                &segments,
                if unset { None } else { written.or(fallback) },
            ) {
                return Err(());
            }
        }
        if *member == "recaptchaConfig" {
            value = value.map(with_recaptcha_phone_defaults);
        }
        let unwritten = value.is_none() || value == initial;
        next.set(
            member,
            (!unwritten).then(|| value.map(|v| v.to_string())).flatten(),
        );
    }
    Ok(changed.then_some(next))
}

/// The members of the reCAPTCHA config's phone side, which production keeps apart from the
/// email side (sandbox recording 2026-09-25, auth-config-sdk/recaptcha).
const RECAPTCHA_PHONE_SIDE: &[&str] = &[
    "phoneEnforcementState",
    "useSmsBotScore",
    "useSmsTollFraudProtection",
];

/// What a masked clear leaves of the reCAPTCHA config: its phone side.
fn recaptcha_phone_side(config: Value) -> Value {
    let Value::Object(fields) = config else {
        return json!({});
    };
    Value::Object(
        fields
            .into_iter()
            .filter(|(key, _)| RECAPTCHA_PHONE_SIDE.contains(&key.as_str()))
            .collect(),
    )
}

/// A stored reCAPTCHA config always reports its phone side: an unwritten enforcement state as
/// unspecified and unwritten SMS switches as off.
fn with_recaptcha_phone_defaults(mut config: Value) -> Value {
    if let Some(fields) = config.as_object_mut() {
        fields
            .entry("phoneEnforcementState")
            .or_insert_with(|| json!("RECAPTCHA_PROVIDER_ENFORCEMENT_STATE_UNSPECIFIED"));
        fields.entry("useSmsBotScore").or_insert(Value::Bool(false));
        fields
            .entry("useSmsTollFraudProtection")
            .or_insert(Value::Bool(false));
    }
    config
}

/// The other members of the oneof `field` of `member` belongs to.
fn oneof_siblings(member: &str, field: &str) -> &'static [&'static str] {
    match (member, field) {
        ("smsRegionConfig", "allowByDefault") => &["allowlistOnly"],
        ("smsRegionConfig", "allowlistOnly") => &["allowByDefault"],
        _ => &[],
    }
}

/// ISO 3166-1 alpha-2 region codes, the codes production takes in `smsRegionConfig` (in any
/// case; it refuses others with `INVALID_REGION_CODE`).
const REGION_CODES: &str = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW";

/// Whether `domain` is a host production takes as an authorized domain: DNS labels only, no
/// scheme, port, path, wildcard or space.
fn valid_authorized_domain(domain: &str) -> bool {
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Whether a reCAPTCHA managed-rule score is one of production's eleven values 0.0..=1.0.
fn valid_score(score: Option<f64>) -> bool {
    score.is_some_and(|score| {
        (0.0..=1.0).contains(&score) && ((score * 10.0).round() - score * 10.0).abs() < 1e-6
    })
}

const TEMPLATES: &[&str] = &[
    "resetPasswordTemplate",
    "verifyEmailTemplate",
    "changeEmailTemplate",
    "revertSecondFactorAdditionTemplate",
    "legacyResetPasswordTemplate",
];

/// Production's refusals of values it parsed but will not take, for the masked paths
/// (AUTH-CONFIG-SDK sandbox recordings 2026-09-25). `strict` adds the refusals the emulator
/// profile does not make (authorized domains, SMS regions, reCAPTCHA rules, email templates).
#[allow(clippy::too_many_lines)]
pub(super) fn validate_values(
    body: &Value,
    fields: &[String],
    strict: bool,
) -> Result<(), JsonResponse> {
    use super::config_proto::refusal;
    let masked = |member: &str| {
        fields.iter().any(|field| {
            field == member
                || field.starts_with(&format!("{member}."))
                || member.starts_with(&format!("{field}."))
        })
    };
    if masked("signIn.phoneNumber.testPhoneNumbers") {
        if let Some(numbers) = body
            .pointer("/signIn/phoneNumber/testPhoneNumbers")
            .and_then(Value::as_object)
        {
            if numbers.keys().any(|number| {
                fireemu_core_auth::store::AuthStore::validate_phone_number(number).is_err()
            }) {
                return Err(refusal("INVALID_PHONE_NUMBER : Invalid format."));
            }
        }
    }
    if masked("authorizedDomains") {
        for domain in body
            .get("authorizedDomains")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if domain.is_empty() {
                return Err(refusal(
                    "INVALID_AUTHORIZED_DOMAIN : An authorized domain is empty.",
                ));
            }
            if strict && !valid_authorized_domain(domain) {
                return Err(refusal(&format!(
                    "INVALID_AUTHORIZED_DOMAIN : {domain} should only contain the valid domain."
                )));
            }
        }
    }
    if !strict {
        return Ok(());
    }
    if masked("smsRegionConfig") {
        let regions = [
            "/smsRegionConfig/allowByDefault/disallowedRegions",
            "/smsRegionConfig/allowlistOnly/allowedRegions",
        ]
        .into_iter()
        .filter_map(|pointer| body.pointer(pointer).and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str);
        for region in regions {
            if !REGION_CODES
                .split(' ')
                .any(|code| code.eq_ignore_ascii_case(region))
            {
                return Err(refusal("INVALID_REGION_CODE : Invalid region code."));
            }
        }
    }
    if masked("recaptchaConfig") {
        if let Some(recaptcha) = body.get("recaptchaConfig") {
            let rules = |key: &str| {
                recaptcha
                    .get(key)
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
            };
            let set = |rule: &Value| {
                rule.get("action")
                    .and_then(Value::as_str)
                    .is_some_and(|a| a != "RECAPTCHA_ACTION_UNSPECIFIED")
            };
            for rule in rules("managedRules") {
                if !valid_score(rule.get("endScore").and_then(Value::as_f64)) {
                    return Err(refusal("INVALID_CONFIG : The end score in reCAPTCHA managed rules must be a value between 0.0 and 1.0, at 11 discrete values; e.g. 0.1, 0.2, 0.3, 0.4, ... 0.9, 1.0."));
                }
                if !set(&rule) {
                    return Err(refusal(
                        "INVALID_CONFIG : The action in reCAPTCHA managed rules must be set.",
                    ));
                }
            }
            for rule in rules("tollFraudManagedRules") {
                if !valid_score(rule.get("startScore").and_then(Value::as_f64)) {
                    return Err(refusal("INVALID_CONFIG : The start score in reCAPTCHA managed rules must be a value between 0.0 and 1.0, at 11 discrete values; e.g. 0.1, 0.2, 0.3, 0.4, ... 0.9, 1.0."));
                }
                if !set(&rule) {
                    return Err(refusal(
                        "INVALID_CONFIG : The action in reCAPTCHA managed rules must be set.",
                    ));
                }
            }
            let phone_on = matches!(
                recaptcha
                    .get("phoneEnforcementState")
                    .and_then(Value::as_str),
                Some("AUDIT" | "ENFORCE")
            );
            let sms_flag = |key: &str| recaptcha.get(key).and_then(Value::as_bool) == Some(true);
            if (sms_flag("useSmsBotScore") || sms_flag("useSmsTollFraudProtection")) && !phone_on {
                return Err(refusal("INVALID_RECAPTCHA_PHONE_AUTH_CONFIGURATION : Phone auth enforcement state must be aligned with toll fraud or bot score enablement."));
            }
            if recaptcha
                .get("recaptchaKeys")
                .and_then(Value::as_array)
                .is_some_and(|keys| !keys.is_empty())
            {
                return Err(refusal("INVALID_SITE_KEY"));
            }
        }
    }
    if fields.iter().any(|field| {
        TEMPLATES.iter().any(|template| {
            let path = format!("notification.sendEmail.{template}");
            field == &path || field.starts_with(&format!("{path}."))
        })
    }) {
        return Err(refusal("EMAIL_TEMPLATE_UPDATE_NOT_ALLOWED"));
    }
    Ok(())
}

/// The client types `v2/recaptchaConfig` takes.
const CLIENT_TYPES: &[&str] = &[
    "CLIENT_TYPE_UNSPECIFIED",
    "CLIENT_TYPE_WEB",
    "CLIENT_TYPE_ANDROID",
    "CLIENT_TYPE_IOS",
];

/// Parses a query string into its decoded pairs.
fn query_pairs(query: Option<&str>) -> Vec<(String, String)> {
    query
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (
                super::decode_query_component(key),
                super::decode_query_component(value),
            )
        })
        .collect()
}

/// `GET v2/recaptchaConfig`: the project's reCAPTCHA enforcement as clients read it (sandbox
/// recording 2026-09-25, AUTH-CONFIG-SDK): both providers' states (unspecified until
/// written), the SMS switches, and production's refusals of a missing or unknown client type
/// and a missing version.
pub(super) fn client_recaptcha_config(
    store: &fireemu_core_auth::store::AuthStore,
    query: Option<&str>,
) -> JsonResponse {
    use super::config_proto::refusal;
    let pairs = query_pairs(query);
    let param = |name: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    let Some(client_type) = param("clientType") else {
        return refusal("MISSING_CLIENT_TYPE");
    };
    if !CLIENT_TYPES.contains(&client_type) {
        let message = format!(
            "Invalid value at 'client_type' (type.googleapis.com/google.cloud.identitytoolkit.v2.ClientType), \"{client_type}\""
        );
        return JsonResponse {
            status: 400,
            body: json!({"error": {
                "code": 400,
                "message": message,
                "status": "INVALID_ARGUMENT",
                "details": [{
                    "@type": "type.googleapis.com/google.rpc.BadRequest",
                    "fieldViolations": [{"field": "client_type", "description": message}],
                }],
            }}),
        };
    }
    if param("version").is_none() {
        return refusal("MISSING_RECAPTCHA_VERSION");
    }
    let config = store
        .stored_config_members()
        .get("recaptchaConfig")
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .unwrap_or_else(|| json!({}));
    let state = |key: &str| match config.get(key).and_then(Value::as_str) {
        Some(state @ ("OFF" | "AUDIT" | "ENFORCE")) => state.to_owned(),
        _ => "ENFORCEMENT_STATE_UNSPECIFIED".to_owned(),
    };
    let flag = |key: &str| config.get(key).and_then(Value::as_bool).unwrap_or(false);
    JsonResponse {
        status: 200,
        body: json!({
            "recaptchaEnforcementState": [
                {"provider": "EMAIL_PASSWORD_PROVIDER", "enforcementState": state("emailPasswordEnforcementState")},
                {"provider": "PHONE_PROVIDER", "enforcementState": state("phoneEnforcementState")},
            ],
            "useSmsBotScore": flag("useSmsBotScore"),
            "useSmsTollFraudProtection": flag("useSmsTollFraudProtection"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{initial_member, without_false};
    use serde_json::json;

    #[test]
    fn false_switches_are_left_out_at_any_depth() {
        assert_eq!(
            without_false(
                json!({"a": false, "b": {"c": false, "d": true}, "e": [{"f": false}], "g": 0})
            ),
            json!({"b": {"d": true}, "e": [{}], "g": 0})
        );
    }

    #[test]
    fn initial_members_are_production_initial_values() {
        assert_eq!(
            initial_member("notification", "p").unwrap()["sendEmail"]["callbackUri"],
            json!("https://p.firebaseapp.com/__/auth/action")
        );
        assert_eq!(
            initial_member("smsRegionConfig", "p"),
            Some(json!({"allowlistOnly": {}}))
        );
        assert_eq!(initial_member("recaptchaConfig", "p"), None);
        assert_eq!(initial_member("autodeleteAnonymousUsers", "p"), None);
    }
}
