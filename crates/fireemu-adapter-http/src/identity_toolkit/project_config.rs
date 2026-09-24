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
            "resetPasswordTemplate": template("Reset your password for %APP_NAME%", RESET_BODY),
            "verifyEmailTemplate": template("Verify your email for %APP_NAME%", VERIFY_BODY),
            "changeEmailTemplate": template("Your sign-in email was changed for %APP_NAME%", CHANGE_BODY),
            "callbackUri": format!("https://{project}.firebaseapp.com/__/auth/action"),
            "dnsInfo": {
                "customDomainState": "NOT_STARTED",
                "domainVerificationRequestTime": "1970-01-01T00:00:00Z",
            },
            "revertSecondFactorAdditionTemplate": template(
                "You've added 2 step verification to your %APP_NAME% account.",
                REVERT_BODY,
            ),
        },
        "sendSms": {"smsTemplate": {"content": "%LOGIN_CODE% is your verification code for %APP_NAME%."}},
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
    members
        .get(member)
        .and_then(|text| serde_json::from_str(text).ok())
        .or_else(|| initial_member(member, project))
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

/// What the document is assembled from: the members' switches as they are stored.
#[allow(clippy::struct_excessive_bools)]
pub(super) struct ConfigSources<'a> {
    pub project: &'a str,
    pub project_number: Option<u64>,
    pub api_key: Option<&'a str>,
    /// `signIn` with the providers and `allowDuplicateEmails`, as the adapter projects them.
    pub sign_in: Value,
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
    let mut sign_in = sources.sign_in.clone();
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
        document["passwordPolicyConfig"] = policy.clone();
    }
    for member in STORED_MEMBERS {
        if let Some(value) = member_value(sources.members, member, project) {
            document[*member] = value;
        }
    }
    without_false(document)
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
    for (member, text) in sources.members.iter() {
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

fn put(value: &mut Value, path: &[&str], new: Option<Value>) {
    let Some((last, parents)) = path.split_last() else {
        return;
    };
    let mut current = value;
    for key in parents {
        if !current.get(*key).is_some_and(Value::is_object) {
            current[*key] = json!({});
        }
        current = &mut current[*key];
    }
    match (current.as_object_mut(), new) {
        (Some(object), Some(new)) => {
            object.insert((*last).to_owned(), new);
        }
        (Some(object), None) => {
            object.remove(*last);
        }
        (None, _) => {}
    }
}

/// Whether a stored member's value is one fireemu accepts. Production's own checks of these
/// members are recorded by the AUTH-CONFIG-SDK corpus; this refuses what is not the member's
/// shape at all.
fn valid_member(member: &str, value: &Value) -> bool {
    const REGIONS: fn(&Value, &str) -> bool = |inner, key| {
        inner.as_object().is_some_and(|object| {
            object.keys().all(|k| k == key)
                && object.get(key).is_none_or(|list| {
                    list.as_array()
                        .is_some_and(|items| items.iter().all(Value::is_string))
                })
        })
    };
    match member {
        "autodeleteAnonymousUsers" => value.is_boolean(),
        "mobileLinksConfig" => value.as_object().is_some_and(|object| {
            object.iter().all(|(key, v)| {
                key == "domain"
                    && matches!(
                        v.as_str(),
                        Some("HOSTING_DOMAIN" | "FIREBASE_DYNAMIC_LINK_DOMAIN")
                    )
            })
        }),
        "smsRegionConfig" => value.as_object().is_some_and(|object| {
            object.len() <= 1
                && object.iter().all(|(key, inner)| match key.as_str() {
                    "allowByDefault" => REGIONS(inner, "disallowedRegions"),
                    "allowlistOnly" => REGIONS(inner, "allowedRegions"),
                    _ => false,
                })
        }),
        "recaptchaConfig" => value.as_object().is_some_and(|object| {
            object.iter().all(|(key, v)| match key.as_str() {
                "emailPasswordEnforcementState" | "phoneEnforcementState" => matches!(
                    v.as_str(),
                    Some(
                        "OFF"
                            | "AUDIT"
                            | "ENFORCE"
                            | "RECAPTCHA_PROVIDER_ENFORCEMENT_STATE_UNSPECIFIED"
                    )
                ),
                "managedRules" | "tollFraudManagedRules" | "recaptchaKeys" => v.is_array(),
                "useAccountDefender" | "useSmsBotScore" | "useSmsTollFraudProtection" => {
                    v.is_boolean()
                }
                _ => false,
            })
        }),
        "monitoring" | "notification" => value.is_object(),
        _ => false,
    }
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
            lookup(body, &[member]).cloned()
        } else {
            member_value(current, member, project)
        };
        for path in paths.iter().filter(|path| **path != *member) {
            let segments: Vec<&str> = path.split('.').skip(1).collect();
            let written = lookup(body, &path.split('.').collect::<Vec<_>>()).cloned();
            let fallback = initial.as_ref().and_then(|v| lookup(v, &segments)).cloned();
            let target = value.get_or_insert_with(|| json!({}));
            put(target, &segments, written.or(fallback));
        }
        if let Some(value) = &value {
            if !valid_member(member, value) {
                return Err(());
            }
        }
        let unwritten = value.is_none() || value == initial;
        next.set(
            member,
            (!unwritten).then(|| value.map(|v| v.to_string())).flatten(),
        );
    }
    Ok(changed.then_some(next))
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
