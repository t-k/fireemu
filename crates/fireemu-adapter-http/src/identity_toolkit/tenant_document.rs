//! The Admin v2 tenant resource (`v2/projects/{p}/tenants`) as production answers it
//! (AUTH-TENANT-BLOCKING sandbox recording 2026-09-27, programs `atb/tenant/*`):
//!
//! - `name` names the project by number when fireemu knows it, and always has `displayName`
//!   and `inheritance` (`{}` until written);
//! - a switch appears only when on, and a member only once written; a written
//!   `emailPrivacyConfig` or `client` stays, emptied, when its switches are turned off;
//! - a read (`GET`) adds the project's scrypt `hashConfig`; a create, update or list does not;
//! - a written `passwordPolicyConfig` carries `schemaVersion` and `lastUpdateTime`;
//!   `autodeleteAnonymousUsers` is taken and never answered.
//!
//! The members fireemu does not interpret are kept as written in the tenant's own store
//! ([`fireemu_core_auth::config_members`]); `mfaConfig` and `testPhoneNumbers` are also
//! installed where the tenant's sign-in reads them.

use std::collections::BTreeMap;

use fireemu_core_auth::config_members::StoredConfigMembers;
use fireemu_core_auth::mfa_config::MfaProjectConfig;
use fireemu_core_auth::store::{AuthStore, TenantMetadata};
use serde_json::{json, Map, Value};

use super::project_config;
use super::JsonResponse;

/// Tenant members kept as written in the tenant's store.
pub(super) const WRITTEN_MEMBERS: &[&str] = &[
    "mfaConfig",
    "testPhoneNumbers",
    "inheritance",
    "monitoring",
    "smsRegionConfig",
    "recaptchaConfig",
    "mobileLinksConfig",
    "autodeleteAnonymousUsers",
];
/// Members answered as written (`autodeleteAnonymousUsers` is taken and not answered).
const ANSWERED_MEMBERS: &[&str] = &[
    "mfaConfig",
    "testPhoneNumbers",
    "inheritance",
    "monitoring",
    "smsRegionConfig",
    "recaptchaConfig",
    "mobileLinksConfig",
];
/// Whether `emailPrivacyConfig` was ever written: it is then answered even when off.
pub(super) const PRIVACY_WRITTEN: &str = "_tenantEmailPrivacyConfigWritten";
/// Whether `client` was ever written: it is then answered even with no permission on.
pub(super) const CLIENT_WRITTEN: &str = "_tenantClientWritten";

const INVALID_DISPLAY_NAME: &str = "INVALID_DISPLAY_NAME : display_name should start with a letter and only consist of letters, digits and hyphens with 4-20 characters.";
const MISSING_DISPLAY_NAME: &str = "MISSING_DISPLAY_NAME : Missing tenant with valid display_name.";

fn refusal(message: &str) -> JsonResponse {
    JsonResponse {
        status: 400,
        body: json!({"error": {"code": 400, "message": message, "status": "INVALID_ARGUMENT"}}),
    }
}

/// A display name production takes: a letter, then 3 to 19 letters, digits or hyphens.
pub(super) fn valid_display_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (4..=20).contains(&bytes.len())
        && bytes[0].is_ascii_alphabetic()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

/// Production's refusal of a tenant's display name (strict profile): missing, or not one it
/// takes.
pub(super) fn display_name_refusal(name: Option<&Value>) -> Option<JsonResponse> {
    match name.and_then(Value::as_str) {
        None => Some(refusal(MISSING_DISPLAY_NAME)),
        Some(name) if !valid_display_name(name) => Some(refusal(INVALID_DISPLAY_NAME)),
        Some(_) => None,
    }
}

/// Production's refusal of an update without a mask: it replaces the whole tenant, which needs
/// a display name (strict profile).
pub(super) fn missing_display_name() -> JsonResponse {
    refusal(MISSING_DISPLAY_NAME)
}

/// The written members an update sets or clears, parsed and checked before anything changes.
#[derive(Debug, Default)]
pub(super) struct WrittenMembers {
    /// `(member, Some(value))` writes, `(member, None)` clears.
    members: Vec<(&'static str, Option<Value>)>,
    /// The MFA config to install, when `mfaConfig` is written or cleared.
    mfa: Option<MfaProjectConfig>,
    /// The test phone numbers to install, when `testPhoneNumbers` is written or cleared.
    phones: Option<BTreeMap<String, String>>,
    privacy_written: bool,
    client_written: bool,
    /// A password policy write: the parsed body, the policy paths it touched, whether a policy
    /// is configured after it, and when it was written (the derived members production keeps).
    policy: Option<(Value, Vec<String>, bool, Option<String>)>,
}

impl WrittenMembers {
    /// The members of `body` (a parsed tenant) that `touched` names: every member of a
    /// create, or the members an update mask reaches (a member absent from the body is
    /// cleared).
    pub(super) fn from_body(
        body: &Value,
        touched: impl Fn(&str) -> bool,
    ) -> Result<Self, JsonResponse> {
        let mut written = Self::default();
        for member in WRITTEN_MEMBERS {
            if !touched(member) {
                continue;
            }
            let value = body.get(*member).filter(|value| !value.is_null()).cloned();
            match *member {
                "mfaConfig" => {
                    let config = match &value {
                        Some(value) => super::project_mfa::mfa_config_from_json(value)
                            .map_err(|refusal| super::mfa_config_refusal(&refusal))?,
                        None => MfaProjectConfig::default(),
                    };
                    written.mfa = Some(config);
                }
                "testPhoneNumbers" => {
                    let numbers: BTreeMap<String, String> = value
                        .as_ref()
                        .and_then(Value::as_object)
                        .map(|numbers| {
                            numbers
                                .iter()
                                .map(|(number, code)| {
                                    (number.clone(), code.as_str().unwrap_or_default().to_owned())
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let check = fireemu_core_auth::store::SignInConfig {
                        test_phone_numbers: numbers.clone(),
                        ..fireemu_core_auth::store::SignInConfig::default()
                    };
                    if !check.is_valid() {
                        return Err(super::error(400, "INVALID_ARGUMENT"));
                    }
                    written.phones = Some(numbers);
                }
                _ => {}
            }
            let value = value.map(ordered_member);
            written.members.push((member, value));
        }
        written.privacy_written = touched("emailPrivacyConfig");
        written.client_written = touched("client");
        Ok(written)
    }

    /// Records a password policy write, for its derived members (`lastUpdateTime`, the written
    /// strength options).
    pub(super) fn with_policy_write(
        mut self,
        body: &Value,
        fields: Vec<String>,
        configured: bool,
        written_at: Option<String>,
    ) -> Self {
        self.policy = Some((body.clone(), fields, configured, written_at));
        self
    }

    /// Installs the members in `store`, the tenant's own. `Err` when the store refuses the
    /// test phone numbers (production's limits on them), before anything is changed.
    pub(super) fn apply(self, store: &mut AuthStore) -> Result<(), JsonResponse> {
        if let Some(numbers) = self.phones {
            let mut sign_in = store.sign_in_config().clone();
            sign_in.test_phone_numbers = numbers;
            store
                .set_sign_in_config(sign_in)
                .map_err(|_| super::error(400, "INVALID_ARGUMENT"))?;
        }
        if let Some(config) = self.mfa {
            store.set_mfa_config(config);
        }
        let mut members: StoredConfigMembers = store.stored_config_members().clone();
        for (member, value) in self.members {
            members.set(member, value.map(|value| value.to_string()));
        }
        if self.privacy_written {
            members.set(PRIVACY_WRITTEN, Some("true".to_owned()));
        }
        if self.client_written {
            members.set(CLIENT_WRITTEN, Some("true".to_owned()));
        }
        if let Some((body, fields, configured, written_at)) = &self.policy {
            super::with_derived_members(
                &mut members,
                body,
                fields,
                *configured,
                written_at.as_deref(),
            );
        }
        store.set_stored_config_members(members);
        Ok(())
    }
}

/// A provider config's members in production's order (`totpProviderConfig`, then `state`).
fn ordered_member(value: Value) -> Value {
    let Value::Object(mut object) = value else {
        return value;
    };
    if let Some(Value::Array(providers)) = object.get_mut("providerConfigs") {
        for provider in providers.iter_mut() {
            if let Value::Object(fields) = provider {
                let mut ordered = Map::new();
                for key in ["totpProviderConfig", "state"] {
                    if let Some(item) = fields.remove(key) {
                        ordered.insert(key.to_owned(), item);
                    }
                }
                ordered.extend(std::mem::take(fields));
                *fields = ordered;
            }
        }
    }
    Value::Object(object)
}

/// Whether a tenant document is a read (with the scrypt parameters) or the answer to a write
/// or a list.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum View {
    Read,
    Written,
}

/// A configured password policy as a tenant answers it: production's rendering with its
/// schema version, write time and the strength options written.
fn written_policy(store: &AuthStore) -> Option<Value> {
    let policy = store.password_policy();
    if !policy.configured {
        return None;
    }
    let members = store.stored_config_members();
    let mut rendered = super::password_policy_config_json(policy);
    for version in rendered
        .get_mut("passwordPolicyVersions")
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        version["schemaVersion"] = json!(1);
    }
    if let Some(time) = members
        .get(project_config::POLICY_UPDATE_TIME)
        .and_then(|text| serde_json::from_str::<String>(text).ok())
    {
        rendered["lastUpdateTime"] = json!(time);
    }
    let mut rendered = project_config::without_false(rendered);
    let written_options: Vec<String> = members
        .get(project_config::POLICY_WRITTEN_OPTIONS)
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or_default();
    if let Some(options) = rendered
        .pointer_mut("/passwordPolicyVersions/0/customStrengthOptions")
        .and_then(Value::as_object_mut)
    {
        for name in &written_options {
            options.entry(name.clone()).or_insert(Value::Bool(false));
        }
    }
    Some(rendered)
}

/// The tenant document production answers. `project_name` is the project's number when
/// fireemu knows it, else its id.
pub(super) fn document(
    project: &str,
    project_name: &str,
    tenant: &str,
    metadata: &TenantMetadata,
    store: &AuthStore,
    view: View,
) -> Value {
    let members = store.stored_config_members();
    let stored = |member: &str| -> Option<Value> {
        members
            .get(member)
            .and_then(|text| serde_json::from_str(text).ok())
    };
    let mut document = Map::new();
    document.insert(
        "name".to_owned(),
        json!(format!("projects/{project_name}/tenants/{tenant}")),
    );
    if let Some(name) = &metadata.display_name {
        document.insert("displayName".to_owned(), json!(name));
    }
    let switch = |document: &mut Map<String, Value>, key: &str, on: bool| {
        if on {
            document.insert(key.to_owned(), Value::Bool(true));
        }
    };
    switch(
        &mut document,
        "allowPasswordSignup",
        metadata.allow_password_signup,
    );
    switch(
        &mut document,
        "enableEmailLinkSignin",
        metadata.enable_email_link_signin,
    );
    switch(&mut document, "disableAuth", metadata.disable_auth);
    if view == View::Read {
        document.insert(
            "hashConfig".to_owned(),
            project_config::hash_config(&format!("{project}/tenants/{tenant}")),
        );
    }
    switch(
        &mut document,
        "enableAnonymousUser",
        metadata.enable_anonymous_user,
    );
    for member in ANSWERED_MEMBERS {
        match stored(member) {
            Some(Value::Object(object)) if *member == "testPhoneNumbers" && object.is_empty() => {}
            Some(value) => {
                document.insert((*member).to_owned(), value);
            }
            None if *member == "inheritance" => {
                document.insert("inheritance".to_owned(), json!({}));
            }
            None => {}
        }
    }
    if let Some(policy) = written_policy(store) {
        document.insert("passwordPolicyConfig".to_owned(), policy);
    }
    if metadata.enable_improved_email_privacy {
        document.insert(
            "emailPrivacyConfig".to_owned(),
            json!({"enableImprovedEmailPrivacy": true}),
        );
    } else if members.get(PRIVACY_WRITTEN).is_some() {
        document.insert("emailPrivacyConfig".to_owned(), json!({}));
    }
    let mut permissions = Map::new();
    if metadata.disabled_user_signup {
        permissions.insert("disabledUserSignup".to_owned(), Value::Bool(true));
    }
    if metadata.disabled_user_deletion {
        permissions.insert("disabledUserDeletion".to_owned(), Value::Bool(true));
    }
    if !permissions.is_empty() || members.get(CLIENT_WRITTEN).is_some() {
        document.insert("client".to_owned(), json!({"permissions": permissions}));
    }
    Value::Object(document)
}

#[cfg(test)]
mod tests {
    use super::valid_display_name;

    #[test]
    fn display_names_follow_production_rule() {
        for name in ["atbx", "Atb-Upper", "a-bcdefghijklmnopqrs", "a123", "a---"] {
            assert!(valid_display_name(name), "{name}");
        }
        for name in [
            "",
            "atb",
            "1atb-name",
            "atb_name",
            "atb-abcdefghijklmnopq",
            "-atb",
            "atb name",
            "ätbx",
        ] {
            assert!(!valid_display_name(name), "{name}");
        }
    }
}
