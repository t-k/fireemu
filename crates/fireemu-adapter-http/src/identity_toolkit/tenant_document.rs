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
/// Under the emulator profile, the tenant's `emailPrivacyConfig` as the official emulator keeps
/// it (firebase-tools 15.28.2): what masked updates wrote, as written, `false` included
/// (`applyMask`), and none from a create (`createTenant`). An update without a mask applies what
/// its body has, as every emulator-profile update without a mask does.
pub(super) const EMULATOR_PRIVACY: &str = "_tenantEmulatorEmailPrivacyConfig";

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

/// Installs the multi-factor config of a tenant the official emulator made on the way
/// (`getTenantProject`): enabled, for `PHONE_SMS`. It is the tenant's own config, read back as
/// written like an `mfaConfig` a create wrote.
pub(super) fn install_default_mfa(store: &mut AuthStore) {
    let config = MfaProjectConfig {
        state: fireemu_core_auth::mfa_config::MfaConfigState::Enabled,
        phone_sms: true,
        totp: None,
    };
    let mut members: StoredConfigMembers = store.stored_config_members().clone();
    members.set(
        "mfaConfig",
        Some(super::project_mfa::mfa_config_json(&config).to_string()),
    );
    store.set_mfa_config(config);
    store.set_stored_config_members(members);
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
    /// Under the emulator profile, the change to the `emailPrivacyConfig` it answers.
    emulator_privacy: Option<EmulatorPrivacyWrite>,
    /// A password policy write: the parsed body, the policy paths it touched, whether a policy
    /// is configured after it, and when it was written (the derived members production keeps).
    policy: Option<(Value, Vec<String>, bool, Option<String>)>,
}

/// A change to the `emailPrivacyConfig` the emulator profile answers: the update's paths,
/// applied to its body as the official emulator's `updateTenant` applies a mask (`applyMask`).
#[derive(Debug)]
pub(super) struct EmulatorPrivacyWrite {
    pub(super) paths: Vec<String>,
    pub(super) body: Value,
}

impl EmulatorPrivacyWrite {
    /// The member after this change, from the one before.
    fn applied(self, before: Option<Value>) -> Option<Value> {
        let Self { paths, body } = self;
        let written = body
            .get("emailPrivacyConfig")
            .filter(|value| !value.is_null());
        let mut after = before;
        for path in paths {
            match path.as_str() {
                "emailPrivacyConfig" => {
                    if let Some(written) = written {
                        after = Some(written.clone());
                    }
                }
                "emailPrivacyConfig.enableImprovedEmailPrivacy" => {
                    // `applyMask` makes the parent an object before it looks for the leaf, and
                    // skips a parent the update lacks or holds as no object.
                    let Some(Value::Object(written)) = written else {
                        continue;
                    };
                    let mut object = match after.take() {
                        Some(Value::Object(object)) => object,
                        _ => Map::new(),
                    };
                    if let Some(leaf) = written
                        .get("enableImprovedEmailPrivacy")
                        .filter(|value| !value.is_null())
                    {
                        object.insert("enableImprovedEmailPrivacy".to_owned(), leaf.clone());
                    }
                    after = Some(Value::Object(object));
                }
                _ => {}
            }
        }
        after
    }
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

    /// Records, under the emulator profile, the change to the `emailPrivacyConfig` it answers.
    pub(super) fn with_emulator_privacy(mut self, write: EmulatorPrivacyWrite) -> Self {
        self.emulator_privacy = Some(write);
        self
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
        if let Some(write) = self.emulator_privacy {
            let before = members
                .get(EMULATOR_PRIVACY)
                .and_then(|text| serde_json::from_str(text).ok());
            members.set(
                EMULATOR_PRIVACY,
                write.applied(before).map(|value| value.to_string()),
            );
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

/// The private markers of a tenant an export carries, with the project's exported private
/// members ([`project_config::EXPORTED_PRIVATE_MEMBERS`]) a tenant's password policy derives.
const EXPORTED_MARKERS: &[&str] = &[PRIVACY_WRITTEN, CLIENT_WRITTEN];
/// The private members an export carries as values: the emulator profile's `emailPrivacyConfig`.
const EXPORTED_VALUES: &[&str] = &[EMULATOR_PRIVACY];

/// A tenant's written members, as `(member, JSON text)` in member order, for an export: the
/// members kept as written, the markers of a written `emailPrivacyConfig` and `client`, and the
/// password policy's derived members. An import restores them ([`restore_tenant_members`]).
#[must_use]
pub fn exportable_tenant_members(members: &StoredConfigMembers) -> Vec<(String, String)> {
    WRITTEN_MEMBERS
        .iter()
        .chain(EXPORTED_MARKERS)
        .chain(EXPORTED_VALUES)
        .chain(project_config::EXPORTED_PRIVATE_MEMBERS)
        .filter_map(|member| {
            members.get(member).map(|text| {
                (
                    project_config::exported_name(member).to_owned(),
                    text.to_owned(),
                )
            })
        })
        .collect()
}

/// Installs a tenant's exported members in `store`, the tenant's own and still empty of them.
/// Each written member is parsed and checked as a tenant write of it is, and installed as that
/// write installs it (`mfaConfig` and `testPhoneNumbers` also where sign-in reads them); a
/// marker must be `true` and a derived member a value a write could have stored. `Err` names
/// the first member refused, before anything is installed.
pub fn restore_tenant_members(
    store: &mut AuthStore,
    members: &[(String, String)],
) -> Result<(), String> {
    let PreparedTenantMembers {
        written,
        private,
        refused,
    } = prepared_tenant_members(members)?;
    // `apply` refuses before it changes anything.
    written.apply(store).map_err(|_| refused)?;
    let mut installed = store.stored_config_members().clone();
    for (member, value) in private {
        installed.set(&member, Some(value.to_string()));
    }
    store.set_stored_config_members(installed);
    Ok(())
}

/// A tenant's exported members, checked and ready to install.
struct PreparedTenantMembers {
    written: WrittenMembers,
    /// The private members, by their stored names.
    private: Vec<(String, Value)>,
    /// The refusal naming the first written member, for a store that refuses them.
    refused: String,
}

fn prepared_tenant_members(members: &[(String, String)]) -> Result<PreparedTenantMembers, String> {
    let mut body = Map::new();
    let mut private = Vec::new();
    let private_members: Vec<&str> = EXPORTED_MARKERS
        .iter()
        .chain(EXPORTED_VALUES)
        .chain(project_config::EXPORTED_PRIVATE_MEMBERS)
        .copied()
        .collect();
    for (name, text) in members {
        let member = &project_config::stored_name(name, &private_members).to_owned();
        let is_private = name != member;
        if body.contains_key(member) || private.iter().any(|(seen, _)| seen == member) {
            return Err(format!("tenant member {member:?} is repeated"));
        }
        let value: Value = serde_json::from_str(text)
            .map_err(|_| format!("tenant member {member:?} is not JSON"))?;
        let written = !is_private && WRITTEN_MEMBERS.contains(&member.as_str());
        let valid = if written {
            !value.is_null()
        } else if !is_private {
            return Err(format!("tenant member {member:?} is not a written member"));
        } else if EXPORTED_MARKERS.contains(&member.as_str()) {
            value == Value::Bool(true)
        } else if EXPORTED_VALUES.contains(&member.as_str()) {
            value.is_object()
        } else {
            project_config::valid_private_member(member, &value)
        };
        if !valid {
            return Err(format!("tenant member {member:?} is not a valid value"));
        }
        if written {
            body.insert(member.clone(), value);
        } else {
            private.push((member.clone(), value));
        }
    }
    let first = body.keys().next().cloned().unwrap_or_default();
    let refused = format!("tenant member {first:?} is not a valid value");
    let parsed = super::config_proto::parse_tenant_body(&Value::Object(body.clone()))
        .map_err(|_| refused.clone())?;
    let written = WrittenMembers::from_body(&parsed, |member| body.contains_key(member))
        .map_err(|_| refused.clone())?;
    Ok(PreparedTenantMembers {
        written,
        private,
        refused,
    })
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
    emulator: bool,
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
    // The emulator profile answers the member as the official emulator keeps it; its privacy
    // behaviour reads the project's (issue
    // emulator-tenant-document-shows-the-projects-email-privacy, 2026-09-29).
    if emulator {
        if let Some(privacy) = stored(EMULATOR_PRIVACY) {
            document.insert("emailPrivacyConfig".to_owned(), privacy);
        }
    } else if metadata.enable_improved_email_privacy {
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
    use super::{exportable_tenant_members, restore_tenant_members, valid_display_name};
    use fireemu_core_auth::mfa::TotpPolicy;
    use fireemu_core_auth::mfa_config::MfaConfigState;
    use fireemu_core_auth::store::AuthStore;
    use fireemu_core_types::determinism::SplitMix64;
    use serde_json::json;

    fn member(name: &str, value: &serde_json::Value) -> (String, String) {
        (name.to_owned(), value.to_string())
    }

    /// Issue strict-multi-tenancy-switch-lost-on-export-import: a tenant's written members.
    #[test]
    fn a_tenants_members_restore_as_written_and_install_what_sign_in_reads() {
        let members = vec![
            member(
                "mfaConfig",
                &json!({"state": "ENABLED", "enabledProviders": ["PHONE_SMS"]}),
            ),
            member("testPhoneNumbers", &json!({"+15555550100": "123456"})),
            member("monitoring", &json!({"requestLogging": {"enabled": true}})),
            member("tenantEmailPrivacyConfigWritten", &json!(true)),
            member("tenantClientWritten", &json!(true)),
            member(
                "passwordPolicyLastUpdateTime",
                &json!("2026-09-27T17:26:19.375Z"),
            ),
        ];
        let mut store = AuthStore::new("demo-app", SplitMix64::new(5), TotpPolicy::default());
        restore_tenant_members(&mut store, &members).expect("valid members restore");
        assert_eq!(store.mfa_config().state, MfaConfigState::Enabled);
        assert!(store.mfa_config().phone_sms);
        assert_eq!(
            store
                .sign_in_config()
                .test_phone_numbers
                .get("+15555550100")
                .map(String::as_str),
            Some("123456")
        );
        assert_eq!(
            store.stored_config_members().get("_tenantClientWritten"),
            Some("true")
        );
        let mut exported = exportable_tenant_members(store.stored_config_members());
        let mut expected = members.clone();
        exported.sort();
        expected.sort();
        assert_eq!(exported, expected);
    }

    #[test]
    fn a_tenant_member_a_write_would_refuse_refuses_the_import() {
        for members in [
            vec![member("mfaConfig", &json!({"state": "SOMETIMES"}))],
            vec![member(
                "testPhoneNumbers",
                &json!({"not a number": "123456"}),
            )],
            vec![member("mfaConfig", &json!(null))],
            vec![member("displayName", &json!("atb-x"))],
            vec![member("_tenantClientWritten", &json!(true))],
            vec![member("tenantClientWritten", &json!(false))],
            vec![member("tenantEmailPrivacyConfigWritten", &json!("true"))],
            vec![member("passwordPolicyLastUpdateTime", &json!("never"))],
            vec![("monitoring".to_owned(), "not json".to_owned())],
            vec![
                member("monitoring", &json!({})),
                member("monitoring", &json!({})),
            ],
        ] {
            let mut store = AuthStore::new("demo-app", SplitMix64::new(5), TotpPolicy::default());
            let before = store.stored_config_members().clone();
            assert!(
                restore_tenant_members(&mut store, &members).is_err(),
                "{members:?}"
            );
            assert_eq!(store.stored_config_members(), &before, "{members:?}");
        }
    }

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
