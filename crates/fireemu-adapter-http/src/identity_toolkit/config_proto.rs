//! How production reads an Admin v2 project config body (`admin/v2/projects/{p}/config`
//! PATCH): as proto3 JSON of `google.cloud.identitytoolkit.admin.v2.Config` (sandbox
//! recordings 2026-09-25, AUTH-CONFIG-SDK). A body production cannot parse is refused with its
//! own `Invalid JSON payload received` / `Invalid value at` messages and a `google.rpc.BadRequest`
//! field violation; a body it can parse is returned normalized as production stores it:
//! booleans written as text or numbers read as booleans, letters in a test phone number read
//! as keypad digits, read-only members dropped.

use serde_json::{json, Map, Value};

use super::JsonResponse;

/// The shape of one proto field.
#[derive(Clone, Copy)]
enum Kind {
    Msg(&'static [Field]),
    List(&'static Kind),
    /// A map from text keys to the given kind.
    Map(&'static Kind),
    Enum(&'static str, &'static [&'static str]),
    Bool,
    Int32,
    Int64,
    Float,
    Str,
    /// A `google.protobuf.Duration` or `Timestamp` (text).
    Text,
    /// A member production accepts that this module does not model; passed through unchecked.
    Opaque,
}

#[derive(Clone, Copy)]
struct Field {
    json: &'static str,
    proto: &'static str,
    kind: Kind,
    /// Output only: accepted in a body and ignored.
    read_only: bool,
    /// The oneof the field belongs to.
    oneof: Option<&'static str>,
}

const fn f(json: &'static str, proto: &'static str, kind: Kind) -> Field {
    Field {
        json,
        proto,
        kind,
        read_only: false,
        oneof: None,
    }
}

const fn ro(json: &'static str, proto: &'static str, kind: Kind) -> Field {
    Field {
        json,
        proto,
        kind,
        read_only: true,
        oneof: None,
    }
}

const fn one(json: &'static str, proto: &'static str, kind: Kind, oneof: &'static str) -> Field {
    Field {
        json,
        proto,
        kind,
        read_only: false,
        oneof: Some(oneof),
    }
}

const PREFIX: &str = "google.cloud.identitytoolkit.admin.v2";

const PERMISSIONS: &[Field] = &[
    f("disabledUserSignup", "disabled_user_signup", Kind::Bool),
    f("disabledUserDeletion", "disabled_user_deletion", Kind::Bool),
];
const CLIENT: &[Field] = &[
    ro("apiKey", "api_key", Kind::Str),
    ro("firebaseSubdomain", "firebase_subdomain", Kind::Str),
    f("permissions", "permissions", Kind::Msg(PERMISSIONS)),
];
const STRENGTH: &[Field] = &[
    f("minPasswordLength", "min_password_length", Kind::Int32),
    f("maxPasswordLength", "max_password_length", Kind::Int32),
    f(
        "containsLowercaseCharacter",
        "contains_lowercase_character",
        Kind::Bool,
    ),
    f(
        "containsUppercaseCharacter",
        "contains_uppercase_character",
        Kind::Bool,
    ),
    f(
        "containsNumericCharacter",
        "contains_numeric_character",
        Kind::Bool,
    ),
    f(
        "containsNonAlphanumericCharacter",
        "contains_non_alphanumeric_character",
        Kind::Bool,
    ),
];
const POLICY_VERSION: &[Field] = &[
    f(
        "customStrengthOptions",
        "custom_strength_options",
        Kind::Msg(STRENGTH),
    ),
    ro("schemaVersion", "schema_version", Kind::Int32),
];
const POLICY_VERSION_KIND: Kind = Kind::Msg(POLICY_VERSION);
const POLICY: &[Field] = &[
    f(
        "passwordPolicyEnforcementState",
        "password_policy_enforcement_state",
        Kind::Enum(
            "PasswordPolicyConfig.PasswordPolicyEnforcementState",
            &[
                "PASSWORD_POLICY_ENFORCEMENT_STATE_UNSPECIFIED",
                "OFF",
                "ENFORCE",
            ],
        ),
    ),
    f(
        "passwordPolicyVersions",
        "password_policy_versions",
        Kind::List(&POLICY_VERSION_KIND),
    ),
    f(
        "forceUpgradeOnSignin",
        "force_upgrade_on_signin",
        Kind::Bool,
    ),
    ro("lastUpdateTime", "last_update_time", Kind::Text),
];
const EMAIL: &[Field] = &[
    f("enabled", "enabled", Kind::Bool),
    f("passwordRequired", "password_required", Kind::Bool),
];
const STR_KIND: Kind = Kind::Str;
const PHONE: &[Field] = &[
    f("enabled", "enabled", Kind::Bool),
    f(
        "testPhoneNumbers",
        "test_phone_numbers",
        Kind::Map(&STR_KIND),
    ),
];
const ANONYMOUS: &[Field] = &[f("enabled", "enabled", Kind::Bool)];
const SIGN_IN: &[Field] = &[
    f("email", "email", Kind::Msg(EMAIL)),
    f("phoneNumber", "phone_number", Kind::Msg(PHONE)),
    ro("hashConfig", "hash_config", Kind::Opaque),
    f("allowDuplicateEmails", "allow_duplicate_emails", Kind::Bool),
    f("anonymous", "anonymous", Kind::Msg(ANONYMOUS)),
];
const TEMPORARY_QUOTA: &[Field] = &[
    f("quota", "quota", Kind::Int64),
    f("startTime", "start_time", Kind::Text),
    f("quotaDuration", "quota_duration", Kind::Text),
];
const QUOTA: &[Field] = &[
    f(
        "signUpQuotaConfig",
        "sign_up_quota_config",
        Kind::Msg(TEMPORARY_QUOTA),
    ),
    // fireemu's own quota simulation (fireemuOnly), configured through the same member.
    f("quotaSimulation", "quota_simulation", Kind::Opaque),
];
const REGIONS_KIND: Kind = Kind::Str;
const ALLOW_BY_DEFAULT: &[Field] = &[f(
    "disallowedRegions",
    "disallowed_regions",
    Kind::List(&REGIONS_KIND),
)];
const ALLOWLIST_ONLY: &[Field] = &[f(
    "allowedRegions",
    "allowed_regions",
    Kind::List(&REGIONS_KIND),
)];
const SMS_REGION: &[Field] = &[
    one(
        "allowByDefault",
        "allow_by_default",
        Kind::Msg(ALLOW_BY_DEFAULT),
        "sms_region_policy",
    ),
    one(
        "allowlistOnly",
        "allowlist_only",
        Kind::Msg(ALLOWLIST_ONLY),
        "sms_region_policy",
    ),
];
const MOBILE_LINKS: &[Field] = &[f(
    "domain",
    "domain",
    Kind::Enum(
        "MobileLinksConfig.Domain",
        &[
            "DOMAIN_UNSPECIFIED",
            "FIREBASE_DYNAMIC_LINK_DOMAIN",
            "HOSTING_DOMAIN",
        ],
    ),
)];
const RECAPTCHA_STATE: Kind = Kind::Enum(
    "RecaptchaConfig.RecaptchaProviderEnforcementState",
    &[
        "RECAPTCHA_PROVIDER_ENFORCEMENT_STATE_UNSPECIFIED",
        "OFF",
        "AUDIT",
        "ENFORCE",
    ],
);
const RECAPTCHA_ACTION: Kind = Kind::Enum(
    "RecaptchaManagedRule.RecaptchaAction",
    &["RECAPTCHA_ACTION_UNSPECIFIED", "BLOCK"],
);
const MANAGED_RULE: &[Field] = &[
    f("endScore", "end_score", Kind::Float),
    f("action", "action", RECAPTCHA_ACTION),
];
const MANAGED_RULE_KIND: Kind = Kind::Msg(MANAGED_RULE);
const TOLL_FRAUD_RULE: &[Field] = &[
    f("startScore", "start_score", Kind::Float),
    f("action", "action", RECAPTCHA_ACTION),
];
const TOLL_FRAUD_RULE_KIND: Kind = Kind::Msg(TOLL_FRAUD_RULE);
const RECAPTCHA_KEY: &[Field] = &[
    f("key", "key", Kind::Str),
    f(
        "type",
        "type",
        Kind::Enum(
            "RecaptchaKey.ClientType",
            &["CLIENT_TYPE_UNSPECIFIED", "WEB", "IOS", "ANDROID"],
        ),
    ),
];
const RECAPTCHA_KEY_KIND: Kind = Kind::Msg(RECAPTCHA_KEY);
const RECAPTCHA: &[Field] = &[
    f(
        "emailPasswordEnforcementState",
        "email_password_enforcement_state",
        RECAPTCHA_STATE,
    ),
    f(
        "phoneEnforcementState",
        "phone_enforcement_state",
        RECAPTCHA_STATE,
    ),
    f(
        "managedRules",
        "managed_rules",
        Kind::List(&MANAGED_RULE_KIND),
    ),
    f(
        "recaptchaKeys",
        "recaptcha_keys",
        Kind::List(&RECAPTCHA_KEY_KIND),
    ),
    f("useAccountDefender", "use_account_defender", Kind::Bool),
    f("useSmsBotScore", "use_sms_bot_score", Kind::Bool),
    f(
        "useSmsTollFraudProtection",
        "use_sms_toll_fraud_protection",
        Kind::Bool,
    ),
    f(
        "tollFraudManagedRules",
        "toll_fraud_managed_rules",
        Kind::List(&TOLL_FRAUD_RULE_KIND),
    ),
];
const REQUEST_LOGGING: &[Field] = &[f("enabled", "enabled", Kind::Bool)];
const MONITORING: &[Field] = &[f(
    "requestLogging",
    "request_logging",
    Kind::Msg(REQUEST_LOGGING),
)];
const MULTI_TENANT: &[Field] = &[
    f("allowTenants", "allow_tenants", Kind::Bool),
    f(
        "defaultTenantLocation",
        "default_tenant_location",
        Kind::Str,
    ),
];
const DOMAINS_KIND: Kind = Kind::Str;
const CONFIG: &[Field] = &[
    ro("name", "name", Kind::Str),
    f("signIn", "sign_in", Kind::Msg(SIGN_IN)),
    f("notification", "notification", Kind::Opaque),
    f("quota", "quota", Kind::Msg(QUOTA)),
    f("monitoring", "monitoring", Kind::Msg(MONITORING)),
    f("multiTenant", "multi_tenant", Kind::Msg(MULTI_TENANT)),
    f(
        "authorizedDomains",
        "authorized_domains",
        Kind::List(&DOMAINS_KIND),
    ),
    ro(
        "subtype",
        "subtype",
        Kind::Enum(
            "Config.Subtype",
            &["SUBTYPE_UNSPECIFIED", "IDENTITY_PLATFORM", "FIREBASE_AUTH"],
        ),
    ),
    f("client", "client", Kind::Msg(CLIENT)),
    f("mfa", "mfa", Kind::Opaque),
    f("blockingFunctions", "blocking_functions", Kind::Opaque),
    f(
        "smsRegionConfig",
        "sms_region_config",
        Kind::Msg(SMS_REGION),
    ),
    ro("defaultHostingSite", "default_hosting_site", Kind::Str),
    f(
        "emailPrivacyConfig",
        "email_privacy_config",
        Kind::Msg(&[f(
            "enableImprovedEmailPrivacy",
            "enable_improved_email_privacy",
            Kind::Bool,
        )]),
    ),
    f(
        "passwordPolicyConfig",
        "password_policy_config",
        Kind::Msg(POLICY),
    ),
    f("recaptchaConfig", "recaptcha_config", Kind::Msg(RECAPTCHA)),
    f(
        "mobileLinksConfig",
        "mobile_links_config",
        Kind::Msg(MOBILE_LINKS),
    ),
    f(
        "autodeleteAnonymousUsers",
        "autodelete_anonymous_users",
        Kind::Bool,
    ),
];

/// Production's `400 INVALID_ARGUMENT` with a `google.rpc.BadRequest` field violation.
#[allow(clippy::needless_pass_by_value)]
fn violation(field: Option<&str>, description: String) -> JsonResponse {
    let mut detail = json!({"description": description});
    if let Some(field) = field {
        detail["field"] = json!(field);
    }
    JsonResponse {
        status: 400,
        body: json!({"error": {
            "code": 400,
            "message": description,
            "status": "INVALID_ARGUMENT",
            "details": [{
                "@type": "type.googleapis.com/google.rpc.BadRequest",
                "fieldViolations": [detail],
            }],
        }}),
    }
}

/// Production's `400 INVALID_ARGUMENT` for a value it parsed but will not take
/// (`INVALID_CONFIG : ...`, `INVALID_AUTHORIZED_DOMAIN : ...`).
pub(super) fn refusal(message: &str) -> JsonResponse {
    JsonResponse {
        status: 400,
        body: json!({"error": {"code": 400, "message": message, "status": "INVALID_ARGUMENT"}}),
    }
}

fn invalid_value(path: &str, kind: &str, value: &Value) -> JsonResponse {
    violation(
        Some(path),
        format!("Invalid value at '{path}' ({kind}), {value}"),
    )
}

/// Reads a JSON value as a proto bool: literals, and text or numbers production reads as one.
fn parse_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => n.as_f64().map(|n| n != 0.0),
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" | "t" | "y" => Some(true),
            "false" | "no" | "0" | "f" | "n" | "" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn parse_integer(value: &Value, bits: u32) -> Option<i64> {
    let parsed = match value {
        Value::Number(n) => n.as_i64().or_else(|| {
            // An integral float within i64 (such as 12.0) reads as that integer.
            #[allow(clippy::cast_possible_truncation)]
            n.as_f64()
                .filter(|f| f.fract() == 0.0 && f.abs() < 9.2e18)
                .map(|f| f as i64)
        }),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }?;
    (bits == 64 || i32::try_from(parsed).is_ok()).then_some(parsed)
}

/// A test phone number as production stores it: letters read as the digits of a phone keypad.
pub(super) fn keypad_number(number: &str) -> String {
    number
        .chars()
        .map(|c| match c.to_ascii_lowercase() {
            'a'..='c' => '2',
            'd'..='f' => '3',
            'g'..='i' => '4',
            'j'..='l' => '5',
            'm'..='o' => '6',
            'p'..='s' => '7',
            't'..='v' => '8',
            'w'..='z' => '9',
            _ => c,
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
fn check(value: &Value, kind: Kind, path: &str) -> Result<Option<Value>, JsonResponse> {
    if value.is_null() {
        return Ok(None);
    }
    match kind {
        Kind::Opaque => Ok(Some(value.clone())),
        Kind::Bool => parse_bool(value)
            .map(|b| Some(json!(b)))
            .ok_or_else(|| invalid_value(path, "TYPE_BOOL", value)),
        Kind::Int32 => parse_integer(value, 32)
            .map(|n| Some(json!(n)))
            .ok_or_else(|| invalid_value(path, "TYPE_INT32", value)),
        Kind::Int64 => parse_integer(value, 64)
            .map(|n| Some(json!(n.to_string())))
            .ok_or_else(|| invalid_value(path, "TYPE_INT64", value)),
        Kind::Float => match value {
            Value::Number(_) => Ok(Some(value.clone())),
            Value::String(s) if s.parse::<f64>().is_ok() => Ok(Some(json!(s.parse::<f64>().ok()))),
            _ => Err(invalid_value(path, "TYPE_FLOAT", value)),
        },
        Kind::Str | Kind::Text => match value {
            Value::String(_) => Ok(Some(value.clone())),
            Value::Number(_) | Value::Bool(_) => Ok(Some(json!(value.to_string()))),
            _ => Err(invalid_value(path, "TYPE_STRING", value)),
        },
        Kind::Enum(name, values) => match value.as_str() {
            Some(text) if values.contains(&text) => Ok(Some(value.clone())),
            _ => Err(invalid_value(
                path,
                &format!("type.googleapis.com/{PREFIX}.{name}"),
                value,
            )),
        },
        Kind::List(inner) => {
            let Some(items) = value.as_array() else {
                return Err(violation(
                    Some(path),
                    format!("Invalid value at '{path}', Proto field is repeated but value is not a list"),
                ));
            };
            let mut out = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                if let Some(item) = check(item, *inner, &format!("{path}[{index}]"))? {
                    out.push(item);
                }
            }
            Ok(Some(Value::Array(out)))
        }
        Kind::Map(inner) => {
            let Some(object) = value.as_object() else {
                return Err(invalid_value(path, "map", value));
            };
            let mut out = Map::new();
            for (key, item) in object {
                if let Some(item) = check(item, *inner, &format!("{path}[{key}]"))? {
                    out.insert(key.clone(), item);
                }
            }
            Ok(Some(Value::Object(out)))
        }
        Kind::Msg(fields) => {
            let Some(object) = value.as_object() else {
                return Err(violation(
                    Some(path),
                    format!("Invalid value at '{path}', Starting a message with a scalar"),
                ));
            };
            let mut out = Map::new();
            let mut oneofs: Vec<&str> = Vec::new();
            for (key, item) in object {
                let Some(field) = fields
                    .iter()
                    .find(|field| field.json == key || field.proto == key)
                else {
                    return Err(violation(
                        Some(path),
                        format!(
                            "Invalid JSON payload received. Unknown name \"{key}\" at '{path}': Cannot find field."
                        ),
                    ));
                };
                if let Some(oneof) = field.oneof {
                    if !item.is_null() {
                        if oneofs.contains(&oneof) {
                            return Err(violation(
                                Some(path),
                                format!(
                                    "Invalid value at '{path}' (oneof), oneof field '{oneof}' is already set. Cannot set '{key}'"
                                ),
                            ));
                        }
                        oneofs.push(oneof);
                    }
                }
                let checked = check(item, field.kind, &format!("{path}.{}", field.proto))?;
                if field.read_only {
                    continue;
                }
                if let Some(checked) = checked {
                    out.insert(field.json.to_owned(), checked);
                }
            }
            Ok(Some(Value::Object(out)))
        }
    }
}

/// Parses an Admin config PATCH body as production does; the result is the body production
/// stores (read-only members dropped, loose scalars read as their fields' types, test phone
/// numbers in keypad digits).
pub(super) fn parse_config_body(body: &Value) -> Result<Value, JsonResponse> {
    if !body.is_object() {
        return Err(violation(
            None,
            "Invalid JSON payload received. Unknown name \"\": Root element must be a message."
                .to_owned(),
        ));
    }
    let mut parsed = check(body, Kind::Msg(CONFIG), "config")?.unwrap_or_else(|| json!({}));
    if let Some(numbers) = parsed
        .pointer_mut("/signIn/phoneNumber/testPhoneNumbers")
        .and_then(Value::as_object_mut)
    {
        let converted: Map<String, Value> = std::mem::take(numbers)
            .into_iter()
            .map(|(number, code)| (keypad_number(&number), code))
            .collect();
        *numbers = converted;
    }
    Ok(parsed)
}

/// Whether production knows `path` as a writable config path; an unknown or read-only path in
/// an update mask is ignored, as production ignores it.
pub(super) fn known_writable_path(path: &str) -> bool {
    let mut fields = CONFIG;
    let mut segments = path.split('.').peekable();
    while let Some(segment) = segments.next() {
        let Some(field) = fields
            .iter()
            .find(|f| f.json == segment || f.proto == segment)
        else {
            return false;
        };
        if field.read_only {
            return false;
        }
        match field.kind {
            Kind::Msg(inner) => fields = inner,
            // Below a member this module does not model, or a map, a path is taken to a bounded
            // depth (no config path is deeper).
            Kind::Opaque | Kind::Map(_) => return path.split('.').count() <= MAX_PATH_DEPTH,
            // Nothing lies below a scalar, an enum or a list.
            _ => return segments.peek().is_none(),
        }
        if segments.peek().is_none() {
            return true;
        }
    }
    true
}

/// The deepest update mask path taken below a member this module does not model.
const MAX_PATH_DEPTH: usize = 8;

#[cfg(test)]
mod tests {
    use super::{keypad_number, known_writable_path, parse_config_body};
    use serde_json::json;

    fn message(result: Result<serde_json::Value, super::JsonResponse>) -> String {
        result.unwrap_err().body["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn production_messages_for_bodies_it_cannot_parse() {
        assert_eq!(
            message(parse_config_body(&json!([]))),
            "Invalid JSON payload received. Unknown name \"\": Root element must be a message."
        );
        assert_eq!(
            message(parse_config_body(&json!({"unknownMember": true}))),
            "Invalid JSON payload received. Unknown name \"unknownMember\" at 'config': Cannot find field."
        );
        assert_eq!(
            message(parse_config_body(&json!({"passwordPolicyConfig": {
                "passwordPolicyVersions": [{"customStrengthOptions": {"containsEmoji": true}}]
            }}))),
            "Invalid JSON payload received. Unknown name \"containsEmoji\" at 'config.password_policy_config.password_policy_versions[0].custom_strength_options': Cannot find field."
        );
        assert_eq!(
            message(parse_config_body(&json!({"passwordPolicyConfig": {
                "passwordPolicyVersions": [{"customStrengthOptions": {"minPasswordLength": 6.5}}]
            }}))),
            "Invalid value at 'config.password_policy_config.password_policy_versions[0].custom_strength_options.min_password_length' (TYPE_INT32), 6.5"
        );
        assert_eq!(
            message(parse_config_body(&json!({"mobileLinksConfig": {"domain": "CUSTOM_DOMAIN"}}))),
            "Invalid value at 'config.mobile_links_config.domain' (type.googleapis.com/google.cloud.identitytoolkit.admin.v2.MobileLinksConfig.Domain), \"CUSTOM_DOMAIN\""
        );
        assert_eq!(
            message(parse_config_body(&json!({"smsRegionConfig": {"allowByDefault": {}, "allowlistOnly": {}}}))),
            "Invalid value at 'config.sms_region_config' (oneof), oneof field 'sms_region_policy' is already set. Cannot set 'allowlistOnly'"
        );
        assert_eq!(
            message(parse_config_body(
                &json!({"quota": {"signUpQuotaConfig": {"quota": "many"}}})
            )),
            "Invalid value at 'config.quota.sign_up_quota_config.quota' (TYPE_INT64), \"many\""
        );
        let root = parse_config_body(&json!([])).unwrap_err();
        assert!(root.body["error"]["details"][0]["fieldViolations"][0]
            .get("field")
            .is_none());
    }

    #[test]
    fn loose_values_read_as_production_stores_them() {
        let parsed = parse_config_body(&json!({
            "name": "projects/1/config",
            "emailPrivacyConfig": {"enableImprovedEmailPrivacy": "yes"},
            "client": {"permissions": {"disabledUserSignup": 1}},
            "signIn": {"phoneNumber": {"testPhoneNumbers": {"+1650555abcd": "123456"}}},
            "passwordPolicyConfig": {"passwordPolicyVersions": [{"schemaVersion": 7}]},
        }))
        .unwrap();
        assert_eq!(
            parsed,
            json!({
                "emailPrivacyConfig": {"enableImprovedEmailPrivacy": true},
                "client": {"permissions": {"disabledUserSignup": true}},
                "signIn": {"phoneNumber": {"testPhoneNumbers": {"+16505552223": "123456"}}},
                "passwordPolicyConfig": {"passwordPolicyVersions": [{}]},
            })
        );
        assert_eq!(keypad_number("+1 (650) FLOWERS"), "+1 (650) 3569377");
    }

    #[test]
    fn unknown_and_read_only_mask_paths_are_not_writable() {
        for path in [
            "emailPrivacyConfig",
            "client.permissions.disabledUserSignup",
            "quota.signUpQuotaConfig",
            "notification.defaultLocale",
            "authorizedDomains",
        ] {
            assert!(known_writable_path(path), "{path}");
        }
        for path in [
            "unknownMember",
            "signIn.unknownMember",
            "name",
            "subtype",
            "defaultHostingSite",
            "client.apiKey",
            "signIn.hashConfig",
            // Nothing lies below a scalar, an enum or a list.
            "autodeleteAnonymousUsers.a",
            "emailPrivacyConfig.enableImprovedEmailPrivacy.a",
            "recaptchaConfig.managedRules.a",
            "recaptchaConfig.emailPasswordEnforcementState.a",
        ] {
            assert!(!known_writable_path(path), "{path}");
        }
        // Below a member this module does not model, a path is taken to a bounded depth.
        assert!(known_writable_path(
            "notification.sendEmail.resetPasswordTemplate.subject"
        ));
        assert!(!known_writable_path(&format!(
            "notification{}",
            ".a".repeat(20)
        )));
    }
}
