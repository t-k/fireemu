//! The Admin v2 `Config.mfa` member: its JSON form and the values a PATCH may set.
//!
//! The read-back has production's shape (sandbox exploration 2026-09-24): `state`, then
//! `enabledProviders` and `providerConfigs` only when they hold something. Which values a PATCH
//! may set follows the AUTH-MFA recordings (`conformance/auth-mfa-production.json`,
//! `auth-mfa/config`).

use fireemu_core_auth::mfa_config::{MfaConfigState, MfaProjectConfig, TotpProviderConfig};
use serde_json::{json, Map, Value};

/// The widest TOTP window the Admin API documents (`adjacentIntervals` 0 to 10).
pub const MAX_ADJACENT_INTERVALS: u8 = 10;

const fn state_name(state: MfaConfigState) -> &'static str {
    match state {
        MfaConfigState::Disabled => "DISABLED",
        MfaConfigState::Enabled => "ENABLED",
        MfaConfigState::Mandatory => "MANDATORY",
    }
}

/// Why production refuses the `mfa` value a PATCH sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MfaConfigRefusal {
    /// An enum member names no value: refused while the request is parsed, with production's
    /// field path (snake case) and the enum's type.
    InvalidEnum {
        /// `config.mfa.state`, `config.mfa.enabled_providers[0]`, ...
        field: String,
        /// The enum type below `google.cloud.identitytoolkit.admin.v2.`.
        type_name: &'static str,
        /// The value sent.
        value: String,
    },
    /// `adjacentIntervals` outside 0 to 10.
    AdjacentIntervalRange,
    /// A member or type the API does not have.
    Shape,
}

/// The read-back form of a project's multi-factor configuration: an `adjacentIntervals` of 0
/// is omitted, as proto3 omits a default (`totpProviderConfig: {}`).
#[must_use]
pub fn mfa_config_json(config: &MfaProjectConfig) -> Value {
    let mut out = Map::new();
    out.insert("state".to_owned(), json!(state_name(config.state)));
    if config.phone_sms {
        out.insert("enabledProviders".to_owned(), json!(["PHONE_SMS"]));
    }
    if let Some(totp) = config.totp {
        let intervals = totp.adjacent_intervals.unwrap_or(0);
        let provider = if intervals == 0 {
            json!({})
        } else {
            json!({"adjacentIntervals": intervals})
        };
        out.insert(
            "providerConfigs".to_owned(),
            json!([{"state": state_name(totp.state), "totpProviderConfig": provider}]),
        );
    }
    Value::Object(out)
}

fn state_member(value: Option<&Value>, field: String) -> Result<MfaConfigState, MfaConfigRefusal> {
    match value {
        None | Some(Value::Null) => Ok(MfaConfigState::Disabled),
        Some(Value::String(name)) => match name.as_str() {
            "DISABLED" | "STATE_UNSPECIFIED" => Ok(MfaConfigState::Disabled),
            "ENABLED" => Ok(MfaConfigState::Enabled),
            "MANDATORY" => Ok(MfaConfigState::Mandatory),
            other => Err(MfaConfigRefusal::InvalidEnum {
                field,
                type_name: "MultiFactorAuthConfig.State",
                value: other.to_owned(),
            }),
        },
        Some(_) => Err(MfaConfigRefusal::Shape),
    }
}

/// A `mfa` member a PATCH sent, as a configuration, or production's refusal. A provider entry
/// without `totpProviderConfig` is dropped, as production drops it (sandbox recording
/// 2026-09-24).
pub fn mfa_config_from_json(value: &Value) -> Result<MfaProjectConfig, MfaConfigRefusal> {
    let object = match value {
        Value::Null => return Ok(MfaProjectConfig::default()),
        Value::Object(object) => object,
        _ => return Err(MfaConfigRefusal::Shape),
    };
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "state" | "enabledProviders" | "providerConfigs"
        )
    }) {
        return Err(MfaConfigRefusal::Shape);
    }
    let state = state_member(object.get("state"), "config.mfa.state".to_owned())?;
    let phone_sms = match object.get("enabledProviders") {
        None | Some(Value::Null) => false,
        Some(Value::Array(providers)) => {
            let mut phone_sms = false;
            for (index, provider) in providers.iter().enumerate() {
                match provider.as_str() {
                    Some("PHONE_SMS") => phone_sms = true,
                    Some("PROVIDER_UNSPECIFIED") => {}
                    Some(other) => {
                        return Err(MfaConfigRefusal::InvalidEnum {
                            field: format!("config.mfa.enabled_providers[{index}]"),
                            type_name: "MultiFactorAuthConfig.Provider",
                            value: other.to_owned(),
                        })
                    }
                    None => return Err(MfaConfigRefusal::Shape),
                }
            }
            phone_sms
        }
        Some(_) => return Err(MfaConfigRefusal::Shape),
    };
    let mut totp = None;
    match object.get("providerConfigs") {
        None | Some(Value::Null) => {}
        Some(Value::Array(entries)) => {
            for (index, entry) in entries.iter().enumerate() {
                let entry = entry.as_object().ok_or(MfaConfigRefusal::Shape)?;
                if entry
                    .keys()
                    .any(|key| !matches!(key.as_str(), "state" | "totpProviderConfig"))
                {
                    return Err(MfaConfigRefusal::Shape);
                }
                let entry_state = state_member(
                    entry.get("state"),
                    format!("config.mfa.provider_configs[{index}].state"),
                )?;
                let adjacent_intervals = match entry.get("totpProviderConfig") {
                    None | Some(Value::Null) => continue,
                    Some(Value::Object(config)) => {
                        if config.keys().any(|key| key != "adjacentIntervals") {
                            return Err(MfaConfigRefusal::Shape);
                        }
                        match config.get("adjacentIntervals") {
                            None | Some(Value::Null) => 0,
                            Some(value) => {
                                let n = value.as_i64().ok_or(MfaConfigRefusal::Shape)?;
                                u8::try_from(n)
                                    .ok()
                                    .filter(|n| *n <= MAX_ADJACENT_INTERVALS)
                                    .ok_or(MfaConfigRefusal::AdjacentIntervalRange)?
                            }
                        }
                    }
                    Some(_) => return Err(MfaConfigRefusal::Shape),
                };
                totp = Some(TotpProviderConfig {
                    state: entry_state,
                    adjacent_intervals: Some(adjacent_intervals),
                });
            }
        }
        Some(_) => return Err(MfaConfigRefusal::Shape),
    }
    Ok(MfaProjectConfig {
        state,
        phone_sms,
        totp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The value the AUTH-MFA programs run under reads back exactly as sent (sandbox
    /// exploration 2026-09-24).
    #[test]
    fn the_enabled_program_config_round_trips() {
        let sent = json!({
            "state": "ENABLED",
            "enabledProviders": ["PHONE_SMS"],
            "providerConfigs": [{"state": "ENABLED", "totpProviderConfig": {"adjacentIntervals": 5}}],
        });
        let config = mfa_config_from_json(&sent).unwrap();
        assert!(config.sms_enabled() && config.totp_enabled());
        assert_eq!(config.totp_window(), Some(5));
        assert_eq!(mfa_config_json(&config), sent);
    }

    #[test]
    fn a_new_project_reads_back_disabled_only() {
        assert_eq!(
            mfa_config_json(&MfaProjectConfig::default()),
            json!({"state": "DISABLED"})
        );
        assert_eq!(
            mfa_config_from_json(&json!({"state": "DISABLED"})).unwrap(),
            MfaProjectConfig::default()
        );
    }

    /// Production's read-back of the values the config program sent (sandbox recording
    /// 2026-09-24, `auth-mfa/config`).
    #[test]
    fn values_read_back_as_production_does() {
        let totp = |entry: Value| json!({"state": "ENABLED", "providerConfigs": [entry]});
        for (sent, read_back) in [
            (
                totp(json!({"state": "ENABLED", "totpProviderConfig": {"adjacentIntervals": 0}})),
                totp(json!({"state": "ENABLED", "totpProviderConfig": {}})),
            ),
            (
                totp(json!({"state": "ENABLED"})),
                json!({"state": "ENABLED"}),
            ),
            (
                totp(json!({"state": "DISABLED", "totpProviderConfig": {"adjacentIntervals": 5}})),
                totp(json!({"state": "DISABLED", "totpProviderConfig": {"adjacentIntervals": 5}})),
            ),
            (
                json!({"state": "MANDATORY", "enabledProviders": ["PHONE_SMS"]}),
                json!({"state": "MANDATORY", "enabledProviders": ["PHONE_SMS"]}),
            ),
        ] {
            let config = mfa_config_from_json(&sent).unwrap();
            assert_eq!(mfa_config_json(&config), read_back, "{sent}");
        }
    }

    #[test]
    fn refusals_name_what_production_names() {
        let range = json!({"state": "ENABLED", "providerConfigs": [{"state": "ENABLED", "totpProviderConfig": {"adjacentIntervals": 11}}]});
        assert_eq!(
            mfa_config_from_json(&range),
            Err(MfaConfigRefusal::AdjacentIntervalRange)
        );
        let negative = json!({"state": "ENABLED", "providerConfigs": [{"state": "ENABLED", "totpProviderConfig": {"adjacentIntervals": -1}}]});
        assert_eq!(
            mfa_config_from_json(&negative),
            Err(MfaConfigRefusal::AdjacentIntervalRange)
        );
        assert_eq!(
            mfa_config_from_json(&json!({"state": "NOT_A_STATE"})),
            Err(MfaConfigRefusal::InvalidEnum {
                field: "config.mfa.state".to_owned(),
                type_name: "MultiFactorAuthConfig.State",
                value: "NOT_A_STATE".to_owned(),
            })
        );
        assert_eq!(
            mfa_config_from_json(
                &json!({"state": "ENABLED", "enabledProviders": ["NOT_A_PROVIDER"]})
            ),
            Err(MfaConfigRefusal::InvalidEnum {
                field: "config.mfa.enabled_providers[0]".to_owned(),
                type_name: "MultiFactorAuthConfig.Provider",
                value: "NOT_A_PROVIDER".to_owned(),
            })
        );
    }

    #[test]
    fn values_outside_the_documented_shape_are_refused() {
        for value in [
            json!("ENABLED"),
            json!({"state": "ENABLED", "unknown": true}),
            json!({"state": "ENABLED", "providerConfigs": [{"state": "ENABLED", "other": {}}]}),
        ] {
            assert_eq!(
                mfa_config_from_json(&value),
                Err(MfaConfigRefusal::Shape),
                "{value}"
            );
        }
    }
}
