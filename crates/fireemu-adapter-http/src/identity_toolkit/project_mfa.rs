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

fn state_from(value: Option<&Value>) -> Result<MfaConfigState, ()> {
    match value {
        None | Some(Value::Null) => Ok(MfaConfigState::Disabled),
        Some(Value::String(name)) => match name.as_str() {
            "DISABLED" | "STATE_UNSPECIFIED" => Ok(MfaConfigState::Disabled),
            "ENABLED" => Ok(MfaConfigState::Enabled),
            "MANDATORY" => Ok(MfaConfigState::Mandatory),
            _ => Err(()),
        },
        Some(_) => Err(()),
    }
}

/// The read-back form of a project's multi-factor configuration.
#[must_use]
pub fn mfa_config_json(config: &MfaProjectConfig) -> Value {
    let mut out = Map::new();
    out.insert("state".to_owned(), json!(state_name(config.state)));
    if config.phone_sms {
        out.insert("enabledProviders".to_owned(), json!(["PHONE_SMS"]));
    }
    if let Some(totp) = config.totp {
        let mut entry = Map::new();
        if let Some(intervals) = totp.adjacent_intervals {
            entry.insert(
                "totpProviderConfig".to_owned(),
                json!({"adjacentIntervals": intervals}),
            );
        }
        entry.insert("state".to_owned(), json!(state_name(totp.state)));
        out.insert("providerConfigs".to_owned(), json!([entry]));
    }
    Value::Object(out)
}

/// A `mfa` member a PATCH sent, as a configuration, or `Err(())` when production would refuse it
/// (the adapter answers the refusal).
pub fn mfa_config_from_json(value: &Value) -> Result<MfaProjectConfig, ()> {
    let object = match value {
        Value::Null => return Ok(MfaProjectConfig::default()),
        Value::Object(object) => object,
        _ => return Err(()),
    };
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "state" | "enabledProviders" | "providerConfigs"
        )
    }) {
        return Err(());
    }
    let state = state_from(object.get("state"))?;
    let phone_sms = match object.get("enabledProviders") {
        None | Some(Value::Null) => false,
        Some(Value::Array(providers)) => {
            let mut phone_sms = false;
            for provider in providers {
                match provider.as_str() {
                    Some("PHONE_SMS") => phone_sms = true,
                    _ => return Err(()),
                }
            }
            phone_sms
        }
        Some(_) => return Err(()),
    };
    let totp = match object.get("providerConfigs") {
        None | Some(Value::Null) => None,
        Some(Value::Array(entries)) => {
            let mut totp = None;
            for entry in entries {
                let entry = entry.as_object().ok_or(())?;
                if entry
                    .keys()
                    .any(|key| !matches!(key.as_str(), "state" | "totpProviderConfig"))
                {
                    return Err(());
                }
                let adjacent_intervals = match entry.get("totpProviderConfig") {
                    None | Some(Value::Null) => None,
                    Some(Value::Object(config)) => {
                        if config.keys().any(|key| key != "adjacentIntervals") {
                            return Err(());
                        }
                        match config.get("adjacentIntervals") {
                            None | Some(Value::Null) => None,
                            Some(value) => Some(
                                value
                                    .as_u64()
                                    .and_then(|n| u8::try_from(n).ok())
                                    .filter(|n| *n <= MAX_ADJACENT_INTERVALS)
                                    .ok_or(())?,
                            ),
                        }
                    }
                    Some(_) => return Err(()),
                };
                if totp.is_some() {
                    return Err(());
                }
                totp = Some(TotpProviderConfig {
                    state: state_from(entry.get("state"))?,
                    adjacent_intervals,
                });
            }
            totp
        }
        Some(_) => return Err(()),
    };
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

    #[test]
    fn values_outside_the_documented_shape_are_refused() {
        for value in [
            json!("ENABLED"),
            json!({"state": "NOT_A_STATE"}),
            json!({"state": "ENABLED", "enabledProviders": ["NOT_A_PROVIDER"]}),
            json!({"state": "ENABLED", "providerConfigs": [{"state": "ENABLED", "totpProviderConfig": {"adjacentIntervals": 11}}]}),
            json!({"state": "ENABLED", "providerConfigs": [{"state": "ENABLED", "totpProviderConfig": {"adjacentIntervals": -1}}]}),
            json!({"state": "ENABLED", "unknown": true}),
            json!({"state": "ENABLED", "providerConfigs": [{"state": "ENABLED", "other": {}}]}),
        ] {
            assert!(mfa_config_from_json(&value).is_err(), "{value}");
        }
    }
}
