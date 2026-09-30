//! Project provider declarations reuse the complete existing Admin create operation.
use super::{percent_encode, provider_config_management, routes, ProviderKind};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, ProviderConfigSeeds};
use fireemu_core_types::determinism::SplitMix64;
use serde_json::Value;
use std::sync::{Arc, Mutex};

/// Parses canonical project provider declarations without changing Admin validation or runtime trust. Diagnostics identify the config location and never include input bodies or credentials.
pub fn provider_config_seeds(value: &Value, strict: bool) -> Result<ProviderConfigSeeds, String> {
    if value.is_null() {
        return Ok(ProviderConfigSeeds::default());
    }
    let object = value
        .as_object()
        .ok_or("auth.providers must be an object")?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "oidc" | "saml"))
    {
        return Err("auth.providers accepts only oidc and saml".into());
    }
    let store = Arc::new(Mutex::new(AuthStore::new(
        "config-validation",
        SplitMix64::new(0),
        TotpPolicy::default(),
    )));
    let mut seeds = ProviderConfigSeeds::default();
    for (key, kind, parameter) in [
        ("oidc", ProviderKind::Oidc, "oauthIdpConfigId"),
        ("saml", ProviderKind::Saml, "inboundSamlConfigId"),
    ] {
        let Some(value) = object.get(key).filter(|value| !value.is_null()) else {
            continue;
        };
        let entries = value
            .as_array()
            .ok_or_else(|| format!("auth.providers.{key} must be an array"))?;
        for (index, body) in entries.iter().enumerate() {
            let location = format!("auth.providers.{key}[{index}]");
            let name = body.get("name").and_then(Value::as_str).ok_or_else(|| {
                format!("{location}.name must use the provider id form ({key}.<id>)")
            })?;
            if name.contains('/') {
                return Err(format!("{location}.name must use the provider id form ({key}.<id>), not a full resource name"));
            }
            let query = format!("{parameter}={}", percent_encode(name));
            let response = provider_config_management(
                &store,
                routes::Handler::ProviderCreate,
                kind,
                Some("config-validation"),
                None,
                None,
                Some(&query),
                body,
                strict,
            );
            if response.status != 200 {
                let message = response.body["error"]["message"]
                    .as_str()
                    .unwrap_or("INVALID_ARGUMENT");
                return Err(format!("{location}: {message}"));
            }
        }
        let parsed = store.lock().map_err(|_| "auth.providers: INTERNAL")?;
        match kind {
            ProviderKind::Oidc => seeds.oidc = Some(parsed.oidc_configs().cloned().collect()),
            ProviderKind::Saml => seeds.saml = Some(parsed.saml_configs().cloned().collect()),
            ProviderKind::DefaultSupported => {
                unreachable!("canonical seeds contain only custom providers")
            }
        }
    }
    Ok(seeds)
}
