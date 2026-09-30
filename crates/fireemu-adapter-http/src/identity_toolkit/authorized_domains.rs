//! Startup domains use the Admin project's existing proto conversion and validation.

use serde_json::{json, Value};

use super::{config_proto, project_config, sign_in_config_from_update, JsonResponse, SignInConfig};

/// Parses a replacement domain list exactly as an Admin config PATCH under `strict` does.
/// Null clears the Admin list; the canonical config loader handles an undeclared seed itself.
/// Numeric and boolean entries become strings and null entries are omitted by proto conversion.
/// Refusals retain the Admin wire body, including its field location.
pub fn authorized_domains_from_json(
    value: &Value,
    strict: bool,
) -> Result<Vec<String>, JsonResponse> {
    let body = config_proto::parse_config_body(&json!({"authorizedDomains": value}))?;
    let fields = vec!["authorizedDomains".to_owned()];
    project_config::validate_values(&body, &fields, strict)?;
    let config = sign_in_config_from_update(&SignInConfig::default(), &body, &fields)?
        .expect("the authorizedDomains mask produces a sign-in update");
    Ok(config.authorized_domains.unwrap_or_default())
}
