//! The Auth Emulator identity-provider login widget pages (`/emulator/auth/handler` and
//! `/emulator/auth/iframe`) the JS SDK opens for a sign-in-with-popup / redirect handoff.
//!
//! The static page bytes are the pinned firebase-tools ones (`widget_templates`); only the
//! provider-account list is built here from the session's store. Unlike the official
//! emulator, every value injected into that list is HTML-escaped: the list renders account
//! display names, emails and photo URLs that a caller controls, and an unescaped value would
//! be stored cross-site scripting in a page the developer opens in their own browser. This is
//! the recorded `auth.idpWidgetHtmlEscaping` divergence. The page still only speaks to a
//! loopback caller: the emulator serves it to any origin, and so does fireemu, but it carries
//! no secret and mints no credential -- the credential is minted by `signInWithIdp`, which is
//! guarded independently.

use std::sync::{Arc, Mutex};

use fireemu_core_auth::store::AuthStore;

use super::{query_params, AuthState};
use crate::identity_toolkit::widget_templates::{
    IFRAME_HTML, WIDGET_AFTER_PROVIDERS, WIDGET_BEFORE_PROVIDERS,
};

/// A rendered widget response: HTML on success, a small JSON error otherwise.
pub struct WidgetResponse {
    /// HTTP status.
    pub status: u16,
    /// `Content-Type` value.
    pub content_type: &'static str,
    /// The body.
    pub body: String,
}

/// Whether `path` (already stripped of its query) is a widget page this module serves.
#[must_use]
pub fn is_widget_path(path: &str) -> bool {
    matches!(path, "/emulator/auth/handler" | "/emulator/auth/iframe")
}

/// Renders the widget page for `path` (already stripped of its query) with its `query`.
#[must_use]
pub fn render(state: &AuthState, path: &str, query: Option<&str>) -> WidgetResponse {
    match path {
        "/emulator/auth/iframe" => WidgetResponse {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body: IFRAME_HTML.to_owned(),
        },
        "/emulator/auth/handler" => render_handler(state, query),
        // `is_widget_path` gates callers, so this arm is unreachable in practice.
        _ => json_error(404, "not found"),
    }
}

/// The sign-in handoff page: the accounts already known at the provider, offered for reuse.
fn render_handler(state: &AuthState, query: Option<&str>) -> WidgetResponse {
    let params = query_params(query);
    let api_key = params.get("apiKey").filter(|k| !k.is_empty());
    let provider_id = params.get("providerId").filter(|p| !p.is_empty());
    let (Some(api_key), Some(provider_id)) = (api_key, provider_id) else {
        return json_error(400, "missing apiKey or providerId query parameters");
    };
    let store_arc = store_for_api_key(state, api_key);
    let Ok(store) = store_arc.lock() else {
        return json_error(500, "internal error");
    };
    let list = provider_list_html(&store, provider_id);
    let html = format!("{WIDGET_BEFORE_PROVIDERS}{list}{WIDGET_AFTER_PROVIDERS}");
    WidgetResponse {
        status: 200,
        content_type: "text/html; charset=utf-8",
        body: html,
    }
}

/// The `<li>` reuse-account items for every identity linked at `provider_id`.
fn provider_list_html(store: &AuthStore, provider_id: &str) -> String {
    store
        .provider_infos(provider_id)
        .iter()
        .map(|info| {
            let claims = fake_claims_json(info);
            let id_token = encode_uri_component(&claims);
            let graphic = match info.photo_url.as_deref().filter(|p| !p.is_empty()) {
                Some(photo) => format!(
                    "\n            <span class=\"mdc-list-item__graphic profile-photo\" style=\"background-image: url('{}')\"></span>",
                    escape_html(photo)
                ),
                None => "\n            <span class=\"mdc-list-item__graphic material-icons\" aria-hidden=true>person</span>".to_owned(),
            };
            let display = info
                .display_name
                .as_deref()
                .filter(|d| !d.is_empty())
                .map_or_else(|| "(No display name)".to_owned(), escape_html);
            let email = info.email.as_deref().map_or_else(String::new, escape_html);
            format!(
                "<li class=\"js-reuse-account mdc-list-item mdc-ripple-upgraded\" tabindex=\"0\" data-id-token=\"{id_token}\">\n          <span class=\"mdc-list-item__ripple\"></span>{graphic}\n          <span class=\"mdc-list-item__text\"><span class=\"mdc-list-item__primary-text\">{display}</span>\n          <span class=\"mdc-list-item__secondary-text fallback-secondary-text\" id=\"reuse-email\">{email}</span>\n      </li>"
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The fake OIDC claims the widget stores in `data-id-token` for an account
/// (`createFakeClaims`). Screen name is not modelled on a linked identity, so it is omitted.
fn fake_claims_json(info: &fireemu_core_auth::store::FederatedIdentity) -> String {
    let claims = serde_json::json!({
        "sub": info.raw_id,
        "iss": "",
        "aud": "",
        "exp": 0,
        "iat": 0,
        "name": info.display_name,
        "email": info.email,
        "email_verified": true,
        "picture": info.photo_url,
    });
    claims.to_string()
}

/// Resolves the store the widget's `apiKey` names: the registered session project's store when
/// the key is known, else the default session store (single-project mode).
fn store_for_api_key(state: &AuthState, api_key: &str) -> Arc<Mutex<AuthStore>> {
    if let Some(registry) = &state.registry {
        let project = state
            .tenancy
            .as_ref()
            .and_then(|t| t.read().ok())
            .and_then(|t| t.project_of_api_key(api_key).map(str::to_owned));
        if let Some(store) = project.and_then(|p| registry.store_for(&p)) {
            return store;
        }
    }
    state.store.clone()
}

/// The `{authEmulator:{error}}` envelope the widget returns for a bad request.
fn json_error(status: u16, message: &str) -> WidgetResponse {
    WidgetResponse {
        status,
        content_type: "application/json; charset=utf-8",
        body: serde_json::json!({ "authEmulator": { "error": message } }).to_string(),
    }
}

/// Minimal HTML-text/attribute escaping for the injected account values.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// `encodeURIComponent`: percent-encodes every byte except the unreserved set
/// `A-Za-z0-9 - _ . ! ~ * ' ( )`. The output is safe inside a double-quoted HTML attribute.
fn encode_uri_component(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
        {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{encode_uri_component, escape_html, is_widget_path};

    #[test]
    fn widget_paths_are_recognised() {
        assert!(is_widget_path("/emulator/auth/handler"));
        assert!(is_widget_path("/emulator/auth/iframe"));
        assert!(!is_widget_path("/emulator/auth/other"));
        assert!(!is_widget_path("/identitytoolkit.googleapis.com/v1/accounts:signInWithIdp"));
    }

    #[test]
    fn html_is_escaped_so_an_account_cannot_inject_markup() {
        let escaped = escape_html("<img src=x onerror=alert(1)>\"'&");
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(!escaped.contains('"'));
        assert_eq!(
            escaped,
            "&lt;img src=x onerror=alert(1)&gt;&quot;&#39;&amp;"
        );
    }

    #[test]
    fn uri_component_encoding_matches_encodeuricomponent() {
        assert_eq!(encode_uri_component("{\"a\":\"b c\"}"), "%7B%22a%22%3A%22b%20c%22%7D");
        assert_eq!(encode_uri_component("aA0-_.!~*'()"), "aA0-_.!~*'()");
    }
}
