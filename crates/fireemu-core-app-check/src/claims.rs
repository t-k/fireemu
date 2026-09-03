//! The App Check session-token claims (specification section 11).

use fireemu_core_types::time::LogicalInstant;

use crate::registry::{ProjectEpoch, RegisteredApp};

/// The issuer prefix every App Check token carries; the project number follows it.
pub const ISSUER_PREFIX: &str = "https://firebaseappcheck.googleapis.com/";

/// The exact issuer of a project.
#[must_use]
pub fn issuer_for(project_number: &str) -> String {
    format!("{ISSUER_PREFIX}{project_number}")
}

/// Both audiences a token must carry: the project number and the project ID.
#[must_use]
pub fn audiences_for(project_number: &str, project_id: &str) -> Vec<String> {
    vec![
        format!("projects/{project_number}"),
        format!("projects/{project_id}"),
    ]
}

/// Whole Unix seconds of a logical instant, rounded towards negative infinity.
#[must_use]
pub fn unix_seconds(at: LogicalInstant) -> i64 {
    i64::try_from(at.as_nanos().div_euclid(1_000_000_000)).unwrap_or(i64::MAX)
}

/// The claims of one locally issued App Check session token.
///
/// `fireemu_epoch` is a local private claim: it binds the token to the project session epoch and
/// makes it non-portable across reset, restore, project deletion and daemon instances.
#[derive(Clone, PartialEq, Eq)]
pub struct AppCheckClaims {
    /// `iss`: `https://firebaseappcheck.googleapis.com/{projectNumber}`.
    pub iss: String,
    /// `sub`: the registered Firebase app ID.
    pub sub: String,
    /// `aud`: `projects/{projectNumber}` and `projects/{projectId}`.
    pub aud: Vec<String>,
    /// `iat`: virtual-clock Unix seconds at exchange.
    pub iat: i64,
    /// `exp`: `iat + tokenTtlSeconds`.
    pub exp: i64,
    /// `jti`: unique within the project epoch (epoch plus an atomic counter).
    pub jti: String,
    /// `fireemu_epoch`: the current project session epoch as 32 hexadecimal characters.
    pub fireemu_epoch: String,
}

impl core::fmt::Debug for AppCheckClaims {
    /// `jti` and `fireemu_epoch` carry the project epoch: they are redacted like the epoch itself.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AppCheckClaims")
            .field("iss", &self.iss)
            .field("sub", &self.sub)
            .field("aud", &self.aud)
            .field("iat", &self.iat)
            .field("exp", &self.exp)
            .field("jti", &"<redacted>")
            .field("fireemu_epoch", &"<redacted>")
            .finish()
    }
}

impl AppCheckClaims {
    /// Builds the claims of a session token for `app`.
    #[must_use]
    pub fn issue(
        app: &RegisteredApp,
        epoch: ProjectEpoch,
        jti: String,
        issued_at: LogicalInstant,
        ttl_seconds: i64,
    ) -> Self {
        let iat = unix_seconds(issued_at);
        Self {
            iss: issuer_for(app.project_number()),
            sub: app.app_id().to_owned(),
            aud: audiences_for(app.project_number(), app.project_id()),
            iat,
            exp: iat.saturating_add(ttl_seconds),
            jti,
            fireemu_epoch: epoch.claim_text(),
        }
    }

    /// The token lifetime in seconds, as the exchange response reports it (`"3600s"`).
    #[must_use]
    pub const fn ttl_seconds(&self) -> i64 {
        self.exp.saturating_sub(self.iat)
    }

    /// Canonical JSON with sorted keys: the exact payload that is signed.
    #[must_use]
    pub fn canonical_json(&self) -> String {
        let audiences = self
            .aud
            .iter()
            .map(|a| format!("\"{}\"", escape(a)))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"aud\":[{audiences}],\"exp\":{},\"fireemu_epoch\":\"{}\",\"iat\":{},\"iss\":\"{}\",\"jti\":\"{}\",\"sub\":\"{}\"}}",
            self.exp,
            escape(&self.fireemu_epoch),
            self.iat,
            escape(&self.iss),
            escape(&self.jti),
            escape(&self.sub),
        )
    }
}

/// Minimal RFC 8259 string escaping for the claim values the issuer controls.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    fireemu_core_types::codec::json_escape_into(
        &mut out,
        text,
        fireemu_core_types::codec::JsonControlEscape::Unicode,
    );
    out
}
