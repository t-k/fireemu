//! Token verification, credential states and the admission decision (specification sections
//! 7.1, 11 and 12).
//!
//! No adapter reimplements any of this: adapters translate transport headers and wire errors,
//! then ask [`verify_token`] and [`AdmissionDecision::decide`] for the answer.

use core::fmt;

use ftd_core_types::json::{parse, JsonValue};
use ftd_core_types::time::LogicalInstant;

use crate::claims::{audiences_for, issuer_for, unix_seconds};
use crate::crypto::AppCheckSigner;
use crate::jwt::{base64url_decode, split_compact};
use crate::limits::MAX_TOKEN_BYTES;
use crate::registry::AppCheckRegistry;

/// Why a presented App Check credential was refused. These reasons are internal and stable;
/// public responses may collapse them (section 17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AppCheckFailure {
    /// Not a three-segment compact JWT with valid base64url and JSON, or an ambiguous header.
    Malformed,
    /// The header algorithm is not `RS256`, or `typ` is not `JWT`.
    UnsupportedAlgorithm,
    /// The `kid` does not name this instance's App Check key.
    UnknownKeyId,
    /// The signature does not verify.
    BadSignature,
    /// `iat` is in the future.
    NotYetValid,
    /// `now >= exp`.
    Expired,
    /// The issuer is not exactly the target project's issuer.
    WrongIssuer,
    /// One of the two required audiences is missing.
    WrongAudience,
    /// `sub` names no registered app.
    UnknownApp,
    /// `sub` names a registered but disabled app.
    AppDisabled,
    /// The token belongs to another registered project.
    WrongProject,
    /// `ftd_epoch` is not the project's current session epoch.
    WrongEpoch,
}

impl AppCheckFailure {
    /// The stable internal reason code (section 17).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed | Self::UnsupportedAlgorithm | Self::UnknownKeyId => {
                "APP_CHECK_MALFORMED"
            }
            Self::BadSignature => "APP_CHECK_BAD_SIGNATURE",
            Self::NotYetValid | Self::Expired => "APP_CHECK_EXPIRED",
            Self::WrongIssuer | Self::WrongAudience | Self::WrongProject => {
                "APP_CHECK_WRONG_PROJECT"
            }
            Self::UnknownApp | Self::AppDisabled => "APP_CHECK_UNKNOWN_APP",
            Self::WrongEpoch => "APP_CHECK_WRONG_EPOCH",
        }
    }
}

impl fmt::Display for AppCheckFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// The class of a presented token. Limited-use tokens are not issued yet
/// (`APPCHECK-REPLAY-1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenClass {
    /// A reusable session token.
    Session,
    /// A limited-use token, consumed once. Unsupported in the initial delivery.
    LimitedUse,
}

/// The verified identity of an app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppIdentity {
    /// Verified Firebase app ID (`sub`).
    pub app_id: String,
    /// Project ID the app belongs to.
    pub project_id: String,
    /// Project number the app belongs to.
    pub project_number: String,
    /// `iat` as a logical instant.
    pub issued_at: LogicalInstant,
    /// `exp` as a logical instant.
    pub expires_at: LogicalInstant,
    /// `jti`.
    pub token_id: String,
    /// Token class.
    pub token_class: TokenClass,
}

/// How a request's App Check credential classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppCheckCredentialState {
    /// An explicitly classified privileged route with its own authenticated credential.
    Bypass,
    /// No App Check header.
    Missing,
    /// A verified token.
    Valid(AppIdentity),
    /// A token that did not verify.
    Invalid(AppCheckFailure),
}

impl AppCheckCredentialState {
    /// The verified identity, if any.
    #[must_use]
    pub const fn identity(&self) -> Option<&AppIdentity> {
        match self {
            Self::Valid(identity) => Some(identity),
            _ => None,
        }
    }
}

/// The baseline enforcement mode of one product (`appCheck.services.*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BaselineMode {
    /// No parsing, no verification, everything allowed, nothing observed.
    #[default]
    Off,
    /// Classified and verified, but never denied. No app identity is exposed for a missing or
    /// invalid token.
    Unenforced,
    /// Missing and invalid credentials are denied.
    Enforced,
}

impl BaselineMode {
    /// Parses the canonical configuration value.
    #[must_use]
    pub fn parse_config(text: &str) -> Option<Self> {
        match text {
            "off" => Some(Self::Off),
            "unenforced" => Some(Self::Unenforced),
            "enforced" => Some(Self::Enforced),
            _ => None,
        }
    }

    /// The canonical configuration value.
    #[must_use]
    pub const fn as_config_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Unenforced => "unenforced",
            Self::Enforced => "enforced",
        }
    }

    /// Whether the mode makes the runtime classify and verify a presented token at all.
    #[must_use]
    pub const fn classifies(self) -> bool {
        !matches!(self, Self::Off)
    }
}

impl fmt::Display for BaselineMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_config_str())
    }
}

/// The public reason code of a denial (section 17). Detailed reasons stay privileged.
pub const PUBLIC_DENIAL_REASON: &str = "APP_CHECK_INVALID";

/// The public reason code of a missing credential under enforcement.
pub const PUBLIC_REQUIRED_REASON: &str = "APP_CHECK_REQUIRED";

/// One request's decision under one coherent policy snapshot (`INV-APPCHECK-005`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionDecision {
    /// How the credential classified.
    pub state: AppCheckCredentialState,
    /// The mode the request was decided under.
    pub mode: BaselineMode,
    /// Whether product logic may run.
    pub allowed: bool,
    /// The public reason code when the request was denied.
    pub reason: Option<&'static str>,
}

impl AdmissionDecision {
    /// Decides admission from the mode and the classified credential.
    ///
    /// `off` never denies and never classifies; `unenforced` never denies but does classify;
    /// `enforced` admits only a verified token or an explicit bypass.
    #[must_use]
    pub fn decide(mode: BaselineMode, state: AppCheckCredentialState) -> Self {
        let (allowed, reason) = match (mode, &state) {
            (BaselineMode::Off | BaselineMode::Unenforced, _)
            | (
                BaselineMode::Enforced,
                AppCheckCredentialState::Bypass | AppCheckCredentialState::Valid(_),
            ) => (true, None),
            (BaselineMode::Enforced, AppCheckCredentialState::Missing) => {
                (false, Some(PUBLIC_REQUIRED_REASON))
            }
            (BaselineMode::Enforced, AppCheckCredentialState::Invalid(_)) => {
                (false, Some(PUBLIC_DENIAL_REASON))
            }
        };
        Self {
            state,
            mode,
            allowed,
            reason,
        }
    }

    /// The app identity product logic may see. `unenforced` never exposes one for a missing or
    /// invalid credential, so a malformed token never becomes an anonymous valid app.
    #[must_use]
    pub const fn identity(&self) -> Option<&AppIdentity> {
        match (&self.state, self.allowed) {
            (AppCheckCredentialState::Valid(identity), true) => Some(identity),
            _ => None,
        }
    }
}

/// Verifies a presented token against the target project.
///
/// The order is the one section 11 requires: framing, then header, then signature, and only
/// then any claim. Nothing about the payload is trusted before the signature verifies.
#[allow(clippy::too_many_lines)]
pub fn verify_token(
    token: &str,
    registry: &AppCheckRegistry,
    project_id: &str,
    signer: &dyn AppCheckSigner,
    now: LogicalInstant,
) -> Result<AppIdentity, AppCheckFailure> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(AppCheckFailure::Malformed);
    }
    let jwt = split_compact(token)?;

    // 1-2: framing, algorithm, type and a known local key ID.
    let header_bytes = base64url_decode(jwt.header)?;
    let header_text = String::from_utf8(header_bytes).map_err(|_| AppCheckFailure::Malformed)?;
    let header = parse(&header_text).map_err(|_| AppCheckFailure::Malformed)?;
    let alg = header
        .get("alg")
        .and_then(JsonValue::as_str)
        .ok_or(AppCheckFailure::Malformed)?;
    if alg != signer.alg() {
        return Err(AppCheckFailure::UnsupportedAlgorithm);
    }
    if header.get("typ").and_then(JsonValue::as_str) != Some("JWT") {
        return Err(AppCheckFailure::UnsupportedAlgorithm);
    }
    if header.get("kid").and_then(JsonValue::as_str) != Some(signer.kid()) {
        return Err(AppCheckFailure::UnknownKeyId);
    }

    // 3: a valid signature before any claim is trusted.
    let signature = base64url_decode(jwt.signature)?;
    if signature.is_empty() || !signer.verify(jwt.signing_input().as_bytes(), &signature) {
        return Err(AppCheckFailure::BadSignature);
    }

    let payload_bytes = base64url_decode(jwt.payload)?;
    let payload_text = String::from_utf8(payload_bytes).map_err(|_| AppCheckFailure::Malformed)?;
    let payload = parse(&payload_text).map_err(|_| AppCheckFailure::Malformed)?;
    if !matches!(payload, JsonValue::Object(_)) {
        return Err(AppCheckFailure::Malformed);
    }

    // 4: integer iat and exp with iat <= now < exp and exp > iat.
    let iat = payload
        .get("iat")
        .and_then(JsonValue::as_i64)
        .ok_or(AppCheckFailure::Malformed)?;
    let exp = payload
        .get("exp")
        .and_then(JsonValue::as_i64)
        .ok_or(AppCheckFailure::Malformed)?;
    if exp <= iat {
        return Err(AppCheckFailure::Malformed);
    }
    let now_seconds = unix_seconds(now);
    if now_seconds < iat {
        return Err(AppCheckFailure::NotYetValid);
    }
    if now_seconds >= exp {
        return Err(AppCheckFailure::Expired);
    }

    // 5: the exact issuer of the target project.
    let expected_number = registry
        .project_number(project_id)
        .ok_or(AppCheckFailure::WrongProject)?;
    let iss = payload
        .get("iss")
        .and_then(JsonValue::as_str)
        .ok_or(AppCheckFailure::Malformed)?;
    if iss != issuer_for(expected_number) {
        let other_project = iss
            .strip_prefix(crate::claims::ISSUER_PREFIX)
            .is_some_and(|number| registry.knows_project_number(number));
        return Err(if other_project {
            AppCheckFailure::WrongProject
        } else {
            AppCheckFailure::WrongIssuer
        });
    }

    // 6: both project audiences.
    let JsonValue::Array(aud) = payload.get("aud").ok_or(AppCheckFailure::Malformed)? else {
        return Err(AppCheckFailure::Malformed);
    };
    let presented: Vec<&str> = aud.iter().filter_map(JsonValue::as_str).collect();
    for required in audiences_for(expected_number, project_id) {
        if !presented.iter().any(|a| *a == required) {
            return Err(AppCheckFailure::WrongAudience);
        }
    }

    // 7: a non-empty subject naming an enabled app of the target project.
    let sub = payload
        .get("sub")
        .and_then(JsonValue::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(AppCheckFailure::Malformed)?;
    let Some(app) = registry.app(project_id, sub) else {
        return Err(if registry.project_of_app(sub).is_some() {
            AppCheckFailure::WrongProject
        } else {
            AppCheckFailure::UnknownApp
        });
    };
    if !app.enabled() {
        return Err(AppCheckFailure::AppDisabled);
    }

    // 8: the current project session epoch.
    let epoch = registry
        .project_epoch(project_id)
        .ok_or(AppCheckFailure::WrongEpoch)?;
    if payload.get("ftd_epoch").and_then(JsonValue::as_str) != Some(epoch.claim_text().as_str()) {
        return Err(AppCheckFailure::WrongEpoch);
    }

    // 9: a non-empty token ID.
    let jti = payload
        .get("jti")
        .and_then(JsonValue::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(AppCheckFailure::Malformed)?;

    Ok(AppIdentity {
        app_id: app.app_id().to_owned(),
        project_id: app.project_id().to_owned(),
        project_number: app.project_number().to_owned(),
        issued_at: LogicalInstant::from_unix_seconds(iat),
        expires_at: LogicalInstant::from_unix_seconds(exp),
        token_id: jti.to_owned(),
        token_class: TokenClass::Session,
    })
}

/// Classifies a presented header value into a credential state.
///
/// This is the only path from a transport header to [`AppCheckCredentialState`]; `Bypass` is
/// never produced here, because it requires a route classification and a separate
/// authenticated credential (section 12.2).
#[must_use]
pub fn classify(
    header: &crate::header::HeaderClassification,
    registry: &AppCheckRegistry,
    project_id: &str,
    signer: &dyn AppCheckSigner,
    now: LogicalInstant,
) -> AppCheckCredentialState {
    match header {
        crate::header::HeaderClassification::Missing => AppCheckCredentialState::Missing,
        crate::header::HeaderClassification::Malformed => {
            AppCheckCredentialState::Invalid(AppCheckFailure::Malformed)
        }
        crate::header::HeaderClassification::Present(token) => {
            match verify_token(token, registry, project_id, signer, now) {
                Ok(identity) => AppCheckCredentialState::Valid(identity),
                Err(failure) => AppCheckCredentialState::Invalid(failure),
            }
        }
    }
}
