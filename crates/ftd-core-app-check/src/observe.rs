//! Secret-free observations of classified App Check requests (specification section 15).
//!
//! An observation carries what a test or the control API may see and nothing else. Section 16
//! (`INV-APPCHECK-004`) forbids a raw JWT, a signature, a raw debug secret, a full digest, a
//! private key, an instance secret, an epoch value and an `Authorization` credential here, so
//! none of them has a field. Unverified app identities are aggregated into a bounded `unknown`
//! bucket rather than becoming a label.

use core::fmt;

use ftd_core_types::time::LogicalInstant;

use crate::verify::{AppCheckCredentialState, AppCheckFailure, BaselineMode};

/// The category of a classified credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialCategory {
    /// A privileged route with its own credential.
    Bypass,
    /// No App Check header at all.
    Missing,
    /// A verified token.
    Valid,
    /// A token that failed classification or verification.
    Invalid,
}

impl CredentialCategory {
    /// The stable lowercase name used by observations and counters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bypass => "bypass",
            Self::Missing => "missing",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        }
    }
}

impl fmt::Display for CredentialCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The bounded label used instead of an unverified app identity.
pub const UNKNOWN_APP_LABEL: &str = "unknown";

/// One classified request, as tests, the control API and a future UI may see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Target project ID.
    pub project_id: String,
    /// Firebase service (`app-check`, `firestore`, `storage`, `auth`, `functions`).
    pub service: &'static str,
    /// Transport (`http`, `grpc`, `webchannel`).
    pub transport: &'static str,
    /// Operation or callable function name.
    pub operation: String,
    /// The baseline mode the request was decided under.
    pub mode: BaselineMode,
    /// Credential category.
    pub category: CredentialCategory,
    /// Stable failure reason, for privileged views only.
    pub failure: Option<AppCheckFailure>,
    /// App ID for valid tokens; [`UNKNOWN_APP_LABEL`] otherwise.
    pub app_id: String,
    /// Logical time of the decision.
    pub at: LogicalInstant,
    /// Non-secret policy generation of the project.
    pub policy_generation: u64,
    /// Whether the request was admitted.
    pub admitted: bool,
}

impl Observation {
    /// Builds an observation from a classified credential state.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // one field per observation column
    pub fn new(
        project_id: &str,
        service: &'static str,
        transport: &'static str,
        operation: &str,
        mode: BaselineMode,
        state: &AppCheckCredentialState,
        at: LogicalInstant,
        policy_generation: u64,
        admitted: bool,
    ) -> Self {
        let (category, failure, app_id) = match state {
            AppCheckCredentialState::Bypass => (CredentialCategory::Bypass, None, None),
            AppCheckCredentialState::Missing => (CredentialCategory::Missing, None, None),
            AppCheckCredentialState::Valid(identity) => (
                CredentialCategory::Valid,
                None,
                Some(identity.app_id.clone()),
            ),
            AppCheckCredentialState::Invalid(failure) => {
                (CredentialCategory::Invalid, Some(*failure), None)
            }
        };
        Self {
            project_id: project_id.to_owned(),
            service,
            transport,
            operation: operation.to_owned(),
            mode,
            category,
            failure,
            app_id: app_id.unwrap_or_else(|| UNKNOWN_APP_LABEL.to_owned()),
            at,
            policy_generation,
            admitted,
        }
    }

    /// The reason code an unprivileged view may see: detailed reasons collapse to `invalid`.
    #[must_use]
    pub const fn public_category(&self) -> &'static str {
        self.category.as_str()
    }

    /// The stable internal reason code, for control-token-authenticated views.
    #[must_use]
    pub fn privileged_reason(&self) -> Option<&'static str> {
        self.failure.map(AppCheckFailure::code)
    }
}
