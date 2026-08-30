//! Secret-free observations of classified App Check requests (specification section 15).
//!
//! An observation carries what a test or the control API may see and nothing else. Section 16
//! (`INV-APPCHECK-004`) forbids a raw JWT, a signature, a raw debug secret, a full digest, a
//! private key, an instance secret, an epoch value and an `Authorization` credential here, so
//! none of them has a field. Unverified app identities are aggregated into a bounded `unknown`
//! bucket rather than becoming a label.
//!
//! Observations and counters are kept per project by [`crate::registry::AppCheckRegistry`], so
//! what one project observed never depends on what another project's traffic did.

use core::fmt;

use ftd_core_types::time::LogicalInstant;

use crate::verify::{AppCheckCredentialState, AppCheckFailure, BaselineMode};

/// The category of a classified credential.
///
/// The ordering is the declaration order and exists only so a counter map can be keyed by a
/// category; it ranks nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

/// The service label of callable Cloud Functions requests.
///
/// It is the one service whose operation is a callable name the daemon itself declared, which
/// is why counters may group by it ([`Observation::callable`]).
pub const FUNCTIONS_SERVICE: &str = "functions";

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

    /// The callable this observation belongs to, for the `functions` service alone.
    ///
    /// A callable name reaches the daemon only after it resolved to a function the runtime
    /// declared, so it is a bounded label; every other service's operation comes from a route
    /// and is never made one.
    #[must_use]
    pub fn callable(&self) -> Option<&str> {
        (self.service == FUNCTIONS_SERVICE).then_some(self.operation.as_str())
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

/// The bounded key one counter is kept under (specification section 15).
///
/// Every component is drawn from a set the daemon controls: the fixed service labels, a
/// verified app ID or [`UNKNOWN_APP_LABEL`], a declared callable name for the `functions`
/// service, one of four categories and one of two outcomes. Nothing a caller supplies becomes
/// a label, which is what keeps the counter map bounded without a sampling rule.
///
/// The field order is also the order counters are reported in, so a view can group by service
/// and then by app without sorting again.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObservationCounterKey {
    /// Firebase service.
    pub service: &'static str,
    /// Verified app ID, or [`UNKNOWN_APP_LABEL`].
    pub app_id: String,
    /// Callable function name, for the `functions` service only.
    pub function: Option<String>,
    /// Credential category.
    pub category: CredentialCategory,
    /// Whether the request was admitted.
    pub admitted: bool,
}

impl ObservationCounterKey {
    /// The key one observation counts under.
    #[must_use]
    pub fn of(observation: &Observation) -> Self {
        Self {
            service: observation.service,
            app_id: observation.app_id.clone(),
            function: observation.callable().map(str::to_owned),
            category: observation.category,
            admitted: observation.admitted,
        }
    }

    /// The same key with the identity labels collapsed.
    ///
    /// A project whose counter map is full folds into this rather than dropping the count or
    /// growing the label set: the app ID and the callable name become the bounded `unknown`
    /// treatment section 15 already prescribes for an unverified identity.
    #[must_use]
    pub fn aggregated(&self) -> Self {
        Self {
            service: self.service,
            app_id: UNKNOWN_APP_LABEL.to_owned(),
            function: None,
            category: self.category,
            admitted: self.admitted,
        }
    }

    /// The stable outcome label: `admitted` or `denied`.
    #[must_use]
    pub const fn outcome(&self) -> &'static str {
        if self.admitted {
            "admitted"
        } else {
            "denied"
        }
    }
}
