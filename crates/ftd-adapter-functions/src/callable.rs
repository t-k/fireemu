//! The daemon-side trust boundary for callable Functions (specification section 13.4).
//!
//! The installed `firebase-functions` debug switch the trusted protocol turns on
//! (`skipTokenVerification`) makes the callable wrapper *decode* both credentials without
//! verifying either: it never contacts Google, but it also never checks a signature. So the
//! daemon has to be the only thing that ever hands the runner a credential, and it has to have
//! verified it first.
//!
//! For every callable request the proxy therefore:
//!
//! 1. classifies `X-Firebase-AppCheck` under the canonical contract of section 7.3 and records
//!    the original state — a valid token is forwarded byte for byte as exactly one field, an
//!    invalid one is removed, a missing one stays missing;
//! 2. accepts as `Authorization` only a Firebase ID token that verifies against the target
//!    project's users on the virtual clock and resolves as a user. `Bearer owner`, service
//!    credentials, duplicate and folded fields are not callable user identities and are never
//!    reinserted;
//! 3. strips every caller-supplied copy of the fields it owns before inserting its own, so a
//!    caller cannot smuggle a second value past the one the daemon verified
//!    (`INV-APPCHECK-009`, `INV-APPCHECK-010`);
//! 4. answers the callable `401 UNAUTHENTICATED` envelope itself for an `enforceAppCheck`
//!    callable with a missing or invalid token, before the runner is reached at all. The SDK
//!    wrapper would refuse it too — the daemon has already stripped the invalid token, so the
//!    wrapper sees `MISSING` — but this way the guarantee does not depend on the wrapper, and a
//!    denied request costs no concurrency slot, no invocation record and no handler run.

use std::sync::Arc;

use ftd_adapter_grpc::rules::{check_audience, Principal, RulesEnforcer};
use ftd_core_app_check::admission::{AdmissionRequest, PrivilegedBypass, ServiceAdmission};
use ftd_core_app_check::header::{classify_app_check_header, HeaderClassification};
use ftd_core_types::time::LogicalInstant;

use crate::http::ProxiedResponse;

/// The credential fields the daemon owns on the way to the runner.
///
/// Every instance of each is removed from a callable request before the trusted values are
/// inserted. The last two are the emulator-internal channels `firebase-functions` honours
/// under `skipTokenVerification` to override v1 callable auth context; no client ever legitimately
/// sends them, and a caller that does is trying to forge `context.auth`.
const OWNED_FIELDS: &[&str] = &[
    "x-firebase-appcheck",
    "authorization",
    "x-ftd-runner-secret",
    "x-callable-context-auth",
    "x-original-auth",
];

/// The fields the proxy strips from *every* request it forwards, callable or not.
pub const ALWAYS_STRIPPED: &[&str] = &[
    "x-ftd-runner-secret",
    "x-callable-context-auth",
    "x-original-auth",
];

/// Whether a field name is one the daemon owns on a callable request.
fn is_owned(name: &str) -> bool {
    OWNED_FIELDS.iter().any(|f| name.eq_ignore_ascii_case(f))
}

/// How one callable request's credentials classified, for the observation record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialState {
    /// No field was presented.
    Missing,
    /// A field was presented and verified.
    Valid,
    /// A field was presented and did not verify (an ambiguous field list included).
    Invalid,
}

impl CredentialState {
    /// The stable label used in traces and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        }
    }
}

/// What the proxy should do with one callable request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallableDecision {
    /// Forward exactly these fields.
    Forward {
        /// The sanitized field list.
        headers: Vec<(String, String)>,
        /// The original App Check classification.
        app_check: CredentialState,
        /// The original Authorization classification.
        auth: CredentialState,
    },
    /// Answer the callable `401 UNAUTHENTICATED` envelope; the runner is not reached.
    Unauthenticated {
        /// The original App Check classification that caused the refusal.
        app_check: CredentialState,
    },
}

/// One callable request as the proxy presents it.
pub struct CallableRequest<'a> {
    /// Function name, for the observation label.
    pub function: &'a str,
    /// The callable's declared `enforceAppCheck`.
    pub enforce_app_check: bool,
    /// The fields as received, duplicates in wire order.
    pub headers: &'a [(String, String)],
    /// Every `X-Firebase-AppCheck` instance, in wire order.
    pub app_check: &'a [String],
    /// Every `Authorization` instance, in wire order.
    pub authorization: &'a [String],
    /// The virtual-clock instant the request is decided at.
    pub now: LogicalInstant,
}

/// The verifier the proxy consults for both callable credentials.
pub struct CallableTrust {
    app_check: Arc<ServiceAdmission>,
    auth: Arc<RulesEnforcer>,
    project: String,
}

impl std::fmt::Debug for CallableTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallableTrust")
            .field("project", &self.project)
            .finish_non_exhaustive()
    }
}

impl CallableTrust {
    /// The trust boundary over one App Check policy and one Auth verifier.
    #[must_use]
    pub fn new(app_check: Arc<ServiceAdmission>, auth: Arc<RulesEnforcer>, project: &str) -> Self {
        Self {
            app_check,
            auth,
            project: project.to_owned(),
        }
    }

    /// Sanitizes one callable request.
    #[must_use]
    pub fn sanitize(&self, req: &CallableRequest<'_>) -> CallableDecision {
        let header = classify_app_check_header(req.app_check);
        // The baseline mode is `unenforced`: the daemon classifies and records every callable
        // token, and the callable's own `enforceAppCheck` decides. That is what makes valid app
        // context available to callables that do not enforce (section 8, activation table).
        let decision = self.app_check.admit(&AdmissionRequest {
            project_id: &self.project,
            transport: "http",
            operation: req.function,
            bypass: PrivilegedBypass::None,
            header: &header,
            now: req.now,
        });
        let admitted = decision.identity().is_some();
        let app_check = match (&header, admitted) {
            (HeaderClassification::Missing, _) => CredentialState::Missing,
            (_, true) => CredentialState::Valid,
            (_, false) => CredentialState::Invalid,
        };
        if req.enforce_app_check && !admitted {
            return CallableDecision::Unauthenticated { app_check };
        }
        let mut headers: Vec<(String, String)> = req
            .headers
            .iter()
            .filter(|(name, _)| !is_owned(name))
            .cloned()
            .collect();
        if admitted {
            if let HeaderClassification::Present(token) = &header {
                // Byte for byte, exactly once.
                headers.push((
                    ftd_core_app_check::header::APP_CHECK_HEADER.to_owned(),
                    token.clone(),
                ));
            }
        }
        let auth = match req.authorization {
            [] => CredentialState::Missing,
            [only] if self.is_verified_user(only) => {
                headers.push(("authorization".to_owned(), only.clone()));
                CredentialState::Valid
            }
            _ => CredentialState::Invalid,
        };
        CallableDecision::Forward {
            headers,
            app_check,
            auth,
        }
    }

    /// Whether one `Authorization` value is a Firebase ID token of this project's users.
    ///
    /// `Principal::Owner` (`Bearer owner`) is deliberately not one: it is the emulator's admin
    /// credential, not an end user, and turning it into `context.auth` would let anybody who
    /// knows the fixed string impersonate a signed-in user inside a callable.
    fn is_verified_user(&self, value: &str) -> bool {
        match self.auth.principal_from_authorization(Some(value)) {
            Ok(principal @ Principal::User(_)) => check_audience(&principal, &self.project).is_ok(),
            _ => false,
        }
    }
}

/// The callable `401 UNAUTHENTICATED` envelope, byte-identical to the one the
/// `firebase-functions` wrapper produces for the same refusal.
#[must_use]
pub fn unauthenticated_response() -> ProxiedResponse {
    let body = serde_json::json!({
        "error": {"message": "Unauthenticated", "status": "UNAUTHENTICATED"}
    });
    ProxiedResponse {
        status: 401,
        headers: vec![(
            "content-type".to_owned(),
            "application/json; charset=utf-8".to_owned(),
        )],
        body: serde_json::to_vec(&body).unwrap_or_default(),
    }
}
