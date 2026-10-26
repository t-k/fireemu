//! The daemon side of the Admin SDK App Check instrumentation (HTTP Functions).
//!
//! A runner whose codebase calls `getAppCheck().verifyToken()` asks the daemon, over its own
//! private stdio pipe, whether a token verifies, and the daemon answers from the very
//! verifier the callable boundary uses ([`fireemu_core_app_check::admin`]), against the
//! runner's project, its *current* session epoch and its app registry. Nothing is cached on
//! either side and nothing is listening: the pipe is owned by the daemon, so the runner's
//! identity is the pipe and never request data.
//!
//! ```text
//! runner -> daemon  {"type":"appCheck:verify","requestId":"…","projectId":"…","token":"…"}
//! daemon -> runner  {"type":"appCheck:verdict","requestId":"…","ok":true}
//!                   {"type":"appCheck:verdict","requestId":"…","ok":false,"reason":"…"}
//! ```
//!
//! A verification takes the session admission barrier shared, so a reset (which holds it
//! exclusively across all of its steps, `INV-APPCHECK-005` and `INV-APPCHECK-007`) never
//! straddles one. A verdict already returned is not retracted by a later reset, exactly as a
//! verified token is not revoked mid-request in production.

use std::sync::Arc;

use fireemu_core_app_check::admin::{AdminPolicy, AdminRejection, AdminVerdict};
use fireemu_core_app_check::admission::AppCheckGate;
use fireemu_core_app_check::limits::MAX_TOKEN_BYTES;
use fireemu_core_session::barrier::AdmissionBarrier;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

/// Verifications one runner may have in flight at once. A function holding more open
/// `verifyToken` calls than this is refused immediately rather than queued without bound.
pub const MAX_IN_FLIGHT: usize = 64;

/// The longest request ID a runner may use.
pub const MAX_REQUEST_ID_BYTES: usize = 128;

/// The longest project ID a request may name.
pub const MAX_PROJECT_ID_BYTES: usize = 256;

/// The wire reason of a request the daemon could not answer (no verifier, too many in flight).
/// The runner reports it the way the SDK reports a failed JWKS fetch.
pub const UNAVAILABLE: &str = "unavailable";

/// Something that can decide an Admin SDK verification.
pub trait AdminAppCheckVerifier: Send + Sync + std::fmt::Debug {
    /// Decides `token` for `project_id`. May block while a reset holds the session barrier.
    /// [`Reply::Unavailable`] when the decision cannot be made (a clock that cannot be read),
    /// never an acceptance.
    fn verify(&self, project_id: &str, token: &str) -> Reply;
}

/// The production verifier: the gate's registry and signer, the virtual clock, and the
/// session admission barrier, for the one project the runner belongs to.
pub struct BarrierVerifier {
    gate: AppCheckGate,
    barrier: Arc<AdmissionBarrier>,
    project: String,
    clock: Arc<dyn Fn() -> Option<LogicalInstant> + Send + Sync>,
    policy: AdminPolicy,
}

impl std::fmt::Debug for BarrierVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BarrierVerifier")
            .field("project", &self.project)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl BarrierVerifier {
    /// A verifier for `project` under `policy`.
    #[must_use]
    pub fn new(
        gate: AppCheckGate,
        barrier: Arc<AdmissionBarrier>,
        project: String,
        clock: Arc<dyn Fn() -> Option<LogicalInstant> + Send + Sync>,
        policy: AdminPolicy,
    ) -> Self {
        Self {
            gate,
            barrier,
            project,
            clock,
            policy,
        }
    }
}

impl AdminAppCheckVerifier for BarrierVerifier {
    fn verify(&self, project_id: &str, token: &str) -> Reply {
        // The runner belongs to one project. A call that names another one is answered as a
        // key this daemon does not hold, and never reads that project's state.
        if project_id != self.project {
            return Reply::Verdict(AdminVerdict::Reject(AdminRejection::NoMatchingKid));
        }
        let _admitted = self.barrier.admit();
        // Without a readable clock nothing can be said about `exp`, so nothing is accepted.
        let Some(now) = (self.clock)() else {
            return Reply::Unavailable;
        };
        Reply::Verdict(
            self.gate
                .verify_for_admin(&self.project, token, now, self.policy),
        )
    }
}

/// One well-formed verification request.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyRequest {
    /// The runner's correlation ID.
    pub request_id: String,
    /// The project the SDK resolved.
    pub project_id: String,
    /// The compact JWT. Never logged.
    pub token: String,
}

impl std::fmt::Debug for VerifyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyRequest")
            .field("request_id", &self.request_id)
            .field("project_id", &self.project_id)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Parses an `appCheck:verify` frame. On failure, carries the request ID when the frame had a
/// usable one, so the runner can fail that call instead of waiting for its own deadline.
///
/// # Errors
///
/// `Err(Some(id))` for a frame that names a request but is otherwise unusable (missing or
/// non-string fields, an empty or oversized project ID, a token over the limit);
/// `Err(None)` when not even the request ID is usable.
pub fn parse_request(frame: &Value) -> Result<VerifyRequest, Option<String>> {
    let request_id = frame
        .get("requestId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= MAX_REQUEST_ID_BYTES)
        .ok_or(None)?;
    let fail = || Some(request_id.to_owned());
    let project_id = frame
        .get("projectId")
        .and_then(Value::as_str)
        .filter(|project| !project.is_empty() && project.len() <= MAX_PROJECT_ID_BYTES)
        .ok_or_else(fail)?;
    let token = frame
        .get("token")
        .and_then(Value::as_str)
        .filter(|token| token.len() <= MAX_TOKEN_BYTES)
        .ok_or_else(fail)?;
    Ok(VerifyRequest {
        request_id: request_id.to_owned(),
        project_id: project_id.to_owned(),
        token: token.to_owned(),
    })
}

/// What a request is answered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// The verifier decided.
    Verdict(AdminVerdict),
    /// There is no verifier, or the runner has too many requests in flight.
    Unavailable,
}

/// Answers one parsed request. Without a verifier the answer is [`Reply::Unavailable`]; it is
/// never an acceptance.
#[must_use]
pub fn answer(request: &VerifyRequest, verifier: Option<&dyn AdminAppCheckVerifier>) -> Reply {
    verifier.map_or(Reply::Unavailable, |verifier| {
        verifier.verify(&request.project_id, &request.token)
    })
}

/// The `appCheck:verdict` frame for `request_id`.
#[must_use]
pub fn reply_frame(request_id: &str, reply: Reply) -> Value {
    match reply {
        Reply::Verdict(AdminVerdict::Accept) => {
            json!({"type": "appCheck:verdict", "requestId": request_id, "ok": true})
        }
        Reply::Verdict(AdminVerdict::Reject(reason)) => {
            json!({"type": "appCheck:verdict", "requestId": request_id, "ok": false, "reason": reason.wire()})
        }
        Reply::Unavailable => {
            json!({"type": "appCheck:verdict", "requestId": request_id, "ok": false, "reason": UNAVAILABLE})
        }
    }
}

/// The reply to a frame that named a request but could not be parsed.
#[must_use]
pub fn malformed_frame(request_id: &str) -> Value {
    reply_frame(
        request_id,
        Reply::Verdict(AdminVerdict::Reject(AdminRejection::Malformed)),
    )
}
