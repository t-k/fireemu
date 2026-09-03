//! Identity Toolkit REST handlers (spec 12A.2, 12A.8).
//!
//! Paths follow the official emulator layout:
//!
//! ```text
//! POST /identitytoolkit.googleapis.com/v1/accounts:signUp
//! POST /identitytoolkit.googleapis.com/v1/accounts:signInWithPassword
//! POST /identitytoolkit.googleapis.com/v1/accounts:lookup
//! POST /identitytoolkit.googleapis.com/v1/accounts:update          (Admin: customAttributes)
//! POST /identitytoolkit.googleapis.com/v2/accounts/mfaEnrollment:start
//! POST /identitytoolkit.googleapis.com/v2/accounts/mfaEnrollment:finalize
//! POST /identitytoolkit.googleapis.com/v2/accounts/mfaSignIn:finalize
//! POST /securetoken.googleapis.com/v1/token
//! ```
//!
//! Error bodies use the Firebase shape `{"error": {"code": 400, "message": "EMAIL_EXISTS"}}`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fireemu_core_app_check::admission::{AdmissionRequest, PrivilegedBypass, ServiceAdmission};
use fireemu_core_app_check::header::classify_app_check_header;
use fireemu_core_auth::base32;
use fireemu_core_auth::claims::{ClaimValue, CustomClaims};
use fireemu_core_auth::jwt::{base64url_decode, encode_payload_with, encode_with, JwtError};
use fireemu_core_auth::mfa::MfaError;
use fireemu_core_auth::store::{
    AuthError, AuthStore, FederatedIdentity, LocalId, NewUser, OobRequestType, PendingSignInId,
    RoutedStoreInstall, SecondFactorAssertion, VerificationPurpose,
};
use fireemu_core_session::clock::VirtualClock;
pub use fireemu_core_session::loopback::origin_is_local;
use fireemu_core_types::determinism::Clock;
use fireemu_core_types::json::JsonValue;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};

mod routes;
pub mod widget;
mod widget_templates;

/// Observer of user lifecycle events (Auth triggers), called after each request while
/// the store is locked, in the order the events happened.
pub type AuthEventSink = Arc<dyn Fn(&fireemu_core_auth::store::UserEvent) + Send + Sync>;

/// A monotonic wall-time anchor for unpinned daemon sessions. The shared virtual clock remains
/// authoritative and may be advanced explicitly; this anchor only prevents Auth request time
/// from freezing at daemon startup when no clock was configured.
#[derive(Debug, Clone)]
pub struct AuthWallClock {
    logical_start: LogicalInstant,
    monotonic_start: std::time::Instant,
}

impl AuthWallClock {
    /// Anchors elapsed monotonic time to a wall-clock instant sampled at the same point in
    /// daemon startup. Capturing the monotonic instant at request-state construction would
    /// lose the setup duration and can put Auth behind the caller near a second boundary.
    #[must_use]
    pub const fn from_anchor(
        logical_start: LogicalInstant,
        monotonic_start: std::time::Instant,
    ) -> Self {
        Self {
            logical_start,
            monotonic_start,
        }
    }

    fn now(&self) -> LogicalInstant {
        let elapsed =
            i128::try_from(self.monotonic_start.elapsed().as_nanos()).unwrap_or(i128::MAX);
        self.logical_start
            .checked_add(LogicalDuration::from_nanos(elapsed))
            .unwrap_or(LogicalInstant::MAX)
    }
}

/// Synchronous bridge to Identity Platform blocking functions. Implementations must perform
/// no Auth store access; the adapter releases the store before calling it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockingFunctionCode {
    /// The operation was cancelled.
    Cancelled,
    /// An unknown server failure occurred.
    Unknown,
    /// The caller supplied an invalid argument.
    InvalidArgument,
    /// The explicit function deadline was exceeded.
    DeadlineExceeded,
    /// The requested resource was not found.
    NotFound,
    /// The requested resource already exists.
    AlreadyExists,
    /// The operation is not permitted.
    PermissionDenied,
    /// Authentication is missing or invalid.
    Unauthenticated,
    /// A resource limit was exhausted.
    ResourceExhausted,
    /// A required precondition is not met.
    FailedPrecondition,
    /// The operation was aborted.
    Aborted,
    /// A value is outside its valid range.
    OutOfRange,
    /// The operation is not implemented.
    Unimplemented,
    /// An internal server failure occurred.
    Internal,
    /// The service is unavailable.
    Unavailable,
    /// Unrecoverable data loss occurred.
    DataLoss,
}

impl BlockingFunctionCode {
    /// Parses the canonical status emitted by the Functions SDK.
    #[must_use]
    pub fn from_canonical_name(name: &str) -> Option<Self> {
        Some(match name {
            "CANCELLED" => Self::Cancelled,
            "UNKNOWN" => Self::Unknown,
            "INVALID_ARGUMENT" => Self::InvalidArgument,
            "DEADLINE_EXCEEDED" => Self::DeadlineExceeded,
            "NOT_FOUND" => Self::NotFound,
            "ALREADY_EXISTS" => Self::AlreadyExists,
            "PERMISSION_DENIED" => Self::PermissionDenied,
            "UNAUTHENTICATED" => Self::Unauthenticated,
            "RESOURCE_EXHAUSTED" => Self::ResourceExhausted,
            "FAILED_PRECONDITION" => Self::FailedPrecondition,
            "ABORTED" => Self::Aborted,
            "OUT_OF_RANGE" => Self::OutOfRange,
            "UNIMPLEMENTED" => Self::Unimplemented,
            "INTERNAL" => Self::Internal,
            "UNAVAILABLE" => Self::Unavailable,
            "DATA_LOSS" => Self::DataLoss,
            _ => return None,
        })
    }

    /// HTTP status returned by the blocking function itself.
    #[must_use]
    pub const fn function_status(self) -> u16 {
        match self {
            Self::Cancelled => 499,
            Self::Unknown | Self::Internal | Self::DataLoss => 500,
            Self::InvalidArgument | Self::FailedPrecondition | Self::OutOfRange => 400,
            Self::DeadlineExceeded => 504,
            Self::NotFound => 404,
            Self::AlreadyExists | Self::Aborted => 409,
            Self::PermissionDenied => 403,
            Self::Unauthenticated => 401,
            Self::ResourceExhausted => 429,
            Self::Unimplemented => 501,
            Self::Unavailable => 503,
        }
    }

    /// Canonical status spelling returned by the Functions SDK.
    #[must_use]
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Cancelled => "CANCELLED",
            Self::Unknown => "UNKNOWN",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::Unauthenticated => "UNAUTHENTICATED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Aborted => "ABORTED",
            Self::OutOfRange => "OUT_OF_RANGE",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Internal => "INTERNAL",
            Self::Unavailable => "UNAVAILABLE",
            Self::DataLoss => "DATA_LOSS",
        }
    }
}

/// Why a blocking function refused an Auth operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockingFunctionFailure {
    code: BlockingFunctionCode,
    message: Box<str>,
    opaque: bool,
}

impl BlockingFunctionFailure {
    /// Maximum UTF-8 message length accepted from a function.
    pub const MAX_MESSAGE_BYTES: usize = 4_096;

    /// Builds a failure from one validated Functions SDK error response.
    pub fn from_function(
        code: BlockingFunctionCode,
        message: impl Into<Box<str>>,
    ) -> Result<Self, &'static str> {
        let message = message.into();
        if message.len() > Self::MAX_MESSAGE_BYTES {
            return Err("blocking function error message is too large");
        }
        if message.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
        }) {
            return Err("blocking function error message contains a control character");
        }
        Ok(Self {
            code,
            message,
            opaque: false,
        })
    }

    /// A handler threw a value other than a supported `HttpsError`.
    #[must_use]
    pub fn unhandled() -> Self {
        Self {
            code: BlockingFunctionCode::Unavailable,
            message: "An unexpected error occurred.".into(),
            opaque: false,
        }
    }

    /// The production seven-second Blocking Function deadline elapsed.
    #[must_use]
    pub fn timeout() -> Self {
        Self {
            code: BlockingFunctionCode::Unavailable,
            message: "Error code: 47".into(),
            opaque: true,
        }
    }

    /// The client-facing Identity Toolkit HTTP status.
    #[must_use]
    pub const fn identity_status(&self) -> u16 {
        let status = self.code.function_status();
        if status < 500 {
            400
        } else {
            status
        }
    }

    fn client_message(&self) -> String {
        if self.opaque {
            return self.message.to_string();
        }
        let quoted = serde_json::to_string(&self.message).unwrap_or_else(|_| "\"\"".to_owned());
        format!(
            "BLOCKING_FUNCTION_ERROR_RESPONSE : HTTP Cloud Function returned an error. Code: {}, Status: \"{}\", Message: {quoted}",
            self.code.function_status(),
            self.code.canonical_name()
        )
    }
}

/// Synchronous bridge invoked before an Auth create or sign-in commit.
pub trait AuthBlockingHook: Send + Sync {
    /// Maximum number of Auth requests that may occupy the synchronous bridge, including
    /// requests waiting for another mutation in the same namespace. The HTTP adapter applies
    /// its own hard ceiling before scheduling blocking work.
    fn request_concurrency_limit(&self) -> usize {
        64
    }

    /// Whether this bridge has a function for `event`. In-process hooks default to both
    /// supported events; runtime-backed bridges override this from their discovered manifest.
    fn handles(&self, _event: fireemu_core_functions::manifest::BlockingAuthEvent) -> bool {
        true
    }

    /// Runs one before-create or before-sign-in function. Implementations must return within a
    /// finite deadline. An error rejects and rolls back the Auth request; the value is the
    /// validated blocking response for future field updates.
    fn invoke(
        &self,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure>;

    /// Runs a hook for the Auth store namespace selected by request routing. Implementations
    /// that host only one project must return `Ok(None)` for every other project before
    /// serializing or forwarding the user record. The default preserves simple in-process
    /// hooks used by embedders and tests.
    fn invoke_for(
        &self,
        _project: &str,
        _tenant: Option<&str>,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Option<Value>, BlockingFunctionFailure> {
        self.invoke(event, user).map(Some)
    }
}

fn handler_may_invoke_blocking_auth(
    blocking: &dyn AuthBlockingHook,
    handler: routes::Handler,
) -> bool {
    use fireemu_core_functions::manifest::BlockingAuthEvent::{BeforeCreate, BeforeSignIn};
    let may_create = matches!(
        handler,
        routes::Handler::SignUp
            | routes::Handler::SignInWithCustomToken
            | routes::Handler::SignInWithEmailLink
            | routes::Handler::SignInWithPhoneNumber
            | routes::Handler::SignInWithIdp
    );
    let may_sign_in = matches!(
        handler,
        routes::Handler::SignUp
            | routes::Handler::SignInWithPassword
            | routes::Handler::SignInWithCustomToken
            | routes::Handler::SignInWithEmailLink
            | routes::Handler::SignInWithPhoneNumber
            | routes::Handler::SignInWithIdp
            | routes::Handler::MfaSignInFinalize
    );
    (may_create && blocking.handles(BeforeCreate))
        || (may_sign_in && blocking.handles(BeforeSignIn))
}

pub(crate) fn request_may_invoke_blocking_auth(
    blocking: Option<&dyn AuthBlockingHook>,
    method: &str,
    path: &str,
) -> bool {
    let Some(blocking) = blocking else {
        return false;
    };
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    matches!(
        routes::resolve(method, path),
        routes::Resolution::Matched { route, .. }
            if handler_may_invoke_blocking_auth(blocking, route.handler)
    )
}

pub(crate) fn blocking_auth_overload_response() -> JsonResponse {
    let failure = BlockingFunctionFailure::unhandled();
    error(failure.identity_status(), &failure.client_message())
}

/// Profile-specific expiry behavior for unsigned fake custom tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeCustomTokenExpiry {
    /// Match the Firebase Auth Emulator, which ignores `exp` on fake custom tokens.
    Ignore,
    /// Retain production-like expiry validation for strict local tests.
    Reject,
}

/// Whether Admin `accounts:query` follows the unbounded official emulator behavior or the
/// documented production page contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthQueryLimits {
    /// Preserve Firebase Auth Emulator compatibility: `limit` and `offset` are ignored.
    EmulatorUnbounded,
    /// Apply Identity Platform's default and maximum page size of 500.
    ProductionBounded,
}

/// Shared Auth state behind the REST surface.
pub struct AuthState {
    /// User store (shared with the gRPC adapter, which verifies ID tokens against it).
    pub store: Arc<Mutex<AuthStore>>,
    /// Virtual clock shared with the other adapters.
    pub clock: Arc<Mutex<VirtualClock>>,
    /// Monotonic wall-time progression for unpinned daemon sessions. Tests and pinned sessions
    /// leave this absent so the virtual clock remains exactly deterministic.
    pub wall_clock: Option<AuthWallClock>,
    /// Whether the fireemu-only TOTP extension was explicitly enabled by `auth.totp`.
    pub totp_extension_enabled: bool,
    /// Session admission barrier (reset waits for requests in flight), when shared.
    pub barrier: Option<Arc<fireemu_core_session::barrier::AdmissionBarrier>>,
    /// User lifecycle observer; `None` drops the events.
    pub events: Option<AuthEventSink>,
    /// Identity Platform blocking-function bridge, when Functions registered one.
    pub blocking: Option<Arc<dyn AuthBlockingHook>>,
    /// Serializes Auth operations while a blocking hook runs without the store lock.
    pub operation_gate: Arc<Mutex<()>>,
    /// The control token browser pages must present (`Authorization: Bearer`) to reach the
    /// emulator inspection routes (they expose action codes, SMS codes and account wipes).
    /// `None` refuses every browser-origin request there.
    pub control_token: Option<String>,
    /// Which session declared which API key (client SDK routes of a session project).
    pub tenancy: Option<fireemu_core_session::tenancy::SharedTenancy>,
    /// Stores of the other session projects: project-scoped routes (`projects/{p}/...`,
    /// `/emulator/v1/projects/{p}/...`) of a registered project use its own store.
    pub registry: Option<Arc<fireemu_core_auth::store::AuthRegistry>>,
    /// Whether unregistered project-scoped Admin routes may use isolated compatibility
    /// namespaces. Strict profile leaves this disabled.
    pub allow_routed_projects: bool,
    /// Whether refresh tokens keep the official emulator's stateless lifecycle. The strict
    /// profile may revoke them to model the production security boundary more closely.
    pub stateless_refresh_tokens: bool,
    /// Expiry policy for unsigned fake custom tokens.
    pub fake_custom_token_expiry: FakeCustomTokenExpiry,
    /// Profile-specific Admin query behavior.
    pub query_limits: AuthQueryLimits,
    /// App Check exchange, JWKS and debug-token management, when `appCheck.enabled` selects
    /// them. `None` makes every App Check route a 404 (the activation table of section 8).
    pub app_check: Option<Arc<crate::app_check::AppCheckState>>,
    /// The App Check baseline policy of Firebase Authentication (`appCheck.services.auth`).
    /// `None` is the `off` mode: no header is collected and nothing is classified.
    pub app_check_policy: Option<Arc<ServiceAdmission>>,
}

/// Hands the user events a request produced to the sink once the handler released the
/// store (drops after it; before the admission is released).
struct EventDrain<'a> {
    store: Arc<Mutex<AuthStore>>,
    sink: Option<&'a AuthEventSink>,
}

impl Drop for EventDrain<'_> {
    fn drop(&mut self) {
        // Taken under the lock, delivered without it: a sink that calls back into Auth
        // must not deadlock, and other Auth requests are not held up by the sink.
        let events = match self.store.lock() {
            Ok(mut store) => store.take_user_events(),
            Err(_) => return,
        };
        if let Some(sink) = self.sink {
            for e in &events {
                sink(e);
            }
        }
    }
}

/// An HTTP response: status code and JSON body.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonResponse {
    /// Status code.
    pub status: u16,
    /// Body.
    pub body: Value,
}

fn error(status: u16, message: &str) -> JsonResponse {
    JsonResponse {
        status,
        body: fireemu_adapter_support::api_error::identity_invalid(status, message),
    }
}

/// Replaces the unsigned internal form of successful response tokens with their configured
/// RS256 form. Callers invoke this only after releasing the Auth store mutex, so the private-key
/// operation never serializes unrelated Auth requests.
fn sign_response_tokens(
    mut response: JsonResponse,
    signer: Option<&dyn fireemu_core_auth::jwt::IdTokenSigner>,
) -> JsonResponse {
    let Some(signer) = signer else {
        return response;
    };
    if response.status != 200 {
        return response;
    }
    let Some(object) = response.body.as_object_mut() else {
        return response;
    };
    for field in ["idToken", "id_token", "access_token", "sessionCookie"] {
        let Some(Value::String(token)) = object.get_mut(field) else {
            continue;
        };
        let mut parts = token.split('.');
        let Some(header) = parts.next() else {
            return error(500, "INTERNAL");
        };
        let Some(payload) = parts.next() else {
            return error(500, "INTERNAL");
        };
        if parts.next() != Some("") || parts.next().is_some() {
            return error(500, "INTERNAL");
        }
        if base64url_decode(header).as_deref() != Ok(br#"{"alg":"none","typ":"JWT"}"#) {
            return error(500, "INTERNAL");
        }
        let Ok(payload) = base64url_decode(payload) else {
            return error(500, "INTERNAL");
        };
        if !serde_json::from_slice::<Value>(&payload).is_ok_and(|value| value.is_object()) {
            return error(500, "INTERNAL");
        }
        let Ok(payload) = std::str::from_utf8(&payload) else {
            return error(500, "INTERNAL");
        };
        *token = encode_payload_with(payload, Some(signer));
    }
    response
}

/// The envelope of a path the official emulator does not serve (measured:
/// `auth/identity-toolkit-error-shapes#unknown-method`). It carries `status` and no `domain`,
/// unlike the `BadRequestError` shape every 400 uses.
fn not_found() -> JsonResponse {
    JsonResponse {
        status: 404,
        body: fireemu_adapter_support::api_error::identity_not_found(),
    }
}

/// `JSON.stringify` semantics for a success body: the official emulator builds its responses
/// from optional fields, so a field it has no value for is absent rather than `null`. The
/// SDKs treat both the same; the recorded fixtures compare key sets, so the shape matters.
fn without_nulls(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, without_nulls(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(without_nulls).collect()),
        other => other,
    }
}

fn auth_error(e: &AuthError) -> JsonResponse {
    match e {
        AuthError::EmailExists => error(400, "EMAIL_EXISTS"),
        AuthError::InvalidEmail => error(400, "INVALID_EMAIL"),
        AuthError::WeakPassword => error(
            400,
            "WEAK_PASSWORD : Password should be at least 6 characters",
        ),
        AuthError::InvalidCredentials => error(400, "INVALID_LOGIN_CREDENTIALS"),
        AuthError::InvalidPassword => error(400, "INVALID_PASSWORD"),
        AuthError::UserDisabled => error(400, "USER_DISABLED"),
        AuthError::InvalidRefreshToken => error(400, "INVALID_REFRESH_TOKEN"),
        AuthError::UserNotFound => error(400, "USER_NOT_FOUND"),
        AuthError::InvalidLocalId => error(400, "INVALID_LOCAL_ID"),
        AuthError::LocalIdExists => error(400, "DUPLICATE_LOCAL_ID"),
        AuthError::PhoneNumberExists => error(400, "PHONE_NUMBER_EXISTS"),
        AuthError::InvalidPhoneNumber => error(400, "INVALID_PHONE_NUMBER"),
        AuthError::EmailNotFound => error(400, "EMAIL_NOT_FOUND"),
        AuthError::InvalidOobCode => error(400, "INVALID_OOB_CODE"),
        AuthError::InvalidSessionInfo => error(400, "INVALID_SESSION_INFO"),
        AuthError::InvalidVerificationCode => error(400, "INVALID_CODE"),
        AuthError::FederatedUserIdAlreadyLinked => error(400, "FEDERATED_USER_ID_ALREADY_LINKED"),
        AuthError::TooManyOutstandingCodes => error(
            400,
            "QUOTA_EXCEEDED : too many outstanding codes; consume or expire some first",
        ),
        AuthError::LimitExceeded(v) => error(400, &format!("INVALID_CLAIMS : {}", v.limit_id)),
    }
}

fn mfa_error(e: &MfaError) -> JsonResponse {
    match e {
        MfaError::InvalidCode => error(400, "INVALID_CODE"),
        MfaError::CodeAlreadyUsed => error(400, "INVALID_CODE : verification code already used"),
        MfaError::EnrollmentSessionExpired => error(400, "SESSION_EXPIRED"),
        MfaError::EnrollmentSessionUnknown | MfaError::PendingSignInUnknown => {
            error(400, "INVALID_SESSION_INFO")
        }
        MfaError::NoEnrolledFactor => error(400, "MFA_ENROLLMENT_NOT_FOUND"),
        MfaError::TooManyFactors => error(400, "SECOND_FACTOR_LIMIT_EXCEEDED"),
        MfaError::TooManyPending => error(
            400,
            "QUOTA_EXCEEDED : too many pending second-factor sessions for this user",
        ),
        MfaError::LimitExceeded(_) => error(400, "SECOND_FACTOR_EXISTS"),
        MfaError::UserDisabled => error(400, "USER_DISABLED"),
        MfaError::UserNotFound => error(400, "USER_NOT_FOUND"),
    }
}

fn jwt_error(e: &JwtError) -> JsonResponse {
    match e {
        JwtError::Expired => error(400, "TOKEN_EXPIRED"),
        JwtError::Revoked => error(400, "TOKEN_EXPIRED : credentials revoked"),
        _ => error(400, "INVALID_ID_TOKEN"),
    }
}

fn now(state: &AuthState) -> LogicalInstant {
    let Ok(mut clock) = state.clock.lock() else {
        return LogicalInstant::UNIX_EPOCH;
    };
    if let Some(wall_clock) = &state.wall_clock {
        let wall_now = wall_clock.now();
        if wall_now > clock.now() {
            let _ = clock.advance_to(wall_now);
        }
    }
    clock.now()
}

fn str_field<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    body.get(key).and_then(Value::as_str)
}

fn issue_tokens(
    store: &mut AuthStore,
    uid: &LocalId,
    second: Option<&SecondFactorAssertion>,
    at: LogicalInstant,
) -> Result<Value, JsonResponse> {
    issue_tokens_with(store, uid, second, at, None, None)
}

/// Issues an ID token + refresh token; `extra` claims (custom-token developer claims) and
/// `provider` are merged into the token and remembered by the refresh session.
fn issue_tokens_with(
    store: &mut AuthStore,
    uid: &LocalId,
    second: Option<&SecondFactorAssertion>,
    at: LogicalInstant,
    extra: Option<&CustomClaims>,
    provider: Option<fireemu_core_auth::store::Provider>,
) -> Result<Value, JsonResponse> {
    issue_tokens_replacing(store, uid, second, at, extra, provider, None)
}

/// Issues policy-adjusted tokens and retires the replayed authentication's provisional
/// refresh session when Blocking Auth is active.
fn issue_tokens_replacing(
    store: &mut AuthStore,
    uid: &LocalId,
    second: Option<&SecondFactorAssertion>,
    at: LogicalInstant,
    extra: Option<&CustomClaims>,
    provider: Option<fireemu_core_auth::store::Provider>,
    provisional_refresh: Option<&str>,
) -> Result<Value, JsonResponse> {
    let mut claims = store
        .id_token_claims(uid, second, at)
        .map_err(|e| auth_error(&e))?;
    if let Some(p) = &provider {
        p.id().clone_into(&mut claims.firebase.sign_in_provider);
    }
    if let Some(extra) = extra {
        for (k, v) in extra.entries() {
            claims
                .custom
                .insert(k, v.clone())
                .map_err(|e| error(400, &format!("INVALID_CUSTOM_TOKEN : {e}")))?;
        }
    }
    let refresh_claims = extra.cloned().unwrap_or_default();
    let second = second.cloned();
    let refresh = match provisional_refresh {
        Some(provisional) => {
            store.replace_refresh_session(provisional, uid, at, provider, refresh_claims, second)
        }
        None => store.issue_refresh_session(uid, at, provider, refresh_claims, second),
    }
    .map_err(|e| auth_error(&e))?;
    Ok(json!({
        "idToken": encode_with(&claims, None),
        "refreshToken": refresh,
        "expiresIn": "3600",
        "localId": uid.as_str(),
        "email": claims.email,
    }))
}

fn verify(store: &AuthStore, body: &Value, at: LogicalInstant) -> Result<LocalId, JsonResponse> {
    verify_session(store, body, at).map(|s| s.uid)
}

/// The session an `idToken` proves: the user and the provider it signed in with (the
/// official emulator reads `firebase.sign_in_provider` back from the token for the routes
/// whose behaviour depends on the first factor).
struct Session {
    uid: LocalId,
    provider: String,
    second_factor: Option<SecondFactorAssertion>,
    extra_claims: CustomClaims,
}

fn verify_session(
    store: &AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> Result<Session, JsonResponse> {
    let token = match body.get("idToken") {
        None | Some(Value::Null) => return Err(error(400, "MISSING_ID_TOKEN")),
        Some(Value::String(t)) => t.as_str(),
        Some(_) => return Err(error(400, "INVALID_ID_TOKEN")),
    };
    let (v, decoded) = fireemu_core_auth::jwt::verify_id_token_decoded(token, store, at)
        .map_err(|e| jwt_error(&e))?;
    let provider = decoded
        .payload
        .get("firebase")
        .and_then(|f| f.get("sign_in_provider"))
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_owned();
    let second_factor = decoded.payload.get("firebase").and_then(|firebase| {
        let sign_in_second_factor = firebase.get("sign_in_second_factor")?.as_str()?;
        let second_factor_identifier = firebase.get("second_factor_identifier")?.as_str()?;
        Some(SecondFactorAssertion {
            sign_in_second_factor: sign_in_second_factor.to_owned(),
            second_factor_identifier: second_factor_identifier.to_owned(),
            verified_at: at,
        })
    });
    let mut extra_claims = CustomClaims::default();
    if let JsonValue::Object(values) = &decoded.payload {
        for (name, value) in values {
            // Reserved token fields are rejected by insert; everything else is a developer,
            // user or blocking-function session claim that a replacement token must retain.
            let _ = extra_claims.insert(name, ClaimValue::from_json(value));
        }
    }
    store
        .user_by_id(&v.uid)
        .map(|u| Session {
            uid: u.local_id.clone(),
            provider,
            second_factor,
            extra_claims,
        })
        .ok_or_else(|| error(400, "USER_NOT_FOUND"))
}

/// Request metadata the JSON handlers need beyond the body.
///
/// `app_check` is the one multi-valued member on purpose: the canonical contract of
/// specification section 7.3 refuses duplicate and folded `X-Firebase-AppCheck` fields, which
/// is impossible to see once a header map has collapsed them, so the wire order is carried
/// through unchanged and classified by `fireemu_core_app_check::header`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestHeaders {
    /// `Authorization` header.
    pub authorization: Option<String>,
    /// `Origin` header (browser requests).
    pub origin: Option<String>,
    /// `Content-Type` header.
    pub content_type: Option<String>,
    /// `Host` header (action links name this daemon).
    pub host: Option<String>,
    /// Every `X-Firebase-AppCheck` field instance, in wire order. A value the transport could
    /// not render as text is carried as an empty string, which classifies as malformed.
    pub app_check: Vec<String>,
}

/// The exact credential the emulator's Admin SDK surface requires. It is the privileged
/// credential the App Check bypass of section 12.2 is granted for, so the comparison is
/// spelled once and both the guard and the bypass classification use it.
pub const OWNER_CREDENTIAL: &str = "Bearer owner";

/// Guards the Admin SDK (project-scoped) routes: owner credential, loopback origin, JSON
/// body, matching project.
fn admin_guard(
    headers: &RequestHeaders,
    method: &str,
    project: &str,
    store: &AuthStore,
) -> Result<(), JsonResponse> {
    admin_request_guard(headers, method)?;
    if project.is_empty() || project != store.project_id() {
        return Err(error(
            400,
            &format!(
                "INVALID_PROJECT_ID : this runtime serves project {}",
                store.project_id()
            ),
        ));
    }
    Ok(())
}

fn admin_request_guard(headers: &RequestHeaders, method: &str) -> Result<(), JsonResponse> {
    if headers.authorization.as_deref() != Some(OWNER_CREDENTIAL) {
        return Err(error(
            401,
            "MISSING_OWNER_CREDENTIAL : project-scoped routes require 'Authorization: Bearer owner'",
        ));
    }
    if let Some(origin) = &headers.origin {
        if !origin_is_local(origin) {
            return Err(error(403, "FORBIDDEN_ORIGIN"));
        }
    }
    if method == "POST" {
        if let Some(ct) = &headers.content_type {
            if !ct.trim_start().starts_with("application/json") {
                return Err(error(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE : application/json required",
                ));
            }
        }
    }
    Ok(())
}

/// Routes one request. Unknown paths return 404; every handler is JSON in / JSON out.
#[must_use]
pub fn handle(state: &AuthState, method: &str, path: &str, body: &Value) -> JsonResponse {
    handle_with(state, method, path, &RequestHeaders::default(), body)
}

/// The stable operation label of an Identity Toolkit route, for observations.
///
/// Every row of the route table carries one bounded label (specification section 13.3
/// publishes the end-user ones), and every path the table does not describe collapses to
/// `unknown`, so an unrecognised path can never become an unbounded metric label (section 15).
#[must_use]
pub fn end_user_operation(path: &str) -> &'static str {
    routes::operation_of(path)
}

/// Which privileged credential, if any, an Identity Toolkit route already authenticated
/// (specification sections 12.2 and 13.3).
///
/// Three surfaces bypass, and each one has to present its own credential first:
///
/// - the Auth JWKS, which is public-key discovery and carries no state at all;
/// - the emulator inspection routes, but only for a caller that presented the control token.
///   Section 12.2 grants that bypass because those routes have "a separate control-token
///   guard", and their own guard only challenges browser requests (those carrying an
///   `Origin`), so the App Check path checks the token itself rather than inheriting a guard
///   that does not run for a command-line caller;
/// - the Admin SDK routes, but only once the caller actually presented the owner credential.
///
/// A request to one of those paths without the matching credential is an ordinary end-user
/// request as far as App Check is concerned, so under `enforced` a missing App Check token is
/// refused before `admin_guard` or the emulator-route guard reports anything.
fn app_check_bypass(
    path: &str,
    headers: &RequestHeaders,
    control_token: Option<&str>,
) -> PrivilegedBypass {
    let class = routes::class_of(path).map(|(class, _)| class);
    match class {
        Some(routes::RouteClass::Jwks) => PrivilegedBypass::ControlApi,
        Some(routes::RouteClass::Emulator) => {
            let presented = headers
                .authorization
                .as_deref()
                .and_then(|a| a.strip_prefix("Bearer "))
                .map(str::trim);
            if control_token.is_some_and(|t| crate::control::token_matches(presented, t)) {
                PrivilegedBypass::ControlApi
            } else {
                PrivilegedBypass::None
            }
        }
        Some(routes::RouteClass::Admin)
            if headers.authorization.as_deref() == Some(OWNER_CREDENTIAL) =>
        {
            PrivilegedBypass::IdentityToolkitAdmin
        }
        Some(routes::RouteClass::Admin | routes::RouteClass::EndUser) | None => {
            PrivilegedBypass::None
        }
    }
}

/// The App Check denial of an Auth request, or `None` when it is admitted.
///
/// This runs after the route and the target project are resolved and before Firebase Auth,
/// Security Rules or any state transition, so a denied request creates no user, issues or
/// rotates no credential, consumes no OOB or phone code, changes no MFA state and touches no
/// modelled abuse counter (`INV-APPCHECK-003`).
fn app_check_denial(
    state: &AuthState,
    path: &str,
    headers: &RequestHeaders,
    project_id: &str,
    at: LogicalInstant,
) -> Option<JsonResponse> {
    let policy = state.app_check_policy.as_ref()?;
    let header = classify_app_check_header(&headers.app_check);
    let decision = policy.admit(&AdmissionRequest {
        project_id,
        transport: "http",
        operation: end_user_operation(path),
        bypass: app_check_bypass(path, headers, state.control_token.as_deref()),
        header: &header,
        now: at,
    });
    let reason = decision.reason?;
    Some(app_check_denied(reason))
}

/// The wire shape of an Auth App Check denial: HTTP 403 Google JSON `PERMISSION_DENIED` with
/// the public reason code (specification section 17). Detailed reasons stay in observations.
fn app_check_denied(reason: &'static str) -> JsonResponse {
    let message = if reason == fireemu_core_app_check::verify::PUBLIC_REQUIRED_REASON {
        "App Check token is required by this project's Firebase Authentication enforcement."
    } else {
        "App Check token is invalid."
    };
    JsonResponse {
        status: 403,
        body: fireemu_adapter_support::api_error::identity_app_check_denied(message, reason),
    }
}

/// Where the session's JWKS is served (the Google path the SDKs know, and the well-known one).
pub const JWKS_PATHS: &[&str] = &[
    "/.well-known/jwks.json",
    "/www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
];

/// The guard of the emulator inspection routes: a browser origin must be local and must
/// present the control token (the routes expose action codes, SMS codes and account wipes).
fn emulator_guard(state: &AuthState, headers: &RequestHeaders) -> Result<(), JsonResponse> {
    let Some(origin) = &headers.origin else {
        return Ok(());
    };
    if !origin_is_local(origin) {
        return Err(error(403, "FORBIDDEN_ORIGIN"));
    }
    let presented = headers
        .authorization
        .as_deref()
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(str::trim);
    if !state
        .control_token
        .as_deref()
        .is_some_and(|t| crate::control::token_matches(presented, t))
    {
        return Err(error(
            403,
            "CONTROL_TOKEN_REQUIRED : browser requests to the emulator routes need Authorization: Bearer <control token>",
        ));
    }
    Ok(())
}

fn blocking_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Number(value)) => Some(value.to_string()),
        Some(Value::Bool(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn blocking_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null | Value::Bool(false)) => false,
        Some(Value::Number(value)) => value.as_f64().is_some_and(|number| number != 0.0),
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Array(_) | Value::Object(_) | Value::Bool(true)) => true,
    }
}

fn blocking_claims(value: Option<&Value>, field: &str) -> Result<CustomClaims, String> {
    let Some(value @ Value::Object(_)) = value else {
        return Err(format!(
            "BLOCKING_FUNCTION_ERROR_RESPONSE : ((Response has malformed {field}.))"
        ));
    };
    CustomClaims::parse_attributes(&value.to_string()).map_err(|error| {
        format!("BLOCKING_FUNCTION_ERROR_RESPONSE : ((Invalid {field}: {error}.))")
    })
}

fn apply_blocking_response(
    store: &mut AuthStore,
    uid: &LocalId,
    event: fireemu_core_functions::manifest::BlockingAuthEvent,
    response: &Value,
) -> Result<Option<CustomClaims>, String> {
    let Some(record) = response.get("userRecord") else {
        return Ok(None);
    };
    let Some(record) = record.as_object() else {
        return Err(
            "BLOCKING_FUNCTION_ERROR_RESPONSE : ((Response userRecord must be an object.))"
                .to_owned(),
        );
    };
    let Some(mask) = record.get("updateMask").and_then(Value::as_str) else {
        return Err(
            "BLOCKING_FUNCTION_ERROR_RESPONSE : ((Response UserRecord is missing updateMask.))"
                .to_owned(),
        );
    };
    let mut custom_claims = None;
    let mut session_claims = None;
    for field in mask.split(',').map(str::trim) {
        match field {
            "displayName" => {
                if let Some(user) = store.user_mut(uid) {
                    user.display_name = blocking_string(record.get(field));
                }
            }
            "photoUrl" => {
                if let Some(user) = store.user_mut(uid) {
                    user.photo_url = blocking_string(record.get(field));
                }
            }
            "disabled" => {
                if let Some(user) = store.user_mut(uid) {
                    user.disabled = blocking_truthy(record.get(field));
                }
            }
            "emailVerified" => {
                if let Some(user) = store.user_mut(uid) {
                    user.email_verified = blocking_truthy(record.get(field));
                }
            }
            "customClaims" => custom_claims = Some(blocking_claims(record.get(field), field)?),
            "sessionClaims"
                if event == fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn =>
            {
                session_claims = Some(blocking_claims(record.get(field), field)?);
            }
            _ => {}
        }
    }
    if let Some(claims) = custom_claims {
        store.set_custom_claims(uid, claims).map_err(|error| {
            format!("BLOCKING_FUNCTION_ERROR_RESPONSE : ((Invalid customClaims: {error}.))")
        })?;
    }
    Ok(session_claims)
}

// The request parts stay separate here so the ordinary dispatcher remains the one source of
// route behavior; grouping them in a second request type would duplicate that boundary.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn dispatch_with_blocking_hook(
    state: &AuthState,
    blocking: &dyn AuthBlockingHook,
    handler: routes::Handler,
    store_arc: &Arc<Mutex<AuthStore>>,
    store: std::sync::MutexGuard<'_, AuthStore>,
    query: Option<&str>,
    body: &Value,
    headers: &RequestHeaders,
    at: LogicalInstant,
) -> JsonResponse {
    let mut candidate = store.clone();
    let response = dispatch(
        handler,
        &mut candidate,
        query,
        body,
        headers,
        at,
        state.into(),
    );
    let is_authentication = matches!(
        handler,
        routes::Handler::SignUp
            | routes::Handler::SignInWithPassword
            | routes::Handler::SignInWithCustomToken
            | routes::Handler::SignInWithEmailLink
            | routes::Handler::SignInWithPhoneNumber
            | routes::Handler::SignInWithIdp
            | routes::Handler::MfaSignInFinalize
    );
    let uid_text = response
        .body
        .get("localId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let uid = uid_text
        .as_deref()
        .and_then(|uid| candidate.user_by_id(uid))
        .map(|user| user.local_id.clone());
    let speculative_uid = uid.clone();
    let is_new = is_authentication
        && uid_text.as_deref().is_some_and(|uid| {
            store.user_by_id(uid).is_none() && candidate.user_by_id(uid).is_some()
        });
    let signed_in = is_authentication
        && response.status == 200
        && (response.body.get("idToken").is_some() || response.body.get("id_token").is_some());
    let project = store.project_id().to_owned();
    let tenant = store.tenant_id().map(str::to_owned);
    drop(store);
    let mut blocking_responses = Vec::new();
    if response.status == 200 {
        if let Some(uid) = uid {
            if is_new
                && blocking
                    .handles(fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate)
            {
                let value = {
                    let user = candidate
                        .user(&uid)
                        .unwrap_or_else(|| unreachable!("the successful response named its user"));
                    match blocking.invoke_for(
                        &project,
                        tenant.as_deref(),
                        fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate,
                        user,
                    ) {
                        Ok(value) => value,
                        Err(failure) => {
                            return error(failure.identity_status(), &failure.client_message())
                        }
                    }
                };
                if let Some(value) = value {
                    if let Err(reason) = apply_blocking_response(
                        &mut candidate,
                        &uid,
                        fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate,
                        &value,
                    ) {
                        return error(400, &reason);
                    }
                    blocking_responses.push((
                        fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate,
                        value,
                    ));
                }
            }
            if signed_in
                && blocking
                    .handles(fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn)
            {
                let value = {
                    let user = candidate
                        .user(&uid)
                        .unwrap_or_else(|| unreachable!("the successful response named its user"));
                    match blocking.invoke_for(
                        &project,
                        tenant.as_deref(),
                        fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn,
                        user,
                    ) {
                        Ok(value) => value,
                        Err(failure) => {
                            return error(failure.identity_status(), &failure.client_message())
                        }
                    }
                };
                if let Some(value) = value {
                    if let Err(reason) = apply_blocking_response(
                        &mut candidate,
                        &uid,
                        fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn,
                        &value,
                    ) {
                        return error(400, &reason);
                    }
                    blocking_responses.push((
                        fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn,
                        value,
                    ));
                }
            }
        }
    }
    let commit = |metadata: Option<&fireemu_core_auth::store::TenantMetadata>| {
        if tenant.is_some() {
            if let Some(denial) = tenant_policy_denial_with_metadata(handler, metadata, body) {
                return denial;
            }
        }
        let Ok(mut live) = store_arc.lock() else {
            return error(500, "INTERNAL");
        };
        let mut committed = live.clone();
        let mut committed_response = if handler == routes::Handler::SignUp && is_new {
            sign_up(
                &mut committed,
                body,
                at,
                speculative_uid
                    .as_ref()
                    .map(fireemu_core_auth::store::LocalId::as_str),
            )
        } else {
            dispatch(
                handler,
                &mut committed,
                query,
                body,
                headers,
                at,
                state.into(),
            )
        };
        if committed_response.status != 200 {
            return committed_response;
        }
        let uid = committed_response
            .body
            .get("localId")
            .and_then(Value::as_str)
            .and_then(|uid| committed.user_by_id(uid))
            .map(|user| user.local_id.clone());
        if is_authentication && uid != speculative_uid {
            return error(
                400,
                "BLOCKING_FUNCTION_ERROR_RESPONSE : identity changed while the hook was running",
            );
        }
        if let Some(uid) = uid {
            let signed_in = is_authentication
                && (committed_response.body.get("idToken").is_some()
                    || committed_response.body.get("id_token").is_some());
            let provisional_refresh = signed_in
                .then(|| {
                    committed_response
                        .body
                        .get("refreshToken")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .flatten();
            let mut issued_session = if signed_in {
                let Some(provisional) = provisional_refresh.as_deref() else {
                    return error(500, "INTERNAL");
                };
                let session = match committed.refresh_session(provisional) {
                    Ok(session) => session.clone(),
                    Err(_) => return error(500, "INTERNAL"),
                };
                let Ok(claims) = committed.id_token_claims_for_session(&session, at) else {
                    return error(500, "INTERNAL");
                };
                Some(Session {
                    uid: session.uid,
                    provider: claims.firebase.sign_in_provider,
                    second_factor: session.second_factor,
                    extra_claims: claims.custom,
                })
            } else {
                None
            };
            let persisted_claim_names: Vec<String> = committed
                .user(&uid)
                .map(|user| user.custom_claims.entries().keys().cloned().collect())
                .unwrap_or_default();
            let mut session_claims = None;
            for (event, value) in &blocking_responses {
                match apply_blocking_response(&mut committed, &uid, *event, value) {
                    Ok(claims)
                        if *event
                            == fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn =>
                    {
                        session_claims = claims;
                    }
                    Ok(_) => {}
                    Err(reason) => return error(400, &reason),
                }
            }
            if let Some(mut session) = issued_session.take() {
                for name in &persisted_claim_names {
                    session.extra_claims.remove(name);
                }
                if let Some(user) = committed.user(&uid) {
                    for name in user.custom_claims.entries().keys() {
                        session.extra_claims.remove(name);
                    }
                }
                if let Some(claims) = session_claims {
                    for (name, value) in claims.entries() {
                        if let Err(reason) = session.extra_claims.insert(name, value.clone()) {
                            return error(
                                400,
                                &format!("BLOCKING_FUNCTION_ERROR_RESPONSE : {reason}"),
                            );
                        }
                    }
                }
                let provider = provider_from_id(&session.provider);
                let Some(provisional_refresh) = provisional_refresh.as_deref() else {
                    return error(500, "INTERNAL");
                };
                let tokens = match issue_tokens_replacing(
                    &mut committed,
                    &uid,
                    session.second_factor.as_ref(),
                    at,
                    Some(&session.extra_claims),
                    Some(provider),
                    Some(provisional_refresh),
                ) {
                    Ok(tokens) => tokens,
                    Err(refusal) => return refusal,
                };
                for field in ["idToken", "refreshToken", "expiresIn", "email"] {
                    committed_response.body[field] = tokens[field].clone();
                }
                if let Some(user) = committed.user(&uid) {
                    committed_response.body["displayName"] = json!(user.display_name);
                    committed_response.body["photoUrl"] = json!(user.photo_url);
                    if handler != routes::Handler::SignUp {
                        committed_response.body["emailVerified"] = json!(user.email_verified);
                    }
                }
            }
        }
        *live = committed;
        committed_response
    };
    match (tenant.as_deref(), state.registry.as_ref()) {
        (Some(tenant), Some(registry)) => {
            registry.with_existing_tenant_metadata(&project, tenant, commit)
        }
        (Some(_), None) => error(400, "TENANT_NOT_FOUND"),
        (None, _) => commit(None),
    }
}

/// Routes one request with its headers (privileged routes check them).
///
/// The order is fixed: the store of the target project is selected, App Check decides, the
/// route's privilege class is checked (owner credential, control token, project match), and
/// only then does the handler run. Every step reads the same route table
/// (`AUTH-ROUTE-03`).
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn handle_with(
    state: &AuthState,
    method: &str,
    path: &str,
    headers: &RequestHeaders,
    body: &Value,
) -> JsonResponse {
    let (path, query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };
    let at = now(state);
    let _admitted = state.barrier.as_ref().map(|b| b.admit());
    let resolution = routes::resolve(method, path);
    let routed_project = match resolution {
        routes::Resolution::Matched {
            route,
            project: Some(project),
            tenant: None,
        } if state.allow_routed_projects && route.class == routes::RouteClass::Admin => {
            Some(project)
        }
        _ => None,
    };
    if let Some(project) = routed_project {
        if fireemu_core_types::ids::ProjectId::try_new(project.to_owned()).is_err() {
            return error(400, "INVALID_PROJECT_ID");
        }
        if let Err(response) = admin_request_guard(headers, method) {
            return response;
        }
    }
    // Serialize the first request for an unregistered compatibility namespace. The gate is
    // acquired before choosing a store, so two concurrent creates cannot both publish a
    // different authoritative store for the same project.
    let routed_gate = if let Some(project) = routed_project {
        match state.registry.as_ref() {
            Some(registry) if registry.store_for(project).is_none() => {
                let Some(gate) = registry.operation_gate(project, None) else {
                    return error(500, "INTERNAL");
                };
                Some(gate)
            }
            _ => None,
        }
    } else {
        None
    };
    let _routed_operation = match routed_gate.as_ref() {
        Some(gate) => match gate.lock() {
            Ok(operation) => Some(operation),
            Err(_) => return error(500, "INTERNAL"),
        },
        None => None,
    };
    let mut pending_routed_project = None;
    let store_arc = if let Some(project) = routed_project {
        let Some(registry) = state.registry.as_ref() else {
            return error(500, "INTERNAL");
        };
        let Some(store) = registry
            .store_for(project)
            .or_else(|| registry.routed_store_for(project))
            .or_else(|| {
                let candidate = registry.routed_candidate(project)?;
                pending_routed_project = Some(project.to_owned());
                Some(Arc::new(Mutex::new(candidate)))
            })
        else {
            return error(400, "INVALID_PROJECT_ID");
        };
        store
    } else {
        match select_store(state, path, query, body, resolution) {
            Ok(store) => store,
            Err(response) => return response,
        }
    };
    let (store_project, store_tenant) = {
        let Ok(store) = store_arc.lock() else {
            return error(500, "INTERNAL");
        };
        (
            store.project_id().to_owned(),
            store.tenant_id().map(str::to_owned),
        )
    };
    let operation_gate = if state.blocking.as_deref().is_some_and(|blocking| {
        matches!(
            resolution,
            routes::Resolution::Matched { route, .. }
                if handler_may_invoke_blocking_auth(blocking, route.handler)
        )
    }) {
        let gate = match state.registry.as_ref() {
            Some(registry) => {
                let Some(gate) = registry.operation_gate(&store_project, store_tenant.as_deref())
                else {
                    return error(500, "INTERNAL");
                };
                gate
            }
            None => state.operation_gate.clone(),
        };
        Some(gate)
    } else {
        None
    };
    let _operation = match operation_gate.as_ref() {
        Some(gate) => match gate.lock() {
            Ok(operation) => Some(operation),
            Err(_) => return error(500, "INTERNAL"),
        },
        None => None,
    };
    let tenant_metadata = store_tenant.as_deref().and_then(|tenant| {
        state
            .registry
            .as_ref()
            .and_then(|registry| registry.tenant_metadata(&store_project, tenant))
    });
    // The functions runtime belongs to the default session: only its users' lifecycle
    // events reach the Auth triggers.
    let default_store = Arc::ptr_eq(&store_arc, &state.store);
    let _drain = EventDrain {
        store: store_arc.clone(),
        sink: state.events.as_ref().filter(|_| default_store),
    };
    let Ok(mut store) = store_arc.lock() else {
        return error(500, "INTERNAL");
    };
    if let Some(request_tenant) = str_field(body, "tenantId") {
        if store.tenant_id() != Some(request_tenant) {
            return error(400, "TENANT_ID_MISMATCH");
        }
    }
    // App Check, once the route and the target project are known and before any Auth work
    // (spec 7.4 and 13.3). Locking the store is not a state transition, so a denial here
    // still leaves no user, no issued or rotated credential, no consumed OOB or phone code,
    // no MFA change and no abuse counter behind.
    if let Some(denial) = app_check_denial(state, path, headers, store.project_id(), at) {
        return denial;
    }
    // The privilege class is decided by the path alone, so a wrong-method request to a
    // privileged path is refused for its missing credential before it is refused for its
    // method: the class check cannot be sidestepped by the method.
    let (route, project, tenant) = match resolution {
        routes::Resolution::Matched {
            route,
            project,
            tenant,
        } => (route, project, tenant),
        routes::Resolution::MethodNotAllowed { class, project, .. } => {
            if let Err(r) = privilege_check(state, class, project, headers, method, &store) {
                return r;
            }
            return error(405, "METHOD_NOT_ALLOWED");
        }
        routes::Resolution::NotFound => return not_found(),
    };
    if let Err(r) = privilege_check(state, route.class, project, headers, method, &store) {
        return r;
    }
    if matches!(
        route.handler,
        routes::Handler::AdminGetProjectConfig | routes::Handler::AdminUpdateProjectConfig
    ) {
        drop(store);
        return project_config_management(state, route.handler, project, body);
    }
    if matches!(
        route.handler,
        routes::Handler::TenantCreate
            | routes::Handler::TenantList
            | routes::Handler::TenantGet
            | routes::Handler::TenantUpdate
            | routes::Handler::TenantDelete
    ) {
        // Tenant management mutates the registry and may initialize a tenant from the parent
        // project's configuration. Release the request's selected store before that registry
        // operation so initialization never attempts to reacquire the same non-reentrant lock.
        drop(store);
        return tenant_management(state, route.handler, project, tenant, query, body);
    }
    if tenant.is_some() && store.tenant_id() != tenant {
        return error(404, "TENANT_NOT_FOUND");
    }
    if route.class == routes::RouteClass::EndUser && store_tenant.is_some() {
        if let Some(denial) =
            tenant_policy_denial_with_metadata(route.handler, tenant_metadata.as_ref(), body)
        {
            return denial;
        }
    }
    // Expired transient credentials are swept before every request is served, so nothing
    // past its lifetime is observable (`AUTH-TRANSIENT-01`, `-02`).
    store.sweep_transient_credentials(at);
    if route.class != routes::RouteClass::EndUser {
        let signer = store.signer_arc();
        let response = dispatch(
            route.handler,
            &mut store,
            query,
            body,
            headers,
            at,
            state.into(),
        );
        let retain_candidate = response.status == 200
            && pending_routed_project.is_some()
            && matches!(
                route.handler,
                routes::Handler::AdminCreate | routes::Handler::AdminBatchCreate
            )
            && store.user_count() != 0;
        drop(store);
        if retain_candidate {
            let project = pending_routed_project.expect("checked above");
            let Some(registry) = state.registry.as_ref() else {
                return error(500, "INTERNAL");
            };
            match registry.install_routed(&project, store_arc.clone()) {
                RoutedStoreInstall::Installed(_) => {}
                RoutedStoreInstall::Existing(_) => {
                    return error(409, "CONCURRENT_PROJECT_OWNERSHIP");
                }
                RoutedStoreInstall::RegisteredConflict => {
                    return error(400, "INVALID_PROJECT_ID");
                }
                RoutedStoreInstall::Capacity => return error(429, "RESOURCE_EXHAUSTED"),
                RoutedStoreInstall::InvalidStore => return error(500, "INTERNAL"),
            }
        }
        let response = if response.status == 200 {
            JsonResponse {
                status: 200,
                body: without_nulls(response.body),
            }
        } else {
            response
        };
        return sign_response_tokens(response, signer.as_deref());
    }
    let signer = store.signer_arc();
    let response = if let Some(blocking) = state
        .blocking
        .as_deref()
        .filter(|blocking| handler_may_invoke_blocking_auth(*blocking, route.handler))
    {
        dispatch_with_blocking_hook(
            state,
            blocking,
            route.handler,
            &store_arc,
            store,
            query,
            body,
            headers,
            at,
        )
    } else {
        let response = dispatch(
            route.handler,
            &mut store,
            query,
            body,
            headers,
            at,
            state.into(),
        );
        drop(store);
        response
    };
    let response = if response.status == 200 {
        JsonResponse {
            status: 200,
            body: without_nulls(response.body),
        }
    } else {
        response
    };
    sign_response_tokens(response, signer.as_deref())
}

/// The credential and project checks of a route class.
fn privilege_check(
    state: &AuthState,
    class: routes::RouteClass,
    project: Option<&str>,
    headers: &RequestHeaders,
    method: &str,
    store: &AuthStore,
) -> Result<(), JsonResponse> {
    match class {
        routes::RouteClass::Jwks | routes::RouteClass::EndUser => Ok(()),
        routes::RouteClass::Emulator => {
            emulator_guard(state, headers)?;
            if project != Some(store.project_id()) {
                return Err(error(400, "INVALID_PROJECT_ID"));
            }
            Ok(())
        }
        routes::RouteClass::Admin => admin_guard(headers, method, project.unwrap_or(""), store),
    }
}

/// Runs the handler of a resolved route.
#[derive(Clone, Copy)]
struct DispatchOptions {
    totp_extension_enabled: bool,
    stateless_refresh_tokens: bool,
    fake_custom_token_expiry: FakeCustomTokenExpiry,
    query_limits: AuthQueryLimits,
}

impl From<&AuthState> for DispatchOptions {
    fn from(state: &AuthState) -> Self {
        Self {
            totp_extension_enabled: state.totp_extension_enabled,
            stateless_refresh_tokens: state.stateless_refresh_tokens,
            fake_custom_token_expiry: state.fake_custom_token_expiry,
            query_limits: state.query_limits,
        }
    }
}

fn dispatch(
    handler: routes::Handler,
    store: &mut AuthStore,
    query: Option<&str>,
    body: &Value,
    headers: &RequestHeaders,
    at: LogicalInstant,
    options: DispatchOptions,
) -> JsonResponse {
    use routes::Handler;
    match handler {
        Handler::Jwks => {
            // The public keys signed ID tokens verify against (empty for unsigned sessions).
            let keys: Vec<Value> = store
                .signer()
                .and_then(|signer| {
                    signer.public_jwk().map_or_else(
                        || serde_json::from_str::<Value>(&signer.public_jwk_json()).ok(),
                        |jwk| Some(crate::signing::jwk_value(jwk)),
                    )
                })
                .into_iter()
                .collect();
            JsonResponse {
                status: 200,
                body: json!({"keys": keys}),
            }
        }
        Handler::SignUp => sign_up(store, body, at, None),
        Handler::SignInWithPassword => sign_in_with_password(store, body, at),
        Handler::SignInWithCustomToken => sign_in_with_custom_token(
            store,
            body,
            at,
            options.fake_custom_token_expiry == FakeCustomTokenExpiry::Reject,
        ),
        Handler::Lookup => lookup(store, body, at, false),
        Handler::Update | Handler::AdminUpdate => {
            update(store, body, at, options.stateless_refresh_tokens)
        }
        Handler::Delete => delete_account(store, body, at, false),
        Handler::SendOobCode => send_oob_code(store, body, at, headers),
        Handler::ResetPassword => reset_password(store, body, at, options.stateless_refresh_tokens),
        Handler::SignInWithEmailLink => sign_in_with_email_link(store, body, at),
        Handler::SendVerificationCode => send_verification_code(store, body, at),
        Handler::SignInWithPhoneNumber => sign_in_with_phone_number(store, body, at),
        Handler::SignInWithIdp => sign_in_with_idp(store, body, at),
        Handler::CreateAuthUri => create_auth_uri(store, body),
        Handler::Projects => JsonResponse {
            status: 200,
            body: json!({"projectId": store.project_id(), "authorizedDomains": ["localhost"]}),
        },
        Handler::RecaptchaParams => JsonResponse {
            status: 200,
            body: json!({
                "kind": "identitytoolkit#GetRecaptchaParamResponse",
                "recaptchaStoken": "This-is-a-fake-token__Dont-send-this-to-the-Recaptcha-service__The-Auth-Emulator-does-not-support-Recaptcha",
                "recaptchaSiteKey": "Fake-key__Do-not-send-this-to-Recaptcha_",
            }),
        },
        Handler::MfaEnrollmentStart => {
            mfa_enrollment_start(store, body, at, options.totp_extension_enabled)
        }
        Handler::MfaEnrollmentFinalize => mfa_enrollment_finalize(store, body, at),
        Handler::MfaEnrollmentWithdraw => mfa_enrollment_withdraw(store, body, at),
        Handler::MfaSignInStart => mfa_sign_in_start(store, body, at),
        Handler::MfaSignInFinalize => mfa_sign_in_finalize(store, body, at),
        Handler::Token => refresh(store, body, at, options.stateless_refresh_tokens),
        Handler::AdminCreate => admin_create(store, body, at),
        Handler::AdminLookup => lookup(store, body, at, true),
        Handler::AdminDelete => delete_account(store, body, at, true),
        Handler::AdminBatchGet => admin_batch_get(store, query, body),
        Handler::AdminBatchCreate => admin_batch_create(store, body, at),
        Handler::AdminBatchDelete => admin_batch_delete(store, body),
        Handler::AdminQuery => admin_query(store, body, options.query_limits),
        // Admin link generators: the code and link come back to the caller.
        Handler::AdminSendOobCode => {
            let mut with_link = body.clone();
            with_link["returnOobLink"] = json!(true);
            send_oob_code(store, &with_link, at, headers)
        }
        Handler::AdminCreateSessionCookie => create_session_cookie(store, body, at),
        Handler::TenantCreate
        | Handler::TenantList
        | Handler::TenantGet
        | Handler::TenantUpdate
        | Handler::TenantDelete
        | Handler::AdminGetProjectConfig
        | Handler::AdminUpdateProjectConfig => error(500, "INTERNAL"),
        Handler::EmulatorOobCodes => emulator_route(store, "GET", "oobCodes", headers, body),
        Handler::EmulatorVerificationCodes => {
            emulator_route(store, "GET", "verificationCodes", headers, body)
        }
        Handler::EmulatorClearAccounts => {
            emulator_route(store, "DELETE", "accounts", headers, body)
        }
        Handler::EmulatorGetConfig => emulator_route(store, "GET", "config", headers, body),
        Handler::EmulatorPatchConfig => emulator_route(store, "PATCH", "config", headers, body),
    }
}

fn project_config_management(
    state: &AuthState,
    handler: routes::Handler,
    project: Option<&str>,
    body: &Value,
) -> JsonResponse {
    use routes::Handler;
    let Some(project) = project else {
        return error(400, "INVALID_PROJECT_ID");
    };
    let store = state
        .registry
        .as_ref()
        .and_then(|registry| registry.store_for(project))
        .or_else(|| {
            (project == state.store.lock().ok()?.project_id()).then(|| state.store.clone())
        });
    let Some(store) = store else {
        return error(400, "INVALID_PROJECT_ID");
    };
    let Ok(store) = store.lock() else {
        return error(500, "INTERNAL");
    };
    let mut config = store.config();
    if handler == Handler::AdminGetProjectConfig {
        return JsonResponse {
            status: 200,
            body: project_config_json(config),
        };
    }
    if let Some(value) = body
        .get("signIn")
        .and_then(|sign_in| sign_in.get("allowDuplicateEmails"))
        .and_then(Value::as_bool)
    {
        config.allow_duplicate_emails = value;
    }
    if let Some(value) = body
        .get("emailPrivacyConfig")
        .and_then(|privacy| privacy.get("enableImprovedEmailPrivacy"))
        .and_then(Value::as_bool)
    {
        config.enable_improved_email_privacy = value;
    }
    drop(store);
    if let Some(registry) = &state.registry {
        if !registry.set_project_config(project, config) {
            return error(500, "INTERNAL");
        }
    } else if let Ok(mut store) = state.store.lock() {
        store.set_config(config);
    } else {
        return error(500, "INTERNAL");
    }
    JsonResponse {
        status: 200,
        body: project_config_json(config),
    }
}

fn tenant_metadata(body: &Value) -> fireemu_core_auth::store::TenantMetadata {
    fireemu_core_auth::store::TenantMetadata {
        display_name: str_field(body, "displayName").map(str::to_owned),
        allow_password_signup: body
            .get("allowPasswordSignup")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        enable_email_link_signin: body
            .get("enableEmailLinkSignin")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        enable_anonymous_user: body
            .get("enableAnonymousUser")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        disable_auth: body
            .get("disableAuth")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

fn tenant_metadata_patch(
    body: &Value,
    query: Option<&str>,
) -> Result<fireemu_core_auth::store::TenantMetadataPatch, JsonResponse> {
    const FIELDS: [&str; 5] = [
        "displayName",
        "allowPasswordSignup",
        "enableEmailLinkSignin",
        "enableAnonymousUser",
        "disableAuth",
    ];
    let params = query_params(query);
    let fields: Vec<&str> = params.get("updateMask").map_or_else(
        || {
            FIELDS
                .into_iter()
                .filter(|field| body.get(*field).is_some())
                .collect()
        },
        |mask| mask.split(',').filter(|field| !field.is_empty()).collect(),
    );
    if fields.iter().any(|field| !FIELDS.contains(field)) {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    let mut patch = fireemu_core_auth::store::TenantMetadataPatch::default();
    for field in fields {
        match field {
            "displayName" => {
                patch.display_name = Some(match body.get(field) {
                    None | Some(Value::Null) => None,
                    Some(Value::String(value)) => Some(value.clone()),
                    Some(_) => return Err(error(400, "INVALID_ARGUMENT")),
                });
            }
            "allowPasswordSignup" => {
                patch.allow_password_signup = Some(bool_update(body, field)?);
            }
            "enableEmailLinkSignin" => {
                patch.enable_email_link_signin = Some(bool_update(body, field)?);
            }
            "enableAnonymousUser" => {
                patch.enable_anonymous_user = Some(bool_update(body, field)?);
            }
            "disableAuth" => patch.disable_auth = Some(bool_update(body, field)?),
            _ => unreachable!("tenant update mask was validated"),
        }
    }
    Ok(patch)
}

fn bool_update(body: &Value, field: &str) -> Result<bool, JsonResponse> {
    match body.get(field) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(error(400, "INVALID_ARGUMENT")),
    }
}

fn tenant_json(
    project: &str,
    tenant: &str,
    metadata: &fireemu_core_auth::store::TenantMetadata,
) -> Value {
    json!({
        "name": format!("projects/{project}/tenants/{tenant}"),
        "displayName": metadata.display_name,
        "allowPasswordSignup": metadata.allow_password_signup,
        "enableEmailLinkSignin": metadata.enable_email_link_signin,
        "enableAnonymousUser": metadata.enable_anonymous_user,
        "disableAuth": metadata.disable_auth,
        "mfaConfig": {"state": "DISABLED", "enabledProviders": []},
    })
}

fn tenant_management(
    state: &AuthState,
    handler: routes::Handler,
    project: Option<&str>,
    tenant: Option<&str>,
    query: Option<&str>,
    body: &Value,
) -> JsonResponse {
    use routes::Handler;
    let Some(registry) = &state.registry else {
        return error(400, "INVALID_PROJECT_ID");
    };
    let Some(project) = project else {
        return error(400, "INVALID_PROJECT_ID");
    };
    match handler {
        Handler::TenantCreate => {
            let metadata = tenant_metadata(body);
            let Some(tenant) = registry.create_tenant(project, metadata.clone()) else {
                return error(400, "INVALID_PROJECT_ID");
            };
            JsonResponse {
                status: 200,
                body: tenant_json(project, &tenant, &metadata),
            }
        }
        Handler::TenantList => {
            let params = query_params(query);
            let page_size = params
                .get("pageSize")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(20)
                .min(1_000);
            let page_token = params.get("pageToken").map(String::as_str);
            let mut ids: Vec<String> = registry
                .tenants(project)
                .into_iter()
                .filter(|id| page_token.is_none_or(|token| id.as_str() > token))
                .collect();
            let has_more = ids.len() > page_size;
            ids.truncate(page_size);
            let tenants: Vec<Value> = ids
                .iter()
                .filter_map(|id| {
                    registry
                        .tenant_metadata(project, id)
                        .map(|metadata| tenant_json(project, id, &metadata))
                })
                .collect();
            let next = has_more.then(|| ids.last().cloned()).flatten();
            JsonResponse {
                status: 200,
                body: json!({"tenants": tenants, "nextPageToken": next}),
            }
        }
        Handler::TenantGet => {
            let Some(tenant) = tenant else {
                return error(400, "INVALID_TENANT_ID");
            };
            let Some(metadata) = registry.tenant_metadata(project, tenant) else {
                return error(404, "TENANT_NOT_FOUND");
            };
            JsonResponse {
                status: 200,
                body: tenant_json(project, tenant, &metadata),
            }
        }
        Handler::TenantUpdate => {
            let Some(tenant) = tenant else {
                return error(400, "INVALID_TENANT_ID");
            };
            let patch = match tenant_metadata_patch(body, query) {
                Ok(patch) => patch,
                Err(response) => return response,
            };
            let Some(metadata) = registry.patch_tenant(project, tenant, patch) else {
                return error(404, "TENANT_NOT_FOUND");
            };
            JsonResponse {
                status: 200,
                body: tenant_json(project, tenant, &metadata),
            }
        }
        Handler::TenantDelete => {
            let Some(tenant) = tenant else {
                return error(400, "INVALID_TENANT_ID");
            };
            if !registry.delete_tenant(project, tenant) {
                return error(404, "TENANT_NOT_FOUND");
            }
            JsonResponse {
                status: 200,
                body: json!({}),
            }
        }
        _ => error(500, "INTERNAL"),
    }
}

fn tenant_policy_denial_with_metadata(
    handler: routes::Handler,
    metadata: Option<&fireemu_core_auth::store::TenantMetadata>,
    body: &Value,
) -> Option<JsonResponse> {
    let Some(metadata) = metadata else {
        return Some(error(400, "TENANT_NOT_FOUND"));
    };
    let authenticates = matches!(
        handler,
        routes::Handler::SignUp
            | routes::Handler::Token
            | routes::Handler::SignInWithPassword
            | routes::Handler::SignInWithCustomToken
            | routes::Handler::SignInWithEmailLink
            | routes::Handler::SignInWithPhoneNumber
            | routes::Handler::SignInWithIdp
            | routes::Handler::MfaSignInFinalize
    );
    if metadata.disable_auth && authenticates {
        return Some(error(400, "PROJECT_DISABLED"));
    }
    if handler == routes::Handler::SignInWithPassword && !metadata.allow_password_signup {
        return Some(error(400, "OPERATION_NOT_ALLOWED"));
    }
    if handler == routes::Handler::SignInWithEmailLink && !metadata.enable_email_link_signin {
        return Some(error(400, "OPERATION_NOT_ALLOWED"));
    }
    if handler == routes::Handler::SignUp {
        let links_existing_user = body.get("idToken").is_some();
        let has_password = str_field(body, "password").is_some();
        let has_email = str_field(body, "email").is_some();
        if has_password && !links_existing_user && !metadata.allow_password_signup {
            return Some(error(400, "OPERATION_NOT_ALLOWED"));
        }
        if !has_email && !has_password && !links_existing_user && !metadata.enable_anonymous_user {
            return Some(error(400, "OPERATION_NOT_ALLOWED"));
        }
    }
    None
}

/// The store a request is for. Project-scoped routes (Admin SDK, emulator inspection)
/// name their project; client SDK routes of a session project are recognised by the API
/// key the session declared, by the audience of the ID token they carry, or by the store
/// that issued their refresh token; everything else is the default project's.
fn select_store(
    state: &AuthState,
    path: &str,
    query: Option<&str>,
    body: &Value,
    resolution: routes::Resolution<'_>,
) -> Result<Arc<Mutex<AuthStore>>, JsonResponse> {
    let Some(registry) = &state.registry else {
        return Ok(state.store.clone());
    };
    if let Some((project, tenant)) = routes::scoped_target(path) {
        return Ok(tenant
            .and_then(|tenant| registry.tenant_store(project, tenant))
            .or_else(|| registry.store_for(project))
            .or_else(|| registry.routed_store_for(project))
            .unwrap_or_else(|| state.store.clone()));
    }
    // Keys are declared from [A-Za-z0-9._-], but a client may still percent-encode them.
    let api_key = query
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("key=")))
        .map(|value| {
            fireemu_core_types::codec::percent_decode(
                value,
                fireemu_core_types::codec::PlusMode::Space,
            )
        });
    if let Some(key) = api_key.as_deref() {
        let project = state
            .tenancy
            .as_ref()
            .and_then(|t| t.read().ok())
            .and_then(|t| t.project_of_api_key(key).map(str::to_owned));
        if let Some(project) = project {
            let tenant = str_field(body, "tenantId");
            if let Some(store) = tenant
                .and_then(|tenant| registry.tenant_store(&project, tenant))
                .or_else(|| registry.store_for(&project))
            {
                return Ok(store);
            }
        }
    }
    let exchanges_custom_token = matches!(
        resolution,
        routes::Resolution::Matched { route, .. }
            if route.handler == routes::Handler::SignInWithCustomToken
    );
    if state.allow_routed_projects && exchanges_custom_token {
        if let Some(uid) = custom_token_uid(body) {
            use fireemu_core_auth::store::CompatibilityUserStoreMatch;

            match registry.compatibility_store_for_unique_user(&uid) {
                CompatibilityUserStoreMatch::Unique(store) => return Ok(store),
                CompatibilityUserStoreMatch::Ambiguous => {
                    return Err(error(400, "INVALID_CUSTOM_TOKEN"));
                }
                CompatibilityUserStoreMatch::Unavailable => return Err(error(500, "INTERNAL")),
                CompatibilityUserStoreMatch::NotFound => {}
            }
        }
    }
    if let Some(token) = str_field(body, "idToken") {
        let signer = state.store.lock().ok().and_then(|s| s.signer_arc());
        let target = fireemu_core_auth::jwt::decode_token(token, signer.as_deref())
            .ok()
            .and_then(|d| {
                let audience = d
                    .payload
                    .get("aud")
                    .and_then(fireemu_core_types::json::JsonValue::as_str)
                    .map(str::to_owned)?;
                let tenant = d
                    .payload
                    .get("firebase")
                    .and_then(|firebase| firebase.get("tenant"))
                    .and_then(fireemu_core_types::json::JsonValue::as_str)
                    .map(str::to_owned);
                Some((audience, tenant))
            });
        if let Some((project, tenant)) = target {
            if let Some(store) = tenant
                .as_deref()
                .and_then(|tenant| registry.tenant_store(&project, tenant))
                .or_else(|| registry.store_for(&project))
                .or_else(|| registry.routed_store_for(&project))
            {
                return Ok(store);
            }
        }
    }
    if let Some(token) = str_field(body, "refresh_token") {
        use fireemu_core_auth::store::RefreshTokenStoreMatch;

        match registry.store_for_refresh_token(token) {
            RefreshTokenStoreMatch::Unique(store) => return Ok(store),
            RefreshTokenStoreMatch::Ambiguous => {
                return Err(error(400, "INVALID_REFRESH_TOKEN"));
            }
            RefreshTokenStoreMatch::Unavailable => return Err(error(500, "INTERNAL")),
            RefreshTokenStoreMatch::NotFound => {}
        }
    }
    if let Some(tenant) = str_field(body, "tenantId") {
        if let Some(store) = registry.tenant_store(registry.default_project(), tenant) {
            return Ok(store);
        }
    }
    Ok(state.store.clone())
}

fn custom_token_uid(body: &Value) -> Option<String> {
    let token = str_field(body, "token")?;
    let payload = if token.trim_start().starts_with('{') {
        fireemu_core_types::json::parse(token).ok()?
    } else {
        let decoded = fireemu_core_auth::jwt::decode_unsigned(token).ok()?;
        (decoded.payload.get("aud").and_then(JsonValue::as_str) == Some(CUSTOM_TOKEN_AUDIENCE))
            .then_some(decoded.payload)?
    };
    payload
        .get("uid")
        .or_else(|| payload.get("user_id"))
        .and_then(|value| match value {
            JsonValue::String(value) if !value.is_empty() => Some(value.clone()),
            JsonValue::Int(value) => Some(value.to_string()),
            _ => None,
        })
}

/// `accounts:signUp`: a password user when an email or a password is present (both are then
/// required, the email first, as the official emulator checks them), otherwise an anonymous
/// user. `localId` is an Admin-only parameter on this route.
fn sign_up(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    forced_local_id: Option<&str>,
) -> JsonResponse {
    if body.get("localId").is_some_and(|v| !v.is_null()) {
        return error(400, "UNEXPECTED_PARAMETER : User ID");
    }
    let email = str_field(body, "email");
    let password = str_field(body, "password");
    // With an `idToken` the request upgrades that session's account (the client SDK's
    // `linkWithCredential` for an email credential) instead of creating one.
    let has_session = body.get("idToken").is_some_and(|t| !t.is_null());
    let new_user = if has_session || email.is_some() || password.is_some() {
        let Some(email) = email.filter(|e| !e.is_empty()) else {
            return error(400, "MISSING_EMAIL");
        };
        if password.is_none_or(str::is_empty) {
            return error(400, "MISSING_PASSWORD");
        }
        NewUser::email(email)
    } else {
        NewUser::anonymous()
    };
    // Validated before the account exists: a rejected password leaves no user behind.
    if let Some(password) = password {
        if let Err(e) = AuthStore::validate_password(password) {
            return auth_error(&e);
        }
    }
    let uid = if has_session {
        let uid = match verify(store, body, at) {
            Ok(uid) => uid,
            Err(r) => return r,
        };
        let Some(email) = new_user.email.as_deref() else {
            return error(400, "MISSING_EMAIL");
        };
        if store
            .user_by_email(email)
            .is_some_and(|u| u.local_id != uid)
        {
            return error(400, "EMAIL_EXISTS");
        }
        if let Err(e) = store.set_email(&uid, email) {
            return auth_error(&e);
        }
        if let Some(u) = store.user_mut(&uid) {
            u.email_verified = false;
            u.provider = fireemu_core_auth::store::Provider::Password;
        }
        uid
    } else {
        match store.create_user_with_id(new_user, forced_local_id, at) {
            Ok(uid) => uid,
            Err(e) => return auth_error(&e),
        }
    };
    if let Some(password) = password {
        if let Err(e) = store.set_password(&uid, password) {
            return auth_error(&e);
        }
    }
    if let Some(name) = str_field(body, "displayName") {
        if let Some(u) = store.user_mut(&uid) {
            u.display_name = Some(name.to_owned());
        }
    }
    store.record_sign_in(&uid, at);
    let display_name = store.user(&uid).and_then(|u| u.display_name.clone());
    match issue_tokens(store, &uid, None, at) {
        Ok(mut body) => {
            body["kind"] = json!("identitytoolkit#SignupNewUserResponse");
            body["displayName"] = json!(display_name);
            JsonResponse { status: 200, body }
        }
        Err(r) => r,
    }
}

/// Audience every Firebase custom token carries.
pub const CUSTOM_TOKEN_AUDIENCE: &str =
    "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

/// `accounts:signInWithCustomToken`: the Admin SDK mints unsigned (`alg: none`) custom
/// tokens against an emulator; the user is created on first sign-in.
fn sign_in_with_custom_token(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    reject_expired: bool,
) -> JsonResponse {
    let Some(token) = str_field(body, "token").filter(|t| !t.is_empty()) else {
        return error(400, "MISSING_CUSTOM_TOKEN");
    };
    // Like the official emulator, a strict JSON object is accepted as a fake custom token
    // beside the unsigned JWT the Admin SDK mints.
    let payload = if token.trim_start().starts_with('{') {
        match fireemu_core_types::json::parse(token) {
            Ok(v) => v,
            Err(_) => {
                return error(
                    400,
                    "INVALID_CUSTOM_TOKEN : ((Auth Emulator only accepts strict JSON or JWTs as fake custom tokens.))",
                )
            }
        }
    } else {
        let Ok(decoded) = fireemu_core_auth::jwt::decode_unsigned(token) else {
            return error(400, "INVALID_CUSTOM_TOKEN : Invalid assertion format");
        };
        if decoded.payload.get("aud").and_then(JsonValue::as_str) != Some(CUSTOM_TOKEN_AUDIENCE) {
            return error(400, "INVALID_CUSTOM_TOKEN : wrong audience");
        }
        decoded.payload
    };
    let uid = payload
        .get("uid")
        .or_else(|| payload.get("user_id"))
        .and_then(|v| match v {
            JsonValue::String(s) => Some(s.clone()),
            JsonValue::Int(i) => Some(i.to_string()),
            _ => None,
        })
        .filter(|s| !s.is_empty());
    let Some(uid) = uid else {
        return error(400, "MISSING_IDENTIFIER");
    };
    let uid = uid.as_str();
    let now_secs = i64::try_from(at.as_nanos().div_euclid(1_000_000_000)).unwrap_or(i64::MAX);
    if reject_expired
        && payload
            .get("exp")
            .and_then(JsonValue::as_i64)
            .is_some_and(|exp| now_secs >= exp)
    {
        return error(400, "TOKEN_EXPIRED");
    }
    let mut extra = CustomClaims::default();
    if let Some(JsonValue::Object(claims)) = payload.get("claims") {
        for (k, v) in claims {
            let Some(cv) = claims_from_json(v) else {
                return error(400, "INVALID_CUSTOM_TOKEN : unsupported claim value");
            };
            if let Err(e) = extra.insert(k, cv) {
                return error(400, &format!("INVALID_CUSTOM_TOKEN : {e}"));
            }
        }
    }
    let (uid, is_new) = if let Some(u) = store.user_by_id(uid) {
        (u.local_id.clone(), false)
    } else {
        let new_user = NewUser {
            email: None,
            email_verified: false,
            provider: fireemu_core_auth::store::Provider::Custom,
        };
        match store.create_user_with_id(new_user, Some(uid), at) {
            Ok(id) => (id, true),
            Err(e) => return auth_error(&e),
        }
    };
    if store.user(&uid).is_some_and(|u| u.disabled) {
        return error(400, "USER_DISABLED");
    }
    store.record_sign_in(&uid, at);
    match issue_tokens_with(
        store,
        &uid,
        None,
        at,
        Some(&extra),
        Some(fireemu_core_auth::store::Provider::Custom),
    ) {
        Ok(mut body) => {
            body["kind"] = json!("identitytoolkit#VerifyCustomTokenResponse");
            body["isNewUser"] = json!(is_new);
            JsonResponse { status: 200, body }
        }
        Err(r) => r,
    }
}

fn sign_in_with_password(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    // The official order: the email is checked (present, well-formed) before the password.
    let Some(email) = str_field(body, "email") else {
        return error(400, "MISSING_EMAIL");
    };
    if !email.contains('@') {
        return error(400, "INVALID_EMAIL");
    }
    let Some(password) = str_field(body, "password").filter(|p| !p.is_empty()) else {
        return error(400, "MISSING_PASSWORD");
    };
    let uid = match store.verify_password(email, password, at) {
        Ok(uid) => uid,
        Err(e) => return auth_error(&e),
    };
    finish_sign_in(
        store,
        &uid,
        at,
        None,
        &[
            ("kind", json!("identitytoolkit#VerifyPasswordResponse")),
            ("registered", json!(true)),
        ],
    )
}

/// Completes a first-factor sign-in: a pending credential when the user has second
/// factors enrolled (every sign-in route enforces MFA, not only passwords), otherwise
/// tokens for `provider` with `extra` fields merged in.
fn finish_sign_in(
    store: &mut AuthStore,
    uid: &LocalId,
    at: LogicalInstant,
    provider: Option<fireemu_core_auth::store::Provider>,
    extra: &[(&str, Value)],
) -> JsonResponse {
    let factors = mfa_info(store, uid, true);
    if !factors.is_empty() {
        // Second factor required: no ID token yet, only a pending credential.
        let email = store.user(uid).and_then(|u| u.email.clone());
        return match store.start_mfa_sign_in(uid, at) {
            Ok(pending) => {
                let mut body = json!({"mfaPendingCredential": pending.as_str(), "mfaInfo": factors, "localId": uid.as_str(), "email": email});
                for (k, v) in extra {
                    body[*k] = v.clone();
                }
                JsonResponse { status: 200, body }
            }
            Err(e) => mfa_error(&e),
        };
    }
    match issue_tokens_with(store, uid, None, at, None, provider) {
        Ok(mut body) => {
            for (k, v) in extra {
                body[*k] = v.clone();
            }
            JsonResponse { status: 200, body }
        }
        Err(r) => r,
    }
}

/// The last four digits stay, every other digit becomes `*`: the shape a pending-credential
/// response reveals of an enrolled phone factor before the second factor is verified.
fn obfuscate_phone_number(phone: &str) -> String {
    let mut digits_seen = 0;
    let mut out: Vec<char> = phone.chars().collect();
    for c in out.iter_mut().rev() {
        if c.is_ascii_digit() {
            digits_seen += 1;
            if digits_seen > 4 {
                *c = '*';
            }
        }
    }
    out.into_iter().collect()
}

fn user_json(store: &AuthStore, uid: &LocalId) -> Value {
    let Some(u) = store.user(uid) else {
        return Value::Null;
    };
    let mfa = mfa_info(store, uid, false);
    let mut providers: Vec<Value> = Vec::new();
    // The official record lists a `password` provider for an email with a password or an
    // email-link sign-in, and nothing for an address that has neither.
    if let Some(email) = &u.email {
        if store.has_password(uid) || u.provider == fireemu_core_auth::store::Provider::EmailLink {
            providers.push(json!({"providerId": "password", "rawId": email, "federatedId": email, "email": email, "displayName": u.display_name, "photoUrl": u.photo_url}));
        }
    }
    if let Some(phone) = &u.phone_number {
        providers.push(json!({"providerId": "phone", "rawId": phone, "phoneNumber": phone}));
    }
    for f in &u.federated {
        providers.push(json!({"providerId": f.provider_id, "rawId": f.raw_id, "federatedId": f.raw_id, "email": f.email, "displayName": f.display_name, "photoUrl": f.photo_url}));
    }
    json!({
        "localId": u.local_id.as_str(),
        "tenantId": store.tenant_id(),
        "email": u.email,
        "displayName": u.display_name,
        "photoUrl": u.photo_url,
        "phoneNumber": u.phone_number,
        "emailVerified": u.email_verified,
        "disabled": u.disabled,
        // Absent, not "{}", when no claim is set: what the Admin SDK reads back as no claims.
        "customAttributes": (u.custom_claims.canonical_json() != "{}").then(|| u.custom_claims.canonical_json()),
        "providerUserInfo": providers,
        "mfaInfo": mfa,
        "createdAt": (u.created_at.as_nanos() / 1_000_000).to_string(),
        "lastLoginAt": u.last_sign_in_at.map(|t| (t.as_nanos() / 1_000_000).to_string()),
        "validSince": (u.tokens_valid_after.as_nanos() / 1_000_000_000).to_string(),
    })
}

/// Maximum identifiers per lookup (Admin SDK `getUsers`).
const MAX_LOOKUP_IDENTIFIERS: usize = 100;

/// Optional string field; a present non-string (other than null) is a type error.
fn opt_str<'a>(body: &'a Value, key: &str) -> Result<Option<&'a str>, JsonResponse> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(error(
            400,
            &format!("INVALID_ARGUMENT : {key} must be a string"),
        )),
    }
}

/// Optional boolean field; a present non-boolean (other than null) is a type error.
fn opt_bool(body: &Value, key: &str) -> Result<Option<bool>, JsonResponse> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(error(
            400,
            &format!("INVALID_ARGUMENT : {key} must be a boolean"),
        )),
    }
}

/// A string or an array of strings (lookup identifiers); bounded.
fn id_list(body: &Value, key: &str) -> Result<Vec<String>, JsonResponse> {
    let items = match body.get(key) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(s) => out.push(s.clone()),
                    _ => {
                        return Err(error(
                            400,
                            &format!("INVALID_ARGUMENT : {key} must contain strings"),
                        ))
                    }
                }
            }
            out
        }
        Some(_) => {
            return Err(error(
                400,
                &format!("INVALID_ARGUMENT : {key} must be a string or an array of strings"),
            ))
        }
    };
    if items.len() > MAX_LOOKUP_IDENTIFIERS {
        return Err(error(
            400,
            &format!("INVALID_ARGUMENT : at most {MAX_LOOKUP_IDENTIFIERS} identifiers per lookup"),
        ));
    }
    Ok(items)
}

fn lookup(store: &AuthStore, body: &Value, at: LogicalInstant, admin: bool) -> JsonResponse {
    let lists = (|| -> Result<_, JsonResponse> {
        let federated: Vec<(String, String)> =
            match body.get("federatedUserId") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(items)) if items.iter().all(Value::is_object) => items
                    .iter()
                    .map(|i| {
                        (
                            str_field(i, "providerId").unwrap_or("").to_owned(),
                            str_field(i, "rawId").unwrap_or("").to_owned(),
                        )
                    })
                    .collect(),
                Some(_) => return Err(error(
                    400,
                    "INVALID_ARGUMENT : federatedUserId must be an array of {providerId, rawId}",
                )),
            };
        Ok((
            id_list(body, "localId")?,
            id_list(body, "email")?,
            id_list(body, "phoneNumber")?,
            federated,
        ))
    })();
    let (local_ids, emails, phones, federated) = match lists {
        Ok(l) => l,
        Err(r) => return r,
    };
    let total = local_ids.len() + emails.len() + phones.len() + federated.len();
    if total > MAX_LOOKUP_IDENTIFIERS {
        return error(
            400,
            &format!("INVALID_ARGUMENT : at most {MAX_LOOKUP_IDENTIFIERS} identifiers per lookup"),
        );
    }
    if total == 0 {
        if admin {
            return error(
                400,
                "MISSING_IDENTIFIER : localId, email, phoneNumber or federatedUserId",
            );
        }
        return match verify(store, body, at) {
            Ok(uid) => JsonResponse {
                status: 200,
                body: json!({"kind": "identitytoolkit#GetAccountInfoResponse", "users": [user_json(store, &uid)]}),
            },
            Err(r) => r,
        };
    }
    // Resolve every identifier, in request order, without duplicates. Federated
    // identities are never linked in this runtime, so they match nobody.
    let mut found: Vec<LocalId> = Vec::new();
    let mut push = |uid: LocalId| {
        if !found.contains(&uid) {
            found.push(uid);
        }
    };
    for id in &local_ids {
        if let Some(u) = store.user_by_id(id) {
            push(u.local_id.clone());
        }
    }
    for email in &emails {
        if let Some(u) = store.user_by_email(email) {
            push(u.local_id.clone());
        }
    }
    for phone in &phones {
        if let Some(u) = store.user_by_phone(phone) {
            push(u.local_id.clone());
        }
    }
    for (provider_id, raw_id) in &federated {
        if let Some(u) = store.user_by_federated(provider_id, raw_id) {
            push(u.local_id.clone());
        }
    }
    let users: Vec<Value> = found.iter().map(|uid| user_json(store, uid)).collect();
    // No match is an absent `users`, not an empty list (what the Admin SDK's
    // `user-not-found` is decided from).
    let mut response = json!({"kind": "identitytoolkit#GetAccountInfoResponse"});
    if !users.is_empty() {
        response["users"] = Value::Array(users);
    }
    JsonResponse {
        status: 200,
        body: response,
    }
}

fn claims_from_json(v: &JsonValue) -> Option<ClaimValue> {
    Some(match v {
        JsonValue::Null => ClaimValue::Null,
        JsonValue::Bool(b) => ClaimValue::Bool(*b),
        JsonValue::Int(i) => ClaimValue::Int(*i),
        JsonValue::Float(f) => ClaimValue::Float(*f),
        JsonValue::String(s) => ClaimValue::String(s.clone()),
        JsonValue::Array(items) => ClaimValue::List(
            items
                .iter()
                .map(claims_from_json)
                .collect::<Option<Vec<_>>>()?,
        ),
        JsonValue::Object(m) => ClaimValue::Map(
            m.iter()
                .map(|(k, v)| claims_from_json(v).map(|c| (k.clone(), c)))
                .collect::<Option<_>>()?,
        ),
    })
}

/// `accounts:update`: used by the Admin SDK for custom claims and disable / enable.
/// Requested change of an optional attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Change {
    /// Not mentioned by the request.
    Keep,
    /// `deleteAttribute` / `deleteProvider`.
    Clear,
    /// New value.
    Set(String),
}

impl Change {
    fn apply(self, slot: &mut Option<String>) {
        match self {
            Self::Keep => {}
            Self::Clear => *slot = None,
            Self::Set(v) => *slot = Some(v),
        }
    }
}

/// Everything an `accounts:update` request asks for, validated before any mutation.
struct UpdatePlan {
    claims: Option<CustomClaims>,
    password: Option<String>,
    email: Option<String>,
    phone_number: Change,
    display_name: Change,
    photo_url: Change,
    email_verified: Option<bool>,
    disable: Option<bool>,
    revoke_at: Option<LogicalInstant>,
    /// `linkProviderUserInfo`.
    link: Option<FederatedIdentity>,
    /// `deleteProvider` entries naming federated providers.
    unlink: Vec<String>,
    /// `mfa.enrollments` (phone factors replace the current ones).
    phone_factors: Option<Vec<(String, Option<String>)>>,
    /// `deleteProvider: password` / `deleteAttribute: PASSWORD`: drop the password credential.
    clear_password: bool,
    /// `deleteProvider: password` / `deleteAttribute: EMAIL`: drop the email address.
    clear_email: bool,
}

/// Request fields this runtime does not model; a non-empty value is refused instead of
/// being silently dropped.
const UNSUPPORTED_UPDATE_FIELDS: &[&str] = &["mfaInfo"];

/// `{providerId, rawId, email?, displayName?, photoUrl?}` of a link request.
fn parse_identity(v: &Value) -> Result<FederatedIdentity, JsonResponse> {
    let provider_id = opt_str(v, "providerId")?
        .filter(|p| !p.is_empty())
        .ok_or_else(|| error(400, "INVALID_ARGUMENT : providerId is required"))?;
    let raw_id = opt_str(v, "rawId")?
        .filter(|p| !p.is_empty())
        .ok_or_else(|| error(400, "INVALID_ARGUMENT : rawId is required"))?;
    if matches!(provider_id, "password" | "phone" | "emailLink") {
        return Err(error(
            400,
            "INVALID_ARGUMENT : linkProviderUserInfo takes a federated providerId",
        ));
    }
    Ok(FederatedIdentity {
        provider_id: provider_id.to_owned(),
        raw_id: raw_id.to_owned(),
        email: opt_str(v, "email")?.map(str::to_owned),
        display_name: opt_str(v, "displayName")?.map(str::to_owned),
        photo_url: opt_str(v, "photoUrl")?.map(str::to_owned),
    })
}

/// Phone factors of `mfaInfo` / `mfa.enrollments` entries (`{phoneInfo, displayName}`).
fn parse_phone_factors(entries: &Value) -> Result<Vec<(String, Option<String>)>, JsonResponse> {
    let Some(items) = entries.as_array() else {
        return Err(error(
            400,
            "INVALID_ARGUMENT : enrollments must be an array",
        ));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(phone) = str_field(item, "phoneInfo") else {
            return Err(error(
                400,
                "INVALID_ARGUMENT : only phone second factors (phoneInfo) can be enrolled by an admin",
            ));
        };
        AuthStore::validate_phone_number(phone).map_err(|e| auth_error(&e))?;
        out.push((
            phone.to_owned(),
            opt_str(item, "displayName")?.map(str::to_owned),
        ));
    }
    Ok(out)
}

fn parse_custom_claims(attrs: &str) -> Result<CustomClaims, JsonResponse> {
    let Ok(JsonValue::Object(parsed)) = fireemu_core_types::json::parse(attrs) else {
        return Err(error(
            400,
            "INVALID_CLAIMS : customAttributes must be a JSON object",
        ));
    };
    let mut claims = CustomClaims::default();
    for (k, v) in &parsed {
        let Some(cv) = claims_from_json(v) else {
            return Err(error(400, "INVALID_CLAIMS"));
        };
        if let Err(e) = claims.insert(k, cv) {
            return Err(error(400, &format!("FORBIDDEN_CLAIM : {e}")));
        }
    }
    Ok(claims)
}

fn reject_unsupported(body: &Value, fields: &[&str]) -> Result<(), JsonResponse> {
    for f in fields {
        let present = match body.get(*f) {
            None | Some(Value::Null) => false,
            Some(Value::Array(a)) => !a.is_empty(),
            Some(Value::Object(o)) => !o.is_empty(),
            Some(Value::String(s)) => !s.is_empty(),
            Some(_) => true,
        };
        if present {
            return Err(error(
                400,
                &format!("UNSUPPORTED_FIELD : {f} is not supported by this runtime"),
            ));
        }
    }
    Ok(())
}

fn string_list(v: &Value, what: &str) -> Result<Vec<String>, JsonResponse> {
    let Some(items) = v.as_array() else {
        return Err(error(
            400,
            &format!("INVALID_ARGUMENT : {what} must be an array"),
        ));
    };
    items
        .iter()
        .map(|a| {
            a.as_str().map(str::to_owned).ok_or_else(|| {
                error(
                    400,
                    &format!("INVALID_ARGUMENT : {what} entries must be strings"),
                )
            })
        })
        .collect()
}

fn parse_valid_since(body: &Value) -> Result<Option<LogicalInstant>, JsonResponse> {
    match body.get("validSince") {
        None => Ok(None),
        Some(Value::String(seconds))
            if !seconds.is_empty() && seconds.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            let seconds = seconds
                .parse::<i64>()
                .map_err(|_| error(400, "INVALID_ARGUMENT : validSince is out of range"))?;
            Ok(Some(LogicalInstant::from_unix_seconds(seconds)))
        }
        Some(Value::Number(seconds)) => {
            let seconds = seconds
                .as_i64()
                .filter(|seconds| *seconds >= 0)
                .ok_or_else(|| {
                    error(
                        400,
                        "INVALID_ARGUMENT : validSince must be a non-negative whole second",
                    )
                })?;
            Ok(Some(LogicalInstant::from_unix_seconds(seconds)))
        }
        Some(_) => Err(error(
            400,
            "INVALID_ARGUMENT : validSince must be a non-negative whole second",
        )),
    }
}

fn parse_update(body: &Value) -> Result<UpdatePlan, JsonResponse> {
    reject_unsupported(body, UNSUPPORTED_UPDATE_FIELDS)?;
    let claims = match opt_str(body, "customAttributes")? {
        Some(attrs) => Some(parse_custom_claims(attrs)?),
        None => None,
    };
    let password = opt_str(body, "password")?.map(str::to_owned);
    if let Some(p) = &password {
        AuthStore::validate_password(p).map_err(|e| auth_error(&e))?;
    }
    let change = |key: &str| -> Result<Change, JsonResponse> {
        Ok(opt_str(body, key)?.map_or(Change::Keep, |v| Change::Set(v.to_owned())))
    };
    let mut display_name = change("displayName")?;
    let mut photo_url = change("photoUrl")?;
    let mut phone_number = change("phoneNumber")?;
    if let Change::Set(p) = &phone_number {
        AuthStore::validate_phone_number(p).map_err(|e| auth_error(&e))?;
    }
    let mut clear_password = false;
    let mut clear_email = false;
    if let Some(attrs) = body.get("deleteAttribute") {
        for a in string_list(attrs, "deleteAttribute")? {
            match a.as_str() {
                "USER_ATTRIBUTE_NAME_UNSPECIFIED" => {}
                "DISPLAY_NAME" => display_name = Change::Clear,
                "PHOTO_URL" => photo_url = Change::Clear,
                "PASSWORD" => clear_password = true,
                "EMAIL" => clear_email = true,
                other => {
                    return Err(error(
                        400,
                        &format!("INVALID_ARGUMENT : unknown deleteAttribute {other:?}"),
                    ))
                }
            }
        }
    }
    let mut unlink = Vec::new();
    if let Some(providers) = body.get("deleteProvider") {
        for p in string_list(providers, "deleteProvider")? {
            match p.as_str() {
                "phone" => phone_number = Change::Clear,
                // The official emulator drops the address with the credential.
                "password" => {
                    clear_password = true;
                    clear_email = true;
                }
                "emailLink" => {
                    return Err(error(
                        400,
                        "UNSUPPORTED_FIELD : deleteProvider \"emailLink\" is not supported",
                    ))
                }
                _ => unlink.push(p),
            }
        }
    }
    let link = match body.get("linkProviderUserInfo") {
        None | Some(Value::Null) => None,
        Some(v) => Some(parse_identity(v)?),
    };
    let phone_factors = match body.get("mfa").and_then(|m| m.get("enrollments")) {
        None | Some(Value::Null) => None,
        Some(v) => Some(parse_phone_factors(v)?),
    };
    let revoke_at = parse_valid_since(body)?;
    Ok(UpdatePlan {
        claims,
        password,
        email: opt_str(body, "email")?.map(str::to_owned),
        phone_number,
        display_name,
        photo_url,
        email_verified: opt_bool(body, "emailVerified")?,
        disable: opt_bool(body, "disableUser")?,
        revoke_at,
        link,
        unlink,
        phone_factors,
        clear_password,
        clear_email,
    })
}

#[allow(clippy::too_many_lines)]
fn update(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    stateless_refresh_tokens: bool,
) -> JsonResponse {
    // `applyActionCode`: an email verification / change code instead of a session.
    if let Some(code) = str_field(body, "oobCode") {
        return apply_oob_code(store, code, at);
    }
    let local_id = match opt_str(body, "localId") {
        Ok(v) => v,
        Err(r) => return r,
    };
    // The provider the request's session signed in with, when it carries one: the official
    // emulator re-issues tokens for a session whose credentials it just changed.
    let mut session_provider: Option<fireemu_core_auth::store::Provider> = None;
    let uid = if let Some(local_id) = local_id {
        match store.user_by_id(local_id) {
            Some(u) => u.local_id.clone(),
            None => return error(400, "USER_NOT_FOUND"),
        }
    } else {
        match verify_session(store, body, at) {
            Ok(session) => {
                if body.get("disableUser").is_some_and(|v| !v.is_null()) {
                    return error(400, "OPERATION_NOT_ALLOWED");
                }
                session_provider = Some(provider_from_id(&session.provider));
                session.uid
            }
            Err(r) => return r,
        }
    };
    // Validate the whole request before touching the store (a rejected request changes
    // nothing); email / phone uniqueness is part of the validation.
    let plan = match parse_update(body) {
        Ok(p) => p,
        Err(r) => return r,
    };
    // Improved email privacy requires a proof-of-ownership OOB flow for address changes.
    // It also removes the legacy setAccountInfo email/password linking path; clients link
    // through accounts:signUp with the current ID token instead. Privileged Admin updates
    // remain available for account administration.
    if local_id.is_none()
        && store.config().enable_improved_email_privacy
        && (plan.email.is_some() || plan.clear_email)
    {
        return error(400, "OPERATION_NOT_ALLOWED");
    }
    if let Some(email) = &plan.email {
        if store
            .user_by_email(email)
            .is_some_and(|u| u.local_id != uid)
        {
            return error(400, "EMAIL_EXISTS");
        }
    }
    if let Change::Set(phone) = &plan.phone_number {
        if store
            .user_by_phone(phone)
            .is_some_and(|u| u.local_id != uid)
        {
            return error(400, "PHONE_NUMBER_EXISTS");
        }
    }
    if let Some(identity) = &plan.link {
        if store
            .user_by_federated(&identity.provider_id, &identity.raw_id)
            .is_some_and(|u| u.local_id != uid)
        {
            return error(400, "FEDERATED_USER_ID_ALREADY_LINKED");
        }
    }
    if let Some(claims) = plan.claims {
        if let Err(e) = store.set_custom_claims(&uid, claims) {
            return auth_error(&e);
        }
    }
    if let Some(identity) = plan.link {
        if let Err(e) = store.link_federated(&uid, identity) {
            return auth_error(&e);
        }
    }
    for provider in &plan.unlink {
        if let Err(e) = store.unlink_federated(&uid, provider) {
            return auth_error(&e);
        }
    }
    if let Some(factors) = plan.phone_factors {
        if let Err(e) = store.set_phone_factors(&uid, factors, at) {
            return mfa_error(&e);
        }
    }
    // A changed address is unverified again unless the request says otherwise; a new
    // address also ends the existing sessions, as a password change does.
    let mut email_changed = false;
    if let Some(email) = &plan.email {
        email_changed = store.user(&uid).and_then(|u| u.email.as_deref()) != Some(email);
        if let Err(e) = store.set_email(&uid, email) {
            return auth_error(&e);
        }
        if email_changed {
            if let Some(u) = store.user_mut(&uid) {
                u.email_verified = false;
            }
        }
    }
    if plan.clear_email {
        if let Err(e) = store.clear_email(&uid) {
            return auth_error(&e);
        }
    }
    if plan.clear_password {
        if let Err(e) = store.clear_password(&uid) {
            return auth_error(&e);
        }
    }
    match &plan.phone_number {
        Change::Keep => {}
        Change::Clear => {
            if let Err(e) = store.set_phone_number(&uid, None) {
                return auth_error(&e);
            }
        }
        Change::Set(phone) => {
            if let Err(e) = store.set_phone_number(&uid, Some(phone)) {
                return auth_error(&e);
            }
        }
    }
    if let Some(password) = &plan.password {
        if let Err(e) = store.set_password(&uid, password) {
            return auth_error(&e);
        }
        // Setting a password makes the session a password session.
        session_provider = Some(fireemu_core_auth::store::Provider::Password);
    }
    if let Some(u) = store.user_mut(&uid) {
        plan.display_name.apply(&mut u.display_name);
        plan.photo_url.apply(&mut u.photo_url);
        if let Some(verified) = plan.email_verified {
            u.email_verified = verified;
        }
        if let Some(disable) = plan.disable {
            u.disabled = disable;
        }
    }
    // A password change, an email change, an explicit `validSince` and a disablement all
    // move `validSince`, so ID tokens issued before this second are refused (what the
    // official emulator does). Under the firebase profile, refresh tokens remain stateless
    // and usable after these mutations, matching the official emulator. The strict profile
    // revokes them after privileged revocation, disablement and privileged credential changes.
    // Self-service credential changes keep the current refresh token in both profiles.
    let credentials_changed = plan.password.is_some() || email_changed || plan.revoke_at.is_some();
    if credentials_changed || plan.disable == Some(true) {
        let _ = store.revoke_tokens(&uid, plan.revoke_at.unwrap_or(at));
    }
    let self_service = local_id.is_none();
    if !stateless_refresh_tokens
        && (plan.revoke_at.is_some()
            || plan.disable == Some(true)
            || (credentials_changed && !self_service))
    {
        store.revoke_refresh_tokens(&uid);
    }
    let mut response =
        json!({"localId": uid.as_str(), "kind": "identitytoolkit#SetAccountInfoResponse"});
    if let Some(u) = store.user(&uid) {
        response["email"] = json!(u.email);
        response["emailVerified"] = json!(u.email_verified);
        response["displayName"] = json!(u.display_name);
        response["photoUrl"] = json!(u.photo_url);
        if email_changed {
            response["newEmail"] = json!(u.email);
        }
    }
    response["providerUserInfo"] = user_json(store, &uid)["providerUserInfo"].clone();
    if credentials_changed && plan.disable != Some(true) {
        if let Some(provider) = session_provider {
            match issue_tokens_with(store, &uid, None, at, None, Some(provider)) {
                Ok(tokens) => {
                    for key in ["idToken", "refreshToken", "expiresIn"] {
                        response[key] = tokens[key].clone();
                    }
                }
                Err(r) => return r,
            }
        }
    }
    JsonResponse {
        status: 200,
        body: response,
    }
}

/// The provider a token's `firebase.sign_in_provider` names.
fn provider_from_id(id: &str) -> fireemu_core_auth::store::Provider {
    use fireemu_core_auth::store::Provider;
    match id {
        "password" => Provider::Password,
        "anonymous" => Provider::Anonymous,
        "custom" => Provider::Custom,
        "phone" => Provider::Phone,
        "emailLink" => Provider::EmailLink,
        other => Provider::Federated(other.to_owned()),
    }
}

/// `accounts:delete`: the session's own account (client `deleteUser`), or, on the Admin
/// route, the account `localId` names.
fn delete_account(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    admin: bool,
) -> JsonResponse {
    let uid = if admin {
        match opt_str(body, "localId") {
            Ok(Some(id)) => match store.user_by_id(id) {
                Some(u) => u.local_id.clone(),
                None => return error(400, "USER_NOT_FOUND"),
            },
            Ok(None) => return error(400, "MISSING_LOCAL_ID"),
            Err(r) => return r,
        }
    } else {
        match verify(store, body, at) {
            Ok(uid) => uid,
            Err(r) => return r,
        }
    };
    match store.delete_user_by_id(uid.as_str()) {
        Ok(()) => JsonResponse {
            status: 200,
            body: json!({"kind": "identitytoolkit#DeleteAccountResponse"}),
        },
        Err(e) => auth_error(&e),
    }
}

/// Admin `POST /v1/projects/{p}/accounts` (createUser). The request is validated in full
/// before the user is inserted, so a rejected request leaves the store unchanged.
fn admin_create(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let parsed = (|| -> Result<_, JsonResponse> {
        reject_unsupported(body, &["mfa", "providerUserInfo"])?;
        let email = opt_str(body, "email")?.map(str::to_owned);
        let password = opt_str(body, "password")?.map(str::to_owned);
        if let Some(p) = &password {
            AuthStore::validate_password(p).map_err(|e| auth_error(&e))?;
        }
        if password.is_some() && email.is_none() {
            return Err(error(400, "INVALID_ARGUMENT : password requires an email"));
        }
        let phone = opt_str(body, "phoneNumber")?.map(str::to_owned);
        if let Some(p) = &phone {
            AuthStore::validate_phone_number(p).map_err(|e| auth_error(&e))?;
            if store.user_by_phone(p).is_some() {
                return Err(error(400, "PHONE_NUMBER_EXISTS"));
            }
        }
        let factors = match body.get("mfaInfo") {
            None | Some(Value::Null) => Vec::new(),
            Some(v) => parse_phone_factors(v)?,
        };
        Ok((
            email,
            password,
            phone,
            opt_str(body, "localId")?.map(str::to_owned),
            opt_str(body, "displayName")?.map(str::to_owned),
            opt_str(body, "photoUrl")?.map(str::to_owned),
            opt_bool(body, "emailVerified")?.unwrap_or(false),
            opt_bool(body, "disabled")?.unwrap_or(false),
            factors,
        ))
    })();
    let (
        email,
        password,
        phone,
        requested_id,
        display_name,
        photo_url,
        email_verified,
        disabled,
        factors,
    ) = match parsed {
        Ok(p) => p,
        Err(r) => return r,
    };
    let new_user = match &email {
        Some(email) => NewUser {
            email: Some(email.clone()),
            email_verified,
            provider: fireemu_core_auth::store::Provider::Password,
        },
        None => NewUser::anonymous(),
    };
    let uid = match store.create_user_with_id(new_user, requested_id.as_deref(), at) {
        Ok(uid) => uid,
        Err(e) => return auth_error(&e),
    };
    if let Some(password) = &password {
        if let Err(e) = store.set_password(&uid, password) {
            // Unreachable after validate_password; keep the store consistent regardless.
            let _ = store.delete_user_by_id(uid.as_str());
            return auth_error(&e);
        }
    }
    if let Err(e) = store.set_phone_number(&uid, phone.as_deref()) {
        let _ = store.delete_user_by_id(uid.as_str());
        return auth_error(&e);
    }
    if let Some(u) = store.user_mut(&uid) {
        u.display_name = display_name;
        u.photo_url = photo_url;
        u.disabled = disabled;
    }
    if let Err(e) = store.set_phone_factors(&uid, factors, at) {
        let _ = store.delete_user_by_id(uid.as_str());
        return mfa_error(&e);
    }
    JsonResponse {
        status: 200,
        body: json!({"kind": "identitytoolkit#SignupNewUserResponse", "localId": uid.as_str(), "email": email, "tenantId": store.tenant_id()}),
    }
}

/// Admin `accounts:batchDelete` (`deleteUsers`): up to 1000 ids; an enabled account is
/// skipped with a per-row error unless `force` is set (the Admin SDK always sets it); an
/// unknown id is silently skipped, as the official emulator does.
fn admin_batch_delete(store: &mut AuthStore, body: &Value) -> JsonResponse {
    let ids = match body.get("localIds") {
        Some(v) => match string_list(v, "localIds") {
            Ok(ids) => ids,
            Err(r) => return r,
        },
        None => Vec::new(),
    };
    if ids.is_empty() || ids.len() > 1000 {
        return error(400, "LOCAL_ID_LIST_EXCEEDS_LIMIT");
    }
    let force = body.get("force").and_then(Value::as_bool).unwrap_or(false);
    let mut errors = Vec::new();
    for (index, id) in ids.iter().enumerate() {
        let Some(user) = store.user_by_id(id) else {
            continue;
        };
        if !user.disabled && !force {
            errors.push(json!({"index": index, "localId": id, "message": "NOT_DISABLED : Disable the account before batch deletion."}));
            continue;
        }
        let _ = store.delete_user_by_id(id);
    }
    let mut response = json!({});
    if !errors.is_empty() {
        response["errors"] = Value::Array(errors);
    }
    JsonResponse {
        status: 200,
        body: response,
    }
}

/// Admin `accounts:query` (`queryAccounts`): the count, or users in `localId` order.
/// Expressions are not implemented by the official emulator either. The Firebase profile
/// preserves its ignored paging fields; strict applies the documented production contract.
fn admin_query(store: &AuthStore, body: &Value, limits: AuthQueryLimits) -> JsonResponse {
    if body
        .get("expression")
        .and_then(Value::as_array)
        .is_some_and(|e| !e.is_empty())
    {
        return not_implemented("expression is not implemented.");
    }
    let return_user_info = if limits == AuthQueryLimits::ProductionBounded {
        match opt_bool(body, "returnUserInfo") {
            Ok(value) => value.unwrap_or(true),
            Err(response) => return response,
        }
    } else {
        body.get("returnUserInfo").and_then(Value::as_bool) != Some(false)
    };
    if limits == AuthQueryLimits::ProductionBounded {
        if let Err(response) = validate_production_admin_query_enums(body) {
            return response;
        }
    }
    let count = store.user_count();
    if !return_user_info {
        if limits == AuthQueryLimits::ProductionBounded
            && ["limit", "offset"]
                .iter()
                .any(|field| body.get(*field).is_some_and(|value| !value.is_null()))
        {
            return error(
                400,
                "INVALID_ARGUMENT : limit and offset require returnUserInfo",
            );
        }
        return JsonResponse {
            status: 200,
            body: json!({"recordsCount": count.to_string()}),
        };
    }
    if limits == AuthQueryLimits::ProductionBounded {
        return production_admin_query_page(store, body);
    }
    let mut ids = store.all_user_ids();
    if str_field(body, "order") == Some("DESC") {
        ids.reverse();
    }
    let users: Vec<Value> = ids.iter().map(|uid| user_json(store, uid)).collect();
    JsonResponse {
        status: 200,
        body: json!({"recordsCount": count.to_string(), "userInfo": users}),
    }
}

fn production_admin_query_page(store: &AuthStore, body: &Value) -> JsonResponse {
    // Enum fields were validated before the count-only branch in `admin_query`.
    let descending = str_field(body, "order") == Some("DESC");
    let limit = match query_i64(body, "limit", 500) {
        Ok(limit @ 0..=500) => usize::try_from(limit).unwrap_or(500),
        Ok(_) | Err(()) => return error(400, "INVALID_ARGUMENT : invalid limit"),
    };
    let offset = match query_i64(body, "offset", 0) {
        Ok(offset @ 0..) => match usize::try_from(offset) {
            Ok(offset) => offset,
            Err(_) => return error(400, "INVALID_ARGUMENT : invalid offset"),
        },
        Ok(_) | Err(()) => return error(400, "INVALID_ARGUMENT : invalid offset"),
    };
    let page = store.users_by_local_id_page(offset, limit, descending);
    let users = page
        .iter()
        .map(|user| user_json(store, &user.local_id))
        .collect::<Vec<_>>();
    JsonResponse {
        status: 200,
        body: json!({"recordsCount": users.len().to_string(), "userInfo": users}),
    }
}

fn validate_production_admin_query_enums(body: &Value) -> Result<(), JsonResponse> {
    match opt_str(body, "sortBy") {
        Ok(None | Some("SORT_BY_FIELD_UNSPECIFIED" | "USER_ID")) => {}
        Ok(Some("NAME" | "CREATED_AT" | "LAST_LOGIN_AT" | "USER_EMAIL")) => {
            return Err(not_implemented("sortBy is not implemented."));
        }
        Ok(Some(_)) | Err(_) => return Err(error(400, "INVALID_ARGUMENT : invalid sortBy")),
    }
    match opt_str(body, "order") {
        Ok(None | Some("ORDER_UNSPECIFIED" | "ASC" | "DESC")) => Ok(()),
        Ok(Some(_)) | Err(_) => Err(error(400, "INVALID_ARGUMENT : invalid order")),
    }
}

fn query_i64(body: &Value, field: &str, default: i64) -> Result<i64, ()> {
    match body.get(field) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::String(value)) => value.parse().map_err(|_| ()),
        Some(Value::Number(value)) => value.as_i64().ok_or(()),
        Some(_) => Err(()),
    }
}

/// The 501 envelope the official emulator answers a request it does not implement with.
fn not_implemented(message: &str) -> JsonResponse {
    JsonResponse {
        status: 501,
        body: fireemu_adapter_support::api_error::identity_unimplemented(message),
    }
}

/// Session cookies last between five minutes and two weeks (the official bounds).
const SESSION_COOKIE_MIN_SECONDS: i64 = 5 * 60;
const SESSION_COOKIE_MAX_SECONDS: i64 = 14 * 24 * 60 * 60;

/// Admin `projects/{p}:createSessionCookie`: the verified session's claims re-issued with
/// the session-cookie issuer and the requested lifetime. Unsigned when the session is, as
/// the official emulator's cookies are (the Admin SDK's `verifySessionCookie` accepts only
/// `alg: none` while it points at an emulator).
fn create_session_cookie(store: &AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let token = match body.get("idToken") {
        None | Some(Value::Null) => return error(400, "MISSING_ID_TOKEN"),
        Some(Value::String(t)) => t.as_str(),
        Some(_) => return error(400, "INVALID_ID_TOKEN"),
    };
    let valid_duration = match body.get("validDuration") {
        None | Some(Value::Null) => SESSION_COOKIE_MAX_SECONDS,
        Some(Value::String(s)) => s.parse::<i64>().unwrap_or(0),
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(_) => 0,
    };
    let valid_duration = if valid_duration == 0 {
        SESSION_COOKIE_MAX_SECONDS
    } else {
        valid_duration
    };
    if !(SESSION_COOKIE_MIN_SECONDS..=SESSION_COOKIE_MAX_SECONDS).contains(&valid_duration) {
        return error(400, "INVALID_DURATION");
    }
    let (_, decoded) = match fireemu_core_auth::jwt::verify_id_token_decoded(token, store, at) {
        Ok(v) => v,
        Err(e) => return jwt_error(&e),
    };
    let Ok(mut payload) = serde_json::from_str::<Value>(&decoded.payload_json) else {
        return error(400, "INVALID_ID_TOKEN");
    };
    let issued_at = i64::try_from(at.as_nanos().div_euclid(1_000_000_000)).unwrap_or(i64::MAX);
    payload["iat"] = json!(issued_at);
    payload["exp"] = json!(issued_at.saturating_add(valid_duration));
    payload["iss"] = json!(format!(
        "https://session.firebase.google.com/{}",
        store.project_id()
    ));
    let cookie = fireemu_core_auth::jwt::encode_payload_with(&payload.to_string(), None);
    JsonResponse {
        status: 200,
        body: json!({"sessionCookie": cookie}),
    }
}

/// Minimal `application/x-www-form-urlencoded` query decoding (ASCII percent escapes).
fn query_params(query: Option<&str>) -> BTreeMap<String, String> {
    fn decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'%' if i + 2 < bytes.len() => {
                    if let Some(b) = s
                        .get(i + 1..i + 3)
                        .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                    {
                        out.push(b);
                        i += 3;
                    } else {
                        out.push(b'%');
                        i += 1;
                    }
                }
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    query
        .unwrap_or("")
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(kv), String::new()),
        })
        .collect()
}

/// The password credential a `batchCreate` row carries, when fireemu can verify it: a
/// `rawPassword`, or a `passwordHash` in the emulator's reversible `fakeHash` form (what an
/// export of either emulator holds). Any other hash is kept out: the account is created
/// without a password credential, which is observably what the official emulator does with
/// a hash it cannot compare (a sign-in against it fails).
fn batch_row_password(row: &Value) -> Result<Option<(String, String)>, JsonResponse> {
    if let Some(raw) = opt_str(row, "rawPassword")? {
        AuthStore::validate_password(raw).map_err(|e| auth_error(&e))?;
        let salt = opt_str(row, "salt")?
            .filter(|s| !s.is_empty())
            .map_or_else(|| "fakeSaltimport".to_owned(), str::to_owned);
        return Ok(Some((salt, raw.to_owned())));
    }
    let Some(hash) = opt_str(row, "passwordHash")? else {
        return Ok(None);
    };
    let Some(rest) = hash.strip_prefix("fakeHash:salt=") else {
        return Ok(None);
    };
    let Some((salt, password)) = rest.split_once(":password=") else {
        return Ok(None);
    };
    if AuthStore::validate_password(password).is_err() {
        return Ok(None);
    }
    Ok(Some((salt.to_owned(), password.to_owned())))
}

/// A millisecond epoch string (`createdAt`, `lastLoginAt`) as an instant.
fn millis_field(row: &Value, key: &str) -> Option<LogicalInstant> {
    let millis = match row.get(key)? {
        Value::String(s) => s.parse::<i64>().ok()?,
        Value::Number(n) => n.as_i64()?,
        _ => return None,
    };
    Some(LogicalInstant::from_nanos(i128::from(millis) * 1_000_000))
}

/// The second factors of a `batchCreate` row: phone factors as the official emulator
/// imports them, and TOTP factors in fireemu's own export shape
/// (`totpInfo.sharedSecretKey`), which the official emulator has no equivalent for.
fn batch_row_factors(
    row: &Value,
    local_id: &str,
    has_email: bool,
    email_verified: bool,
    at: LogicalInstant,
) -> Result<
    (
        Vec<fireemu_core_auth::mfa::TotpFactor>,
        Vec<fireemu_core_auth::mfa::PhoneFactor>,
    ),
    JsonResponse,
> {
    use fireemu_core_auth::mfa::{PhoneFactor, TotpFactor, TotpSecret};
    let mut totp_factors = Vec::new();
    let mut phone_factors = Vec::new();
    let Some(items) = row.get("mfaInfo").and_then(Value::as_array) else {
        return Ok((totp_factors, phone_factors));
    };
    if !items.is_empty() {
        if !has_email {
            return Err(error(
                400,
                "Second factor account requires email to be presented.",
            ));
        }
        if !email_verified {
            return Err(error(
                400,
                "Second factor account requires email to be verified.",
            ));
        }
    }
    for (index, item) in items.iter().enumerate() {
        let enrollment_id = opt_str(item, "mfaEnrollmentId")?
            .filter(|id| !id.is_empty())
            .map_or_else(|| format!("{local_id}-mfa-{index}"), str::to_owned);
        let display_name = opt_str(item, "displayName")?.map(str::to_owned);
        let enrolled_at = opt_str(item, "enrolledAt")?
            .and_then(|t| LogicalInstant::parse_rfc3339(t).ok())
            .unwrap_or(at);
        if let Some(phone) = opt_str(item, "phoneInfo")? {
            AuthStore::validate_phone_number(phone)
                .map_err(|_| error(400, "Phone number format is invalid"))?;
            phone_factors.push(PhoneFactor {
                mfa_enrollment_id: enrollment_id,
                display_name,
                phone_number: phone.to_owned(),
                enrolled_at,
            });
        } else if let Some(secret) = item
            .get("totpInfo")
            .and_then(|t| t.get("sharedSecretKey"))
            .and_then(Value::as_str)
        {
            let bytes = base32::decode(secret)
                .map_err(|_| error(400, "totpInfo.sharedSecretKey is not base32"))?;
            totp_factors.push(TotpFactor {
                mfa_enrollment_id: enrollment_id,
                display_name,
                secret: TotpSecret::new(bytes),
                enrolled_at,
                last_accepted_step: None,
            });
        } else {
            return Err(error(400, "Second factor not supported."));
        }
    }
    Ok((totp_factors, phone_factors))
}

/// One `batchCreate` row as the account it records.
fn batch_row_user(
    row: &Value,
    at: LogicalInstant,
) -> Result<fireemu_core_auth::store::ImportedUser, JsonResponse> {
    use fireemu_core_auth::store::{ImportedUser, Provider};
    let local_id = opt_str(row, "localId")?
        .filter(|id| !id.is_empty())
        .ok_or_else(|| error(400, "localId is missing"))?;
    let email = opt_str(row, "email")?.map(str::to_owned);
    if let Some(email) = &email {
        if !email.contains('@') {
            return Err(error(400, "email is invalid"));
        }
    }
    let phone_number = opt_str(row, "phoneNumber")?.map(str::to_owned);
    if let Some(phone) = &phone_number {
        AuthStore::validate_phone_number(phone)
            .map_err(|_| error(400, "phone number format is invalid"))?;
    }
    let custom_claims = match opt_str(row, "customAttributes")? {
        Some(attrs) if !attrs.is_empty() => parse_custom_claims(attrs)?,
        _ => CustomClaims::default(),
    };
    let mut federated = Vec::new();
    if let Some(items) = row.get("providerUserInfo").and_then(Value::as_array) {
        for item in items {
            let provider_id = opt_str(item, "providerId")?.unwrap_or("");
            if matches!(provider_id, "password" | "phone") {
                continue;
            }
            let raw_id = opt_str(item, "rawId")?.unwrap_or("");
            if provider_id.is_empty() || raw_id.is_empty() {
                return Err(error(
                    400,
                    "federatedId or (providerId & rawId) is required",
                ));
            }
            federated.push(FederatedIdentity {
                provider_id: provider_id.to_owned(),
                raw_id: raw_id.to_owned(),
                email: opt_str(item, "email")?.map(str::to_owned),
                display_name: opt_str(item, "displayName")?.map(str::to_owned),
                photo_url: opt_str(item, "photoUrl")?.map(str::to_owned),
            });
        }
    }
    let email_verified = opt_bool(row, "emailVerified")?.unwrap_or(false);
    let (totp_factors, phone_factors) =
        batch_row_factors(row, local_id, email.is_some(), email_verified, at)?;
    let password = batch_row_password(row)?;
    let provider = if password.is_some() || email.is_some() {
        Provider::Password
    } else if phone_number.is_some() {
        Provider::Phone
    } else if let Some(first) = federated.first() {
        Provider::Federated(first.provider_id.clone())
    } else {
        Provider::Anonymous
    };
    Ok(ImportedUser {
        local_id: local_id.to_owned(),
        email,
        email_verified,
        display_name: opt_str(row, "displayName")?.map(str::to_owned),
        photo_url: opt_str(row, "photoUrl")?.map(str::to_owned),
        phone_number,
        disabled: opt_bool(row, "disabled")?.unwrap_or(false),
        provider,
        custom_claims,
        created_at: millis_field(row, "createdAt").unwrap_or(at),
        last_sign_in_at: millis_field(row, "lastLoginAt"),
        tokens_valid_after: at,
        federated,
        password,
        totp_factors,
        phone_factors,
    })
}

/// Admin `accounts:batchCreate` (`importUsers`): every row is attempted, and a refused row
/// is reported by index in `error` while the others are created, which is the official
/// contract of the route. With `allowOverwrite` an existing account of the same `localId`
/// is replaced; without it the row is refused.
fn admin_batch_create(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let Some(rows) = body
        .get("users")
        .and_then(Value::as_array)
        .filter(|r| !r.is_empty())
    else {
        return error(400, "MISSING_USER_ACCOUNT");
    };
    let allow_overwrite = body
        .get("allowOverwrite")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !allow_overwrite {
        let mut seen = std::collections::BTreeSet::new();
        for row in rows {
            let id = str_field(row, "localId").unwrap_or("");
            if !seen.insert(id) {
                return error(400, &format!("DUPLICATE_LOCAL_ID : {id}"));
            }
        }
    }
    let mut errors = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let refused = |message: String| json!({"index": index, "message": message});
        let user = match batch_row_user(row, at) {
            Ok(u) => u,
            Err(r) => {
                let message = r.body["error"]["message"]
                    .as_str()
                    .unwrap_or("invalid row")
                    .to_owned();
                errors.push(refused(message));
                continue;
            }
        };
        if store.user_by_id(&user.local_id).is_some() {
            if !allow_overwrite {
                errors.push(refused(
                    "localId belongs to an existing account - can not overwrite.".to_owned(),
                ));
                continue;
            }
            let _ = store.delete_user_by_id(&user.local_id);
        }
        if let Err(e) = store.import_user(user) {
            errors.push(refused(e.to_string()));
        }
    }
    JsonResponse {
        status: 200,
        body: json!({"kind": "identitytoolkit#UploadAccountResponse", "error": errors}),
    }
}

/// Admin `accounts:batchGet` (`listUsers`): `GET ?maxResults=&nextPageToken=`, users in
/// creation order; the page token is an opaque versioned cursor.
fn admin_batch_get(store: &AuthStore, query: Option<&str>, body: &Value) -> JsonResponse {
    let params = query_params(query);
    let max_text = params.get("maxResults").cloned().or_else(|| {
        body.get("maxResults").map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    });
    let max = match max_text.as_deref() {
        None => 1_000usize,
        Some(t) => match t.parse::<usize>() {
            Ok(n) if (1..=1_000).contains(&n) => n,
            _ => return error(400, "INVALID_ARGUMENT : maxResults must be 1..=1000"),
        },
    };
    let token = params
        .get("nextPageToken")
        .cloned()
        .or_else(|| {
            body.get("nextPageToken")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .filter(|t| !t.is_empty());
    let after: u64 = match token.as_deref() {
        None => 0,
        Some(t) => match t.strip_prefix("v1:").and_then(|n| n.parse::<u64>().ok()) {
            Some(n) => n,
            None => return error(400, "INVALID_PAGE_TOKEN"),
        },
    };
    let page: Vec<&fireemu_core_auth::store::UserRecord> =
        store.users_after_sequence(after, max.saturating_add(1));
    let has_more = page.len() > max;
    let page = &page[..page.len().min(max)];
    let users: Vec<Value> = page.iter().map(|u| user_json(store, &u.local_id)).collect();
    let mut response = json!({"kind": "identitytoolkit#DownloadAccountResponse", "users": users});
    if has_more {
        if let Some(last) = page.last() {
            response["nextPageToken"] = Value::String(format!("v1:{}", last.sequence));
        }
    }
    JsonResponse {
        status: 200,
        body: response,
    }
}

/// First factors that cannot carry a second factor (the official emulator's
/// `MFA_INELIGIBLE_PROVIDER`): a session signed in with one of them is refused before any
/// enrollment state exists.
const MFA_INELIGIBLE_PROVIDERS: &[&str] = &["anonymous", "phone", "custom", "gc.apple.com"];

/// The refusals the official emulator makes before a phone factor is enrolled (measured:
/// `auth/mfa-error-shapes` and `auth/mfa-enrollment-eligibility`): an ineligible first
/// factor, an unverified email (the start step only: the finalize step checks the code
/// first and never the flag), and a number already enrolled on the account. None of them
/// has a side effect.
fn phone_enrollment_refusal(
    store: &AuthStore,
    session: &Session,
    phone: Option<&str>,
    require_verified_email: bool,
) -> Option<JsonResponse> {
    if MFA_INELIGIBLE_PROVIDERS.contains(&session.provider.as_str()) {
        return Some(error(
            400,
            "UNSUPPORTED_FIRST_FACTOR : MFA is not available for the given first factor.",
        ));
    }
    let user = store.user(&session.uid)?;
    if require_verified_email && !user.email_verified {
        return Some(error(
            400,
            "UNVERIFIED_EMAIL : Need to verify email first before enrolling second factors.",
        ));
    }
    if let Some(phone) = phone {
        if AuthStore::validate_phone_number(phone).is_err() {
            return Some(error(400, "INVALID_PHONE_NUMBER : Invalid format."));
        }
        if user
            .mfa
            .phone_factors()
            .iter()
            .any(|f| f.phone_number == phone)
        {
            return Some(error(
                400,
                "SECOND_FACTOR_EXISTS : Phone number already enrolled as second factor for this account.",
            ));
        }
    }
    None
}

fn mfa_enrollment_start(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    totp_extension_enabled: bool,
) -> JsonResponse {
    let session = match verify_session(store, body, at) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let uid = session.uid.clone();
    if let Some(phone) = body.get("phoneEnrollmentInfo") {
        let number = str_field(phone, "phoneNumber").unwrap_or("");
        if let Some(refusal) = phone_enrollment_refusal(store, &session, Some(number), true) {
            return refusal;
        }
        return match store.send_verification_code(
            number,
            VerificationPurpose::Enrollment { uid },
            at,
        ) {
            Ok(code) => JsonResponse {
                status: 200,
                body: json!({"phoneSessionInfo": {"sessionInfo": code.session_info}}),
            },
            Err(e) => auth_error(&e),
        };
    }
    if body.get("totpEnrollmentInfo").is_none() {
        return error(
            400,
            "INVALID_ARGUMENT : totpEnrollmentInfo or phoneEnrollmentInfo is required",
        );
    }
    if !totp_extension_enabled {
        return error(400, "INVALID_ARGUMENT : ((Missing phoneEnrollmentInfo.))");
    }
    match store.start_totp_enrollment(&uid, at) {
        Ok(material) => {
            let policy = *store.policy();
            JsonResponse {
                status: 200,
                body: json!({
                    "totpSessionInfo": {
                        "sharedSecretKey": base32::encode(material.secret_for_test()),
                        "verificationCodeLength": policy.digits,
                        "hashingAlgorithm": "HMAC_SHA1",
                        "periodSec": policy.period_seconds,
                        "sessionInfo": material.session_id,
                        "finalizeEnrollmentTime": LogicalInstant::to_rfc3339(material.expires_at).unwrap_or_default(),
                    }
                }),
            }
        }
        Err(e) => mfa_error(&e),
    }
}

fn parse_code(v: Option<&Value>) -> Option<u32> {
    match v {
        Some(Value::String(s)) if s.len() <= 8 && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse().ok()
        }
        Some(Value::Number(n)) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
        _ => None,
    }
}

fn mfa_enrollment_finalize(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> JsonResponse {
    let session = match verify_session(store, body, at) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let uid = session.uid.clone();
    if let Some(phone) = body.get("phoneVerificationInfo") {
        if let Some(refusal) = phone_enrollment_refusal(store, &session, None, false) {
            return refusal;
        }
        return finalize_phone_enrollment(store, &session, phone, body, at);
    }
    let info = body.get("totpVerificationInfo");
    let session = info
        .and_then(|i| i.get("sessionInfo"))
        .and_then(Value::as_str);
    let code = parse_code(info.and_then(|i| i.get("verificationCode")));
    let (Some(session), Some(code)) = (session, code) else {
        return error(
            400,
            "INVALID_CODE : missing sessionInfo or verificationCode",
        );
    };
    match store.finalize_totp_enrollment(&uid, session, code, at) {
        Ok(factor) => {
            let assertion = SecondFactorAssertion {
                sign_in_second_factor: "totp".to_owned(),
                second_factor_identifier: factor.mfa_enrollment_id.clone(),
                verified_at: at,
            };
            match issue_tokens(store, &uid, Some(&assertion), at) {
                Ok(tokens) => token_only_response(&tokens, false),
                Err(r) => r,
            }
        }
        Err(e) => mfa_error(&e),
    }
}

/// The official multi-factor finalize responses carry only the tokens
/// (`{idToken, refreshToken}`; the withdraw response also carries `expiresIn`), measured by
/// `auth/mfa-enrollment-eligibility`. The enrollment id reaches the client through the
/// second-factor claim of the ID token and through the account record.
fn token_only_response(tokens: &Value, with_expires_in: bool) -> JsonResponse {
    let mut body = json!({"idToken": tokens["idToken"], "refreshToken": tokens["refreshToken"]});
    if with_expires_in {
        body["expiresIn"] = tokens["expiresIn"].clone();
    }
    JsonResponse { status: 200, body }
}

fn mfa_sign_in_finalize(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let Some(pending) = str_field(body, "mfaPendingCredential") else {
        return error(400, "MISSING_MFA_PENDING_CREDENTIAL");
    };
    if let Some(phone) = body.get("phoneVerificationInfo") {
        return finalize_phone_sign_in(store, pending, phone, at);
    }
    let code = parse_code(
        body.get("totpVerificationInfo")
            .and_then(|i| i.get("verificationCode")),
    );
    let Some(code) = code else {
        return error(400, "INVALID_CODE : missing verificationCode");
    };
    let Some(uid) = PendingSignInId::parse(pending).and_then(|p| store.pending_sign_in_user(&p))
    else {
        return error(400, "INVALID_MFA_PENDING_CREDENTIAL");
    };
    let pending_id = PendingSignInId::parse(pending)
        .unwrap_or_else(|| PendingSignInId::parse("").expect("empty id parses"));
    match store.finalize_mfa_sign_in(&uid, &pending_id, code, at) {
        Ok(assertion) => match issue_tokens(store, &uid, Some(&assertion), at) {
            Ok(tokens) => token_only_response(&tokens, false),
            Err(r) => r,
        },
        Err(e) => mfa_error(&e),
    }
}

fn refresh(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    stateless_refresh_tokens: bool,
) -> JsonResponse {
    if str_field(body, "grant_type") != Some("refresh_token") {
        return error(400, "INVALID_GRANT_TYPE");
    }
    let Some(token) = str_field(body, "refresh_token") else {
        return error(400, "MISSING_REFRESH_TOKEN");
    };
    let session = match if stateless_refresh_tokens {
        store.stateless_refresh_session(token)
    } else {
        store.refresh_session(token)
    } {
        Ok(s) => s.clone(),
        Err(e) => return auth_error(&e),
    };
    match store.id_token_claims_for_session(&session, at) {
        Ok(claims) => {
            let id_token = encode_with(&claims, None);
            JsonResponse {
                status: 200,
                body: json!({
                    "id_token": id_token,
                    "access_token": id_token,
                    "refresh_token": token,
                    "expires_in": "3600",
                    "token_type": "Bearer",
                    "user_id": session.uid.as_str(),
                    "project_id": store.project_id(),
                }),
            }
        }
        Err(e) => auth_error(&e),
    }
}

// ---- email actions --------------------------------------------------------------------

/// `mfaInfo` entries of every enrolled factor. A pending-credential response (`redacted`)
/// shows an obfuscated phone number, as the official emulator's does; an account record
/// carries the number in full.
fn mfa_info(store: &AuthStore, uid: &LocalId, redacted: bool) -> Vec<Value> {
    let Some(u) = store.user(uid) else {
        return Vec::new();
    };
    let mut out: Vec<Value> = u
        .mfa
        .totp_factors()
        .iter()
        .map(|f| json!({"mfaEnrollmentId": f.mfa_enrollment_id, "displayName": f.display_name, "enrolledAt": LogicalInstant::to_rfc3339(f.enrolled_at).unwrap_or_default(), "totpInfo": {}}))
        .collect();
    out.extend(u.mfa.phone_factors().iter().map(|f| {
        let phone = if redacted {
            obfuscate_phone_number(&f.phone_number)
        } else {
            f.phone_number.clone()
        };
        json!({"mfaEnrollmentId": f.mfa_enrollment_id, "displayName": f.display_name, "enrolledAt": LogicalInstant::to_rfc3339(f.enrolled_at).unwrap_or_default(), "phoneInfo": phone})
    }));
    out
}

/// The action link of an email action (what the Emulator's console prints).
fn oob_link(
    headers: &RequestHeaders,
    request_type: OobRequestType,
    code: &str,
    body: &Value,
) -> String {
    let host = headers.host.as_deref().unwrap_or("127.0.0.1:9099");
    let mode = match request_type {
        OobRequestType::PasswordReset => "resetPassword",
        OobRequestType::VerifyEmail => "verifyEmail",
        OobRequestType::EmailSignIn => "signIn",
        OobRequestType::VerifyAndChangeEmail => "verifyAndChangeEmail",
    };
    let mut link = format!(
        "http://{host}/emulator/action?mode={mode}&lang=en&oobCode={code}&apiKey=fake-api-key"
    );
    if let Some(url) = str_field(body, "continueUrl") {
        link.push_str("&continueUrl=");
        link.push_str(&percent_encode(url));
    }
    link
}

fn percent_encode(s: &str) -> String {
    use std::fmt::Write as _;
    s.bytes()
        .fold(String::with_capacity(s.len()), |mut out, b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                out.push(b as char);
            } else {
                let _ = write!(out, "%{b:02X}");
            }
            out
        })
}

/// `accounts:sendOobCode`: `PASSWORD_RESET` (email), `VERIFY_EMAIL` (idToken),
/// `EMAIL_SIGNIN` (email), `VERIFY_AND_CHANGE_EMAIL` (idToken + newEmail). Nothing is
/// mailed: the code is kept for `/emulator/v1/projects/{p}/oobCodes`, and returned here
/// with its link when `returnOobLink` is set (the Admin SDK's link generators).
fn send_oob_code(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    headers: &RequestHeaders,
) -> JsonResponse {
    let request_type = match str_field(body, "requestType") {
        None | Some("" | "OOB_REQ_TYPE_UNSPECIFIED") => return error(400, "MISSING_REQ_TYPE"),
        Some(t) => match OobRequestType::parse(t) {
            Some(t) => t,
            None => {
                return JsonResponse {
                    status: 501,
                    body: fireemu_adapter_support::api_error::identity_unimplemented(t),
                }
            }
        },
    };
    let (email, uid, new_email) = match request_type {
        OobRequestType::PasswordReset => {
            let Some(email) = str_field(body, "email") else {
                return error(400, "MISSING_EMAIL");
            };
            match store.user_by_email(email) {
                Some(u) => (email.to_owned(), Some(u.local_id.clone()), None),
                // Improved email privacy: an unknown address is answered as if a mail had
                // been sent, and no code is created.
                None if store.config().enable_improved_email_privacy => {
                    return JsonResponse {
                        status: 200,
                        body: json!({"kind": "identitytoolkit#GetOobConfirmationCodeResponse", "email": email}),
                    }
                }
                None => return error(400, "EMAIL_NOT_FOUND"),
            }
        }
        OobRequestType::EmailSignIn => {
            let Some(email) = str_field(body, "email") else {
                return error(400, "MISSING_EMAIL");
            };
            if !email.contains('@') {
                return error(400, "INVALID_EMAIL");
            }
            let uid = store.user_by_email(email).map(|u| u.local_id.clone());
            (email.to_owned(), uid, None)
        }
        OobRequestType::VerifyEmail | OobRequestType::VerifyAndChangeEmail => {
            // A session, or (Admin link generators) the email itself.
            let uid = match (str_field(body, "idToken"), str_field(body, "email")) {
                (Some(_), _) => match verify(store, body, at) {
                    Ok(uid) => uid,
                    Err(r) => return r,
                },
                (None, Some(email)) => match store.user_by_email(email) {
                    Some(u) => u.local_id.clone(),
                    None => return error(400, "EMAIL_NOT_FOUND"),
                },
                (None, None) => return error(400, "MISSING_ID_TOKEN"),
            };
            let Some(email) = store.user(&uid).and_then(|u| u.email.clone()) else {
                return error(400, "MISSING_EMAIL : the user has no email");
            };
            let new_email = if request_type == OobRequestType::VerifyAndChangeEmail {
                let Some(new_email) = str_field(body, "newEmail") else {
                    return error(400, "MISSING_NEW_EMAIL");
                };
                if store
                    .user_by_email(new_email)
                    .is_some_and(|u| u.local_id != uid)
                {
                    return error(400, "EMAIL_EXISTS");
                }
                Some(new_email.to_owned())
            } else {
                None
            };
            (email, Some(uid), new_email)
        }
    };
    let code = match store.create_oob_code(request_type, &email, uid, new_email, at) {
        Ok(code) => code,
        Err(e) => return auth_error(&e),
    };
    let mut response =
        json!({"kind": "identitytoolkit#GetOobConfirmationCodeResponse", "email": email});
    if body.get("returnOobLink").and_then(Value::as_bool) == Some(true) {
        response["oobCode"] = json!(code);
        response["oobLink"] = json!(oob_link(headers, request_type, &code, body));
    }
    JsonResponse {
        status: 200,
        body: response,
    }
}

/// `accounts:resetPassword`: verifies a `PASSWORD_RESET` code (`verifyPasswordResetCode`)
/// and, with `newPassword`, consumes it and sets the password (`confirmPasswordReset`).
fn reset_password(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    stateless_refresh_tokens: bool,
) -> JsonResponse {
    let Some(code) = str_field(body, "oobCode") else {
        return error(400, "MISSING_OOB_CODE");
    };
    let Some(entry) = store.oob_code(code).cloned() else {
        return error(400, "INVALID_OOB_CODE");
    };
    if entry.request_type != OobRequestType::PasswordReset {
        return error(400, "INVALID_OOB_CODE");
    }
    let Some(uid) = entry.uid.clone() else {
        return error(400, "INVALID_OOB_CODE");
    };
    let Some(new_password) = str_field(body, "newPassword") else {
        return JsonResponse {
            status: 200,
            body: json!({"kind": "identitytoolkit#ResetPasswordResponse", "email": entry.email, "requestType": "PASSWORD_RESET"}),
        };
    };
    if let Err(e) = AuthStore::validate_password(new_password) {
        return auth_error(&e);
    }
    if store.user(&uid).is_none_or(|u| u.disabled) {
        return error(400, "USER_DISABLED");
    }
    if let Err(e) = store.consume_oob_code(code, Some(OobRequestType::PasswordReset), at) {
        return auth_error(&e);
    }
    if let Err(e) = store.set_password(&uid, new_password) {
        return auth_error(&e);
    }
    // A reset advances `validSince` and verifies the address (the user read the mail). The
    // Firebase profile keeps the official emulator's stateless refresh credentials; strict
    // mode also removes them.
    let _ = store.revoke_tokens(&uid, at);
    if !stateless_refresh_tokens {
        store.revoke_refresh_tokens(&uid);
    }
    if let Some(u) = store.user_mut(&uid) {
        u.email_verified = true;
    }
    JsonResponse {
        status: 200,
        body: json!({"kind": "identitytoolkit#ResetPasswordResponse", "email": entry.email, "requestType": "PASSWORD_RESET"}),
    }
}

/// `accounts:update` with an `oobCode` (`applyActionCode`): `VERIFY_EMAIL` marks the
/// address verified, `VERIFY_AND_CHANGE_EMAIL` switches to the new address.
fn apply_oob_code(store: &mut AuthStore, code: &str, at: LogicalInstant) -> JsonResponse {
    let Some(entry) = store.oob_code(code).cloned() else {
        return error(400, "INVALID_OOB_CODE");
    };
    let Some(uid) = entry.uid.clone() else {
        return error(400, "INVALID_OOB_CODE");
    };
    match entry.request_type {
        OobRequestType::VerifyEmail => {
            if let Err(e) = store.consume_oob_code(code, None, at) {
                return auth_error(&e);
            }
            if let Some(u) = store.user_mut(&uid) {
                u.email_verified = true;
            }
        }
        OobRequestType::VerifyAndChangeEmail => {
            let Some(new_email) = entry.new_email.clone() else {
                return error(400, "INVALID_OOB_CODE");
            };
            if let Err(e) = store.consume_oob_code(code, None, at) {
                return auth_error(&e);
            }
            if let Err(e) = store.set_email(&uid, &new_email) {
                return auth_error(&e);
            }
            if let Some(u) = store.user_mut(&uid) {
                u.email_verified = true;
            }
        }
        OobRequestType::PasswordReset | OobRequestType::EmailSignIn => {
            return error(400, "INVALID_OOB_CODE");
        }
    }
    let email = store.user(&uid).and_then(|u| u.email.clone());
    JsonResponse {
        status: 200,
        body: json!({"kind": "identitytoolkit#SetAccountInfoResponse", "localId": uid.as_str(), "email": email, "emailVerified": true}),
    }
}

/// `accounts:signInWithEmailLink`: an `EMAIL_SIGNIN` code for `email`.
fn sign_in_with_email_link(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> JsonResponse {
    let (Some(email), Some(code)) = (str_field(body, "email"), str_field(body, "oobCode")) else {
        return error(400, "MISSING_OOB_CODE");
    };
    let matches = store
        .oob_code(code)
        .is_some_and(|c| c.request_type == OobRequestType::EmailSignIn && c.email == email);
    if !matches {
        return error(400, "INVALID_OOB_CODE");
    }
    // With a session: link the (now verified) email to that user instead. The code is
    // consumed only once the request is known to succeed.
    if body.get("idToken").is_some_and(|t| !t.is_null()) {
        let uid = match verify(store, body, at) {
            Ok(uid) => uid,
            Err(r) => return r,
        };
        if store
            .user_by_email(email)
            .is_some_and(|u| u.local_id != uid)
        {
            return error(400, "EMAIL_EXISTS");
        }
        if let Err(e) = store.consume_oob_code(code, Some(OobRequestType::EmailSignIn), at) {
            return auth_error(&e);
        }
        if let Err(e) = store.set_email(&uid, email) {
            return auth_error(&e);
        }
        if let Some(u) = store.user_mut(&uid) {
            u.email_verified = true;
        }
        return match issue_tokens(store, &uid, None, at) {
            Ok(mut tokens) => {
                tokens["isNewUser"] = json!(false);
                JsonResponse {
                    status: 200,
                    body: tokens,
                }
            }
            Err(r) => r,
        };
    }
    if let Err(e) = store.consume_oob_code(code, Some(OobRequestType::EmailSignIn), at) {
        return auth_error(&e);
    }
    let (uid, is_new) = match store.sign_in_with_email_link(email, at) {
        Ok(r) => r,
        Err(e) => return auth_error(&e),
    };
    finish_sign_in(
        store,
        &uid,
        at,
        Some(fireemu_core_auth::store::Provider::EmailLink),
        &[
            ("kind", json!("identitytoolkit#EmailLinkSigninResponse")),
            ("isNewUser", json!(is_new)),
        ],
    )
}

// ---- phone sign-in ----------------------------------------------------------------------

/// `accounts:sendVerificationCode`: no SMS is sent; the code is kept for
/// `/emulator/v1/projects/{p}/verificationCodes` (reCAPTCHA tokens are not checked).
fn send_verification_code(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let Some(phone) = str_field(body, "phoneNumber") else {
        return error(400, "MISSING_PHONE_NUMBER");
    };
    match store.send_verification_code(phone, VerificationPurpose::SignIn, at) {
        Ok(code) => JsonResponse {
            status: 200,
            body: json!({"sessionInfo": code.session_info}),
        },
        Err(e) => auth_error(&e),
    }
}

/// `accounts:signInWithPhoneNumber`: `sessionInfo` + `code`; with an `idToken` the number
/// is linked to that user instead of signing in.
fn sign_in_with_phone_number(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> JsonResponse {
    let (Some(session), Some(code)) = (str_field(body, "sessionInfo"), str_field(body, "code"))
    else {
        return error(400, "MISSING_SESSION_INFO");
    };
    // Checked first, consumed once the request is known to succeed.
    let verified = match store.check_phone_code(session, code, at) {
        Ok(v) => v,
        Err(e) => return auth_error(&e),
    };
    if verified.purpose != VerificationPurpose::SignIn {
        return error(400, "INVALID_SESSION_INFO");
    }
    if body.get("idToken").is_some_and(|t| !t.is_null()) {
        let uid = match verify(store, body, at) {
            Ok(uid) => uid,
            Err(r) => return r,
        };
        if store
            .user_by_phone(&verified.phone_number)
            .is_some_and(|u| u.local_id != uid)
        {
            return error(400, "PHONE_NUMBER_EXISTS");
        }
        store.consume_phone_code(session);
        if let Err(e) = store.set_phone_number(&uid, Some(&verified.phone_number)) {
            return auth_error(&e);
        }
        return match issue_tokens(store, &uid, None, at) {
            Ok(mut tokens) => {
                tokens["phoneNumber"] = json!(verified.phone_number);
                tokens["isNewUser"] = json!(false);
                JsonResponse {
                    status: 200,
                    body: tokens,
                }
            }
            Err(r) => r,
        };
    }
    store.consume_phone_code(session);
    let (uid, is_new) = match store.sign_in_with_phone(&verified.phone_number, at) {
        Ok(r) => r,
        Err(e) => return auth_error(&e),
    };
    finish_sign_in(
        store,
        &uid,
        at,
        Some(fireemu_core_auth::store::Provider::Phone),
        &[
            ("phoneNumber", json!(verified.phone_number)),
            ("isNewUser", json!(is_new)),
        ],
    )
}

// ---- federated sign-in (fixture identity providers) --------------------------------------

/// The identity carried by a provider token. The token is not verified against any
/// provider: like the Emulator, a JWT's payload or a bare JSON object with `sub` is
/// trusted as the provider's assertion.
fn parse_idp_token(token: &str) -> Option<Value> {
    let payload = if token.trim_start().starts_with('{') {
        token.to_owned()
    } else {
        let middle = token.split('.').nth(1)?;
        let bytes = fireemu_core_auth::jwt::base64url_decode(middle).ok()?;
        String::from_utf8(bytes).ok()?
    };
    serde_json::from_str(&payload).ok()
}

/// A federated identity as the fake identity provider would report it, per the official emulator's
/// `fakeFetchUserInfoFromIdp`: the raw id, the profile fields, the `federatedId` shape the
/// provider uses, and the JSON `rawUserInfo` blob the SDKs read back.
struct IdpUserInfo {
    raw_id: String,
    email: Option<String>,
    email_verified: bool,
    display_name: Option<String>,
    photo_url: Option<String>,
    screen_name: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    federated_id: String,
    raw_user_info: String,
}

/// `/^[^@]+@[^@]+$/`: the official `isValidEmailAddress`.
fn is_valid_email(email: &str) -> bool {
    let mut parts = email.split('@');
    matches!((parts.next(), parts.next(), parts.next()), (Some(l), Some(r), None) if !l.is_empty() && !r.is_empty())
}

/// `email.toLowerCase()`: the official `canonicalizeEmailAddress`.
fn canonicalize_email(email: &str) -> String {
    email.to_lowercase()
}

/// A providerId is rejected before it is used as a map key, a token claim and (for the widget)
/// HTML if it carries a NUL or another control character or runs past a sane length. The
/// official emulator does not validate the providerId; this stricter check is recorded as the
/// `auth.idpProviderIdValidation` divergence (a malformed provider id cannot reach the store).
fn provider_id_is_wellformed(provider_id: &str) -> bool {
    !provider_id.is_empty()
        && provider_id.len() <= 256
        && !provider_id.chars().any(char::is_control)
}

/// The provider-reported identity the fake identity provider builds from the (JSON or JWT) claims and, for a
/// SAML provider, the parsed `SAMLResponse` (`fakeFetchUserInfoFromIdp`).
fn fake_fetch_user_info(provider_id: &str, claims: &Value, saml: Option<&Value>) -> IdpUserInfo {
    let raw_id = str_field(claims, "sub").unwrap_or_default().to_owned();
    let email = str_field(claims, "email").map(canonicalize_email);
    let email_verified = claims
        .get("email_verified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let display_name = str_field(claims, "name").map(str::to_owned);
    let photo_url = str_field(claims, "picture").map(str::to_owned);
    let screen_name = str_field(claims, "screen_name").map(str::to_owned);
    let mut info = IdpUserInfo {
        federated_id: raw_id.clone(),
        raw_id,
        email,
        email_verified,
        display_name,
        photo_url,
        screen_name,
        first_name: None,
        last_name: None,
        raw_user_info: claims.to_string(),
    };
    if provider_id == "google.com" {
        info.federated_id = format!("https://accounts.google.com/{}", info.raw_id);
        let mut granted = "openid https://www.googleapis.com/auth/userinfo.profile".to_owned();
        if info.email.is_some() {
            granted.push_str(" https://www.googleapis.com/auth/userinfo.email");
        }
        info.first_name = str_field(claims, "given_name").map(str::to_owned);
        info.last_name = str_field(claims, "family_name").map(str::to_owned);
        info.raw_user_info = json!({
            "granted_scopes": granted,
            "id": info.raw_id,
            "name": info.display_name,
            "given_name": claims.get("given_name"),
            "family_name": claims.get("family_name"),
            "verified_email": info.email_verified,
            "locale": "en",
            "email": info.email,
            "picture": info.photo_url,
        })
        .to_string();
    } else if provider_id.starts_with("saml.") {
        // The SAML subject's nameId becomes the email when it is one; the assertion is always
        // trusted for the email (the fake IdP does not verify it), and the attribute
        // statements are the rawUserInfo.
        let name_id = saml
            .and_then(|s| s.get("assertion"))
            .and_then(|a| a.get("subject"))
            .and_then(|s| s.get("nameId"))
            .and_then(Value::as_str);
        if let Some(name_id) = name_id.filter(|n| is_valid_email(n)) {
            info.email = Some(name_id.to_owned());
        }
        info.email_verified = true;
        let attributes = saml
            .and_then(|s| s.get("assertion"))
            .and_then(|a| a.get("attributeStatements"))
            .cloned()
            .unwrap_or(Value::Null);
        info.raw_user_info = attributes.to_string();
    }
    // oidc.* and every other provider keep the JSON claims as rawUserInfo (the default).
    info
}

/// The response fields threaded from a resolved credential to the final response, as ordered
/// `(key, value)` pairs (a field with a `Null` value is dropped by `without_nulls`).
type IdpBase = Vec<(&'static str, Value)>;

/// A resolved `signInWithIdp` credential: the lowercased provider id, the provider-reported
/// identity and the base `VerifyAssertionResponse` fields.
struct ResolvedIdp {
    provider_id: String,
    info: IdpUserInfo,
    base: IdpBase,
}

/// The base `VerifyAssertionResponse` fields the fake identity provider always returns.
fn idp_response_base(
    provider_id: &str,
    info: &IdpUserInfo,
    oauth_id_token: Option<&String>,
    oauth_access_token_out: &str,
) -> IdpBase {
    vec![
        ("kind", json!("identitytoolkit#VerifyAssertionResponse")),
        ("context", json!("")),
        ("providerId", json!(provider_id)),
        ("federatedId", json!(info.federated_id)),
        ("rawId", json!(info.raw_id)),
        ("oauthAccessToken", json!(oauth_access_token_out)),
        ("oauthIdToken", json!(oauth_id_token.cloned())),
        ("displayName", json!(info.display_name)),
        ("fullName", json!(info.display_name)),
        ("firstName", json!(info.first_name)),
        ("lastName", json!(info.last_name)),
        ("screenName", json!(info.screen_name)),
        ("email", json!(info.email)),
        ("emailVerified", json!(info.email_verified)),
        ("photoUrl", json!(info.photo_url)),
        ("rawUserInfo", json!(info.raw_user_info)),
    ]
}

/// The error the official emulator raises when no claims can be parsed from the credential.
fn idp_missing_claims_error(
    provider_id: &str,
    oauth_id_token: Option<&String>,
    oauth_access_token: Option<&String>,
) -> JsonResponse {
    match (oauth_id_token, oauth_access_token) {
        (Some(t), _) => error(
            400,
            &format!(
                "INVALID_IDP_RESPONSE : Unable to parse id_token: {t} ((Auth Emulator only accepts strict JSON or JWTs as fake id_tokens.))"
            ),
        ),
        (None, Some(_)) if provider_id == "google.com" || provider_id == "apple.com" => {
            not_implemented(&format!(
                "The Auth Emulator only support sign-in with {provider_id} using id_token, not access_token. Please update your code to use id_token."
            ))
        }
        (None, Some(_)) => not_implemented(&format!(
            "The Auth Emulator does not support {provider_id} sign-in with credentials."
        )),
        (None, None) => not_implemented(
            "The Auth Emulator only supports sign-in with credentials (id_token required).",
        ),
    }
}

/// Parses and validates a `SAMLResponse` (a JSON blob, not real XML): it must carry an
/// assertion with a subject nameId. `Ok(None)` when no `SAMLResponse` is present.
fn validate_saml_response(raw: Option<&String>) -> Result<Option<Value>, JsonResponse> {
    let Some(raw) = raw else { return Ok(None) };
    let parsed: Value = serde_json::from_str(raw).unwrap_or(Value::Null);
    let present = |v: Option<&Value>| v.is_some() && v != Some(&Value::Null);
    let assertion = parsed.get("assertion");
    if !present(assertion) {
        return Err(error(
            400,
            "INVALID_IDP_RESPONSE ((Missing assertion in SAMLResponse.))",
        ));
    }
    let subject = assertion.and_then(|a| a.get("subject"));
    if !present(subject) {
        return Err(error(
            400,
            "INVALID_IDP_RESPONSE ((Missing assertion.subject in SAMLResponse.))",
        ));
    }
    if !present(subject.and_then(|s| s.get("nameId"))) {
        return Err(error(
            400,
            "INVALID_IDP_RESPONSE ((Missing assertion.subject.nameId in SAMLResponse.))",
        ));
    }
    Ok(Some(parsed))
}

/// Parses and validates a `signInWithIdp` credential, or the error the official emulator raises.
fn resolve_idp_credential(body: &Value) -> Result<ResolvedIdp, JsonResponse> {
    if body.get("returnRefreshToken").is_some_and(|v| !v.is_null()) {
        return Err(not_implemented(
            "returnRefreshToken is not implemented yet.",
        ));
    }
    if body.get("pendingIdToken").is_some_and(|v| !v.is_null()) {
        return Err(not_implemented("pendingIdToken is not implemented yet."));
    }
    let Some(request_uri) = str_field(body, "requestUri") else {
        return Err(error(400, "MISSING_REQUEST_URI"));
    };
    if !uri_is_absolute(request_uri) {
        return Err(error(400, "INVALID_REQUEST_URI"));
    }
    let params = normalized_idp_params(request_uri, str_field(body, "postBody"));
    let Some(provider_id) = params
        .get("providerId")
        .filter(|p| !p.is_empty())
        .map(|p| p.to_lowercase())
    else {
        return Err(error(
            400,
            &format!(
                "INVALID_CREDENTIAL_OR_PROVIDER_ID : Invalid IdP response/credential: {request_uri}"
            ),
        ));
    };
    if !provider_id_is_wellformed(&provider_id) {
        return Err(error(
            400,
            "INVALID_CREDENTIAL_OR_PROVIDER_ID : providerId contains control characters or is too long",
        ));
    }
    let oauth_id_token = params.get("id_token").filter(|t| !t.is_empty());
    let oauth_access_token = params.get("access_token").filter(|t| !t.is_empty());
    let claims = oauth_id_token
        .and_then(|t| parse_idp_claims(t))
        .or_else(|| oauth_access_token.and_then(|t| parse_idp_claims(t)));
    let Some(claims) = claims else {
        return Err(idp_missing_claims_error(
            &provider_id,
            oauth_id_token,
            oauth_access_token,
        ));
    };
    let saml = validate_saml_response(params.get("SAMLResponse"))?;
    let info = fake_fetch_user_info(&provider_id, &claims, saml.as_ref());
    let oauth_access_token_out = oauth_access_token.map_or_else(
        || format!("FirebaseAuthEmulatorFakeAccessToken_{provider_id}"),
        String::clone,
    );
    let base = idp_response_base(&provider_id, &info, oauth_id_token, &oauth_access_token_out);
    Ok(ResolvedIdp {
        provider_id,
        info,
        base,
    })
}

/// `accounts:signInWithIdp` (`verifyAssertion`): the generic identity-provider assertion flow.
///
/// The credential arrives in `requestUri` and/or `postBody` (the official `getNormalizedUri`
/// merges the request URI's query, the post body and the URI fragment). The `id_token` (a fake
/// JWT or strict JSON) or a JSON `access_token` carries the claims; a `SAMLResponse` carries
/// the SAML assertion. With an `idToken` on the request the identity is linked to that user.
fn sign_in_with_idp(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let ResolvedIdp {
        provider_id,
        info,
        mut base,
    } = match resolve_idp_credential(body) {
        Ok(resolved) => resolved,
        Err(r) => return r,
    };
    let identity = FederatedIdentity {
        provider_id: provider_id.clone(),
        raw_id: info.raw_id.clone(),
        email: info.email.clone(),
        display_name: info.display_name.clone(),
        photo_url: info.photo_url.clone(),
    };

    // Linking to the session's user (`idToken` present) or a create-or-link sign-in.
    let (uid, is_new) = if body.get("idToken").is_some_and(|t| !t.is_null()) {
        let uid = match verify(store, body, at) {
            Ok(uid) => uid,
            Err(r) => return r,
        };
        // The identity may not already be linked to a different account.
        if store
            .user_by_federated(&provider_id, &info.raw_id)
            .is_some_and(|u| u.local_id != uid)
        {
            return maybe_idp_credential_error(body, &base, "FEDERATED_USER_ID_ALREADY_LINKED");
        }
        if let Err(e) = store.link_federated(&uid, identity) {
            return auth_error(&e);
        }
        (uid, false)
    } else {
        match store.sign_in_with_idp(identity, info.email_verified, at) {
            Ok(fireemu_core_auth::store::IdpSignIn::SignedIn {
                uid,
                is_new,
                email_recycled,
            }) => {
                if email_recycled {
                    base.push(("emailRecycled", json!(true)));
                }
                (uid, is_new)
            }
            Ok(fireemu_core_auth::store::IdpSignIn::NeedConfirmation {
                uid,
                verified_providers,
            }) => {
                // No tokens and no state change: the client must confirm the account.
                base.push(("localId", json!(uid.as_str())));
                base.push(("needConfirmation", json!(true)));
                base.push(("verifiedProvider", json!(verified_providers)));
                let mut obj = serde_json::Map::new();
                for (k, v) in base {
                    obj.insert((*k).to_owned(), v);
                }
                return JsonResponse {
                    status: 200,
                    body: without_nulls(Value::Object(obj)),
                };
            }
            Err(e) => return auth_error(&e),
        }
    };
    base.push(("isNewUser", json!(is_new)));

    // The stored account decides the final emailVerified when its email is the assertion's.
    if let Some(u) = store.user(&uid) {
        if u.email == info.email {
            for entry in &mut base {
                if entry.0 == "emailVerified" {
                    entry.1 = json!(u.email_verified);
                }
            }
        }
    }

    finish_sign_in(
        store,
        &uid,
        at,
        Some(fireemu_core_auth::store::Provider::Federated(provider_id)),
        &base,
    )
}

/// When `returnIdpCredential` is set the client wants the credential and the error together, so
/// a bad-request during linking becomes a 200 carrying `errorMessage` rather than a 400
/// (the JS SDK reads `errorMessage` to surface a linking conflict). Otherwise it is a 400.
fn maybe_idp_credential_error(
    body: &Value,
    base: &[(&'static str, Value)],
    message: &str,
) -> JsonResponse {
    if body.get("returnIdpCredential").and_then(Value::as_bool) == Some(true) {
        let mut obj = serde_json::Map::new();
        for (k, v) in base {
            obj.insert((*k).to_owned(), v.clone());
        }
        obj.insert("errorMessage".to_owned(), json!(message));
        return JsonResponse {
            status: 200,
            body: Value::Object(obj),
        };
    }
    error(400, message)
}

/// The identity-provider claims: strict JSON when the token starts with `{`, else the JWT payload. `sub`
/// must be present and a string (the official `parseClaims`). `None` when neither parses or
/// `sub` is missing/non-string.
fn parse_idp_claims(token: &str) -> Option<Value> {
    let payload = parse_idp_token(token)?;
    let sub = payload.get("sub")?;
    if !sub.is_string() || sub.as_str() == Some("") {
        return None;
    }
    Some(payload)
}

/// Whether `uri` is an absolute URI (has a scheme), the official `parseAbsoluteUri` guard.
fn uri_is_absolute(uri: &str) -> bool {
    match uri.find(':') {
        Some(i) if i > 0 => {
            let scheme = &uri[..i];
            scheme
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        }
        _ => false,
    }
}

/// The credential parameters of a `signInWithIdp` request: the request URI's query, then the
/// post body's parameters, then the URI fragment, each overriding the last (the official
/// `getNormalizedUri`).
fn normalized_idp_params(request_uri: &str, post_body: Option<&str>) -> BTreeMap<String, String> {
    let (before_fragment, fragment) = match request_uri.split_once('#') {
        Some((head, frag)) => (head, Some(frag)),
        None => (request_uri, None),
    };
    let uri_query = before_fragment.split_once('?').map(|(_, q)| q);
    let mut params = query_params(uri_query);
    for (k, v) in query_params(post_body) {
        params.insert(k, v);
    }
    for (k, v) in query_params(fragment) {
        params.insert(k, v);
    }
    params
}

/// `accounts:createAuthUri` (`fetchSignInMethodsForEmail`): whether the email is
/// registered and how it can sign in. A `providerId` (a sign-in-with-identity-provider request) is not
/// implemented by the official emulator, and neither is it here.
fn create_auth_uri(store: &AuthStore, body: &Value) -> JsonResponse {
    let session_id = str_field(body, "sessionId")
        .filter(|s| !s.is_empty())
        .unwrap_or("fireemu-session")
        .to_owned();
    // The official emulator does not implement createAuthUri for a provider (it is a legacy
    // redirect helper the SDKs no longer use); it answers NotImplementedError.
    if body.get("providerId").is_some_and(|v| !v.is_null()) {
        return not_implemented("Sign-in with IDP is not yet supported.");
    }
    let Some(identifier) = str_field(body, "identifier") else {
        return error(400, "MISSING_IDENTIFIER");
    };
    if str_field(body, "continueUri").is_none_or(str::is_empty) {
        return error(400, "MISSING_CONTINUE_URI");
    }
    if !is_valid_email(identifier) {
        return error(400, "INVALID_IDENTIFIER");
    }
    if !uri_is_absolute(str_field(body, "continueUri").unwrap_or("")) {
        return error(400, "INVALID_CONTINUE_URI");
    }
    let email = canonicalize_email(identifier);
    // Under improved email privacy the response reveals nothing about the address.
    if store.config().enable_improved_email_privacy {
        return JsonResponse {
            status: 200,
            body: json!({"kind": "identitytoolkit#CreateAuthUriResponse", "sessionId": session_id}),
        };
    }
    let mut methods: Vec<String> = Vec::new();
    let registered = match store.user_by_email(&email) {
        Some(u) => {
            if store.has_password(&u.local_id) {
                methods.push("password".to_owned());
            } else if u.provider == fireemu_core_auth::store::Provider::EmailLink {
                methods.push("emailLink".to_owned());
            }
            methods.extend(u.federated.iter().map(|f| f.provider_id.clone()));
            true
        }
        None => false,
    };
    JsonResponse {
        status: 200,
        body: json!({
            "kind": "identitytoolkit#CreateAuthUriResponse",
            "registered": registered,
            "signinMethods": methods,
            "allProviders": methods,
            "sessionId": session_id,
        }),
    }
}

// ---- phone second factor --------------------------------------------------------------------

fn finalize_phone_enrollment(
    store: &mut AuthStore,
    session: &Session,
    phone: &Value,
    body: &Value,
    at: LogicalInstant,
) -> JsonResponse {
    let uid = &session.uid;
    let Some(code) = str_field(phone, "code").filter(|c| !c.is_empty()) else {
        return error(400, "MISSING_CODE");
    };
    let Some(session_info) = str_field(phone, "sessionInfo").filter(|s| !s.is_empty()) else {
        return error(400, "MISSING_SESSION_INFO");
    };
    // Checked, then consumed only once the enrollment is known to be admissible: a number
    // already enrolled must not burn the code either.
    let verified = match store.check_phone_code(session_info, code, at) {
        Ok(v) => v,
        Err(e) => return auth_error(&e),
    };
    if verified.purpose != (VerificationPurpose::Enrollment { uid: uid.clone() }) {
        return error(400, "INVALID_SESSION_INFO");
    }
    if let Some(refusal) =
        phone_enrollment_refusal(store, session, Some(&verified.phone_number), false)
    {
        return refusal;
    }
    store.consume_phone_code(session_info);
    let display_name = str_field(body, "displayName").map(str::to_owned);
    match store.enroll_phone_factor(uid, &verified.phone_number, display_name, at) {
        Ok(factor) => {
            let assertion = SecondFactorAssertion {
                sign_in_second_factor: "phone".to_owned(),
                second_factor_identifier: factor.mfa_enrollment_id.clone(),
                verified_at: at,
            };
            match issue_tokens(store, uid, Some(&assertion), at) {
                Ok(tokens) => token_only_response(&tokens, false),
                Err(r) => r,
            }
        }
        Err(e) => mfa_error(&e),
    }
}

/// `mfaEnrollment:withdraw`: removes a factor of any kind.
fn mfa_enrollment_withdraw(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> JsonResponse {
    let uid = match verify(store, body, at) {
        Ok(uid) => uid,
        Err(r) => return r,
    };
    let Some(id) = str_field(body, "mfaEnrollmentId") else {
        return error(400, "MISSING_MFA_ENROLLMENT_ID");
    };
    match store.unenroll_factor(&uid, id) {
        Ok(true) => match issue_tokens(store, &uid, None, at) {
            Ok(tokens) => token_only_response(&tokens, true),
            Err(r) => r,
        },
        Ok(false) => error(400, "MFA_ENROLLMENT_NOT_FOUND"),
        Err(e) => mfa_error(&e),
    }
}

/// `mfaSignIn:start`: sends the code of the chosen phone factor (TOTP has no start step).
fn mfa_sign_in_start(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    // The official order: both request fields first, then the credential, then the factor.
    let Some(pending) = str_field(body, "mfaPendingCredential").filter(|p| !p.is_empty()) else {
        return error(
            400,
            "MISSING_MFA_PENDING_CREDENTIAL : Request does not have MFA pending credential.",
        );
    };
    let Some(enrollment_id) = str_field(body, "mfaEnrollmentId").filter(|e| !e.is_empty()) else {
        return error(
            400,
            "MISSING_MFA_ENROLLMENT_ID : No second factor identifier is provided.",
        );
    };
    let Some(pending_id) = PendingSignInId::parse(pending) else {
        return error(400, "INVALID_MFA_PENDING_CREDENTIAL");
    };
    let Some(uid) = store.pending_sign_in_user(&pending_id) else {
        return error(400, "INVALID_MFA_PENDING_CREDENTIAL");
    };
    if body.get("phoneSignInInfo").is_none() {
        return error(
            400,
            "INVALID_ARGUMENT : TOTP sign-in has no start step; call mfaSignIn:finalize",
        );
    }
    let Some(phone) = store.user(&uid).and_then(|u| {
        u.mfa
            .phone_factors()
            .iter()
            .find(|f| f.mfa_enrollment_id == enrollment_id)
            .map(|f| f.phone_number.clone())
    }) else {
        return error(400, "MFA_ENROLLMENT_NOT_FOUND");
    };
    match store.send_verification_code(
        &phone,
        VerificationPurpose::MfaSignIn {
            uid,
            pending: pending_id,
            enrollment_id: enrollment_id.to_owned(),
        },
        at,
    ) {
        Ok(code) => JsonResponse {
            status: 200,
            body: json!({"phoneResponseInfo": {"sessionInfo": code.session_info}}),
        },
        Err(e) => auth_error(&e),
    }
}

fn finalize_phone_sign_in(
    store: &mut AuthStore,
    pending: &str,
    phone: &Value,
    at: LogicalInstant,
) -> JsonResponse {
    let (Some(session), Some(code)) = (str_field(phone, "sessionInfo"), str_field(phone, "code"))
    else {
        return error(400, "INVALID_CODE : missing sessionInfo or code");
    };
    let verified = match store.verify_phone_code(session, code, at) {
        Ok(v) => v,
        Err(e) => return auth_error(&e),
    };
    let VerificationPurpose::MfaSignIn {
        uid,
        pending: pending_id,
        enrollment_id,
    } = verified.purpose
    else {
        return error(400, "INVALID_SESSION_INFO");
    };
    if pending_id.as_str() != pending {
        return error(400, "INVALID_MFA_PENDING_CREDENTIAL");
    }
    match store.finalize_phone_mfa_sign_in(&uid, &pending_id, &enrollment_id, at) {
        Ok(assertion) => match issue_tokens(store, &uid, Some(&assertion), at) {
            Ok(tokens) => token_only_response(&tokens, false),
            Err(r) => r,
        },
        Err(e) => mfa_error(&e),
    }
}

// ---- emulator inspection routes -----------------------------------------------------------

/// `/emulator/v1/projects/{p}/{oobCodes | verificationCodes | accounts | config}`: what the
/// Firebase Auth Emulator exposes so tests can read codes and wipe users.
fn emulator_route(
    store: &mut AuthStore,
    method: &str,
    resource: &str,
    headers: &RequestHeaders,
    body: &Value,
) -> JsonResponse {
    match (method, resource) {
        ("GET", "oobCodes") => {
            let codes: Vec<Value> = store
                .oob_codes()
                .into_iter()
                .map(|c| {
                    json!({
                        "email": c.email,
                        "oobCode": c.code,
                        "oobLink": oob_link(headers, c.request_type, &c.code, &Value::Null),
                        "requestType": c.request_type.as_str(),
                    })
                })
                .collect();
            JsonResponse {
                status: 200,
                body: json!({"oobCodes": codes}),
            }
        }
        ("GET", "verificationCodes") => {
            let codes: Vec<Value> = store
                .verification_codes()
                .into_iter()
                .map(|c| json!({"phoneNumber": c.phone_number, "sessionInfo": c.session_info, "code": c.code}))
                .collect();
            JsonResponse {
                status: 200,
                body: json!({"verificationCodes": codes}),
            }
        }
        ("DELETE", "accounts") => {
            store.clear();
            JsonResponse {
                status: 200,
                body: json!({}),
            }
        }
        ("GET", "config") => JsonResponse {
            status: 200,
            body: project_config_json(store.config()),
        },
        // `PATCH` replaces the switches the request names and reads the rest back. The
        // official emulator applies both; `enableImprovedEmailPrivacy` changes what a
        // password sign-in, a password reset and `createAuthUri` reveal, while
        // `allowDuplicateEmails` is recorded for export and does not yet admit duplicates.
        ("PATCH", "config") => {
            let mut config = store.config();
            if let Some(v) = body
                .get("signIn")
                .and_then(|s| s.get("allowDuplicateEmails"))
                .and_then(Value::as_bool)
            {
                config.allow_duplicate_emails = v;
            }
            if let Some(v) = body
                .get("emailPrivacyConfig")
                .and_then(|s| s.get("enableImprovedEmailPrivacy"))
                .and_then(Value::as_bool)
            {
                config.enable_improved_email_privacy = v;
            }
            store.set_config(config);
            JsonResponse {
                status: 200,
                body: project_config_json(config),
            }
        }
        (_, "oobCodes" | "verificationCodes" | "accounts" | "config") => {
            error(405, "METHOD_NOT_ALLOWED")
        }
        _ => not_found(),
    }
}

/// The document `GET` / `PATCH /emulator/v1/projects/{p}/config` serve.
fn project_config_json(config: fireemu_core_auth::store::ProjectAuthConfig) -> Value {
    json!({
        "signIn": {"allowDuplicateEmails": config.allow_duplicate_emails},
        "emailPrivacyConfig": {"enableImprovedEmailPrivacy": config.enable_improved_email_privacy},
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AllBlockingHooks;
    struct BeforeCreateOnlyHook;
    struct NoBlockingHooks;

    impl AuthBlockingHook for AllBlockingHooks {
        fn invoke(
            &self,
            _event: fireemu_core_functions::manifest::BlockingAuthEvent,
            _user: &fireemu_core_auth::store::UserRecord,
        ) -> Result<Value, BlockingFunctionFailure> {
            unreachable!("the route classifier never invokes a hook")
        }
    }

    impl AuthBlockingHook for NoBlockingHooks {
        fn handles(&self, _event: fireemu_core_functions::manifest::BlockingAuthEvent) -> bool {
            false
        }

        fn invoke(
            &self,
            _event: fireemu_core_functions::manifest::BlockingAuthEvent,
            _user: &fireemu_core_auth::store::UserRecord,
        ) -> Result<Value, BlockingFunctionFailure> {
            unreachable!("a bridge without matching exports is never invoked")
        }
    }

    impl AuthBlockingHook for BeforeCreateOnlyHook {
        fn handles(&self, event: fireemu_core_functions::manifest::BlockingAuthEvent) -> bool {
            event == fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate
        }

        fn invoke(
            &self,
            _event: fireemu_core_functions::manifest::BlockingAuthEvent,
            _user: &fireemu_core_auth::store::UserRecord,
        ) -> Result<Value, BlockingFunctionFailure> {
            unreachable!("the route classifier never invokes a hook")
        }
    }

    #[test]
    fn blocking_function_codes_match_the_functions_sdk_and_identity_statuses() {
        for (code, name, function_status) in [
            (BlockingFunctionCode::Cancelled, "CANCELLED", 499),
            (BlockingFunctionCode::Unknown, "UNKNOWN", 500),
            (
                BlockingFunctionCode::InvalidArgument,
                "INVALID_ARGUMENT",
                400,
            ),
            (
                BlockingFunctionCode::DeadlineExceeded,
                "DEADLINE_EXCEEDED",
                504,
            ),
            (BlockingFunctionCode::NotFound, "NOT_FOUND", 404),
            (BlockingFunctionCode::AlreadyExists, "ALREADY_EXISTS", 409),
            (
                BlockingFunctionCode::PermissionDenied,
                "PERMISSION_DENIED",
                403,
            ),
            (
                BlockingFunctionCode::Unauthenticated,
                "UNAUTHENTICATED",
                401,
            ),
            (
                BlockingFunctionCode::ResourceExhausted,
                "RESOURCE_EXHAUSTED",
                429,
            ),
            (
                BlockingFunctionCode::FailedPrecondition,
                "FAILED_PRECONDITION",
                400,
            ),
            (BlockingFunctionCode::Aborted, "ABORTED", 409),
            (BlockingFunctionCode::OutOfRange, "OUT_OF_RANGE", 400),
            (BlockingFunctionCode::Unimplemented, "UNIMPLEMENTED", 501),
            (BlockingFunctionCode::Internal, "INTERNAL", 500),
            (BlockingFunctionCode::Unavailable, "UNAVAILABLE", 503),
            (BlockingFunctionCode::DataLoss, "DATA_LOSS", 500),
        ] {
            assert_eq!(BlockingFunctionCode::from_canonical_name(name), Some(code));
            assert_eq!(code.canonical_name(), name);
            assert_eq!(code.function_status(), function_status);
            let failure = BlockingFunctionFailure::from_function(code, "safe").unwrap();
            assert_eq!(
                failure.identity_status(),
                if function_status < 500 {
                    400
                } else {
                    function_status
                }
            );
        }
        assert_eq!(
            BlockingFunctionCode::from_canonical_name("unavailable"),
            None
        );
        assert_eq!(BlockingFunctionCode::from_canonical_name("OK"), None);
    }

    #[test]
    fn the_blocking_auth_lane_covers_only_routes_that_can_reach_a_configured_hook() {
        let blocking = AllBlockingHooks;
        for (method, path, expected) in [
            (
                "POST",
                "/identitytoolkit.googleapis.com/v1/accounts:signUp",
                true,
            ),
            (
                "POST",
                "/identitytoolkit.googleapis.com/v1/accounts:lookup?key=fake",
                false,
            ),
            (
                "POST",
                "/identitytoolkit.googleapis.com/v1/projects/demo-app/accounts:lookup",
                false,
            ),
            ("GET", "/", false),
            ("POST", "/emulator/v1/projects/demo-app/accounts", false),
            (
                "GET",
                "/identitytoolkit.googleapis.com/v1/accounts:signUp",
                false,
            ),
            ("POST", "/unknown", false),
        ] {
            assert_eq!(
                request_may_invoke_blocking_auth(Some(&blocking), method, path),
                expected,
                "{method} {path}"
            );
        }
        assert!(!request_may_invoke_blocking_auth(
            Some(&NoBlockingHooks),
            "POST",
            "/identitytoolkit.googleapis.com/v1/accounts:signUp",
        ));
        assert!(request_may_invoke_blocking_auth(
            Some(&BeforeCreateOnlyHook),
            "POST",
            "/identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken",
        ));
        assert!(!request_may_invoke_blocking_auth(
            Some(&BeforeCreateOnlyHook),
            "POST",
            "/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword",
        ));
    }

    #[test]
    fn blocking_function_failure_bounds_and_escapes_its_message() {
        let accepted = "a".repeat(BlockingFunctionFailure::MAX_MESSAGE_BYTES);
        BlockingFunctionFailure::from_function(BlockingFunctionCode::InvalidArgument, accepted)
            .unwrap();
        assert!(BlockingFunctionFailure::from_function(
            BlockingFunctionCode::InvalidArgument,
            "a".repeat(BlockingFunctionFailure::MAX_MESSAGE_BYTES + 1),
        )
        .is_err());
        for message in [
            "nul\0",
            "line\nfeed",
            "return\r",
            "next\u{0085}line",
            "left\u{202e}override",
            "isolate\u{2066}text",
        ] {
            assert!(BlockingFunctionFailure::from_function(
                BlockingFunctionCode::InvalidArgument,
                message,
            )
            .is_err());
        }
        let failure = BlockingFunctionFailure::from_function(
            BlockingFunctionCode::PermissionDenied,
            "quoted \"slash\\ 日本語",
        )
        .unwrap();
        assert_eq!(failure.identity_status(), 400);
        assert_eq!(
            failure.client_message(),
            "BLOCKING_FUNCTION_ERROR_RESPONSE : HTTP Cloud Function returned an error. Code: 403, Status: \"PERMISSION_DENIED\", Message: \"quoted \\\"slash\\\\ 日本語\""
        );
    }

    #[test]
    fn elapsed_blocking_deadline_uses_the_production_opaque_unavailable_error() {
        let failure = BlockingFunctionFailure::timeout();
        assert_eq!(failure.identity_status(), 503);
        assert_eq!(failure.client_message(), "Error code: 47");

        let explicit = BlockingFunctionFailure::from_function(
            BlockingFunctionCode::DeadlineExceeded,
            "explicit deadline",
        )
        .unwrap();
        assert_eq!(explicit.identity_status(), 504);
        assert!(explicit.client_message().contains("DEADLINE_EXCEEDED"));
    }

    #[test]
    fn auth_wall_clock_advances_from_its_monotonic_anchor() {
        let start = LogicalInstant::from_unix_seconds(1_800_000_000);
        let mut wall_clock = AuthWallClock::from_anchor(start, std::time::Instant::now());
        wall_clock.monotonic_start = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(2))
            .unwrap();

        assert!(wall_clock.now() >= start.checked_add(LogicalDuration::from_seconds(2)).unwrap());
    }
}
