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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use fireemu_core_app_check::admission::{AdmissionRequest, PrivilegedBypass, ServiceAdmission};
use fireemu_core_app_check::header::classify_app_check_header;
use fireemu_core_auth::base32;
use fireemu_core_auth::claims::{ClaimValue, CustomClaims};
use fireemu_core_auth::jwt::{base64url_decode, encode_with, HeaderShape, JwtError};
use fireemu_core_auth::mfa::{MfaError, PendingSignInContext, PendingSignInCredentials};
use fireemu_core_auth::password_policy::{EnforcementState, PasswordPolicy, ViolationCode};
use fireemu_core_auth::signup_quota::{
    QuotaAlgorithm, QuotaMode, SignupQuotaConfig, SignupReservation, TemporaryQuota,
};
use fireemu_core_auth::store::{
    AuthError, AuthPrincipal, AuthStore, CredentialNotice, FederatedIdentity,
    InboundSamlProviderConfig, LocalId, NewUser, OAuthResponseType, OidcProviderConfig,
    OobRequestType, PendingSignInId, PhoneCodeUse, ProjectAuthConfigPatch, RoutedStoreInstall,
    SecondFactorAssertion, SignInConfig, UserQueryExpression, UserSortField, VerificationCode,
    VerificationPurpose,
};
use fireemu_core_session::clock::VirtualClock;
pub use fireemu_core_session::loopback::origin_is_local;
use fireemu_core_types::determinism::Clock;
use fireemu_core_types::json::JsonValue;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};

const PASSWORD_POLICY_FIELDS: [&str; 3] = [
    "passwordPolicyEnforcementState",
    "forceUpgradeOnSignin",
    "passwordPolicyVersions",
];
const PASSWORD_POLICY_OPTION_FIELDS: [&str; 6] = [
    "minPasswordLength",
    "maxPasswordLength",
    "containsUppercaseCharacter",
    "containsLowercaseCharacter",
    "containsNumericCharacter",
    "containsNonAlphanumericCharacter",
];
const QUOTA_FIELDS: [&str; 2] = ["signUpQuotaConfig", "quotaSimulation"];
const QUOTA_SIMULATION_FIELDS: [&str; 4] = [
    "mode",
    "algorithm",
    "defaultQuotaPerHour",
    "maxTrackedBuckets",
];
const SIGNUP_QUOTA_FIELDS: [&str; 3] = ["quota", "startTime", "quotaDuration"];

mod custom_token;
pub use custom_token::{CustomTokenRefusal, CustomTokenTrust};
mod password_hash;
mod project_mfa;
pub use password_hash::restorable_spec as restorable_imported_hash_spec;
mod routes;
pub mod widget;
mod widget_templates;

/// Observer of user lifecycle events (Auth triggers), called after each request while
/// the store is locked, in the order the events happened.
pub type AuthEventSink = Arc<dyn Fn(&fireemu_core_auth::store::UserEvent) + Send + Sync>;

/// Observer of the credentials the official emulator prints instead of sending (email
/// action links, SMS codes), called once per issued code after the request that issued it
/// released the store. `None` drops them; the codes stay readable from the emulator routes.
pub type AuthNoticeSink = Arc<dyn Fn(&fireemu_core_auth::store::CredentialNotice) + Send + Sync>;

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

/// Identity-provider credentials exposed to a Blocking Auth handler for the current request.
#[derive(Clone, PartialEq)]
pub struct AuthBlockingCredential {
    /// SAML attributes or OIDC claims. Other providers leave this absent.
    pub claims: Option<Value>,
    /// Provider ID, such as `saml.corp` or `oidc.corp`.
    pub provider_id: String,
    /// Sign-in method. Identity Platform currently uses the provider ID here.
    pub sign_in_method: String,
    /// OAuth access token supplied by the caller, when credential forwarding is enabled.
    pub access_token: Option<String>,
    /// Identity-provider ID token supplied by the caller, when credential forwarding is enabled.
    pub id_token: Option<String>,
    /// OAuth refresh token supplied by the caller, when credential forwarding is enabled.
    pub refresh_token: Option<String>,
}

impl core::fmt::Debug for AuthBlockingCredential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthBlockingCredential")
            .field("claims", &self.claims.as_ref().map(|_| "[redacted]"))
            .field("provider_id", &self.provider_id)
            .field("sign_in_method", &self.sign_in_method)
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "[redacted]"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "[redacted]"))
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// Provider profile exposed to a Blocking Auth handler for the current request.
#[derive(Clone, PartialEq)]
pub struct AuthBlockingAdditionalUserInfo {
    /// Provider ID for the sign-in.
    pub provider_id: String,
    /// Parsed `rawUserInfo`, when the provider supplied it.
    pub profile: Option<Value>,
    /// Whether this is the before-create invocation for a new user.
    pub is_new_user: bool,
}

impl core::fmt::Debug for AuthBlockingAdditionalUserInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthBlockingAdditionalUserInfo")
            .field("provider_id", &self.provider_id)
            .field("profile", &self.profile.as_ref().map(|_| "[redacted]"))
            .field("is_new_user", &self.is_new_user)
            .finish()
    }
}

/// Per-request context supplied to a Blocking Auth handler.
#[derive(Clone, Default, PartialEq)]
pub struct AuthBlockingContext {
    /// Provider credential for an identity-provider sign-in.
    pub credential: Option<AuthBlockingCredential>,
    /// Additional provider profile information for the sign-in.
    pub additional_user_info: Option<AuthBlockingAdditionalUserInfo>,
    /// Sign-in method used to suffix the before-sign-in event type.
    pub sign_in_method: Option<String>,
}

impl core::fmt::Debug for AuthBlockingContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthBlockingContext")
            .field("credential", &self.credential)
            .field("additional_user_info", &self.additional_user_info)
            .field("sign_in_method", &self.sign_in_method)
            .finish()
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

    /// Whether raw caller-supplied identity-provider credentials may be sent to this hook.
    /// Credentials are omitted by default and are never synthesized for missing fields.
    fn forward_inbound_credentials(&self) -> bool {
        false
    }

    /// Raw fields required by the effective target for one event. The default preserves the
    /// all-or-nothing policy of existing in-process hooks.
    fn inbound_credential_policy(
        &self,
        _event: fireemu_core_functions::manifest::BlockingAuthEvent,
    ) -> fireemu_core_functions::manifest::BlockingAuthTokenPolicy {
        if self.forward_inbound_credentials() {
            fireemu_core_functions::manifest::BlockingAuthTokenPolicy::ALL
        } else {
            fireemu_core_functions::manifest::BlockingAuthTokenPolicy::default()
        }
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

    /// Runs a hook with the request-scoped provider context. The default preserves existing
    /// embedders whose hooks only consume the user record and namespace.
    fn invoke_for_with_context(
        &self,
        project: &str,
        tenant: Option<&str>,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
        _context: &AuthBlockingContext,
    ) -> Result<Option<Value>, BlockingFunctionFailure> {
        self.invoke_for(project, tenant, event, user)
    }

    /// Returns the logical project-level blocking settings, when this hook is backed by a
    /// configurable local Functions runtime. The projection must not contain runner addresses,
    /// secrets or dynamic ports.
    fn blocking_auth_settings(&self) -> Option<Value> {
        None
    }

    /// Returns the logical settings for an export, or an error when an explicit local target can
    /// no longer be resolved. Export must not silently discard a configured target after a
    /// Functions manifest change.
    fn blocking_auth_settings_for_export(&self) -> Result<Option<Value>, String> {
        Ok(self.blocking_auth_settings())
    }

    /// Captures enough logical state to restore a settings update if the paired Auth config
    /// commit fails. Runtime-backed bridges may include private discovery markers here; this
    /// value is never written to an export.
    fn blocking_auth_settings_snapshot(&self) -> Result<Option<Value>, String> {
        Ok(self.blocking_auth_settings())
    }

    /// Restores a snapshot captured by [`Self::blocking_auth_settings_snapshot`].
    fn restore_blocking_auth_settings_snapshot(&self, snapshot: &Value) -> Result<(), String> {
        self.update_blocking_auth_settings(snapshot)
    }

    /// Restores a snapshot only when the public blocking settings still equal the candidate
    /// written by this request. The project config route holds its Auth operation gate across
    /// this check and the paired Auth update, so an intervening config request cannot be erased
    /// by rollback. Runtime-backed implementations may override this when their settings store
    /// provides a stronger compare-and-swap primitive.
    fn restore_blocking_auth_settings_snapshot_if_unchanged(
        &self,
        snapshot: &Value,
        candidate: &Value,
    ) -> Result<(), String> {
        let current = self
            .blocking_auth_settings()
            .ok_or_else(|| "blocking Auth settings are unavailable".to_owned())?;
        if current != *candidate {
            return Err("blocking Auth settings changed during the transaction".to_owned());
        }
        self.restore_blocking_auth_settings_snapshot(snapshot)
    }

    /// Validates a complete logical blocking settings projection without changing state.
    fn validate_blocking_auth_settings(&self, _settings: &Value) -> Result<(), String> {
        Err("blocking Auth settings are not configurable for this hook".to_owned())
    }

    /// Atomically replaces a previously validated logical blocking settings projection.
    fn update_blocking_auth_settings(&self, _settings: &Value) -> Result<(), String> {
        Err("blocking Auth settings are not configurable for this hook".to_owned())
    }

    /// Applies a masked logical settings update. Runtime-backed hooks may override this to
    /// preserve internal discovery selections while complete replacements still use explicit
    /// omitted-event semantics. The default treats the supplied value as a complete projection.
    fn update_blocking_auth_settings_masked(
        &self,
        settings: &Value,
        _fields: &[String],
    ) -> Result<(), String> {
        self.update_blocking_auth_settings(settings)
    }

    /// Returns the project whose daemon-owned Functions manifest backs this hook.
    fn blocking_auth_project(&self) -> Option<&str> {
        None
    }

    /// Monotonic revision of the selected blocking-function configuration. Bridges with mutable
    /// function selection should increment it whenever the selection or token policy changes;
    /// the default keeps legacy immutable in-process hooks compatible.
    fn blocking_auth_revision(&self) -> u64 {
        0
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

/// Returns whether a blocking hook is allowed to observe the selected Auth project.
///
/// A runtime-backed bridge reports the project owned by its Functions runtime. Hooks that do not
/// report a binding are legacy in-process hooks: they remain valid for the default store, but a
/// registry-backed adapter must not pass them users from a routed project. This check belongs at
/// the adapter boundary because the default `invoke_for` implementation cannot know which stores
/// the adapter exposes.
fn blocking_hook_applies_to_project(
    state: &AuthState,
    blocking: &dyn AuthBlockingHook,
    project: &str,
) -> bool {
    let bound_project = blocking.blocking_auth_project();
    if bound_project.is_some_and(|bound_project| bound_project != project) {
        return false;
    }
    if bound_project.is_some() || state.registry.is_none() {
        return true;
    }
    state
        .registry
        .as_ref()
        .is_some_and(|registry| registry.default_project() == project)
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

/// Whether client routes admit a caller that presents neither an API key nor a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientApiKeyPolicy {
    /// Match the Firebase Auth Emulator, which serves keyless client requests.
    Optional,
    /// Refuse them as production's API front end does ("unregistered callers").
    Required,
}

/// Whether this embedding exposes bounded local `pendingToken` continuation handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdpContinuationPolicy {
    /// Preserve the Firebase Emulator response shape; pending-token input is unsupported.
    Disabled,
    /// Enable namespace/authority-bound local handles, never production token verification.
    LocalBounded,
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
    /// Issued-credential observer (console lines for action links and SMS codes).
    pub notices: Option<AuthNoticeSink>,
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
    /// Service-account keys signed custom tokens verify against (`auth.customTokenSigners`).
    /// With none, the unsigned tokens the Admin SDK mints in emulator mode are accepted.
    pub custom_token_trust: Option<Arc<CustomTokenTrust>>,
    /// Profile-specific Admin query behavior.
    pub query_limits: AuthQueryLimits,
    /// Whether client routes refuse a request carrying neither an API key nor a credential.
    pub client_api_key: ClientApiKeyPolicy,
    /// Explicit local `IdP` continuation policy, independent of query paging.
    pub idp_continuations: IdpContinuationPolicy,
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
    notices: Option<&'a AuthNoticeSink>,
}

impl Drop for EventDrain<'_> {
    fn drop(&mut self) {
        // Taken under the lock, delivered without it: a sink that calls back into Auth
        // must not deadlock, and other Auth requests are not held up by the sink.
        let (events, notices) = match self.store.lock() {
            Ok(mut store) => (store.take_user_events(), store.take_credential_notices()),
            Err(_) => return,
        };
        if let Some(sink) = self.sink {
            for e in &events {
                sink(e);
            }
        }
        if let Some(sink) = self.notices {
            for n in &notices {
                sink(n);
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

/// A proto3 JSON decoding refusal as production sends it: the gRPC status name, an `errors`
/// entry without a domain, and a `BadRequest` violation naming the proto field (sandbox
/// recording 2026-09-23).
fn proto_field_error(field: &str, description: &str) -> JsonResponse {
    JsonResponse {
        status: 400,
        body: json!({"error": {
            "code": 400,
            "message": description,
            "errors": [{"message": description, "reason": "invalid"}],
            "status": "INVALID_ARGUMENT",
            "details": [{
                "@type": "type.googleapis.com/google.rpc.BadRequest",
                "fieldViolations": [{"field": field, "description": description}],
            }],
        }}),
    }
}

/// Secure Token refusals carry a gRPC status name and no `errors` list, unlike Identity
/// Toolkit's (sandbox recording 2026-09-23).
fn secure_token_error_shape(mut response: JsonResponse) -> JsonResponse {
    if let Some(error) = response
        .body
        .get_mut("error")
        .and_then(Value::as_object_mut)
    {
        error.remove("errors");
        if response.status == 400 {
            error.insert("status".to_owned(), json!("INVALID_ARGUMENT"));
        }
    }
    response
}

/// Production answers an Admin create with a longer id with an internal error and creates
/// nothing (sandbox exploration 2026-09-24).
fn local_id_too_long(id: &str) -> bool {
    id.encode_utf16().count() > fireemu_core_auth::store::MAX_LOCAL_ID_UTF16_UNITS
}

/// Production's generic backend failure (sandbox recording 2026-09-23).
fn backend_internal_error() -> JsonResponse {
    const MESSAGE: &str = "Internal error encountered.";
    JsonResponse {
        status: 500,
        body: json!({"error": {
            "code": 500,
            "message": MESSAGE,
            "errors": [{"message": MESSAGE, "domain": "global", "reason": "backendError"}],
            "status": "INTERNAL",
        }}),
    }
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
        let Ok(header) = base64url_decode(header) else {
            return error(500, "INTERNAL");
        };
        let Some(shape) = [HeaderShape::Typed, HeaderShape::Untyped]
            .into_iter()
            .find(|shape| header == fireemu_core_auth::jwt::unsigned_header(*shape))
        else {
            return error(500, "INTERNAL");
        };
        let Ok(payload) = base64url_decode(payload) else {
            return error(500, "INTERNAL");
        };
        if !serde_json::from_slice::<Value>(&payload).is_ok_and(|value| value.is_object()) {
            return error(500, "INTERNAL");
        }
        let Ok(payload) = std::str::from_utf8(&payload) else {
            return error(500, "INTERNAL");
        };
        *token = fireemu_core_auth::jwt::encode_payload_shaped(payload, Some(signer), shape);
    }
    response
}

/// Commit the issuance timestamp only after a successful response has been signed.
fn finish_token_response(
    response: JsonResponse,
    signer: Option<&dyn fireemu_core_auth::jwt::IdTokenSigner>,
    store: &Arc<Mutex<AuthStore>>,
    at: LogicalInstant,
) -> JsonResponse {
    let response = sign_response_tokens(response, signer);
    if response.status == 200
        && (response.body.get("idToken").is_some() || response.body.get("id_token").is_some())
    {
        if let Some(refresh) = response
            .body
            .get("refreshToken")
            .or_else(|| response.body.get("refresh_token"))
            .and_then(Value::as_str)
        {
            let Ok(mut store) = store.lock() else {
                return error(500, "INTERNAL");
            };
            store.record_token_issuance(refresh, at);
        }
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

/// A `303 See Other` to `location`. The HTTP server turns the body into the `Location`
/// header ([`redirect_location`]); nothing else produces a 303.
fn redirect(location: &str) -> JsonResponse {
    JsonResponse {
        status: 303,
        body: json!({"location": location}),
    }
}

/// The target of a redirect response built by this module, or `None` for any other body.
#[must_use]
pub fn redirect_location(body: &Value) -> Option<&str> {
    body.get("location").and_then(Value::as_str)
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
        AuthError::PasswordTooLong => error(
            400,
            "PASSWORD_DOES_NOT_MEET_REQUIREMENTS : Password cannot be longer than 4096 characters",
        ),
        AuthError::PasswordPolicyViolation(refusal) => {
            error(400, &password_requirements_message(refusal))
        }
        // Production names the client-permission refusal (sandbox recording 2026-09-23).
        AuthError::UserSignupDisabled | AuthError::UserDeletionDisabled => {
            error(400, "ADMIN_ONLY_OPERATION")
        }
        AuthError::SignupQuotaExceeded => error(400, "SIGNUP_QUOTA_EXCEEDED"),
        AuthError::SignupQuotaUnavailable => error(500, "SIGNUP_QUOTA_UNAVAILABLE"),
        AuthError::InvalidCredentials => error(400, "INVALID_LOGIN_CREDENTIALS"),
        AuthError::InvalidPassword => error(400, "INVALID_PASSWORD"),
        AuthError::UserDisabled => error(400, "USER_DISABLED"),
        AuthError::InvalidRefreshToken => error(400, "INVALID_REFRESH_TOKEN"),
        AuthError::ExpiredRefreshToken => error(400, "TOKEN_EXPIRED"),
        AuthError::UserNotFound => error(400, "USER_NOT_FOUND"),
        AuthError::InvalidLocalId => error(400, "INVALID_LOCAL_ID"),
        AuthError::ImportedHashFailure => backend_internal_error(),
        AuthError::LocalIdExists => error(400, "DUPLICATE_LOCAL_ID"),
        AuthError::PhoneNumberExists => error(400, "PHONE_NUMBER_EXISTS"),
        AuthError::InvalidPhoneNumber => error(400, "INVALID_PHONE_NUMBER"),
        AuthError::EmailNotFound => error(400, "EMAIL_NOT_FOUND"),
        AuthError::InvalidOobCode => error(400, "INVALID_OOB_CODE"),
        AuthError::ExpiredOobCode => error(400, "EXPIRED_OOB_CODE"),
        AuthError::InvalidSessionInfo => error(400, "INVALID_SESSION_INFO"),
        AuthError::InvalidVerificationCode => error(400, "INVALID_CODE"),
        AuthError::FederatedUserIdAlreadyLinked => error(400, "FEDERATED_USER_ID_ALREADY_LINKED"),
        AuthError::ControlCharacterInText(field) => error(
            400,
            &format!("INVALID_ARGUMENT : {field} must not contain control characters"),
        ),
        AuthError::TooManyOutstandingCodes => error(
            400,
            "QUOTA_EXCEEDED : too many outstanding codes; consume or expire some first",
        ),
        AuthError::LimitExceeded(v) if v.limit_id == "AUTH-LIMIT-CUSTOM-CLAIMS-BYTES" => {
            error(400, "CLAIMS_TOO_LARGE")
        }
        AuthError::LimitExceeded(v) => error(400, &format!("INVALID_CLAIMS : {}", v.limit_id)),
    }
}

/// Production lists every unmet requirement of a custom password policy (sandbox recording
/// 2026-09-23, auth-account/policy/enforce-custom). The maximum, upper-case, numeric and
/// non-alphanumeric sentences and their relative order are observed; the minimum and
/// lower-case sentences follow the same wording and are not yet observed.
fn password_requirements_message(
    refusal: &fireemu_core_auth::password_policy::PolicyRefusal,
) -> String {
    use fireemu_core_auth::password_policy::ViolationCode;
    let sentences: Vec<String> = refusal
        .violations
        .iter()
        .map(|violation| match violation {
            ViolationCode::MinimumPasswordLength => {
                format!(
                    "Password must contain at least {} characters",
                    refusal.min_length
                )
            }
            ViolationCode::MaximumPasswordLength => format!(
                "Password may contain at most {} characters",
                refusal.max_length.unwrap_or(4096)
            ),
            ViolationCode::MissingLowercaseCharacter => {
                "Password must contain a lower case character".to_owned()
            }
            ViolationCode::MissingUppercaseCharacter => {
                "Password must contain an upper case character".to_owned()
            }
            ViolationCode::MissingNumericCharacter => {
                "Password must contain a numeric character".to_owned()
            }
            ViolationCode::MissingNonAlphanumericCharacter => {
                "Password must contain a non-alphanumeric character".to_owned()
            }
        })
        .collect();
    format!(
        "PASSWORD_DOES_NOT_MEET_REQUIREMENTS : Missing password requirements: [{}]",
        sentences.join(", ")
    )
}

fn mfa_error(e: &MfaError) -> JsonResponse {
    match e {
        MfaError::InvalidCode => error(400, "INVALID_CODE"),
        MfaError::CodeAlreadyUsed => error(400, "INVALID_CODE : verification code already used"),
        MfaError::EnrollmentSessionExpired => error(400, "SESSION_EXPIRED"),
        MfaError::TooManyEnrollmentAttempts => {
            error(400, "TOO_MANY_ENROLLMENT_ATTEMPTS : restart enrollment")
        }
        MfaError::EnrollmentAlreadyComplete => error(
            400,
            "MFA_ENROLLMENT_ALREADY_COMPLETE : This MFA enrollment has already been completed.",
        ),
        MfaError::TotpChallengeTimeout => error(
            400,
            "TOTP_CHALLENGE_TIMEOUT : TOTP challenge timeout, provide first factor again.",
        ),
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
        MfaError::ControlCharacterInText(field) => error(
            400,
            &format!("INVALID_ARGUMENT : {field} must not contain control characters"),
        ),
    }
}

fn jwt_error(e: &JwtError) -> JsonResponse {
    match e {
        // Production has no detail for a revoked token either (sandbox recording 2026-09-23),
        // and answers a token past its expiry allowance as invalid, not expired (2026-09-24).
        JwtError::Revoked => error(400, "TOKEN_EXPIRED"),
        JwtError::UserDisabled => error(400, "USER_DISABLED"),
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
    issue_tokens_replacing(
        store,
        uid,
        second,
        at,
        TokenIssue {
            extra,
            provider,
            sign_in_attributes: None,
            provisional_refresh: None,
        },
    )
}

fn issue_tokens_with_sign_in_attributes(
    store: &mut AuthStore,
    uid: &LocalId,
    second: Option<&SecondFactorAssertion>,
    at: LogicalInstant,
    extra: Option<&CustomClaims>,
    provider: Option<fireemu_core_auth::store::Provider>,
    sign_in_attributes: Option<&ClaimValue>,
) -> Result<Value, JsonResponse> {
    issue_tokens_replacing(
        store,
        uid,
        second,
        at,
        TokenIssue {
            extra,
            provider,
            sign_in_attributes,
            provisional_refresh: None,
        },
    )
}

struct TokenIssue<'a> {
    extra: Option<&'a CustomClaims>,
    provider: Option<fireemu_core_auth::store::Provider>,
    sign_in_attributes: Option<&'a ClaimValue>,
    provisional_refresh: Option<&'a str>,
}

/// Issues policy-adjusted tokens and retires the replayed authentication's provisional
/// refresh session when Blocking Auth is active.
fn issue_tokens_replacing(
    store: &mut AuthStore,
    uid: &LocalId,
    second: Option<&SecondFactorAssertion>,
    at: LogicalInstant,
    issue: TokenIssue<'_>,
) -> Result<Value, JsonResponse> {
    let mut claims = store
        .id_token_claims(uid, second, at)
        .map_err(|e| auth_error(&e))?;
    if let Some(p) = &issue.provider {
        p.sign_in_provider_claim()
            .clone_into(&mut claims.firebase.sign_in_provider);
    }
    claims.firebase.sign_in_attributes = issue.sign_in_attributes.cloned();
    if let Some(extra) = issue.extra {
        for (k, v) in extra.entries() {
            claims
                .custom
                .insert_blocking_response(k, v.clone())
                .map_err(|e| error(400, &format!("INVALID_CUSTOM_TOKEN : {e}")))?;
        }
    }
    let refresh_claims = issue.extra.cloned().unwrap_or_default();
    let second = second.cloned();
    let refresh = match issue.provisional_refresh {
        Some(provisional) => store.replace_refresh_session(
            provisional,
            uid,
            at,
            issue.provider,
            refresh_claims,
            second,
        ),
        None => store.issue_refresh_session(uid, at, issue.provider, refresh_claims, second),
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

/// [`verify`] on a route production was observed to honour the legacy token on.
fn verify_honouring_legacy(
    store: &AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> Result<LocalId, JsonResponse> {
    verify_session_accepting(store, body, at, jwt_error, LegacyTokens::Honoured).map(|s| s.uid)
}

/// The session an `idToken` proves: the user and the provider it signed in with (the
/// official emulator reads `firebase.sign_in_provider` back from the token for the routes
/// whose behaviour depends on the first factor).
struct Session {
    uid: LocalId,
    /// The token's `auth_time` (Unix seconds), when it carries one.
    auth_time: Option<i64>,
    provider: String,
    second_factor: Option<SecondFactorAssertion>,
    extra_claims: CustomClaims,
    sign_in_attributes: Option<ClaimValue>,
}

fn sign_in_attributes(payload: &JsonValue) -> Option<ClaimValue> {
    payload
        .get("firebase")
        .and_then(|firebase| firebase.get("sign_in_attributes"))
        .map(ClaimValue::from_json)
}

fn verify_session(
    store: &AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> Result<Session, JsonResponse> {
    verify_session_with_error(store, body, at, jwt_error)
}

fn verify_session_with_error(
    store: &AuthStore,
    body: &Value,
    at: LogicalInstant,
    map_error: fn(&fireemu_core_auth::jwt::JwtError) -> JsonResponse,
) -> Result<Session, JsonResponse> {
    verify_session_accepting(store, body, at, map_error, LegacyTokens::Refused)
}

/// Whether a route honours the legacy Identity Toolkit token. Production was observed to honour
/// it on account lookup, update and delete, a verification mail and an email change, phone
/// linking, email-link linking, a sign-up upgrade and MFA enrollment (sandbox recordings
/// 2026-09-24); identity-provider linking and session-cookie creation refuse it (the last
/// observed, the other until observed).
#[derive(Clone, Copy, PartialEq, Eq)]
enum LegacyTokens {
    Honoured,
    Refused,
}

fn verify_session_accepting(
    store: &AuthStore,
    body: &Value,
    at: LogicalInstant,
    map_error: fn(&fireemu_core_auth::jwt::JwtError) -> JsonResponse,
    legacy_tokens: LegacyTokens,
) -> Result<Session, JsonResponse> {
    let token = match body.get("idToken") {
        None | Some(Value::Null) => return Err(error(400, "MISSING_ID_TOKEN")),
        Some(Value::String(t)) => t.as_str(),
        Some(_) => return Err(error(400, "INVALID_ID_TOKEN")),
    };
    // Account lookup, update and delete also honour the legacy Identity Toolkit token (sandbox
    // recording 2026-09-24); every other route verifies ID tokens only.
    let leeway = fireemu_core_auth::jwt::IDENTITY_TOOLKIT_EXPIRY_LEEWAY_SECONDS;
    let (v, decoded) =
        match fireemu_core_auth::jwt::verify_id_token_decoded_with_leeway(token, store, at, leeway)
        {
            // A token of another issuer may be a legacy token; that verifier checks the issuer.
            Err(fireemu_core_auth::jwt::JwtError::WrongIssuer { .. })
                if legacy_tokens == LegacyTokens::Honoured =>
            {
                fireemu_core_auth::jwt::verify_legacy_token(token, store, at, leeway)
            }
            verified => verified,
        }
        .map_err(|e| map_error(&e))?;
    let legacy = decoded.payload.get("iss").and_then(JsonValue::as_str)
        == Some(fireemu_core_auth::jwt::LEGACY_TOKEN_ISSUER);
    let provider = if legacy {
        decoded.payload.get("sign_in_provider")
    } else {
        decoded
            .payload
            .get("firebase")
            .and_then(|f| f.get("sign_in_provider"))
    }
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
    let sign_in_attributes = sign_in_attributes(&decoded.payload);
    let mut extra_claims = CustomClaims::default();
    let developer = if legacy {
        decoded.payload.get("extra_claims")
    } else {
        Some(&decoded.payload)
    };
    if let Some(JsonValue::Object(values)) = developer {
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
            auth_time: decoded.payload.get("auth_time").and_then(JsonValue::as_i64),
            provider,
            second_factor,
            extra_claims,
            sign_in_attributes,
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
    /// Trusted transport peer address. The HTTP server populates this from `peer_addr`; callers
    /// of the in-process handler may leave it absent and receive the loopback test default.
    pub peer_ip: Option<String>,
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
    api_key: bool,
    project: &str,
    store: &AuthStore,
) -> Result<(), JsonResponse> {
    admin_request_guard(headers, method, api_key)?;
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

/// Production's API front end refuses a key the project does not own before the service reads
/// the request (sandbox recording 2026-09-24, auth-credential/refresh/refusals#invalid-api-key).
fn invalid_api_key(service: &str) -> JsonResponse {
    const MESSAGE: &str = "API key not valid. Please pass a valid API key.";
    let mut response = invalid_api_key_without_errors(service);
    // Identity Toolkit adds its `errors` list; Secure Token does not (2026-09-24).
    if service == "identitytoolkit.googleapis.com" {
        response.body["error"]["errors"] =
            json!([{"message": MESSAGE, "domain": "global", "reason": "badRequest"}]);
    }
    response
}

fn invalid_api_key_without_errors(service: &str) -> JsonResponse {
    const MESSAGE: &str = "API key not valid. Please pass a valid API key.";
    JsonResponse {
        status: 400,
        body: json!({"error": {
            "code": 400,
            "message": MESSAGE,
            "status": "INVALID_ARGUMENT",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "API_KEY_INVALID",
                    "domain": "googleapis.com",
                    "metadata": {"service": service},
                },
                {
                    "@type": "type.googleapis.com/google.rpc.LocalizedMessage",
                    "locale": "en-US",
                    "message": MESSAGE,
                },
            ],
        }}),
    }
}

/// Production's refusal of an API key where session management needs a credential.
fn session_management_credentials_missing() -> JsonResponse {
    JsonResponse {
        status: 401,
        body: json!({"error": {
            "code": 401,
            "message": "API keys are not supported by this API. Expected OAuth2 access token or other authentication credentials that assert a principal. See https://cloud.google.com/docs/authentication",
            "errors": [{
                "message": "Login Required.",
                "domain": "global",
                "reason": "required",
                "location": "Authorization",
                "locationType": "header",
            }],
            "status": "UNAUTHENTICATED",
            "details": [{
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": "CREDENTIALS_MISSING",
                "domain": "googleapis.com",
                "metadata": {
                    "method": "google.cloud.identitytoolkit.v1.SessionManagementService.CreateSessionCookie",
                    "service": "identitytoolkit.googleapis.com",
                },
            }],
        }}),
    }
}

/// The Google API a request path addresses, as the front end names it.
fn api_service(path: &str) -> &'static str {
    if path.starts_with("/securetoken.googleapis.com/") {
        "securetoken.googleapis.com"
    } else {
        "identitytoolkit.googleapis.com"
    }
}

/// Refuses an API key the project did not declare, when it declared any.
fn declared_api_key_check(
    state: &AuthState,
    path: &str,
    query: Option<&str>,
) -> Result<(), JsonResponse> {
    let (Ok((Some(key), _)), Some(tenancy)) = (query_selectors(query), state.tenancy.as_ref())
    else {
        return Ok(());
    };
    let Ok(tenancy) = tenancy.read() else {
        return Err(error(500, "INTERNAL"));
    };
    if tenancy.refuses_api_key(&key) {
        return Err(invalid_api_key(api_service(path)));
    }
    Ok(())
}

/// Production's API front end refuses a caller that presents no identity at all: neither a
/// credential nor an API key (sandbox recording 2026-09-23).
fn unregistered_caller() -> JsonResponse {
    const MESSAGE: &str = "Method doesn't allow unregistered callers (callers without established identity). Please use API Key or other form of API consumer identity to call this API.";
    JsonResponse {
        status: 403,
        body: json!({"error": {
            "code": 403,
            "message": MESSAGE,
            "errors": [{"message": MESSAGE, "domain": "global", "reason": "forbidden"}],
            "status": "PERMISSION_DENIED",
        }}),
    }
}

fn admin_request_guard(
    headers: &RequestHeaders,
    method: &str,
    api_key: bool,
) -> Result<(), JsonResponse> {
    // Without an `Authorization` header production answers by what the request still
    // carries: an API key identifies the caller but cannot address a project, and nothing at
    // all is an unregistered caller (sandbox recording 2026-09-23). A present but foreign
    // credential keeps the local owner-credential refusal; its production shape is unobserved.
    if headers.authorization.is_none() {
        return Err(if api_key {
            error(
                400,
                "INSUFFICIENT_PERMISSION : Only authenticated requests can specify target_project_id.",
            )
        } else {
            unregistered_caller()
        });
    }
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
        Some(routes::RouteClass::ActionLink) => PrivilegedBypass::IdentityToolkitActionLink,
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

const BLOCKING_CLAIMS_MAX_CHARACTERS: usize = 1_000;

fn javascript_stringify_string_len(value: &str) -> usize {
    2_usize.saturating_add(value.chars().fold(0_usize, |length, character| {
        length.saturating_add(match character {
            '"' | '\\' | '\u{0008}' | '\u{000c}' | '\n' | '\r' | '\t' => 2,
            '\u{0000}'..='\u{001f}' => 6,
            other => other.len_utf16(),
        })
    }))
}

fn javascript_number_string(value: &serde_json::Number) -> String {
    if value.is_i64() || value.is_u64() {
        return value.to_string();
    }
    let Some(number) = value.as_f64() else {
        return value.to_string();
    };
    if number == 0.0 {
        return "0".to_owned();
    }
    let raw = value.to_string();
    let (negative, unsigned) = raw
        .strip_prefix('-')
        .map_or((false, raw.as_str()), |unsigned| (true, unsigned));
    let (mantissa, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or((unsigned, 0_i32), |(mantissa, exponent)| {
            (mantissa, exponent.parse::<i32>().unwrap_or(0))
        });
    let decimal = mantissa.find('.').unwrap_or(mantissa.len());
    let mut digits = mantissa
        .chars()
        .filter(|character| *character != '.')
        .collect::<String>();
    let leading_zeroes = digits
        .chars()
        .take_while(|character| *character == '0')
        .count();
    digits.drain(..leading_zeroes);
    let decimal_position = i32::try_from(decimal)
        .unwrap_or(i32::MAX)
        .saturating_add(exponent)
        .saturating_sub(i32::try_from(leading_zeroes).unwrap_or(i32::MAX));
    while digits.ends_with('0') && digits.len() > 1 {
        digits.pop();
    }
    if digits.is_empty() {
        return "0".to_owned();
    }
    let scientific_exponent = decimal_position.saturating_sub(1);
    let mut formatted = if (-6..21).contains(&scientific_exponent) {
        if decimal_position <= 0 {
            let zeroes = usize::try_from(decimal_position.saturating_neg()).unwrap_or(usize::MAX);
            format!("0.{}{}", "0".repeat(zeroes), digits)
        } else {
            let position = usize::try_from(decimal_position).unwrap_or(usize::MAX);
            if position >= digits.len() {
                format!(
                    "{}{}",
                    digits,
                    "0".repeat(position.saturating_sub(digits.len()))
                )
            } else {
                format!("{}.{}", &digits[..position], &digits[position..])
            }
        }
    } else {
        let mut scientific = digits.remove(0).to_string();
        if !digits.is_empty() {
            scientific.push('.');
            scientific.push_str(&digits);
        }
        let sign = if scientific_exponent >= 0 { "+" } else { "" };
        format!("{scientific}e{sign}{scientific_exponent}")
    };
    if negative {
        formatted.insert(0, '-');
    }
    formatted
}

fn javascript_json_stringify_len(value: &Value) -> usize {
    match value {
        Value::Null | Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(value) => javascript_number_string(value).len(),
        Value::String(value) => javascript_stringify_string_len(value),
        Value::Array(values) => values
            .iter()
            .fold(2_usize, |length, value| {
                length.saturating_add(javascript_json_stringify_len(value))
            })
            .saturating_add(values.len().saturating_sub(1)),
        Value::Object(values) => values
            .iter()
            .fold(2_usize, |length, (name, value)| {
                length
                    .saturating_add(javascript_stringify_string_len(name))
                    .saturating_add(1)
                    .saturating_add(javascript_json_stringify_len(value))
            })
            .saturating_add(values.len().saturating_sub(1)),
    }
}

fn blocking_claim_value(value: &Value) -> ClaimValue {
    match value {
        Value::Null => ClaimValue::Null,
        Value::Bool(value) => ClaimValue::Bool(*value),
        Value::Number(value) => value.as_i64().map_or_else(
            || ClaimValue::Float(value.as_f64().unwrap_or(0.0)),
            ClaimValue::Int,
        ),
        Value::String(value) => ClaimValue::String(value.clone()),
        Value::Array(values) => ClaimValue::List(values.iter().map(blocking_claim_value).collect()),
        Value::Object(values) => ClaimValue::Map(
            values
                .iter()
                .map(|(name, value)| (name.clone(), blocking_claim_value(value)))
                .collect(),
        ),
    }
}

struct BlockingClaims {
    claims: CustomClaims,
    original: serde_json::Map<String, Value>,
}

fn blocking_claims(value: Option<&Value>, field: &str) -> Result<BlockingClaims, String> {
    let Some(value @ Value::Object(object)) = value else {
        return Err(format!(
            "BLOCKING_FUNCTION_ERROR_RESPONSE : ((Response has malformed {field}.))"
        ));
    };
    if javascript_json_stringify_len(value) > BLOCKING_CLAIMS_MAX_CHARACTERS {
        return Err(format!(
            "BLOCKING_FUNCTION_ERROR_RESPONSE : ((The {field} payload should not exceed {BLOCKING_CLAIMS_MAX_CHARACTERS} characters.))"
        ));
    }
    let mut claims = CustomClaims::default();
    for (name, value) in object {
        claims
            .insert_blocking_response(name, blocking_claim_value(value))
            .map_err(|error| {
                format!("BLOCKING_FUNCTION_ERROR_RESPONSE : ((Invalid {field}: {error}.))")
            })?;
    }
    Ok(BlockingClaims {
        claims,
        original: object.clone(),
    })
}

fn validate_combined_blocking_claims(
    custom_claims: Option<&BlockingClaims>,
    session_claims: Option<&BlockingClaims>,
) -> Result<(), String> {
    let (Some(custom_claims), Some(session_claims)) = (custom_claims, session_claims) else {
        return Ok(());
    };
    let mut combined = custom_claims.original.clone();
    for (name, value) in &session_claims.original {
        combined.insert(name.clone(), value.clone());
    }
    if javascript_json_stringify_len(&Value::Object(combined)) > BLOCKING_CLAIMS_MAX_CHARACTERS {
        return Err(format!(
            "BLOCKING_FUNCTION_ERROR_RESPONSE : ((The customClaims and sessionClaims payloads should not exceed {BLOCKING_CLAIMS_MAX_CHARACTERS} characters combined.))"
        ));
    }
    Ok(())
}

fn claim_value_to_json(value: &ClaimValue) -> Option<Value> {
    let mut encoded = String::new();
    value.write_canonical_json(&mut encoded);
    serde_json::from_str(&encoded).ok()
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
    validate_combined_blocking_claims(custom_claims.as_ref(), session_claims.as_ref())?;
    if let Some(claims) = custom_claims {
        store
            .set_custom_claims(uid, claims.claims)
            .map_err(|error| {
                format!("BLOCKING_FUNCTION_ERROR_RESPONSE : ((Invalid customClaims: {error}.))")
            })?;
    }
    Ok(session_claims.map(|claims| claims.claims))
}

fn inbound_credentials_from_request(
    body: &Value,
    policy: fireemu_core_functions::manifest::BlockingAuthTokenPolicy,
) -> Option<PendingSignInCredentials> {
    let request_uri = str_field(body, "requestUri")?;
    let params = normalized_idp_params(request_uri, str_field(body, "postBody"));
    let credentials = PendingSignInCredentials::new(
        policy
            .access_token
            .then(|| {
                params
                    .get("access_token")
                    .filter(|token| !token.is_empty())
                    .cloned()
            })
            .flatten(),
        policy
            .id_token
            .then(|| {
                params
                    .get("id_token")
                    .filter(|token| !token.is_empty())
                    .cloned()
            })
            .flatten(),
        policy
            .refresh_token
            .then(|| {
                params
                    .get("refresh_token")
                    .filter(|token| !token.is_empty())
                    .cloned()
            })
            .flatten(),
    );
    (credentials.access_token().is_some()
        || credentials.id_token().is_some()
        || credentials.refresh_token().is_some())
    .then_some(credentials)
}

fn blocking_credential(
    provider_id: &str,
    claims: Option<Value>,
    inbound_credentials: Option<&PendingSignInCredentials>,
    policy: fireemu_core_functions::manifest::BlockingAuthTokenPolicy,
) -> Option<AuthBlockingCredential> {
    let has_inbound_credentials = inbound_credentials.is_some_and(|credentials| {
        credentials.access_token().is_some()
            || credentials.id_token().is_some()
            || credentials.refresh_token().is_some()
    });
    if claims.is_none() && !has_inbound_credentials {
        return None;
    }
    Some(AuthBlockingCredential {
        claims,
        provider_id: provider_id.to_owned(),
        sign_in_method: provider_id.to_owned(),
        access_token: policy
            .access_token
            .then(|| {
                inbound_credentials
                    .and_then(|credentials| credentials.access_token().map(str::to_owned))
            })
            .flatten(),
        id_token: policy
            .id_token
            .then(|| {
                inbound_credentials
                    .and_then(|credentials| credentials.id_token().map(str::to_owned))
            })
            .flatten(),
        refresh_token: policy
            .refresh_token
            .then(|| {
                inbound_credentials
                    .and_then(|credentials| credentials.refresh_token().map(str::to_owned))
            })
            .flatten(),
    })
}

fn blocking_context(
    response: &JsonResponse,
    event: fireemu_core_functions::manifest::BlockingAuthEvent,
    pending: Option<&PendingSignInContext>,
    sign_in_method: Option<&str>,
    inbound_credentials: Option<&PendingSignInCredentials>,
    policy: fireemu_core_functions::manifest::BlockingAuthTokenPolicy,
) -> AuthBlockingContext {
    if let Some(pending) = pending {
        let provider_id = pending.sign_in_provider();
        let is_idp = provider_id
            .is_some_and(|provider| provider.starts_with("saml.") || provider.starts_with("oidc."));
        let claims = is_idp
            .then(|| pending.sign_in_attributes().and_then(claim_value_to_json))
            .flatten();
        let inbound_credentials = pending.inbound_credentials().or(inbound_credentials);
        let credential = provider_id.and_then(|provider_id| {
            blocking_credential(provider_id, claims.clone(), inbound_credentials, policy)
        });
        return AuthBlockingContext {
            credential,
            additional_user_info: provider_id.filter(|_| is_idp).map(|provider_id| {
                AuthBlockingAdditionalUserInfo {
                    provider_id: provider_id.to_owned(),
                    profile: claims,
                    is_new_user: pending.is_new_user(),
                }
            }),
            sign_in_method: sign_in_method.map(str::to_owned),
        };
    }
    let provider_id = response.body.get("providerId").and_then(Value::as_str);
    let profile = response
        .body
        .get("rawUserInfo")
        .and_then(Value::as_str)
        .and_then(|raw| serde_json::from_str(raw).ok())
        .filter(|profile: &Value| !profile.is_null());
    let claims = provider_id
        .is_some_and(|provider| provider.starts_with("saml.") || provider.starts_with("oidc."))
        .then(|| profile.clone())
        .flatten();
    let credential = provider_id.and_then(|provider_id| {
        blocking_credential(provider_id, claims.clone(), inbound_credentials, policy)
    });
    AuthBlockingContext {
        credential,
        additional_user_info: provider_id.map(|provider_id| AuthBlockingAdditionalUserInfo {
            provider_id: provider_id.to_owned(),
            profile,
            is_new_user: event == fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate,
        }),
        sign_in_method: sign_in_method.map(str::to_owned),
    }
}

fn blocking_sign_in_method<'a>(
    handler: routes::Handler,
    body: &Value,
    response: &'a JsonResponse,
    pending: Option<&'a PendingSignInContext>,
) -> Option<&'a str> {
    if let Some(method) = pending.and_then(PendingSignInContext::sign_in_provider) {
        return Some(method);
    }
    match handler {
        routes::Handler::SignUp => {
            Some(if body.get("password").and_then(Value::as_str).is_some() {
                "password"
            } else {
                "anonymous"
            })
        }
        routes::Handler::SignInWithPassword => Some("password"),
        routes::Handler::SignInWithCustomToken => Some("custom"),
        routes::Handler::SignInWithEmailLink => Some("emailLink"),
        routes::Handler::SignInWithPhoneNumber => Some("phone"),
        routes::Handler::SignInWithIdp => response.body.get("providerId").and_then(Value::as_str),
        _ => None,
    }
}

fn discard_pending_inbound_credentials(
    store: &Arc<Mutex<AuthStore>>,
    pending: Option<&PendingSignInId>,
) {
    let Some(pending) = pending else {
        return;
    };
    let mut store = store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    store.clear_pending_sign_in_credentials(pending);
}

fn discard_pending_inbound_credentials_if_revision_current(
    store: &Arc<Mutex<AuthStore>>,
    pending: Option<&PendingSignInId>,
    settings_gate: &Arc<Mutex<()>>,
    blocking: &dyn AuthBlockingHook,
    expected_blocking_revision: u64,
) -> Result<(), JsonResponse> {
    let Some(pending) = pending else {
        return Ok(());
    };
    let Ok(_settings_operation) = settings_gate.lock() else {
        return Err(error(500, "INTERNAL"));
    };
    if blocking.blocking_auth_revision() != expected_blocking_revision {
        return Err(error(409, "BLOCKING_FUNCTION_CONFIGURATION_CHANGED"));
    }
    discard_pending_inbound_credentials(store, Some(pending));
    Ok(())
}

struct GeneratedLocalIdReservation {
    store: Arc<Mutex<AuthStore>>,
    id: String,
    generation: u64,
    ticket: u64,
}

impl Drop for GeneratedLocalIdReservation {
    fn drop(&mut self) {
        let store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store.release_reserved_generated_local_id_at_ticket(&self.id, self.generation, self.ticket);
    }
}

// The request parts stay separate here so the ordinary dispatcher remains the one source of
// route behavior; grouping them in a second request type would duplicate that boundary.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn dispatch_with_blocking_hook(
    state: &AuthState,
    blocking: &dyn AuthBlockingHook,
    expected_blocking_revision: u64,
    handler: routes::Handler,
    store_arc: &Arc<Mutex<AuthStore>>,
    store: std::sync::MutexGuard<'_, AuthStore>,
    settings_gate: &Arc<Mutex<()>>,
    operation_gate: Option<&Arc<Mutex<()>>>,
    query: Option<&str>,
    body: &Value,
    headers: &RequestHeaders,
    at: LogicalInstant,
    quota_reservation: &mut Option<SignupReservation>,
) -> JsonResponse {
    let pending_continuation = (handler == routes::Handler::MfaSignInFinalize)
        .then(|| str_field(body, "mfaPendingCredential"))
        .flatten()
        .and_then(PendingSignInId::parse)
        .and_then(|pending| {
            Some((
                pending.clone(),
                store.pending_sign_in_user(&pending)?,
                store.pending_sign_in_context(&pending)?.clone(),
            ))
        });
    if blocking.blocking_auth_revision() != expected_blocking_revision {
        return error(409, "BLOCKING_FUNCTION_CONFIGURATION_CHANGED");
    }
    let generated_id_interference = store.generated_id_interference_count();
    let mut candidate = store.clone();
    let live_snapshot = store.clone();
    let reset_generation = store.reset_generation();
    let reserve_local_id = request_may_create_end_user(handler, &store, body, at)
        .then(|| candidate.reserve_next_generated_local_id_with_ticket());
    // Register the reservation while the candidate still shares its reservation registry with
    // the live store, then release the request's store guard before constructing the Drop guard.
    // Every subsequent early return may therefore safely release the reservation without trying
    // to re-lock this still-held mutex.
    drop(store);
    let reservation_ticket = reserve_local_id.clone();
    let _reserved_local_id =
        reserve_local_id.map(|(id, generation, ticket)| GeneratedLocalIdReservation {
            store: store_arc.clone(),
            id,
            generation,
            ticket,
        });
    let response = dispatch(
        handler,
        &mut candidate,
        query,
        body,
        headers,
        at,
        &blocking_dispatch_options(state),
    );
    if blocking.blocking_auth_revision() != expected_blocking_revision {
        return error(409, "BLOCKING_FUNCTION_CONFIGURATION_CHANGED");
    }
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
        .map(|user| user.local_id.clone())
        .or_else(|| pending_continuation.as_ref().map(|(_, uid, _)| uid.clone()));
    let speculative_uid = uid.clone();
    let is_new = is_authentication
        && uid_text.as_deref().is_some_and(|uid| {
            live_snapshot.user_by_id(uid).is_none() && candidate.user_by_id(uid).is_some()
        });
    let signed_in = is_authentication
        && response.status == 200
        && (response.body.get("idToken").is_some() || response.body.get("id_token").is_some());
    let sign_in_method = blocking_sign_in_method(
        handler,
        body,
        &response,
        pending_continuation.as_ref().map(|(_, _, context)| context),
    )
    .map(str::to_owned);
    let before_create_policy = blocking.inbound_credential_policy(
        fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate,
    );
    let before_sign_in_policy = blocking.inbound_credential_policy(
        fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn,
    );
    let retained_policy = before_create_policy.union(before_sign_in_policy);
    let inbound_credentials = retained_policy
        .any()
        .then(|| inbound_credentials_from_request(body, retained_policy))
        .flatten();
    let project = live_snapshot.project_id().to_owned();
    let tenant = live_snapshot.tenant_id().map(str::to_owned);
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
                    let context = blocking_context(
                        &response,
                        fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate,
                        None,
                        sign_in_method.as_deref(),
                        inbound_credentials.as_ref(),
                        before_create_policy,
                    );
                    match blocking.invoke_for_with_context(
                        &project,
                        tenant.as_deref(),
                        fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate,
                        user,
                        &context,
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
                    let context = blocking_context(
                        &response,
                        fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn,
                        pending_continuation.as_ref().map(|(_, _, context)| context),
                        sign_in_method.as_deref(),
                        inbound_credentials.as_ref(),
                        before_sign_in_policy,
                    );
                    match blocking.invoke_for_with_context(
                        &project,
                        tenant.as_deref(),
                        fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn,
                        user,
                        &context,
                    ) {
                        Ok(value) => value,
                        Err(failure) => {
                            if let Err(response) =
                                discard_pending_inbound_credentials_if_revision_current(
                                    store_arc,
                                    pending_continuation.as_ref().map(|(pending, _, _)| pending),
                                    settings_gate,
                                    blocking,
                                    expected_blocking_revision,
                                )
                            {
                                return response;
                            }
                            return error(failure.identity_status(), &failure.client_message());
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
                        if let Err(response) =
                            discard_pending_inbound_credentials_if_revision_current(
                                store_arc,
                                pending_continuation.as_ref().map(|(pending, _, _)| pending),
                                settings_gate,
                                blocking,
                                expected_blocking_revision,
                            )
                        {
                            return response;
                        }
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
    if blocking.blocking_auth_revision() != expected_blocking_revision {
        return error(409, "BLOCKING_FUNCTION_CONFIGURATION_CHANGED");
    }
    let mut commit = |metadata: Option<&fireemu_core_auth::store::TenantMetadata>| {
        if blocking.blocking_auth_revision() != expected_blocking_revision {
            return error(409, "BLOCKING_FUNCTION_CONFIGURATION_CHANGED");
        }
        if tenant.is_some() {
            if let Some(denial) = tenant_policy_denial_with_metadata(handler, metadata, body) {
                return denial;
            }
        }
        let Ok(mut live) = store_arc.lock() else {
            return error(500, "INTERNAL");
        };
        if live.reset_generation() != reset_generation {
            return error(409, "AUTH_STATE_RESET");
        }
        if tenant.is_none() {
            if let Some(denial) = project_provider_denial(handler, live.sign_in_config(), body) {
                return denial;
            }
        }
        if live.generated_id_interference_count() != generated_id_interference {
            return error(
                400,
                "BLOCKING_FUNCTION_ERROR_RESPONSE : identity changed while the hook was running",
            );
        }
        let mut committed = live.clone();
        if is_new {
            if let Some(uid) = speculative_uid.as_ref().map(LocalId::as_str) {
                // Some creation routes (for example custom-token sign-in) use an explicit UID
                // supplied by the caller rather than the generated reservation. Only retire a
                // ticket when it names the UID that the candidate actually selected; otherwise
                // the outer guard releases the unused generated reservation on return.
                if let Some((reserved_id, generation, ticket)) = reservation_ticket.as_ref() {
                    if reserved_id == uid
                        && !committed.use_reserved_generated_local_id_with_ticket(
                            uid,
                            *generation,
                            *ticket,
                        )
                    {
                        return error(409, "AUTH_STATE_CHANGED");
                    }
                }
            }
        }
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
                &blocking_dispatch_options(state),
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
            .map(|user| user.local_id.clone())
            .or_else(|| {
                (handler == routes::Handler::MfaSignInFinalize)
                    .then(|| speculative_uid.clone())
                    .flatten()
            });
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
                let sign_in_attributes = committed_response
                    .body
                    .get("idToken")
                    .or_else(|| committed_response.body.get("id_token"))
                    .and_then(Value::as_str)
                    .and_then(|token| {
                        fireemu_core_auth::jwt::verify_id_token_decoded(token, &committed, at).ok()
                    })
                    .and_then(|(_, decoded)| sign_in_attributes(&decoded.payload));
                let Ok(claims) = committed.id_token_claims_for_session(&session, at) else {
                    return error(500, "INTERNAL");
                };
                Some(Session {
                    uid: session.uid,
                    auth_time: Some(claims.auth_time),
                    provider: claims.firebase.sign_in_provider,
                    second_factor: session.second_factor,
                    extra_claims: claims.custom,
                    sign_in_attributes,
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
            // A hook response that disables the account refuses the very request that
            // ran it with USER_DISABLED and no tokens (production, recorded 2026-09-11
            // and 2026-09-12). What persists depends on the request, as recorded: a
            // sign-up keeps its created, disabled record (a second sign-up is
            // EMAIL_EXISTS); an MFA finalize persists the response on the record; a
            // first-factor sign-in of an existing account persists nothing (the flag
            // read back as not disabled before, immediately after, and up to thirty
            // seconds after the refusal, while sign-ins stayed refused under the
            // registered function; the same account after the function's removal was
            // not observed in production). Paths other than password sign-in, sign-up
            // and phone MFA finalize are unobserved and follow the existing-account
            // rule.
            if issued_session.is_some() && committed.user(&uid).is_some_and(|u| u.disabled) {
                if live.user(&uid).is_none() {
                    committed.revoke_refresh_tokens(&uid);
                    *live = committed;
                } else if handler == routes::Handler::MfaSignInFinalize {
                    // Applied to a working copy so that a response that passed on the
                    // committed copy but fails against the live record (claims size)
                    // leaves no partial update; the refusal is USER_DISABLED either way.
                    let mut updated = live.clone();
                    let applied = blocking_responses.iter().all(|(event, value)| {
                        apply_blocking_response(&mut updated, &uid, *event, value).is_ok()
                    });
                    if applied {
                        *live = updated;
                    }
                }
                // Do not call `discard_pending_inbound_credentials` here: it takes the
                // store lock that this closure already holds.
                return error(400, "USER_DISABLED");
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
                        if let Err(reason) = session
                            .extra_claims
                            .insert_blocking_response(name, value.clone())
                        {
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
                    TokenIssue {
                        extra: Some(&session.extra_claims),
                        provider: Some(provider),
                        sign_in_attributes: session.sign_in_attributes.as_ref(),
                        provisional_refresh: Some(provisional_refresh),
                    },
                ) {
                    Ok(tokens) => tokens,
                    Err(refusal) => return refusal,
                };
                for field in ["idToken", "refreshToken", "expiresIn", "email"] {
                    if committed_response.body.get(field).is_some() {
                        committed_response.body[field] = tokens[field].clone();
                    }
                }
                if let Some(user) = committed.user(&uid) {
                    if committed_response.body.get("displayName").is_some() {
                        committed_response.body["displayName"] = json!(user.display_name);
                    }
                    if committed_response.body.get("photoUrl").is_some() {
                        committed_response.body["photoUrl"] = json!(user.photo_url);
                    }
                    if committed_response.body.get("emailVerified").is_some() {
                        committed_response.body["emailVerified"] = json!(user.email_verified);
                    }
                }
            }
        }
        if let Some(reservation) = quota_reservation.clone() {
            if is_new {
                if let Err(error) = committed.commit_signup(reservation, now(state)) {
                    return auth_error(&error);
                }
                quota_reservation.take();
            }
        }
        *live = committed;
        committed_response
    };
    // Do not hold either adapter settings gate or namespace gate while invoking the synchronous
    // hook: hooks may re-enter Auth routes (for example, an Admin update) before returning.
    // Acquire both only after the callback completes, before reading metadata or locking the
    // live store. This preserves the adapter-to-registry gate order at the commit boundary while
    // allowing a callback to perform a nested settings operation.
    let Ok(_settings_operation) = settings_gate.lock() else {
        return error(500, "INTERNAL");
    };
    let _operation = match operation_gate {
        Some(gate) => match gate.lock() {
            Ok(operation) => Some(operation),
            Err(_) => return error(500, "INTERNAL"),
        },
        None => None,
    };
    match (tenant.as_deref(), state.registry.as_ref()) {
        (Some(tenant), Some(registry)) => {
            registry.with_existing_tenant_metadata(&project, tenant, commit)
        }
        (Some(_), None) => error(400, "TENANT_NOT_FOUND"),
        (None, _) => commit(None),
    }
}

/// Handles standard REST requests with caller-pinned local OIDC verification enabled.
///
/// This embedder/test configuration is not a new HTTP API. Every `signInWithIdp` request
/// must match this single trust pin and an enabled provider configuration in the selected
/// namespace; refusal never falls back to fixture parsing. No discovery or network calls
/// occur. The daemon and [`handle_with`] retain fixture mode until explicitly wired here.
///
/// The order is fixed: the store of the target project is selected, App Check decides, the
/// route's privilege class is checked (owner credential, control token, project match), and
/// only then does the handler run. Every step reads the same route table
/// (`AUTH-ROUTE-03`).
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn handle_with_oidc_trust(
    state: &AuthState,
    method: &str,
    path: &str,
    headers: &RequestHeaders,
    body: &Value,
    trust: &crate::oidc::LocalOidcTrust,
) -> JsonResponse {
    handle_with_policy(state, method, path, headers, body, Some(trust))
}

/// Handles a request using the emulator fixture assertion policy.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn handle_with(
    state: &AuthState,
    method: &str,
    path: &str,
    headers: &RequestHeaders,
    body: &Value,
) -> JsonResponse {
    handle_with_policy(state, method, path, headers, body, None)
}

#[allow(clippy::too_many_lines)]
fn handle_with_policy(
    state: &AuthState,
    method: &str,
    path: &str,
    headers: &RequestHeaders,
    body: &Value,
    oidc_trust: Option<&crate::oidc::LocalOidcTrust>,
) -> JsonResponse {
    let (path, query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };
    // Whether the caller identified itself with an API key; its validity is checked when the
    // store is selected.
    let api_key = query_selectors(query).is_ok_and(|(key, _)| key.is_some());
    let at = now(state);
    let resolution = routes::resolve(method, path);
    // Production's API front end answers a caller without identity before the service reads
    // any selector, tenant or body (sandbox recording 2026-09-23).
    if let Err(response) = caller_identity_check(state, resolution, headers, api_key) {
        return if api_service(path) == "securetoken.googleapis.com" {
            secure_token_error_shape(response)
        } else {
            response
        };
    }
    if let Err(response) = declared_api_key_check(state, path, query) {
        return response;
    }
    let emulator_clear = matches!(
        resolution,
        routes::Resolution::Matched {
            route,
            ..
        } if route.handler == routes::Handler::EmulatorClearAccounts
    );
    // Account clearing is a lifecycle boundary. Take the shared session barrier exclusively so
    // a blocking candidate cannot finish its callback and publish after the wipe. Ordinary Auth
    // requests retain shared admission; embedded states without a barrier are protected by the
    // store generation checked at the blocking commit boundary below.
    let _exclusive =
        emulator_clear.then(|| state.barrier.as_ref().map(|barrier| barrier.exclusive()));
    let _admitted = (!emulator_clear).then(|| state.barrier.as_ref().map(|b| b.admit()));
    // Project configuration uses this adapter-level gate. Blocking Auth requests acquire the
    // same gate only at their commit boundary, after their synchronous callback has returned, so
    // a callback can re-enter an Admin configuration route without recursively locking it.
    let settings_boundary = matches!(
        resolution,
        routes::Resolution::Matched { route, .. }
            if matches!(
                route.handler,
                routes::Handler::AdminGetProjectConfig
                    | routes::Handler::AdminUpdateProjectConfig
            )
    );
    let _settings_operation = if settings_boundary {
        match state.operation_gate.lock() {
            Ok(operation) => Some(operation),
            Err(_) => return error(500, "INTERNAL"),
        }
    } else {
        None
    };
    let routed_project = match resolution {
        routes::Resolution::Matched {
            route,
            project: Some(project),
            tenant: None,
            ..
        } if state.allow_routed_projects && route.class == routes::RouteClass::Admin => {
            Some(project)
        }
        _ => None,
    };
    if let Some(project) = routed_project {
        if fireemu_core_types::ids::ProjectId::try_new(project.to_owned()).is_err() {
            return error(400, "INVALID_PROJECT_ID");
        }
        if let Err(response) = admin_request_guard(headers, method, api_key) {
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
    let routed_operation = match routed_gate.as_ref() {
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
    let end_user_request = matches!(
        resolution,
        routes::Resolution::Matched { route, .. }
            if route.class == routes::RouteClass::EndUser
    );
    let (store_project, store_tenant) = {
        let Ok(store) = store_arc.lock() else {
            return error(500, "INTERNAL");
        };
        (
            store.project_id().to_owned(),
            store.tenant_id().map(str::to_owned),
        )
    };
    let blocking_auth = state.blocking.as_deref().is_some_and(|blocking| {
        matches!(
            resolution,
            routes::Resolution::Matched { route, .. }
                if handler_may_invoke_blocking_auth(blocking, route.handler)
        ) && blocking_hook_applies_to_project(state, blocking, &store_project)
    });
    let blocking_revision = state
        .blocking
        .as_deref()
        .map_or(0, AuthBlockingHook::blocking_auth_revision);
    // End-user requests take the namespace gate before acquiring the store guard. Configuration
    // PATCHes use this same gate and then lock the store, so keeping one order prevents a signup
    // from holding the store while a concurrent PATCH waits for the gate. The gate also covers
    // ordinary reads in a routed namespace; this is deliberately conservative because deciding
    // whether a request creates an account requires the store snapshot.
    // A registry-backed namespace has one gate shared by end-user admission and config PATCHes.
    // The legacy single-store blocking bridge may synchronously call back into that store from
    // its hook (some test and embedding bridges do), so preserve its re-entrant store behavior
    // when no registry exists instead of introducing a store/gate deadlock. The adapter-wide
    // gate is reacquired by the blocking commit boundary after the callback returns. End-user
    // requests without a blocking hook still use the adapter-wide gate, which is also used by
    // the single-store config route.
    let operation_gate = if emulator_clear {
        let gate = match state.registry.as_ref() {
            Some(registry) => registry
                .operation_gate(&store_project, None)
                .ok_or_else(|| error(500, "INTERNAL")),
            None => Ok(state.operation_gate.clone()),
        };
        Some(match gate {
            Ok(gate) => gate,
            Err(response) => return response,
        })
    } else if state.registry.is_none() && state.blocking.is_some() {
        // Release the namespace gate before invoking a legacy single-store hook. The gate is
        // reacquired by dispatch_with_blocking_hook for its commit, while non-hooking routes can
        // continue to read the store during an external callback.
        None
    } else if blocking_auth || end_user_request {
        let gate = match state.registry.as_ref() {
            Some(registry) => registry
                // Project and tenant management both commit through the project gate. A
                // tenant-specific request therefore uses that same parent gate so a project
                // update cannot race a tenant policy admission or store commit.
                .operation_gate(&store_project, None)
                .ok_or_else(|| error(500, "INTERNAL")),
            None => Ok(state.operation_gate.clone()),
        };
        Some(match gate {
            Ok(gate) => gate,
            Err(response) => return response,
        })
    } else {
        None
    };
    // Non-blocking end-user requests keep the gate through admission and commit. Blocking hooks
    // release it while the external callback runs and reacquire it in the commit boundary below,
    // so a synchronous hook can safely re-enter Auth.
    let _operation = if blocking_auth {
        None
    } else {
        match operation_gate.as_ref() {
            Some(gate) => match gate.lock() {
                Ok(operation) => Some(operation),
                Err(_) => return error(500, "INTERNAL"),
            },
            None => None,
        }
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
        notices: state.notices.as_ref(),
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
            resource: _,
        } => (route, project, tenant),
        routes::Resolution::MethodNotAllowed { class, project, .. } => {
            if let Err(r) = privilege_check(state, class, project, headers, method, api_key, &store)
            {
                return r;
            }
            // Production's front end answers a POST to accounts:batchGet with a plain 404
            // (sandbox recording 2026-09-23); other method mismatches are unobserved.
            if path.ends_with("/accounts:batchGet") {
                return not_found();
            }
            return error(405, "METHOD_NOT_ALLOWED");
        }
        routes::Resolution::NotFound => return not_found(),
    };
    if let Err(r) = privilege_check(
        state,
        route.class,
        project,
        headers,
        method,
        api_key,
        &store,
    ) {
        return r;
    }
    if matches!(
        route.handler,
        routes::Handler::AdminGetProjectConfig | routes::Handler::AdminUpdateProjectConfig
    ) {
        drop(store);
        // Existing namespaces commit through the core-owned gate. A pending candidate remains
        // isolated under the routed gate until a successful write installs it.
        if pending_routed_project.is_none() {
            drop(routed_operation);
        }
        return project_config_management(
            state,
            route.handler,
            project,
            &store_arc,
            pending_routed_project.as_deref(),
            query,
            body,
        );
    }
    if matches!(
        route.handler,
        routes::Handler::ProviderCreate
            | routes::Handler::ProviderList
            | routes::Handler::ProviderGet
            | routes::Handler::ProviderUpdate
            | routes::Handler::ProviderDelete
    ) {
        if tenant.is_some() && store.tenant_id() != tenant {
            return error(404, "TENANT_NOT_FOUND");
        }
        let resource = match resolution {
            routes::Resolution::Matched { resource, .. } => resource,
            _ => None,
        };
        let provider_kind = if path.contains("/oauthIdpConfigs") {
            ProviderKind::Oidc
        } else {
            ProviderKind::Saml
        };
        drop(store);
        let response = provider_config_management(
            &store_arc,
            route.handler,
            provider_kind,
            project,
            tenant,
            resource,
            query,
            body,
        );
        if response.status == 200
            && matches!(
                route.handler,
                routes::Handler::ProviderCreate | routes::Handler::ProviderUpdate
            )
        {
            if let Some(project) = pending_routed_project.as_deref() {
                if let Err(response) = install_routed_candidate(state, project, &store_arc) {
                    return response;
                }
            }
        }
        return response;
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
        drop(routed_operation);
        return tenant_management(state, route.handler, project, tenant, query, body);
    }
    if tenant.is_some() && store.tenant_id() != tenant {
        return error(404, "TENANT_NOT_FOUND");
    }
    if route.handler == routes::Handler::SignInWithIdp
        && state.idp_continuations == IdpContinuationPolicy::Disabled
        && body
            .get("pendingToken")
            .is_some_and(|value| !value.is_null())
    {
        return not_implemented("pendingToken requires local continuation mode.");
    }
    let idp_authority = (route.handler == routes::Handler::SignInWithIdp
        && state.idp_continuations == IdpContinuationPolicy::LocalBounded)
        .then(|| idp_continuation_authority(oidc_trust));
    let idp_generation = store.reset_generation();
    let incoming_pending = body
        .get("pendingToken")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let resumed_body = match idp_authority.as_deref() {
        Some(authority) => match resume_idp_body(&store, body, authority, at) {
            Ok(body) => body,
            Err(response) => return response,
        },
        None => None,
    };
    let body = resumed_body.as_ref().unwrap_or(body);
    if route.class == routes::RouteClass::EndUser && store_tenant.is_some() {
        if let Some(denial) =
            tenant_policy_denial_with_metadata(route.handler, tenant_metadata.as_ref(), body)
        {
            return denial;
        }
    }
    if route.class == routes::RouteClass::EndUser && store_tenant.is_none() {
        if let Some(denial) = project_provider_denial(route.handler, store.sign_in_config(), body) {
            return denial;
        }
    }
    if route.class == routes::RouteClass::EndUser {
        if let Some(denial) = end_user_client_permission_denial(route.handler, &store, body, at) {
            return denial;
        }
    }
    // Verify the selected namespace and assertion before any account or transient mutation.
    if route.handler == routes::Handler::SignInWithIdp {
        if let Some(trust) = oidc_trust {
            let params = normalized_idp_params(
                str_field(body, "requestUri").unwrap_or_default(),
                str_field(body, "postBody"),
            );
            if !trust.accepts(&store, &params, at) {
                return error(400, "INVALID_IDP_RESPONSE");
            }
        }
    }
    // Strict (stateful refresh sessions) follows production's action-code lifetimes: a reset
    // code lives an hour and is then refused as expired (sandbox recording 2026-09-24).
    store.set_production_oob_lifetimes(!state.stateless_refresh_tokens);
    store.set_production_mfa(!state.stateless_refresh_tokens);
    // Expired transient credentials are swept before every request is served, so nothing
    // past its lifetime is observable (`AUTH-TRANSIENT-01`, `-02`).
    store.sweep_transient_credentials(at);
    let quota_request = route.class == routes::RouteClass::EndUser
        && request_may_create_end_user(route.handler, &store, body, at);
    let mut quota_reservation = if quota_request {
        let peer_ip = headers.peer_ip.as_deref().unwrap_or("127.0.0.1");
        match store.reserve_signup(AuthPrincipal::EndUser, peer_ip, at) {
            Ok(reservation) => Some(reservation),
            Err(e) => return auth_error(&e),
        }
    } else {
        None
    };
    if route.class != routes::RouteClass::EndUser {
        let signer = store.signer_arc();
        let response = dispatch(
            route.handler,
            &mut store,
            query,
            body,
            headers,
            at,
            &state.into(),
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
            if let Err(response) = install_routed_candidate(state, &project, &store_arc) {
                return response;
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
        return finish_token_response(response, signer.as_deref(), &store_arc, at);
    }
    let signer = store.signer_arc();
    if !blocking_auth
        && state.blocking.as_deref().is_some_and(|blocking| {
            blocking.blocking_auth_revision() != blocking_revision
                || (handler_may_invoke_blocking_auth(blocking, route.handler)
                    && blocking_hook_applies_to_project(state, blocking, &store_project))
        })
    {
        // A hook enabled after admission must not be silently skipped. Returning a conflict
        // gives the caller a coherent retry point without dispatching while retaining a gate
        // that the hook commit path would need to reacquire.
        return error(409, "BLOCKING_FUNCTION_CONFIGURATION_CHANGED");
    }
    let response = if blocking_auth {
        let Some(blocking) = state.blocking.as_deref() else {
            return error(500, "INTERNAL");
        };
        // The first decision also determines whether this request owns the namespace gate. A
        // mutable Functions manifest may change between planning and dispatch; reject that
        // transition instead of entering the hook path while retaining a guard that the commit
        // path would acquire again (or silently using a stale allow/deny decision).
        let still_applies = handler_may_invoke_blocking_auth(blocking, route.handler)
            && blocking_hook_applies_to_project(state, blocking, &store_project);
        if !still_applies || blocking.blocking_auth_revision() != blocking_revision {
            return error(409, "BLOCKING_FUNCTION_CONFIGURATION_CHANGED");
        }
        dispatch_with_blocking_hook(
            state,
            blocking,
            blocking_revision,
            route.handler,
            &store_arc,
            store,
            &state.operation_gate,
            operation_gate.as_ref(),
            query,
            body,
            headers,
            at,
            &mut quota_reservation,
        )
    } else if let Some(reservation) = quota_reservation.clone() {
        // Run quota-accounted creation on an isolated store copy. This gives the quota
        // commit a real transaction boundary: if the effective policy or window changed
        // before commit, neither the account nor its credentials reach the live store.
        let mut candidate = store.clone();
        let response = dispatch(
            route.handler,
            &mut candidate,
            query,
            body,
            headers,
            at,
            &state.into(),
        );
        // Determine creation from the request's returned identity and the isolated store
        // transition. A global user-count delta is not a per-request result: another actor may
        // delete an unrelated account while this request is being processed.
        let created = response.status == 200
            && response
                .body
                .get("localId")
                .and_then(Value::as_str)
                .is_some_and(|uid| {
                    store.user_by_id(uid).is_none() && candidate.user_by_id(uid).is_some()
                });
        if created {
            if let Err(error) = candidate.commit_signup(reservation, now(state)) {
                let _ = store.release_signup(
                    quota_reservation
                        .take()
                        .expect("live quota reservation remains until candidate commit"),
                );
                return auth_error(&error);
            }
            quota_reservation.take();
            *store = candidate;
        } else {
            let live_reservation = quota_reservation
                .take()
                .expect("live quota reservation remains until candidate dispatch completes");
            if let Err(error) = store.release_signup(live_reservation) {
                return auth_error(&error);
            }
        }
        drop(store);
        response
    } else {
        let response = dispatch(
            route.handler,
            &mut store,
            query,
            body,
            headers,
            at,
            &state.into(),
        );
        drop(store);
        response
    };
    let response = if response.status == 200 {
        let body = without_nulls(response.body);
        JsonResponse {
            status: 200,
            body: if route.handler == routes::Handler::SignInWithCustomToken {
                public_custom_token_answer(body)
            } else {
                body
            },
        }
    } else {
        response
    };
    let mut response = finish_token_response(response, signer.as_deref(), &store_arc, at);
    if let Some(reservation) = quota_reservation.take() {
        // Blocking dispatch commits a successful new-account reservation at its typed
        // per-request creation boundary. Any reservation left here belongs to a failed or
        // non-creating request and must be released; comparing the live user count with a stale
        // preflight count would misclassify an unrelated deletion as a failed signup.
        let Ok(mut store) = store_arc.lock() else {
            return error(500, "INTERNAL");
        };
        let result = store.release_signup(reservation);
        if let Err(e) = result {
            return auth_error(&e);
        }
    }
    if let Some(authority) = idp_authority {
        let continuation_response = response.status == 200
            && response
                .body
                .get("providerId")
                .and_then(Value::as_str)
                .is_some()
            && (response
                .body
                .get("idToken")
                .and_then(Value::as_str)
                .is_some()
                || response
                    .body
                    .get("mfaPendingCredential")
                    .and_then(Value::as_str)
                    .is_some()
                || response
                    .body
                    .get("needConfirmation")
                    .and_then(Value::as_bool)
                    == Some(true)
                || matches!(
                    response.body.get("errorMessage").and_then(Value::as_str),
                    Some("EMAIL_EXISTS" | "FEDERATED_USER_ID_ALREADY_LINKED")
                ));
        if continuation_response {
            if let Ok(mut live) = store_arc.lock() {
                // A reset while a blocking hook/signing task ran must not mint a
                // continuation in the next incarnation from a pre-reset assertion.
                if live.reset_generation() == idp_generation {
                    let token = incoming_pending.or_else(|| {
                        let original = json!({
                            "requestUri": body.get("requestUri"),
                            "postBody": body.get("postBody"),
                        });
                        live.remember_idp_sign_in(original.to_string(), authority, at)
                    });
                    if let Some(token) = token {
                        response.body["pendingToken"] = json!(token);
                    }
                }
            }
        }
    }
    response
}

/// Refuses a request that carries no `Authorization` header where production's front end does:
/// every Admin route, and client routes when the profile requires an API key.
fn caller_identity_check(
    state: &AuthState,
    resolution: routes::Resolution<'_>,
    headers: &RequestHeaders,
    api_key: bool,
) -> Result<(), JsonResponse> {
    if headers.authorization.is_some() {
        return Ok(());
    }
    let class = match resolution {
        routes::Resolution::Matched { route, .. } => route.class,
        routes::Resolution::MethodNotAllowed { class, .. } => class,
        routes::Resolution::NotFound => return Ok(()),
    };
    match class {
        // Session management refuses an API key in place of a credential with its own shape
        // (sandbox recording 2026-09-24, session-cookie/sessions#client-api-key).
        routes::RouteClass::Admin
            if api_key
                && matches!(
                    resolution,
                    routes::Resolution::Matched { route, .. }
                        if route.handler == routes::Handler::AdminCreateSessionCookie
                ) =>
        {
            Err(session_management_credentials_missing())
        }
        routes::RouteClass::Admin => admin_request_guard(headers, "", api_key),
        routes::RouteClass::EndUser
            if state.client_api_key == ClientApiKeyPolicy::Required && !api_key =>
        {
            Err(unregistered_caller())
        }
        _ => Ok(()),
    }
}

/// The credential and project checks of a route class.
fn privilege_check(
    state: &AuthState,
    class: routes::RouteClass,
    project: Option<&str>,
    headers: &RequestHeaders,
    method: &str,
    api_key: bool,
    store: &AuthStore,
) -> Result<(), JsonResponse> {
    match class {
        routes::RouteClass::Jwks | routes::RouteClass::EndUser | routes::RouteClass::ActionLink => {
            Ok(())
        }
        routes::RouteClass::Emulator => {
            emulator_guard(state, headers)?;
            if project != Some(store.project_id()) {
                return Err(error(400, "INVALID_PROJECT_ID"));
            }
            Ok(())
        }
        routes::RouteClass::Admin => {
            admin_guard(headers, method, api_key, project.unwrap_or(""), store)
        }
    }
}

/// Runs the handler of a resolved route.
#[derive(Clone)]
struct DispatchOptions {
    totp_extension_enabled: bool,
    stateless_refresh_tokens: bool,
    fake_custom_token_expiry: FakeCustomTokenExpiry,
    custom_token_trust: Option<Arc<CustomTokenTrust>>,
    /// Whether sign-in without `returnSecureToken` answers with the legacy token, as
    /// production does. The emulator profile (stateless refresh tokens) keeps the official
    /// emulator's secure tokens. A request whose blocking trigger is selected keeps secure tokens
    /// too: the hook re-issues tokens through the refresh session a legacy sign-in does not open,
    /// and the legacy behaviour of blocking functions is unobserved.
    legacy_tokens: bool,
    query_limits: AuthQueryLimits,
    inbound_credential_policy: fireemu_core_functions::manifest::BlockingAuthTokenPolicy,
}

/// The options of a request whose blocking trigger is selected: it keeps secure tokens.
fn blocking_dispatch_options(state: &AuthState) -> DispatchOptions {
    DispatchOptions {
        legacy_tokens: false,
        ..state.into()
    }
}

impl From<&AuthState> for DispatchOptions {
    fn from(state: &AuthState) -> Self {
        Self {
            totp_extension_enabled: state.totp_extension_enabled,
            stateless_refresh_tokens: state.stateless_refresh_tokens,
            fake_custom_token_expiry: state.fake_custom_token_expiry,
            custom_token_trust: state.custom_token_trust.clone(),
            legacy_tokens: !state.stateless_refresh_tokens,
            query_limits: state.query_limits,
            inbound_credential_policy: state.blocking.as_deref().map_or_else(
                fireemu_core_functions::manifest::BlockingAuthTokenPolicy::default,
                |blocking| {
                    blocking
                        .inbound_credential_policy(
                            fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate,
                        )
                        .union(blocking.inbound_credential_policy(
                            fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn,
                        ))
                },
            ),
        }
    }
}

#[allow(clippy::too_many_lines)]
fn dispatch(
    handler: routes::Handler,
    store: &mut AuthStore,
    query: Option<&str>,
    body: &Value,
    headers: &RequestHeaders,
    at: LogicalInstant,
    options: &DispatchOptions,
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
        Handler::SignInWithPassword => {
            sign_in_with_password(store, body, at, options.legacy_tokens)
        }
        Handler::SignInWithCustomToken => sign_in_with_custom_token(
            store,
            body,
            at,
            options.fake_custom_token_expiry == FakeCustomTokenExpiry::Reject,
            options.custom_token_trust.as_deref(),
            options.legacy_tokens,
        ),
        Handler::Lookup => lookup(store, body, at, false),
        Handler::Update | Handler::AdminUpdate => update(
            store,
            body,
            at,
            options.stateless_refresh_tokens,
            handler == Handler::AdminUpdate,
        ),
        Handler::Delete => {
            delete_account(store, body, at, false, !options.stateless_refresh_tokens)
        }
        Handler::SendOobCode => send_oob_code(
            store,
            body,
            at,
            headers,
            false,
            !options.stateless_refresh_tokens,
        ),
        Handler::ResetPassword => reset_password(store, body, at, options.stateless_refresh_tokens),
        Handler::SignInWithEmailLink => {
            sign_in_with_email_link(store, body, at, !options.stateless_refresh_tokens)
        }
        Handler::SendVerificationCode => send_verification_code(store, body, at),
        Handler::SignInWithPhoneNumber => sign_in_with_phone_number(store, body, at),
        Handler::SignInWithIdp => {
            sign_in_with_idp(store, body, at, options.inbound_credential_policy)
        }
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
        Handler::PasswordPolicy => password_policy_json(store.password_policy()),
        // Strict: production's answer when TOTP is not enabled, and the v2 API's error shape
        // (sandbox recording 2026-09-24); the emulator keeps the official emulator's.
        Handler::MfaEnrollmentStart => v2_error_shape(
            mfa_enrollment_start(
                store,
                body,
                at,
                options.totp_extension_enabled,
                !options.stateless_refresh_tokens,
            ),
            !options.stateless_refresh_tokens,
        ),
        Handler::MfaEnrollmentFinalize => v2_error_shape(
            mfa_enrollment_finalize(store, body, at),
            !options.stateless_refresh_tokens,
        ),
        Handler::MfaEnrollmentWithdraw => v2_error_shape(
            if store.second_factor_rules_are_production() {
                mfa_enrollment_withdraw_production(store, body, at)
            } else {
                mfa_enrollment_withdraw(store, body, at)
            },
            !options.stateless_refresh_tokens,
        ),
        Handler::MfaSignInStart => v2_error_shape(
            {
                let production = store.second_factor_rules_are_production();
                mfa_sign_in_start(store, body, at, production)
            },
            !options.stateless_refresh_tokens,
        ),
        Handler::MfaSignInFinalize => v2_error_shape(
            if store.second_factor_rules_are_production() {
                mfa_sign_in_finalize_production(store, body, at)
            } else {
                mfa_sign_in_finalize(store, body, at)
            },
            !options.stateless_refresh_tokens,
        ),
        Handler::Token => {
            secure_token_error_shape(refresh(store, body, at, options.stateless_refresh_tokens))
        }
        Handler::AdminCreate => admin_create(store, body, at),
        Handler::AdminLookup => lookup(store, body, at, true),
        Handler::AdminDelete => {
            delete_account(store, body, at, true, !options.stateless_refresh_tokens)
        }
        Handler::AdminBatchGet => admin_batch_get(store, query, body),
        Handler::AdminBatchCreate => admin_batch_create(store, body, at),
        Handler::AdminBatchDelete => {
            admin_batch_delete(store, body, !options.stateless_refresh_tokens)
        }
        Handler::AdminQuery => admin_query(store, body, options.query_limits),
        // Admin link generators: the code and link come back to the caller.
        Handler::AdminSendOobCode => {
            if let Err(response) = opt_bool(body, "returnOobLink") {
                return response;
            }
            let mut with_link = body.clone();
            with_link["returnOobLink"] = json!(true);
            send_oob_code(
                store,
                &with_link,
                at,
                headers,
                true,
                !options.stateless_refresh_tokens,
            )
        }
        // Stateful refresh sessions mark the strict profile.
        Handler::AdminCreateSessionCookie => {
            create_session_cookie(store, body, at, !options.stateless_refresh_tokens)
        }
        Handler::TenantCreate
        | Handler::TenantList
        | Handler::TenantGet
        | Handler::TenantUpdate
        | Handler::TenantDelete
        | Handler::ProviderCreate
        | Handler::ProviderList
        | Handler::ProviderGet
        | Handler::ProviderUpdate
        | Handler::ProviderDelete
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
        Handler::EmulatorAction => {
            emulator_action(store, query, headers, at, options.stateless_refresh_tokens)
        }
    }
}

/// Production's answers to a refused `mfa` value (sandbox recording 2026-09-24,
/// `auth-mfa/config`): the v2 Admin API's shape, without the v1 `errors` list.
fn mfa_config_refusal(refusal: &project_mfa::MfaConfigRefusal) -> JsonResponse {
    use project_mfa::MfaConfigRefusal;
    let body = match refusal {
        MfaConfigRefusal::InvalidEnum {
            field,
            type_name,
            value,
        } => {
            let message = format!(
                "Invalid value at '{field}' (type.googleapis.com/google.cloud.identitytoolkit.admin.v2.{type_name}), \"{value}\""
            );
            json!({"error": {
                "code": 400,
                "message": message,
                "status": "INVALID_ARGUMENT",
                "details": [{
                    "@type": "type.googleapis.com/google.rpc.BadRequest",
                    "fieldViolations": [{"field": field, "description": message}],
                }],
            }})
        }
        MfaConfigRefusal::AdjacentIntervalRange => json!({"error": {
            "code": 400,
            "message": "INVALID_ADJACENT_INTERVAL_RANGE : Allowed number of adjacent intervals must be between 0 and 10, inclusive",
            "status": "INVALID_ARGUMENT",
        }}),
        MfaConfigRefusal::Shape => return error(400, "INVALID_ARGUMENT"),
    };
    JsonResponse { status: 400, body }
}

fn install_routed_candidate(
    state: &AuthState,
    project: &str,
    store: &Arc<Mutex<AuthStore>>,
) -> Result<(), JsonResponse> {
    let Some(registry) = state.registry.as_ref() else {
        return Err(error(500, "INTERNAL"));
    };
    match registry.install_routed(project, store.clone()) {
        RoutedStoreInstall::Installed(_) => Ok(()),
        RoutedStoreInstall::Existing(_) => Err(error(409, "CONCURRENT_PROJECT_OWNERSHIP")),
        RoutedStoreInstall::RegisteredConflict => Err(error(400, "INVALID_PROJECT_ID")),
        RoutedStoreInstall::Capacity => Err(error(429, "RESOURCE_EXHAUSTED")),
        RoutedStoreInstall::InvalidStore => Err(error(500, "INTERNAL")),
    }
}

fn apply_project_config_fields(
    config: &mut ProjectAuthConfigPatch,
    body: &Value,
    fields: &[String],
) -> Result<(), JsonResponse> {
    for field in fields {
        match field.as_str() {
            "signIn" => apply_project_config_parent(
                body,
                "signIn",
                "allowDuplicateEmails",
                &mut config.allow_duplicate_emails,
            )?,
            "signIn.allowDuplicateEmails" => {
                config.allow_duplicate_emails = Some(nested_bool_default_false(
                    body,
                    "signIn",
                    "allowDuplicateEmails",
                )?);
            }
            "emailPrivacyConfig" => apply_project_config_parent(
                body,
                "emailPrivacyConfig",
                "enableImprovedEmailPrivacy",
                &mut config.enable_improved_email_privacy,
            )?,
            "emailPrivacyConfig.enableImprovedEmailPrivacy" => {
                config.enable_improved_email_privacy = Some(nested_bool_default_false(
                    body,
                    "emailPrivacyConfig",
                    "enableImprovedEmailPrivacy",
                )?);
            }
            "client.permissions" => {
                apply_project_config_parent_path(
                    body,
                    &["client", "permissions"],
                    "disabledUserSignup",
                    &mut config.disabled_user_signup,
                )?;
                apply_project_config_parent_path(
                    body,
                    &["client", "permissions"],
                    "disabledUserDeletion",
                    &mut config.disabled_user_deletion,
                )?;
            }
            "client.permissions.disabledUserSignup" => {
                config.disabled_user_signup = Some(nested_bool_default_false_path(
                    body,
                    &["client", "permissions", "disabledUserSignup"],
                )?);
            }
            "client.permissions.disabledUserDeletion" => {
                config.disabled_user_deletion = Some(nested_bool_default_false_path(
                    body,
                    &["client", "permissions", "disabledUserDeletion"],
                )?);
            }
            // Decoded whole by `project_mfa`, like the sign-in providers.
            "mfa" => {}
            field
                if field == "passwordPolicyConfig"
                    || field.starts_with("passwordPolicyConfig.")
                    || SIGN_IN_PROVIDER_FIELDS.contains(&field)
                    || valid_blocking_config_field(field)
                    || valid_quota_field(field) => {}
            _ => return Err(error(400, "INVALID_ARGUMENT")),
        }
    }
    Ok(())
}

fn password_policy_from_config_json(value: &Value) -> Result<PasswordPolicy, JsonResponse> {
    let object = value
        .as_object()
        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
    if object
        .keys()
        .any(|field| !PASSWORD_POLICY_FIELDS.contains(&field.as_str()))
    {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    let state = match object.get("passwordPolicyEnforcementState") {
        None | Some(Value::Null) => EnforcementState::Off,
        Some(Value::String(value)) => match value.as_str() {
            "OFF" => EnforcementState::Off,
            "ENFORCE" => EnforcementState::Enforce,
            _ => return Err(error(400, "INVALID_ARGUMENT")),
        },
        Some(_) => return Err(error(400, "INVALID_ARGUMENT")),
    };
    let force = match object.get("forceUpgradeOnSignin") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(error(400, "INVALID_ARGUMENT")),
    };
    let options = match object.get("passwordPolicyVersions") {
        None | Some(Value::Null) => None,
        Some(Value::Array(versions)) if versions.len() == 1 => {
            let version = versions[0]
                .as_object()
                .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
            if version.keys().any(|field| field != "customStrengthOptions") {
                return Err(error(400, "INVALID_ARGUMENT"));
            }
            match version.get("customStrengthOptions") {
                Some(Value::Object(options)) => Some(options),
                Some(Value::Null) => None,
                None | Some(_) => return Err(error(400, "INVALID_ARGUMENT")),
            }
        }
        Some(_) => return Err(error(400, "INVALID_ARGUMENT")),
    };
    if options.is_some_and(|options| {
        options
            .keys()
            .any(|field| !PASSWORD_POLICY_OPTION_FIELDS.contains(&field.as_str()))
    }) {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    let number = |key: &str, default: usize| {
        options
            .and_then(|o| o.get(key))
            .filter(|value| !value.is_null())
            .map_or(Ok(default), |v| {
                v.as_u64()
                    .and_then(|n| usize::try_from(n).ok())
                    .ok_or_else(|| error(400, "INVALID_ARGUMENT"))
            })
    };
    let boolean = |key: &str| {
        options
            .and_then(|o| o.get(key))
            .filter(|value| !value.is_null())
            .map_or(Ok(false), |v| {
                v.as_bool().ok_or_else(|| error(400, "INVALID_ARGUMENT"))
            })
    };
    let max = options
        .and_then(|o| o.get("maxPasswordLength"))
        .filter(|v| !v.is_null())
        .map(|v| {
            v.as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .ok_or_else(|| error(400, "INVALID_ARGUMENT"))
        })
        .transpose()?;
    PasswordPolicy::try_new(
        state,
        force,
        number("minPasswordLength", 6)?,
        max,
        boolean("containsUppercaseCharacter")?,
        boolean("containsLowercaseCharacter")?,
        boolean("containsNumericCharacter")?,
        boolean("containsNonAlphanumericCharacter")?,
        fireemu_core_auth::password_policy::default_allowed_non_alphanumeric(),
    )
    .map_err(|_| error(400, "INVALID_ARGUMENT"))
}

fn password_policy_config_json(policy: &PasswordPolicy) -> Value {
    let mut options = serde_json::Map::from_iter([
        ("minPasswordLength".to_owned(), json!(policy.min_length)),
        (
            "containsUppercaseCharacter".to_owned(),
            json!(policy.require_uppercase),
        ),
        (
            "containsLowercaseCharacter".to_owned(),
            json!(policy.require_lowercase),
        ),
        (
            "containsNumericCharacter".to_owned(),
            json!(policy.require_numeric),
        ),
        (
            "containsNonAlphanumericCharacter".to_owned(),
            json!(policy.require_non_alphanumeric),
        ),
    ]);
    if let Some(max) = policy.max_length {
        options.insert("maxPasswordLength".to_owned(), json!(max));
    }
    json!({
        "passwordPolicyEnforcementState": match policy.enforcement_state {
            EnforcementState::Off => "OFF",
            EnforcementState::Enforce => "ENFORCE",
        },
        "forceUpgradeOnSignin": policy.force_upgrade_on_signin,
        "passwordPolicyVersions": [{"customStrengthOptions": options}],
    })
}

fn password_policy_from_update(
    current: &PasswordPolicy,
    body: &Value,
    fields: &[String],
) -> Result<Option<PasswordPolicy>, JsonResponse> {
    let policy_fields: Vec<&str> = fields
        .iter()
        .map(String::as_str)
        .filter(|field| {
            *field == "passwordPolicyConfig" || field.starts_with("passwordPolicyConfig.")
        })
        .collect();
    if policy_fields.is_empty() {
        return Ok(None);
    }
    let Some(value) = body.get("passwordPolicyConfig") else {
        return Err(error(400, "INVALID_ARGUMENT"));
    };
    if value.is_null() && policy_fields.contains(&"passwordPolicyConfig") {
        if policy_fields.len() != 1 {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
        return Ok(Some(PasswordPolicy::default()));
    }
    let object = match value {
        Value::Null => serde_json::Map::new(),
        Value::Object(object) => object.clone(),
        _ => return Err(error(400, "INVALID_ARGUMENT")),
    };
    // Validate the complete supplied policy before applying the mask. A malformed policy
    // payload must never become a partial successful update merely because its malformed
    // member was outside the selected mask.
    if !value.is_null() {
        let _supplied_policy = password_policy_from_config_json(value)?;
    }
    if policy_fields.contains(&"passwordPolicyConfig") {
        if policy_fields.len() != 1 {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
        return password_policy_from_config_json(value).map(Some);
    }

    let mut merged = password_policy_config_json(current);
    let merged_object = merged
        .as_object_mut()
        .expect("password policy projection is an object");
    for field in policy_fields {
        let child = field
            .strip_prefix("passwordPolicyConfig.")
            .expect("nested password policy field");
        match child {
            "passwordPolicyEnforcementState"
            | "forceUpgradeOnSignin"
            | "passwordPolicyVersions" => {
                if let Some(value) = object.get(child).filter(|value| !value.is_null()) {
                    merged_object.insert(child.to_owned(), value.clone());
                } else {
                    let defaults = password_policy_config_json(&PasswordPolicy::default());
                    if let Some(value) = defaults.get(child) {
                        merged_object.insert(child.to_owned(), value.clone());
                    }
                }
            }
            _ => return Err(error(400, "INVALID_ARGUMENT")),
        }
    }
    password_policy_from_config_json(&merged).map(Some)
}

fn valid_password_policy_field(field: &str) -> bool {
    matches!(
        field,
        "passwordPolicyConfig"
            | "passwordPolicyConfig.passwordPolicyEnforcementState"
            | "passwordPolicyConfig.forceUpgradeOnSignin"
            | "passwordPolicyConfig.passwordPolicyVersions"
    )
}

fn apply_project_config_parent(
    body: &Value,
    parent: &str,
    child: &str,
    current: &mut Option<bool>,
) -> Result<(), JsonResponse> {
    let Some(value) = body.get(parent) else {
        return Ok(());
    };
    if value.is_null() {
        *current = Some(false);
        return Ok(());
    }
    let Some(object) = value.as_object() else {
        return Err(error(400, "INVALID_ARGUMENT"));
    };
    if let Some(value) = object.get(child) {
        *current = Some(match value {
            Value::Bool(value) => *value,
            Value::Null => false,
            _ => return Err(error(400, "INVALID_ARGUMENT")),
        });
    }
    Ok(())
}

fn nested_bool_default_false(
    body: &Value,
    parent: &str,
    child: &str,
) -> Result<bool, JsonResponse> {
    let Some(value) = body.get(parent) else {
        return Ok(false);
    };
    if value.is_null() {
        return Ok(false);
    }
    let Some(object) = value.as_object() else {
        return Err(error(400, "INVALID_ARGUMENT"));
    };
    match object.get(child) {
        Some(Value::Bool(value)) => Ok(*value),
        None | Some(Value::Null) => Ok(false),
        Some(_) => Err(error(400, "INVALID_ARGUMENT")),
    }
}

fn apply_project_config_parent_path(
    body: &Value,
    parent_path: &[&str],
    child: &str,
    current: &mut Option<bool>,
) -> Result<(), JsonResponse> {
    let mut path = parent_path.to_vec();
    path.push(child);
    *current = Some(nested_bool_default_false_path(body, &path)?);
    Ok(())
}

fn valid_project_config_field(field: &str) -> bool {
    matches!(
        field,
        "mfa"
            | "signIn"
            | "signIn.allowDuplicateEmails"
            | "emailPrivacyConfig"
            | "emailPrivacyConfig.enableImprovedEmailPrivacy"
            | "client.permissions"
            | "client.permissions.disabledUserSignup"
            | "client.permissions.disabledUserDeletion"
            | "passwordPolicyConfig"
            | "passwordPolicyConfig.passwordPolicyEnforcementState"
            | "passwordPolicyConfig.forceUpgradeOnSignin"
            | "passwordPolicyConfig.passwordPolicyVersions"
            | "quota"
            | "quota.signUpQuotaConfig"
            | "quota.quotaSimulation"
            | "quota.quotaSimulation.mode"
            | "quota.quotaSimulation.algorithm"
            | "quota.quotaSimulation.defaultQuotaPerHour"
            | "quota.quotaSimulation.maxTrackedBuckets"
            | "blockingFunctions"
            | "blockingFunctions.triggers"
            | "blockingFunctions.triggers.beforeCreate"
            | "blockingFunctions.triggers.beforeSignIn"
            | "blockingFunctions.forwardInboundCredentials"
            | "blockingFunctions.forwardInboundCredentials.idToken"
            | "blockingFunctions.forwardInboundCredentials.accessToken"
            | "blockingFunctions.forwardInboundCredentials.refreshToken"
    ) || SIGN_IN_PROVIDER_FIELDS.contains(&field)
}

/// Project config fields of the sign-in providers and test phone numbers.
const SIGN_IN_PROVIDER_FIELDS: &[&str] = &[
    "signIn.email",
    "signIn.email.enabled",
    "signIn.email.passwordRequired",
    "signIn.anonymous",
    "signIn.anonymous.enabled",
    "signIn.phoneNumber",
    "signIn.phoneNumber.enabled",
    "signIn.phoneNumber.testPhoneNumbers",
    "authorizedDomains",
];

/// The sign-in configuration a masked Admin config PATCH produces from `current`, or `None`
/// when the mask names no sign-in provider field. A whole-object mask (`signIn.email`)
/// replaces the object, so an omitted switch is off; the parent `signIn` mask replaces only
/// the provider objects the body carries.
fn sign_in_config_from_update(
    current: &SignInConfig,
    body: &Value,
    fields: &[String],
) -> Result<Option<SignInConfig>, JsonResponse> {
    let invalid = || error(400, "INVALID_ARGUMENT");
    let provider = |name: &str| {
        body.get("signIn")
            .and_then(|sign_in| sign_in.get(name))
            .filter(|value| !value.is_null())
    };
    let switch = |name: &str, key: &str| match provider(name).and_then(|p| p.get(key)) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(invalid()),
    };
    let numbers = || -> Result<BTreeMap<String, String>, JsonResponse> {
        match provider("phoneNumber").and_then(|p| p.get("testPhoneNumbers")) {
            None | Some(Value::Null) => Ok(BTreeMap::new()),
            Some(Value::Object(entries)) => entries
                .iter()
                .map(|(number, code)| {
                    code.as_str()
                        .map(|code| (number.clone(), code.to_owned()))
                        .ok_or_else(invalid)
                })
                .collect(),
            Some(_) => Err(invalid()),
        }
    };
    // A masked replacement: an absent or null list clears it, anything but non-empty host
    // strings is refused.
    let domains = || -> Result<Vec<String>, JsonResponse> {
        match body.get("authorizedDomains") {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(entries)) => entries
                .iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .filter(|domain| !domain.is_empty())
                        .map(str::to_owned)
                        .ok_or_else(invalid)
                })
                .collect(),
            Some(_) => Err(invalid()),
        }
    };
    let mut next = current.clone();
    let mut changed = false;
    for field in fields {
        let whole = |name: &str| field == "signIn" && provider(name).is_some();
        if field == "signIn.email" || whole("email") {
            next.email_enabled = switch("email", "enabled")?;
            next.password_required = switch("email", "passwordRequired")?;
            changed = true;
        }
        if field == "signIn.anonymous" || whole("anonymous") {
            next.anonymous_enabled = switch("anonymous", "enabled")?;
            changed = true;
        }
        if field == "signIn.phoneNumber" || whole("phoneNumber") {
            next.phone_enabled = switch("phoneNumber", "enabled")?;
            next.test_phone_numbers = numbers()?;
            changed = true;
        }
        match field.as_str() {
            "signIn.email.enabled" => next.email_enabled = switch("email", "enabled")?,
            "signIn.email.passwordRequired" => {
                next.password_required = switch("email", "passwordRequired")?;
            }
            "signIn.anonymous.enabled" => next.anonymous_enabled = switch("anonymous", "enabled")?,
            "signIn.phoneNumber.enabled" => next.phone_enabled = switch("phoneNumber", "enabled")?,
            "signIn.phoneNumber.testPhoneNumbers" => next.test_phone_numbers = numbers()?,
            "authorizedDomains" => next.authorized_domains = Some(domains()?),
            _ => continue,
        }
        changed = true;
    }
    if !changed {
        return Ok(None);
    }
    if !next.is_valid() {
        return Err(invalid());
    }
    Ok(Some(next))
}

/// Adds the sign-in providers to a project config body in production's shape: an enabled
/// provider reports `enabled`, a disabled one is omitted, and test numbers are listed.
fn add_sign_in_config_json(body: &mut Value, config: &SignInConfig) {
    let sign_in = &mut body["signIn"];
    if config.email_enabled {
        sign_in["email"] = json!({"enabled": true});
        if config.password_required {
            sign_in["email"]["passwordRequired"] = json!(true);
        }
    }
    if config.anonymous_enabled {
        sign_in["anonymous"] = json!({"enabled": true});
    }
    if config.phone_enabled || !config.test_phone_numbers.is_empty() {
        let mut phone = serde_json::Map::new();
        if config.phone_enabled {
            phone.insert("enabled".to_owned(), json!(true));
        }
        if !config.test_phone_numbers.is_empty() {
            phone.insert(
                "testPhoneNumbers".to_owned(),
                json!(config.test_phone_numbers),
            );
        }
        sign_in["phoneNumber"] = Value::Object(phone);
    }
}

/// Project sign-in providers gate their client flows as a tenant's switches do.
fn project_provider_denial(
    handler: routes::Handler,
    config: &SignInConfig,
    body: &Value,
) -> Option<JsonResponse> {
    if !config.phone_enabled
        && matches!(
            handler,
            routes::Handler::SendVerificationCode | routes::Handler::SignInWithPhoneNumber
        )
    {
        return Some(error(400, "OPERATION_NOT_ALLOWED"));
    }
    let metadata = fireemu_core_auth::store::TenantMetadata {
        allow_password_signup: config.email_enabled,
        enable_email_link_signin: config.email_enabled && !config.password_required,
        enable_anonymous_user: config.anonymous_enabled,
        ..fireemu_core_auth::store::TenantMetadata::default()
    };
    tenant_policy_denial_with_metadata(handler, Some(&metadata), body)
}

fn valid_blocking_config_field(field: &str) -> bool {
    matches!(
        field,
        "blockingFunctions"
            | "blockingFunctions.triggers"
            | "blockingFunctions.triggers.beforeCreate"
            | "blockingFunctions.triggers.beforeSignIn"
            | "blockingFunctions.forwardInboundCredentials"
            | "blockingFunctions.forwardInboundCredentials.idToken"
            | "blockingFunctions.forwardInboundCredentials.accessToken"
            | "blockingFunctions.forwardInboundCredentials.refreshToken"
    )
}

/// Decodes the complete blocking-functions message using `ProtoJSON` message-null semantics.
///
/// A null nested message is equivalent to an omitted nested message. Keep this normalization at
/// the HTTP boundary so the blocking bridge receives the same object it would receive when the
/// nested fields were omitted, while malformed non-null siblings still reach the normal full
/// candidate validation path.
fn normalize_complete_blocking_functions(value: Value) -> Value {
    let Value::Object(mut object) = value else {
        return value;
    };
    for key in ["triggers", "forwardInboundCredentials"] {
        if object.get(key).is_some_and(Value::is_null) {
            object.remove(key);
        }
    }
    Value::Object(object)
}

fn project_blocking_settings_update(
    state: &AuthState,
    project: &str,
    body: &Value,
    fields: &[String],
) -> Result<Option<Value>, JsonResponse> {
    let blocking_fields: Vec<&str> = fields
        .iter()
        .map(String::as_str)
        .filter(|field| valid_blocking_config_field(field))
        .collect();
    if blocking_fields.is_empty() {
        return Ok(None);
    }
    let Some(blocking) = state
        .blocking
        .as_ref()
        .filter(|hook| hook.blocking_auth_project() == Some(project))
    else {
        return Err(error(400, "FAILED_PRECONDITION"));
    };
    let mut candidate = blocking
        .blocking_auth_settings()
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    for field in blocking_fields {
        let input = body
            .get("blockingFunctions")
            .filter(|value| !value.is_null());
        let value = match field {
            "blockingFunctions" => {
                normalize_complete_blocking_functions(input.cloned().unwrap_or_else(|| json!({})))
            }
            "blockingFunctions.triggers" => input
                .and_then(|value| value.get("triggers"))
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or_else(|| json!({})),
            "blockingFunctions.triggers.beforeCreate"
            | "blockingFunctions.triggers.beforeSignIn" => {
                let event = field
                    .strip_prefix("blockingFunctions.triggers.")
                    .expect("validated blocking trigger field");
                input
                    .and_then(|value| value.get("triggers"))
                    .and_then(|value| value.get(event))
                    .cloned()
                    .unwrap_or(Value::Null)
            }
            "blockingFunctions.forwardInboundCredentials" => input
                .and_then(|value| value.get("forwardInboundCredentials"))
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or_else(|| json!({})),
            "blockingFunctions.forwardInboundCredentials.idToken"
            | "blockingFunctions.forwardInboundCredentials.accessToken"
            | "blockingFunctions.forwardInboundCredentials.refreshToken" => {
                let key = field
                    .strip_prefix("blockingFunctions.forwardInboundCredentials.")
                    .expect("validated blocking forwarding field");
                input
                    .and_then(|value| value.get("forwardInboundCredentials"))
                    .and_then(|value| value.get(key))
                    .filter(|value| !value.is_null())
                    .cloned()
                    .unwrap_or(Value::Bool(false))
            }
            _ => return Err(error(400, "INVALID_ARGUMENT")),
        };
        if field == "blockingFunctions" {
            candidate = value;
            continue;
        }
        let root = candidate
            .as_object_mut()
            .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
        let (group, key) = if let Some(key) = field.strip_prefix("blockingFunctions.triggers.") {
            ("triggers", key)
        } else if let Some(key) = field.strip_prefix("blockingFunctions.forwardInboundCredentials.")
        {
            ("forwardInboundCredentials", key)
        } else if field == "blockingFunctions.triggers" {
            root.insert("triggers".to_owned(), value);
            continue;
        } else if field == "blockingFunctions.forwardInboundCredentials" {
            root.insert("forwardInboundCredentials".to_owned(), value);
            continue;
        } else {
            return Err(error(400, "INVALID_ARGUMENT"));
        };
        let group_value = root
            .entry(group.to_owned())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        let group_object = group_value
            .as_object_mut()
            .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
        group_object.insert(key.to_owned(), value);
    }
    blocking
        .validate_blocking_auth_settings(&candidate)
        .map_err(|_| error(400, "INVALID_ARGUMENT"))?;
    Ok(Some(candidate))
}

fn valid_quota_field(field: &str) -> bool {
    field == "quota"
        || field == "quota.signUpQuotaConfig"
        || field == "quota.quotaSimulation"
        || matches!(
            field,
            "quota.quotaSimulation.mode"
                | "quota.quotaSimulation.algorithm"
                | "quota.quotaSimulation.defaultQuotaPerHour"
                | "quota.quotaSimulation.maxTrackedBuckets"
        )
}

fn quota_duration_from_json(value: &Value) -> Result<LogicalDuration, JsonResponse> {
    let text = value
        .as_str()
        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
    let body = text
        .strip_suffix('s')
        .filter(|body| !body.is_empty() && !body.starts_with(['+', '-']))
        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
    let (seconds, fraction) = body
        .split_once('.')
        .map_or((body, None), |(seconds, fraction)| {
            (seconds, Some(fraction))
        });
    if !seconds.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    let seconds = seconds
        .parse::<i128>()
        .map_err(|_| error(400, "INVALID_ARGUMENT"))?;
    let fraction_nanos = match fraction {
        None => 0,
        Some(fraction)
            if !fraction.is_empty()
                && fraction.len() <= 9
                && fraction.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            fraction
                .parse::<i128>()
                .map_err(|_| error(400, "INVALID_ARGUMENT"))?
                .checked_mul(10_i128.pow(u32::try_from(9 - fraction.len()).unwrap_or(0)))
                .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?
        }
        Some(_) => return Err(error(400, "INVALID_ARGUMENT")),
    };
    let nanos = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(fraction_nanos))
        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
    Ok(LogicalDuration::from_nanos(nanos))
}

fn quota_mode_from_json(value: &Value) -> Result<QuotaMode, JsonResponse> {
    match value
        .as_str()
        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?
    {
        "off" => Ok(QuotaMode::Off),
        "observe" => Ok(QuotaMode::Observe),
        "enforce" => Ok(QuotaMode::Enforce),
        _ => Err(error(400, "INVALID_ARGUMENT")),
    }
}

fn quota_config_from_json(
    value: &Value,
    current: &SignupQuotaConfig,
) -> Result<SignupQuotaConfig, JsonResponse> {
    let object = value
        .as_object()
        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
    if object
        .keys()
        .any(|field| field != "signUpQuotaConfig" && field != "quotaSimulation")
    {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    let mut next = current.clone();
    if let Some(value) = object.get("signUpQuotaConfig") {
        next.temporary = if value.is_null() {
            None
        } else {
            let quota_object = value
                .as_object()
                .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
            if quota_object
                .keys()
                .any(|field| !SIGNUP_QUOTA_FIELDS.contains(&field.as_str()))
            {
                return Err(error(400, "INVALID_ARGUMENT"));
            }
            let quota_number = quota_object
                .get("quota")
                .and_then(Value::as_str)
                .filter(|value| {
                    !value.is_empty()
                        && value.bytes().all(|byte| byte.is_ascii_digit())
                        && value
                            .parse::<u64>()
                            .is_ok_and(|value| i64::try_from(value).is_ok())
                })
                .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?
                .parse::<u64>()
                .map_err(|_| error(400, "INVALID_ARGUMENT"))?;
            let start_time = LogicalInstant::parse_rfc3339(
                quota_object
                    .get("startTime")
                    .and_then(Value::as_str)
                    .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?,
            )
            .map_err(|_| error(400, "INVALID_ARGUMENT"))?;
            let duration = quota_duration_from_json(
                quota_object
                    .get("quotaDuration")
                    .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?,
            )?;
            Some(
                TemporaryQuota::new(quota_number, start_time, duration)
                    .map_err(|_| error(400, "INVALID_ARGUMENT"))?,
            )
        };
    }
    if let Some(value) = object
        .get("quotaSimulation")
        .filter(|value| !value.is_null())
    {
        let simulation = value
            .as_object()
            .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
        if simulation
            .keys()
            .any(|field| !QUOTA_SIMULATION_FIELDS.contains(&field.as_str()))
        {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
        if let Some(value) = simulation.get("mode").filter(|value| !value.is_null()) {
            next.mode = quota_mode_from_json(value)?;
        }
        if let Some(value) = simulation.get("algorithm").filter(|value| !value.is_null()) {
            if value.as_str() != Some("fixed-window-v1") {
                return Err(error(400, "INVALID_ARGUMENT"));
            }
            next.algorithm = QuotaAlgorithm::FixedWindowV1;
        }
        if let Some(value) = simulation
            .get("defaultQuotaPerHour")
            .filter(|value| !value.is_null())
        {
            next.default_quota_per_hour = value
                .as_u64()
                .filter(|value| *value <= 1_000_000)
                .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
        }
        if let Some(value) = simulation
            .get("maxTrackedBuckets")
            .filter(|value| !value.is_null())
        {
            next.max_tracked_buckets = value
                .as_u64()
                .filter(|value| (1..=65_536).contains(value))
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
        }
    }
    next.validate()
        .map_err(|_| error(400, "INVALID_ARGUMENT"))?;
    Ok(next)
}

#[allow(clippy::too_many_lines)]
fn quota_config_from_update(
    current: &SignupQuotaConfig,
    body: &Value,
    fields: &[String],
) -> Result<Option<SignupQuotaConfig>, JsonResponse> {
    let quota_fields = fields
        .iter()
        .filter(|field| valid_quota_field(field))
        .map(String::as_str)
        .collect::<Vec<_>>();
    if quota_fields.is_empty() {
        return Ok(None);
    }
    if quota_fields.contains(&"quota") && quota_fields.len() != 1 {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    let Some(quota_value) = body.get("quota") else {
        return Err(error(400, "INVALID_ARGUMENT"));
    };
    if quota_value.is_null() {
        if quota_fields.contains(&"quota") {
            return Ok(Some(SignupQuotaConfig::default()));
        }
        let mut selected = serde_json::Map::new();
        if quota_fields.contains(&"quota.signUpQuotaConfig") {
            selected.insert("signUpQuotaConfig".to_owned(), Value::Null);
        }
        if quota_fields.contains(&"quota.quotaSimulation") {
            selected.insert(
                "quotaSimulation".to_owned(),
                quota_config_json(&SignupQuotaConfig::default())["quotaSimulation"].clone(),
            );
        } else if quota_fields
            .iter()
            .any(|field| field.starts_with("quota.quotaSimulation."))
        {
            let defaults = quota_config_json(&SignupQuotaConfig::default());
            let mut simulation = serde_json::Map::new();
            for field in quota_fields
                .iter()
                .filter_map(|field| field.strip_prefix("quota.quotaSimulation."))
            {
                if let Some(value) = defaults["quotaSimulation"].get(field) {
                    simulation.insert(field.to_owned(), value.clone());
                }
            }
            selected.insert("quotaSimulation".to_owned(), Value::Object(simulation));
        }
        return quota_config_from_json(&Value::Object(selected), current).map(Some);
    }
    let quota = quota_value
        .as_object()
        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
    // Validate every supplied quota member before applying the mask. A malformed value outside
    // the selected mask must not be smuggled through as a successful partial update.
    quota_config_from_json(&Value::Object(quota.clone()), current)?;
    let mut selected = serde_json::Map::new();
    if quota_fields
        .iter()
        .any(|field| *field == "quota" || *field == "quota.signUpQuotaConfig")
    {
        if let Some(value) = quota.get("signUpQuotaConfig") {
            selected.insert("signUpQuotaConfig".to_owned(), value.clone());
        }
    }
    if quota_fields
        .iter()
        .any(|field| *field == "quota" || *field == "quota.quotaSimulation")
    {
        if let Some(value) = quota.get("quotaSimulation") {
            if value.is_null() {
                selected.insert(
                    "quotaSimulation".to_owned(),
                    quota_config_json(&SignupQuotaConfig::default())["quotaSimulation"].clone(),
                );
            } else {
                selected.insert("quotaSimulation".to_owned(), value.clone());
            }
        }
    }
    if quota_fields
        .iter()
        .any(|field| field.starts_with("quota.quotaSimulation."))
    {
        let mut simulation = serde_json::Map::new();
        let value = quota.get("quotaSimulation");
        let defaults = quota_config_json(&SignupQuotaConfig::default());
        let value = value.and_then(Value::as_object);
        for field in quota_fields
            .iter()
            .filter_map(|field| field.strip_prefix("quota.quotaSimulation."))
        {
            if let Some(value) = value.and_then(|value| value.get(field)) {
                if value.is_null() {
                    if let Some(default) = defaults["quotaSimulation"].get(field) {
                        simulation.insert(field.to_owned(), default.clone());
                    }
                } else {
                    simulation.insert(field.to_owned(), value.clone());
                }
            } else if let Some(default) = defaults["quotaSimulation"].get(field) {
                simulation.insert(field.to_owned(), default.clone());
            }
        }
        selected.insert("quotaSimulation".to_owned(), Value::Object(simulation));
    }
    quota_config_from_json(&Value::Object(selected), current).map(Some)
}

fn quota_config_json(quota: &SignupQuotaConfig) -> Value {
    let mode = match quota.mode {
        QuotaMode::Off => "off",
        QuotaMode::Observe => "observe",
        QuotaMode::Enforce => "enforce",
    };
    let mut quota_object = serde_json::Map::new();
    if let Some(temporary) = quota.temporary {
        let nanos = temporary.duration.as_nanos();
        let seconds = nanos.div_euclid(1_000_000_000);
        let fraction = nanos.rem_euclid(1_000_000_000);
        let duration = if fraction == 0 {
            format!("{seconds}s")
        } else {
            format!("{seconds}.{fraction:09}s")
                .trim_end_matches('0')
                .to_owned()
        };
        quota_object.insert(
            "signUpQuotaConfig".to_owned(),
            json!({
                "quota": temporary.quota.to_string(),
                "startTime": temporary.start_time.to_rfc3339().unwrap_or_default(),
                "quotaDuration": duration,
            }),
        );
    }
    quota_object.insert(
        "quotaSimulation".to_owned(),
        json!({
            "mode": mode,
            "algorithm": "fixed-window-v1",
            "defaultQuotaPerHour": quota.default_quota_per_hour,
            "maxTrackedBuckets": quota.max_tracked_buckets,
        }),
    );
    Value::Object(quota_object)
}

#[allow(clippy::too_many_lines)]
fn validate_project_config_payload(body: &Value) -> Result<(), JsonResponse> {
    let object = body
        .as_object()
        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "signIn"
                | "emailPrivacyConfig"
                | "client"
                | "passwordPolicyConfig"
                | "quota"
                | "blockingFunctions"
                | "authorizedDomains"
                | "mfa"
        ) {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
    }
    if let Some(value) = object.get("signIn").filter(|value| !value.is_null()) {
        let sign_in = value
            .as_object()
            .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
        if sign_in.keys().any(|key| {
            !matches!(
                key.as_str(),
                "allowDuplicateEmails" | "email" | "anonymous" | "phoneNumber"
            )
        }) {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
        for (provider, allowed) in [
            ("email", &["enabled", "passwordRequired"][..]),
            ("anonymous", &["enabled"][..]),
            ("phoneNumber", &["enabled", "testPhoneNumbers"][..]),
        ] {
            match sign_in.get(provider) {
                None | Some(Value::Null) => {}
                Some(Value::Object(fields)) => {
                    if fields.keys().any(|key| !allowed.contains(&key.as_str())) {
                        return Err(error(400, "INVALID_ARGUMENT"));
                    }
                }
                Some(_) => return Err(error(400, "INVALID_ARGUMENT")),
            }
        }
        if sign_in
            .get("allowDuplicateEmails")
            .is_some_and(|value| !value.is_boolean() && !value.is_null())
        {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
    }
    if let Some(value) = object
        .get("emailPrivacyConfig")
        .filter(|value| !value.is_null())
    {
        let privacy = value
            .as_object()
            .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
        if privacy
            .keys()
            .any(|key| key != "enableImprovedEmailPrivacy")
        {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
        if privacy
            .get("enableImprovedEmailPrivacy")
            .is_some_and(|value| !value.is_boolean() && !value.is_null())
        {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
    }
    if let Some(value) = object.get("client").filter(|value| !value.is_null()) {
        let client = value
            .as_object()
            .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
        if client.keys().any(|key| key != "permissions") {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
        if let Some(permissions) = client.get("permissions").filter(|value| !value.is_null()) {
            let permissions = permissions
                .as_object()
                .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
            if permissions
                .keys()
                .any(|key| key != "disabledUserSignup" && key != "disabledUserDeletion")
            {
                return Err(error(400, "INVALID_ARGUMENT"));
            }
            for key in ["disabledUserSignup", "disabledUserDeletion"] {
                if permissions
                    .get(key)
                    .is_some_and(|value| !value.is_boolean() && !value.is_null())
                {
                    return Err(error(400, "INVALID_ARGUMENT"));
                }
            }
        }
    }
    if let Some(value) = object.get("passwordPolicyConfig") {
        if !value.is_null() {
            password_policy_from_config_json(value)?;
        }
    }
    if let Some(value) = object.get("quota").filter(|value| !value.is_null()) {
        let quota = value
            .as_object()
            .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
        if quota
            .keys()
            .any(|key| !QUOTA_FIELDS.contains(&key.as_str()))
        {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
        if let Some(value) = quota.get("signUpQuotaConfig") {
            if !value.is_null() {
                let config = value
                    .as_object()
                    .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
                if config
                    .keys()
                    .any(|key| !SIGNUP_QUOTA_FIELDS.contains(&key.as_str()))
                {
                    return Err(error(400, "INVALID_ARGUMENT"));
                }
            }
        }
        if let Some(value) = quota
            .get("quotaSimulation")
            .filter(|value| !value.is_null())
        {
            let simulation = value
                .as_object()
                .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
            if simulation
                .keys()
                .any(|key| !QUOTA_SIMULATION_FIELDS.contains(&key.as_str()))
            {
                return Err(error(400, "INVALID_ARGUMENT"));
            }
        }
        // Validate the complete supplied quota before applying updateMask. This catches a
        // malformed unselected member without changing the current namespace.
        quota_config_from_json(value, &SignupQuotaConfig::default())?;
    }
    if let Some(value) = object
        .get("blockingFunctions")
        .filter(|value| !value.is_null())
    {
        let blocking = value
            .as_object()
            .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
        if blocking
            .keys()
            .any(|key| key != "triggers" && key != "forwardInboundCredentials")
        {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
        if let Some(triggers) = blocking.get("triggers").filter(|value| !value.is_null()) {
            let triggers = triggers
                .as_object()
                .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
            if triggers
                .keys()
                .any(|key| key != "beforeCreate" && key != "beforeSignIn")
            {
                return Err(error(400, "INVALID_ARGUMENT"));
            }
            for key in ["beforeCreate", "beforeSignIn"] {
                let Some(value) = triggers.get(key) else {
                    continue;
                };
                if value.is_null() {
                    continue;
                }
                let trigger = value
                    .as_object()
                    .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
                if trigger.keys().any(|field| field != "functionUri")
                    || trigger
                        .get("functionUri")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty)
                {
                    return Err(error(400, "INVALID_ARGUMENT"));
                }
            }
        }
        if let Some(forwarding) = blocking
            .get("forwardInboundCredentials")
            .filter(|value| !value.is_null())
        {
            let forwarding = forwarding
                .as_object()
                .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
            if forwarding
                .keys()
                .any(|key| key != "idToken" && key != "accessToken" && key != "refreshToken")
                || forwarding
                    .values()
                    .any(|value| !value.is_boolean() && !value.is_null())
            {
                return Err(error(400, "INVALID_ARGUMENT"));
            }
        }
    }
    Ok(())
}

fn contains_non_null_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(values) => values.iter().any(contains_non_null_value),
        Value::Object(values) => values.values().any(contains_non_null_value),
        _ => true,
    }
}

#[allow(clippy::too_many_lines)]
fn project_config_management(
    state: &AuthState,
    handler: routes::Handler,
    project: Option<&str>,
    selected_store: &Arc<Mutex<AuthStore>>,
    pending_project: Option<&str>,
    query: Option<&str>,
    body: &Value,
) -> JsonResponse {
    use routes::Handler;
    let Some(project) = project else {
        return error(400, "INVALID_PROJECT_ID");
    };
    if handler == Handler::AdminGetProjectConfig {
        let Ok(store) = selected_store.lock() else {
            return error(500, "INTERNAL");
        };
        let mut body = project_config_json_with_auth_settings(
            store.config(),
            store.password_policy(),
            store.signup_quota().config(),
        );
        add_sign_in_config_json(&mut body, store.sign_in_config());
        body["mfa"] = project_mfa::mfa_config_json(store.mfa_config());
        body["authorizedDomains"] = json!(store.authorized_domains());
        if let Some(blocking) = state
            .blocking
            .as_ref()
            .filter(|hook| hook.blocking_auth_project() == Some(project))
            .and_then(|hook| hook.blocking_auth_settings())
        {
            body["blockingFunctions"] = blocking;
        }
        return JsonResponse { status: 200, body };
    }
    if !body.is_object() {
        return error(400, "INVALID_ARGUMENT");
    }
    if let Err(response) = validate_project_config_payload(body) {
        return response;
    }
    let fields = match update_mask(query) {
        Ok(Some(fields)) => fields,
        Ok(None) => {
            let mut fields = Vec::new();
            if body.get("signIn").is_some_and(contains_non_null_value) {
                fields.push("signIn".to_owned());
            }
            if body
                .get("emailPrivacyConfig")
                .is_some_and(contains_non_null_value)
            {
                fields.push("emailPrivacyConfig".to_owned());
            }
            if body
                .get("client")
                .and_then(|value| value.get("permissions"))
                .is_some_and(contains_non_null_value)
            {
                fields.push("client.permissions".to_owned());
            }
            if body
                .get("passwordPolicyConfig")
                .is_some_and(contains_non_null_value)
            {
                fields.push("passwordPolicyConfig".to_owned());
            }
            if let Some(quota) = body
                .get("quota")
                .filter(|value| !value.is_null())
                .and_then(Value::as_object)
            {
                for field in quota.keys() {
                    if quota.get(field).is_some_and(contains_non_null_value) {
                        fields.push(format!("quota.{field}"));
                    }
                }
            }
            if body
                .get("blockingFunctions")
                .is_some_and(contains_non_null_value)
            {
                fields.push("blockingFunctions".to_owned());
            }
            if body
                .get("authorizedDomains")
                .is_some_and(|value| !value.is_null())
            {
                fields.push("authorizedDomains".to_owned());
            }
            if body.get("mfa").is_some_and(|value| !value.is_null()) {
                fields.push("mfa".to_owned());
            }
            fields
        }
        Err(response) => return response,
    };
    if fields.iter().any(|field| {
        (field.starts_with("passwordPolicyConfig") && !valid_password_policy_field(field))
            || (!valid_project_config_field(field) && !valid_blocking_config_field(field))
    }) {
        return error(400, "INVALID_ARGUMENT");
    }
    let blocking_settings = match project_blocking_settings_update(state, project, body, &fields) {
        Ok(settings) => settings,
        Err(response) => return response,
    };
    let mut patch = ProjectAuthConfigPatch::default();
    if let Err(response) = apply_project_config_fields(&mut patch, body, &fields) {
        return response;
    }
    // The masked `mfa` member replaces the project's whole multi-factor configuration.
    let mfa_update = if fields.iter().any(|field| field == "mfa") {
        match project_mfa::mfa_config_from_json(body.get("mfa").unwrap_or(&Value::Null)) {
            Ok(config) => Some(config),
            Err(refusal) => return mfa_config_refusal(&refusal),
        }
    } else {
        None
    };
    // Decode the sign-in providers before anything changes; they are applied after the rest.
    let updates_sign_in = match sign_in_config_from_update(&SignInConfig::default(), body, &fields)
    {
        Ok(update) => update.is_some(),
        Err(response) => return response,
    };
    // Keep a rollback snapshot while the paired Auth candidate is published. Runtime-backed
    // bridges include private discovery markers in this snapshot so a failed Auth update cannot
    // turn an omitted Discovery trigger into Disabled.
    let blocking_transaction = if let Some(settings) = blocking_settings.as_ref() {
        let Some(blocking) = state
            .blocking
            .as_ref()
            .filter(|hook| hook.blocking_auth_project() == Some(project))
        else {
            return error(400, "FAILED_PRECONDITION");
        };
        let Ok(Some(snapshot)) = blocking.blocking_auth_settings_snapshot() else {
            return error(400, "FAILED_PRECONDITION");
        };
        if blocking
            .update_blocking_auth_settings_masked(settings, &fields)
            .is_err()
        {
            return error(400, "INVALID_ARGUMENT");
        }
        Some((blocking, snapshot, settings.clone()))
    } else {
        None
    };

    let rollback_blocking = |response: JsonResponse| {
        if let Some((blocking, snapshot, candidate)) = &blocking_transaction {
            let _ =
                blocking.restore_blocking_auth_settings_snapshot_if_unchanged(snapshot, candidate);
        }
        response
    };
    let config = if let Some(registry) = state
        .registry
        .as_ref()
        .filter(|_| pending_project.is_none())
    {
        // Decode masked replacements after the registry has acquired the namespace gate. This
        // keeps a concurrent PATCH from merging against a stale policy or quota snapshot.
        match registry.patch_project_config_with_current_settings(
            project,
            patch,
            |current_policy, current_quota| {
                let password_policy = password_policy_from_update(current_policy, body, &fields)?;
                let signup_quota = quota_config_from_update(current_quota, body, &fields)?;
                Ok((password_policy, signup_quota))
            },
        ) {
            Ok(Some(config)) => {
                if let Some(mfa) = mfa_update.clone() {
                    if registry.update_project_mfa_config(project, mfa).is_none() {
                        return rollback_blocking(error(500, "INTERNAL"));
                    }
                }
                if updates_sign_in {
                    match registry.update_project_sign_in_config(project, |current| {
                        sign_in_config_from_update(current, body, &fields)
                            .map(|next| next.unwrap_or_else(|| current.clone()))
                    }) {
                        Ok(Some(_)) => {}
                        Ok(None) => return rollback_blocking(error(500, "INTERNAL")),
                        Err(response) => return rollback_blocking(response),
                    }
                }
                config
            }
            Ok(None) => return rollback_blocking(error(500, "INTERNAL")),
            Err(response) => return rollback_blocking(response),
        }
    } else {
        // A pending routed project is not published in the registry yet. Keep its config and
        // policy transition under the selected store lock until the candidate is installed.
        let Ok(mut store) = selected_store.lock() else {
            return rollback_blocking(error(500, "INTERNAL"));
        };
        let current_policy = store.password_policy().clone();
        let current_quota = store.signup_quota().config().clone();
        let password_policy = match password_policy_from_update(&current_policy, body, &fields) {
            Ok(policy) => policy,
            Err(response) => return rollback_blocking(response),
        };
        let signup_quota = match quota_config_from_update(&current_quota, body, &fields) {
            Ok(quota) => quota,
            Err(response) => return rollback_blocking(response),
        };
        let sign_in = match sign_in_config_from_update(store.sign_in_config(), body, &fields) {
            Ok(sign_in) => sign_in,
            Err(response) => return rollback_blocking(response),
        };
        let has_policy = password_policy.is_some();
        let has_quota = signup_quota.is_some();
        let has_sign_in = sign_in.is_some();
        let has_mfa = mfa_update.is_some();
        if let Some(mfa) = mfa_update {
            store.set_mfa_config(mfa);
        }
        let config = patch.apply_to(store.config());
        if !patch.is_empty() {
            store.set_config(config);
        }
        if let Some(policy) = password_policy {
            store.set_password_policy(policy);
        }
        if let Some(quota) = signup_quota {
            if store.set_signup_quota_config(quota).is_err() {
                return rollback_blocking(error(400, "INVALID_ARGUMENT"));
            }
        }
        if let Some(sign_in) = sign_in {
            if store.set_sign_in_config(sign_in).is_err() {
                return rollback_blocking(error(400, "INVALID_ARGUMENT"));
            }
        }
        drop(store);
        if !patch.is_empty() || has_policy || has_quota || has_sign_in || has_mfa {
            if let Some(project) = pending_project {
                if let Err(response) = install_routed_candidate(state, project, selected_store) {
                    return rollback_blocking(response);
                }
            }
        }
        config
    };
    JsonResponse {
        status: 200,
        body: {
            let Ok(store) = selected_store.lock() else {
                return error(500, "INTERNAL");
            };
            let mut body = project_config_json_with_auth_settings(
                config,
                store.password_policy(),
                store.signup_quota().config(),
            );
            add_sign_in_config_json(&mut body, store.sign_in_config());
            body["mfa"] = project_mfa::mfa_config_json(store.mfa_config());
            body["authorizedDomains"] = json!(store.authorized_domains());
            if let Some(blocking) = state
                .blocking
                .as_ref()
                .filter(|hook| hook.blocking_auth_project() == Some(project))
                .and_then(|hook| hook.blocking_auth_settings())
            {
                body["blockingFunctions"] = blocking;
            }
            body
        },
    }
}

#[derive(Clone, Copy)]
enum ProviderKind {
    Oidc,
    Saml,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn provider_config_management(
    store: &Arc<Mutex<AuthStore>>,
    handler: routes::Handler,
    kind: ProviderKind,
    project: Option<&str>,
    tenant: Option<&str>,
    resource: Option<&str>,
    query: Option<&str>,
    body: &Value,
) -> JsonResponse {
    use routes::Handler;
    let Some(project) = project else {
        return error(400, "INVALID_PROJECT_ID");
    };
    let path_prefix = format!("projects/{project}/");
    let path_prefix = if let Some(tenant) = tenant {
        format!("{path_prefix}tenants/{tenant}/")
    } else {
        path_prefix
    };
    let (collection, collection_key) = match kind {
        ProviderKind::Oidc => ("oauthIdpConfigs", "oauthIdpConfigs"),
        ProviderKind::Saml => ("inboundSamlConfigs", "inboundSamlConfigs"),
    };
    let name = |id: &str| format!("{path_prefix}{collection}/{id}");
    let response = match (kind, handler) {
        (ProviderKind::Oidc, Handler::ProviderCreate) => {
            let Some(id) = query_params(query)
                .get("oauthIdpConfigId")
                .filter(|id| valid_provider_id(id, ProviderKind::Oidc))
                .cloned()
            else {
                return error(400, "INVALID_ARGUMENT");
            };
            let config = match parse_oidc(body, id) {
                Ok(config) => config,
                Err(response) => return response,
            };
            let Ok(mut store) = store.lock() else {
                return error(500, "INTERNAL");
            };
            if !store.create_oidc_config(config.clone()) {
                return error(409, "ALREADY_EXISTS");
            }
            JsonResponse {
                status: 200,
                body: oidc_json(&name(&config.id), &config),
            }
        }
        (ProviderKind::Saml, Handler::ProviderCreate) => {
            let Some(id) = query_params(query)
                .get("inboundSamlConfigId")
                .filter(|id| valid_provider_id(id, ProviderKind::Saml))
                .cloned()
            else {
                return error(400, "INVALID_ARGUMENT");
            };
            let config = match parse_saml(body, id) {
                Ok(config) => config,
                Err(response) => return response,
            };
            let Ok(mut store) = store.lock() else {
                return error(500, "INTERNAL");
            };
            if !store.create_saml_config(config.clone()) {
                return error(409, "ALREADY_EXISTS");
            }
            JsonResponse {
                status: 200,
                body: saml_json(&name(&config.id), &config),
            }
        }
        (ProviderKind::Oidc, Handler::ProviderList) => {
            let Ok(store) = store.lock() else {
                return error(500, "INTERNAL");
            };
            let params = query_params(query);
            let page_size = params
                .get("pageSize")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(20)
                .clamp(1, 1_000);
            let page_token = params.get("pageToken").map(String::as_str);
            let mut configs = store
                .oidc_configs()
                .map(|config| oidc_json(&name(&config.id), config))
                .collect::<Vec<_>>();
            if let Some(token) = page_token {
                let Some(index) = configs.iter().position(|config| {
                    config["name"]
                        .as_str()
                        .and_then(|value| value.rsplit('/').next())
                        == Some(token)
                }) else {
                    configs.clear();
                    return JsonResponse {
                        status: 400,
                        body: json!({"error": "INVALID_ARGUMENT"}),
                    };
                };
                configs = configs.into_iter().skip(index + 1).collect();
            }
            let next = (configs.len() > page_size)
                .then(|| {
                    configs
                        .get(page_size - 1)
                        .and_then(|config| config["name"].as_str())
                        .and_then(|name| name.rsplit('/').next())
                        .map(str::to_owned)
                })
                .flatten();
            configs.truncate(page_size);
            let mut body = json!({});
            body[collection_key] = json!(configs);
            if let Some(next) = next {
                body["nextPageToken"] = json!(next);
            }
            JsonResponse { status: 200, body }
        }
        (ProviderKind::Saml, Handler::ProviderList) => {
            let Ok(store) = store.lock() else {
                return error(500, "INTERNAL");
            };
            let params = query_params(query);
            let page_size = params
                .get("pageSize")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(20)
                .clamp(1, 1_000);
            let page_token = params.get("pageToken").map(String::as_str);
            let mut configs = store
                .saml_configs()
                .map(|config| saml_json(&name(&config.id), config))
                .collect::<Vec<_>>();
            if let Some(token) = page_token {
                let Some(index) = configs.iter().position(|config| {
                    config["name"]
                        .as_str()
                        .and_then(|value| value.rsplit('/').next())
                        == Some(token)
                }) else {
                    configs.clear();
                    return JsonResponse {
                        status: 400,
                        body: json!({"error": "INVALID_ARGUMENT"}),
                    };
                };
                configs = configs.into_iter().skip(index + 1).collect();
            }
            let next = (configs.len() > page_size)
                .then(|| {
                    configs
                        .get(page_size - 1)
                        .and_then(|config| config["name"].as_str())
                        .and_then(|name| name.rsplit('/').next())
                        .map(str::to_owned)
                })
                .flatten();
            configs.truncate(page_size);
            let mut body = json!({});
            body[collection_key] = json!(configs);
            if let Some(next) = next {
                body["nextPageToken"] = json!(next);
            }
            JsonResponse { status: 200, body }
        }
        (
            ProviderKind::Oidc,
            Handler::ProviderGet | Handler::ProviderUpdate | Handler::ProviderDelete,
        ) => {
            let Some(id) = resource.filter(|id| valid_provider_id(id, ProviderKind::Oidc)) else {
                return error(400, "INVALID_ARGUMENT");
            };
            let Ok(mut store) = store.lock() else {
                return error(500, "INTERNAL");
            };
            let Some(existing) = store.oidc_config(id).cloned() else {
                return error(404, "NOT_FOUND");
            };
            match handler {
                Handler::ProviderGet => JsonResponse {
                    status: 200,
                    body: oidc_json(&name(id), &existing),
                },
                Handler::ProviderDelete => {
                    store.delete_oidc_config(id);
                    JsonResponse {
                        status: 200,
                        body: json!({}),
                    }
                }
                Handler::ProviderUpdate => {
                    let updated = match patch_oidc(existing, body, query) {
                        Ok(updated) => updated,
                        Err(response) => return response,
                    };
                    store.replace_oidc_config(updated.clone());
                    JsonResponse {
                        status: 200,
                        body: oidc_json(&name(id), &updated),
                    }
                }
                _ => unreachable!(),
            }
        }
        (
            ProviderKind::Saml,
            Handler::ProviderGet | Handler::ProviderUpdate | Handler::ProviderDelete,
        ) => {
            let Some(id) = resource.filter(|id| valid_provider_id(id, ProviderKind::Saml)) else {
                return error(400, "INVALID_ARGUMENT");
            };
            let Ok(mut store) = store.lock() else {
                return error(500, "INTERNAL");
            };
            let Some(existing) = store.saml_config(id).cloned() else {
                return error(404, "NOT_FOUND");
            };
            match handler {
                Handler::ProviderGet => JsonResponse {
                    status: 200,
                    body: saml_json(&name(id), &existing),
                },
                Handler::ProviderDelete => {
                    store.delete_saml_config(id);
                    JsonResponse {
                        status: 200,
                        body: json!({}),
                    }
                }
                Handler::ProviderUpdate => {
                    let updated = match patch_saml(existing, body, query) {
                        Ok(updated) => updated,
                        Err(response) => return response,
                    };
                    store.replace_saml_config(updated.clone());
                    JsonResponse {
                        status: 200,
                        body: saml_json(&name(id), &updated),
                    }
                }
                _ => unreachable!(),
            }
        }
        _ => error(500, "INTERNAL"),
    };
    response
}

fn valid_provider_id(id: &str, kind: ProviderKind) -> bool {
    let prefix = match kind {
        ProviderKind::Oidc => "oidc.",
        ProviderKind::Saml => "saml.",
    };
    id.starts_with(prefix)
        && (prefix.len() + 1..=128).contains(&id.len())
        && id[prefix.len()..].chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
}

fn required_string(body: &Value, field: &str) -> Result<String, JsonResponse> {
    body.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))
}

fn optional_string(body: &Value, field: &str) -> Result<Option<String>, JsonResponse> {
    match body.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(error(400, "INVALID_ARGUMENT")),
    }
}

fn optional_bool(body: &Value, field: &str, default: bool) -> Result<bool, JsonResponse> {
    match body.get(field) {
        None => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(error(400, "INVALID_ARGUMENT")),
    }
}

fn parse_response_type(value: Option<&Value>) -> Result<OAuthResponseType, JsonResponse> {
    let Some(value) = value else {
        return Ok(OAuthResponseType {
            id_token: true,
            ..OAuthResponseType::default()
        });
    };
    let Some(object) = value.as_object() else {
        return Err(error(400, "INVALID_ARGUMENT"));
    };
    let read = |field: &str| match object.get(field) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(error(400, "INVALID_ARGUMENT")),
    };
    let response = OAuthResponseType {
        id_token: read("idToken")?,
        code: read("code")?,
        token: read("token")?,
    };
    validate_response_type(response)?;
    Ok(response)
}

fn validate_response_type(response: OAuthResponseType) -> Result<(), JsonResponse> {
    if response.token
        || (!response.id_token && !response.code)
        || (response.id_token && response.code)
    {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    Ok(())
}

fn parse_oidc(body: &Value, id: String) -> Result<OidcProviderConfig, JsonResponse> {
    let config = OidcProviderConfig {
        id,
        display_name: optional_string(body, "displayName")?,
        enabled: optional_bool(body, "enabled", false)?,
        client_id: required_string(body, "clientId")?,
        issuer: required_string(body, "issuer")?,
        client_secret: optional_string(body, "clientSecret")?,
        response_type: parse_response_type(body.get("responseType"))?,
    };
    validate_oidc(&config)?;
    Ok(config)
}

fn valid_url(value: &str) -> bool {
    let Some((scheme, host)) = value.split_once("://") else {
        return false;
    };
    matches!(scheme, "http" | "https")
        && !host.is_empty()
        && !host
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
}

fn validate_oidc(config: &OidcProviderConfig) -> Result<(), JsonResponse> {
    if !valid_url(&config.issuer)
        || (config.response_type.code && config.client_secret.as_deref().is_none_or(str::is_empty))
    {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    Ok(())
}

fn parse_saml(body: &Value, id: String) -> Result<InboundSamlProviderConfig, JsonResponse> {
    let Some(idp) = body.get("idpConfig").and_then(Value::as_object) else {
        return Err(error(400, "INVALID_ARGUMENT"));
    };
    let Some(sp) = body.get("spConfig").and_then(Value::as_object) else {
        return Err(error(400, "INVALID_ARGUMENT"));
    };
    let required_object_string = |object: &serde_json::Map<String, Value>, field: &str| {
        object
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| error(400, "INVALID_ARGUMENT"))
    };
    let certificates = match idp.get("idpCertificates") {
        None => Vec::new(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .get("x509Certificate")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| error(400, "INVALID_ARGUMENT"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(error(400, "INVALID_ARGUMENT")),
    };
    if certificates.is_empty() {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    let config = InboundSamlProviderConfig {
        id,
        display_name: optional_string(body, "displayName")?,
        enabled: optional_bool(body, "enabled", false)?,
        idp_entity_id: required_object_string(idp, "idpEntityId")?,
        sso_url: required_object_string(idp, "ssoUrl")?,
        idp_certificates: certificates,
        sign_request: match idp.get("signRequest") {
            None => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            Some(_) => Err(error(400, "INVALID_ARGUMENT")),
        }?,
        sp_entity_id: required_object_string(sp, "spEntityId")?,
        callback_uri: required_object_string(sp, "callbackUri")?,
    };
    if !valid_url(&config.sso_url) || !valid_url(&config.callback_uri) {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    Ok(config)
}

fn update_mask(query: Option<&str>) -> Result<Option<Vec<String>>, JsonResponse> {
    let mut value = None;
    for pair in query
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        let (key, candidate) = pair.split_once('=').unwrap_or((pair, ""));
        if malformed_query_component(key) || malformed_query_component(candidate) {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
        let decoded_key = decode_query_component(key);
        if decoded_key != "updateMask" {
            continue;
        }
        if value.is_some() {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
        value = Some(decode_query_component(candidate));
    }
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let mut fields = Vec::new();
    let mut seen = BTreeSet::new();
    for field in value.split(',') {
        if field.is_empty()
            || field.split('.').any(|part| {
                part.is_empty()
                    || !part.chars().enumerate().all(|(index, character)| {
                        (index == 0 && (character.is_ascii_alphabetic() || character == '_'))
                            || (index > 0
                                && (character.is_ascii_alphanumeric() || character == '_'))
                    })
            })
        {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
        if !seen.insert(field.to_owned()) {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
        fields.push(field.to_owned());
    }
    Ok(Some(fields))
}

fn malformed_query_component(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}

fn patch_oidc(
    mut current: OidcProviderConfig,
    body: &Value,
    query: Option<&str>,
) -> Result<OidcProviderConfig, JsonResponse> {
    for field in update_mask(query)?.unwrap_or_default() {
        match field.as_str() {
            "displayName" => current.display_name = optional_string(body, "displayName")?,
            "enabled" => current.enabled = optional_bool(body, "enabled", false)?,
            "clientId" => current.client_id = required_string(body, "clientId")?,
            "issuer" => current.issuer = required_string(body, "issuer")?,
            "clientSecret" => current.client_secret = optional_string(body, "clientSecret")?,
            "responseType" => {
                current.response_type = parse_response_type(body.get("responseType"))?;
            }
            "responseType.idToken" => {
                current.response_type.id_token = nested_bool(body, "responseType", "idToken")?;
            }
            "responseType.code" => {
                current.response_type.code = nested_bool(body, "responseType", "code")?;
            }
            "responseType.token" => {
                current.response_type.token = nested_bool(body, "responseType", "token")?;
            }
            "name" => {}
            _ => return Err(error(400, "INVALID_ARGUMENT")),
        }
    }
    validate_response_type(current.response_type)?;
    validate_oidc(&current)?;
    Ok(current)
}

fn nested_bool(body: &Value, parent: &str, field: &str) -> Result<bool, JsonResponse> {
    body.get(parent)
        .and_then(Value::as_object)
        .and_then(|object| object.get(field))
        .and_then(Value::as_bool)
        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))
}

fn patch_saml(
    mut current: InboundSamlProviderConfig,
    body: &Value,
    query: Option<&str>,
) -> Result<InboundSamlProviderConfig, JsonResponse> {
    if !body.is_object() {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    let fields = update_mask(query)?.unwrap_or_default();
    for field in fields {
        match field.as_str() {
            "displayName" => current.display_name = optional_string(body, "displayName")?,
            "enabled" => current.enabled = optional_bool(body, "enabled", false)?,
            "idpConfig" => {
                let Some(idp) = body.get("idpConfig").and_then(Value::as_object) else {
                    return Err(error(400, "INVALID_ARGUMENT"));
                };
                if let Some(value) = idp.get("idpEntityId") {
                    current.idp_entity_id = value
                        .as_str()
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
                }
                if let Some(value) = idp.get("ssoUrl") {
                    current.sso_url = value
                        .as_str()
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
                }
                if let Some(value) = idp.get("idpCertificates") {
                    current.idp_certificates = parse_saml_certificates(value)?;
                }
                if let Some(value) = idp.get("signRequest") {
                    current.sign_request = value
                        .as_bool()
                        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
                }
            }
            "idpConfig.idpEntityId" | "idpConfig.ssoUrl" | "idpConfig.idpCertificates" => {
                let Some(idp) = body.get("idpConfig").and_then(Value::as_object) else {
                    return Err(error(400, "INVALID_ARGUMENT"));
                };
                if field == "idpConfig.idpEntityId" {
                    if let Some(value) = idp.get("idpEntityId") {
                        current.idp_entity_id = value
                            .as_str()
                            .filter(|value| !value.is_empty())
                            .map(str::to_owned)
                            .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
                    }
                }
                if field == "idpConfig.ssoUrl" {
                    if let Some(value) = idp.get("ssoUrl") {
                        current.sso_url = value
                            .as_str()
                            .filter(|value| !value.is_empty())
                            .map(str::to_owned)
                            .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
                    }
                }
                if field == "idpConfig.idpCertificates" {
                    if let Some(value) = idp.get("idpCertificates") {
                        current.idp_certificates = parse_saml_certificates(value)?;
                    }
                }
            }
            "idpConfig.signRequest" => {
                current.sign_request = nested_bool_default_false(body, "idpConfig", "signRequest")?;
            }
            "spConfig" | "spConfig.spEntityId" | "spConfig.callbackUri" => {
                let Some(sp) = body.get("spConfig").and_then(Value::as_object) else {
                    return Err(error(400, "INVALID_ARGUMENT"));
                };
                if field == "spConfig" || field == "spConfig.spEntityId" {
                    if let Some(value) = sp.get("spEntityId") {
                        current.sp_entity_id = value
                            .as_str()
                            .filter(|value| !value.is_empty())
                            .map(str::to_owned)
                            .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
                    }
                }
                if field == "spConfig" || field == "spConfig.callbackUri" {
                    if let Some(value) = sp.get("callbackUri") {
                        current.callback_uri = value
                            .as_str()
                            .filter(|value| !value.is_empty())
                            .map(str::to_owned)
                            .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
                    }
                }
            }
            "name" => {}
            _ => return Err(error(400, "INVALID_ARGUMENT")),
        }
    }
    if current.idp_certificates.is_empty()
        || !valid_url(&current.sso_url)
        || !valid_url(&current.callback_uri)
    {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    Ok(current)
}

fn parse_saml_certificates(value: &Value) -> Result<Vec<String>, JsonResponse> {
    let Some(values) = value.as_array() else {
        return Err(error(400, "INVALID_ARGUMENT"));
    };
    values
        .iter()
        .map(|value| {
            value
                .get("x509Certificate")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| error(400, "INVALID_ARGUMENT"))
        })
        .collect()
}

fn oidc_json(name: &str, config: &OidcProviderConfig) -> Value {
    let mut body = json!({
        "name": name,
        "enabled": config.enabled,
        "clientId": config.client_id,
        "issuer": config.issuer,
        "responseType": {
            "idToken": config.response_type.id_token,
            "code": config.response_type.code,
            "token": config.response_type.token,
        },
    });
    if let Some(display_name) = &config.display_name {
        body["displayName"] = json!(display_name);
    }
    if let Some(client_secret) = &config.client_secret {
        body["clientSecret"] = json!(client_secret);
    }
    body
}

fn saml_json(name: &str, config: &InboundSamlProviderConfig) -> Value {
    let mut body = json!({
        "name": name,
        "enabled": config.enabled,
        "idpConfig": {
            "idpEntityId": config.idp_entity_id,
            "ssoUrl": config.sso_url,
            "idpCertificates": config.idp_certificates.iter().map(|certificate| json!({"x509Certificate": certificate})).collect::<Vec<_>>(),
            "signRequest": config.sign_request,
        },
        "spConfig": {
            "spEntityId": config.sp_entity_id,
            "callbackUri": config.callback_uri,
        },
    });
    if let Some(display_name) = &config.display_name {
        body["displayName"] = json!(display_name);
    }
    body
}

fn tenant_metadata(body: &Value) -> Result<fireemu_core_auth::store::TenantMetadata, JsonResponse> {
    let object = body
        .as_object()
        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "displayName"
                | "allowPasswordSignup"
                | "enableEmailLinkSignin"
                | "enableAnonymousUser"
                | "disableAuth"
                | "client"
                | "emailPrivacyConfig"
                | "passwordPolicyConfig"
        )
    }) {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    let display_name = match object.get("displayName") {
        None => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(_) => return Err(error(400, "INVALID_ARGUMENT")),
    };
    let scalar_bool = |key: &str| match object.get(key) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(error(400, "INVALID_ARGUMENT")),
    };
    let client = match object.get("client") {
        None => None,
        Some(Value::Object(value)) => Some(value),
        Some(_) => return Err(error(400, "INVALID_ARGUMENT")),
    };
    let permissions = match client {
        None => None,
        Some(client) => {
            if client.keys().any(|key| key != "permissions") {
                return Err(error(400, "INVALID_ARGUMENT"));
            }
            match client.get("permissions") {
                Some(Value::Object(value)) => Some(value),
                Some(_) | None => return Err(error(400, "INVALID_ARGUMENT")),
            }
        }
    };
    if permissions.is_some_and(|value| {
        value
            .keys()
            .any(|key| key != "disabledUserSignup" && key != "disabledUserDeletion")
    }) {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    let nested_bool = |key: &str| match permissions.and_then(|value| value.get(key)) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(error(400, "INVALID_ARGUMENT")),
    };
    let privacy = match object.get("emailPrivacyConfig") {
        None => None,
        Some(Value::Object(value)) => Some(value),
        Some(_) => return Err(error(400, "INVALID_ARGUMENT")),
    };
    if privacy.is_some_and(|value| value.keys().any(|key| key != "enableImprovedEmailPrivacy")) {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    let improved_email_privacy =
        match privacy.and_then(|value| value.get("enableImprovedEmailPrivacy")) {
            None => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => return Err(error(400, "INVALID_ARGUMENT")),
        };
    Ok(fireemu_core_auth::store::TenantMetadata {
        display_name,
        allow_password_signup: scalar_bool("allowPasswordSignup")?,
        enable_email_link_signin: scalar_bool("enableEmailLinkSignin")?,
        enable_anonymous_user: scalar_bool("enableAnonymousUser")?,
        disable_auth: scalar_bool("disableAuth")?,
        disabled_user_signup: nested_bool("disabledUserSignup")?,
        disabled_user_deletion: nested_bool("disabledUserDeletion")?,
        enable_improved_email_privacy: improved_email_privacy,
    })
}

fn tenant_metadata_patch(
    body: &Value,
    query: Option<&str>,
) -> Result<fireemu_core_auth::store::TenantMetadataPatch, JsonResponse> {
    const FIELDS: [&str; 10] = [
        "displayName",
        "allowPasswordSignup",
        "enableEmailLinkSignin",
        "enableAnonymousUser",
        "disableAuth",
        "client.permissions.disabledUserSignup",
        "client.permissions.disabledUserDeletion",
        "emailPrivacyConfig.enableImprovedEmailPrivacy",
        "client.permissions",
        "emailPrivacyConfig",
    ];
    let params = query_params(query);
    let fields: Vec<&str> = params.get("updateMask").map_or_else(
        || {
            FIELDS
                .into_iter()
                .filter(|field| match *field {
                    "client.permissions" => body
                        .get("client")
                        .and_then(|value| value.get("permissions"))
                        .is_some_and(contains_non_null_value),
                    "emailPrivacyConfig" => body
                        .get("emailPrivacyConfig")
                        .is_some_and(contains_non_null_value),
                    field => body.get(field).is_some_and(contains_non_null_value),
                })
                .collect()
        },
        |mask| mask.split(',').filter(|field| !field.is_empty()).collect(),
    );
    if fields
        .iter()
        .any(|field| !FIELDS.contains(field) && !valid_password_policy_field(field))
    {
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
            "client.permissions.disabledUserSignup" => {
                patch.disabled_user_signup = Some(nested_bool_default_false_path(
                    body,
                    &["client", "permissions", "disabledUserSignup"],
                )?);
            }
            "client.permissions.disabledUserDeletion" => {
                patch.disabled_user_deletion = Some(nested_bool_default_false_path(
                    body,
                    &["client", "permissions", "disabledUserDeletion"],
                )?);
            }
            "emailPrivacyConfig.enableImprovedEmailPrivacy" | "emailPrivacyConfig" => {
                patch.enable_improved_email_privacy = Some(nested_bool_default_false_path(
                    body,
                    &["emailPrivacyConfig", "enableImprovedEmailPrivacy"],
                )?);
            }
            "client.permissions" => {
                patch.disabled_user_signup = Some(nested_bool_default_false_path(
                    body,
                    &["client", "permissions", "disabledUserSignup"],
                )?);
                patch.disabled_user_deletion = Some(nested_bool_default_false_path(
                    body,
                    &["client", "permissions", "disabledUserDeletion"],
                )?);
            }
            field if valid_password_policy_field(field) => {}
            _ => unreachable!("tenant update mask was validated"),
        }
    }
    Ok(patch)
}

fn nested_bool_default_false_path(body: &Value, path: &[&str]) -> Result<bool, JsonResponse> {
    let mut value = body;
    for key in &path[..path.len().saturating_sub(1)] {
        value = match value.get(*key) {
            None | Some(Value::Null) => return Ok(false),
            Some(value) => value,
        };
        if !value.is_object() {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
    }
    match value.get(path[path.len() - 1]) {
        Some(Value::Bool(value)) => Ok(*value),
        None | Some(Value::Null) => Ok(false),
        Some(_) => Err(error(400, "INVALID_ARGUMENT")),
    }
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
        "client": {"permissions": {
            "disabledUserSignup": metadata.disabled_user_signup,
            "disabledUserDeletion": metadata.disabled_user_deletion,
        }},
        "emailPrivacyConfig": {
            "enableImprovedEmailPrivacy": metadata.enable_improved_email_privacy,
        },
        "mfaConfig": {"state": "DISABLED", "enabledProviders": []},
    })
}

fn tenant_json_with_policy(
    project: &str,
    tenant: &str,
    metadata: &fireemu_core_auth::store::TenantMetadata,
    policy: &PasswordPolicy,
) -> Value {
    let mut result = tenant_json(project, tenant, metadata);
    result["passwordPolicyConfig"] = project_config_json_with_password_policy(
        fireemu_core_auth::store::ProjectAuthConfig::default(),
        policy,
    )["passwordPolicyConfig"]
        .clone();
    result
}

fn tenant_client_config_patch(body: &Value) -> fireemu_core_auth::store::TenantMetadataPatch {
    let disabled_user_signup = body
        .get("client")
        .and_then(|client| client.get("permissions"))
        .and_then(|permissions| permissions.get("disabledUserSignup"))
        .and_then(Value::as_bool);
    let disabled_user_deletion = body
        .get("client")
        .and_then(|client| client.get("permissions"))
        .and_then(|permissions| permissions.get("disabledUserDeletion"))
        .and_then(Value::as_bool);
    let enable_improved_email_privacy = body
        .get("emailPrivacyConfig")
        .and_then(|config| config.get("enableImprovedEmailPrivacy"))
        .and_then(Value::as_bool);
    fireemu_core_auth::store::TenantMetadataPatch {
        disabled_user_signup,
        disabled_user_deletion,
        enable_improved_email_privacy,
        ..Default::default()
    }
}

fn validate_tenant_update_payload(body: &Value) -> Result<(), JsonResponse> {
    const FIELDS: [&str; 9] = [
        "tenantId",
        "displayName",
        "allowPasswordSignup",
        "enableEmailLinkSignin",
        "enableAnonymousUser",
        "disableAuth",
        "client",
        "emailPrivacyConfig",
        "passwordPolicyConfig",
    ];
    let object = body
        .as_object()
        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
    if object.keys().any(|field| !FIELDS.contains(&field.as_str())) {
        return Err(error(400, "INVALID_ARGUMENT"));
    }

    if object
        .get("tenantId")
        .is_some_and(|value| !value.is_null() && value.as_str().is_none_or(str::is_empty))
    {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    if object
        .get("displayName")
        .is_some_and(|value| !value.is_string() && !value.is_null())
    {
        return Err(error(400, "INVALID_ARGUMENT"));
    }
    for field in [
        "allowPasswordSignup",
        "enableEmailLinkSignin",
        "enableAnonymousUser",
        "disableAuth",
    ] {
        if object
            .get(field)
            .is_some_and(|value| !value.is_boolean() && !value.is_null())
        {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
    }

    if let Some(value) = object.get("client") {
        if !value.is_null() {
            let client = value
                .as_object()
                .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
            if client.keys().any(|field| field != "permissions") {
                return Err(error(400, "INVALID_ARGUMENT"));
            }
            if let Some(permissions) = client.get("permissions") {
                if !permissions.is_null() {
                    let permissions = permissions
                        .as_object()
                        .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
                    if permissions.keys().any(|field| {
                        field != "disabledUserSignup" && field != "disabledUserDeletion"
                    }) {
                        return Err(error(400, "INVALID_ARGUMENT"));
                    }
                    for field in ["disabledUserSignup", "disabledUserDeletion"] {
                        if permissions
                            .get(field)
                            .is_some_and(|value| !value.is_boolean() && !value.is_null())
                        {
                            return Err(error(400, "INVALID_ARGUMENT"));
                        }
                    }
                }
            }
        }
    }

    if let Some(value) = object.get("emailPrivacyConfig") {
        if !value.is_null() {
            let privacy = value
                .as_object()
                .ok_or_else(|| error(400, "INVALID_ARGUMENT"))?;
            if privacy
                .keys()
                .any(|field| field != "enableImprovedEmailPrivacy")
            {
                return Err(error(400, "INVALID_ARGUMENT"));
            }
            if privacy
                .get("enableImprovedEmailPrivacy")
                .is_some_and(|value| !value.is_boolean() && !value.is_null())
            {
                return Err(error(400, "INVALID_ARGUMENT"));
            }
        }
    }

    if let Some(value) = object.get("passwordPolicyConfig") {
        if !value.is_null() {
            password_policy_from_config_json(value)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
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
            let metadata = match tenant_metadata(body) {
                Ok(metadata) => metadata,
                Err(response) => return response,
            };
            let password_policy = match body.get("passwordPolicyConfig") {
                None => None,
                Some(value) => match password_policy_from_config_json(value) {
                    Ok(policy) => Some(policy),
                    Err(response) => return response,
                },
            };
            let Some((tenant, metadata, policy)) = registry.create_tenant_with_password_policy(
                project,
                metadata,
                tenant_client_config_patch(body),
                password_policy,
            ) else {
                return if registry.store_for(project).is_some() {
                    error(500, "INTERNAL")
                } else {
                    error(400, "INVALID_PROJECT_ID")
                };
            };
            JsonResponse {
                status: 200,
                body: tenant_json_with_policy(project, &tenant, &metadata, &policy),
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
                    let metadata = registry.tenant_metadata(project, id)?;
                    let store = registry.tenant_store(project, id)?;
                    let store = store.lock().ok()?;
                    Some(tenant_json_with_policy(
                        project,
                        id,
                        &metadata,
                        store.password_policy(),
                    ))
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
            let Some(store) = registry.tenant_store(project, tenant) else {
                return error(404, "TENANT_NOT_FOUND");
            };
            let Ok(store) = store.lock() else {
                return error(500, "INTERNAL");
            };
            JsonResponse {
                status: 200,
                body: tenant_json_with_policy(project, tenant, &metadata, store.password_policy()),
            }
        }
        Handler::TenantUpdate => {
            let Some(tenant) = tenant else {
                return error(400, "INVALID_TENANT_ID");
            };
            if let Err(response) = validate_tenant_update_payload(body) {
                return response;
            }
            let fields = match update_mask(query) {
                Ok(Some(fields)) => fields,
                Ok(None) => {
                    let mut fields = Vec::new();
                    for field in [
                        "displayName",
                        "allowPasswordSignup",
                        "enableEmailLinkSignin",
                        "enableAnonymousUser",
                        "disableAuth",
                    ] {
                        if body.get(field).is_some() {
                            fields.push(field.to_owned());
                        }
                    }
                    if body
                        .get("client")
                        .and_then(|value| value.get("permissions"))
                        .is_some()
                    {
                        fields.push("client.permissions".to_owned());
                    }
                    if body.get("emailPrivacyConfig").is_some() {
                        fields.push("emailPrivacyConfig".to_owned());
                    }
                    // A message-level ProtoJSON null is absent when no update mask selects it.
                    // An explicit mask still reaches `password_policy_from_update` and can
                    // clear the policy.
                    if body
                        .get("passwordPolicyConfig")
                        .is_some_and(contains_non_null_value)
                    {
                        fields.push("passwordPolicyConfig".to_owned());
                    }
                    fields
                }
                Err(response) => return response,
            };
            if fields.iter().any(|field| {
                field.starts_with("passwordPolicyConfig") && !valid_password_policy_field(field)
            }) {
                return error(400, "INVALID_ARGUMENT");
            }
            let current_policy = if fields.iter().any(|field| {
                field == "passwordPolicyConfig" || field.starts_with("passwordPolicyConfig.")
            }) {
                let Some(store) = registry.tenant_store(project, tenant) else {
                    return error(404, "TENANT_NOT_FOUND");
                };
                let Ok(store) = store.lock() else {
                    return error(500, "INTERNAL");
                };
                Some(store.password_policy().clone())
            } else {
                None
            };
            let password_policy = match current_policy {
                Some(current) => match password_policy_from_update(&current, body, &fields) {
                    Ok(policy) => policy,
                    Err(response) => return response,
                },
                None => None,
            };
            let patch = match tenant_metadata_patch(body, query) {
                Ok(patch) => patch,
                Err(response) => return response,
            };
            let Some((metadata, policy)) =
                registry.patch_tenant_with_password_policy(project, tenant, patch, password_policy)
            else {
                return error(404, "TENANT_NOT_FOUND");
            };
            JsonResponse {
                status: 200,
                body: tenant_json_with_policy(project, tenant, &metadata, &policy),
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
            | routes::Handler::Lookup
            | routes::Handler::SendOobCode
            | routes::Handler::ResetPassword
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
    if matches!(
        handler,
        routes::Handler::SendOobCode | routes::Handler::ResetPassword
    ) {
        let password_operation = handler == routes::Handler::ResetPassword
            || body.get("requestType").and_then(Value::as_str) == Some("PASSWORD_RESET");
        if password_operation && !metadata.allow_password_signup {
            return Some(error(400, "OPERATION_NOT_ALLOWED"));
        }
        let email_link_operation =
            body.get("requestType").and_then(Value::as_str) == Some("EMAIL_SIGNIN");
        if email_link_operation && !metadata.enable_email_link_signin {
            return Some(error(400, "OPERATION_NOT_ALLOWED"));
        }
    }
    if handler == routes::Handler::SignUp {
        let links_existing_user = body.get("idToken").is_some_and(|value| !value.is_null());
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

fn end_user_client_permission_denial(
    handler: routes::Handler,
    store: &AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> Option<JsonResponse> {
    if !store.allows_user_signup(AuthPrincipal::EndUser)
        && request_may_create_end_user(handler, store, body, at)
    {
        return Some(auth_error(&AuthError::UserSignupDisabled));
    }
    None
}

fn request_may_create_end_user(
    handler: routes::Handler,
    store: &AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> bool {
    match handler {
        routes::Handler::SignUp => body.get("idToken").is_none_or(Value::is_null),
        routes::Handler::SignInWithCustomToken => {
            custom_token_uid(body).is_some_and(|uid| store.user_by_id(&uid).is_none())
        }
        routes::Handler::SignInWithEmailLink => {
            body.get("idToken").is_none_or(Value::is_null)
                && str_field(body, "email")
                    .map(canonicalize_email)
                    .is_some_and(|email| store.user_by_email(&email).is_none())
        }
        routes::Handler::SignInWithPhoneNumber => {
            if body.get("idToken").is_some_and(|value| !value.is_null()) {
                return false;
            }
            let (Some(session), Some(code)) =
                (str_field(body, "sessionInfo"), str_field(body, "code"))
            else {
                return false;
            };
            store
                .check_phone_code(session, code, at)
                .ok()
                .is_some_and(|verified| store.user_by_phone(&verified.phone_number).is_none())
        }
        routes::Handler::SignInWithIdp => {
            if body.get("idToken").is_some_and(|value| !value.is_null()) {
                return false;
            }
            let Ok(resolved) = resolve_idp_credential(body) else {
                return false;
            };
            if store
                .user_by_federated(&resolved.provider_id, &resolved.info.raw_id)
                .is_some()
            {
                return false;
            }
            store.config().allow_duplicate_emails
                || resolved
                    .info
                    .email
                    .as_deref()
                    .and_then(|email| store.user_by_email(email))
                    .is_none()
        }
        _ => false,
    }
}

/// The store a request is for. Project-scoped routes (Admin SDK, emulator inspection)
/// name their project; client SDK routes of a session project are recognised by the API
/// key the session declared, by the audience of the ID token they carry, or by the store
/// that issued their refresh token; everything else is the default project's.
#[allow(clippy::too_many_lines)]
fn select_store(
    state: &AuthState,
    path: &str,
    query: Option<&str>,
    body: &Value,
    resolution: routes::Resolution<'_>,
) -> Result<Arc<Mutex<AuthStore>>, JsonResponse> {
    let (api_key, query_tenant) = query_selectors(query)?;
    let query_body_scope = state.query_limits == AuthQueryLimits::ProductionBounded
        && matches!(
            resolution,
            routes::Resolution::Matched { route, .. }
                if route.handler == routes::Handler::AdminQuery
        );
    if query_body_scope
        && body
            .get("tenantId")
            .is_some_and(|value| !value.is_null() && !value.is_string())
    {
        return Err(error(400, "INVALID_ARGUMENT : tenantId must be a string"));
    }
    let body_tenant = str_field(body, "tenantId");
    if let Some((body_tenant, query_tenant)) = body_tenant.as_ref().zip(query_tenant.as_ref()) {
        if body_tenant != query_tenant {
            return Err(error(400, "TENANT_ID_MISMATCH"));
        }
    }
    let requested_tenant = body_tenant.or(query_tenant.as_deref());
    if let Some((_, Some(path_tenant))) = routes::scoped_target(path) {
        if requested_tenant.is_some_and(|requested| requested != path_tenant) {
            return Err(error(400, "TENANT_ID_MISMATCH"));
        }
    }
    let id_token_target = str_field(body, "idToken").and_then(|token| {
        let signer = state.store.lock().ok().and_then(|s| s.signer_arc());
        fireemu_core_auth::jwt::decode_token(token, signer.as_deref())
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
            })
    });
    let exchanges_custom_token = matches!(
        resolution,
        routes::Resolution::Matched { route, .. }
            if route.handler == routes::Handler::SignInWithCustomToken
    );
    let exchanges_refresh_token = matches!(
        resolution,
        routes::Resolution::Matched { route, .. }
            if route.handler == routes::Handler::Token
    );
    if exchanges_custom_token {
        // A selected tenant is an explicit namespace assertion, whether it came from the query
        // or the request body. A valid custom token without a tenant claim is project-scoped and
        // must not be silently rebound to the requested tenant; malformed tokens are left to the
        // normal handler for its existing error shape.
        if let Some(requested_tenant) = requested_tenant {
            let token_mismatches = match custom_token_tenant(body) {
                Some(CustomTokenTenant::ProjectScoped) => true,
                Some(CustomTokenTenant::Tenant(token_tenant)) => token_tenant != requested_tenant,
                None => false,
            };
            if token_mismatches {
                return Err(error(400, "TENANT_ID_MISMATCH"));
            }
        }
    }
    if let Some((_, token_tenant)) = id_token_target.as_ref() {
        if query_tenant
            .as_ref()
            .is_some_and(|requested| token_tenant.as_deref() != Some(requested.as_str()))
        {
            // A query tenant is an explicit namespace assertion. Do not let a tenant
            // embedded in the ID token override it, and do not let a project-scoped token
            // silently fall back to the project store for a tenant request.
            return Err(error(400, "TENANT_ID_MISMATCH"));
        }
    }
    let Some(registry) = &state.registry else {
        if requested_tenant.is_some()
            || routes::scoped_target(path).is_some_and(|(_, tenant)| tenant.is_some())
        {
            return Err(error(
                if body_tenant.is_some() { 400 } else { 404 },
                "TENANT_NOT_FOUND",
            ));
        }
        return Ok(state.store.clone());
    };
    if let Some((project, tenant)) = routes::scoped_target(path) {
        if let Some(tenant) = tenant {
            let Some(store) = registry.tenant_store(project, tenant) else {
                return Err(error(404, "TENANT_NOT_FOUND"));
            };
            return Ok(store);
        }
        // Administrator query accepts its tenant selector in the JSON body as well.
        // Do not route a tenant query into the default project store. Other handlers
        // retain their existing selector rules; path/body/query conflicts were checked above.
        let selected_tenant =
            query_tenant
                .as_deref()
                .or(if query_body_scope { body_tenant } else { None });
        if let Some(selected_tenant) = selected_tenant {
            let Some(store) = registry.tenant_store(project, selected_tenant) else {
                return Err(error(404, "TENANT_NOT_FOUND"));
            };
            return Ok(store);
        }
        return Ok(registry
            .store_for(project)
            .or_else(|| registry.routed_store_for(project))
            .unwrap_or_else(|| state.store.clone()));
    }
    if exchanges_refresh_token && query_tenant.is_some() {
        if let Some(token) = str_field(body, "refresh_token") {
            use fireemu_core_auth::store::RefreshTokenStoreMatch;

            if let RefreshTokenStoreMatch::Unique(store) = registry.store_for_refresh_token(token) {
                let token_tenant = store
                    .lock()
                    .ok()
                    .and_then(|store| store.tenant_id().map(str::to_owned));
                if token_tenant.as_deref() != query_tenant.as_deref() {
                    return Err(error(400, "TENANT_ID_MISMATCH"));
                }
            }
        }
    }
    if let Some(key) = api_key.as_deref() {
        // A registry without a tenancy selector is the single-namespace adapter/test
        // configuration. It has no API-key ownership map to consult, so retain the historical
        // default-store behavior for compatibility keys such as the emulator's fake key.
        let selected_project = match state.tenancy.as_ref() {
            None => None,
            Some(tenancy) => {
                let Ok(tenancy) = tenancy.read() else {
                    return Err(error(500, "INTERNAL"));
                };
                match tenancy.project_of_api_key(key).map(str::to_owned) {
                    Some(project) => Some(project),
                    None if tenancy.registered().is_empty() || tenancy.is_default_api_key(key) => {
                        None
                    }
                    None => {
                        // An explicit API-key selector is an assertion about the target
                        // project. Never silently route an unknown key to the default namespace.
                        return Err(invalid_api_key(if exchanges_refresh_token {
                            "securetoken.googleapis.com"
                        } else {
                            "identitytoolkit.googleapis.com"
                        }));
                    }
                }
            }
        };
        if let Some(tenant) = requested_tenant {
            let project = selected_project
                .as_deref()
                .unwrap_or_else(|| registry.default_project());
            let Some(store) = registry.tenant_store(project, tenant) else {
                return Err(error(404, "TENANT_NOT_FOUND"));
            };
            return Ok(store);
        }
        if exchanges_refresh_token {
            // The Web SDK renews a tenant session on securetoken with the API key alone
            // (`requestStsToken` never sends `tenantId`; the securetoken API has no such
            // parameter). The refresh token encodes its issuing namespace, so a token minted
            // by a tenant of the key's project selects that tenant store. A token of another
            // project, a legacy or unowned token, and a deleted tenant's token keep falling
            // through to the project store, where the existing refusal applies.
            if let Some(store) = tenant_store_issuing_refresh_token(
                registry,
                selected_project
                    .as_deref()
                    .unwrap_or_else(|| registry.default_project()),
                body,
            )? {
                return Ok(store);
            }
        }
        let Some(project) = selected_project else {
            // With no registered tenancy sessions, preserve the historical fake-key behavior for
            // the default namespace. An explicit tenant above still had to resolve through the
            // registry, so it can never silently land in this store.
            return Ok(state.store.clone());
        };
        let Some(store) = registry
            .store_for(&project)
            .or_else(|| registry.routed_store_for(&project))
        else {
            return Err(error(400, "INVALID_PROJECT_ID"));
        };
        return Ok(store);
    }
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
    if let Some((project, tenant)) = id_token_target {
        if let Some(store) = tenant
            .as_deref()
            .and_then(|tenant| registry.tenant_store(&project, tenant))
            .or_else(|| registry.store_for(&project))
            .or_else(|| registry.routed_store_for(&project))
        {
            return Ok(store);
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
    if let Some(tenant) = body_tenant.or(query_tenant.as_deref()) {
        let Some(store) = registry.tenant_store(registry.default_project(), tenant) else {
            // Preserve the client-body tenant error shape while refusing to route an
            // unknown query tenant to the default project namespace.
            return Err(error(
                if body_tenant.is_some() { 400 } else { 404 },
                "TENANT_NOT_FOUND",
            ));
        };
        return Ok(store);
    }
    Ok(state.store.clone())
}

/// The tenant store of `project` that issued the request's `refresh_token`, when the token
/// names one; `None` for project-scoped, foreign-project, legacy and unowned tokens.
fn tenant_store_issuing_refresh_token(
    registry: &fireemu_core_auth::store::AuthRegistry,
    project: &str,
    body: &Value,
) -> Result<Option<Arc<Mutex<AuthStore>>>, JsonResponse> {
    use fireemu_core_auth::store::RefreshTokenStoreMatch;

    let Some(token) = str_field(body, "refresh_token") else {
        return Ok(None);
    };
    let store = match registry.store_for_refresh_token(token) {
        RefreshTokenStoreMatch::Unique(store) => store,
        RefreshTokenStoreMatch::Unavailable => return Err(error(500, "INTERNAL")),
        RefreshTokenStoreMatch::Ambiguous | RefreshTokenStoreMatch::NotFound => return Ok(None),
    };
    let issued_by_tenant_of_project = match store.lock() {
        Ok(issuer) => issuer.tenant_id().is_some() && issuer.project_id() == project,
        Err(_) => return Err(error(500, "INTERNAL")),
    };
    Ok(issued_by_tenant_of_project.then_some(store))
}

/// The API key (`key`, or the action link's `apiKey`) and the action link's `tenantId` a
/// query carries, decoded. Keys are declared from [A-Za-z0-9._-], but a client may still
/// percent-encode them.
fn query_selectors(query: Option<&str>) -> Result<(Option<String>, Option<String>), JsonResponse> {
    let decode = |value: &str| {
        fireemu_core_types::codec::percent_decode(value, fireemu_core_types::codec::PlusMode::Space)
    };
    let mut api_key = None;
    let mut tenant = None;
    for kv in query.unwrap_or("").split('&').filter(|kv| !kv.is_empty()) {
        let Some((name, value)) = kv.split_once('=') else {
            if matches!(decode(kv).as_str(), "key" | "apiKey" | "tenantId") {
                return Err(error(400, "INVALID_ARGUMENT"));
            }
            continue;
        };
        let decoded_name = decode(name);
        let slot = match decoded_name.as_str() {
            "key" | "apiKey" => &mut api_key,
            "tenantId" => &mut tenant,
            _ => continue,
        };
        if value.is_empty() || malformed_query_component(name) || malformed_query_component(value) {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
        if slot.is_some() {
            return Err(error(400, "INVALID_ARGUMENT"));
        }
        *slot = Some(decode(value));
    }
    Ok((api_key, tenant))
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

/// Returns the tenant scope of a syntactically valid custom token. `None` means that the token is
/// absent or malformed, so the normal sign-in handler retains responsibility for its existing
/// validation error. A valid project-scoped token is represented separately from a tenant token
/// for query-tenant assertions.
enum CustomTokenTenant {
    /// A valid custom token without a tenant claim.
    ProjectScoped,
    /// A valid custom token carrying a tenant claim.
    Tenant(String),
}

fn custom_token_tenant(body: &Value) -> Option<CustomTokenTenant> {
    let token = str_field(body, "token")?;
    let payload = if token.trim_start().starts_with('{') {
        fireemu_core_types::json::parse(token).ok()?
    } else {
        let decoded = fireemu_core_auth::jwt::decode_unsigned(token).ok()?;
        (decoded.payload.get("aud").and_then(JsonValue::as_str) == Some(CUSTOM_TOKEN_AUDIENCE))
            .then_some(decoded.payload)?
    };
    match payload.get("tenant_id") {
        None => Some(CustomTokenTenant::ProjectScoped),
        Some(JsonValue::String(tenant)) => Some(CustomTokenTenant::Tenant(tenant.clone())),
        Some(_) => None,
    }
}

/// `accounts:signUp`: a password user when an email or a password is present (both are then
/// required, the email first, as the official emulator checks them), otherwise an anonymous
/// user. `localId` is an Admin-only parameter on this route.
#[allow(clippy::too_many_lines)]
fn sign_up(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    forced_local_id: Option<&str>,
) -> JsonResponse {
    if body.get("localId").is_some_and(|v| !v.is_null()) {
        return error(400, "UNEXPECTED_PARAMETER : User ID");
    }
    // `str_field` ignores a non-string the way the assignment below does: this guard adds a
    // refusal for control characters, not a new type refusal.
    if let Some(name) = str_field(body, "displayName") {
        if let Err(r) = reject_control_characters(name, "displayName") {
            return r;
        }
    }
    let email = match opt_str(body, "email") {
        Ok(email) => email,
        Err(r) => return r,
    };
    let password = match opt_str(body, "password") {
        Ok(password) => password,
        Err(r) => return r,
    };
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
    let (uid, created_new) = if has_session {
        let uid = match verify_honouring_legacy(store, body, at) {
            Ok(uid) => uid,
            Err(r) => return r,
        };
        // Authenticate the session before evaluating a supplied password. This keeps invalid,
        // expired, or cross-session tokens from being classified as password-policy failures.
        if let Some(password) = password {
            if let Err(e) = store.validate_password_for(
                fireemu_core_auth::password_policy::Operation::Registration,
                password,
            ) {
                return auth_error(&e);
            }
        }
        let Some(email) = new_user.email.as_deref() else {
            return error(400, "MISSING_EMAIL");
        };
        // The upgrade always gives the account a password, so another password account on
        // the address refuses it even in duplicate-email mode (closure re-review 2026-09-24).
        if store.users_by_email(email).iter().any(|u| {
            u.local_id != uid
                && (!store.config().allow_duplicate_emails || store.has_password(&u.local_id))
        }) {
            return error(400, "EMAIL_EXISTS");
        }
        if let Err(e) = store.set_email(&uid, email) {
            return auth_error(&e);
        }
        if let Some(u) = store.user_mut(&uid) {
            u.email_verified = false;
            u.provider = fireemu_core_auth::store::Provider::Password;
        }
        (uid, false)
    } else {
        // Validate before creating a new account so rejected passwords leave no user behind.
        if let Some(password) = password {
            if let Err(e) = store.validate_password_for(
                fireemu_core_auth::password_policy::Operation::Registration,
                password,
            ) {
                return auth_error(&e);
            }
        }
        match store.create_user_with_id_as(AuthPrincipal::EndUser, new_user, forced_local_id, at) {
            Ok(uid) => (uid, true),
            Err(e) => return auth_error(&e),
        }
    };
    if let Some(password) = password {
        if let Err(e) = store.set_password_for(
            &uid,
            password,
            at,
            fireemu_core_auth::password_policy::Operation::Registration,
        ) {
            if created_new {
                let _ = store.delete_user_by_id(uid.as_str());
            }
            return auth_error(&e);
        }
    }
    if let Some(name) = str_field(body, "displayName") {
        if let Some(u) = store.user_mut(&uid) {
            u.display_name = Some(name.to_owned());
        }
    }
    // `photoUrl` is listed on the sign-up request but production does not persist it
    // (recorded 2026-09-12, tools/auth-blocking-create-disable: the control's photo URL
    // was absent on lookup and invisible to a blocking hook); it stays ignored here.
    store.record_sign_in(&uid, at);
    let display_name = store.user(&uid).and_then(|u| u.display_name.clone());
    match issue_tokens(store, &uid, None, at) {
        Ok(mut body) => {
            body["kind"] = json!("identitytoolkit#SignupNewUserResponse");
            body["displayName"] = json!(display_name);
            JsonResponse { status: 200, body }
        }
        Err(r) => {
            if created_new {
                let _ = store.delete_user_by_id(uid.as_str());
            }
            r
        }
    }
}

/// Audience every Firebase custom token carries.
pub const CUSTOM_TOKEN_AUDIENCE: &str =
    "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

/// `accounts:signInWithCustomToken`: the Admin SDK mints unsigned (`alg: none`) custom
/// tokens against an emulator; the user is created on first sign-in.
#[allow(clippy::too_many_lines)]
fn sign_in_with_custom_token(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    reject_expired: bool,
    trust: Option<&CustomTokenTrust>,
    legacy_tokens: bool,
) -> JsonResponse {
    // Production's rules apply with configured signers and in the strict profile; the
    // emulator profile keeps the official emulator's leniency (sandbox recording 2026-09-24).
    let production_rules = trust.is_some() || reject_expired;
    // Production accepts only a signed token. The strict profile therefore needs the signers
    // (`auth.customTokenSigners`) to verify one, and without them refuses every custom token as
    // production refuses an unsigned one; the daemon says so at startup.
    if reject_expired && trust.is_none() && str_field(body, "token").is_some_and(|t| !t.is_empty())
    {
        return error(400, "INVALID_CUSTOM_TOKEN");
    }
    // An empty token is a malformed one to production and a missing one to the emulator.
    let token = match str_field(body, "token") {
        Some("") if production_rules => {
            return error(400, custom_token::INVALID_ASSERTION_FORMAT);
        }
        None | Some("") => return error(400, "MISSING_CUSTOM_TOKEN"),
        Some(token) => token,
    };
    // With configured signers only a token they signed is accepted, as in production; without
    // them, like the official emulator, a strict JSON object is accepted as a fake custom token
    // beside the unsigned JWT the Admin SDK mints.
    let (payload, jwt) = if let Some(trust) = trust {
        match trust.verify(token, store.project_id()) {
            Ok(claims) => (claims, true),
            Err(refusal) => return error(400, refusal.message()),
        }
    } else if token.trim_start().starts_with('{') {
        match fireemu_core_types::json::parse(token) {
            Ok(v) => (v, false),
            Err(_) => {
                return error(
                    400,
                    "INVALID_CUSTOM_TOKEN : ((Auth Emulator only accepts strict JSON or JWTs as fake custom tokens.))",
                )
            }
        }
    } else {
        let Ok(decoded) = fireemu_core_auth::jwt::decode_unsigned(token) else {
            return error(
                400,
                if production_rules {
                    custom_token::INVALID_ASSERTION_FORMAT
                } else {
                    "INVALID_CUSTOM_TOKEN : Invalid assertion format"
                },
            );
        };
        if !production_rules
            && decoded.payload.get("aud").and_then(JsonValue::as_str) != Some(CUSTOM_TOKEN_AUDIENCE)
        {
            return error(400, "INVALID_CUSTOM_TOKEN : wrong audience");
        }
        (decoded.payload, true)
    };
    let now_secs = i64::try_from(at.as_nanos().div_euclid(1_000_000_000)).unwrap_or(i64::MAX);
    if production_rules && jwt && !custom_token_claims_hold(&payload, now_secs) {
        return error(400, "INVALID_CUSTOM_TOKEN");
    }
    if let Some(tenant_id) = payload.get("tenant_id") {
        let Some(tenant_id) = tenant_id.as_str() else {
            return error(400, "INVALID_CUSTOM_TOKEN : tenant_id must be a string");
        };
        if store.tenant_id() != Some(tenant_id) {
            return error(400, "TENANT_ID_MISMATCH");
        }
    }
    let uid = match payload.get("uid").or_else(|| payload.get("user_id")) {
        Some(JsonValue::String(s)) => Some(s.clone()),
        Some(JsonValue::Int(i)) => Some(i.to_string()),
        _ => None,
    };
    let Some(uid) = uid else {
        return error(400, "MISSING_IDENTIFIER");
    };
    // Production bounds the uid to 1..=128 characters (sandbox recording 2026-09-24).
    if production_rules && (uid.is_empty() || uid.chars().count() > 128) {
        return error(
            400,
            "INVALID_IDENTIFIER : Invalid user ID length. Expect to have length between 1 and 128.",
        );
    }
    if uid.is_empty() {
        return error(400, "MISSING_IDENTIFIER");
    }
    if uid.chars().count() > 128 {
        return auth_error(&AuthError::InvalidLocalId);
    }
    let uid = uid.as_str();
    let mut extra = CustomClaims::default();
    if let Some(claims) = payload.get("claims") {
        let JsonValue::Object(claims) = claims else {
            return error(
                400,
                if production_rules {
                    "INVALID_CLAIMS"
                } else {
                    "INVALID_CUSTOM_TOKEN : claims must be an object"
                },
            );
        };
        for (k, v) in claims {
            let Some(cv) = claims_from_json(v) else {
                return error(400, "INVALID_CUSTOM_TOKEN : unsupported claim value");
            };
            if let Err(e) = extra.insert(k, cv) {
                return error(
                    400,
                    &if production_rules {
                        format!("FORBIDDEN_CLAIM : {k}")
                    } else {
                        format!("INVALID_CUSTOM_TOKEN : {e}")
                    },
                );
            }
        }
    }
    // Production accepted developer claims past the 1000-byte account-claim limit (sandbox
    // recording 2026-09-24, custom-token/sign-in#claims-over-limit); the official emulator's
    // bound stays in the emulator profile.
    if !production_rules {
        if let Err(e) = extra.check_size() {
            return error(400, &format!("INVALID_CUSTOM_TOKEN : {e}"));
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
        match store.create_user_with_id_as(AuthPrincipal::EndUser, new_user, Some(uid), at) {
            Ok(id) => (id, true),
            Err(e) => return auth_error(&e),
        }
    };
    if store.user(&uid).is_some_and(|u| u.disabled) {
        return error(400, "USER_DISABLED");
    }
    // Any custom-token sign-in marks the account (sandbox recording 2026-09-24,
    // id-token/methods#admin-lookup-after-custom-sign-in).
    if let Some(user) = store.user_mut(&uid) {
        user.custom_auth = true;
    }
    store.record_sign_in(&uid, at);
    if legacy_tokens && wants_legacy_token(store, body) {
        let id_token = match legacy_sign_in_token(store, &uid, at, "custom", Some(&extra)) {
            Ok(token) => token,
            Err(r) => return r,
        };
        return JsonResponse {
            status: 200,
            body: json!({
                "kind": "identitytoolkit#VerifyCustomTokenResponse",
                "localId": uid.as_str(),
                "idToken": id_token,
                "isNewUser": is_new,
            }),
        };
    }
    match issue_tokens_with(
        store,
        &uid,
        None,
        at,
        Some(&extra),
        Some(fireemu_core_auth::store::Provider::Custom),
    ) {
        Ok(mut body) => {
            // `localId` and `email` stay until the request's creation is committed; the answer
            // is trimmed afterwards (`public_custom_token_answer`).
            body["kind"] = json!("identitytoolkit#VerifyCustomTokenResponse");
            body["isNewUser"] = json!(is_new);
            JsonResponse { status: 200, body }
        }
        Err(r) => r,
    }
}

/// The claims production requires of a custom token (sandbox recording 2026-09-24): its
/// audience, `iss` equal to `sub`, an `iat` and an `exp` at most an hour apart, an `iat` no more
/// than the skew allowance ahead, and an `exp` no more than the allowance behind.
fn custom_token_claims_hold(payload: &JsonValue, now_secs: i64) -> bool {
    let leeway = fireemu_core_auth::jwt::IDENTITY_TOOLKIT_EXPIRY_LEEWAY_SECONDS;
    let text = |name: &str| payload.get(name).and_then(JsonValue::as_str);
    let (Some(iat), Some(exp)) = (
        payload.get("iat").and_then(JsonValue::as_i64),
        payload.get("exp").and_then(JsonValue::as_i64),
    ) else {
        return false;
    };
    text("aud") == Some(CUSTOM_TOKEN_AUDIENCE)
        && text("iss").is_some()
        && text("iss") == text("sub")
        && exp.saturating_sub(iat) <= 3600
        && iat <= now_secs.saturating_add(leeway)
        && now_secs < exp.saturating_add(leeway)
}

/// The v2 API's refusal: a gRPC status name and no `errors` list (sandbox recording
/// 2026-09-24, mfaEnrollment:start and :withdraw). Applied in the strict profile only.
fn v2_error_shape(response: JsonResponse, strict: bool) -> JsonResponse {
    if strict && response.status == 400 {
        secure_token_error_shape(response)
    } else {
        response
    }
}

/// Production's custom-token answer names the account only inside the token (sandbox
/// recording 2026-09-24): the `localId` and `email` the creation commit reads are removed once
/// it has run.
fn public_custom_token_answer(mut body: Value) -> Value {
    if let Some(object) = body.as_object_mut() {
        object.remove("localId");
        object.remove("email");
    }
    body
}

/// Whether a sign-in answers with the legacy Identity Toolkit token: production does so for
/// password and custom-token sign-in unless `returnSecureToken` is true (sandbox recording
/// 2026-09-24). Tenant namespaces keep secure tokens until their legacy shape is observed.
fn wants_legacy_token(store: &AuthStore, body: &Value) -> bool {
    body.get("returnSecureToken").and_then(Value::as_bool) != Some(true)
        && store.tenant_id().is_none()
}

/// A legacy Identity Toolkit token for `uid`, in the unsigned internal form the response
/// signer replaces. It opens no refresh session.
fn legacy_sign_in_token(
    store: &mut AuthStore,
    uid: &LocalId,
    at: LogicalInstant,
    sign_in_provider: &str,
    developer_claims: Option<&CustomClaims>,
) -> Result<String, JsonResponse> {
    let iat = i64::try_from(at.as_nanos().div_euclid(1_000_000_000)).unwrap_or(i64::MAX);
    let payload = store
        .legacy_token_payload(uid, iat, sign_in_provider, developer_claims)
        .map_err(|e| auth_error(&e))?;
    Ok(fireemu_core_auth::jwt::encode_payload_shaped(
        &payload,
        None,
        HeaderShape::Untyped,
    ))
}

fn password_policy_notification(code: ViolationCode, policy: &PasswordPolicy) -> Value {
    let message = match code {
        ViolationCode::MissingLowercaseCharacter => {
            "Password must contain a lowercase character".to_owned()
        }
        ViolationCode::MissingUppercaseCharacter => {
            "Password must contain an uppercase character".to_owned()
        }
        ViolationCode::MissingNumericCharacter => {
            "Password must contain a numeric character".to_owned()
        }
        ViolationCode::MissingNonAlphanumericCharacter => {
            "Password must contain a non-alphanumeric character".to_owned()
        }
        ViolationCode::MinimumPasswordLength => {
            format!("Password must be at least {} characters", policy.min_length)
        }
        ViolationCode::MaximumPasswordLength => policy.max_length.map_or_else(
            || "Password exceeds the maximum allowed length".to_owned(),
            |max| format!("Password must be at most {max} characters"),
        ),
    };
    json!({
        "notificationCode": code.as_str(),
        "notificationMessage": message,
    })
}

fn sign_in_with_password(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    legacy_tokens: bool,
) -> JsonResponse {
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
    let (uid, violations) = match store.verify_password_with_imports(
        email,
        password,
        at,
        &password_hash::ImportedHashes,
    ) {
        Ok(result) => result,
        Err(e) => return auth_error(&e),
    };
    // Production always carries `displayName`, empty when the account has none.
    let display_name = store
        .user(&uid)
        .and_then(|u| u.display_name.clone())
        .unwrap_or_default();
    let mut extra = vec![
        ("kind", json!("identitytoolkit#VerifyPasswordResponse")),
        ("registered", json!(true)),
        ("displayName", json!(display_name)),
    ];
    if let Some(photo) = store.user(&uid).and_then(|u| u.photo_url.clone()) {
        extra.push(("profilePicture", json!(photo)));
    }
    if !violations.is_empty() {
        let policy = store.password_policy().clone();
        extra.push((
            "userNotifications",
            Value::Array(
                violations
                    .into_iter()
                    .map(|code| password_policy_notification(code, &policy))
                    .collect(),
            ),
        ));
    }
    if legacy_tokens && wants_legacy_token(store, body) && mfa_info(store, &uid, true).is_empty() {
        let id_token = match legacy_sign_in_token(store, &uid, at, "password", None) {
            Ok(token) => token,
            Err(r) => return r,
        };
        let mut response = json!({
            "localId": uid.as_str(),
            "email": store.user(&uid).and_then(|u| u.email.clone()),
            "idToken": id_token,
        });
        for (key, value) in extra {
            response[key] = value;
        }
        return JsonResponse {
            status: 200,
            body: response,
        };
    }
    finish_sign_in(
        store,
        &uid,
        at,
        Some(fireemu_core_auth::store::Provider::Password),
        &extra,
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
    finish_sign_in_with_attributes(store, uid, at, provider, extra, None)
}

fn finish_sign_in_with_attributes(
    store: &mut AuthStore,
    uid: &LocalId,
    at: LogicalInstant,
    provider: Option<fireemu_core_auth::store::Provider>,
    extra: &[(&str, Value)],
    sign_in_attributes: Option<&ClaimValue>,
) -> JsonResponse {
    finish_sign_in_with_attributes_and_credentials(
        store,
        uid,
        at,
        provider,
        extra,
        sign_in_attributes,
        None,
    )
}

fn finish_sign_in_with_attributes_and_credentials(
    store: &mut AuthStore,
    uid: &LocalId,
    at: LogicalInstant,
    provider: Option<fireemu_core_auth::store::Provider>,
    extra: &[(&str, Value)],
    sign_in_attributes: Option<&ClaimValue>,
    inbound_credentials: Option<&PendingSignInCredentials>,
) -> JsonResponse {
    let factors = mfa_info(store, uid, true);
    if !factors.is_empty() && store.second_factor_required_for(uid) {
        let strict = store.second_factor_rules_are_production();
        // Second factor required: no ID token yet, only a pending credential.
        let email = store.user(uid).and_then(|u| u.email.clone());
        let sign_in_provider = provider
            .as_ref()
            .map(|provider| provider.id().to_owned())
            .or_else(|| store.user(uid).map(|user| user.provider.id().to_owned()));
        let is_new_user = extra
            .iter()
            .find(|(field, _)| *field == "isNewUser")
            .and_then(|(_, value)| value.as_bool())
            .unwrap_or(false);
        let context = PendingSignInContext::new_with_credentials(
            sign_in_provider,
            is_new_user,
            sign_in_attributes.cloned(),
            inbound_credentials.cloned(),
        );
        return match store.start_mfa_sign_in_with_context(uid, at, context) {
            Ok(pending) => {
                let mut body = json!({"mfaPendingCredential": pending.as_str(), "mfaInfo": factors, "localId": uid.as_str(), "email": email});
                for (k, v) in extra {
                    // The pending-second-factor answer carries no profile fields on the
                    // official emulator (conformance/fixtures/auth/mfa-enrollment-eligibility).
                    // Production keeps a password sign-in's `displayName` and leaves out an
                    // email link's `isNewUser` (sandbox recording 2026-09-24, auth-mfa).
                    let dropped = if strict {
                        *k == "isNewUser"
                    } else {
                        *k == "displayName"
                    };
                    if !dropped {
                        body[*k] = v.clone();
                    }
                }
                JsonResponse { status: 200, body }
            }
            Err(e) => mfa_error(&e),
        };
    }
    match issue_tokens_with_sign_in_attributes(
        store,
        uid,
        None,
        at,
        None,
        provider,
        sign_in_attributes,
    ) {
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
    // Production lists phone first, then federated identities in link order, then password
    // (sandbox recording 2026-09-23: auth-account/provider, admin/create, admin/import).
    let mut providers: Vec<Value> = Vec::new();
    if let Some(phone) = &u.phone_number {
        providers.push(json!({"providerId": "phone", "rawId": phone, "phoneNumber": phone}));
    }
    for f in &u.federated {
        providers.push(json!({"providerId": f.provider_id, "rawId": f.raw_id, "federatedId": f.raw_id, "email": f.email, "displayName": f.display_name, "photoUrl": f.photo_url}));
    }
    // The official record lists a `password` provider for an email with a password or an
    // email-link sign-in, and nothing for an address that has neither.
    if let Some(email) = &u.email {
        if store.has_password(uid)
            || u.email_link_signin
            || u.provider == fireemu_core_auth::store::Provider::EmailLink
        {
            providers.push(json!({"providerId": "password", "rawId": email, "federatedId": email, "email": email, "displayName": u.display_name, "photoUrl": u.photo_url}));
        }
    }
    // Production omits most default-valued fields (proto3 JSON): no empty `mfaInfo` or
    // `providerUserInfo`, `emailVerified` only with an address. `disabled` and `validSince`
    // are present for an account the Admin API created (the sandbox recording of 2026-09-23),
    // and otherwise `disabled` only when true and `validSince` once tokens were ever revoked
    // or a password set. The password hash is the
    // redacted marker production sends a caller without hash-config permission
    // (conformance/auth-production-matrix.json, password/sign-up-and-sign-in#lookup).
    let has_password = store.has_password(uid);
    let valid_since = (has_password
        || u.tokens_revoked
        || u.admin_created
        || u.custom_auth
        || u.email_link_created)
        .then_some(u.tokens_valid_after);
    json!({
        "localId": u.local_id.as_str(),
        "tenantId": store.tenant_id(),
        "email": u.email,
        "displayName": u.display_name,
        "photoUrl": u.photo_url,
        "phoneNumber": u.phone_number,
        // Reported with an address, and while true even without one (production keeps the
        // flag through an Admin email removal).
        "emailVerified": (u.email.is_some() || u.email_verified || u.email_verified_recorded)
            .then_some(u.email_verified),
        "disabled": (u.disabled || u.admin_created).then_some(u.disabled),
        // Absent, not "{}", when no claim is set: what the Admin SDK reads back as no claims.
        "customAttributes": u.custom_claims.attributes_text(),
        "providerUserInfo": (!providers.is_empty()).then_some(providers),
        "mfaInfo": (!mfa.is_empty()).then_some(mfa),
        "passwordHash": has_password.then_some(REDACTED_PASSWORD_HASH),
        "passwordUpdatedAt": store.password_updated_at(uid).map(|t| t.as_nanos() / 1_000_000),
        "createdAt": (u.created_at.as_nanos() / 1_000_000).to_string(),
        "lastRefreshAt": u.last_refresh_at.and_then(|t| LogicalInstant::to_rfc3339(t).ok()),
        "lastLoginAt": u.last_sign_in_at.map(|t| (t.as_nanos() / 1_000_000).to_string()),
        "validSince": valid_since.map(|t| (t.as_nanos() / 1_000_000_000).to_string()),
        "customAuth": u.custom_auth.then_some(true),
        "emailLinkSignin": u.email_link_signin.then_some(true),
        "initialEmail": u.initial_email,
    })
}

/// The `passwordHash` production returns to a caller without permission to read hash
/// configuration: base64 of `REDACTED`.
const REDACTED_PASSWORD_HASH: &str = "UkVEQUNURUQ=";

/// Maximum identifiers per lookup. Production accepted 101 (sandbox recording 2026-09-23);
/// this is a local guard, not an observed quota.
const MAX_LOOKUP_IDENTIFIERS: usize = 10_000;

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
                    // Proto3 JSON reads a number into a string field (production accepted
                    // `localId: [42]`).
                    Value::Number(n) => out.push(n.to_string()),
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

fn federated_identifiers(body: &Value) -> Result<Vec<(String, String)>, JsonResponse> {
    match body.get("federatedUserId") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                let object = item.as_object().ok_or_else(|| {
                    error(
                        400,
                        "INVALID_ARGUMENT : federatedUserId must be an array of {providerId, rawId}",
                    )
                })?;
                let provider_id = object
                    .get("providerId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        error(
                            400,
                            "INVALID_ARGUMENT : federatedUserId items require string providerId and rawId",
                        )
                    })?;
                let raw_id = object
                    .get("rawId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        error(
                            400,
                            "INVALID_ARGUMENT : federatedUserId items require string providerId and rawId",
                        )
                    })?;
                Ok((provider_id.to_owned(), raw_id.to_owned()))
            })
            .collect(),
        Some(_) => Err(error(
            400,
            "INVALID_ARGUMENT : federatedUserId must be an array of {providerId, rawId}",
        )),
    }
}

fn lookup(store: &AuthStore, body: &Value, at: LogicalInstant, admin: bool) -> JsonResponse {
    if !admin {
        // Select the trust boundary before parsing any administrator search criteria.
        // End-user lookup always verifies a token and can return only its subject.
        let session = match verify_session_accepting(
            store,
            body,
            at,
            |e| {
                if matches!(e, fireemu_core_auth::jwt::JwtError::UnknownUser) {
                    error(400, "USER_NOT_FOUND")
                } else {
                    jwt_error(e)
                }
            },
            LegacyTokens::Honoured,
        ) {
            Ok(session) => session,
            Err(response) => return response,
        };
        // Admin selectors beside a verified session are ignored: production answers with the
        // session's subject only (sandbox recording 2026-09-23).
        return JsonResponse {
            status: 200,
            body: json!({"kind": "identitytoolkit#GetAccountInfoResponse", "users": [user_json(store, &session.uid)]}),
        };
    }
    let lists = (|| -> Result<_, JsonResponse> {
        let federated = federated_identifiers(body)?;
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
    // `initialEmail` is a selector production accepts; it matched nothing in the sandbox
    // recording (2026-09-23) and fireemu keeps no initial address, so it never matches here.
    let initial_emails = match id_list(body, "initialEmail") {
        Ok(list) => list.len(),
        Err(r) => return r,
    };
    let total = local_ids.len() + emails.len() + phones.len() + federated.len() + initial_emails;
    if total > MAX_LOOKUP_IDENTIFIERS {
        return error(
            400,
            &format!("INVALID_ARGUMENT : at most {MAX_LOOKUP_IDENTIFIERS} identifiers per lookup"),
        );
    }
    if total == 0 {
        // Production answers an Admin lookup without identifiers as if it lacked a token.
        return error(400, "MISSING_ID_TOKEN");
    }
    // Authenticated Admin lookup resolves identifiers in request order without duplicates.
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
    // Every account sharing an address answers (sandbox recording 2026-09-23,
    // `config/duplicate-email#admin-lookup-by-email`).
    for email in &emails {
        for u in store.users_by_email(email) {
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

/// Refuses a profile string a request states directly when it carries a NUL or another
/// control character. [`AuthStore::import_user`] already refuses these at its own boundary,
/// so a value that cannot be imported cannot be created through a request either.
/// Production's refusal shape for this input is unobserved, and so are the length bounds it
/// applies, which are therefore not imposed here.
fn reject_control_characters(value: &str, field: &str) -> Result<(), JsonResponse> {
    if value.chars().any(char::is_control) {
        return Err(error(
            400,
            &format!("INVALID_ARGUMENT : {field} must not contain control characters"),
        ));
    }
    Ok(())
}

/// `{providerId, rawId, email?, displayName?, photoUrl?}` of a link request.
fn parse_identity(v: &Value) -> Result<FederatedIdentity, JsonResponse> {
    // Production's refusals (sandbox recording 2026-09-23, auth-account/provider).
    let missing = || {
        error(
            400,
            "MISSING_IDENTIFIER : providerId & rawId are both required for provider linking",
        )
    };
    let provider_id = opt_str(v, "providerId")?
        .filter(|p| !p.is_empty())
        .ok_or_else(missing)?;
    let raw_id = opt_str(v, "rawId")?
        .filter(|p| !p.is_empty())
        .ok_or_else(missing)?;
    if matches!(provider_id, "password" | "phone" | "emailLink") {
        return Err(error(400, "INVALID_PROVIDER_ID"));
    }
    let identity = FederatedIdentity {
        provider_id: provider_id.to_owned(),
        raw_id: raw_id.to_owned(),
        email: opt_str(v, "email")?.map(str::to_owned),
        display_name: opt_str(v, "displayName")?.map(str::to_owned),
        photo_url: opt_str(v, "photoUrl")?.map(str::to_owned),
    };
    // The store's `FederatedIdentity::validate` is the single truth, but it runs when the
    // identity is linked, which is after this request's other writes. Parsing is before all
    // of them, so the same check runs here to keep a refused request from applying half of
    // itself.
    identity.validate().map_err(|e| auth_error(&e))?;
    Ok(identity)
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
        // An entry with `phoneInfo` is a phone factor whatever else it carries, as the official
        // emulator reads it. Production's words for an entry with only `totpInfo` (sandbox
        // recording 2026-09-24, auth-mfa/admin-factors#admin-set-totp-factor-ia and
        // #admin-set-invalid-phone-ia); one with both is unobserved and stays accepted.
        let Some(phone) = str_field(item, "phoneInfo") else {
            if item.get("totpInfo").is_some_and(|v| !v.is_null()) {
                return Err(error(
                    400,
                    "UNSUPPORTED_SECOND_FACTOR : attempting to add a new TOTP enrollment",
                ));
            }
            return Err(error(
                400,
                "INVALID_ARGUMENT : only phone second factors (phoneInfo) can be enrolled by an admin",
            ));
        };
        AuthStore::validate_phone_number(phone)
            .map_err(|_| error(400, "INVALID_PHONE_NUMBER : Invalid format."))?;
        out.push((
            phone.to_owned(),
            opt_str(item, "displayName")?.map(str::to_owned),
        ));
    }
    Ok(out)
}

fn parse_custom_claims(attrs: &str) -> Result<CustomClaims, JsonResponse> {
    let Ok(JsonValue::Object(parsed)) = fireemu_core_types::json::parse(attrs) else {
        // Production echoes a well-formed non-object value compactly ("Not a JSON Object:
        // [1,2]"); for malformed JSON it returns its parser's exception text, which is not
        // reproduced.
        return Err(match serde_json::from_str::<Value>(attrs) {
            Ok(value) => error(400, &format!("INVALID_CLAIMS : Not a JSON Object: {value}")),
            Err(_) => error(
                400,
                "INVALID_CLAIMS : customAttributes must be a JSON object",
            ),
        });
    };
    let mut claims = CustomClaims::default();
    for (k, v) in &parsed {
        let Some(cv) = claims_from_json(v) else {
            return Err(error(400, "INVALID_CLAIMS"));
        };
        if claims.insert(k, cv).is_err() {
            // Production names only the claim: "FORBIDDEN_CLAIM : sub".
            return Err(error(400, &format!("FORBIDDEN_CLAIM : {k}")));
        }
    }
    // Production reads the attributes back as they were set (sandbox recording 2026-09-23).
    Ok(claims.with_source(attrs))
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
    // Production stores a displayName carrying control characters, NUL included, on update
    // (sandbox recording 2026-09-23, auth-account/values). photoUrl stays refused until observed.
    if let Some(value) = opt_str(body, "photoUrl")? {
        reject_control_characters(value, "photoUrl")?;
    }
    let mut display_name = change("displayName")?;
    let mut photo_url = change("photoUrl")?;
    let mut phone_number = change("phoneNumber")?;
    if let Change::Set(p) = &mut phone_number {
        *p = AuthStore::normalize_phone_number(p).map_err(|e| auth_error(&e))?;
    }
    // Java string length, so UTF-16 units (sandbox recording 2026-09-23, 257 is refused).
    if let Change::Set(name) = &display_name {
        if name.encode_utf16().count() > 256 {
            return Err(error(
                400,
                "INVALID_PROFILE_ATTRIBUTE : Display name too long.",
            ));
        }
    }
    let mut clear_password = false;
    let mut clear_email = false;
    if let Some(attrs) = body.get("deleteAttribute") {
        for (index, a) in string_list(attrs, "deleteAttribute")?.iter().enumerate() {
            match a.as_str() {
                "USER_ATTRIBUTE_NAME_UNSPECIFIED" => {}
                "DISPLAY_NAME" => display_name = Change::Clear,
                "PHOTO_URL" => photo_url = Change::Clear,
                "PASSWORD" => clear_password = true,
                "EMAIL" => clear_email = true,
                other => {
                    // The proto3 JSON enum decoder's refusal, index and all.
                    let field = format!("delete_attribute[{index}]");
                    return Err(proto_field_error(
                        &field,
                        &format!("Invalid value at '{field}' (type.googleapis.com/google.cloud.identitytoolkit.v1.SetAccountInfoRequest.UserAttributeName), {other:?}"),
                    ));
                }
            }
        }
    }
    let mut unlink = Vec::new();
    if let Some(providers) = body.get("deleteProvider") {
        for p in string_list(providers, "deleteProvider")? {
            match p.as_str() {
                "phone" => phone_number = Change::Clear,
                // Production keeps the address when the password provider is removed
                // (sandbox recording 2026-09-23); the official emulator drops it.
                "password" => clear_password = true,
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
    // `mfa` replaces every factor; without `enrollments` it clears them, as production does
    // (sandbox recording 2026-09-24, auth-mfa/admin-factors#admin-lookup-cleared).
    let phone_factors = match body.get("mfa") {
        None | Some(Value::Null) => None,
        Some(mfa) => match mfa.get("enrollments") {
            None | Some(Value::Null) => Some(Vec::new()),
            Some(v) => Some(parse_phone_factors(v)?),
        },
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

// A verified client may update normal profile fields, but email verification remains
// server-controlled. OOB and Admin planning do not use this projection.
// Second45 observed client scalar decoding. Keep session error precedence and the
// Admin/OOB routes separate; no mutation is planned before this check succeeds.
fn validate_client_update_shapes(body: &Value) -> Result<(), JsonResponse> {
    for (field, proto) in [
        ("localId", "local_id"),
        ("displayName", "display_name"),
        ("emailVerified", "email_verified"),
        ("customAttributes", "custom_attributes"),
    ] {
        let Some(value) = body.get(field) else {
            continue;
        };
        let (description, field_path) = if value.is_object() {
            (
                format!("Invalid value ({proto}), Starting an object on a scalar field"),
                false,
            )
        } else if value.is_array() {
            (format!("Invalid JSON payload received. Unknown name \"{field}\": Proto field is not repeating, cannot start list."), false)
        } else if field == "displayName" && value.is_boolean() {
            (
                format!("Invalid value at '{proto}' (TYPE_STRING), {value}"),
                true,
            )
        } else {
            continue;
        };
        let mut violation = json!({"description": description});
        if field_path {
            violation["field"] = json!(proto);
        }
        return Err(JsonResponse {
            status: 400,
            body: json!({"error": {
                "code": 400, "message": description,
                "errors": [{"message": description, "reason": "invalid"}],
                "status": "INVALID_ARGUMENT",
                "details": [{"@type": "type.googleapis.com/google.rpc.BadRequest", "fieldViolations": [violation]}]
            }}),
        });
    }
    Ok(())
}

fn parse_client_update(body: &Value) -> Result<UpdatePlan, JsonResponse> {
    let mut client = body.clone();
    if let Some(fields) = client.as_object_mut() {
        fields.remove("emailVerified");
        if fields.get("customAttributes").is_some_and(Value::is_null) {
            fields.remove("customAttributes");
        }
        if let Some(Value::Number(number)) = fields.get("displayName") {
            fields.insert("displayName".to_owned(), Value::String(number.to_string()));
        }
    }
    parse_update(&client)
}

#[allow(clippy::too_many_lines)]
fn update(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    stateless_refresh_tokens: bool,
    privileged: bool,
) -> JsonResponse {
    // Account ownership does not authorize administrative field changes. Presence
    // includes false/empty/null. On the OOB route the field is rejected before the code
    // is consumed; on the end-user session route the session is authenticated first and
    // the field authorized after (see the session branch below).
    let has_admin_field = !privileged
        && [
            "customAttributes",
            "emailVerified",
            "mfa",
            "linkProviderUserInfo",
        ]
        .iter()
        .any(|field| body.get(*field).is_some());
    // `applyActionCode`: an email verification / change code instead of a session.
    // Strict: with an ID token the request is that account's own update and the code is not
    // applied (sandbox recording 2026-09-24, ownership#apply-a-change-with-b-token); the
    // official emulator applies the code first.
    let strict = !stateless_refresh_tokens;
    let with_session = body.get("idToken").is_some_and(|token| !token.is_null());
    if let Some(code) = str_field(body, "oobCode").filter(|_| !(strict && with_session)) {
        if has_admin_field {
            return error(400, "OPERATION_NOT_ALLOWED");
        }
        return apply_oob_code(store, code, at, strict);
    }
    let self_service = !privileged;
    let local_id = if privileged {
        match opt_str(body, "localId") {
            Ok(v) => v,
            Err(r) => return r,
        }
    } else {
        None
    };
    // The observed missing/null token profile family does not change shared token errors.
    if self_service
        && body.as_object().is_some_and(|o| {
            o.contains_key("displayName")
                && o.keys()
                    .all(|k| matches!(k.as_str(), "displayName" | "localId" | "idToken"))
                && o.get("idToken").is_none_or(Value::is_null)
        })
    {
        return error(400, "INVALID_REQ_TYPE");
    }
    // The provider the request's session signed in with, when it carries one: the official
    // emulator re-issues tokens for a session whose credentials it just changed.
    let mut session_provider: Option<fireemu_core_auth::store::Provider> = None;
    if privileged && local_id.is_none() && body.get("idToken").is_none_or(Value::is_null) {
        return error(400, "MISSING_LOCAL_ID");
    }
    let uid = if let Some(local_id) = local_id {
        // An enforced custom policy refuses the password before the account is looked up;
        // the default minimum length is checked after (sandbox recording 2026-09-23,
        // `policy/enforce-custom#admin-update-weak`, `policy/default/routes#admin-update-weak`).
        if let Some(password) = str_field(body, "password") {
            if let Err(e @ AuthError::PasswordPolicyViolation(_)) = store.validate_password_for(
                fireemu_core_auth::password_policy::Operation::Change,
                password,
            ) {
                return auth_error(&e);
            }
        }
        match store.user_by_id(local_id) {
            Some(u) => u.local_id.clone(),
            None => return error(400, "USER_NOT_FOUND"),
        }
    } else {
        // Authenticate the client before planning any mutation. A supplied localId is
        // never a client selector, and does not change self-service invalidation rules.
        match verify_session_accepting(store, body, at, jwt_error, LegacyTokens::Honoured) {
            Ok(session) => {
                if self_service {
                    if let Err(response) = validate_client_update_shapes(body) {
                        return response;
                    }
                    if body.get("customAttributes").is_some_and(|v| !v.is_null()) {
                        return error(400, "INSUFFICIENT_PERMISSION");
                    }
                }
                if has_admin_field && body.get("linkProviderUserInfo").is_some() {
                    // Sandbox recording 2026-09-23 (`client-update-link-provider`).
                    return error(
                        400,
                        "UNEXPECTED_PARAMETER : link_provider_user_info is not allowed with ID token.",
                    );
                }
                if has_admin_field && body.get("mfa").is_some() {
                    return error(400, "OPERATION_NOT_ALLOWED");
                }
                if body.get("disableUser").is_some_and(|v| !v.is_null()) {
                    return error(400, "OPERATION_NOT_ALLOWED");
                }
                session_provider = self_service.then(|| provider_from_id(&session.provider));
                session.uid
            }
            Err(r) => return r,
        }
    };
    // Validate the whole request before touching the store (a rejected request changes
    // nothing); email / phone uniqueness is part of the validation.
    let plan = match if self_service {
        parse_client_update(body)
    } else {
        parse_update(body)
    } {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Some(password) = &plan.password {
        if let Err(e) = store.validate_password_for(
            fireemu_core_auth::password_policy::Operation::Change,
            password,
        ) {
            return auth_error(&e);
        }
    }
    // Improved email privacy requires a proof-of-ownership OOB flow for address changes.
    // It also removes the legacy setAccountInfo email/password linking path; clients link
    // through accounts:signUp with the current ID token instead. Privileged Admin updates
    // remain available for account administration.
    if self_service
        && store.config().enable_improved_email_privacy
        && (plan.email.is_some() || plan.clear_email)
    {
        if plan
            .email
            .as_deref()
            .is_some_and(|email| !email.contains('@'))
        {
            return error(400, "INVALID_EMAIL");
        }
        return error(
            400,
            "OPERATION_NOT_ALLOWED : Please verify the new email before changing email.",
        );
    }
    if let Some(email) = &plan.email {
        if !store.config().allow_duplicate_emails
            && store
                .user_by_email(email)
                .is_some_and(|u| u.local_id != uid)
        {
            return error(400, "EMAIL_EXISTS");
        }
    }
    // Duplicate-email mode never gives an address two password accounts, judged on the state
    // this update produces, so neither the address nor the password can arrive second
    // (closure re-review 2026-09-24).
    let final_email = if plan.clear_email {
        None
    } else {
        plan.email
            .clone()
            .or_else(|| store.user(&uid).and_then(|u| u.email.clone()))
    };
    let final_password =
        plan.password.is_some() || (store.has_password(&uid) && !plan.clear_password);
    if final_password
        && (plan.email.is_some() || plan.password.is_some())
        && final_email.as_deref().is_some_and(|email| {
            store
                .users_by_email(email)
                .iter()
                .any(|other| other.local_id != uid && store.has_password(&other.local_id))
        })
    {
        return error(400, "EMAIL_EXISTS");
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
    // Every refusal a later step of this update can raise is decided here, before the first
    // write. The store calls below run in a fixed order (claims, providers, factors,
    // address, ...), so a condition checked only by the step that owns it would let the
    // steps ahead of it land and then return 400. The order of the checks is the order of
    // the writes they stand for, which keeps the error a request with several faults gets.
    if let Some(claims) = &plan.claims {
        if let Err(e) = claims.check_size() {
            return auth_error(&AuthError::LimitExceeded(e));
        }
    }
    if let Some(factors) = &plan.phone_factors {
        if let Err(e) = store.check_phone_factors(&uid, factors) {
            return mfa_error(&e);
        }
    }
    if let Some(email) = &plan.email {
        if let Err(e) = store.validate_email_update(&uid, email) {
            return auth_error(&e);
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
        let canonical_email = canonicalize_email(email);
        email_changed =
            store.user(&uid).and_then(|u| u.email.as_deref()) != Some(canonical_email.as_str());
        if let Err(e) = store.set_email(&uid, email) {
            return auth_error(&e);
        }
        // Production keeps emailVerified through an Admin email change (sandbox recording
        // 2026-09-23); an end-user change still starts unverified.
        if email_changed && self_service {
            if let Some(u) = store.user_mut(&uid) {
                u.email_verified = false;
            }
        }
    }
    if plan.clear_email {
        let verified = store.user(&uid).is_some_and(|u| u.email_verified);
        if let Err(e) = store.clear_email(&uid) {
            return auth_error(&e);
        }
        // An Admin email removal keeps emailVerified in production (sandbox recording
        // 2026-09-23, auth-account/admin/update#delete-email).
        if !self_service && verified {
            if let Some(u) = store.user_mut(&uid) {
                u.email_verified = true;
            }
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
        if let Err(e) = store.set_password_for(
            &uid,
            password,
            at,
            fireemu_core_auth::password_policy::Operation::Change,
        ) {
            return auth_error(&e);
        }
        // Setting a password over a session makes it a password session, so the session's
        // own credential change re-issues tokens. A privileged administrative update
        // (localId, no session) issues nothing: production returns no tokens for an
        // administrative password update, of an enabled account as of a disabled one
        // (auth-pending-trigger admin-password-update, recorded and approved 2026-09-12).
        if self_service {
            session_provider = Some(fireemu_core_auth::store::Provider::Password);
        }
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
    // Disable-only strict updates suspend use without destroying existing credentials,
    // matching the recorded disable/re-enable flow. Preserve the emulator's validSince
    // behavior, and keep credential changes and explicit revocation independent of disablement.
    let credentials_changed = plan.password.is_some() || email_changed || plan.revoke_at.is_some();
    let implicit_revocation = plan.password.is_some() || email_changed;
    if implicit_revocation || (stateless_refresh_tokens && plan.disable == Some(true)) {
        let _ = store.revoke_tokens(&uid, at);
    }
    // An administrator's validSince is stored as given, even when it is earlier than before;
    // sessions are judged against it when they are used (sandbox recording 2026-09-24). A
    // client update's validSince changes nothing (AUTH-ACCOUNT recording 2026-09-23,
    // privilege/valid-token-admin-fields#admin-readback-valid-since).
    if let Some(valid_since) = plan.revoke_at.filter(|_| !self_service) {
        let _ = store.set_valid_since(&uid, valid_since);
    }
    // A privileged password replacement or an explicit validSince advances `validSince` but
    // keeps the refresh-session record, so a session issued in the revocation second is not
    // older than the floored instant and older sessions fail as TOKEN_EXPIRED. Administrative
    // email changes still retire the session immediately. Credential-removal flags retain their
    // existing session behavior.
    let removes_refresh_credential = email_changed && !self_service;
    if !stateless_refresh_tokens && removes_refresh_credential {
        store.revoke_refresh_tokens(&uid);
    }
    // Production's Admin update answer carries no `newEmail` (sandbox recording 2026-09-23,
    // `auth-account/admin/update#change-email`).
    let new_email = store
        .user(&uid)
        .and_then(|u| u.email.clone())
        .filter(|_| email_changed && self_service);
    let mut response = account_update_answer(store, &uid, new_email.as_deref());
    // Tokens follow a credential change only for an account that is enabled after this
    // update: production (recorded 2026-09-12) applies an administrative password
    // replacement to a disabled account without returning tokens.
    let enabled_after = store.user(&uid).is_some_and(|u| !u.disabled);
    if credentials_changed && enabled_after {
        if let Some(provider) = session_provider {
            match issue_tokens_with(store, &uid, None, at, None, Some(provider)) {
                Ok(tokens) => {
                    // Production returns the refresh token and its lifetime only when the
                    // request asks with returnSecureToken (sandbox recording 2026-09-23).
                    let keys: &[&str] =
                        if body.get("returnSecureToken").and_then(Value::as_bool) == Some(true) {
                            &["idToken", "refreshToken", "expiresIn"]
                        } else {
                            &["idToken"]
                        };
                    for key in keys {
                        response[*key] = tokens[*key].clone();
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
    strict: bool,
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
        // As for lookup, a token whose account is gone is USER_NOT_FOUND.
        match verify_session_accepting(
            store,
            body,
            at,
            |e| {
                if matches!(e, fireemu_core_auth::jwt::JwtError::UnknownUser) {
                    error(400, "USER_NOT_FOUND")
                } else {
                    jwt_error(e)
                }
            },
            LegacyTokens::Honoured,
        ) {
            Ok(session) => session.uid,
            Err(r) => return r,
        }
    };
    let email = store.user(&uid).and_then(|u| u.email.clone());
    match store.delete_user_by_id_as(
        if admin {
            AuthPrincipal::Admin
        } else {
            AuthPrincipal::EndUser
        },
        uid.as_str(),
    ) {
        Ok(()) => {
            // Strict: a deleted account's codes are refused, inspected or used (sandbox
            // recording 2026-09-24); the official emulator keeps them.
            if strict {
                store.void_oob_codes_of(&uid, email.as_deref());
            }
            JsonResponse {
                status: 200,
                body: json!({"kind": "identitytoolkit#DeleteAccountResponse"}),
            }
        }
        Err(e) => auth_error(&e),
    }
}

/// The account an Admin create makes: a password account with an address, a phone account
/// with only a number (its sessions carry no anonymous `provider_id`, sandbox recording
/// 2026-09-24, generate/admin#phone-sign-in), and otherwise an anonymous one.
fn admin_new_user(email: Option<&str>, email_verified: bool, has_phone: bool) -> NewUser {
    match email {
        Some(email) => NewUser {
            email: Some(email.to_owned()),
            email_verified,
            provider: fireemu_core_auth::store::Provider::Password,
        },
        None if has_phone => NewUser {
            email: None,
            email_verified,
            provider: fireemu_core_auth::store::Provider::Phone,
        },
        None => NewUser::anonymous(),
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
        // Production's Admin create stores the number normalized and names the format problem
        // (sandbox recording 2026-09-23).
        let phone = opt_str(body, "phoneNumber")?
            .map(|p| {
                AuthStore::normalize_phone_number(p)
                    .map_err(|_| error(400, "INVALID_PHONE_NUMBER : Invalid format."))
            })
            .transpose()?;
        if let Some(p) = &phone {
            if store.user_by_phone(p).is_some() {
                return Err(error(400, "PHONE_NUMBER_EXISTS"));
            }
        }
        let factors = match body.get("mfaInfo") {
            None | Some(Value::Null) => Vec::new(),
            Some(v) => parse_phone_factors(v)?,
        };
        for field in ["displayName", "photoUrl"] {
            if let Some(value) = opt_str(body, field)? {
                reject_control_characters(value, field)?;
            }
        }
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
    if requested_id.as_deref().is_some_and(local_id_too_long) {
        return backend_internal_error();
    }
    let new_user = admin_new_user(email.as_deref(), email_verified, phone.is_some());
    let uid = match store.create_user_with_id_as(
        AuthPrincipal::Admin,
        new_user,
        requested_id.as_deref(),
        at,
    ) {
        Ok(uid) => uid,
        Err(e) => return auth_error(&e),
    };
    if let Some(password) = &password {
        if let Err(e) = store.set_password(&uid, password, at) {
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
        u.admin_created = true;
    }
    if let Err(e) = store.set_phone_factors(&uid, factors, at) {
        let _ = store.delete_user_by_id(uid.as_str());
        return mfa_error(&e);
    }
    JsonResponse {
        status: 200,
        // Production always carries `email` here, empty when the request gave none.
        body: json!({"kind": "identitytoolkit#SignupNewUserResponse", "localId": uid.as_str(), "email": email.as_deref().unwrap_or(""), "tenantId": store.tenant_id()}),
    }
}

/// Admin `accounts:batchDelete` (`deleteUsers`): up to 1000 ids; an enabled account is
/// skipped with a per-row error unless `force` is set (the Admin SDK always sets it); an
/// unknown id is silently skipped, as the official emulator does.
fn admin_batch_delete(store: &mut AuthStore, body: &Value, strict: bool) -> JsonResponse {
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
        let (uid, email) = (user.local_id.clone(), user.email.clone());
        if store.delete_user_by_id(id).is_ok() && strict {
            store.void_oob_codes_of(&uid, email.as_deref());
        }
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

/// Admin `accounts:query` (`queryAccounts`): count or a bounded, field-sorted page.
/// The Firebase profile preserves its unimplemented expression/ignored paging behavior.
/// Strict mode accepts the typed `SqlExpression` shape, with an explicit local exact-union policy.
fn admin_query(store: &AuthStore, body: &Value, limits: AuthQueryLimits) -> JsonResponse {
    let expressions = if limits == AuthQueryLimits::ProductionBounded {
        match parse_admin_query_expressions(body) {
            Ok(expressions) => expressions,
            Err(response) => return response,
        }
    } else {
        if body
            .get("expression")
            .and_then(Value::as_array)
            .is_some_and(|e| !e.is_empty())
        {
            return not_implemented("expression is not implemented.");
        }
        Vec::new()
    };
    let return_user_info = if limits == AuthQueryLimits::ProductionBounded {
        match opt_bool(body, "returnUserInfo") {
            Ok(value) => value.unwrap_or(true),
            Err(response) => return response,
        }
    } else {
        body.get("returnUserInfo").and_then(Value::as_bool) != Some(false)
    };
    let sort = if limits == AuthQueryLimits::ProductionBounded {
        match validate_production_admin_query_enums(body) {
            Ok(sort) => sort,
            Err(response) => return response,
        }
    } else {
        UserSortField::LocalId
    };
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
            body: json!({"recordsCount": store.matching_user_count(&expressions).to_string()}),
        };
    }
    if limits == AuthQueryLimits::ProductionBounded {
        return production_admin_query_page(store, body, sort, &expressions);
    }
    let mut ids = store.all_user_ids();
    if str_field(body, "order") == Some("DESC") {
        ids.reverse();
    }
    let users: Vec<Value> = ids.iter().map(|uid| user_json(store, uid)).collect();
    JsonResponse {
        status: 200,
        body: json!({"recordsCount": store.user_count().to_string(), "userInfo": users}),
    }
}

/// Decode `SqlExpression`, not a SQL string. Validate every field before applying the
/// documented priority email > phoneNumber > userId. Unrecognized or mistyped selectors are
/// refused; an empty one is no constraint, as production answers it. Limits below are local
/// parser safety limits, not claimed Identity Platform quotas.
fn parse_admin_query_expressions(body: &Value) -> Result<Vec<UserQueryExpression>, JsonResponse> {
    const MAX_EXPRESSIONS: usize = 128;
    const MAX_SELECTOR_BYTES: usize = 4_096;
    let expressions = match body.get("expression") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(expressions)) if expressions.len() <= MAX_EXPRESSIONS => expressions,
        _ => return Err(error(400, "INVALID_ARGUMENT : invalid expression array")),
    };
    let mut result = Vec::new();
    for expression in expressions {
        let Some(object) = expression.as_object() else {
            return Err(error(
                400,
                "INVALID_ARGUMENT : expression must be an object",
            ));
        };
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "email" | "phoneNumber" | "userId"))
        {
            return Err(error(400, "INVALID_ARGUMENT : unknown expression field"));
        }
        // JSON null is an unset proto scalar; every supplied non-null value is typed,
        // including a lower-priority selector that will not be used for matching.
        for value in object.values() {
            if !value.is_null()
                && !value.as_str().is_some_and(|text| {
                    text.len() <= MAX_SELECTOR_BYTES && !text.chars().any(char::is_control)
                })
            {
                return Err(error(400, "INVALID_ARGUMENT : invalid expression selector"));
            }
        }
        // The first non-empty selector in email > phoneNumber > userId order; none at all is
        // no constraint, as production answers it (sandbox recording 2026-09-23,
        // expression-empty-item and expression-empty-string).
        let non_empty = |key: &str| str_field(expression, key).filter(|v| !v.is_empty());
        let selected = non_empty("email")
            .map(|email| UserQueryExpression::Email(canonicalize_email(email)))
            .or_else(|| {
                non_empty("phoneNumber")
                    .map(|phone| UserQueryExpression::PhoneNumber(phone.to_owned()))
            })
            .or_else(|| non_empty("userId").map(|id| UserQueryExpression::UserId(id.to_owned())));
        result.push(selected);
    }
    // Production evaluates only the first expression (sandbox recording 2026-09-23,
    // auth-account/admin/query#expression-two); every item is still type-checked above.
    Ok(result.into_iter().next().flatten().into_iter().collect())
}

fn production_admin_query_page(
    store: &AuthStore,
    body: &Value,
    sort: UserSortField,
    expressions: &[UserQueryExpression],
) -> JsonResponse {
    // Enum fields were validated before the count-only branch in `admin_query`.
    let descending = str_field(body, "order") == Some("DESC");
    // Production accepts a limit above 500 (sandbox recording 2026-09-23); the upper bound
    // here is a local guard, not an observed quota.
    let limit = match query_i64(body, "limit", 500) {
        Ok(limit @ 0..=10_000) => usize::try_from(limit).unwrap_or(500),
        Ok(_) | Err(()) => return error(400, "INVALID_ARGUMENT : invalid limit"),
    };
    let offset = match query_i64(body, "offset", 0) {
        Ok(offset @ 0..) => match usize::try_from(offset) {
            Ok(offset) => offset,
            Err(_) => return error(400, "INVALID_ARGUMENT : invalid offset"),
        },
        // Production fails a negative offset internally (corpus v2 recording 2026-09-24).
        Ok(_) => return backend_internal_error(),
        Err(()) => return error(400, "INVALID_ARGUMENT : invalid offset"),
    };
    let page = store.users_matching_sorted_page(expressions, sort, offset, limit, descending);
    let users = page
        .iter()
        .map(|user| user_json(store, &user.local_id))
        .collect::<Vec<_>>();
    // An empty page carries no `userInfo` (sandbox recording 2026-09-23, limit-0).
    let mut body = json!({"recordsCount": users.len().to_string()});
    if !users.is_empty() {
        body["userInfo"] = Value::Array(users);
    }
    JsonResponse { status: 200, body }
}

fn validate_production_admin_query_enums(body: &Value) -> Result<UserSortField, JsonResponse> {
    let sort = match opt_str(body, "sortBy") {
        Ok(None | Some("SORT_BY_FIELD_UNSPECIFIED" | "USER_ID")) => UserSortField::LocalId,
        Ok(Some("NAME")) => UserSortField::Name,
        Ok(Some("CREATED_AT")) => UserSortField::CreatedAt,
        Ok(Some("LAST_LOGIN_AT")) => UserSortField::LastLoginAt,
        Ok(Some("USER_EMAIL")) => UserSortField::Email,
        Ok(Some(other)) => {
            return Err(proto_field_error(
                "sort_by",
                &format!("Invalid value at 'sort_by' (type.googleapis.com/google.cloud.identitytoolkit.v1.QueryUserInfoRequest.SortByField), {other:?}"),
            ))
        }
        Err(_) => return Err(error(400, "INVALID_ARGUMENT : invalid sortBy")),
    };
    match opt_str(body, "order") {
        Ok(None | Some("ORDER_UNSPECIFIED" | "ASC" | "DESC")) => Ok(sort),
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
fn create_session_cookie(
    store: &AuthStore,
    body: &Value,
    at: LogicalInstant,
    strict: bool,
) -> JsonResponse {
    // Strict: `validDuration` is an int64 decoded with the request; an omitted one is the maximum
    // and any other value, zero included, must lie within the bounds (sandbox recording
    // 2026-09-24). Emulator: the official emulator's `Number(v) || two weeks`.
    let valid_duration = match body.get("validDuration") {
        None | Some(Value::Null) => SESSION_COOKIE_MAX_SECONDS,
        Some(value) if !strict => emulator_valid_duration(value),
        Some(value) => {
            let decoded = match value {
                Value::String(text) => text.parse::<i64>().ok(),
                Value::Number(n) => n.as_i64(),
                _ => None,
            };
            let Some(decoded) = decoded else {
                return proto_field_error(
                    "valid_duration",
                    &format!("Invalid value at 'valid_duration' (TYPE_INT64), {value}"),
                );
            };
            decoded
        }
    };
    let token = match body.get("idToken") {
        None | Some(Value::Null) => return error(400, "MISSING_ID_TOKEN"),
        Some(Value::String(t)) => t.as_str(),
        Some(_) => return error(400, "INVALID_ID_TOKEN"),
    };
    if !(SESSION_COOKIE_MIN_SECONDS..=SESSION_COOKIE_MAX_SECONDS).contains(&valid_duration) {
        return error(400, "INVALID_DURATION");
    }
    let (_, decoded) = match fireemu_core_auth::jwt::verify_id_token_decoded_with_leeway(
        token,
        store,
        at,
        fireemu_core_auth::jwt::IDENTITY_TOOLKIT_EXPIRY_LEEWAY_SECONDS,
    ) {
        Ok(v) => v,
        // A deleted account's token names nobody (sandbox recording 2026-09-24).
        Err(JwtError::UnknownUser) => return error(400, "USER_NOT_FOUND"),
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
    let cookie = fireemu_core_auth::jwt::encode_payload_shaped(
        &payload.to_string(),
        None,
        HeaderShape::Untyped,
    );
    JsonResponse {
        status: 200,
        body: json!({"sessionCookie": cookie}),
    }
}

/// The official emulator's `Number(validDuration) || two weeks`, in whole seconds: zero, blank
/// text and a value that is not a number mean the maximum, and a fraction is truncated as the
/// emulator's signer truncates the resulting expiry.
fn emulator_valid_duration(value: &Value) -> i64 {
    let number = match value {
        Value::Number(n) => n.as_f64(),
        Value::String(text) => text.trim().parse::<f64>().ok(),
        Value::Bool(flag) => Some(if *flag { 1.0 } else { 0.0 }),
        _ => None,
    }
    .filter(|n| n.is_finite() && *n != 0.0);
    // A float-to-integer `as` saturates, so an enormous value stays out of range, as it is.
    #[allow(clippy::cast_possible_truncation)]
    number.map_or(SESSION_COOKIE_MAX_SECONDS, |n| n.trunc() as i64)
}

/// `application/x-www-form-urlencoded` query decoding through the shared codec: `+` is a
/// space and only two ASCII hexadecimal digits form an escape, so `%+f` stays literal.
fn decode_query_component(s: &str) -> String {
    fireemu_core_types::codec::percent_decode(s, fireemu_core_types::codec::PlusMode::Space)
}

fn query_params(query: Option<&str>) -> BTreeMap<String, String> {
    query
        .unwrap_or("")
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (decode_query_component(k), decode_query_component(v)),
            None => (decode_query_component(kv), String::new()),
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
        AuthStore::validate_imported_password(raw).map_err(|e| auth_error(&e))?;
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
    AuthStore::validate_password(password).map_err(|e| auth_error(&e))?;
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

fn validate_batch_row_shapes(row: &Value) -> Result<(), JsonResponse> {
    for key in ["mfaInfo", "providerUserInfo"] {
        match row.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::Array(items)) => {
                if items.iter().any(|item| !item.is_object()) {
                    return Err(error(
                        400,
                        &format!("INVALID_ARGUMENT : {key} entries must be objects"),
                    ));
                }
            }
            Some(_) => {
                return Err(error(
                    400,
                    &format!("INVALID_ARGUMENT : {key} must be an array"),
                ));
            }
        }
    }
    for key in ["createdAt", "lastLoginAt"] {
        let Some(value) = row.get(key) else {
            continue;
        };
        let valid = match value {
            Value::Null => true,
            Value::String(value) => value.parse::<i64>().is_ok(),
            Value::Number(value) => value.as_i64().is_some(),
            _ => false,
        };
        if !valid {
            return Err(error(
                400,
                &format!("INVALID_ARGUMENT : {key} must be a millisecond timestamp"),
            ));
        }
    }
    Ok(())
}

/// The second factors of a `batchCreate` row: phone factors as the official emulator
/// imports them, and TOTP factors in fireemu's own export shape
/// (`totpInfo.sharedSecretKey`), which the official emulator has no equivalent for.
///
/// Under production's second-factor rules every TOTP factor is refused with production's words
/// and a factor without an id or a time takes [`AuthStore::imported_factor_defaults`].
fn batch_row_factors(
    row: &Value,
    local_id: &str,
    has_email: bool,
    email_verified: bool,
    at: LogicalInstant,
    store: &mut AuthStore,
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
        if store.second_factor_rules_are_production()
            && item.get("totpInfo").is_some_and(|v| !v.is_null())
        {
            return Err(error(400, "Importing TOTP MFA is not supported."));
        }
        let (default_id, default_at) = store
            .imported_factor_defaults(at)
            .unwrap_or_else(|| (format!("{local_id}-mfa-{index}"), at));
        let enrollment_id = opt_str(item, "mfaEnrollmentId")?
            .filter(|id| !id.is_empty())
            .map_or(default_id, str::to_owned);
        let display_name = opt_str(item, "displayName")?.map(str::to_owned);
        let enrolled_at = opt_str(item, "enrolledAt")?
            .and_then(|t| LogicalInstant::parse_rfc3339(t).ok())
            .unwrap_or(default_at);
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
    hash_spec: Option<&password_hash::HashSpec>,
    store: &mut AuthStore,
) -> Result<fireemu_core_auth::store::ImportedUser, JsonResponse> {
    use fireemu_core_auth::store::{ImportedUser, Provider};
    validate_batch_row_shapes(row)?;
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
        batch_row_factors(row, local_id, email.is_some(), email_verified, at, store)?;
    let password = batch_row_password(row)?;
    let imported_password = if password.is_none() {
        batch_row_imported_hash(row, hash_spec)?
    } else {
        None
    };
    let provider = if password.is_some() || imported_password.is_some() || email.is_some() {
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
        last_refresh_at: str_field(row, "lastRefreshAt")
            .and_then(|v| LogicalInstant::parse_rfc3339(v).ok()),
        tokens_valid_after: at,
        federated,
        password,
        imported_password,
        allow_shared_email: true,
        totp_factors,
        phone_factors,
    })
}

/// A row's `passwordHash` (and `salt`) under the request's hash algorithm, kept for the
/// adapter's verifier. A row without a hash has no password credential.
fn batch_row_imported_hash(
    row: &Value,
    spec: Option<&password_hash::HashSpec>,
) -> Result<Option<fireemu_core_auth::store::ImportedPasswordHash>, JsonResponse> {
    let Some(hash) = opt_str(row, "passwordHash")? else {
        return Ok(None);
    };
    let hash =
        password_hash::base64_decode(hash).ok_or_else(|| error(400, "INVALID_PASSWORD_HASH"))?;
    // proto3 reads empty bytes as unset: an empty hash is no password credential (external
    // review 2026-09-24; unobserved in production).
    if hash.is_empty() {
        return Ok(None);
    }
    let salt = match opt_str(row, "salt")? {
        Some(salt) => {
            password_hash::base64_decode(salt).ok_or_else(|| error(400, "INVALID_SALT"))?
        }
        None => Vec::new(),
    };
    // Without `hashAlgorithm` production still keeps the hash as the password credential;
    // no password ever matches it.
    Ok(Some(fireemu_core_auth::store::ImportedPasswordHash {
        spec: spec.map_or_else(
            || password_hash::UNSPECIFIED_SPEC.to_owned(),
            password_hash::encode,
        ),
        hash,
        salt,
    }))
}

/// Admin `accounts:batchCreate` (`importUsers`): every row is attempted, and a refused row
/// is reported by index in `error` while the others are created, which is the official
/// contract of the route. With `allowOverwrite` an existing account of the same `localId`
/// is replaced; without it the row is refused.
/// Bytes and int64 fields of `batchCreate` rows are decoded with the request, before anything
/// else is validated; a malformed one refuses the whole request.
fn decode_batch_rows(rows: &[Value]) -> Result<(), JsonResponse> {
    for (index, row) in rows.iter().enumerate() {
        for (key, field) in [
            ("createdAt", "created_at"),
            ("lastLoginAt", "last_login_at"),
        ] {
            let decodes = match row.get(key) {
                None | Some(Value::Null) => true,
                Some(Value::Number(n)) => n.is_i64(),
                Some(Value::String(text)) => text.parse::<i64>().is_ok(),
                Some(_) => false,
            };
            if !decodes {
                let field = format!("users[{index}].{field}");
                let value = row.get(key).map(Value::to_string).unwrap_or_default();
                return Err(proto_field_error(
                    &field,
                    &format!("Invalid value at '{field}' (TYPE_INT64), {value}"),
                ));
            }
        }
        for (key, field) in [("passwordHash", "password"), ("salt", "salt")] {
            if let Some(text) = row.get(key).and_then(Value::as_str) {
                if !text.starts_with("fakeHash:") && password_hash::base64_decode(text).is_none() {
                    let field = format!("users[{index}].{field}");
                    return Err(proto_field_error(
                        &field,
                        &format!("Invalid value at '{field}' (TYPE_BYTES), Base64 decoding failed for {text:?}"),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn admin_batch_create(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let Some(rows) = body
        .get("users")
        .and_then(Value::as_array)
        .filter(|r| !r.is_empty())
    else {
        return error(400, "MISSING_USER_ACCOUNT");
    };
    let allow_overwrite = match body.get("allowOverwrite") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return error(400, "INVALID_ARGUMENT : allowOverwrite must be a boolean"),
    };
    // Production upserts rows by localId whatever allowOverwrite says: a repeated localId in
    // the request is replaced by its later row and an existing account is replaced without an
    // error (sandbox recording 2026-09-23). The field is still type-checked above.
    let _ = allow_overwrite;
    // sanityCheck refuses an address repeated inside the request, before anything is imported.
    if body.get("sanityCheck").and_then(Value::as_bool) == Some(true) {
        let mut seen = std::collections::BTreeSet::new();
        for row in rows {
            if let Some(email) = str_field(row, "email").filter(|e| !e.is_empty()) {
                if !seen.insert(canonicalize_email(email)) {
                    return error(400, &format!("DUPLICATE_EMAIL : {email}"));
                }
            }
        }
    }
    if let Err(response) = decode_batch_rows(rows) {
        return response;
    }
    // The hash algorithm and its parameters apply to every row of the request; production
    // refuses the whole request when they are invalid.
    let hash_spec = match body.get("hashAlgorithm") {
        None | Some(Value::Null) => None,
        Some(_) => match password_hash::spec_from_options(body) {
            Ok(spec) => Some(spec),
            Err(code) => return error(400, code),
        },
    };
    let mut errors = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let refused = |message: String| json!({"index": index, "message": message});
        let user = match batch_row_user(row, at, hash_spec.as_ref(), store) {
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
        let imported_password = user.imported_password.is_some() || user.password.is_some();
        let import_result = if store.user_by_id(&user.local_id).is_some() {
            // Validate and install a replacement on a copy first. A row can fail after the
            // UID collision check (for example because its email belongs to another account),
            // and a failed import must leave the existing account untouched.
            let mut replacement = store.clone();
            let _ = replacement.delete_user_by_id(&user.local_id);
            match replacement.import_user(user) {
                Ok(uid) => {
                    *store = replacement;
                    Ok(uid)
                }
                Err(error) => Err(error),
            }
        } else {
            store.import_user(user)
        };
        match import_result {
            // Production stamps an imported password, raw or hashed, with the import time.
            Ok(uid) if imported_password => store.set_password_updated_at(&uid, at),
            Ok(_) => {}
            Err(e) => errors.push(refused(e.to_string())),
        }
    }
    JsonResponse {
        status: 200,
        // Production omits `error` when every row was imported.
        body: if errors.is_empty() {
            json!({"kind": "identitytoolkit#UploadAccountResponse"})
        } else {
            json!({"kind": "identitytoolkit#UploadAccountResponse", "error": errors})
        },
    }
}

/// Admin `accounts:batchGet` (`listUsers`): `GET ?maxResults=&nextPageToken=`, users in
/// user-id order; the page token is the last user id of the page.
fn admin_batch_get(store: &AuthStore, query: Option<&str>, body: &Value) -> JsonResponse {
    let params = query_params(query);
    let max_text = params.get("maxResults").cloned().or_else(|| {
        body.get("maxResults").map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    });
    // Production answers maxResults 0 with no users and caps larger values at 1000 (sandbox
    // recording 2026-09-23).
    let max = match max_text.as_deref() {
        None => 1_000usize,
        Some(t) => match t.parse::<usize>() {
            Ok(n) => n.min(1_000),
            Err(_) => return error(400, "INVALID_ARGUMENT : maxResults must be a number"),
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
    // The page token is the last user id of the previous page; production reads any other
    // string the same way (sandbox recording 2026-09-23).
    let page: Vec<&fireemu_core_auth::store::UserRecord> =
        store.users_after_local_id(token.as_deref(), max.saturating_add(1));
    let has_more = page.len() > max;
    let page = &page[..page.len().min(max)];
    // The Admin download carries the stored hash material production returns to a caller that
    // may read it: fireemu's own digest and salt, and hash version 0.
    let users: Vec<Value> = page
        .iter()
        .map(|u| {
            let mut user = user_json(store, &u.local_id);
            if let Some(digest) = store.password_digest(&u.local_id) {
                let (hash, salt) = digest.stored_material();
                user["passwordHash"] = json!(fireemu_core_types::hash::base64_standard(&hash));
                user["salt"] = json!(fireemu_core_types::hash::base64_standard(&salt));
                user["version"] = json!(0);
            }
            user
        })
        .collect();
    let mut response = json!({"kind": "identitytoolkit#DownloadAccountResponse"});
    if !users.is_empty() {
        response["users"] = json!(users);
    }
    if has_more {
        if let Some(last) = page.last() {
            response["nextPageToken"] = Value::String(last.local_id.as_str().to_owned());
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
/// factor, an unverified email, and a number already enrolled on the account. TOTP finalize
/// applies the email check before consuming its pending state; phone finalize keeps its
/// phone-code validation order. None of these refusals has a side effect.
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

/// The session of an MFA enrollment request. The v2 enrollment routes answer a missing
/// `idToken` with `INVALID_ID_TOKEN` in production (conformance/auth-production-matrix.json,
/// tokens/errors#mfa-enrollment-start-without-token); the official emulator says
/// `MISSING_ID_TOKEN`.
fn verify_enrollment_session(
    store: &AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> Result<Session, JsonResponse> {
    if matches!(body.get("idToken"), None | Some(Value::Null)) {
        return Err(error(400, "INVALID_ID_TOKEN"));
    }
    verify_session_accepting(store, body, at, jwt_error, LegacyTokens::Honoured)
}

/// Production's answers to an enrollment start's shape and to a full phone slate (sandbox
/// recording 2026-09-24, auth-mfa/totp/enroll#start-without-info,
/// interactions#start-both-kinds and #phone-start-at-limit).
fn production_enrollment_start_refusal(
    store: &AuthStore,
    uid: &LocalId,
    body: &Value,
) -> Option<JsonResponse> {
    let totp = body.get("totpEnrollmentInfo").is_some_and(|v| !v.is_null());
    let phone = body
        .get("phoneEnrollmentInfo")
        .is_some_and(|v| !v.is_null());
    if totp && phone {
        return Some(oneof_already_set("enrollment_info", "phoneEnrollmentInfo"));
    }
    if !totp && !phone {
        return Some(error(400, "Request contains an invalid argument."));
    }
    let full = store
        .user(uid)
        .is_some_and(|u| u.mfa.factor_count() >= fireemu_core_auth::mfa::MAX_FACTORS_PER_USER);
    (phone && full).then(|| {
        error(
            400,
            "SECOND_FACTOR_LIMIT_EXCEEDED : Too many second factors enrolled for this account.",
        )
    })
}

fn mfa_enrollment_start(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    totp_extension_enabled: bool,
    strict: bool,
) -> JsonResponse {
    let session = match verify_enrollment_session(store, body, at) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let uid = session.uid.clone();
    // Production's second-factor rules (strict, outside tenants, whose second factors keep
    // their earlier rules under scope decision M2).
    let production = store.second_factor_rules_are_production();
    if production {
        if let Some(refusal) = production_enrollment_start_refusal(store, &uid, body) {
            return refusal;
        }
    }
    if let Some(phone) = body.get("phoneEnrollmentInfo") {
        // Strict: production refuses a phone factor while the project does not enable SMS
        // second factors (sandbox recording 2026-09-24, auth-mfa/disabled#phone-start); the
        // official emulator always enrolls one.
        if production && !store.mfa_config().sms_enabled() {
            return error(400, "OPERATION_NOT_ALLOWED : SMS based MFA not enabled.");
        }
        let number = str_field(phone, "phoneNumber").unwrap_or("");
        if let Some(refusal) = phone_enrollment_refusal(store, &session, Some(number), true) {
            return refusal;
        }
        return match store.send_verification_code(
            number,
            VerificationPurpose::Enrollment { uid },
            at,
        ) {
            Ok(code) => {
                announce_phone_code(store, &code, PhoneCodeUse::MfaEnrollment);
                JsonResponse {
                    status: 200,
                    body: json!({"phoneSessionInfo": {"sessionInfo": code.session_info}}),
                }
            }
            Err(e) => auth_error(&e),
        };
    }
    if body.get("totpEnrollmentInfo").is_none() {
        return error(
            400,
            "INVALID_ARGUMENT : totpEnrollmentInfo or phoneEnrollmentInfo is required",
        );
    }
    // TOTP is on when the project's `mfa` config enables it (production). The fireemu
    // `auth.totp` extension turns it on too, except under production's rules, where only the
    // project config does (`auth-mfa/disabled#totp-start`; AUTH-MFA follow-up directive).
    let extension = totp_extension_enabled && !production;
    if !extension && !store.mfa_config().totp_enabled() {
        return error(
            400,
            if strict {
                "OPERATION_NOT_ALLOWED : TOTP based MFA not enabled."
            } else {
                "INVALID_ARGUMENT : ((Missing phoneEnrollmentInfo.))"
            },
        );
    }
    if let Some(refusal) = phone_enrollment_refusal(store, &session, None, true) {
        return refusal;
    }
    if session
        .auth_time
        .is_some_and(|auth_time| store.totp_enrollment_login_too_old(auth_time, at))
    {
        return error(400, "CREDENTIAL_TOO_OLD_LOGIN_AGAIN");
    }
    match store.start_totp_enrollment(&uid, at) {
        Ok(material) => {
            let policy = *store.policy();
            JsonResponse {
                status: 200,
                // Production's members: `SHA1` and a deadline in microseconds (sandbox
                // recording 2026-09-24, auth-mfa/totp/enroll#start).
                body: json!({
                    "totpSessionInfo": {
                        "sharedSecretKey": base32::encode(material.secret_for_test()),
                        "verificationCodeLength": policy.digits,
                        "hashingAlgorithm": "SHA1",
                        "periodSec": policy.period_seconds,
                        "sessionInfo": material.session_id,
                        "finalizeEnrollmentTime": proto_timestamp(LogicalInstant::from_nanos(
                            material.expires_at.as_nanos().div_euclid(1_000) * 1_000,
                        )),
                    }
                }),
            }
        }
        Err(e) if production && matches!(e, MfaError::LimitExceeded(_)) => error(
            400,
            "SECOND_FACTOR_LIMIT_EXCEEDED : Too many TOTP based second factors enrolled for this account.",
        ),
        Err(e) => mfa_error(&e),
    }
}

/// Production's parse-time refusal of a second member of a oneof (sandbox recording
/// 2026-09-24, auth-mfa/interactions#start-both-kinds).
fn oneof_already_set(oneof: &str, member: &str) -> JsonResponse {
    let message = format!(
        "Invalid value (oneof), oneof field '{oneof}' is already set. Cannot set '{member}'"
    );
    JsonResponse {
        status: 400,
        body: json!({"error": {
            "code": 400,
            "message": message,
            "status": "INVALID_ARGUMENT",
            "details": [{
                "@type": "type.googleapis.com/google.rpc.BadRequest",
                "fieldViolations": [{"description": message}],
            }],
        }}),
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
    let session = match verify_enrollment_session(store, body, at) {
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
    if let Some(refusal) = phone_enrollment_refusal(store, &session, None, true) {
        return refusal;
    }
    let info = body.get("totpVerificationInfo");
    let session = info
        .and_then(|i| i.get("sessionInfo"))
        .and_then(Value::as_str);
    let display_name = str_field(body, "displayName")
        .filter(|name| !name.is_empty())
        .map(str::to_owned);
    // Production checks the session, then the display name, then the code (sandbox recording
    // 2026-09-24, auth-mfa/totp/enroll#finalize-missing-session and #finalize-missing-code);
    // tenants keep their earlier rules (scope decision M2).
    let production = store.second_factor_rules_are_production();
    if production {
        if session.is_none_or(|session| !store.has_enrollment_session(&uid, session)) {
            return error(400, "INVALID_SESSION_INFO");
        }
        if display_name.is_none() {
            return error(400, "MISSING_DISPLAY_NAME : display name cannot be empty");
        }
    }
    let code = parse_code(info.and_then(|i| i.get("verificationCode")));
    let (Some(session), Some(code)) = (session, code) else {
        return error(
            400,
            "INVALID_CODE : missing sessionInfo or verificationCode",
        );
    };
    match store.finalize_totp_enrollment_named(&uid, session, code, display_name, at) {
        Ok(factor) => {
            let assertion = SecondFactorAssertion {
                sign_in_second_factor: "totp".to_owned(),
                second_factor_identifier: factor.mfa_enrollment_id.clone(),
                verified_at: at,
            };
            match issue_tokens(store, &uid, Some(&assertion), at) {
                Ok(tokens) => {
                    let mut response = token_only_response(&tokens, false);
                    // Production's TOTP answer names its factor kind (sandbox recording
                    // 2026-09-24, auth-mfa/totp/enroll#finalize).
                    if production {
                        response.body["totpAuthInfo"] = json!({});
                    }
                    response
                }
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
    let Some(enrollment_id) = str_field(body, "mfaEnrollmentId").filter(|id| !id.is_empty()) else {
        return error(
            400,
            "MISSING_MFA_ENROLLMENT_ID : No second factor identifier is provided.",
        );
    };
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
    let first_factor = store.pending_sign_in_context(&pending_id).cloned();
    match store.finalize_mfa_sign_in_for_factor(&uid, &pending_id, enrollment_id, code, at) {
        Ok(assertion) => match issue_tokens_with_sign_in_attributes(
            store,
            &uid,
            Some(&assertion),
            at,
            None,
            first_factor
                .as_ref()
                .and_then(PendingSignInContext::sign_in_provider)
                .map(provider_from_id),
            first_factor
                .as_ref()
                .and_then(PendingSignInContext::sign_in_attributes),
        ) {
            Ok(tokens) => token_only_response(&tokens, false),
            Err(r) => r,
        },
        Err(e) => mfa_error(&e),
    }
}

/// Strict `mfaSignIn:finalize`: production's refusals and their order (sandbox recording
/// 2026-09-24, auth-mfa/totp/sign-in, interactions): the request's shape first (`Request
/// contains an invalid argument.`), then the pending credential (`INVALID_PENDING_TOKEN`, or
/// `USER_NOT_FOUND` once its account is gone), then the factor (`INVALID_MFA_ENROLLMENT_ID`),
/// then the code. The store keeps the pending credential after success and completes the
/// sign-in of an account disabled after its first factor, as production does.
fn mfa_sign_in_finalize_production(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> JsonResponse {
    let invalid = || error(400, "Request contains an invalid argument.");
    let Some(pending) = str_field(body, "mfaPendingCredential").filter(|p| !p.is_empty()) else {
        return invalid();
    };
    if let Some(phone) = body.get("phoneVerificationInfo").filter(|v| !v.is_null()) {
        return finalize_phone_sign_in(store, pending, phone, at);
    }
    let Some(enrollment_id) = str_field(body, "mfaEnrollmentId").filter(|id| !id.is_empty()) else {
        return invalid();
    };
    let Some(code) = parse_code(
        body.get("totpVerificationInfo")
            .and_then(|i| i.get("verificationCode")),
    ) else {
        return invalid();
    };
    let Some(pending_id) = PendingSignInId::parse(pending) else {
        return error(400, "INVALID_PENDING_TOKEN");
    };
    let Some(uid) = store.pending_sign_in_user(&pending_id) else {
        return error(
            400,
            if store.pending_sign_in_orphaned(&pending_id) {
                "USER_NOT_FOUND"
            } else {
                "INVALID_PENDING_TOKEN"
            },
        );
    };
    if !store.user(&uid).is_some_and(|u| {
        u.mfa
            .totp_factors()
            .iter()
            .any(|f| f.mfa_enrollment_id == enrollment_id)
    }) {
        return error(400, "INVALID_MFA_ENROLLMENT_ID");
    }
    let first_factor = store.pending_sign_in_context(&pending_id).cloned();
    match store.finalize_mfa_sign_in_for_factor(&uid, &pending_id, enrollment_id, code, at) {
        Ok(assertion) => match issue_tokens_with_sign_in_attributes(
            store,
            &uid,
            Some(&assertion),
            at,
            None,
            first_factor
                .as_ref()
                .and_then(PendingSignInContext::sign_in_provider)
                .map(provider_from_id),
            first_factor
                .as_ref()
                .and_then(PendingSignInContext::sign_in_attributes),
        ) {
            Ok(tokens) => token_only_response(&tokens, false),
            Err(r) => r,
        },
        // A code already used is a plain INVALID_CODE (auth-mfa/totp/sign-in
        // #replayed-sign-in-code).
        Err(MfaError::CodeAlreadyUsed) => error(400, "INVALID_CODE"),
        Err(e) => mfa_error(&e),
    }
}

fn refresh(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    stateless_refresh_tokens: bool,
) -> JsonResponse {
    // An empty field is an absent one, as proto3 reads it (sandbox recording 2026-09-24).
    match str_field(body, "grant_type") {
        None | Some("") => return error(400, "MISSING_GRANT_TYPE"),
        Some("refresh_token") => {}
        Some(_) => return error(400, "INVALID_GRANT_TYPE"),
    }
    let Some(token) = str_field(body, "refresh_token").filter(|token| !token.is_empty()) else {
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
                    "project_id": store.project_number().map_or_else(|| store.project_id().to_owned(), |number| number.to_string()),
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
    // Production writes a factor's time as a protobuf Timestamp and lists factors in the order
    // they were enrolled, whatever their kind (sandbox recording 2026-09-24,
    // auth-mfa/admin-factors#admin-lookup-m).
    let strict = store.second_factor_rules_are_production();
    let time = |at: LogicalInstant| {
        if strict {
            proto_timestamp(at)
        } else {
            LogicalInstant::to_rfc3339(at).unwrap_or_default()
        }
    };
    let mut entries: Vec<(LogicalInstant, Value)> = u
        .mfa
        .totp_factors()
        .iter()
        .map(|f| (f.enrolled_at, json!({"mfaEnrollmentId": f.mfa_enrollment_id, "displayName": f.display_name, "enrolledAt": time(f.enrolled_at), "totpInfo": {}})))
        .collect();
    entries.extend(u.mfa.phone_factors().iter().map(|f| {
        let phone = if redacted {
            obfuscate_phone_number(&f.phone_number)
        } else {
            f.phone_number.clone()
        };
        (f.enrolled_at, json!({"mfaEnrollmentId": f.mfa_enrollment_id, "displayName": f.display_name, "enrolledAt": time(f.enrolled_at), "phoneInfo": phone}))
    }));
    entries.sort_by_key(|(at, _)| *at);
    entries.into_iter().map(|(_, entry)| entry).collect()
}

/// An instant as protobuf's JSON Timestamp: RFC 3339 with 0, 3, 6 or 9 fraction digits, the
/// fewest that keep its precision.
fn proto_timestamp(at: LogicalInstant) -> String {
    let full = LogicalInstant::to_rfc3339(at).unwrap_or_default();
    let Some(body) = full.strip_suffix('Z') else {
        return full;
    };
    let (seconds, fraction) = body.split_once('.').unwrap_or((body, ""));
    let mut fraction: String = fraction
        .chars()
        .chain(std::iter::repeat('0'))
        .take(9)
        .collect();
    while !fraction.is_empty() && fraction.ends_with("000") {
        fraction.truncate(fraction.len() - 3);
    }
    if fraction.is_empty() {
        format!("{seconds}Z")
    } else {
        format!("{seconds}.{fraction}Z")
    }
}

/// The action link of an email action (what the Emulator's console prints).
fn oob_link(
    headers: &RequestHeaders,
    request_type: OobRequestType,
    code: &str,
    body: &Value,
    tenant: Option<&str>,
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
    // A tenant's link names the tenant, as the official emulator's TenantProjectState does.
    if let Some(tenant) = tenant {
        link.push_str("&tenantId=");
        link.push_str(&percent_encode(tenant));
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
// Keep authorization, target selection and credential issuance in one auditable flow.
#[allow(clippy::too_many_lines)]
fn send_oob_code(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    headers: &RequestHeaders,
    privileged: bool,
    strict: bool,
) -> JsonResponse {
    let return_oob_link = match opt_bool(body, "returnOobLink") {
        Ok(Some(value)) => value,
        Ok(None) => false,
        Err(response) => return response,
    };
    // Only the authenticated Admin route may return a credential to the caller. Checked before
    // a code is created or a delivery notice emitted; production and the official emulator
    // answer INSUFFICIENT_PERMISSION (sandbox recording 2026-09-24).
    if !privileged && return_oob_link {
        return error(400, "INSUFFICIENT_PERMISSION");
    }
    let request_type = match str_field(body, "requestType") {
        Some("OOB_REQ_TYPE_UNSPECIFIED") if strict => return error(400, "INVALID_REQ_TYPE"),
        None | Some("" | "OOB_REQ_TYPE_UNSPECIFIED") => return error(400, "MISSING_REQ_TYPE"),
        Some(t) => match OobRequestType::parse(t) {
            Some(t) => t,
            // Strict: production decodes the enum before anything else looks at the request.
            None if strict => {
                return proto_field_error(
                    "req_type",
                    &format!(
                        "Invalid value at 'req_type' (type.googleapis.com/google.cloud.identitytoolkit.v1.OobReqType), {}",
                        Value::String(t.to_owned())
                    ),
                )
            }
            None => {
                return JsonResponse {
                    status: 501,
                    body: fireemu_adapter_support::api_error::identity_unimplemented(t),
                }
            }
        },
    };
    // The official emulator refuses a continue URL that is not absolute before anything else;
    // strict checks it with production's wording once the address is known (below).
    if !strict {
        if let Some(url) = str_field(body, "continueUrl").filter(|url| !url.is_empty()) {
            if !uri_is_absolute(url) {
                return error(
                    400,
                    "INVALID_CONTINUE_URI : ((expected an absolute URI with valid scheme and host))",
                );
            }
        }
    }
    let privacy = store.config().enable_improved_email_privacy;
    let hidden = |email: &str| JsonResponse {
        status: 200,
        body: json!({"kind": "identitytoolkit#GetOobConfirmationCodeResponse", "email": email}),
    };
    let (email, uid, new_email) = match request_type {
        OobRequestType::PasswordReset => {
            let Some(email) = str_field(body, "email").map(canonicalize_email) else {
                return error(400, "MISSING_EMAIL");
            };
            if strict && !is_valid_email(&email) {
                return error(400, "INVALID_EMAIL");
            }
            match store.user_by_email(&email) {
                Some(u) => (email.clone(), Some(u.local_id.clone()), None),
                // Improved email privacy: an unknown address is answered as if a mail had
                // been sent, and no code is created, for the Admin link generator too
                // (sandbox recording 2026-09-24; the official emulator answers the same).
                // Production answers so before it looks at the continue URL.
                None if privacy => return hidden(&email),
                None => return error(400, "EMAIL_NOT_FOUND"),
            }
        }
        OobRequestType::EmailSignIn => {
            // Strict: the Admin generator is refused while email links are off, as the client
            // route is (sandbox recording 2026-09-24). The official emulator always reports
            // email links as enabled (firebase-tools `state.js` `enableEmailLinkSignin`), so the
            // emulator profile adds no rejection here.
            let sign_in = store.sign_in_config();
            if strict && (!sign_in.email_enabled || sign_in.password_required) {
                return error(400, "OPERATION_NOT_ALLOWED");
            }
            let Some(email) = str_field(body, "email").map(canonicalize_email) else {
                return error(400, "MISSING_EMAIL");
            };
            if !email.contains('@') {
                return error(400, "INVALID_EMAIL");
            }
            // Strict: a sign-in link needs somewhere to continue, and a disabled owner gets
            // none (sandbox recording 2026-09-24).
            if strict && str_field(body, "continueUrl").is_none() {
                return error(400, "MISSING_CONTINUE_URI");
            }
            // Only the Admin route was observed; a client under improved email privacy is
            // not told that an address belongs to a disabled account.
            let owner = store.user_by_email(&email);
            if strict && privileged && owner.is_some_and(|u| u.disabled) {
                return error(400, "USER_DISABLED");
            }
            let uid = owner.map(|u| u.local_id.clone());
            (email.clone(), uid, None)
        }
        OobRequestType::VerifyEmail | OobRequestType::VerifyAndChangeEmail => {
            let change = request_type == OobRequestType::VerifyAndChangeEmail;
            // The Admin generator selects the account by its address, as production and the
            // official emulator do; production's generator of an address change reads only
            // the address, a verification also an ID token (sandbox recording 2026-09-24).
            let by_token = if privileged {
                str_field(body, "idToken").is_some() && !(strict && change)
            } else {
                true
            };
            let uid = if by_token {
                match verify_honouring_legacy(store, body, at) {
                    Ok(uid) => uid,
                    Err(r) => return r,
                }
            } else {
                let Some(email) = str_field(body, "email").map(canonicalize_email) else {
                    return error(400, "MISSING_EMAIL");
                };
                match store.user_by_email(&email) {
                    Some(u) => u.local_id.clone(),
                    None => return error(400, "USER_NOT_FOUND"),
                }
            };
            let Some(email) = store.user(&uid).and_then(|u| u.email.clone()) else {
                return error(400, "MISSING_EMAIL");
            };
            let new_email = if change {
                let Some(new_email) = str_field(body, "newEmail").map(canonicalize_email) else {
                    return error(400, "MISSING_NEW_EMAIL");
                };
                if strict && !is_valid_email(&new_email) {
                    return error(400, "INVALID_NEW_EMAIL");
                }
                let taken = store
                    .user_by_email(&new_email)
                    .is_some_and(|u| u.local_id != uid);
                // Strict: improved email privacy hides a taken or unchanged new address
                // behind the answer of a sent mail (sandbox recording 2026-09-24).
                if strict && privacy && (taken || new_email == email) {
                    return hidden(&email);
                }
                if taken && !store.config().allow_duplicate_emails {
                    return error(400, "EMAIL_EXISTS");
                }
                Some(new_email)
            } else {
                None
            };
            (email, Some(uid), new_email)
        }
    };
    // Strict: production's continue-URL checks, once the address is known.
    if strict {
        if let Some(url) = str_field(body, "continueUrl") {
            if absolute_uri_host(url).is_none() {
                return error(400, "INVALID_CONTINUE_URI : Missing domain in continue url");
            }
            if let Some(response) = unauthorized_continue_url(store, body) {
                return response;
            }
        }
        // A newer password reset, email change or sign-in link retires the older one; a
        // verification link cannot be asked for twice within minutes, so its rule is unobserved.
        if request_type != OobRequestType::VerifyEmail {
            store.retire_oob_codes(request_type, &email);
        }
    }
    let code = match store.create_oob_code(request_type, &email, uid, new_email, at) {
        Ok(code) => code,
        Err(e) => return auth_error(&e),
    };
    let mut response =
        json!({"kind": "identitytoolkit#GetOobConfirmationCodeResponse", "email": email});
    if return_oob_link {
        response["oobCode"] = json!(code);
        response["oobLink"] = json!(oob_link(
            headers,
            request_type,
            &code,
            body,
            store.tenant_id()
        ));
    } else {
        // The mail that is not sent: the official emulator prints the link instead.
        store.push_credential_notice(CredentialNotice::EmailAction {
            request_type,
            email: email.clone(),
            new_email: store.oob_code(&code).and_then(|c| c.new_email.clone()),
            link: oob_link(headers, request_type, &code, body, store.tenant_id()),
        });
    }
    JsonResponse {
        status: 200,
        body: response,
    }
}

/// The refusal of a continue URL whose host is not one of the project's authorized domains.
fn unauthorized_continue_url(store: &AuthStore, body: &Value) -> Option<JsonResponse> {
    let url = str_field(body, "continueUrl")?;
    let host = absolute_uri_host(url)?;
    if store
        .authorized_domains()
        .iter()
        .any(|domain| domain.eq_ignore_ascii_case(&host))
    {
        return None;
    }
    Some(error(
        400,
        "UNAUTHORIZED_DOMAIN : Domain not allowlisted by project",
    ))
}

/// An outstanding code by value: `INVALID_OOB_CODE` for none, `EXPIRED_OOB_CODE` for one past
/// its lifetime under production lifetimes (sandbox recording 2026-09-24, auth-action/expiry).
fn live_oob_code(
    store: &AuthStore,
    code: &str,
    at: LogicalInstant,
) -> Result<fireemu_core_auth::store::OobCode, JsonResponse> {
    match store.oob_code(code) {
        None => Err(error(400, "INVALID_OOB_CODE")),
        Some(entry) if store.oob_code_expired(entry, at) => Err(error(400, "EXPIRED_OOB_CODE")),
        Some(entry) => Ok(entry.clone()),
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
    let strict = !stateless_refresh_tokens;
    let Some(code) = str_field(body, "oobCode") else {
        return error(400, "MISSING_OOB_CODE");
    };
    let entry = match live_oob_code(store, code, at) {
        Ok(entry) => entry,
        Err(response) => return response,
    };
    let new_password = match opt_str(body, "newPassword") {
        // Check mode (`checkActionCode` / `verifyPasswordResetCode`): describe the code
        // without consuming it, whatever its type. Only the reset itself is restricted to
        // `PASSWORD_RESET`. The official emulator reads an empty password as none.
        Ok(None) => return check_oob_code(&entry),
        Ok(Some("")) if !strict => return check_oob_code(&entry),
        Ok(Some(new_password)) => new_password,
        Err(r) => return r,
    };
    // Strict: production refuses an empty password without the length hint, and only
    // inspects a sign-in link offered with a password (sandbox recording 2026-09-24).
    if strict && new_password.is_empty() {
        return error(400, "WEAK_PASSWORD");
    }
    if strict && entry.request_type == OobRequestType::EmailSignIn {
        return check_oob_code(&entry);
    }
    if entry.request_type != OobRequestType::PasswordReset {
        return error(400, "INVALID_OOB_CODE");
    }
    // The official `resetPassword` checks the new password before it spends the code and
    // looks the address up; strict keeps the order observed so far (the lookup first).
    let validate = |store: &AuthStore| {
        store.validate_password_for(
            fireemu_core_auth::password_policy::Operation::Reset,
            new_password,
        )
    };
    if !strict {
        if let Err(e) = validate(store) {
            return auth_error(&e);
        }
    }
    // The code names an address, and the account that owns it now is reset: production does
    // so (sandbox recordings 2026-09-24, password-reset#reset-e-after-email-change and
    // auth-action/address-reuse), and so does the official emulator's `resetPassword`. Nobody
    // owning it is production's USER_NOT_FOUND, or the official INVALID_OOB_CODE, which spends
    // the code as the official handler does.
    let uid = match store.user_by_email(&entry.email) {
        Some(u) => u.local_id.clone(),
        None if strict => return error(400, "USER_NOT_FOUND"),
        None => {
            let _ = store.consume_oob_code(code, None, at);
            return error(400, "INVALID_OOB_CODE");
        }
    };
    if strict {
        if let Err(e) = validate(store) {
            return auth_error(&e);
        }
    }
    if store.user(&uid).is_none_or(|u| u.disabled) {
        // Strict: the refusal spends the code (sandbox recording 2026-09-24,
        // password-reset#check-f-after-refused-reset).
        if strict {
            let _ = store.consume_oob_code(code, Some(OobRequestType::PasswordReset), at);
        }
        return error(400, "USER_DISABLED");
    }
    if let Err(e) = store.consume_oob_code(code, Some(OobRequestType::PasswordReset), at) {
        return auth_error(&e);
    }
    if let Err(e) = store.set_password_for(
        &uid,
        new_password,
        at,
        fireemu_core_auth::password_policy::Operation::Reset,
    ) {
        return auth_error(&e);
    }
    // A reset advances `validSince` and verifies the address (the user read the mail). The
    // sessions before it are refused as TOKEN_EXPIRED: strict keeps their refresh records so
    // a refresh answers so too (sandbox recording 2026-09-24), and the emulator profile keeps
    // the official emulator's stateless refresh credentials.
    let _ = store.revoke_tokens(&uid, at);
    if let Some(u) = store.user_mut(&uid) {
        u.email_verified = true;
    }
    JsonResponse {
        status: 200,
        body: json!({"kind": "identitytoolkit#ResetPasswordResponse", "email": entry.email, "requestType": "PASSWORD_RESET"}),
    }
}

/// The `accounts:resetPassword` answer for a code that is only being inspected. Production
/// reports the code's own `requestType`, the address it concerns and, for a pending address
/// change, the new address; the address is omitted for a sign-in link.
fn check_oob_code(entry: &fireemu_core_auth::store::OobCode) -> JsonResponse {
    let mut body = serde_json::Map::new();
    body.insert(
        "kind".to_owned(),
        Value::String("identitytoolkit#ResetPasswordResponse".to_owned()),
    );
    body.insert(
        "requestType".to_owned(),
        Value::String(entry.request_type.as_str().to_owned()),
    );
    if entry.request_type != OobRequestType::EmailSignIn {
        body.insert("email".to_owned(), Value::String(entry.email.clone()));
    }
    if let Some(new_email) = entry.new_email.clone() {
        body.insert("newEmail".to_owned(), Value::String(new_email));
    }
    JsonResponse {
        status: 200,
        body: Value::Object(body),
    }
}

/// `accounts:update` with an `oobCode` (`applyActionCode`): `VERIFY_EMAIL` marks the
/// address verified, `VERIFY_AND_CHANGE_EMAIL` switches to the new address.
fn apply_oob_code(
    store: &mut AuthStore,
    code: &str,
    at: LogicalInstant,
    strict: bool,
) -> JsonResponse {
    let entry = match live_oob_code(store, code, at) {
        Ok(entry) => entry,
        Err(response) => return response,
    };
    let Some(owner) = entry.uid.clone() else {
        return error(400, "INVALID_OOB_CODE");
    };
    // A verification finds its account by the address it names, as production does (it
    // answers EMAIL_NOT_FOUND once nobody owns it; sandbox recordings 2026-09-24,
    // verify-email and auth-action/address-reuse) and as the official emulator's
    // `setAccountInfo` does (INVALID_OOB_CODE, spending the code). Strict also refuses a
    // disabled account (sandbox recording 2026-09-24).
    let uid = if entry.request_type == OobRequestType::VerifyEmail {
        match store.user_by_email(&entry.email) {
            Some(u) => u.local_id.clone(),
            None if strict => return error(400, "EMAIL_NOT_FOUND"),
            None => {
                let _ = store.consume_oob_code(code, None, at);
                return error(400, "INVALID_OOB_CODE");
            }
        }
    } else {
        owner
    };
    if strict && store.user(&uid).is_some_and(|u| u.disabled) {
        return error(400, "USER_DISABLED");
    }
    let mut new_email_answer = None;
    match entry.request_type {
        OobRequestType::VerifyEmail => {
            if store.user(&uid).is_none() {
                return error(400, "INVALID_OOB_CODE");
            }
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
            let Some(replaced) = store.user(&uid).map(|u| u.email.clone()) else {
                return error(400, "INVALID_OOB_CODE");
            };
            if let Err(e) = store.validate_email_update(&uid, &new_email) {
                return auth_error(&e);
            }
            if let Err(e) = store.consume_oob_code(code, None, at) {
                return auth_error(&e);
            }
            if let Err(e) = store.set_email(&uid, &new_email) {
                return auth_error(&e);
            }
            if let Some(u) = store.user_mut(&uid) {
                u.email_verified = true;
                // Strict: the address the first applied change replaced, as production
                // records it (the official emulator records it only on a direct update).
                if strict && u.initial_email.is_none() {
                    u.initial_email.clone_from(&replaced);
                }
            }
            // Strict: the change revokes the sessions before it and voids the verification
            // codes of the replaced address (sandbox recording 2026-09-24,
            // change-email#lookup-token-before-change, #apply-old-verify-ch).
            if strict {
                let _ = store.revoke_tokens(&uid, at);
                if let Some(replaced) = replaced.as_deref() {
                    store.retire_oob_codes(OobRequestType::VerifyEmail, replaced);
                }
            }
            new_email_answer = Some(new_email);
        }
        OobRequestType::PasswordReset | OobRequestType::EmailSignIn => {
            return error(400, "INVALID_OOB_CODE");
        }
    }
    if strict {
        return JsonResponse {
            status: 200,
            body: account_update_answer(store, &uid, new_email_answer.as_deref()),
        };
    }
    let email = store.user(&uid).and_then(|u| u.email.clone());
    JsonResponse {
        status: 200,
        body: json!({"kind": "identitytoolkit#SetAccountInfoResponse", "localId": uid.as_str(), "email": email, "emailVerified": true}),
    }
}

/// Production's `SetAccountInfoResponse` for an account: its address and verification, profile,
/// providers and redacted password hash, and `newEmail` after an address change.
fn account_update_answer(store: &AuthStore, uid: &LocalId, new_email: Option<&str>) -> Value {
    let mut response =
        json!({"localId": uid.as_str(), "kind": "identitytoolkit#SetAccountInfoResponse"});
    if let Some(u) = store.user(uid) {
        response["email"] = json!(u.email);
        // As in a lookup: with an address, and while true after one was removed; never for an
        // account that had none (sandbox recording 2026-09-24).
        if u.email.is_some() || u.email_verified || u.email_verified_recorded {
            response["emailVerified"] = json!(u.email_verified);
        }
        response["displayName"] = json!(u.display_name);
        response["photoUrl"] = json!(u.photo_url);
        if let Some(new_email) = new_email {
            response["newEmail"] = json!(new_email);
        }
    }
    let record = user_json(store, uid);
    for key in ["providerUserInfo", "passwordHash"] {
        if let Some(value) = record.get(key) {
            response[key] = value.clone();
        }
    }
    response
}

/// The `authEmulator` JSON document every action-link answer is wrapped in.
fn action_response(status: u16, auth_emulator: Value) -> JsonResponse {
    JsonResponse {
        status,
        body: Value::Object(serde_json::Map::from_iter([(
            "authEmulator".to_owned(),
            auth_emulator,
        )])),
    }
}

/// The official wording for a code that is gone, whatever the reason.
fn action_expired(what: &str, retry: &str) -> JsonResponse {
    action_response(
        400,
        json!({
            "error": format!("Your request to {what} has expired or the link has already been used."),
            "instructions": retry,
        }),
    )
}

/// `GET /emulator/action`: the link the emulator prints instead of mailing, as the official
/// emulator's handler serves it. Each mode acts on the code and answers an `authEmulator`
/// JSON document, or redirects (303) to `continueUrl` once it has acted. `signIn` does not
/// consume the code: it forwards every parameter to `continueUrl`, where the SDK finishes.
fn emulator_action(
    store: &mut AuthStore,
    query: Option<&str>,
    headers: &RequestHeaders,
    at: LogicalInstant,
    stateless_refresh_tokens: bool,
) -> JsonResponse {
    let params = query_params(query);
    let param = |name: &str| {
        params
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    };
    if param("apiKey").is_none() {
        return action_response(
            400,
            json!({
                "error": "missing apiKey query parameter",
                "instructions": "Please modify the URL to specify an apiKey, such as ...&apiKey=YOUR_API_KEY",
            }),
        );
    }
    let Some(code) = param("oobCode") else {
        return action_response(
            400,
            json!({
                "error": "missing oobCode query parameter",
                "instructions": "Please modify the URL to specify an oobCode, such as ...&oobCode=YOUR_OOB_CODE",
            }),
        );
    };
    let continue_url = param("continueUrl");
    match param("mode") {
        Some("recoverEmail") => action_response(
            400,
            json!({
                "error": "Requested mode does not match the OOB code provided.",
                "instructions": "If you're trying to test the reverting email flow, try changing the email again to generate a new link.",
            }),
        ),
        Some("resetPassword") => action_reset_password(
            store,
            code,
            param("newPassword"),
            continue_url,
            headers,
            at,
            stateless_refresh_tokens,
        ),
        Some("verifyEmail") => action_apply(
            store,
            code,
            OobRequestType::VerifyEmail,
            continue_url,
            at,
            ApplyPage {
                strict: !stateless_refresh_tokens,
                what: "verify your email",
                retry: "Try verifying your email again.",
                success: |email| json!({"success": "The email has been successfully verified.", "email": email}),
            },
        ),
        Some("verifyAndChangeEmail") => action_apply(
            store,
            code,
            OobRequestType::VerifyAndChangeEmail,
            continue_url,
            at,
            ApplyPage {
                strict: !stateless_refresh_tokens,
                what: "change your email",
                retry: "Try changing your email again.",
                success: |email| json!({"success": "The email has been successfully changed.", "newEmail": email}),
            },
        ),
        Some("signIn") => {
            if live_oob_code(store, code, at)
                .ok()
                .is_none_or(|entry| entry.request_type != OobRequestType::EmailSignIn)
            {
                action_expired("sign in", "Try signing in again.")
            } else {
                action_sign_in(query, &params, continue_url)
            }
        }
        _ => action_response(400, json!({"error": "Invalid mode"})),
    }
}

/// `mode=resetPassword`: the code must be a live reset code, `newPassword` must be given and
/// must not be the placeholder; then the reset runs as `accounts:resetPassword` would.
fn action_reset_password(
    store: &mut AuthStore,
    code: &str,
    new_password: Option<&str>,
    continue_url: Option<&str>,
    headers: &RequestHeaders,
    at: LogicalInstant,
    stateless_refresh_tokens: bool,
) -> JsonResponse {
    // A code past its lifetime is gone to the action page, also while strict still keeps it.
    let Some(entry) = live_oob_code(store, code, at)
        .ok()
        .filter(|c| c.request_type == OobRequestType::PasswordReset)
    else {
        return action_expired("reset your password", "Try resetting your password again.");
    };
    let template = format!(
        "{}&newPassword=NEW_PASSWORD_HERE",
        oob_link(
            headers,
            entry.request_type,
            code,
            &Value::Null,
            store.tenant_id()
        )
    );
    let Some(new_password) = new_password else {
        return action_response(
            400,
            json!({
                "error": "missing newPassword query parameter",
                "instructions": format!("To reset the password for {}, send an HTTP GET request to the following URL.", entry.email),
                "instructions2": "You may use a web browser or any HTTP client, such as curl.",
                "urlTemplate": template,
            }),
        );
    };
    if new_password == "NEW_PASSWORD_HERE" {
        return action_response(
            400,
            json!({
                "error": "newPassword must be something other than 'NEW_PASSWORD_HERE'",
                "instructions": "The string 'NEW_PASSWORD_HERE' is just a placeholder.",
                "instructions2": "Please change the URL to specify a new password instead.",
                "urlTemplate": template,
            }),
        );
    }
    let response = reset_password(
        store,
        &json!({"oobCode": code, "newPassword": new_password}),
        at,
        stateless_refresh_tokens,
    );
    if response.status != 200 {
        return response;
    }
    match continue_url {
        Some(url) => redirect(url),
        None => action_response(
            200,
            json!({"success": "The password has been successfully updated.", "email": entry.email}),
        ),
    }
}

/// How the action page applies one kind of code: under which profile's rules, and the words
/// of its refusal and of its success answer.
struct ApplyPage<'a, F: FnOnce(&Value) -> Value> {
    strict: bool,
    what: &'a str,
    retry: &'a str,
    success: F,
}

/// `mode=verifyEmail` and `mode=verifyAndChangeEmail`: `applyActionCode`, with
/// `INVALID_OOB_CODE` mapped to the official wording and every other API error passed
/// through unchanged, as the official handler does.
fn action_apply(
    store: &mut AuthStore,
    code: &str,
    expected: OobRequestType,
    continue_url: Option<&str>,
    at: LogicalInstant,
    page: ApplyPage<'_, impl FnOnce(&Value) -> Value>,
) -> JsonResponse {
    let ApplyPage {
        strict,
        what,
        retry,
        success,
    } = page;
    if live_oob_code(store, code, at)
        .ok()
        .is_none_or(|entry| entry.request_type != expected)
    {
        return action_expired(what, retry);
    }
    // The page applies the code as `accounts:update` does, so strict follows the same
    // production rules on both routes (sessions revoked, `initialEmail` recorded, the replaced
    // address's verification codes void); only the page's own wording differs.
    let response = apply_oob_code(store, code, at, strict);
    if response.status != 200 {
        return if response.body["error"]["message"].as_str() == Some("INVALID_OOB_CODE") {
            action_expired(what, retry)
        } else {
            response
        };
    }
    match continue_url {
        Some(url) => redirect(url),
        None => action_response(200, success(&response.body["email"])),
    }
}

/// `mode=signIn`: redirect to `continueUrl` with every other parameter of the link set on
/// it, in the order the link carried them (`URLSearchParams.set`).
fn action_sign_in(
    query: Option<&str>,
    params: &BTreeMap<String, String>,
    continue_url: Option<&str>,
) -> JsonResponse {
    let Some(url) = continue_url else {
        return action_response(
            400,
            json!({
                "error": "Missing continueUrl query parameter",
                "instructions": "To sign in, append &continueUrl=YOUR_APP_URL to the link.",
            }),
        );
    };
    let mut ordered: Vec<(&str, &str)> = Vec::new();
    for kv in query.unwrap_or("").split('&') {
        let raw_name = kv.split_once('=').map_or(kv, |(k, _)| k);
        let Some(name) = query_params(Some(raw_name)).into_keys().next() else {
            continue;
        };
        if name == "continueUrl" || ordered.iter().any(|(n, _)| *n == name) {
            continue;
        }
        if let Some((name, value)) = params.get_key_value(&name) {
            ordered.push((name.as_str(), value.as_str()));
        }
    }
    redirect(&with_query_params(url, &ordered))
}

/// `url` with each of `params` set the way `URLSearchParams.set` does: an existing name is
/// replaced in place (further duplicates dropped), a new name is appended. The fragment is
/// kept.
fn with_query_params(url: &str, params: &[(&str, &str)]) -> String {
    let (url, fragment) = match url.split_once('#') {
        Some((u, f)) => (u, Some(f)),
        None => (url, None),
    };
    let (base, query) = match url.split_once('?') {
        Some((b, q)) => (b, q),
        None => (url, ""),
    };
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let mut decoded = query_params(Some(kv));
            decoded.pop_first().unwrap_or_default()
        })
        .collect();
    for (name, value) in params {
        let mut seen = false;
        pairs.retain_mut(|(n, v)| {
            if n != name {
                return true;
            }
            if seen {
                return false;
            }
            seen = true;
            (*value).clone_into(v);
            true
        });
        if !seen {
            pairs.push(((*name).to_owned(), (*value).to_owned()));
        }
    }
    let mut out = base.to_owned();
    if !pairs.is_empty() {
        out.push('?');
        let encoded: Vec<String> = pairs
            .iter()
            .map(|(n, v)| format!("{}={}", form_encode(n), form_encode(v)))
            .collect();
        out.push_str(&encoded.join("&"));
    }
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

/// `application/x-www-form-urlencoded` serialization of one component, as `URLSearchParams`
/// writes it (`*-._` and alphanumerics literal, space as `+`).
fn form_encode(s: &str) -> String {
    use std::fmt::Write as _;
    s.bytes()
        .fold(String::with_capacity(s.len()), |mut out, b| {
            match b {
                b' ' => out.push('+'),
                b if b.is_ascii_alphanumeric() || matches!(b, b'*' | b'-' | b'.' | b'_') => {
                    out.push(b as char);
                }
                b => {
                    let _ = write!(out, "%{b:02X}");
                }
            }
            out
        })
}

/// `accounts:signInWithEmailLink`: an `EMAIL_SIGNIN` code for `email`.
fn sign_in_with_email_link(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    strict: bool,
) -> JsonResponse {
    // Production and the official emulator name a missing address before a missing code
    // (sandbox recording 2026-09-24).
    let Some(email) = str_field(body, "email") else {
        return error(400, "MISSING_EMAIL");
    };
    let Some(code) = str_field(body, "oobCode") else {
        return error(400, "MISSING_OOB_CODE");
    };
    let email = canonicalize_email(email);
    let entry = match live_oob_code(store, code, at) {
        Ok(entry) if entry.request_type == OobRequestType::EmailSignIn => entry,
        Ok(_) => return error(400, "INVALID_OOB_CODE"),
        Err(response) => return response,
    };
    if entry.email != email {
        return error(
            400,
            "INVALID_EMAIL : The email provided does not match the sign-in email address.",
        );
    }
    let response_fields = |is_new: bool| {
        [
            ("kind", json!("identitytoolkit#EmailLinkSigninResponse")),
            ("isNewUser", json!(is_new)),
        ]
    };
    // With a session: link the (now verified) email to that user instead. The code is
    // consumed only once the request is known to succeed. Strict honours a legacy token, as
    // production does (sandbox recording 2026-09-24, auth-action/legacy-token).
    if body.get("idToken").is_some_and(|t| !t.is_null()) {
        let verified = if strict {
            verify_honouring_legacy(store, body, at)
        } else {
            verify(store, body, at)
        };
        let uid = match verified {
            Ok(uid) => uid,
            Err(r) => return r,
        };
        if !store.config().allow_duplicate_emails
            && store
                .user_by_email(&email)
                .is_some_and(|u| u.local_id != uid)
        {
            return error(400, "EMAIL_EXISTS");
        }
        if let Err(e) = store.consume_oob_code(code, Some(OobRequestType::EmailSignIn), at) {
            return auth_error(&e);
        }
        if let Err(e) = store.set_email(&uid, &email) {
            return auth_error(&e);
        }
        if let Some(u) = store.user_mut(&uid) {
            u.email_verified = true;
            u.email_link_signin = true;
            // A linked anonymous account becomes an email-link account: its session is a
            // `password` session and it lists the password provider, as in production and
            // the official emulator.
            if u.provider == fireemu_core_auth::store::Provider::Anonymous {
                u.provider = fireemu_core_auth::store::Provider::EmailLink;
            }
        }
        return finish_sign_in(
            store,
            &uid,
            at,
            Some(fireemu_core_auth::store::Provider::EmailLink),
            &response_fields(false),
        );
    }
    if let Err(e) = store.consume_oob_code(code, Some(OobRequestType::EmailSignIn), at) {
        return auth_error(&e);
    }
    // Strict: an account whose address was never verified loses its password when the link
    // proves the address, as production does (sandbox recording 2026-09-24).
    let unverified_owner = store
        .user_by_email(&email)
        .filter(|u| !u.email_verified && !u.disabled)
        .map(|u| u.local_id.clone());
    let (uid, is_new) = match store.sign_in_with_email_link(&email, at) {
        Ok(r) => r,
        Err(e) => return auth_error(&e),
    };
    if strict && unverified_owner.as_ref() == Some(&uid) {
        if let Err(e) = store.clear_password(&uid) {
            return auth_error(&e);
        }
    }
    if let Some(u) = store.user_mut(&uid) {
        u.email_link_signin = true;
        u.email_link_created |= is_new;
        // Removing the password leaves an account without a provider; the link makes it an
        // email-link account, whose sessions carry no anonymous `provider_id` (sandbox
        // recording 2026-09-24, email-link/session#sign-in-p).
        if u.provider == fireemu_core_auth::store::Provider::Anonymous {
            u.provider = fireemu_core_auth::store::Provider::EmailLink;
        }
    }
    // The account and the pending credential keep `Provider::EmailLink`, which drives
    // `providerUserInfo`, the `createAuthUri` sign-in methods and the `emailLink` sign-in
    // method Blocking Functions see. The token claim itself is rendered as `password`.
    finish_sign_in(
        store,
        &uid,
        at,
        Some(fireemu_core_auth::store::Provider::EmailLink),
        &response_fields(is_new),
    )
}

// ---- phone sign-in ----------------------------------------------------------------------

/// The SMS that is not sent: the official emulator prints the code instead.
fn announce_phone_code(store: &mut AuthStore, code: &VerificationCode, purpose: PhoneCodeUse) {
    store.push_credential_notice(CredentialNotice::PhoneCode {
        phone_number: code.phone_number.clone(),
        code: code.code.clone(),
        purpose,
    });
}

/// `accounts:sendVerificationCode`: no SMS is sent; the code is kept for
/// `/emulator/v1/projects/{p}/verificationCodes` (reCAPTCHA tokens are not checked).
fn send_verification_code(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let Some(phone) = str_field(body, "phoneNumber") else {
        return error(400, "MISSING_PHONE_NUMBER");
    };
    match store.send_verification_code(phone, VerificationPurpose::SignIn, at) {
        Ok(code) => {
            announce_phone_code(store, &code, PhoneCodeUse::SignIn);
            JsonResponse {
                status: 200,
                body: json!({"sessionInfo": code.session_info}),
            }
        }
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
    if let Some(proof) = str_field(body, "temporaryProof") {
        return sign_in_with_temporary_proof(store, body, proof, at);
    }
    // Production names the missing code before the session (sandbox recording 2026-09-23,
    // `auth-account/phone#missing-code`).
    let Some(code) = str_field(body, "code") else {
        return error(400, "MISSING_CODE");
    };
    let Some(session) = str_field(body, "sessionInfo") else {
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
        let uid = match verify_honouring_legacy(store, body, at) {
            Ok(uid) => uid,
            Err(r) => return r,
        };
        if store
            .user_by_phone(&verified.phone_number)
            .is_some_and(|u| u.local_id != uid)
        {
            // Production answers a link to a taken number with a proof of the verified number
            // instead of an error (sandbox recording 2026-09-23, `phone#link-taken-phone`).
            store.consume_phone_code(session);
            return match store.issue_temporary_proof(&verified.phone_number, at) {
                Ok(proof) => JsonResponse {
                    status: 200,
                    body: json!({
                        "temporaryProof": proof,
                        "phoneNumber": verified.phone_number,
                        "temporaryProofExpiresIn":
                            fireemu_core_auth::store::TEMPORARY_PROOF_TTL_SECONDS.to_string(),
                    }),
                },
                Err(e) => auth_error(&e),
            };
        }
        store.consume_phone_code(session);
        if let Err(e) = store.set_phone_number(&uid, Some(&verified.phone_number)) {
            return auth_error(&e);
        }
        // The new session is a phone sign-in (sandbox recording 2026-09-24).
        return match issue_tokens_with(
            store,
            &uid,
            None,
            at,
            None,
            Some(fireemu_core_auth::store::Provider::Phone),
        ) {
            Ok(mut tokens) => {
                // Production's link answer carries no email (sandbox recording 2026-09-23).
                if let Some(fields) = tokens.as_object_mut() {
                    fields.remove("email");
                }
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

/// `accounts:signInWithPhoneNumber` with a `temporaryProof`: signs in to the number's owner,
/// as the SDK does after a link to a taken number.
fn sign_in_with_temporary_proof(
    store: &mut AuthStore,
    body: &Value,
    proof: &str,
    at: LogicalInstant,
) -> JsonResponse {
    let Some(phone) = str_field(body, "phoneNumber") else {
        return error(400, "MISSING_PHONE_NUMBER");
    };
    if !store.check_temporary_proof(proof, phone, at) {
        return error(400, "INVALID_TEMPORARY_PROOF");
    }
    let (uid, is_new) = match store.sign_in_with_phone(phone, at) {
        Ok(r) => r,
        Err(e) => return auth_error(&e),
    };
    finish_sign_in(
        store,
        &uid,
        at,
        Some(fireemu_core_auth::store::Provider::Phone),
        &[("phoneNumber", json!(phone)), ("isNewUser", json!(is_new))],
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

fn idp_claim_value(value: &Value) -> Option<ClaimValue> {
    fireemu_core_types::json::parse(&value.to_string())
        .ok()
        .and_then(|value| claims_from_json(&value))
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
    sign_in_attributes: Option<ClaimValue>,
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
        sign_in_attributes: provider_id
            .starts_with("oidc.")
            .then(|| idp_claim_value(claims))
            .flatten(),
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
            .cloned();
        info.raw_user_info = attributes.clone().unwrap_or(Value::Null).to_string();
        info.sign_in_attributes = attributes.and_then(|attributes| idp_claim_value(&attributes));
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
    oauth_refresh_token: Option<&String>,
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
        ("oauthRefreshToken", json!(oauth_refresh_token.cloned())),
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
    let assertion = parsed.get("assertion");
    if !assertion.is_some_and(Value::is_object) {
        return Err(error(
            400,
            "INVALID_IDP_RESPONSE ((Missing assertion in SAMLResponse.))",
        ));
    }
    let subject = assertion.and_then(|a| a.get("subject"));
    if !subject.is_some_and(Value::is_object) {
        return Err(error(
            400,
            "INVALID_IDP_RESPONSE ((Missing assertion.subject in SAMLResponse.))",
        ));
    }
    if !subject
        .and_then(|s| s.get("nameId"))
        .and_then(Value::as_str)
        .is_some_and(|name| !name.is_empty() && !name.chars().any(char::is_control))
    {
        return Err(error(
            400,
            "INVALID_IDP_RESPONSE ((Missing assertion.subject.nameId in SAMLResponse.))",
        ));
    }
    if assertion
        .and_then(|a| a.get("attributeStatements"))
        .is_some_and(|value| !value.is_null() && !value.is_object())
    {
        return Err(error(
            400,
            "INVALID_IDP_RESPONSE ((Invalid SAML attributeStatements.))",
        ));
    }
    Ok(Some(parsed))
}

/// Opaque continuation authority is supplied by the trusted embedder, never by HTTP.
fn idp_continuation_authority(trust: Option<&crate::oidc::LocalOidcTrust>) -> String {
    match trust {
        None => "fixture-idp-v1".to_owned(),
        Some(trust) => {
            let pin = json!({
                "project": trust.project_id,
                "tenant": trust.tenant_id,
                "provider": trust.provider_id,
                "issuer": trust.issuer,
                "client": trust.client_id,
                "jwk": trust.jwk,
            });
            format!(
                "signed-oidc-v1:{}",
                fireemu_core_types::hash::hex_lower(&fireemu_core_types::hash::sha256(
                    pin.to_string().as_bytes()
                ))
            )
        }
    }
}

/// Resolve pendingToken *before* signup admission and assertion verification. A caller
/// cannot replace cached credentials with a postBody, change the original redirect URI,
/// or carry a linking ID token over from the earlier request. The current request's ID
/// token and response flags are validated normally after this function.
fn resume_idp_body(
    store: &AuthStore,
    body: &Value,
    authority: &str,
    at: LogicalInstant,
) -> Result<Option<Value>, JsonResponse> {
    let token = match body.get("pendingToken") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(token)) if !token.is_empty() && token.len() <= 256 => token,
        _ => return Err(error(400, "INVALID_PENDING_TOKEN")),
    };
    if body.get("postBody").is_some_and(|value| !value.is_null())
        || body
            .get("pendingIdToken")
            .is_some_and(|value| !value.is_null())
    {
        return Err(error(400, "INVALID_PENDING_TOKEN"));
    }
    let Some(raw) = store.pending_idp_sign_in(token, authority, at) else {
        return Err(error(400, "INVALID_PENDING_TOKEN"));
    };
    let original: Value =
        serde_json::from_str(raw).map_err(|_| error(400, "INVALID_PENDING_TOKEN"))?;
    let Some(uri) = original.get("requestUri").and_then(Value::as_str) else {
        return Err(error(400, "INVALID_PENDING_TOKEN"));
    };
    if body.get("requestUri").and_then(Value::as_str) != Some(uri) {
        return Err(error(400, "INVALID_REQUEST_URI"));
    }
    let mut resolved = body.clone();
    let Some(object) = resolved.as_object_mut() else {
        return Err(error(400, "INVALID_PENDING_TOKEN"));
    };
    object.remove("pendingToken");
    object.insert(
        "postBody".to_owned(),
        original.get("postBody").cloned().unwrap_or(Value::Null),
    );
    Ok(Some(resolved))
}

/// Parses and validates a `signInWithIdp` credential, or the error the official emulator raises.
fn resolve_idp_credential(body: &Value) -> Result<ResolvedIdp, JsonResponse> {
    if body
        .get("pendingToken")
        .is_some_and(|value| !value.is_null())
    {
        return Err(error(400, "INVALID_PENDING_TOKEN"));
    }
    let return_refresh_token = match body.get("returnRefreshToken") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(error(400, "INVALID_ARGUMENT")),
    };
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
    let oauth_refresh_token = return_refresh_token
        .then(|| {
            params
                .get("refresh_token")
                .filter(|token| !token.is_empty())
                .cloned()
        })
        .flatten();
    let base = idp_response_base(
        &provider_id,
        &info,
        oauth_id_token,
        &oauth_access_token_out,
        oauth_refresh_token.as_ref(),
    );
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
fn sign_in_with_idp(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    inbound_credential_policy: fireemu_core_functions::manifest::BlockingAuthTokenPolicy,
) -> JsonResponse {
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

    let inbound_credentials = inbound_credential_policy
        .any()
        .then(|| inbound_credentials_from_request(body, inbound_credential_policy))
        .flatten();
    finish_sign_in_with_attributes_and_credentials(
        store,
        &uid,
        at,
        Some(fireemu_core_auth::store::Provider::Federated(provider_id)),
        &base,
        info.sign_in_attributes.as_ref(),
        inbound_credentials.as_ref(),
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

/// The lower-cased host of an absolute `scheme://authority` URI, without user info or port;
/// `None` when the URI has no scheme or no authority. A backslash ends the authority, as a
/// browser reads it, so `https://evil.example\@allowed.host/` names `evil.example`.
fn absolute_uri_host(uri: &str) -> Option<String> {
    if !uri_is_absolute(uri) {
        return None;
    }
    let (_, rest) = uri.split_once("://")?;
    let authority = rest.split(['/', '\\', '?', '#']).next().unwrap_or_default();
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if let Some(bracketed) = host_port.strip_prefix('[') {
        bracketed.split_once(']').map(|(host, _)| host)?
    } else {
        host_port.split(':').next().unwrap_or_default()
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
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
    // Production accepts a test number's enrollment session again, and then refuses it as the
    // number now enrolled (sandbox recording 2026-09-24, auth-mfa/sms#finalize-again).
    let test_number = store
        .sign_in_config()
        .test_phone_numbers
        .contains_key(&verified.phone_number);
    if !(store.second_factor_rules_are_production() && test_number) {
        store.consume_phone_code(session_info);
    }
    let display_name = str_field(body, "displayName").map(str::to_owned);
    match store.enroll_phone_factor(uid, &verified.phone_number, display_name, at) {
        Ok(factor) => {
            // Production ends the sessions before a phone enrollment (validSince moves;
            // sandbox recording 2026-09-24, auth-mfa/sms#admin-lookup-s and
            // lifetime#control-start-s450); a TOTP enrollment leaves them.
            if store.second_factor_rules_are_production() {
                let _ = store.revoke_tokens(uid, at);
            }
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
    let uid = match verify_honouring_legacy(store, body, at) {
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

/// Strict `mfaEnrollment:withdraw` (sandbox recording 2026-09-24, auth-mfa/totp/withdraw and
/// sms#withdraw-first-phone): a missing token is `INVALID_ID_TOKEN` and a missing factor id
/// `MFA_ENROLLMENT_NOT_FOUND`; a withdrawal ends every session before it (`validSince`), and
/// the new session keeps the second factor of the one that asked, unless that factor is the
/// one withdrawn. The answer carries no `expiresIn`.
fn mfa_enrollment_withdraw_production(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> JsonResponse {
    if str_field(body, "idToken").is_none_or(str::is_empty) {
        return error(400, "INVALID_ID_TOKEN");
    }
    let uid = match verify_honouring_legacy(store, body, at) {
        Ok(uid) => uid,
        Err(r) => return r,
    };
    let Some(id) = str_field(body, "mfaEnrollmentId").filter(|id| !id.is_empty()) else {
        return error(400, "MFA_ENROLLMENT_NOT_FOUND");
    };
    // The token was verified above; read its claims with the store's own signer.
    let signer = store.signer_arc();
    let kept = str_field(body, "idToken")
        .and_then(|token| fireemu_core_auth::jwt::decode_token(token, signer.as_deref()).ok())
        .and_then(|decoded| serde_json::from_str::<Value>(&decoded.payload_json).ok())
        .and_then(|claims| {
            let firebase = claims.get("firebase")?;
            let factor = firebase.get("sign_in_second_factor")?.as_str()?;
            let identifier = firebase.get("second_factor_identifier")?.as_str()?;
            (identifier != id).then(|| SecondFactorAssertion {
                sign_in_second_factor: factor.to_owned(),
                second_factor_identifier: identifier.to_owned(),
                verified_at: at,
            })
        });
    match store.unenroll_factor(&uid, id) {
        Ok(true) => {
            let _ = store.revoke_tokens(&uid, at);
            match issue_tokens(store, &uid, kept.as_ref(), at) {
                Ok(tokens) => token_only_response(&tokens, false),
                Err(r) => r,
            }
        }
        Ok(false) => error(400, "MFA_ENROLLMENT_NOT_FOUND"),
        Err(e) => mfa_error(&e),
    }
}

/// `mfaSignIn:start`: sends the code of the chosen phone factor (TOTP has no start step).
fn mfa_sign_in_start(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    strict: bool,
) -> JsonResponse {
    // Strict: production's answers (sandbox recording 2026-09-24, auth-mfa/totp/sign-in
    // #start-totp and #start-totp-as-phone, sms#sign-in-start-without-info).
    if strict {
        let invalid = || error(400, "Request contains an invalid argument.");
        let (Some(pending), Some(enrollment_id)) = (
            str_field(body, "mfaPendingCredential").filter(|p| !p.is_empty()),
            str_field(body, "mfaEnrollmentId").filter(|e| !e.is_empty()),
        ) else {
            return invalid();
        };
        if body.get("phoneSignInInfo").is_none_or(Value::is_null) {
            return invalid();
        }
        let Some(pending_id) = PendingSignInId::parse(pending) else {
            return error(400, "INVALID_PENDING_TOKEN");
        };
        let Some(uid) = store.pending_sign_in_user(&pending_id) else {
            return error(
                400,
                if store.pending_sign_in_orphaned(&pending_id) {
                    "USER_NOT_FOUND"
                } else {
                    "INVALID_PENDING_TOKEN"
                },
            );
        };
        if store.user(&uid).is_some_and(|u| {
            u.mfa
                .totp_factors()
                .iter()
                .any(|f| f.mfa_enrollment_id == enrollment_id)
        }) {
            return error(400, "INVALID_PHONE_NUMBER : Invalid format.");
        }
        if store.sms_pending_start_expired(&pending_id, at) {
            return error(
                400,
                "INVALID_MFA_PENDING_CREDENTIAL : MFA pending credential is expired.",
            );
        }
    }
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
    // A disabled account is not refused here: production accepts mfaSignIn:start on an
    // account disabled after its pending credential and issues the code, enforcing
    // USER_DISABLED only at mfaSignIn:finalize (auth-mfa-start-disabled, recorded and
    // approved 2026-09-12, GAP-AUTH-005). The finalize path already refuses a disabled
    // account, so the sign-in still cannot complete.
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
        Ok(code) => {
            announce_phone_code(store, &code, PhoneCodeUse::MfaSignIn);
            JsonResponse {
                status: 200,
                body: json!({"phoneResponseInfo": {"sessionInfo": code.session_info}}),
            }
        }
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
    let verified = match store.check_phone_code(session, code, at) {
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
    let first_factor = store.pending_sign_in_context(&pending_id).cloned();
    let test_number = store
        .sign_in_config()
        .test_phone_numbers
        .contains_key(&verified.phone_number);
    match store.finalize_phone_mfa_sign_in(&uid, &pending_id, &enrollment_id, at) {
        Ok(assertion) => {
            // Production accepts a test number's session again (sandbox recording
            // 2026-09-24, auth-mfa/sms#sign-in-finalize-again).
            if !(store.second_factor_rules_are_production() && test_number) {
                store.consume_phone_code(session);
            }
            match issue_tokens_with_sign_in_attributes(
                store,
                &uid,
                Some(&assertion),
                at,
                None,
                first_factor
                    .as_ref()
                    .and_then(PendingSignInContext::sign_in_provider)
                    .map(provider_from_id),
                first_factor
                    .as_ref()
                    .and_then(PendingSignInContext::sign_in_attributes),
            ) {
                Ok(tokens) => token_only_response(&tokens, false),
                Err(r) => r,
            }
        }
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
                        "oobLink": oob_link(headers, c.request_type, &c.code, &Value::Null, store.tenant_id()),
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
        // `allowDuplicateEmails` is persisted in the export and controls the email ownership
        // policy of the selected project.
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
            if let Some(v) = body
                .get("client")
                .and_then(|s| s.get("permissions"))
                .and_then(|s| s.get("disabledUserSignup"))
                .and_then(Value::as_bool)
            {
                config.disabled_user_signup = v;
            }
            if let Some(v) = body
                .get("client")
                .and_then(|s| s.get("permissions"))
                .and_then(|s| s.get("disabledUserDeletion"))
                .and_then(Value::as_bool)
            {
                config.disabled_user_deletion = v;
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
        "client": {"permissions": {
            "disabledUserSignup": config.disabled_user_signup,
            "disabledUserDeletion": config.disabled_user_deletion,
        }},
        "emailPrivacyConfig": {"enableImprovedEmailPrivacy": config.enable_improved_email_privacy},
    })
}

fn project_config_json_with_password_policy(
    config: fireemu_core_auth::store::ProjectAuthConfig,
    policy: &PasswordPolicy,
) -> Value {
    let mut result = project_config_json(config);
    result["passwordPolicyConfig"] = password_policy_config_json(policy);
    result
}

fn project_config_json_with_auth_settings(
    config: fireemu_core_auth::store::ProjectAuthConfig,
    policy: &PasswordPolicy,
    quota: &SignupQuotaConfig,
) -> Value {
    let mut result = project_config_json_with_password_policy(config, policy);
    result["quota"] = quota_config_json(quota);
    result
}

fn password_policy_json(policy: &PasswordPolicy) -> JsonResponse {
    // Production's order first, then any other configured character in code-point order.
    let order = fireemu_core_auth::password_policy::DEFAULT_NON_ALPHANUMERIC_ORDER;
    let allowed: Vec<String> = order
        .chars()
        .filter(|c| policy.allowed_non_alphanumeric.contains(c))
        .chain(
            policy
                .allowed_non_alphanumeric
                .iter()
                .copied()
                .filter(|c| !order.contains(*c)),
        )
        .map(String::from)
        .collect();
    let options = password_policy_config_json(policy)
        .get("passwordPolicyVersions")
        .and_then(Value::as_array)
        .and_then(|versions| versions.first())
        .and_then(|version| version.get("customStrengthOptions"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    JsonResponse {
        status: 200,
        body: json!({
            "customStrengthOptions": options,
            "allowedNonAlphanumericCharacters": allowed,
            "enforcementState": match policy.enforcement_state {
                EnforcementState::Off => "OFF",
                EnforcementState::Enforce => "ENFORCE",
            },
            "forceUpgradeOnSignin": policy.force_upgrade_on_signin,
            "schemaVersion": 1,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fireemu_core_auth::mfa::TotpPolicy;
    use fireemu_core_types::determinism::SplitMix64;

    #[test]
    fn an_absolute_uri_host_is_its_lower_cased_authority_host() {
        for (uri, host) in [
            (
                "https://Demo-App.firebaseapp.com/done?x=1",
                Some("demo-app.firebaseapp.com"),
            ),
            ("http://localhost:5000/done", Some("localhost")),
            (
                "https://user:pw@demo-app.web.app#frag",
                Some("demo-app.web.app"),
            ),
            (
                "https://demo-app.web.app?x=@evil.example.com",
                Some("demo-app.web.app"),
            ),
            ("http://[::1]:8080/x", Some("::1")),
            ("myapp://callback", Some("callback")),
            ("not a url", None),
            ("", None),
            ("/relative/path", None),
            ("https://", None),
            ("mailto:someone@example.com", None),
            ("http://[::1/x", None),
            (
                "https://evil.example\\@demo-app.firebaseapp.com/x",
                Some("evil.example"),
            ),
            ("https:\\\\evil.example", None),
        ] {
            assert_eq!(absolute_uri_host(uri).as_deref(), host, "{uri}");
        }
    }

    struct AllBlockingHooks;
    struct BeforeCreateOnlyHook;
    struct NoBlockingHooks;
    struct FixedBlockingRevision(u64);

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

    impl AuthBlockingHook for FixedBlockingRevision {
        fn invoke(
            &self,
            _event: fireemu_core_functions::manifest::BlockingAuthEvent,
            _user: &fireemu_core_auth::store::UserRecord,
        ) -> Result<Value, BlockingFunctionFailure> {
            unreachable!("the revision helper test never invokes a hook")
        }

        fn blocking_auth_revision(&self) -> u64 {
            self.0
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
    fn blocking_claim_length_uses_javascript_number_and_escape_spelling() {
        for (value, expected) in [
            (json!(1e20), "100000000000000000000"),
            (json!(1e21), "1e+21"),
            (json!(1e-6), "0.000001"),
            (json!(1e-7), "1e-7"),
            (json!(-0.0), "0"),
            (json!(123.45), "123.45"),
        ] {
            let Value::Number(number) = value else {
                unreachable!();
            };
            assert_eq!(javascript_number_string(&number), expected);
        }
        assert_eq!(
            javascript_json_stringify_len(&json!({"v": "\u{0008}\u{000c}"})),
            r#"{"v":"\b\f"}"#.encode_utf16().count()
        );
        assert_eq!(
            javascript_json_stringify_len(&json!({"v": "😀"})),
            r#"{"v":"😀"}"#.encode_utf16().count()
        );
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
    fn stale_before_sign_in_cleanup_does_not_discard_pending_credentials() {
        let now = LogicalInstant::from_unix_seconds(1_788_004_860);
        let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let uid = store
            .create_user_with_password(NewUser::email("pending@example.com"), "hunter22", now)
            .unwrap();
        store
            .set_phone_factors(
                &uid,
                vec![("+15550001234".to_owned(), Some("primary".to_owned()))],
                now,
            )
            .unwrap();
        let pending = store
            .start_mfa_sign_in_with_context(
                &uid,
                now,
                PendingSignInContext::new_with_credentials(
                    Some("password".to_owned()),
                    false,
                    None,
                    Some(PendingSignInCredentials::new(
                        Some("access-token".to_owned()),
                        Some("id-token".to_owned()),
                        Some("refresh-token".to_owned()),
                    )),
                ),
            )
            .unwrap();
        let store = Arc::new(Mutex::new(store));
        let settings_gate = Arc::new(Mutex::new(()));
        let result = discard_pending_inbound_credentials_if_revision_current(
            &store,
            Some(&pending),
            &settings_gate,
            &FixedBlockingRevision(1),
            0,
        );
        let response = result.unwrap_err();
        assert_eq!(response.status, 409);

        let store = store.lock().unwrap();
        let credentials = store
            .pending_sign_in_context(&pending)
            .and_then(PendingSignInContext::inbound_credentials)
            .expect("revision drift must retain pending credentials");
        assert_eq!(credentials.access_token(), Some("access-token"));
        assert_eq!(credentials.id_token(), Some("id-token"));
        assert_eq!(credentials.refresh_token(), Some("refresh-token"));
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

    #[test]
    fn password_policy_versions_rejects_malformed_presence() {
        for versions in [
            json!([]),
            json!([{}, {}]),
            json!([{"customStrengthOptions": {}} , {}]),
        ] {
            let body = json!({
                "passwordPolicyEnforcementState": "ENFORCE",
                "passwordPolicyVersions": versions,
            });
            assert!(password_policy_from_config_json(&body).is_err());
        }
        assert!(password_policy_from_config_json(&json!({
            "passwordPolicyEnforcementState": "ENFORCE",
            "passwordPolicyVersions": null,
        }))
        .is_ok());
        assert!(password_policy_from_config_json(&json!({
            "passwordPolicyEnforcementState": "ENFORCE",
            "passwordPolicyVersions": [{"customStrengthOptions": {"minPasswordLength": 12}}]
        }))
        .is_ok());
    }
}
