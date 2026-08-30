//! TOTP second-factor state (spec 12A.5).
//!
//! ```text
//! NotEnrolled -> EnrollmentStarted(secret, session, expires) -> Enrolled(factor)
//!                        `-> Expired
//! Enrolled -> SignInPending(session) -> SignedIn(second factor assertion)
//! ```
//!
//! Invariants: a code for a time step at or below the last accepted step is never accepted
//! again (`INV-AUTH-001`); shared secrets never appear in `Debug` output (`INV-AUTH-003`).

use core::fmt;
use std::collections::BTreeMap;

use fireemu_core_limits::evaluate::LimitViolation;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

use crate::base32;
use crate::totp::{hotp, time_step, TotpParams};

/// TOTP policy (versioned; unconfirmed values are conformance items).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpPolicy {
    /// Time step in seconds.
    pub period_seconds: u32,
    /// Code digits.
    pub digits: u8,
    /// Accepted steps before and after the current one.
    pub window_steps: u8,
    /// Enrollment session lifetime.
    pub enrollment_session_ttl: LogicalDuration,
    /// Maximum TOTP factors per user (`AUTH-LIMIT-TOTP-FACTORS-PER-USER`).
    pub max_totp_factors_per_user: u32,
}

impl Default for TotpPolicy {
    fn default() -> Self {
        Self {
            period_seconds: 30,
            digits: 6,
            window_steps: 1,
            enrollment_session_ttl: LogicalDuration::from_seconds(300),
            max_totp_factors_per_user: 1,
        }
    }
}

impl TotpPolicy {
    /// Code parameters.
    #[must_use]
    pub const fn params(&self) -> TotpParams {
        TotpParams {
            period_seconds: self.period_seconds,
            digits: self.digits,
        }
    }
}

/// A shared secret. `Debug` never prints the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpSecret(Vec<u8>);

impl TotpSecret {
    /// Wraps raw secret bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Exposes the bytes. Only enrollment (to build the `otpauth` URI) and tests may call this.
    #[must_use]
    pub fn expose_for_enrollment(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSecret([redacted])")
    }
}

/// An enrolled TOTP factor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpFactor {
    /// Enrollment ID (`second_factor_identifier` in tokens).
    pub mfa_enrollment_id: String,
    /// Display name.
    pub display_name: Option<String>,
    /// Shared secret.
    pub secret: TotpSecret,
    /// Enrollment time.
    pub enrolled_at: LogicalInstant,
    /// Highest accepted time step (replay protection).
    pub last_accepted_step: Option<u64>,
}

/// An enrolled phone (SMS) factor. Codes are delivered through the runtime's verification
/// code list (no SMS is sent), like the Firebase Auth Emulator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhoneFactor {
    /// Enrollment ID (`second_factor_identifier` in tokens).
    pub mfa_enrollment_id: String,
    /// Display name.
    pub display_name: Option<String>,
    /// Phone number (E.164).
    pub phone_number: String,
    /// Enrollment time.
    pub enrolled_at: LogicalInstant,
}

/// Maximum second factors of every kind per user (Firebase: five).
pub const MAX_FACTORS_PER_USER: usize = 5;

/// Public view of an enrolled factor (no secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledFactor {
    /// Enrollment ID.
    pub mfa_enrollment_id: String,
    /// Display name.
    pub display_name: Option<String>,
    /// Enrollment time.
    pub enrolled_at: LogicalInstant,
}

/// Pending enrollment session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEnrollment {
    /// Secret proposed for this session.
    pub secret: TotpSecret,
    /// Expiry.
    pub expires_at: LogicalInstant,
}

/// Pending second-factor sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSignIn {
    /// Started at.
    pub started_at: LogicalInstant,
}

/// Enrollment material returned to the client. `Debug` redacts the secret and the URI.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpEnrollmentMaterial {
    /// Enrollment session ID.
    pub session_id: String,
    /// `otpauth://totp/...` URI (contains the secret).
    pub otpauth_uri: String,
    /// Session expiry.
    pub expires_at: LogicalInstant,
    secret: TotpSecret,
}

impl TotpEnrollmentMaterial {
    pub(crate) fn new(
        session_id: String,
        issuer: &str,
        account: &str,
        secret: TotpSecret,
        params: TotpParams,
        expires_at: LogicalInstant,
    ) -> Self {
        let otpauth_uri = format!(
            "otpauth://totp/{issuer}:{account}?secret={}&issuer={issuer}&algorithm=SHA1&digits={}&period={}",
            base32::encode(secret.expose_for_enrollment()),
            params.digits,
            params.period_seconds
        );
        Self {
            session_id,
            otpauth_uri,
            expires_at,
            secret,
        }
    }

    /// Secret bytes for tests that need to compute codes.
    #[must_use]
    pub fn secret_for_test(&self) -> &[u8] {
        self.secret.expose_for_enrollment()
    }
}

impl fmt::Debug for TotpEnrollmentMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpEnrollmentMaterial")
            .field("session_id", &self.session_id)
            .field("otpauth_uri", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .field("secret", &self.secret)
            .finish()
    }
}

/// Why a second factor an import artifact recorded was refused.
///
/// This is deliberately separate from [`MfaError`]: nothing on the enrollment or sign-in
/// paths can produce it, and the adapters that map `MfaError` to Identity Toolkit error
/// codes have no code to map it to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportedFactorError {
    /// More than [`MAX_FACTORS_PER_USER`] factors on one account.
    TooMany,
    /// A factor has an empty enrollment id, or two share one.
    InvalidEnrollmentId,
}

impl fmt::Display for ImportedFactorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooMany => write!(
                f,
                "an imported account has more than {MAX_FACTORS_PER_USER} second factors"
            ),
            Self::InvalidEnrollmentId => f.write_str(
                "an imported second factor has an empty enrollment id, or two share one",
            ),
        }
    }
}

impl std::error::Error for ImportedFactorError {}

/// MFA errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MfaError {
    /// Unknown user.
    UserNotFound,
    /// The user is disabled.
    UserDisabled,
    /// The code does not match any step in the window.
    InvalidCode,
    /// The code matched a step that was already consumed.
    CodeAlreadyUsed,
    /// Enrollment session expired.
    EnrollmentSessionExpired,
    /// Unknown enrollment session.
    EnrollmentSessionUnknown,
    /// Unknown pending sign-in.
    PendingSignInUnknown,
    /// No enrolled factor.
    NoEnrolledFactor,
    /// More than [`MAX_FACTORS_PER_USER`] factors.
    TooManyFactors,
    /// A limit was violated.
    LimitExceeded(LimitViolation),
}

impl fmt::Display for MfaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserNotFound => f.write_str("user not found"),
            Self::UserDisabled => f.write_str("user is disabled"),
            Self::InvalidCode => f.write_str("invalid verification code"),
            Self::CodeAlreadyUsed => f.write_str("verification code already used"),
            Self::EnrollmentSessionExpired => f.write_str("enrollment session expired"),
            Self::EnrollmentSessionUnknown => f.write_str("unknown enrollment session"),
            Self::PendingSignInUnknown => f.write_str("unknown pending sign-in"),
            Self::NoEnrolledFactor => f.write_str("no second factor enrolled"),
            Self::TooManyFactors => f.write_str("too many second factors"),
            Self::LimitExceeded(v) => write!(f, "limit exceeded: {v}"),
        }
    }
}

impl std::error::Error for MfaError {}

/// Per-user MFA state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MfaState {
    totp: Vec<TotpFactor>,
    phone: Vec<PhoneFactor>,
    pending_enrollments: BTreeMap<String, PendingEnrollment>,
    pending_sign_ins: BTreeMap<String, PendingSignIn>,
}

/// Outcome of matching a code against a factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeMatch {
    /// Matched at this step and the step is fresh.
    Accepted {
        /// Matched step.
        step: u64,
    },
    /// Matched a step at or below the last accepted step.
    Replayed,
    /// No step in the window matched.
    NoMatch,
}

/// Matches `code` against `secret` within `window_steps` of `now`, honouring replay state.
#[must_use]
pub fn match_code(
    secret: &TotpSecret,
    params: &TotpParams,
    window_steps: u8,
    last_accepted: Option<u64>,
    code: u32,
    now: LogicalInstant,
) -> CodeMatch {
    let current = time_step(params, now);
    let window = u64::from(window_steps);
    let low = current.saturating_sub(window);
    let high = current.saturating_add(window);
    let mut replayed = false;
    for step in low..=high {
        if hotp(secret.expose_for_enrollment(), step, params.digits) == code {
            match last_accepted {
                Some(last) if step <= last => replayed = true,
                _ => return CodeMatch::Accepted { step },
            }
        }
    }
    if replayed {
        CodeMatch::Replayed
    } else {
        CodeMatch::NoMatch
    }
}

impl MfaState {
    /// Enrolled TOTP factors.
    #[must_use]
    pub fn totp_factors(&self) -> &[TotpFactor] {
        &self.totp
    }

    pub(crate) fn totp_factors_mut(&mut self) -> &mut Vec<TotpFactor> {
        &mut self.totp
    }

    /// Enrolled phone factors.
    #[must_use]
    pub fn phone_factors(&self) -> &[PhoneFactor] {
        &self.phone
    }

    pub(crate) fn phone_factors_mut(&mut self) -> &mut Vec<PhoneFactor> {
        &mut self.phone
    }

    /// Installs the second factors an import artifact recorded, with their enrollment ids,
    /// display names, secrets and enrollment times.
    ///
    /// The per-user factor limit still applies, and every enrollment id must be unique and
    /// non-empty: an artifact that gave two factors the same id would make the second
    /// unreachable through the enrollment routes.
    pub fn import_factors(
        &mut self,
        totp: Vec<TotpFactor>,
        phone: Vec<PhoneFactor>,
    ) -> Result<(), ImportedFactorError> {
        if totp.len() + phone.len() > MAX_FACTORS_PER_USER {
            return Err(ImportedFactorError::TooMany);
        }
        let mut seen = std::collections::BTreeSet::new();
        for id in totp
            .iter()
            .map(|f| &f.mfa_enrollment_id)
            .chain(phone.iter().map(|f| &f.mfa_enrollment_id))
        {
            if id.is_empty() || !seen.insert(id.clone()) {
                return Err(ImportedFactorError::InvalidEnrollmentId);
            }
        }
        self.totp = totp;
        self.phone = phone;
        Ok(())
    }

    /// Whether no second factor of any kind is enrolled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.totp.is_empty() && self.phone.is_empty()
    }

    /// Number of enrolled factors of every kind.
    #[must_use]
    pub fn factor_count(&self) -> usize {
        self.totp.len() + self.phone.len()
    }

    /// Whether `id` names an enrolled factor of any kind.
    #[must_use]
    pub fn has_factor(&self, id: &str) -> bool {
        self.totp.iter().any(|f| f.mfa_enrollment_id == id)
            || self.phone.iter().any(|f| f.mfa_enrollment_id == id)
    }

    pub(crate) fn pending_enrollments_mut(&mut self) -> &mut BTreeMap<String, PendingEnrollment> {
        &mut self.pending_enrollments
    }

    pub(crate) fn pending_sign_ins_mut(&mut self) -> &mut BTreeMap<String, PendingSignIn> {
        &mut self.pending_sign_ins
    }

    pub(crate) fn has_pending_sign_in(&self, id: &str) -> bool {
        self.pending_sign_ins.contains_key(id)
    }

    /// Clears replay state. Test helper for stepping through window fixtures.
    pub fn reset_replay_state_for_test(&mut self) {
        for f in &mut self.totp {
            f.last_accepted_step = None;
        }
    }
}
