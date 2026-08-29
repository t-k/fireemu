//! In-memory user store with TOTP enrollment / sign-in and ID token claim construction.

use core::fmt;
use std::collections::BTreeMap;

use ftd_core_limits::catalogs::FIREBASE_AUTH_2026_08_30;
use ftd_core_limits::evaluate::{evaluate, LimitDisposition, LimitViolation, DEFAULT_THRESHOLDS};
use ftd_core_limits::plan::FirestorePlanProfile;
use ftd_core_types::determinism::{DeterministicRng, SplitMix64};
use ftd_core_types::time::{LogicalDuration, LogicalInstant};

use crate::claims::{CustomClaims, FirebaseClaims, IdTokenClaims};
use crate::mfa::{
    match_code, CodeMatch, EnrolledFactor, MfaError, MfaState, PendingEnrollment, PendingSignIn,
    TotpEnrollmentMaterial, TotpFactor, TotpPolicy, TotpSecret,
};

/// ID token lifetime (`AUTH-LIMIT-ID-TOKEN-TTL-SECONDS`).
const ID_TOKEN_TTL_SECONDS: i64 = 3_600;

/// User local ID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalId(String);

impl LocalId {
    /// Text form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LocalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Sign-in provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provider {
    /// Email + password.
    Password,
    /// Anonymous.
    Anonymous,
    /// Custom token.
    Custom,
}

impl Provider {
    fn id(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Anonymous => "anonymous",
            Self::Custom => "custom",
        }
    }
}

/// New user request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUser {
    /// Email.
    pub email: Option<String>,
    /// Email verified.
    pub email_verified: bool,
    /// Provider.
    pub provider: Provider,
}

impl NewUser {
    /// Password user with `email`.
    #[must_use]
    pub fn email(email: &str) -> Self {
        Self {
            email: Some(email.to_owned()),
            email_verified: false,
            provider: Provider::Password,
        }
    }

    /// Anonymous user.
    #[must_use]
    pub const fn anonymous() -> Self {
        Self {
            email: None,
            email_verified: false,
            provider: Provider::Anonymous,
        }
    }
}

/// User record.
#[derive(Debug, Clone, PartialEq)]
pub struct UserRecord {
    /// Local ID.
    pub local_id: LocalId,
    /// Email.
    pub email: Option<String>,
    /// Email verified.
    pub email_verified: bool,
    /// Display name.
    pub display_name: Option<String>,
    /// Disabled flag.
    pub disabled: bool,
    /// Provider.
    pub provider: Provider,
    /// Custom claims.
    pub custom_claims: CustomClaims,
    /// MFA state.
    pub mfa: MfaState,
    /// Creation time.
    pub created_at: LogicalInstant,
    /// Last sign-in.
    pub last_sign_in_at: Option<LogicalInstant>,
    /// Tokens issued before this instant are revoked.
    pub tokens_valid_after: LogicalInstant,
    /// Salted password digest (local test hashing, not Firebase's scrypt). `None` for users
    /// without a password credential.
    password: Option<PasswordDigest>,
}

/// Salted SHA-1 digest of a password. Test-only hashing: never claims scrypt compatibility.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordDigest {
    salt: [u8; 16],
    digest: [u8; 20],
}

impl fmt::Debug for PasswordDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordDigest([redacted])")
    }
}

impl PasswordDigest {
    fn new(salt: [u8; 16], password: &str) -> Self {
        let mut input = Vec::with_capacity(16 + password.len());
        input.extend_from_slice(&salt);
        input.extend_from_slice(password.as_bytes());
        Self {
            salt,
            digest: crate::sha1::sha1(&input),
        }
    }

    fn verify(&self, password: &str) -> bool {
        Self::new(self.salt, password).digest == self.digest
    }
}

/// Auth errors.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthError {
    /// Unknown user.
    UserNotFound,
    /// Duplicate email.
    EmailExists,
    /// Invalid email syntax.
    InvalidEmail,
    /// Password shorter than six characters (Firebase minimum).
    WeakPassword,
    /// Unknown email or wrong password.
    InvalidCredentials,
    /// The user is disabled.
    UserDisabled,
    /// Unknown or revoked refresh token.
    InvalidRefreshToken,
    /// Caller-chosen user ID is malformed.
    InvalidLocalId,
    /// Caller-chosen user ID already exists.
    LocalIdExists,
    /// Limit violation.
    LimitExceeded(LimitViolation),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserNotFound => f.write_str("user not found"),
            Self::EmailExists => f.write_str("email already exists"),
            Self::InvalidEmail => f.write_str("invalid email"),
            Self::WeakPassword => f.write_str("password must be at least 6 characters"),
            Self::InvalidCredentials => f.write_str("invalid email or password"),
            Self::UserDisabled => f.write_str("user is disabled"),
            Self::InvalidRefreshToken => f.write_str("invalid refresh token"),
            Self::InvalidLocalId => f.write_str("invalid local id"),
            Self::LocalIdExists => f.write_str("local id already exists"),
            Self::LimitExceeded(v) => write!(f, "limit exceeded: {v}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// Result of a completed second-factor sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecondFactorAssertion {
    /// `totp`
    pub sign_in_second_factor: String,
    /// Enrollment ID.
    pub second_factor_identifier: String,
    /// When the factor was verified.
    pub verified_at: LogicalInstant,
}

/// Pending sign-in handle (`mfaPendingCredential` on the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSignInId(String);

impl PendingSignInId {
    /// Text form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parses an opaque credential string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        (!s.is_empty() && !s.chars().any(char::is_control)).then(|| Self(s.to_owned()))
    }
}

/// Deterministic in-memory auth store for one project.
#[derive(Debug)]
pub struct AuthStore {
    project_id: String,
    rng: SplitMix64,
    policy: TotpPolicy,
    users: BTreeMap<LocalId, UserRecord>,
    counter: u64,
    refresh_tokens: BTreeMap<String, (LocalId, LogicalInstant)>,
    next_id_override: Option<String>,
}

impl AuthStore {
    /// Creates a store for `project_id`.
    #[must_use]
    pub fn new(project_id: &str, rng: SplitMix64, policy: TotpPolicy) -> Self {
        Self {
            project_id: project_id.to_owned(),
            rng,
            policy,
            users: BTreeMap::new(),
            counter: 0,
            refresh_tokens: BTreeMap::new(),
            next_id_override: None,
        }
    }

    /// TOTP policy.
    #[must_use]
    pub const fn policy(&self) -> &TotpPolicy {
        &self.policy
    }

    /// Project ID (token audience).
    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Looks up a user by its ID text.
    #[must_use]
    pub fn user_by_id(&self, uid: &str) -> Option<&UserRecord> {
        self.users
            .iter()
            .find(|(k, _)| k.as_str() == uid)
            .map(|(_, u)| u)
    }

    fn next_id(&mut self, prefix: &str) -> String {
        self.counter += 1;
        format!(
            "{prefix}{:016x}{:04}",
            self.rng.next_u64(),
            self.counter % 10_000
        )
    }

    fn random_secret(&mut self) -> TotpSecret {
        let mut bytes = Vec::with_capacity(20);
        for _ in 0..3 {
            bytes.extend_from_slice(&self.rng.next_u64().to_be_bytes());
        }
        bytes.truncate(20);
        TotpSecret::new(bytes)
    }

    /// Creates a user with a caller-chosen ID (Admin SDK `uid`), or a generated one.
    pub fn create_user_with_id(
        &mut self,
        new: NewUser,
        id: Option<&str>,
        now: LogicalInstant,
    ) -> Result<LocalId, AuthError> {
        match id {
            None => self.create_user(new, now),
            Some(id) => {
                if id.is_empty() || id.chars().count() > 128 || id.chars().any(char::is_control) {
                    return Err(AuthError::InvalidLocalId);
                }
                if self.users.contains_key(&LocalId(id.to_owned())) {
                    return Err(AuthError::LocalIdExists);
                }
                self.next_id_override = Some(id.to_owned());
                let result = self.create_user(new, now);
                self.next_id_override = None;
                result
            }
        }
    }

    /// Deletes a user and its refresh tokens.
    pub fn delete_user_by_id(&mut self, uid: &str) -> Result<(), AuthError> {
        let key = LocalId(uid.to_owned());
        self.users.remove(&key).ok_or(AuthError::UserNotFound)?;
        self.refresh_tokens.retain(|_, (owner, _)| owner != &key);
        Ok(())
    }

    /// All user IDs in canonical order.
    #[must_use]
    pub fn all_user_ids(&self) -> Vec<LocalId> {
        self.users.keys().cloned().collect()
    }

    /// Creates a user.
    pub fn create_user(&mut self, new: NewUser, now: LogicalInstant) -> Result<LocalId, AuthError> {
        if let Some(email) = &new.email {
            if !email.contains('@') || email.chars().any(char::is_control) {
                return Err(AuthError::InvalidEmail);
            }
            if self
                .users
                .values()
                .any(|u| u.email.as_deref() == Some(email.as_str()))
            {
                return Err(AuthError::EmailExists);
            }
        }
        let local_id = match self.next_id_override.take() {
            Some(id) => LocalId(id),
            None => loop {
                // Generated IDs share the namespace with caller-chosen ones: skip collisions.
                let candidate = LocalId(self.next_id("u"));
                if !self.users.contains_key(&candidate) {
                    break candidate;
                }
            },
        };
        let std::collections::btree_map::Entry::Vacant(slot) = self.users.entry(local_id.clone())
        else {
            return Err(AuthError::LocalIdExists);
        };
        slot.insert(UserRecord {
            local_id: local_id.clone(),
            email: new.email,
            email_verified: new.email_verified,
            display_name: None,
            disabled: false,
            provider: new.provider,
            custom_claims: CustomClaims::default(),
            mfa: MfaState::default(),
            created_at: now,
            last_sign_in_at: None,
            tokens_valid_after: now,
            password: None,
        });
        Ok(local_id)
    }

    /// Minimum password length enforced by Firebase.
    pub const MIN_PASSWORD_CHARS: usize = 6;

    /// Validates a password without storing it (lets callers fail before mutating).
    pub fn validate_password(password: &str) -> Result<(), AuthError> {
        if password.chars().count() < Self::MIN_PASSWORD_CHARS {
            return Err(AuthError::WeakPassword);
        }
        if password.chars().any(char::is_control) {
            return Err(AuthError::WeakPassword);
        }
        Ok(())
    }

    /// Removes every refresh token of `uid` (password change, explicit revocation).
    pub fn revoke_refresh_tokens(&mut self, uid: &LocalId) {
        self.refresh_tokens.retain(|_, (owner, _)| owner != uid);
    }

    /// Sets a password credential.
    pub fn set_password(&mut self, uid: &LocalId, password: &str) -> Result<(), AuthError> {
        Self::validate_password(password)?;
        let mut salt = [0u8; 16];
        salt[..8].copy_from_slice(&self.rng.next_u64().to_be_bytes());
        salt[8..].copy_from_slice(&self.rng.next_u64().to_be_bytes());
        let user = self.users.get_mut(uid).ok_or(AuthError::UserNotFound)?;
        user.password = Some(PasswordDigest::new(salt, password));
        Ok(())
    }

    /// Verifies an email + password sign-in; returns the user ID.
    pub fn verify_password(
        &mut self,
        email: &str,
        password: &str,
        now: LogicalInstant,
    ) -> Result<LocalId, AuthError> {
        let (uid, disabled, ok) = self
            .users
            .values()
            .find(|u| u.email.as_deref() == Some(email))
            .map(|u| {
                (
                    u.local_id.clone(),
                    u.disabled,
                    u.password.as_ref().is_some_and(|p| p.verify(password)),
                )
            })
            .ok_or(AuthError::InvalidCredentials)?;
        if !ok {
            return Err(AuthError::InvalidCredentials);
        }
        if disabled {
            return Err(AuthError::UserDisabled);
        }
        if let Some(u) = self.users.get_mut(&uid) {
            u.last_sign_in_at = Some(now);
        }
        Ok(uid)
    }

    /// Looks up a user by email.
    #[must_use]
    pub fn user_by_email(&self, email: &str) -> Option<&UserRecord> {
        self.users
            .values()
            .find(|u| u.email.as_deref() == Some(email))
    }

    /// Issues a refresh token bound to `uid` at `now`.
    pub fn issue_refresh_token(
        &mut self,
        uid: &LocalId,
        now: LogicalInstant,
    ) -> Result<String, AuthError> {
        if !self.users.contains_key(uid) {
            return Err(AuthError::UserNotFound);
        }
        let token = self.next_id("rt-");
        self.refresh_tokens
            .insert(token.clone(), (uid.clone(), now));
        Ok(token)
    }

    /// Redeems a refresh token: unknown tokens, tokens issued before a revocation, and disabled
    /// users are rejected.
    pub fn redeem_refresh_token(&self, token: &str) -> Result<LocalId, AuthError> {
        let (uid, issued_at) = self
            .refresh_tokens
            .get(token)
            .ok_or(AuthError::InvalidRefreshToken)?;
        let user = self.users.get(uid).ok_or(AuthError::InvalidRefreshToken)?;
        if user.disabled {
            return Err(AuthError::UserDisabled);
        }
        if *issued_at < user.tokens_valid_after {
            return Err(AuthError::InvalidRefreshToken);
        }
        Ok(uid.clone())
    }

    /// Looks up a user.
    #[must_use]
    pub fn user(&self, uid: &LocalId) -> Option<&UserRecord> {
        self.users.get(uid)
    }

    /// Mutable user access.
    pub fn user_mut(&mut self, uid: &LocalId) -> Option<&mut UserRecord> {
        self.users.get_mut(uid)
    }

    /// Sets custom claims after the size check.
    pub fn set_custom_claims(
        &mut self,
        uid: &LocalId,
        claims: CustomClaims,
    ) -> Result<(), AuthError> {
        claims.check_size().map_err(AuthError::LimitExceeded)?;
        let user = self.users.get_mut(uid).ok_or(AuthError::UserNotFound)?;
        user.custom_claims = claims;
        Ok(())
    }

    /// Starts TOTP enrollment.
    pub fn start_totp_enrollment(
        &mut self,
        uid: &LocalId,
        now: LogicalInstant,
    ) -> Result<TotpEnrollmentMaterial, MfaError> {
        let policy = self.policy;
        let user = self.users.get(uid).ok_or(MfaError::UserNotFound)?;
        if user.disabled {
            return Err(MfaError::UserDisabled);
        }
        let def = FIREBASE_AUTH_2026_08_30
            .find("AUTH-LIMIT-TOTP-FACTORS-PER-USER")
            .unwrap_or_else(|| unreachable!("catalog entry is checked by catalog tests"));
        let prospective = user.mfa.totp_factors().len() as u64 + 1;
        let plan = FirestorePlanProfile::default();
        match evaluate(
            def,
            prospective.max(u64::from(policy.max_totp_factors_per_user).min(prospective)),
            &plan,
            DEFAULT_THRESHOLDS,
        ) {
            LimitDisposition::Reject(v) | LimitDisposition::ObservedOverLimit(v) => {
                return Err(MfaError::LimitExceeded(v))
            }
            LimitDisposition::Allow | LimitDisposition::AllowWithWarnings(_) => {}
        }
        if prospective > u64::from(policy.max_totp_factors_per_user) {
            // Policy stricter than the catalog: reuse the catalog violation shape.
            if let LimitDisposition::Reject(v) =
                evaluate(def, prospective, &plan, DEFAULT_THRESHOLDS)
            {
                return Err(MfaError::LimitExceeded(v));
            }
        }
        let account = user
            .email
            .clone()
            .unwrap_or_else(|| uid.as_str().to_owned());
        let secret = self.random_secret();
        let session_id = self.next_id("enroll-");
        let expires_at = now
            .checked_add(policy.enrollment_session_ttl)
            .unwrap_or(LogicalInstant::MAX);
        let material = TotpEnrollmentMaterial::new(
            session_id.clone(),
            &self.project_id,
            &account,
            secret.clone(),
            policy.params(),
            expires_at,
        );
        let user = self.users.get_mut(uid).ok_or(MfaError::UserNotFound)?;
        user.mfa
            .pending_enrollments_mut()
            .insert(session_id, PendingEnrollment { secret, expires_at });
        Ok(material)
    }

    /// Finalizes enrollment with a code generated from the proposed secret.
    pub fn finalize_totp_enrollment(
        &mut self,
        uid: &LocalId,
        session_id: &str,
        code: u32,
        now: LogicalInstant,
    ) -> Result<EnrolledFactor, MfaError> {
        let policy = self.policy;
        let enrollment_id = self.next_id("mfa-");
        let user = self.users.get_mut(uid).ok_or(MfaError::UserNotFound)?;
        let pending = user
            .mfa
            .pending_enrollments_mut()
            .get(session_id)
            .cloned()
            .ok_or(MfaError::EnrollmentSessionUnknown)?;
        if now > pending.expires_at {
            user.mfa.pending_enrollments_mut().remove(session_id);
            return Err(MfaError::EnrollmentSessionExpired);
        }
        let step = match match_code(
            &pending.secret,
            &policy.params(),
            policy.window_steps,
            None,
            code,
            now,
        ) {
            CodeMatch::Accepted { step } => step,
            CodeMatch::Replayed | CodeMatch::NoMatch => return Err(MfaError::InvalidCode),
        };
        user.mfa.pending_enrollments_mut().remove(session_id);
        let factor = TotpFactor {
            mfa_enrollment_id: enrollment_id.clone(),
            display_name: None,
            secret: pending.secret,
            enrolled_at: now,
            last_accepted_step: Some(step),
        };
        user.mfa.totp_factors_mut().push(factor);
        Ok(EnrolledFactor {
            mfa_enrollment_id: enrollment_id,
            display_name: None,
            enrolled_at: now,
        })
    }

    /// Starts the second-factor step of a sign-in.
    pub fn start_mfa_sign_in(
        &mut self,
        uid: &LocalId,
        now: LogicalInstant,
    ) -> Result<PendingSignInId, MfaError> {
        let pending_id = self.next_id("signin-");
        let user = self.users.get_mut(uid).ok_or(MfaError::UserNotFound)?;
        if user.disabled {
            return Err(MfaError::UserDisabled);
        }
        if user.mfa.totp_factors().is_empty() {
            return Err(MfaError::NoEnrolledFactor);
        }
        user.mfa
            .pending_sign_ins_mut()
            .insert(pending_id.clone(), PendingSignIn { started_at: now });
        Ok(PendingSignInId(pending_id))
    }

    /// User that owns a pending sign-in, if any.
    #[must_use]
    pub fn pending_sign_in_user(&self, pending: &PendingSignInId) -> Option<LocalId> {
        self.users
            .values()
            .find(|u| u.mfa.has_pending_sign_in(&pending.0))
            .map(|u| u.local_id.clone())
    }

    /// Completes the second-factor step.
    pub fn finalize_mfa_sign_in(
        &mut self,
        uid: &LocalId,
        pending: &PendingSignInId,
        code: u32,
        now: LogicalInstant,
    ) -> Result<SecondFactorAssertion, MfaError> {
        let policy = self.policy;
        let user = self.users.get_mut(uid).ok_or(MfaError::UserNotFound)?;
        if user.mfa.pending_sign_ins_mut().remove(&pending.0).is_none() {
            return Err(MfaError::PendingSignInUnknown);
        }
        let mut replayed = false;
        for factor in user.mfa.totp_factors_mut() {
            match match_code(
                &factor.secret,
                &policy.params(),
                policy.window_steps,
                factor.last_accepted_step,
                code,
                now,
            ) {
                CodeMatch::Accepted { step } => {
                    factor.last_accepted_step = Some(step);
                    user.last_sign_in_at = Some(now);
                    return Ok(SecondFactorAssertion {
                        sign_in_second_factor: "totp".to_owned(),
                        second_factor_identifier: factor.mfa_enrollment_id.clone(),
                        verified_at: now,
                    });
                }
                CodeMatch::Replayed => replayed = true,
                CodeMatch::NoMatch => {}
            }
        }
        Err(if replayed {
            MfaError::CodeAlreadyUsed
        } else {
            MfaError::InvalidCode
        })
    }

    /// Builds ID token claims for `uid`, optionally with a verified second factor.
    pub fn id_token_claims(
        &self,
        uid: &LocalId,
        second_factor: Option<&SecondFactorAssertion>,
        now: LogicalInstant,
    ) -> Result<IdTokenClaims, AuthError> {
        let user = self.users.get(uid).ok_or(AuthError::UserNotFound)?;
        let iat = i64::try_from(now.as_nanos().div_euclid(1_000_000_000)).unwrap_or(i64::MAX);
        let mut identities = BTreeMap::new();
        if let Some(email) = &user.email {
            identities.insert("email".to_owned(), vec![email.clone()]);
        }
        // INV-AUTH-002: a second factor claim only ever comes from an enrolled factor.
        let second = second_factor.filter(|a| {
            user.mfa
                .totp_factors()
                .iter()
                .any(|f| f.mfa_enrollment_id == a.second_factor_identifier)
        });
        Ok(IdTokenClaims {
            iss: format!("https://securetoken.google.com/{}", self.project_id),
            aud: self.project_id.clone(),
            auth_time: iat,
            user_id: uid.as_str().to_owned(),
            sub: uid.as_str().to_owned(),
            iat,
            exp: iat.saturating_add(ID_TOKEN_TTL_SECONDS),
            email: user.email.clone(),
            email_verified: user.email_verified,
            firebase: FirebaseClaims {
                identities,
                sign_in_provider: user.provider.id().to_owned(),
                sign_in_second_factor: second.map(|a| a.sign_in_second_factor.clone()),
                second_factor_identifier: second.map(|a| a.second_factor_identifier.clone()),
            },
            custom: user.custom_claims.clone(),
        })
    }

    /// Revokes refresh tokens: tokens issued before `now` become invalid.
    pub fn revoke_tokens(&mut self, uid: &LocalId, now: LogicalInstant) -> Result<(), AuthError> {
        let user = self.users.get_mut(uid).ok_or(AuthError::UserNotFound)?;
        user.tokens_valid_after = now;
        Ok(())
    }

    /// Whether a token with `auth_time` is still valid for `uid` at `now`.
    #[must_use]
    pub fn token_is_valid(
        &self,
        uid: &LocalId,
        auth_time: LogicalInstant,
        exp: LogicalInstant,
        now: LogicalInstant,
    ) -> bool {
        self.users
            .get(uid)
            .is_some_and(|u| !u.disabled && auth_time >= u.tokens_valid_after && now < exp)
    }

    /// Token lifetime.
    #[must_use]
    pub const fn id_token_ttl() -> LogicalDuration {
        LogicalDuration::from_seconds(ID_TOKEN_TTL_SECONDS)
    }
}
