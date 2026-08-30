//! In-memory user store with TOTP enrollment / sign-in and ID token claim construction.

use core::fmt;
use std::collections::BTreeMap;
use std::sync::Arc;

use ftd_core_limits::catalogs::FIREBASE_AUTH_2026_08_30;
use ftd_core_limits::evaluate::{evaluate, LimitDisposition, LimitViolation, DEFAULT_THRESHOLDS};
use ftd_core_limits::plan::FirestorePlanProfile;
use ftd_core_types::determinism::{DeterministicRng, SplitMix64};
use ftd_core_types::time::{LogicalDuration, LogicalInstant};

use crate::claims::{CustomClaims, FirebaseClaims, IdTokenClaims};
use crate::mfa::{
    match_code, CodeMatch, EnrolledFactor, MfaError, MfaState, PendingEnrollment, PendingSignIn,
    PhoneFactor, TotpEnrollmentMaterial, TotpFactor, TotpPolicy, TotpSecret, MAX_FACTORS_PER_USER,
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
    /// Phone number (SMS code).
    Phone,
    /// Email link (passwordless).
    EmailLink,
    /// A federated identity provider (`google.com`, `apple.com`, ...; fixture provider only).
    Federated(String),
}

impl Provider {
    /// Provider ID as it appears in `firebase.sign_in_provider`.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Password => "password",
            Self::Anonymous => "anonymous",
            Self::Custom => "custom",
            Self::Phone => "phone",
            Self::EmailLink => "emailLink",
            Self::Federated(id) => id,
        }
    }
}

/// A linked federated identity (`providerUserInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedIdentity {
    /// Provider ID (`google.com`).
    pub provider_id: String,
    /// The provider's user ID (`sub`).
    pub raw_id: String,
    /// Email at the provider.
    pub email: Option<String>,
    /// Display name at the provider.
    pub display_name: Option<String>,
    /// Photo URL at the provider.
    pub photo_url: Option<String>,
}

/// Out-of-band (email action) code kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OobRequestType {
    /// Password reset.
    PasswordReset,
    /// Email verification.
    VerifyEmail,
    /// Email link sign-in.
    EmailSignIn,
    /// Verify and change the email.
    VerifyAndChangeEmail,
}

impl OobRequestType {
    /// The Identity Toolkit `requestType` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PasswordReset => "PASSWORD_RESET",
            Self::VerifyEmail => "VERIFY_EMAIL",
            Self::EmailSignIn => "EMAIL_SIGNIN",
            Self::VerifyAndChangeEmail => "VERIFY_AND_CHANGE_EMAIL",
        }
    }

    /// Parses the Identity Toolkit `requestType` name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "PASSWORD_RESET" => Self::PasswordReset,
            "VERIFY_EMAIL" => Self::VerifyEmail,
            "EMAIL_SIGNIN" => Self::EmailSignIn,
            "VERIFY_AND_CHANGE_EMAIL" => Self::VerifyAndChangeEmail,
            _ => return None,
        })
    }
}

/// An outstanding email action code. Never sent anywhere: tests read it from the store
/// (the `/emulator/v1/projects/{p}/oobCodes` list).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OobCode {
    /// The code.
    pub code: String,
    /// Kind.
    pub request_type: OobRequestType,
    /// Email the action concerns.
    pub email: String,
    /// User the action concerns (none for a sign-in link of an unknown email).
    pub uid: Option<LocalId>,
    /// New email (`VERIFY_AND_CHANGE_EMAIL`).
    pub new_email: Option<String>,
    /// Creation time.
    pub created_at: LogicalInstant,
}

/// What a phone verification code is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationPurpose {
    /// Phone sign-in / linking.
    SignIn,
    /// Enrolling a phone second factor.
    Enrollment {
        /// User enrolling.
        uid: LocalId,
    },
    /// The second-factor step of a sign-in.
    MfaSignIn {
        /// User signing in.
        uid: LocalId,
        /// Pending sign-in.
        pending: PendingSignInId,
        /// Factor being verified.
        enrollment_id: String,
    },
}

/// An outstanding phone verification code. Never sent as SMS: tests read it from the
/// store (the `/emulator/v1/projects/{p}/verificationCodes` list).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationCode {
    /// Session handle returned to the client.
    pub session_info: String,
    /// Phone number.
    pub phone_number: String,
    /// Six-digit code.
    pub code: String,
    /// Purpose.
    pub purpose: VerificationPurpose,
    /// Creation time.
    pub created_at: LogicalInstant,
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

/// What a refresh token restores: the user, when it was issued, and how the session was
/// obtained (sign-in provider, custom-token claims, second factor).
#[derive(Debug, Clone)]
pub struct RefreshSession {
    /// User.
    pub uid: LocalId,
    /// Issue time (revocation compares against it).
    pub issued_at: LogicalInstant,
    /// Provider override (`custom` for custom-token sign-ins).
    pub provider: Option<Provider>,
    /// Custom-token developer claims.
    pub claims: CustomClaims,
    /// Second factor of the session.
    pub second_factor: Option<SecondFactorAssertion>,
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
    /// Photo URL.
    pub photo_url: Option<String>,
    /// Phone number (E.164).
    pub phone_number: Option<String>,
    /// Creation sequence (stable listing order).
    pub sequence: u64,
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
    /// Linked federated identities.
    pub federated: Vec<FederatedIdentity>,
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
    /// Phone number already used by another user.
    PhoneNumberExists,
    /// Phone number is not E.164.
    InvalidPhoneNumber,
    /// Unknown email (password reset).
    EmailNotFound,
    /// Unknown, consumed or mismatched action code.
    InvalidOobCode,
    /// Unknown phone verification session.
    InvalidSessionInfo,
    /// Wrong phone verification code.
    InvalidVerificationCode,
    /// The federated identity is linked to another user.
    FederatedUserIdAlreadyLinked,
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
            Self::PhoneNumberExists => f.write_str("phone number already exists"),
            Self::InvalidPhoneNumber => f.write_str("invalid phone number"),
            Self::EmailNotFound => f.write_str("email not found"),
            Self::InvalidOobCode => f.write_str("invalid action code"),
            Self::InvalidSessionInfo => f.write_str("invalid verification session"),
            Self::InvalidVerificationCode => f.write_str("invalid verification code"),
            Self::FederatedUserIdAlreadyLinked => {
                f.write_str("federated identity linked to another user")
            }
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
    refresh_tokens: BTreeMap<String, RefreshSession>,
    next_id_override: Option<String>,
    next_sequence: u64,
    signer: Option<Arc<dyn crate::jwt::IdTokenSigner>>,
    oob_codes: BTreeMap<String, OobCode>,
    verification_codes: BTreeMap<String, VerificationCode>,
}

impl AuthStore {
    /// Installs the ID token signer (RS256 session key). Tokens issued afterwards are
    /// signed and only signed tokens verify.
    pub fn set_signer(&mut self, signer: Arc<dyn crate::jwt::IdTokenSigner>) {
        self.signer = Some(signer);
    }

    /// The ID token signer, if one is installed.
    #[must_use]
    pub fn signer(&self) -> Option<&dyn crate::jwt::IdTokenSigner> {
        self.signer.as_deref()
    }

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
            next_sequence: 0,
            signer: None,
            oob_codes: BTreeMap::new(),
            verification_codes: BTreeMap::new(),
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
        self.refresh_tokens.retain(|_, s| s.uid != key);
        Ok(())
    }

    /// Removes every user, credential and token (session reset). The project ID and the
    /// deterministic generator are kept so IDs stay reproducible per session.
    pub fn clear(&mut self) {
        self.users.clear();
        self.refresh_tokens.clear();
        self.oob_codes.clear();
        self.verification_codes.clear();
    }

    /// Records a successful sign-in (Admin `lastLoginAt`).
    pub fn record_sign_in(&mut self, uid: &LocalId, now: LogicalInstant) {
        if let Some(u) = self.users.get_mut(uid) {
            u.last_sign_in_at = Some(now);
        }
    }

    /// Users in creation order (stable `listUsers` paging).
    #[must_use]
    pub fn users_by_creation(&self) -> Vec<&UserRecord> {
        let mut users: Vec<&UserRecord> = self.users.values().collect();
        users.sort_by_key(|u| u.sequence);
        users
    }

    /// User by phone number.
    #[must_use]
    pub fn user_by_phone(&self, phone: &str) -> Option<&UserRecord> {
        self.users
            .values()
            .find(|u| u.phone_number.as_deref() == Some(phone))
    }

    /// Changes the email (unique across users).
    pub fn set_email(&mut self, uid: &LocalId, email: &str) -> Result<(), AuthError> {
        if !email.contains('@') || email.chars().any(char::is_control) {
            return Err(AuthError::InvalidEmail);
        }
        if self
            .users
            .values()
            .any(|u| u.local_id != *uid && u.email.as_deref() == Some(email))
        {
            return Err(AuthError::EmailExists);
        }
        let user = self.users.get_mut(uid).ok_or(AuthError::UserNotFound)?;
        user.email = Some(email.to_owned());
        Ok(())
    }

    /// Validates an E.164 phone number (`+` followed by 7..=15 digits).
    pub fn validate_phone_number(phone: &str) -> Result<(), AuthError> {
        let digits = phone.strip_prefix('+').unwrap_or("");
        if digits.is_empty()
            || !(7..=15).contains(&digits.len())
            || !digits.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(AuthError::InvalidPhoneNumber);
        }
        Ok(())
    }

    /// Sets or clears the phone number (unique across users).
    pub fn set_phone_number(
        &mut self,
        uid: &LocalId,
        phone: Option<&str>,
    ) -> Result<(), AuthError> {
        if let Some(phone) = phone {
            Self::validate_phone_number(phone)?;
            if self
                .users
                .values()
                .any(|u| u.local_id != *uid && u.phone_number.as_deref() == Some(phone))
            {
                return Err(AuthError::PhoneNumberExists);
            }
        }
        let user = self.users.get_mut(uid).ok_or(AuthError::UserNotFound)?;
        user.phone_number = phone.map(str::to_owned);
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
            photo_url: None,
            phone_number: None,
            sequence: {
                self.next_sequence += 1;
                self.next_sequence
            },
            disabled: false,
            provider: new.provider,
            custom_claims: CustomClaims::default(),
            mfa: MfaState::default(),
            created_at: now,
            last_sign_in_at: None,
            tokens_valid_after: now,
            federated: Vec::new(),
            password: None,
        });
        Ok(local_id)
    }

    // ---- email actions, phone sign-in, federated identities ----------------------------

    /// Creates an email action code.
    pub fn create_oob_code(
        &mut self,
        request_type: OobRequestType,
        email: &str,
        uid: Option<LocalId>,
        new_email: Option<String>,
        now: LogicalInstant,
    ) -> String {
        let code = self.next_id("oob-");
        self.oob_codes.insert(
            code.clone(),
            OobCode {
                code: code.clone(),
                request_type,
                email: email.to_owned(),
                uid,
                new_email,
                created_at: now,
            },
        );
        code
    }

    /// Outstanding email action codes, oldest first.
    #[must_use]
    pub fn oob_codes(&self) -> Vec<&OobCode> {
        let mut codes: Vec<&OobCode> = self.oob_codes.values().collect();
        codes.sort_by_key(|c| c.created_at);
        codes
    }

    /// An outstanding code (not consumed).
    #[must_use]
    pub fn oob_code(&self, code: &str) -> Option<&OobCode> {
        self.oob_codes.get(code)
    }

    /// Consumes an action code of the expected kind (any kind when `None`).
    pub fn consume_oob_code(
        &mut self,
        code: &str,
        expected: Option<OobRequestType>,
    ) -> Result<OobCode, AuthError> {
        let matches = self
            .oob_codes
            .get(code)
            .is_some_and(|c| expected.is_none_or(|e| c.request_type == e));
        if !matches {
            return Err(AuthError::InvalidOobCode);
        }
        self.oob_codes.remove(code).ok_or(AuthError::InvalidOobCode)
    }

    /// Creates a phone verification code for `phone` (a deterministic six-digit code).
    pub fn send_verification_code(
        &mut self,
        phone: &str,
        purpose: VerificationPurpose,
        now: LogicalInstant,
    ) -> Result<VerificationCode, AuthError> {
        Self::validate_phone_number(phone)?;
        let session_info = self.next_id("sms-");
        let code = format!("{:06}", self.rng.next_u64() % 1_000_000);
        let entry = VerificationCode {
            session_info: session_info.clone(),
            phone_number: phone.to_owned(),
            code,
            purpose,
            created_at: now,
        };
        self.verification_codes.insert(session_info, entry.clone());
        Ok(entry)
    }

    /// Outstanding phone verification codes, oldest first.
    #[must_use]
    pub fn verification_codes(&self) -> Vec<&VerificationCode> {
        let mut codes: Vec<&VerificationCode> = self.verification_codes.values().collect();
        codes.sort_by_key(|c| c.created_at);
        codes
    }

    /// Checks and consumes a phone verification code.
    pub fn verify_phone_code(
        &mut self,
        session_info: &str,
        code: &str,
    ) -> Result<VerificationCode, AuthError> {
        let entry = self
            .verification_codes
            .get(session_info)
            .ok_or(AuthError::InvalidSessionInfo)?;
        if entry.code != code {
            return Err(AuthError::InvalidVerificationCode);
        }
        self.verification_codes
            .remove(session_info)
            .ok_or(AuthError::InvalidSessionInfo)
    }

    /// Signs in with a verified phone number: the user owning it, or a new phone user.
    /// Returns the user and whether it was created.
    pub fn sign_in_with_phone(
        &mut self,
        phone: &str,
        now: LogicalInstant,
    ) -> Result<(LocalId, bool), AuthError> {
        if let Some(u) = self.user_by_phone(phone) {
            if u.disabled {
                return Err(AuthError::UserDisabled);
            }
            let uid = u.local_id.clone();
            self.record_sign_in(&uid, now);
            return Ok((uid, false));
        }
        let uid = self.create_user(
            NewUser {
                email: None,
                email_verified: false,
                provider: Provider::Phone,
            },
            now,
        )?;
        self.set_phone_number(&uid, Some(phone))?;
        self.record_sign_in(&uid, now);
        Ok((uid, true))
    }

    /// Signs in with a verified email link: the user owning the email (now verified), or
    /// a new passwordless user.
    pub fn sign_in_with_email_link(
        &mut self,
        email: &str,
        now: LogicalInstant,
    ) -> Result<(LocalId, bool), AuthError> {
        if let Some(u) = self.user_by_email(email) {
            if u.disabled {
                return Err(AuthError::UserDisabled);
            }
            let uid = u.local_id.clone();
            if let Some(u) = self.users.get_mut(&uid) {
                u.email_verified = true;
            }
            self.record_sign_in(&uid, now);
            return Ok((uid, false));
        }
        let uid = self.create_user(
            NewUser {
                email: Some(email.to_owned()),
                email_verified: true,
                provider: Provider::EmailLink,
            },
            now,
        )?;
        self.record_sign_in(&uid, now);
        Ok((uid, true))
    }

    /// User owning a federated identity.
    #[must_use]
    pub fn user_by_federated(&self, provider_id: &str, raw_id: &str) -> Option<&UserRecord> {
        self.users.values().find(|u| {
            u.federated
                .iter()
                .any(|f| f.provider_id == provider_id && f.raw_id == raw_id)
        })
    }

    /// Links a federated identity to `uid` (replacing the user's identity at that provider).
    pub fn link_federated(
        &mut self,
        uid: &LocalId,
        identity: FederatedIdentity,
    ) -> Result<(), AuthError> {
        if self
            .user_by_federated(&identity.provider_id, &identity.raw_id)
            .is_some_and(|u| u.local_id != *uid)
        {
            return Err(AuthError::FederatedUserIdAlreadyLinked);
        }
        let user = self.users.get_mut(uid).ok_or(AuthError::UserNotFound)?;
        user.federated
            .retain(|f| f.provider_id != identity.provider_id);
        user.federated.push(identity);
        Ok(())
    }

    /// Unlinks the identity at `provider_id`; `true` when one was linked.
    pub fn unlink_federated(
        &mut self,
        uid: &LocalId,
        provider_id: &str,
    ) -> Result<bool, AuthError> {
        let user = self.users.get_mut(uid).ok_or(AuthError::UserNotFound)?;
        let before = user.federated.len();
        user.federated.retain(|f| f.provider_id != provider_id);
        Ok(user.federated.len() != before)
    }

    /// Signs in with a federated identity: the user it is linked to, else the user owning
    /// the identity's email (the identity is linked to it, as the Emulator does for a
    /// verified provider email), else a new user. Returns the user and whether it was
    /// created.
    pub fn sign_in_with_idp(
        &mut self,
        identity: FederatedIdentity,
        now: LogicalInstant,
    ) -> Result<(LocalId, bool), AuthError> {
        let existing = self
            .user_by_federated(&identity.provider_id, &identity.raw_id)
            .or_else(|| {
                identity
                    .email
                    .as_deref()
                    .and_then(|e| self.user_by_email(e))
            })
            .map(|u| (u.local_id.clone(), u.disabled));
        if let Some((uid, disabled)) = existing {
            if disabled {
                return Err(AuthError::UserDisabled);
            }
            self.link_federated(&uid, identity)?;
            self.record_sign_in(&uid, now);
            return Ok((uid, false));
        }
        let uid = self.create_user(
            NewUser {
                email: identity.email.clone(),
                email_verified: identity.email.is_some(),
                provider: Provider::Federated(identity.provider_id.clone()),
            },
            now,
        )?;
        if let Some(u) = self.users.get_mut(&uid) {
            u.display_name.clone_from(&identity.display_name);
            u.photo_url.clone_from(&identity.photo_url);
        }
        self.link_federated(&uid, identity)?;
        self.record_sign_in(&uid, now);
        Ok((uid, true))
    }

    /// Enrolls a phone second factor (the number was verified by the caller).
    pub fn enroll_phone_factor(
        &mut self,
        uid: &LocalId,
        phone: &str,
        display_name: Option<String>,
        now: LogicalInstant,
    ) -> Result<EnrolledFactor, MfaError> {
        AuthStore::validate_phone_number(phone).map_err(|_| MfaError::InvalidCode)?;
        let enrollment_id = self.next_id("mfa-");
        let user = self.users.get_mut(uid).ok_or(MfaError::UserNotFound)?;
        if user.disabled {
            return Err(MfaError::UserDisabled);
        }
        if user.mfa.factor_count() >= MAX_FACTORS_PER_USER {
            return Err(MfaError::TooManyFactors);
        }
        user.mfa.phone_factors_mut().push(PhoneFactor {
            mfa_enrollment_id: enrollment_id.clone(),
            display_name: display_name.clone(),
            phone_number: phone.to_owned(),
            enrolled_at: now,
        });
        Ok(EnrolledFactor {
            mfa_enrollment_id: enrollment_id,
            display_name,
            enrolled_at: now,
        })
    }

    /// Replaces the phone factors (Admin `mfa.enrollments`).
    pub fn set_phone_factors(
        &mut self,
        uid: &LocalId,
        factors: Vec<(String, Option<String>)>,
        now: LogicalInstant,
    ) -> Result<(), MfaError> {
        if let Some(user) = self.users.get_mut(uid) {
            user.mfa.phone_factors_mut().clear();
        }
        for (phone, display_name) in factors {
            self.enroll_phone_factor(uid, &phone, display_name, now)?;
        }
        Ok(())
    }

    /// Removes one factor of any kind; `true` when it existed.
    pub fn unenroll_factor(
        &mut self,
        uid: &LocalId,
        enrollment_id: &str,
    ) -> Result<bool, MfaError> {
        let user = self.users.get_mut(uid).ok_or(MfaError::UserNotFound)?;
        let before = user.mfa.factor_count();
        user.mfa
            .totp_factors_mut()
            .retain(|f| f.mfa_enrollment_id != enrollment_id);
        user.mfa
            .phone_factors_mut()
            .retain(|f| f.mfa_enrollment_id != enrollment_id);
        Ok(user.mfa.factor_count() != before)
    }

    /// Completes the second-factor step with a verified phone code for `enrollment_id`.
    pub fn finalize_phone_mfa_sign_in(
        &mut self,
        uid: &LocalId,
        pending: &PendingSignInId,
        enrollment_id: &str,
        now: LogicalInstant,
    ) -> Result<SecondFactorAssertion, MfaError> {
        let user = self.users.get_mut(uid).ok_or(MfaError::UserNotFound)?;
        if user.mfa.pending_sign_ins_mut().remove(&pending.0).is_none() {
            return Err(MfaError::PendingSignInUnknown);
        }
        if !user
            .mfa
            .phone_factors()
            .iter()
            .any(|f| f.mfa_enrollment_id == enrollment_id)
        {
            return Err(MfaError::NoEnrolledFactor);
        }
        user.last_sign_in_at = Some(now);
        Ok(SecondFactorAssertion {
            sign_in_second_factor: "phone".to_owned(),
            second_factor_identifier: enrollment_id.to_owned(),
            verified_at: now,
        })
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
        self.refresh_tokens.retain(|_, s| s.uid != *uid);
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

    /// Whether `uid` has a password credential (`createAuthUri` sign-in methods).
    #[must_use]
    pub fn has_password(&self, uid: &LocalId) -> bool {
        self.users.get(uid).is_some_and(|u| u.password.is_some())
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

    /// Issues a refresh token for `uid` (plain session: the user's own provider and claims).
    pub fn issue_refresh_token(
        &mut self,
        uid: &LocalId,
        now: LogicalInstant,
    ) -> Result<String, AuthError> {
        self.issue_refresh_session(uid, now, None, CustomClaims::default(), None)
    }

    /// Issues a refresh token that remembers how the session was obtained: the sign-in
    /// provider, custom-token claims and the second factor, so refreshed ID tokens carry the
    /// same `firebase` block and claims as the first one.
    pub fn issue_refresh_session(
        &mut self,
        uid: &LocalId,
        now: LogicalInstant,
        provider: Option<Provider>,
        claims: CustomClaims,
        second_factor: Option<SecondFactorAssertion>,
    ) -> Result<String, AuthError> {
        if !self.users.contains_key(uid) {
            return Err(AuthError::UserNotFound);
        }
        let token = self.next_id("rt-");
        self.refresh_tokens.insert(
            token.clone(),
            RefreshSession {
                uid: uid.clone(),
                issued_at: now,
                provider,
                claims,
                second_factor,
            },
        );
        Ok(token)
    }

    /// The session behind a refresh token (validated like [`Self::redeem_refresh_token`]).
    pub fn refresh_session(&self, token: &str) -> Result<&RefreshSession, AuthError> {
        self.redeem_refresh_token(token)?;
        self.refresh_tokens
            .get(token)
            .ok_or(AuthError::InvalidRefreshToken)
    }

    /// ID token claims for a refreshed session.
    pub fn id_token_claims_for_session(
        &self,
        session: &RefreshSession,
        now: LogicalInstant,
    ) -> Result<IdTokenClaims, AuthError> {
        let mut claims = self.id_token_claims(&session.uid, session.second_factor.as_ref(), now)?;
        if let Some(p) = &session.provider {
            p.id().clone_into(&mut claims.firebase.sign_in_provider);
        }
        for (k, v) in session.claims.entries() {
            claims
                .custom
                .insert(k, v.clone())
                .map_err(|_| AuthError::InvalidRefreshToken)?;
        }
        Ok(claims)
    }

    /// Redeems a refresh token: unknown tokens, tokens issued before a revocation, and disabled
    /// users are rejected.
    pub fn redeem_refresh_token(&self, token: &str) -> Result<LocalId, AuthError> {
        let session = self
            .refresh_tokens
            .get(token)
            .ok_or(AuthError::InvalidRefreshToken)?;
        let user = self
            .users
            .get(&session.uid)
            .ok_or(AuthError::InvalidRefreshToken)?;
        if user.disabled {
            return Err(AuthError::UserDisabled);
        }
        if session.issued_at < user.tokens_valid_after {
            return Err(AuthError::InvalidRefreshToken);
        }
        Ok(session.uid.clone())
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
        if user.mfa.is_empty() {
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
        let mut identities: BTreeMap<String, Vec<String>> = BTreeMap::new();
        if let Some(email) = &user.email {
            identities.insert("email".to_owned(), vec![email.clone()]);
        }
        if let Some(phone) = &user.phone_number {
            identities.insert("phone".to_owned(), vec![phone.clone()]);
        }
        for f in &user.federated {
            identities
                .entry(f.provider_id.clone())
                .or_default()
                .push(f.raw_id.clone());
        }
        // INV-AUTH-002: a second factor claim only ever comes from an enrolled factor.
        let second = second_factor.filter(|a| user.mfa.has_factor(&a.second_factor_identifier));
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
            phone_number: user.phone_number.clone(),
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
