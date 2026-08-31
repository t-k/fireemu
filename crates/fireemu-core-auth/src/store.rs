//! In-memory user store with TOTP enrollment / sign-in and ID token claim construction.

use core::fmt;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use fireemu_core_limits::catalogs::FIREBASE_AUTH_2026_08_30;
use fireemu_core_limits::evaluate::{
    evaluate, LimitDisposition, LimitViolation, DEFAULT_THRESHOLDS,
};
use fireemu_core_limits::plan::FirestorePlanProfile;
use fireemu_core_types::determinism::{DeterministicRng, SplitMix64};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

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

/// The outcome of a federated identity-provider sign-in.
///
/// The official emulator either signs the user in (linking the identity to an existing
/// account or creating one) or, when an unverified assertion names an email an existing
/// account already owns, asks the client to confirm before linking (`needConfirmation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdpSignIn {
    /// Signed in: the user, whether it was created, and whether an account already linked
    /// this provider under a different raw id (`emailRecycled`).
    SignedIn {
        /// The signed-in user.
        uid: LocalId,
        /// Whether the account was created by this sign-in.
        is_new: bool,
        /// Whether the account already linked this provider under a different raw id.
        email_recycled: bool,
    },
    /// The assertion's email is owned by an existing account and the assertion did not vouch
    /// for the email: the client must confirm before the identity is linked. No state changes.
    NeedConfirmation {
        /// The account owning the email.
        uid: LocalId,
        /// The federated providers already linked to that account (`verifiedProvider`).
        verified_providers: Vec<String>,
    },
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
    /// Creation order within the store (listings sort by it after `created_at`, so a
    /// pinned clock still lists codes oldest first).
    pub sequence: u64,
}

/// A user lifecycle event (Auth triggers).
#[derive(Debug, Clone, PartialEq)]
pub struct UserEvent {
    /// Created or deleted.
    pub kind: UserEventKind,
    /// The user as created / as it was before deletion.
    pub user: UserRecord,
}

/// User lifecycle event kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserEventKind {
    /// Created.
    Created,
    /// Deleted.
    Deleted,
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
    /// Creation order within the store (see [`OobCode::sequence`]).
    pub sequence: u64,
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
///
/// A credential also remembers the emulator salt and plaintext it was imported from, when
/// it was imported from one. The Local Emulator Suite stores passwords in the clear
/// (`passwordHash: "fakeHash:salt=<salt>:password=<plaintext>"`), so an export directory
/// already holds them; keeping them lets fireemu write an export the official suite can sign
/// in against, rather than one that silently drops every password. A credential created
/// through fireemu's own API has no such form and is never given one -- exporting it writes
/// no `passwordHash` at all instead of inventing a reversible one.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordDigest {
    salt: [u8; 16],
    digest: [u8; 20],
    /// The emulator salt and plaintext this credential was imported with.
    emulator: Option<(String, String)>,
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
            emulator: None,
        }
    }

    fn verify(&self, password: &str) -> bool {
        let candidate = Self::new(self.salt, password).digest;
        candidate
            .iter()
            .zip(self.digest.iter())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
    }

    /// The emulator salt and plaintext an export has to write back, when the credential
    /// came from one.
    #[must_use]
    pub fn emulator_form(&self) -> Option<(&str, &str)> {
        self.emulator
            .as_ref()
            .map(|(salt, password)| (salt.as_str(), password.as_str()))
    }
}

/// The project-level Auth configuration `auth_export/config.json` carries.
///
/// fireemu records it so that an import followed by an export does not lose it. Both switches
/// also affect the matching and error behavior of the emulated Identity Toolkit surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProjectAuthConfig {
    /// `signIn.allowDuplicateEmails`.
    pub allow_duplicate_emails: bool,
    /// `emailPrivacyConfig.enableImprovedEmailPrivacy`.
    pub enable_improved_email_privacy: bool,
}

/// Why an account an import artifact recorded was refused.
#[derive(Debug, Clone, PartialEq)]
pub enum ImportUserError {
    /// The account itself is not acceptable.
    Account(AuthError),
    /// One of its second factors is not acceptable.
    SecondFactor(crate::mfa::ImportedFactorError),
}

impl fmt::Display for ImportUserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Account(e) => write!(f, "{e}"),
            Self::SecondFactor(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ImportUserError {}

/// A user an import artifact recorded, with the identity and times it has to keep.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportedUser {
    /// The account identifier, exactly as recorded.
    pub local_id: String,
    /// Email address.
    pub email: Option<String>,
    /// Whether the email address is verified.
    pub email_verified: bool,
    /// Display name.
    pub display_name: Option<String>,
    /// Photo URL.
    pub photo_url: Option<String>,
    /// Phone number.
    pub phone_number: Option<String>,
    /// Whether the account is disabled.
    pub disabled: bool,
    /// The sign-in provider the account is attributed to.
    pub provider: Provider,
    /// Custom claims.
    pub custom_claims: CustomClaims,
    /// When the account was created.
    pub created_at: LogicalInstant,
    /// When the account last signed in.
    pub last_sign_in_at: Option<LogicalInstant>,
    /// Tokens minted before this instant are refused.
    pub tokens_valid_after: LogicalInstant,
    /// Linked federated identities.
    pub federated: Vec<FederatedIdentity>,
    /// The emulator salt and plaintext password, when the account has a password
    /// credential.
    pub password: Option<(String, String)>,
    /// Enrolled TOTP second factors.
    pub totp_factors: Vec<crate::mfa::TotpFactor>,
    /// Enrolled phone second factors.
    pub phone_factors: Vec<crate::mfa::PhoneFactor>,
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
    /// Unknown email or wrong password, undistinguished (the improved email privacy mode).
    InvalidCredentials,
    /// Wrong password, or no password credential, for a known email (the default mode of
    /// the official emulator, which distinguishes it from an unknown email).
    InvalidPassword,
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
    /// The project already holds [`MAX_OUTSTANDING_CODES`] outstanding codes of the kind
    /// requested; nothing was created.
    TooManyOutstandingCodes,
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
            Self::InvalidPassword => f.write_str("invalid password"),
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
            Self::TooManyOutstandingCodes => f.write_str("too many outstanding codes"),
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
#[derive(Debug, Clone)]
pub struct AuthStore {
    project_id: String,
    tenant_id: Option<String>,
    rng: SplitMix64,
    policy: TotpPolicy,
    /// User records, each behind an `Arc` so an unchanged user is shared by reference between
    /// the live store and every snapshot and only copied on mutation (`SNAP-MEM-03`, the Auth
    /// analogue of the Storage `Arc<Vec<u8>>` blobs). Every mutation site clones exactly the
    /// one user it touches through [`Arc::make_mut`].
    users: BTreeMap<LocalId, Arc<UserRecord>>,
    /// The account currently selected by an email-only lookup. Duplicate-email mode still
    /// has one active lookup target, matching the official emulator's `email -> localId`
    /// index: the most recently created or updated account wins.
    local_id_for_email: BTreeMap<String, LocalId>,
    counter: u64,
    refresh_tokens: BTreeMap<String, RefreshSession>,
    next_id_override: Option<String>,
    next_sequence: u64,
    signer: Option<Arc<dyn crate::jwt::IdTokenSigner>>,
    oob_codes: BTreeMap<String, OobCode>,
    verification_codes: BTreeMap<String, VerificationCode>,
    /// Which user owns each outstanding pending sign-in (`mfaPendingCredential`), so a
    /// credential is resolved directly rather than by scanning every user
    /// (`AUTH-TRANSIENT-04`). Kept in step with the users' own pending maps.
    pending_sign_in_owners: BTreeMap<String, LocalId>,
    created_users: Vec<LocalId>,
    deleted_users: Vec<UserRecord>,
    /// The project-level Auth configuration an import carried, kept so an export can write
    /// it back.
    config: ProjectAuthConfig,
}

/// Email action codes expire after an hour of virtual time.
pub const OOB_CODE_TTL_SECONDS: i64 = 3_600;
/// Phone verification codes expire after ten minutes of virtual time.
pub const SMS_CODE_TTL_SECONDS: i64 = 600;
/// A pending second-factor sign-in (`mfaPendingCredential`) expires after an hour of virtual
/// time. The official emulator's credential is stateless and never expires; this is a local
/// lifecycle policy, not a claimed production value.
pub const PENDING_SIGN_IN_TTL_SECONDS: i64 = 3_600;
/// Outstanding email action codes, and separately outstanding phone verification codes, one
/// project may hold. A flow that keeps requesting codes without consuming them is refused at
/// this budget, and the refused request creates nothing (`AUTH-TRANSIENT-03`).
pub const MAX_OUTSTANDING_CODES: usize = 1_000;

/// A cheap, saturating estimate of the heap bytes one user record holds: the fixed record
/// plus the lengths of its owned strings, claims, second factors and federated identities.
/// It only has to be monotonic and un-overflowable -- it gates a byte budget, it is not a
/// wire size.
fn user_record_bytes(user: &UserRecord) -> u64 {
    let mut total = core::mem::size_of::<UserRecord>() as u64;
    let text = |s: &Option<String>| s.as_ref().map_or(0, |t| t.len() as u64);
    total = total.saturating_add(user.local_id.as_str().len() as u64);
    total = total.saturating_add(text(&user.email));
    total = total.saturating_add(text(&user.display_name));
    total = total.saturating_add(text(&user.photo_url));
    total = total.saturating_add(text(&user.phone_number));
    total = total.saturating_add(user.custom_claims.canonical_json().len() as u64);
    for f in &user.federated {
        total = total.saturating_add(f.provider_id.len() as u64);
        total = total.saturating_add(f.raw_id.len() as u64);
        total = total.saturating_add(text(&f.email));
        total = total.saturating_add(text(&f.display_name));
        total = total.saturating_add(text(&f.photo_url));
    }
    // Second factors: enrollment ids, display names, phone numbers and any secret bytes.
    for f in user.mfa.totp_factors() {
        total = total.saturating_add(f.mfa_enrollment_id.len() as u64);
        total = total.saturating_add(text(&f.display_name));
        total = total.saturating_add(f.secret.expose_for_enrollment().len() as u64);
    }
    for f in user.mfa.phone_factors() {
        total = total.saturating_add(f.mfa_enrollment_id.len() as u64);
        total = total.saturating_add(text(&f.display_name));
        total = total.saturating_add(f.phone_number.len() as u64);
    }
    total
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

    /// The installed signer as a shared handle (to install it on another project's store).
    #[must_use]
    pub fn signer_arc(&self) -> Option<Arc<dyn crate::jwt::IdTokenSigner>> {
        self.signer.clone()
    }

    /// Creates a store for `project_id`.
    #[must_use]
    pub fn new(project_id: &str, rng: SplitMix64, policy: TotpPolicy) -> Self {
        Self {
            project_id: project_id.to_owned(),
            tenant_id: None,
            rng,
            policy,
            users: BTreeMap::new(),
            local_id_for_email: BTreeMap::new(),
            counter: 0,
            refresh_tokens: BTreeMap::new(),
            next_id_override: None,
            next_sequence: 0,
            signer: None,
            oob_codes: BTreeMap::new(),
            verification_codes: BTreeMap::new(),
            pending_sign_in_owners: BTreeMap::new(),
            created_users: Vec::new(),
            deleted_users: Vec::new(),
            config: ProjectAuthConfig::default(),
        }
    }

    /// Creates an isolated Identity Platform tenant store under `project_id`.
    #[must_use]
    pub fn new_tenant(
        project_id: &str,
        tenant_id: &str,
        rng: SplitMix64,
        policy: TotpPolicy,
    ) -> Self {
        let mut store = Self::new(project_id, rng, policy);
        store.tenant_id = Some(tenant_id.to_owned());
        store
    }

    /// Identity Platform tenant ID, absent for the parent project namespace.
    #[must_use]
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    /// User lifecycle events recorded since the last call (Auth triggers). A created user
    /// is reported as it is now (password, phone, profile and factors applied after the
    /// insert included); a user created and deleted in between (a rolled-back multi-step
    /// create) produces no event.
    pub fn take_user_events(&mut self) -> Vec<UserEvent> {
        let created = std::mem::take(&mut self.created_users);
        let deleted = std::mem::take(&mut self.deleted_users);
        let mut events = Vec::new();
        for uid in &created {
            if let Some(user) = self.users.get(uid) {
                events.push(UserEvent {
                    kind: UserEventKind::Created,
                    user: UserRecord::clone(user),
                });
            }
        }
        for user in deleted {
            if !created.contains(&user.local_id) {
                events.push(UserEvent {
                    kind: UserEventKind::Deleted,
                    user,
                });
            }
        }
        events
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
            .map(|(_, u)| u.as_ref())
    }

    fn next_id(&mut self, prefix: &str) -> String {
        self.counter += 1;
        format!(
            "{prefix}{:016x}{:04}",
            self.rng.next_u64(),
            self.counter % 10_000
        )
    }

    /// A generated identifier of the official shape: 28 characters of `[A-Za-z0-9]`, what
    /// the official emulator and production assign to accounts and MFA enrollments (the
    /// client SDKs surface its length).
    fn random_id28(&mut self) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut id = String::with_capacity(28);
        while id.len() < 28 {
            let mut word = self.rng.next_u64();
            // Ten characters per 64-bit word: 62^10 < 2^60, so each draw is a fair index.
            for _ in 0..10 {
                if id.len() == 28 {
                    break;
                }
                let index = usize::try_from(word % 62).unwrap_or(0);
                id.push(char::from(ALPHABET[index]));
                word /= 62;
            }
        }
        id
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

    /// Deletes a user and its refresh tokens, pending sign-ins and phone codes.
    pub fn delete_user_by_id(&mut self, uid: &str) -> Result<(), AuthError> {
        let key = LocalId(uid.to_owned());
        let user = self.users.remove(&key).ok_or(AuthError::UserNotFound)?;
        if let Some(email) = &user.email {
            self.local_id_for_email.remove(email);
        }
        self.refresh_tokens.retain(|_, s| s.uid != key);
        self.pending_sign_in_owners.retain(|_, owner| *owner != key);
        self.verification_codes.retain(|_, c| match &c.purpose {
            VerificationPurpose::SignIn => true,
            VerificationPurpose::Enrollment { uid }
            | VerificationPurpose::MfaSignIn { uid, .. } => *uid != key,
        });
        self.deleted_users.push(Arc::unwrap_or_clone(user));
        Ok(())
    }

    /// Removes every user, credential and token (session reset). The project ID and the
    /// deterministic generator are kept so IDs stay reproducible per session.
    pub fn clear(&mut self) {
        self.users.clear();
        self.local_id_for_email.clear();
        self.refresh_tokens.clear();
        self.oob_codes.clear();
        self.verification_codes.clear();
        self.pending_sign_in_owners.clear();
    }

    /// Drops every transient credential past its lifetime: email action codes
    /// ([`OOB_CODE_TTL_SECONDS`]), phone verification codes ([`SMS_CODE_TTL_SECONDS`]), TOTP
    /// enrollment sessions (the policy's session lifetime) and pending second-factor sign-ins
    /// ([`PENDING_SIGN_IN_TTL_SECONDS`]), each at the boundary its consumer already applied.
    /// Refresh tokens are not transient credentials and are never swept here.
    ///
    /// The adapter calls this before every request and the store calls it before every
    /// creation, so an expired entry is never observable as active and the retained state is
    /// bounded under abandoned flows (`AUTH-TRANSIENT-01`, `-02`). It depends on `now` and on
    /// the order of operations only.
    pub fn sweep_transient_credentials(&mut self, now: LogicalInstant) {
        self.oob_codes
            .retain(|_, c| !Self::expired(c.created_at, OOB_CODE_TTL_SECONDS, now));
        self.verification_codes
            .retain(|_, c| !Self::expired(c.created_at, SMS_CODE_TTL_SECONDS, now));
        let sign_in_ttl = LogicalDuration::from_seconds(PENDING_SIGN_IN_TTL_SECONDS);
        let enrollment_grace = self.policy.enrollment_session_ttl;
        for user in self.users.values_mut() {
            // A user with nothing pending has nothing to sweep; leave its `Arc` shared with
            // any snapshot rather than cloning it for a no-op (`SNAP-MEM-03`).
            if user.mfa.pending_count() == 0 {
                continue;
            }
            for dropped in Arc::make_mut(user)
                .mfa
                .sweep(now, sign_in_ttl, enrollment_grace)
            {
                self.pending_sign_in_owners.remove(&dropped);
            }
        }
        // A phone code for a pending sign-in that no longer exists can never be finalized.
        let owners = &self.pending_sign_in_owners;
        self.verification_codes.retain(|_, c| match &c.purpose {
            VerificationPurpose::MfaSignIn { pending, .. } => owners.contains_key(&pending.0),
            VerificationPurpose::SignIn | VerificationPurpose::Enrollment { .. } => true,
        });
    }

    /// Outstanding pending second-factor sign-ins across every user (bounded state).
    #[must_use]
    pub fn pending_sign_in_count(&self) -> usize {
        self.pending_sign_in_owners.len()
    }

    /// Records a successful sign-in (Admin `lastLoginAt`).
    pub fn record_sign_in(&mut self, uid: &LocalId, now: LogicalInstant) {
        if let Some(u) = self.users.get_mut(uid).map(Arc::make_mut) {
            u.last_sign_in_at = Some(now);
        }
    }

    /// The project-level Auth configuration an export carries.
    #[must_use]
    pub const fn config(&self) -> ProjectAuthConfig {
        self.config
    }

    /// Records the project-level Auth configuration an import carried.
    pub fn set_config(&mut self, config: ProjectAuthConfig) {
        self.config = config;
    }

    /// The password credential of a user, when it has one. An export reads it to write the
    /// emulator's `passwordHash` and `salt` back out.
    #[must_use]
    pub fn password_digest(&self, uid: &LocalId) -> Option<&PasswordDigest> {
        self.users.get(uid).and_then(|u| u.password.as_ref())
    }

    /// Installs a user from an import artifact, exactly as it was recorded.
    ///
    /// This is not [`Self::create_user`]: an import restores accounts that already existed,
    /// so the local id, the creation time, the last sign-in, the token revocation instant,
    /// the custom claims, the linked providers and the enrolled second factors all come from
    /// the artifact rather than being generated. No user event is recorded, because no
    /// account was created while the suite was running -- an Auth trigger firing for every
    /// account of an import would be an invented event.
    ///
    /// The listing order stays the artifact's: users keep the sequence they are imported in,
    /// and `next_sequence` moves past them so a later sign-up sorts after the import.
    pub fn import_user(&mut self, user: ImportedUser) -> Result<LocalId, ImportUserError> {
        if user.local_id.is_empty()
            || user.local_id.chars().count() > 128
            || user.local_id.chars().any(char::is_control)
        {
            return Err(ImportUserError::Account(AuthError::InvalidLocalId));
        }
        let local_id = LocalId(user.local_id);
        if self.users.contains_key(&local_id) {
            return Err(ImportUserError::Account(AuthError::LocalIdExists));
        }
        if let Some(phone) = &user.phone_number {
            Self::validate_phone_number(phone).map_err(ImportUserError::Account)?;
        }
        // The same checks a sign-up gets: a well-formed email without control characters,
        // unique unless the project allows duplicates, and bounded custom claims.
        if let Some(email) = &user.email {
            if !email.contains('@') || email.chars().any(char::is_control) {
                return Err(ImportUserError::Account(AuthError::InvalidEmail));
            }
            if !self.config.allow_duplicate_emails
                && self
                    .users
                    .values()
                    .any(|u| u.email.as_deref() == Some(email))
            {
                return Err(ImportUserError::Account(AuthError::EmailExists));
            }
        }
        for text in [&user.display_name, &user.photo_url] {
            if text
                .as_deref()
                .is_some_and(|t| t.chars().any(char::is_control))
            {
                return Err(ImportUserError::Account(AuthError::InvalidLocalId));
            }
        }
        user.custom_claims
            .check_size()
            .map_err(|e| ImportUserError::Account(AuthError::LimitExceeded(e)))?;
        let password = match user.password {
            Some((salt, plaintext)) => {
                Self::validate_password(&plaintext).map_err(ImportUserError::Account)?;
                // The digest is fireemu's own; the emulator form is kept beside it so an
                // export can write back exactly what it read.
                let mut bytes = [0u8; 16];
                for (slot, byte) in bytes.iter_mut().zip(salt.bytes()) {
                    *slot = byte;
                }
                let mut digest = PasswordDigest::new(bytes, &plaintext);
                digest.emulator = Some((salt, plaintext));
                Some(digest)
            }
            None => None,
        };
        // Sequences start at one, exactly as `create_user` assigns them: the listing cursor
        // is "everything after this sequence", so a zero would make the first account
        // unlistable.
        self.next_sequence += 1;
        let sequence = self.next_sequence;
        let mut mfa = MfaState::default();
        mfa.import_factors(user.totp_factors, user.phone_factors)
            .map_err(ImportUserError::SecondFactor)?;
        let email = user.email.clone();
        self.users.insert(
            local_id.clone(),
            Arc::new(UserRecord {
                local_id: local_id.clone(),
                email: user.email,
                email_verified: user.email_verified,
                display_name: user.display_name,
                photo_url: user.photo_url,
                phone_number: user.phone_number,
                sequence,
                disabled: user.disabled,
                provider: user.provider,
                custom_claims: user.custom_claims,
                mfa,
                created_at: user.created_at,
                last_sign_in_at: user.last_sign_in_at,
                tokens_valid_after: user.tokens_valid_after,
                federated: user.federated,
                password,
            }),
        );
        if let Some(email) = email {
            self.local_id_for_email.insert(email, local_id.clone());
        }
        Ok(local_id)
    }

    /// Users in creation order (stable `listUsers` paging).
    #[must_use]
    pub fn users_by_creation(&self) -> Vec<&UserRecord> {
        let mut users: Vec<&UserRecord> = self.users.values().map(Arc::as_ref).collect();
        users.sort_by_key(|u| u.sequence);
        users
    }

    /// User by phone number.
    #[must_use]
    pub fn user_by_phone(&self, phone: &str) -> Option<&UserRecord> {
        self.users
            .values()
            .find(|u| u.phone_number.as_deref() == Some(phone))
            .map(Arc::as_ref)
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
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
        if let Some(old) = user.email.replace(email.to_owned()) {
            self.local_id_for_email.remove(&old);
        }
        self.local_id_for_email
            .insert(email.to_owned(), uid.clone());
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
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
        user.phone_number = phone.map(str::to_owned);
        Ok(())
    }

    /// All user IDs in canonical order.
    #[must_use]
    pub fn all_user_ids(&self) -> Vec<LocalId> {
        self.users.keys().cloned().collect()
    }

    /// A cheap estimate of the heap bytes the user records hold (`SNAP-MEM-01`), each user
    /// counted once. Saturating throughout, so no store -- however large or adversarial -- can
    /// overflow the estimate into a small number and slip past a byte budget.
    #[must_use]
    pub fn retained_user_bytes(&self) -> u64 {
        self.users
            .values()
            .map(|u| user_record_bytes(u))
            .fold(0u64, u64::saturating_add)
    }

    /// A cheap estimate of the heap bytes the transient maps a snapshot still copies in full
    /// hold: refresh sessions, email action codes and phone verification codes. Bounded by
    /// [`MAX_OUTSTANDING_CODES`] and the number of live sessions; saturating.
    #[must_use]
    pub fn transient_bytes(&self) -> u64 {
        let refresh = (self.refresh_tokens.len() as u64).saturating_mul(96);
        let oob = (self.oob_codes.len() as u64).saturating_mul(96);
        let verification = (self.verification_codes.len() as u64).saturating_mul(96);
        refresh
            .saturating_add(oob)
            .saturating_add(verification)
            .saturating_add((self.pending_sign_in_owners.len() as u64).saturating_mul(64))
    }

    /// Bytes of user records this store shares with `other` by allocation: users whose record
    /// is the same `Arc` on both sides (`SNAP-MEM-03`). Used to see that a capture copied
    /// nothing for the users it did not touch.
    #[must_use]
    pub fn users_shared_with(&self, other: &Self) -> u64 {
        self.users
            .iter()
            .filter_map(|(id, rec)| {
                other
                    .users
                    .get(id)
                    .filter(|theirs| Arc::ptr_eq(rec, theirs))
                    .map(|_| user_record_bytes(rec))
            })
            .fold(0u64, u64::saturating_add)
    }

    /// Creates a user.
    pub fn create_user(&mut self, new: NewUser, now: LogicalInstant) -> Result<LocalId, AuthError> {
        self.create_user_with_email_policy(new, now, true)
    }

    /// Creates the provider-scoped account used by `IdP` sign-in when email uniqueness is off.
    fn create_idp_user(&mut self, new: NewUser, now: LogicalInstant) -> Result<LocalId, AuthError> {
        self.create_user_with_email_policy(new, now, false)
    }

    fn create_user_with_email_policy(
        &mut self,
        new: NewUser,
        now: LogicalInstant,
        enforce_unique_email: bool,
    ) -> Result<LocalId, AuthError> {
        if let Some(email) = &new.email {
            if !email.contains('@') || email.chars().any(char::is_control) {
                return Err(AuthError::InvalidEmail);
            }
            if enforce_unique_email
                && self
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
                let candidate = LocalId(self.random_id28());
                if !self.users.contains_key(&candidate) {
                    break candidate;
                }
            },
        };
        let std::collections::btree_map::Entry::Vacant(slot) = self.users.entry(local_id.clone())
        else {
            return Err(AuthError::LocalIdExists);
        };
        let email = new.email.clone();
        slot.insert(Arc::new(UserRecord {
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
            tokens_valid_after: Self::whole_second(now),
            federated: Vec::new(),
            password: None,
        }));
        if let Some(email) = email {
            self.local_id_for_email.insert(email, local_id.clone());
        }
        self.created_users.push(local_id.clone());
        Ok(local_id)
    }

    // ---- email actions, phone sign-in, federated identities ----------------------------

    /// Creates an email action code. Expired codes are swept first; at
    /// [`MAX_OUTSTANDING_CODES`] outstanding codes the request is refused and creates nothing.
    pub fn create_oob_code(
        &mut self,
        request_type: OobRequestType,
        email: &str,
        uid: Option<LocalId>,
        new_email: Option<String>,
        now: LogicalInstant,
    ) -> Result<String, AuthError> {
        self.sweep_transient_credentials(now);
        if self.oob_codes.len() >= MAX_OUTSTANDING_CODES {
            return Err(AuthError::TooManyOutstandingCodes);
        }
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
                sequence: self.counter,
            },
        );
        Ok(code)
    }

    /// Outstanding email action codes, oldest first.
    #[must_use]
    pub fn oob_codes(&self) -> Vec<&OobCode> {
        let mut codes: Vec<&OobCode> = self.oob_codes.values().collect();
        codes.sort_by_key(|c| (c.created_at, c.sequence));
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
        now: LogicalInstant,
    ) -> Result<OobCode, AuthError> {
        let matches = self
            .oob_codes
            .get(code)
            .is_some_and(|c| expected.is_none_or(|e| c.request_type == e));
        if !matches {
            return Err(AuthError::InvalidOobCode);
        }
        if self
            .oob_codes
            .get(code)
            .is_some_and(|c| Self::expired(c.created_at, OOB_CODE_TTL_SECONDS, now))
        {
            self.oob_codes.remove(code);
            return Err(AuthError::InvalidOobCode);
        }
        self.oob_codes.remove(code).ok_or(AuthError::InvalidOobCode)
    }

    fn expired(created_at: LogicalInstant, ttl_seconds: i64, now: LogicalInstant) -> bool {
        now.as_nanos() - created_at.as_nanos() > i128::from(ttl_seconds) * 1_000_000_000
    }

    /// Creates a phone verification code for `phone` (a deterministic six-digit code).
    /// Expired codes are swept first; at [`MAX_OUTSTANDING_CODES`] outstanding codes the
    /// request is refused and creates nothing.
    pub fn send_verification_code(
        &mut self,
        phone: &str,
        purpose: VerificationPurpose,
        now: LogicalInstant,
    ) -> Result<VerificationCode, AuthError> {
        Self::validate_phone_number(phone)?;
        self.sweep_transient_credentials(now);
        if self.verification_codes.len() >= MAX_OUTSTANDING_CODES {
            return Err(AuthError::TooManyOutstandingCodes);
        }
        let session_info = self.next_id("sms-");
        let code = format!("{:06}", self.rng.next_u64() % 1_000_000);
        let entry = VerificationCode {
            session_info: session_info.clone(),
            phone_number: phone.to_owned(),
            code,
            purpose,
            created_at: now,
            sequence: self.counter,
        };
        self.verification_codes.insert(session_info, entry.clone());
        Ok(entry)
    }

    /// Outstanding phone verification codes, oldest first.
    #[must_use]
    pub fn verification_codes(&self) -> Vec<&VerificationCode> {
        let mut codes: Vec<&VerificationCode> = self.verification_codes.values().collect();
        codes.sort_by_key(|c| (c.created_at, c.sequence));
        codes
    }

    /// Checks and consumes a phone verification code.
    pub fn verify_phone_code(
        &mut self,
        session_info: &str,
        code: &str,
        now: LogicalInstant,
    ) -> Result<VerificationCode, AuthError> {
        let entry = self.check_phone_code(session_info, code, now)?;
        self.consume_phone_code(session_info);
        Ok(entry)
    }

    /// Checks a phone verification code without consuming it (callers validate the rest
    /// of the request first, so a rejected request does not burn the code).
    pub fn check_phone_code(
        &self,
        session_info: &str,
        code: &str,
        now: LogicalInstant,
    ) -> Result<VerificationCode, AuthError> {
        let entry = self
            .verification_codes
            .get(session_info)
            .ok_or(AuthError::InvalidSessionInfo)?;
        if Self::expired(entry.created_at, SMS_CODE_TTL_SECONDS, now) {
            return Err(AuthError::InvalidSessionInfo);
        }
        if entry.code != code {
            return Err(AuthError::InvalidVerificationCode);
        }
        Ok(entry.clone())
    }

    /// Consumes a phone verification session.
    pub fn consume_phone_code(&mut self, session_info: &str) {
        self.verification_codes.remove(session_info);
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
            if let Some(u) = self.users.get_mut(&uid).map(Arc::make_mut) {
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
        self.users
            .values()
            .find(|u| {
                u.federated
                    .iter()
                    .any(|f| f.provider_id == provider_id && f.raw_id == raw_id)
            })
            .map(Arc::as_ref)
    }

    /// Every identity linked at `provider_id`, in account-creation order: the accounts the identity-provider
    /// login widget offers for reuse (`listProviderInfosByProviderId`).
    #[must_use]
    pub fn provider_infos(&self, provider_id: &str) -> Vec<FederatedIdentity> {
        let mut users: Vec<&UserRecord> = self.users.values().map(Arc::as_ref).collect();
        users.sort_by_key(|u| u.sequence);
        users
            .into_iter()
            .filter_map(|u| {
                u.federated
                    .iter()
                    .find(|f| f.provider_id == provider_id)
                    .cloned()
            })
            .collect()
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
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
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
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
        let before = user.federated.len();
        user.federated.retain(|f| f.provider_id != provider_id);
        Ok(user.federated.len() != before)
    }

    /// Signs in with a federated identity, matching the official emulator's create-or-link
    /// semantics (`signInWithIdp` / `verifyAssertion`).
    ///
    /// The identity is matched first by its `(providerId, rawId)`. When no account links it and
    /// the project keeps one account per email (`allowDuplicateEmails` is false), the
    /// assertion's email is matched next:
    ///
    /// - if the provider vouches for the email (`emailVerified`), the identity is linked to the
    ///   owning account. When that account's own email was unverified, a verified identity-provider email
    ///   takes it over: its password, phone number and existing providers are cleared and its
    ///   tokens are invalidated (the account is recycled), exactly as the official emulator
    ///   does. `emailRecycled` reports that the account already linked this provider under a
    ///   different raw id.
    /// - if the provider does not vouch for the email, the account owning it must be confirmed
    ///   before linking: [`IdpSignIn::NeedConfirmation`] is returned and nothing changes.
    ///
    /// Otherwise a new account is created and the identity linked to it.
    pub fn sign_in_with_idp(
        &mut self,
        identity: FederatedIdentity,
        email_verified: bool,
        now: LogicalInstant,
    ) -> Result<IdpSignIn, AuthError> {
        // 1. An account already linking this exact provider identity signs straight in.
        if let Some(u) = self.user_by_federated(&identity.provider_id, &identity.raw_id) {
            let (uid, disabled) = (u.local_id.clone(), u.disabled);
            if disabled {
                return Err(AuthError::UserDisabled);
            }
            self.link_profile_from_identity(&uid, &identity);
            self.link_federated(&uid, identity)?;
            self.record_sign_in(&uid, now);
            return Ok(IdpSignIn::SignedIn {
                uid,
                is_new: false,
                email_recycled: false,
            });
        }
        // 2. Match the assertion's email, unless the project allows duplicate emails.
        if !self.config.allow_duplicate_emails {
            if let Some(email) = identity.email.clone() {
                if let Some(u) = self.user_by_email(&email) {
                    let uid = u.local_id.clone();
                    let disabled = u.disabled;
                    let owner_email_verified = u.email_verified;
                    let email_recycled = u.federated.iter().any(|f| {
                        f.provider_id == identity.provider_id && f.raw_id != identity.raw_id
                    });
                    if !email_verified {
                        // The assertion does not vouch for the email: confirm before linking.
                        let verified_providers =
                            u.federated.iter().map(|f| f.provider_id.clone()).collect();
                        return Ok(IdpSignIn::NeedConfirmation {
                            uid,
                            verified_providers,
                        });
                    }
                    if disabled {
                        return Err(AuthError::UserDisabled);
                    }
                    // A verified IdP email over an unverified-email account recycles it: the
                    // password, phone and any other providers are dropped and its tokens are
                    // invalidated so nothing minted under the old owner survives.
                    if !owner_email_verified {
                        if let Some(user) = self.users.get_mut(&uid).map(Arc::make_mut) {
                            user.password = None;
                            user.phone_number = None;
                            user.federated.clear();
                            user.tokens_valid_after = Self::whole_second(now);
                        }
                    }
                    self.set_email_verified_flag(&uid, true);
                    self.link_profile_from_identity(&uid, &identity);
                    self.link_federated(&uid, identity)?;
                    self.record_sign_in(&uid, now);
                    return Ok(IdpSignIn::SignedIn {
                        uid,
                        is_new: false,
                        email_recycled,
                    });
                }
            }
        }
        // 3. No match: a new account, linked to the identity.
        let new_user = NewUser {
            email: identity.email.clone(),
            email_verified: identity.email.is_some() && email_verified,
            provider: Provider::Federated(identity.provider_id.clone()),
        };
        let uid = if self.config.allow_duplicate_emails {
            self.create_idp_user(new_user, now)?
        } else {
            self.create_user(new_user, now)?
        };
        self.link_profile_from_identity(&uid, &identity);
        self.link_federated(&uid, identity)?;
        self.record_sign_in(&uid, now);
        Ok(IdpSignIn::SignedIn {
            uid,
            is_new: true,
            email_recycled: false,
        })
    }

    /// Refreshes the account's display name and photo from an assertion when the assertion
    /// carries them (the official emulator updates the profile on every federated sign-in).
    fn link_profile_from_identity(&mut self, uid: &LocalId, identity: &FederatedIdentity) {
        if let Some(u) = self.users.get_mut(uid).map(Arc::make_mut) {
            if identity.display_name.is_some() {
                u.display_name.clone_from(&identity.display_name);
            }
            if identity.photo_url.is_some() {
                u.photo_url.clone_from(&identity.photo_url);
            }
        }
    }

    /// Sets the account's email-verified flag.
    fn set_email_verified_flag(&mut self, uid: &LocalId, verified: bool) {
        if let Some(u) = self.users.get_mut(uid).map(Arc::make_mut) {
            u.email_verified = verified;
        }
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
        let enrollment_id = self.random_id28();
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(MfaError::UserNotFound)?;
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
        if let Some(user) = self.users.get_mut(uid).map(Arc::make_mut) {
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
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(MfaError::UserNotFound)?;
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
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(MfaError::UserNotFound)?;
        if user.mfa.pending_sign_ins_mut().remove(&pending.0).is_none() {
            return Err(MfaError::PendingSignInUnknown);
        }
        self.pending_sign_in_owners.remove(&pending.0);
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
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
        user.password = Some(PasswordDigest::new(salt, password));
        Ok(())
    }

    /// Removes the password credential (`deleteProvider: password`, `deleteAttribute:
    /// PASSWORD`); `true` when there was one.
    pub fn clear_password(&mut self, uid: &LocalId) -> Result<bool, AuthError> {
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
        Ok(user.password.take().is_some())
    }

    /// Removes the email address and its verified flag (`deleteAttribute: EMAIL`).
    pub fn clear_email(&mut self, uid: &LocalId) -> Result<(), AuthError> {
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
        if let Some(email) = user.email.take() {
            self.local_id_for_email.remove(&email);
        }
        user.email_verified = false;
        Ok(())
    }

    /// Whether `uid` has a password credential (`createAuthUri` sign-in methods).
    #[must_use]
    pub fn has_password(&self, uid: &LocalId) -> bool {
        self.users.get(uid).is_some_and(|u| u.password.is_some())
    }

    /// Verifies an email + password sign-in; returns the user ID.
    ///
    /// The refusal follows the project's email privacy setting the way the official emulator's
    /// does: by default an unknown email is [`AuthError::EmailNotFound`] and a wrong password
    /// [`AuthError::InvalidPassword`]; with `enableImprovedEmailPrivacy` both collapse into
    /// [`AuthError::InvalidCredentials`] so the response no longer reveals whether the email
    /// is registered.
    pub fn verify_password(
        &mut self,
        email: &str,
        password: &str,
        now: LogicalInstant,
    ) -> Result<LocalId, AuthError> {
        let private = self.config.enable_improved_email_privacy;
        let Some(user) = self.user_by_email(email) else {
            if private {
                let dummy = PasswordDigest {
                    salt: [0_u8; 16],
                    digest: [0_u8; 20],
                    emulator: None,
                };
                let _ = dummy.verify(password);
                return Err(AuthError::InvalidCredentials);
            }
            return Err(AuthError::EmailNotFound);
        };
        let (uid, disabled, ok) = (
            user.local_id.clone(),
            user.disabled,
            user.password.as_ref().is_some_and(|p| p.verify(password)),
        );
        // The official emulator reports a disabled account before it checks the password.
        if disabled {
            return Err(AuthError::UserDisabled);
        }
        if !ok {
            return Err(if private {
                AuthError::InvalidCredentials
            } else {
                AuthError::InvalidPassword
            });
        }
        if let Some(u) = self.users.get_mut(&uid).map(Arc::make_mut) {
            u.last_sign_in_at = Some(now);
        }
        Ok(uid)
    }

    /// Looks up a user by email.
    #[must_use]
    pub fn user_by_email(&self, email: &str) -> Option<&UserRecord> {
        self.local_id_for_email
            .get(email)
            .and_then(|uid| self.users.get(uid))
            .map(Arc::as_ref)
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
        self.users.get(uid).map(Arc::as_ref)
    }

    /// Mutable user access. Clones the one user through [`Arc::make_mut`], so a snapshot that
    /// shares it is left untouched (`SNAP-MEM-03`).
    pub fn user_mut(&mut self, uid: &LocalId) -> Option<&mut UserRecord> {
        self.users.get_mut(uid).map(Arc::make_mut)
    }

    /// Sets custom claims after the size check.
    pub fn set_custom_claims(
        &mut self,
        uid: &LocalId,
        claims: CustomClaims,
    ) -> Result<(), AuthError> {
        claims.check_size().map_err(AuthError::LimitExceeded)?;
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
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
        // Expired sessions are swept before the budget is measured, so an abandoned flow
        // frees its slot on expiry; a refused start creates no secret and no session.
        self.sweep_transient_credentials(now);
        let user = self.users.get(uid).ok_or(MfaError::UserNotFound)?;
        if user.mfa.pending_count() >= crate::mfa::MAX_PENDING_PER_USER {
            return Err(MfaError::TooManyPending);
        }
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
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(MfaError::UserNotFound)?;
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
        let enrollment_id = self.random_id28();
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(MfaError::UserNotFound)?;
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
        self.sweep_transient_credentials(now);
        let pending_id = self.next_id("signin-");
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(MfaError::UserNotFound)?;
        if user.disabled {
            return Err(MfaError::UserDisabled);
        }
        if user.mfa.is_empty() {
            return Err(MfaError::NoEnrolledFactor);
        }
        if user.mfa.pending_count() >= crate::mfa::MAX_PENDING_PER_USER {
            return Err(MfaError::TooManyPending);
        }
        user.mfa
            .pending_sign_ins_mut()
            .insert(pending_id.clone(), PendingSignIn { started_at: now });
        self.pending_sign_in_owners
            .insert(pending_id.clone(), uid.clone());
        Ok(PendingSignInId(pending_id))
    }

    /// User that owns a pending sign-in, if any: a direct lookup in the ownership index,
    /// confirmed against the user's own pending map so the two can never disagree.
    #[must_use]
    pub fn pending_sign_in_user(&self, pending: &PendingSignInId) -> Option<LocalId> {
        let owner = self.pending_sign_in_owners.get(&pending.0)?;
        self.users
            .get(owner)
            .filter(|u| u.mfa.has_pending_sign_in(&pending.0))
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
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(MfaError::UserNotFound)?;
        if user.mfa.pending_sign_ins_mut().remove(&pending.0).is_none() {
            return Err(MfaError::PendingSignInUnknown);
        }
        self.pending_sign_in_owners.remove(&pending.0);
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
            display_name: user.display_name.clone(),
            photo_url: user.photo_url.clone(),
            firebase: FirebaseClaims {
                identities,
                sign_in_provider: user.provider.id().to_owned(),
                sign_in_second_factor: second.map(|a| a.sign_in_second_factor.clone()),
                second_factor_identifier: second.map(|a| a.second_factor_identifier.clone()),
                tenant: self.tenant_id.clone(),
            },
            custom: user.custom_claims.clone(),
        })
    }

    /// Revokes refresh tokens: tokens issued before `now` become invalid.
    pub fn revoke_tokens(&mut self, uid: &LocalId, now: LogicalInstant) -> Result<(), AuthError> {
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
        user.tokens_valid_after = Self::whole_second(now);
        Ok(())
    }

    /// `validSince` has second precision on the wire and a token's `auth_time` is a whole
    /// second, so the revocation instant is floored: a token issued in the same second as
    /// the revocation stays valid on both sides, as it does in the official emulator.
    fn whole_second(at: LogicalInstant) -> LogicalInstant {
        let seconds = at.as_nanos().div_euclid(1_000_000_000);
        LogicalInstant::from_nanos(seconds * 1_000_000_000)
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

/// What a restore could not bring back faithfully.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// Enrolled TOTP factors whose secret the live store no longer held (withdrawn, the
    /// account deleted, or the session reset since the capture); they were dropped from
    /// the restored account rather than restored unusable.
    pub totp_factors_dropped: usize,
}

/// A default snapshot of an Auth store: everything the store owns except TOTP secret
/// material. Enrolled TOTP factors are kept with a detached secret and pending TOTP
/// enrollments are not kept at all, so the captured part holds no shared secret
/// (`INV-AUTH-003`, ADR-034). On restore each factor is rebound to the secret the live
/// store still holds for the same enrollment; a factor whose secret is gone is dropped and
/// counted in the [`RestoreReport`], never restored as an unusable factor and never claimed
/// faithful.
#[derive(Debug, Clone)]
pub struct AuthSnapshot(AuthStore);

impl AuthSnapshot {
    /// Copies `store` without its TOTP secret material.
    ///
    /// Copy-on-write per user (`SNAP-MEM-03`): cloning the store bumps each user's `Arc`
    /// refcount rather than deep-copying it, so a user with no TOTP secret -- the common case --
    /// is shared by reference with the live store. Only a user that actually holds secret
    /// material is cloned through [`Arc::make_mut`] and detached, so the snapshot still carries
    /// no shared secret (`INV-AUTH-003`, ADR-034) while every unchanged user stays shared.
    #[must_use]
    pub fn capture(store: &AuthStore) -> Self {
        let mut copy = store.clone();
        for user in copy.users.values_mut() {
            if user.mfa.holds_no_totp_secret() {
                continue;
            }
            Arc::make_mut(user).mfa.detach_totp_secrets();
        }
        Self(copy)
    }

    /// An estimate of the heap bytes the snapshot retains: the user records plus the transient
    /// maps a capture still copies in full (refresh tokens, action and verification codes).
    /// Saturating, so an adversarial store can never overflow the session byte budget
    /// (`SNAP-MEM-01`).
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        self.0
            .retained_user_bytes()
            .saturating_add(self.0.transient_bytes())
    }

    /// Bytes of user records this snapshot shares with `live` by allocation: users whose
    /// record is the same `Arc` on both sides, so the capture copied nothing for them
    /// (`SNAP-MEM-03`, the Auth analogue of `StorageState::blob_bytes_shared_with`).
    #[must_use]
    pub fn users_shared_with(&self, live: &AuthStore) -> u64 {
        self.0.users_shared_with(live)
    }

    /// Whether no user of the snapshot holds any TOTP secret material. Always true for a
    /// snapshot this type produced; the test proves it rather than trusting the constructor.
    #[must_use]
    pub fn holds_no_totp_secret(&self) -> bool {
        self.0.users.values().all(|u| u.mfa.holds_no_totp_secret())
    }

    /// The project the snapshot was taken from.
    #[must_use]
    pub fn project_id(&self) -> &str {
        self.0.project_id()
    }

    /// Replaces `live` with the snapshot, rebinding TOTP secrets from what `live` held.
    pub fn restore_into(&self, live: &mut AuthStore) -> RestoreReport {
        let mut restored = self.0.clone();
        let mut report = RestoreReport::default();
        for user in restored.users.values_mut() {
            // Only a user with an enrolled (detached) TOTP factor needs rebinding; a user
            // with none is left shared rather than cloned for a no-op.
            if user.mfa.totp_factors().is_empty() {
                continue;
            }
            let dropped = match live.users.get(&user.local_id) {
                Some(current) => Arc::make_mut(user).mfa.rebind_totp_secrets(&current.mfa),
                None => Arc::make_mut(user)
                    .mfa
                    .rebind_totp_secrets(&MfaState::default()),
            };
            report.totp_factors_dropped += dropped;
        }
        // The signer is process state shared by every copy; keep whichever the live store
        // has (a snapshot taken before a signer was installed must not uninstall it).
        restored.signer = live.signer.clone().or(restored.signer);
        *live = restored;
        report
    }
}

type SharedAuthStore = Arc<Mutex<AuthStore>>;
type TenantKey = (String, String);

/// The Auth stores of every project a daemon serves: the configured (default) project plus
/// the projects created as sessions through the control API. Tokens name their project in
/// `aud`, so a verifier picks the store by audience.
#[derive(Debug)]
pub struct AuthRegistry {
    default_project: String,
    default: SharedAuthStore,
    others: Mutex<BTreeMap<String, SharedAuthStore>>,
    tenants: Mutex<BTreeMap<TenantKey, SharedAuthStore>>,
    tenant_metadata: Mutex<BTreeMap<TenantKey, TenantMetadata>>,
    operation_gates: Mutex<BTreeMap<TenantKey, Arc<Mutex<()>>>>,
    next_tenant_id: AtomicU64,
}

/// Mutable Identity Platform tenant settings represented by the Admin v2 surface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct TenantMetadata {
    /// Human-readable tenant name.
    pub display_name: Option<String>,
    /// Whether password account creation and sign-in are enabled.
    pub allow_password_signup: bool,
    /// Whether email-link sign-in is enabled.
    pub enable_email_link_signin: bool,
    /// Whether anonymous sign-in is enabled.
    pub enable_anonymous_user: bool,
    /// Whether all authentication is disabled.
    pub disable_auth: bool,
}

/// Fields changed by one atomic tenant PATCH operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantMetadataPatch {
    /// `None` leaves the field unchanged; `Some(None)` clears it.
    pub display_name: Option<Option<String>>,
    /// `None` leaves the field unchanged.
    pub allow_password_signup: Option<bool>,
    /// `None` leaves the field unchanged.
    pub enable_email_link_signin: Option<bool>,
    /// `None` leaves the field unchanged.
    pub enable_anonymous_user: Option<bool>,
    /// `None` leaves the field unchanged.
    pub disable_auth: Option<bool>,
}

impl AuthRegistry {
    /// A registry around the default project's store.
    #[must_use]
    pub fn new(default_project: &str, default: Arc<Mutex<AuthStore>>) -> Self {
        Self {
            default_project: default_project.to_owned(),
            default,
            others: Mutex::new(BTreeMap::new()),
            tenants: Mutex::new(BTreeMap::new()),
            tenant_metadata: Mutex::new(BTreeMap::new()),
            operation_gates: Mutex::new(BTreeMap::new()),
            next_tenant_id: AtomicU64::new(1),
        }
    }

    /// The default project.
    #[must_use]
    pub fn default_project(&self) -> &str {
        &self.default_project
    }

    /// The default project's store.
    #[must_use]
    pub fn default_store(&self) -> Arc<Mutex<AuthStore>> {
        self.default.clone()
    }

    /// The store of `project`, if it is the default or a registered session.
    #[must_use]
    pub fn store_for(&self, project: &str) -> Option<Arc<Mutex<AuthStore>>> {
        if project == self.default_project {
            return Some(self.default.clone());
        }
        self.others.lock().ok()?.get(project).cloned()
    }

    /// Registers a project's store; `false` when the project already has one.
    pub fn register(&self, project: &str, store: AuthStore) -> bool {
        if project == self.default_project {
            return false;
        }
        let Ok(mut others) = self.others.lock() else {
            return false;
        };
        if others.contains_key(project) {
            return false;
        }
        others.insert(project.to_owned(), Arc::new(Mutex::new(store)));
        true
    }

    /// Removes a registered project; `false` when it was not registered.
    pub fn remove(&self, project: &str) -> bool {
        let removed = self
            .others
            .lock()
            .ok()
            .is_some_and(|mut o| o.remove(project).is_some());
        if removed {
            if let Ok(mut tenants) = self.tenants.lock() {
                tenants.retain(|(candidate, _), _| candidate != project);
            }
            if let Ok(mut metadata) = self.tenant_metadata.lock() {
                metadata.retain(|(candidate, _), _| candidate != project);
            }
            if let Ok(mut gates) = self.operation_gates.lock() {
                gates.retain(|(candidate, _), _| candidate != project);
            }
        }
        removed
    }

    /// Returns an existing tenant store.
    #[must_use]
    pub fn tenant_store(&self, project: &str, tenant: &str) -> Option<Arc<Mutex<AuthStore>>> {
        self.tenants
            .lock()
            .ok()?
            .get(&(project.to_owned(), tenant.to_owned()))
            .cloned()
    }

    /// Per-namespace gate used while a blocking function runs without the store lock.
    #[must_use]
    pub fn operation_gate(&self, project: &str, tenant: Option<&str>) -> Arc<Mutex<()>> {
        let key = (project.to_owned(), tenant.unwrap_or_default().to_owned());
        self.operation_gates.lock().map_or_else(
            |_| Arc::new(Mutex::new(())),
            |mut gates| {
                gates
                    .entry(key)
                    .or_insert_with(|| Arc::new(Mutex::new(())))
                    .clone()
            },
        )
    }

    /// Returns a tenant store, creating its isolated namespace on first use.
    pub fn ensure_tenant(&self, project: &str, tenant: &str) -> Option<Arc<Mutex<AuthStore>>> {
        if tenant.is_empty() || tenant.contains(['/', '\\']) {
            return None;
        }
        if let Some(store) = self.tenant_store(project, tenant) {
            return Some(store);
        }
        let parent = self.store_for(project)?;
        let (policy, config, signer) = {
            let parent = parent.lock().ok()?;
            (*parent.policy(), parent.config(), parent.signer_arc())
        };
        let seed = project
            .bytes()
            .chain(tenant.bytes())
            .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
                hash.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte)
            });
        let mut store = AuthStore::new_tenant(project, tenant, SplitMix64::new(seed), policy);
        store.set_config(config);
        if let Some(signer) = signer {
            store.set_signer(signer);
        }
        let store = Arc::new(Mutex::new(store));
        let mut tenants = self.tenants.lock().ok()?;
        let selected = tenants
            .entry((project.to_owned(), tenant.to_owned()))
            .or_insert_with(|| store.clone())
            .clone();
        drop(tenants);
        if let Ok(mut metadata) = self.tenant_metadata.lock() {
            metadata
                .entry((project.to_owned(), tenant.to_owned()))
                .or_insert_with(|| TenantMetadata {
                    allow_password_signup: true,
                    enable_email_link_signin: true,
                    enable_anonymous_user: true,
                    ..TenantMetadata::default()
                });
        }
        Some(selected)
    }

    /// Creates an explicitly configured tenant and returns its generated ID.
    pub fn create_tenant(&self, project: &str, metadata: TenantMetadata) -> Option<String> {
        self.store_for(project)?;
        let sequence = self.next_tenant_id.fetch_add(1, Ordering::Relaxed);
        let tenant = format!("fireemu-{sequence:020}");
        self.ensure_tenant(project, &tenant)?;
        self.tenant_metadata
            .lock()
            .ok()?
            .insert((project.to_owned(), tenant.clone()), metadata);
        Some(tenant)
    }

    /// Tenant metadata when the tenant exists.
    #[must_use]
    pub fn tenant_metadata(&self, project: &str, tenant: &str) -> Option<TenantMetadata> {
        self.tenant_metadata
            .lock()
            .ok()?
            .get(&(project.to_owned(), tenant.to_owned()))
            .cloned()
    }

    /// Runs a closure while both the tenant namespace and metadata entry are locked.
    ///
    /// This is the commit boundary for authentication that raced tenant deletion or policy
    /// changes. The closure must not call back into this registry.
    pub fn with_existing_tenant_metadata<R>(
        &self,
        project: &str,
        tenant: &str,
        inspect: impl FnOnce(Option<&TenantMetadata>) -> R,
    ) -> R {
        let key = (project.to_owned(), tenant.to_owned());
        let Ok(stores) = self.tenants.lock() else {
            return inspect(None);
        };
        let Ok(metadata) = self.tenant_metadata.lock() else {
            return inspect(None);
        };
        let selected = stores
            .contains_key(&key)
            .then(|| metadata.get(&key))
            .flatten();
        inspect(selected)
    }

    /// Applies one tenant metadata patch under a single lock acquisition.
    pub fn patch_tenant(
        &self,
        project: &str,
        tenant: &str,
        patch: TenantMetadataPatch,
    ) -> Option<TenantMetadata> {
        let mut values = self.tenant_metadata.lock().ok()?;
        let value = values.get_mut(&(project.to_owned(), tenant.to_owned()))?;
        if let Some(display_name) = patch.display_name {
            value.display_name = display_name;
        }
        if let Some(setting) = patch.allow_password_signup {
            value.allow_password_signup = setting;
        }
        if let Some(setting) = patch.enable_email_link_signin {
            value.enable_email_link_signin = setting;
        }
        if let Some(setting) = patch.enable_anonymous_user {
            value.enable_anonymous_user = setting;
        }
        if let Some(setting) = patch.disable_auth {
            value.disable_auth = setting;
        }
        Some(value.clone())
    }

    /// Replaces tenant metadata; `false` when the tenant is unknown.
    pub fn update_tenant(&self, project: &str, tenant: &str, metadata: TenantMetadata) -> bool {
        let Ok(mut values) = self.tenant_metadata.lock() else {
            return false;
        };
        let Some(value) = values.get_mut(&(project.to_owned(), tenant.to_owned())) else {
            return false;
        };
        *value = metadata;
        true
    }

    /// Lists tenant IDs in stable lexical order.
    #[must_use]
    pub fn tenants(&self, project: &str) -> Vec<String> {
        self.tenant_metadata
            .lock()
            .map(|values| {
                values
                    .keys()
                    .filter(|(candidate, _)| candidate == project)
                    .map(|(_, tenant)| tenant.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Applies project-level Auth configuration and propagates inherited switches to tenants.
    pub fn set_project_config(&self, project: &str, config: ProjectAuthConfig) -> bool {
        let Some(parent) = self.store_for(project) else {
            return false;
        };
        let Ok(mut parent) = parent.lock() else {
            return false;
        };
        parent.set_config(config);
        drop(parent);
        if let Ok(tenants) = self.tenants.lock() {
            for ((candidate, _), store) in tenants.iter() {
                if candidate == project {
                    if let Ok(mut store) = store.lock() {
                        store.set_config(config);
                    }
                }
            }
        }
        true
    }

    /// Deletes a tenant namespace and its metadata.
    pub fn delete_tenant(&self, project: &str, tenant: &str) -> bool {
        let key = (project.to_owned(), tenant.to_owned());
        let removed = self
            .tenants
            .lock()
            .ok()
            .is_some_and(|mut stores| stores.remove(&key).is_some());
        if let Ok(mut metadata) = self.tenant_metadata.lock() {
            metadata.remove(&key);
        }
        if let Ok(mut gates) = self.operation_gates.lock() {
            gates.remove(&key);
        }
        removed
    }

    /// The first store (the default first, then the registered ones in name order) that
    /// satisfies `pred`.
    pub fn find(&self, pred: impl Fn(&AuthStore) -> bool) -> Option<Arc<Mutex<AuthStore>>> {
        if self.default.lock().is_ok_and(|s| pred(&s)) {
            return Some(self.default.clone());
        }
        let others = self.others.lock().ok()?;
        if let Some(found) = others
            .values()
            .find(|s| s.lock().is_ok_and(|s| pred(&s)))
            .cloned()
        {
            return Some(found);
        }
        drop(others);
        self.tenants
            .lock()
            .ok()?
            .values()
            .find(|s| s.lock().is_ok_and(|s| pred(&s)))
            .cloned()
    }

    /// Every project with a store, the default first.
    #[must_use]
    pub fn projects(&self) -> Vec<String> {
        let mut out = vec![self.default_project.clone()];
        if let Ok(others) = self.others.lock() {
            out.extend(others.keys().cloned());
        }
        out
    }
}

#[cfg(test)]
mod snapshot_cow_tests {
    //! Copy-on-write per user (`SNAP-MEM-03`): an [`AuthSnapshot`] shares the `Arc` of every
    //! unchanged user with the live store, so a capture copies only the users it must detach,
    //! and a post-capture mutation clones exactly the one user it touches while every retained
    //! snapshot stays exactly as it was captured. These tests reach the private `users` map so
    //! they can assert `Arc` identity directly.

    use super::{AuthSnapshot, AuthStore, LocalId, NewUser};
    use crate::mfa::TotpPolicy;
    use crate::totp::totp_at;
    use fireemu_core_types::determinism::SplitMix64;
    use fireemu_core_types::time::LogicalInstant;
    use std::sync::Arc;

    const AT: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

    fn store() -> AuthStore {
        AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default())
    }

    fn shares(snapshot: &AuthSnapshot, live: &AuthStore, uid: &LocalId) -> bool {
        match (snapshot.0.users.get(uid), live.users.get(uid)) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }

    #[test]
    fn a_capture_shares_every_unchanged_user_by_reference() {
        let mut live = store();
        let a = live
            .create_user(NewUser::email("a@example.com"), AT)
            .unwrap();
        let b = live
            .create_user(NewUser::email("b@example.com"), AT)
            .unwrap();

        let snapshot = AuthSnapshot::capture(&live);
        assert!(shares(&snapshot, &live, &a), "an unchanged user is shared");
        assert!(shares(&snapshot, &live, &b), "an unchanged user is shared");
        // Every byte the snapshot retains for its users is shared with the live store: the
        // capture copied no user record at all.
        assert_eq!(
            snapshot.users_shared_with(&live),
            live.retained_user_bytes(),
            "no user record was copied on capture"
        );
    }

    #[test]
    fn a_post_capture_mutation_copies_only_the_one_user_and_leaves_the_snapshot_exact() {
        let mut live = store();
        let a = live
            .create_user(NewUser::email("a@example.com"), AT)
            .unwrap();
        let b = live
            .create_user(NewUser::email("b@example.com"), AT)
            .unwrap();

        let snapshot = AuthSnapshot::capture(&live);

        // Mutate user a in the live store after the capture.
        live.set_email(&a, "changed@example.com").unwrap();

        // The snapshot's copy of a is untouched, and it is no longer the same allocation.
        assert_eq!(
            snapshot.0.users.get(&a).unwrap().email.as_deref(),
            Some("a@example.com"),
            "the retained snapshot keeps the captured value"
        );
        assert!(
            !shares(&snapshot, &live, &a),
            "a mutated user is copied, not shared"
        );
        // b was never touched: it is still the same allocation on both sides.
        assert!(
            shares(&snapshot, &live, &b),
            "an untouched user stays shared after another user is mutated"
        );
    }

    #[test]
    fn a_capture_detaches_only_the_users_that_hold_a_secret_and_shares_the_rest() {
        let mut live = store();
        let plain = live
            .create_user(NewUser::email("plain@example.com"), AT)
            .unwrap();
        let mfa = live
            .create_user(NewUser::email("mfa@example.com"), AT)
            .unwrap();
        let material = live.start_totp_enrollment(&mfa, AT).unwrap();
        let code = totp_at(material.secret_for_test(), &live.policy().params(), AT);
        live.finalize_totp_enrollment(&mfa, &material.session_id, code, AT)
            .unwrap();

        let snapshot = AuthSnapshot::capture(&live);
        assert!(snapshot.holds_no_totp_secret(), "no secret is retained");
        assert!(
            shares(&snapshot, &live, &plain),
            "a user with no secret is shared"
        );
        assert!(
            !shares(&snapshot, &live, &mfa),
            "a user with a TOTP secret is copied so its secret can be detached"
        );
        // The live store still holds the real secret; only the snapshot's copy is detached.
        assert!(
            !live.user(&mfa).unwrap().mfa.totp_factors()[0]
                .secret
                .is_detached(),
            "detaching the snapshot never touched the live secret"
        );
        assert!(snapshot.0.users.get(&mfa).unwrap().mfa.totp_factors()[0]
            .secret
            .is_detached());
    }
}
