//! In-memory user store with TOTP enrollment / sign-in and ID token claim construction.

use core::fmt;
use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

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
    PendingSignInContext, PhoneFactor, TotpEnrollmentMaterial, TotpFactor, TotpPolicy, TotpSecret,
    MAX_FACTORS_PER_USER,
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

impl Borrow<str> for LocalId {
    fn borrow(&self) -> &str {
        self.as_str()
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
    /// Every account owning an email, including inactive duplicates. Membership checks never
    /// scan the user map; the separate active lookup retains official-emulator overwrite and
    /// delete semantics.
    local_ids_for_email: BTreeMap<String, BTreeSet<LocalId>>,
    /// Phone owners in canonical local-ID order. Imported artifacts may contain duplicates,
    /// so the first owner preserves the previous `BTreeMap` scan result.
    local_ids_for_phone: BTreeMap<String, BTreeSet<LocalId>>,
    /// Federated identity owners in canonical local-ID order, with the same import-safe
    /// duplicate handling as phone numbers.
    local_ids_for_federated: BTreeMap<(String, String), BTreeSet<LocalId>>,
    /// User IDs in stable creation order. This makes list-user pagination a bounded range
    /// lookup instead of a full-store collection and sort for every page.
    by_sequence: BTreeMap<u64, LocalId>,
    counter: u64,
    /// Refresh sessions are copy-on-write so speculative blocking-function stores and session
    /// snapshots share the unchanged registry in O(1).
    refresh_tokens: Arc<BTreeMap<String, RefreshSession>>,
    /// Refresh-token values owned by each user. Revocation and deletion touch one user's
    /// sessions instead of scanning every live session.
    tokens_by_user: Arc<BTreeMap<LocalId, BTreeSet<String>>>,
    next_id_override: Option<String>,
    next_sequence: u64,
    signer: Option<Arc<dyn crate::jwt::IdTokenSigner>>,
    oob_codes: Arc<BTreeMap<String, OobCode>>,
    verification_codes: Arc<BTreeMap<String, VerificationCode>>,
    /// Which user owns each outstanding pending sign-in (`mfaPendingCredential`), so a
    /// credential is resolved directly rather than by scanning every user
    /// (`AUTH-TRANSIENT-04`). Kept in step with the users' own pending maps.
    pending_sign_in_owners: Arc<BTreeMap<String, LocalId>>,
    /// Users that currently own a pending enrollment or sign-in. Credential sweeping only
    /// visits this bounded subset instead of cloning or scanning every account.
    pending_user_ids: BTreeSet<LocalId>,
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
    total = total.saturating_add(user.mfa.pending_retained_bytes());
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
            local_ids_for_email: BTreeMap::new(),
            local_ids_for_phone: BTreeMap::new(),
            local_ids_for_federated: BTreeMap::new(),
            by_sequence: BTreeMap::new(),
            counter: 0,
            refresh_tokens: Arc::new(BTreeMap::new()),
            tokens_by_user: Arc::new(BTreeMap::new()),
            next_id_override: None,
            next_sequence: 0,
            signer: None,
            oob_codes: Arc::new(BTreeMap::new()),
            verification_codes: Arc::new(BTreeMap::new()),
            pending_sign_in_owners: Arc::new(BTreeMap::new()),
            pending_user_ids: BTreeSet::new(),
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
        self.users.get(uid).map(Arc::as_ref)
    }

    fn email_owned_by_other(&self, email: &str, uid: Option<&LocalId>) -> bool {
        self.local_ids_for_email
            .get(email)
            .is_some_and(|owners| owners.iter().any(|owner| Some(owner) != uid))
    }

    fn add_email_owner(&mut self, email: String, uid: &LocalId) {
        self.local_ids_for_email
            .entry(email.clone())
            .or_default()
            .insert(uid.clone());
        self.local_id_for_email.insert(email, uid.clone());
    }

    /// Mirrors the official emulator's `updateUserByLocalId`: every successful user update,
    /// including one that does not change the email field, makes that duplicate the active
    /// target of an email lookup.
    fn activate_email_owner(&mut self, uid: &LocalId) {
        if let Some(email) = self.users.get(uid).and_then(|user| user.email.clone()) {
            self.local_id_for_email.insert(email, uid.clone());
        }
    }

    fn remove_email_owner(&mut self, email: &str, uid: &LocalId) {
        if let Some(owners) = self.local_ids_for_email.get_mut(email) {
            owners.remove(uid);
        }
        if self
            .local_ids_for_email
            .get(email)
            .is_some_and(BTreeSet::is_empty)
        {
            self.local_ids_for_email.remove(email);
        }
        // The official Auth Emulator deletes the single active email index entry whenever
        // any duplicate owner is removed; it does not restore another owner automatically.
        self.local_id_for_email.remove(email);
    }

    fn next_id(&mut self, prefix: &str) -> String {
        self.counter += 1;
        format!(
            "{prefix}{:016x}{:04}",
            self.rng.next_u64(),
            self.counter % 10_000
        )
    }

    fn next_refresh_token(&mut self) -> String {
        let entropy = self.next_id("");
        let tenant = self.tenant_id.as_deref().unwrap_or_default();
        format!(
            "rt1.{}.{}.{}{}.{}",
            self.project_id.len(),
            tenant.len(),
            self.project_id,
            tenant,
            entropy
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
            self.remove_email_owner(email, &key);
        }
        if let Some(phone) = &user.phone_number {
            Self::remove_index_owner(&mut self.local_ids_for_phone, phone, &key);
        }
        for identity in &user.federated {
            let identity_key = (identity.provider_id.clone(), identity.raw_id.clone());
            Self::remove_index_owner(&mut self.local_ids_for_federated, &identity_key, &key);
        }
        self.by_sequence.remove(&user.sequence);
        self.remove_refresh_tokens_for(&key);
        Arc::make_mut(&mut self.pending_sign_in_owners).retain(|_, owner| *owner != key);
        self.pending_user_ids.remove(&key);
        Arc::make_mut(&mut self.verification_codes).retain(|_, c| match &c.purpose {
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
        self.local_ids_for_email.clear();
        self.local_ids_for_phone.clear();
        self.local_ids_for_federated.clear();
        self.by_sequence.clear();
        self.refresh_tokens = Arc::new(BTreeMap::new());
        self.tokens_by_user = Arc::new(BTreeMap::new());
        self.oob_codes = Arc::new(BTreeMap::new());
        self.verification_codes = Arc::new(BTreeMap::new());
        self.pending_sign_in_owners = Arc::new(BTreeMap::new());
        self.pending_user_ids.clear();
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
        if self
            .oob_codes
            .values()
            .any(|code| Self::expired(code.created_at, OOB_CODE_TTL_SECONDS, now))
        {
            Arc::make_mut(&mut self.oob_codes)
                .retain(|_, code| !Self::expired(code.created_at, OOB_CODE_TTL_SECONDS, now));
        }
        if self
            .verification_codes
            .values()
            .any(|code| Self::expired(code.created_at, SMS_CODE_TTL_SECONDS, now))
        {
            Arc::make_mut(&mut self.verification_codes)
                .retain(|_, code| !Self::expired(code.created_at, SMS_CODE_TTL_SECONDS, now));
        }
        let sign_in_ttl = LogicalDuration::from_seconds(PENDING_SIGN_IN_TTL_SECONDS);
        let enrollment_grace = self.policy.enrollment_session_ttl;
        let candidates: Vec<LocalId> = self.pending_user_ids.iter().cloned().collect();
        for uid in candidates {
            let mut remains_pending = false;
            if let Some(user) = self.users.get_mut(&uid) {
                let user = Arc::make_mut(user);
                for dropped in user.mfa.sweep(now, sign_in_ttl, enrollment_grace) {
                    Arc::make_mut(&mut self.pending_sign_in_owners).remove(&dropped);
                }
                remains_pending = user.mfa.pending_count() != 0;
            }
            if !remains_pending {
                self.pending_user_ids.remove(&uid);
            }
        }
        // A phone code for a pending sign-in that no longer exists can never be finalized.
        let has_orphan = self
            .verification_codes
            .values()
            .any(|code| match &code.purpose {
                VerificationPurpose::MfaSignIn { pending, .. } => {
                    !self.pending_sign_in_owners.contains_key(&pending.0)
                }
                VerificationPurpose::SignIn | VerificationPurpose::Enrollment { .. } => false,
            });
        if has_orphan {
            let owners = &self.pending_sign_in_owners;
            Arc::make_mut(&mut self.verification_codes).retain(|_, code| match &code.purpose {
                VerificationPurpose::MfaSignIn { pending, .. } => owners.contains_key(&pending.0),
                VerificationPurpose::SignIn | VerificationPurpose::Enrollment { .. } => true,
            });
        }
    }

    /// Outstanding pending second-factor sign-ins across every user (bounded state).
    #[must_use]
    pub fn pending_sign_in_count(&self) -> usize {
        self.pending_sign_in_owners.len()
    }

    /// Users that currently own any pending MFA state.
    #[must_use]
    pub fn pending_mfa_user_count(&self) -> usize {
        self.pending_user_ids.len()
    }

    /// Records a successful sign-in (Admin `lastLoginAt`).
    pub fn record_sign_in(&mut self, uid: &LocalId, now: LogicalInstant) {
        if let Some(u) = self.users.get_mut(uid).map(Arc::make_mut) {
            u.last_sign_in_at = Some(now);
            self.activate_email_owner(uid);
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
            if !self.config.allow_duplicate_emails && self.email_owned_by_other(email, None) {
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
        let phone = user.phone_number.clone();
        let identities: Vec<(String, String)> = user
            .federated
            .iter()
            .map(|identity| (identity.provider_id.clone(), identity.raw_id.clone()))
            .collect();
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
        self.by_sequence.insert(sequence, local_id.clone());
        if let Some(email) = email {
            self.add_email_owner(email, &local_id);
        }
        if let Some(phone) = phone {
            self.local_ids_for_phone
                .entry(phone)
                .or_default()
                .insert(local_id.clone());
        }
        for identity in identities {
            self.local_ids_for_federated
                .entry(identity)
                .or_default()
                .insert(local_id.clone());
        }
        Ok(local_id)
    }

    /// Users in creation order (stable `listUsers` paging).
    #[must_use]
    pub fn users_by_creation(&self) -> Vec<&UserRecord> {
        self.by_sequence
            .values()
            .filter_map(|id| self.users.get(id).map(Arc::as_ref))
            .collect()
    }

    /// At most `limit` users created after `sequence`, in stable creation order.
    #[must_use]
    pub fn users_after_sequence(&self, sequence: u64, limit: usize) -> Vec<&UserRecord> {
        use std::ops::Bound::{Excluded, Unbounded};

        self.by_sequence
            .range((Excluded(sequence), Unbounded))
            .take(limit)
            .filter_map(|(_, id)| self.users.get(id).map(Arc::as_ref))
            .collect()
    }

    /// User by phone number.
    #[must_use]
    pub fn user_by_phone(&self, phone: &str) -> Option<&UserRecord> {
        self.local_ids_for_phone
            .get(phone)
            .and_then(|owners| owners.first())
            .and_then(|uid| self.users.get(uid))
            .map(Arc::as_ref)
    }

    /// Changes the email, enforcing uniqueness unless the project enables duplicate emails.
    pub fn set_email(&mut self, uid: &LocalId, email: &str) -> Result<(), AuthError> {
        if !email.contains('@') || email.chars().any(char::is_control) {
            return Err(AuthError::InvalidEmail);
        }
        if !self.config.allow_duplicate_emails && self.email_owned_by_other(email, Some(uid)) {
            return Err(AuthError::EmailExists);
        }
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
        let old = user.email.replace(email.to_owned());
        if let Some(old) = old {
            self.remove_email_owner(&old, uid);
        }
        self.add_email_owner(email.to_owned(), uid);
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
            if self.local_ids_for_phone.get(phone).is_some_and(|owners| {
                owners.len() > 1 || owners.first().is_some_and(|owner| owner != uid)
            }) {
                return Err(AuthError::PhoneNumberExists);
            }
        }
        let old_phone = self
            .users
            .get(uid)
            .ok_or(AuthError::UserNotFound)?
            .phone_number
            .clone();
        if let Some(old_phone) = old_phone {
            Self::remove_index_owner(&mut self.local_ids_for_phone, &old_phone, uid);
        }
        self.users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?
            .phone_number = phone.map(str::to_owned);
        if let Some(phone) = phone {
            self.local_ids_for_phone
                .entry(phone.to_owned())
                .or_default()
                .insert(uid.clone());
        }
        self.activate_email_owner(uid);
        Ok(())
    }

    fn remove_index_owner<K: Ord>(
        index: &mut BTreeMap<K, BTreeSet<LocalId>>,
        key: &K,
        uid: &LocalId,
    ) {
        let remove_key = index.get_mut(key).is_some_and(|owners| {
            owners.remove(uid);
            owners.is_empty()
        });
        if remove_key {
            index.remove(key);
        }
    }

    /// All user IDs in canonical order.
    #[must_use]
    pub fn all_user_ids(&self) -> Vec<LocalId> {
        self.users.keys().cloned().collect()
    }

    /// A bounded page in canonical local-ID order without collecting or sorting the store.
    #[must_use]
    pub fn users_by_local_id_page(
        &self,
        offset: usize,
        limit: usize,
        descending: bool,
    ) -> Vec<&UserRecord> {
        if descending {
            self.users
                .values()
                .rev()
                .skip(offset)
                .take(limit)
                .map(Arc::as_ref)
                .collect()
        } else {
            self.users
                .values()
                .skip(offset)
                .take(limit)
                .map(Arc::as_ref)
                .collect()
        }
    }

    /// Number of users without allocating an ID list.
    #[must_use]
    pub fn user_count(&self) -> usize {
        self.users.len()
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
        let refresh_owners = self
            .tokens_by_user
            .iter()
            .fold(0_u64, |total, (uid, tokens)| {
                let owner = 64_u64.saturating_add(uid.as_str().len() as u64);
                let entries = tokens.iter().fold(0_u64, |bytes, token| {
                    bytes.saturating_add(48_u64.saturating_add(token.len() as u64))
                });
                total.saturating_add(owner).saturating_add(entries)
            });
        refresh
            .saturating_add(oob)
            .saturating_add(verification)
            .saturating_add(refresh_owners)
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

    /// Number of copy-on-write transient registries this store shares with `other`.
    ///
    /// The five registries are refresh sessions, their per-user index, email action codes,
    /// phone verification codes, and pending-sign-in owners. A speculative Auth operation
    /// that only issues a refresh session must leave the other three allocations shared.
    #[must_use]
    pub fn transient_registries_shared_with(&self, other: &Self) -> usize {
        usize::from(Arc::ptr_eq(&self.refresh_tokens, &other.refresh_tokens))
            + usize::from(Arc::ptr_eq(&self.tokens_by_user, &other.tokens_by_user))
            + usize::from(Arc::ptr_eq(&self.oob_codes, &other.oob_codes))
            + usize::from(Arc::ptr_eq(
                &self.verification_codes,
                &other.verification_codes,
            ))
            + usize::from(Arc::ptr_eq(
                &self.pending_sign_in_owners,
                &other.pending_sign_in_owners,
            ))
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
                && !self.config.allow_duplicate_emails
                && self.email_owned_by_other(email, None)
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
        self.next_sequence += 1;
        let sequence = self.next_sequence;
        slot.insert(Arc::new(UserRecord {
            local_id: local_id.clone(),
            email: new.email,
            email_verified: new.email_verified,
            display_name: None,
            photo_url: None,
            phone_number: None,
            sequence,
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
            self.add_email_owner(email, &local_id);
        }
        self.by_sequence.insert(sequence, local_id.clone());
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
        Arc::make_mut(&mut self.oob_codes).insert(
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
            Arc::make_mut(&mut self.oob_codes).remove(code);
            return Err(AuthError::InvalidOobCode);
        }
        Arc::make_mut(&mut self.oob_codes)
            .remove(code)
            .ok_or(AuthError::InvalidOobCode)
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
        Arc::make_mut(&mut self.verification_codes).insert(session_info, entry.clone());
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
        Arc::make_mut(&mut self.verification_codes).remove(session_info);
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
        self.local_ids_for_federated
            .get(&(provider_id.to_owned(), raw_id.to_owned()))
            .and_then(|owners| owners.first())
            .and_then(|uid| self.users.get(uid))
            .map(Arc::as_ref)
    }

    /// Every identity linked at `provider_id`, in account-creation order: the accounts the identity-provider
    /// login widget offers for reuse (`listProviderInfosByProviderId`).
    #[must_use]
    pub fn provider_infos(&self, provider_id: &str) -> Vec<FederatedIdentity> {
        self.by_sequence
            .values()
            .filter_map(|id| self.users.get(id).map(Arc::as_ref))
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
        let previous = self
            .users
            .get(uid)
            .ok_or(AuthError::UserNotFound)?
            .federated
            .iter()
            .find(|existing| existing.provider_id == identity.provider_id)
            .map(|existing| (existing.provider_id.clone(), existing.raw_id.clone()));
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
        user.federated
            .retain(|f| f.provider_id != identity.provider_id);
        let identity_key = (identity.provider_id.clone(), identity.raw_id.clone());
        user.federated.push(identity);
        if let Some(previous) = previous {
            Self::remove_index_owner(&mut self.local_ids_for_federated, &previous, uid);
        }
        self.local_ids_for_federated
            .entry(identity_key)
            .or_default()
            .insert(uid.clone());
        self.activate_email_owner(uid);
        Ok(())
    }

    /// Unlinks the identity at `provider_id`; `true` when one was linked.
    pub fn unlink_federated(
        &mut self,
        uid: &LocalId,
        provider_id: &str,
    ) -> Result<bool, AuthError> {
        let removed: Vec<(String, String)> = self
            .users
            .get(uid)
            .ok_or(AuthError::UserNotFound)?
            .federated
            .iter()
            .filter(|identity| identity.provider_id == provider_id)
            .map(|identity| (identity.provider_id.clone(), identity.raw_id.clone()))
            .collect();
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
        let before = user.federated.len();
        user.federated.retain(|f| f.provider_id != provider_id);
        let changed = user.federated.len() != before;
        for identity in &removed {
            Self::remove_index_owner(&mut self.local_ids_for_federated, identity, uid);
        }
        self.activate_email_owner(uid);
        Ok(changed)
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
                        let old_phone = self
                            .users
                            .get(&uid)
                            .and_then(|user| user.phone_number.clone());
                        let old_identities: Vec<(String, String)> = self
                            .users
                            .get(&uid)
                            .map(|user| {
                                user.federated
                                    .iter()
                                    .map(|identity| {
                                        (identity.provider_id.clone(), identity.raw_id.clone())
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        if let Some(user) = self.users.get_mut(&uid).map(Arc::make_mut) {
                            user.password = None;
                            user.phone_number = None;
                            user.federated.clear();
                            user.tokens_valid_after = Self::whole_second(now);
                        }
                        if let Some(phone) = old_phone {
                            Self::remove_index_owner(&mut self.local_ids_for_phone, &phone, &uid);
                        }
                        for identity in &old_identities {
                            Self::remove_index_owner(
                                &mut self.local_ids_for_federated,
                                identity,
                                &uid,
                            );
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
            self.activate_email_owner(uid);
        }
    }

    /// Sets the account's email-verified flag.
    fn set_email_verified_flag(&mut self, uid: &LocalId, verified: bool) {
        if let Some(u) = self.users.get_mut(uid).map(Arc::make_mut) {
            u.email_verified = verified;
            self.activate_email_owner(uid);
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
        self.activate_email_owner(uid);
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
        self.activate_email_owner(uid);
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
        let changed = user.mfa.factor_count() != before;
        if changed {
            self.activate_email_owner(uid);
        }
        Ok(changed)
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
        Arc::make_mut(&mut self.pending_sign_in_owners).remove(&pending.0);
        if user.mfa.pending_count() == 0 {
            self.pending_user_ids.remove(uid);
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
        self.activate_email_owner(uid);
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
        self.remove_refresh_tokens_for(uid);
    }

    fn remove_refresh_tokens_for(&mut self, uid: &LocalId) {
        let Some(tokens) = Arc::make_mut(&mut self.tokens_by_user).remove(uid) else {
            return;
        };
        let sessions = Arc::make_mut(&mut self.refresh_tokens);
        for token in tokens {
            sessions.remove(&token);
        }
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
        self.activate_email_owner(uid);
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
        let changed = user.password.take().is_some();
        self.activate_email_owner(uid);
        Ok(changed)
    }

    /// Removes the email address and its verified flag (`deleteAttribute: EMAIL`).
    pub fn clear_email(&mut self, uid: &LocalId) -> Result<(), AuthError> {
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
        let email = user.email.take();
        user.email_verified = false;
        if let Some(email) = email {
            self.remove_email_owner(&email, uid);
        }
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
        self.activate_email_owner(&uid);
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
        let token = self.next_refresh_token();
        Arc::make_mut(&mut self.refresh_tokens).insert(
            token.clone(),
            RefreshSession {
                uid: uid.clone(),
                issued_at: now,
                provider,
                claims,
                second_factor,
            },
        );
        Arc::make_mut(&mut self.tokens_by_user)
            .entry(uid.clone())
            .or_default()
            .insert(token.clone());
        Ok(token)
    }

    /// Replaces one provisional refresh session with its post-policy session atomically.
    ///
    /// Blocking Auth evaluates policy before a sign-in response is committed. The replayed
    /// authentication may already have issued a session, so that exact credential must be
    /// retired when the policy-adjusted token is created.
    pub fn replace_refresh_session(
        &mut self,
        provisional_token: &str,
        uid: &LocalId,
        now: LogicalInstant,
        provider: Option<Provider>,
        claims: CustomClaims,
        second_factor: Option<SecondFactorAssertion>,
    ) -> Result<String, AuthError> {
        let belongs_to_user = self
            .refresh_tokens
            .get(provisional_token)
            .is_some_and(|session| session.uid == *uid);
        if !belongs_to_user {
            return Err(AuthError::InvalidRefreshToken);
        }
        let committed = self.issue_refresh_session(uid, now, provider, claims, second_factor)?;
        Arc::make_mut(&mut self.refresh_tokens).remove(provisional_token);
        let owners = Arc::make_mut(&mut self.tokens_by_user);
        if let Some(tokens) = owners.get_mut(uid) {
            tokens.remove(provisional_token);
            if tokens.is_empty() {
                owners.remove(uid);
            }
        }
        Ok(committed)
    }

    /// The session behind a refresh token (validated like [`Self::redeem_refresh_token`]).
    pub fn refresh_session(&self, token: &str) -> Result<&RefreshSession, AuthError> {
        self.validate_refresh_token(token, true)?;
        self.refresh_tokens
            .get(token)
            .ok_or(AuthError::InvalidRefreshToken)
    }

    /// The session behind a refresh token when the compatibility profile treats refresh
    /// tokens as stateless credentials. The user must still exist and be enabled, but an
    /// account-level `validSince` change does not revoke the credential.
    pub fn stateless_refresh_session(&self, token: &str) -> Result<&RefreshSession, AuthError> {
        self.validate_refresh_token(token, false)?;
        self.refresh_tokens
            .get(token)
            .ok_or(AuthError::InvalidRefreshToken)
    }

    /// Whether this project issued a refresh token. Routing uses ownership without treating
    /// revocation or disablement as absence; the selected project returns the precise error.
    #[must_use]
    pub fn owns_refresh_token(&self, token: &str) -> bool {
        self.refresh_tokens.contains_key(token)
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
        self.validate_refresh_token(token, true)
    }

    fn validate_refresh_token(
        &self,
        token: &str,
        enforce_revocation: bool,
    ) -> Result<LocalId, AuthError> {
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
        if enforce_revocation && session.issued_at < user.tokens_valid_after {
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
        self.activate_email_owner(uid);
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
        self.activate_email_owner(uid);
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
        self.pending_user_ids.insert(uid.clone());
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
            if user.mfa.pending_count() == 0 {
                self.pending_user_ids.remove(uid);
            }
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
        if user.mfa.pending_count() == 0 {
            self.pending_user_ids.remove(uid);
        }
        let factor = TotpFactor {
            mfa_enrollment_id: enrollment_id.clone(),
            display_name: None,
            secret: pending.secret,
            enrolled_at: now,
            last_accepted_step: Some(step),
        };
        user.mfa.totp_factors_mut().push(factor);
        self.activate_email_owner(uid);
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
        self.start_mfa_sign_in_with_context(uid, now, PendingSignInContext::default())
    }

    /// Starts the second-factor step while retaining the first-factor provenance needed by
    /// token issuance and Blocking Auth after verification.
    pub fn start_mfa_sign_in_with_context(
        &mut self,
        uid: &LocalId,
        now: LogicalInstant,
        context: PendingSignInContext,
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
        user.mfa.pending_sign_ins_mut().insert(
            pending_id.clone(),
            PendingSignIn {
                started_at: now,
                context,
            },
        );
        Arc::make_mut(&mut self.pending_sign_in_owners).insert(pending_id.clone(), uid.clone());
        self.pending_user_ids.insert(uid.clone());
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

    /// First-factor provenance owned by a live pending credential.
    #[must_use]
    pub fn pending_sign_in_context(
        &self,
        pending: &PendingSignInId,
    ) -> Option<&PendingSignInContext> {
        let owner = self.pending_sign_in_owners.get(&pending.0)?;
        self.users
            .get(owner)?
            .mfa
            .pending_sign_in(&pending.0)
            .map(|pending| &pending.context)
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
        Arc::make_mut(&mut self.pending_sign_in_owners).remove(&pending.0);
        if user.mfa.pending_count() == 0 {
            self.pending_user_ids.remove(uid);
        }
        let mut replayed = false;
        let mut accepted_identifier = None;
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
                    accepted_identifier = Some(factor.mfa_enrollment_id.clone());
                    break;
                }
                CodeMatch::Replayed => replayed = true,
                CodeMatch::NoMatch => {}
            }
        }
        if let Some(second_factor_identifier) = accepted_identifier {
            self.activate_email_owner(uid);
            return Ok(SecondFactorAssertion {
                sign_in_second_factor: "totp".to_owned(),
                second_factor_identifier,
                verified_at: now,
            });
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
                sign_in_attributes: None,
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
        user.tokens_valid_after = user.tokens_valid_after.max(Self::whole_second(now));
        self.activate_email_owner(uid);
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

/// A default snapshot of an Auth store: everything the store owns except TOTP secret material
/// and raw identity-provider credentials. Enrolled TOTP factors are kept with a detached secret,
/// pending TOTP enrollments are not kept, and pending MFA sign-ins retain only non-secret
/// provenance. The captured part therefore holds no raw credential material (`INV-AUTH-003`,
/// ADR-034). On restore each factor is rebound to the secret the live store still holds for the
/// same enrollment; a factor whose secret is gone is dropped and counted in the
/// [`RestoreReport`], never restored as an unusable factor and never claimed faithful.
#[derive(Debug, Clone)]
pub struct AuthSnapshot(AuthStore);

impl AuthSnapshot {
    /// Copies `store` without TOTP secret material or raw identity-provider credentials.
    ///
    /// Copy-on-write per user (`SNAP-MEM-03`): cloning the store bumps each user's `Arc`
    /// refcount rather than deep-copying it, so a user with no TOTP secret or raw credential --
    /// the common case -- is shared by reference with the live store. Only a user that actually
    /// holds either sensitive value is cloned through [`Arc::make_mut`] and detached, so the
    /// snapshot still carries no raw credential material (`INV-AUTH-003`, ADR-034) while every
    /// unchanged user stays shared.
    #[must_use]
    pub fn capture(store: &AuthStore) -> Self {
        let mut copy = store.clone();
        for user in copy.users.values_mut() {
            if user.mfa.holds_no_totp_secret() && user.mfa.holds_no_inbound_credentials() {
                continue;
            }
            let mfa = &mut Arc::make_mut(user).mfa;
            mfa.detach_totp_secrets();
            mfa.detach_inbound_credentials();
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
        let namespace_matches =
            restored.project_id == live.project_id && restored.tenant_id == live.tenant_id;
        if !namespace_matches {
            restored.refresh_tokens = Arc::new(BTreeMap::new());
            restored.tokens_by_user = Arc::new(BTreeMap::new());
        }
        live.project_id.clone_into(&mut restored.project_id);
        live.tenant_id.clone_into(&mut restored.tenant_id);
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

enum TenantPublication {
    Published(SharedAuthStore),
    Existing {
        store: SharedAuthStore,
        unpublished_metadata: TenantMetadata,
    },
    Unavailable,
}

/// Maximum compatibility-routed Auth project namespaces retained by one daemon.
pub const MAX_ROUTED_AUTH_PROJECTS: usize = 1_024;

#[derive(Debug, Default)]
struct ProjectStores {
    registered: BTreeMap<String, SharedAuthStore>,
    routed: BTreeMap<String, SharedAuthStore>,
}

/// Result of atomically installing a compatibility-routed project store.
#[derive(Debug, Clone)]
pub enum RoutedStoreInstall {
    /// This request installed the supplied store.
    Installed(SharedAuthStore),
    /// Another request already installed the authoritative routed store.
    Existing(SharedAuthStore),
    /// An explicitly registered session owns the project.
    RegisteredConflict,
    /// The fixed routed-project capacity has been reached.
    Capacity,
    /// The candidate aliases another namespace or carries different namespace metadata.
    InvalidStore,
}

/// Result of resolving a project-less compatibility request from an existing user ID.
#[derive(Debug, Clone)]
pub enum CompatibilityUserStoreMatch {
    /// No default or compatibility-routed namespace contains the user.
    NotFound,
    /// Exactly one namespace contains the user.
    Unique(SharedAuthStore),
    /// More than one namespace contains the user, so selecting one would cross a boundary.
    Ambiguous,
    /// A poisoned store or registry lock prevented a complete decision.
    Unavailable,
}

/// Result of resolving an opaque refresh token to one Auth namespace.
#[derive(Debug, Clone)]
pub enum RefreshTokenStoreMatch {
    /// No namespace owns the token.
    NotFound,
    /// Exactly one namespace owns the token.
    Unique(SharedAuthStore),
    /// More than one namespace owns a legacy or imported token.
    Ambiguous,
    /// A poisoned store or registry lock prevented a complete decision.
    Unavailable,
}

/// The Auth stores of every project a daemon serves: the configured (default) project plus
/// the projects created as sessions through the control API. Tokens name their project in
/// `aud`, so a verifier picks the store by audience.
#[derive(Debug)]
pub struct AuthRegistry {
    default_project: String,
    default: SharedAuthStore,
    scoped_refresh_routing: bool,
    projects: Mutex<ProjectStores>,
    tenants: Mutex<BTreeMap<TenantKey, SharedAuthStore>>,
    tenant_metadata: Mutex<BTreeMap<TenantKey, TenantMetadata>>,
    operation_gates: Mutex<BTreeMap<TenantKey, Weak<Mutex<()>>>>,
    membership_generation: AtomicU64,
    next_tenant_id: AtomicU64,
    #[cfg(test)]
    refresh_token_scans: AtomicU64,
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
        let scoped_refresh_routing = default.lock().is_ok_and(|store| {
            store.project_id() == default_project && store.tenant_id().is_none()
        });
        Self {
            default_project: default_project.to_owned(),
            default,
            scoped_refresh_routing,
            projects: Mutex::new(ProjectStores::default()),
            tenants: Mutex::new(BTreeMap::new()),
            tenant_metadata: Mutex::new(BTreeMap::new()),
            operation_gates: Mutex::new(BTreeMap::new()),
            membership_generation: AtomicU64::new(0),
            next_tenant_id: AtomicU64::new(1),
            #[cfg(test)]
            refresh_token_scans: AtomicU64::new(0),
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
        self.projects.lock().ok()?.registered.get(project).cloned()
    }

    /// An existing compatibility-routed store. Explicitly registered projects are not
    /// returned through this method.
    #[must_use]
    pub fn routed_store_for(&self, project: &str) -> Option<Arc<Mutex<AuthStore>>> {
        self.projects.lock().ok()?.routed.get(project).cloned()
    }

    /// Builds an isolated compatibility store without registering it. A rejected request can
    /// use and drop this candidate without growing the registry.
    pub fn routed_candidate(&self, project: &str) -> Option<AuthStore> {
        if !valid_routed_project(project) || project == self.default_project {
            return None;
        }
        let (policy, config, signer) = {
            let default = self.default.lock().ok()?;
            (*default.policy(), default.config(), default.signer_arc())
        };
        let seed = project
            .bytes()
            .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
                hash.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte)
            });
        let mut store = AuthStore::new(project, SplitMix64::new(seed), policy);
        store.set_config(config);
        if let Some(signer) = signer {
            store.set_signer(signer);
        }
        Some(store)
    }

    /// Atomically installs a compatibility store without ever replacing a registered or
    /// already-routed namespace.
    pub fn install_routed(&self, project: &str, store: SharedAuthStore) -> RoutedStoreInstall {
        if project == self.default_project {
            return RoutedStoreInstall::RegisteredConflict;
        }
        let Ok(mut projects) = self.projects.lock() else {
            return RoutedStoreInstall::RegisteredConflict;
        };
        if projects.registered.contains_key(project) {
            return RoutedStoreInstall::RegisteredConflict;
        }
        if let Some(existing) = projects.routed.get(project) {
            return RoutedStoreInstall::Existing(existing.clone());
        }
        if Arc::ptr_eq(&store, &self.default)
            || projects
                .registered
                .values()
                .chain(projects.routed.values())
                .any(|existing| Arc::ptr_eq(existing, &store))
        {
            return RoutedStoreInstall::InvalidStore;
        }
        let Ok(candidate) = store.lock() else {
            return RoutedStoreInstall::InvalidStore;
        };
        if candidate.project_id() != project || candidate.tenant_id().is_some() {
            return RoutedStoreInstall::InvalidStore;
        }
        drop(candidate);
        if projects.routed.len() >= MAX_ROUTED_AUTH_PROJECTS {
            return RoutedStoreInstall::Capacity;
        }
        projects.routed.insert(project.to_owned(), store.clone());
        self.membership_generation.fetch_add(1, Ordering::Release);
        RoutedStoreInstall::Installed(store)
    }

    /// Clears every compatibility namespace owned by the default session.
    pub fn clear_routed(&self) {
        let removed = self.projects.lock().map_or_else(
            |_| Vec::new(),
            |mut projects| {
                let removed = projects.routed.keys().cloned().collect::<Vec<_>>();
                projects.routed.clear();
                removed
            },
        );
        if let Ok(mut gates) = self.operation_gates.lock() {
            gates
                .retain(|(project, _), gate| !removed.contains(project) && gate.strong_count() > 0);
        }
        if !removed.is_empty() {
            self.membership_generation.fetch_add(1, Ordering::Release);
        }
    }

    /// Number of retained compatibility namespaces.
    #[must_use]
    pub fn routed_count(&self) -> usize {
        self.projects
            .lock()
            .map_or(0, |projects| projects.routed.len())
    }

    /// Finds a user in the default and compatibility-routed namespaces only when the match is
    /// unique. Registered sessions and tenants require their explicit routing credentials.
    #[must_use]
    pub fn compatibility_store_for_unique_user(
        &self,
        local_id: &str,
    ) -> CompatibilityUserStoreMatch {
        // Keep membership and every participating store locked until the decision is complete.
        // Store mutations use these same mutexes, so the instant the final lock is acquired is a
        // coherent snapshot. The global order is registry membership, default store, then routed
        // stores in lexical project order.
        let Ok(projects) = self.projects.lock() else {
            return CompatibilityUserStoreMatch::Unavailable;
        };
        let stores = core::iter::once(&self.default)
            .chain(projects.routed.values())
            .cloned()
            .collect::<Vec<_>>();
        for (index, store) in stores.iter().enumerate() {
            if stores[..index]
                .iter()
                .any(|previous| Arc::ptr_eq(previous, store))
            {
                return CompatibilityUserStoreMatch::Unavailable;
            }
        }
        let mut guards = Vec::with_capacity(stores.len());
        for store in &stores {
            let Ok(guard) = store.lock() else {
                return CompatibilityUserStoreMatch::Unavailable;
            };
            guards.push(guard);
        }

        let mut found = None;
        for (index, candidate) in guards.iter().enumerate() {
            if candidate.user_by_id(local_id).is_none() {
                continue;
            }
            if found.is_some() {
                return CompatibilityUserStoreMatch::Ambiguous;
            }
            found = Some(stores[index].clone());
        }
        found.map_or(
            CompatibilityUserStoreMatch::NotFound,
            CompatibilityUserStoreMatch::Unique,
        )
    }

    /// Registers a project's store; `false` when the project already has one.
    pub fn register(&self, project: &str, store: AuthStore) -> bool {
        if project == self.default_project
            || store.project_id() != project
            || store.tenant_id().is_some()
        {
            return false;
        }
        let Ok(mut projects) = self.projects.lock() else {
            return false;
        };
        if projects.registered.contains_key(project) || projects.routed.contains_key(project) {
            return false;
        }
        projects
            .registered
            .insert(project.to_owned(), Arc::new(Mutex::new(store)));
        self.membership_generation.fetch_add(1, Ordering::Release);
        true
    }

    /// Removes a registered project; `false` when it was not registered.
    pub fn remove(&self, project: &str) -> bool {
        let removed = self
            .projects
            .lock()
            .ok()
            .is_some_and(|mut projects| projects.registered.remove(project).is_some());
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
            self.membership_generation.fetch_add(1, Ordering::Release);
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

    fn existing_tenant_with_metadata(&self, key: &TenantKey) -> Option<Arc<Mutex<AuthStore>>> {
        let tenants = self.tenants.lock().ok()?;
        let metadata = self.tenant_metadata.lock().ok()?;
        metadata
            .contains_key(key)
            .then(|| tenants.get(key).cloned())
            .flatten()
    }

    fn build_tenant_store(&self, project: &str, tenant: &str) -> Option<Arc<Mutex<AuthStore>>> {
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
        Some(Arc::new(Mutex::new(store)))
    }

    fn publish_tenant(
        &self,
        key: TenantKey,
        store: Arc<Mutex<AuthStore>>,
        metadata: TenantMetadata,
    ) -> TenantPublication {
        // Tenant authentication reads stores before metadata, so lifecycle writes retain both
        // locks in that same order and never expose a namespace without its final policy.
        let Ok(mut tenants) = self.tenants.lock() else {
            return TenantPublication::Unavailable;
        };
        let Ok(mut tenant_metadata) = self.tenant_metadata.lock() else {
            return TenantPublication::Unavailable;
        };
        if let Some(existing) = tenants.get(&key) {
            return if tenant_metadata.contains_key(&key) {
                TenantPublication::Existing {
                    store: existing.clone(),
                    unpublished_metadata: metadata,
                }
            } else {
                TenantPublication::Unavailable
            };
        }
        tenant_metadata.insert(key.clone(), metadata);
        tenants.insert(key, store.clone());
        self.membership_generation.fetch_add(1, Ordering::Release);
        TenantPublication::Published(store)
    }

    /// Per-namespace gate used while a blocking function runs without the store lock.
    #[must_use]
    pub fn operation_gate(&self, project: &str, tenant: Option<&str>) -> Option<Arc<Mutex<()>>> {
        let key = (project.to_owned(), tenant.unwrap_or_default().to_owned());
        let mut gates = self.operation_gates.lock().ok()?;
        gates.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = gates.get(&key).and_then(Weak::upgrade) {
            return Some(gate);
        }
        let gate = Arc::new(Mutex::new(()));
        gates.insert(key, Arc::downgrade(&gate));
        Some(gate)
    }

    /// Returns a tenant store, creating its isolated namespace on first use.
    pub fn ensure_tenant(&self, project: &str, tenant: &str) -> Option<Arc<Mutex<AuthStore>>> {
        if tenant.is_empty() || tenant.contains(['/', '\\']) {
            return None;
        }
        let key = (project.to_owned(), tenant.to_owned());
        if let Some(store) = self.existing_tenant_with_metadata(&key) {
            return Some(store);
        }
        let store = self.build_tenant_store(project, tenant)?;
        match self.publish_tenant(
            key,
            store,
            TenantMetadata {
                allow_password_signup: true,
                enable_email_link_signin: true,
                enable_anonymous_user: true,
                ..TenantMetadata::default()
            },
        ) {
            TenantPublication::Published(store)
            | TenantPublication::Existing {
                store,
                unpublished_metadata: _,
            } => Some(store),
            TenantPublication::Unavailable => None,
        }
    }

    /// Creates an explicitly configured tenant and returns its generated ID.
    pub fn create_tenant(&self, project: &str, metadata: TenantMetadata) -> Option<String> {
        self.store_for(project)?;
        let mut metadata = metadata;
        loop {
            let sequence = self.next_tenant_id.fetch_add(1, Ordering::Relaxed);
            let tenant = format!("fireemu-{sequence:020}");
            let store = self.build_tenant_store(project, &tenant)?;
            match self.publish_tenant((project.to_owned(), tenant.clone()), store, metadata) {
                TenantPublication::Published(_) => return Some(tenant),
                TenantPublication::Existing {
                    unpublished_metadata,
                    ..
                } => metadata = unpublished_metadata,
                TenantPublication::Unavailable => return None,
            }
        }
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
        let removed = self.tenants.lock().ok().and_then(|mut stores| {
            let mut metadata = self.tenant_metadata.lock().ok()?;
            let removed = stores.remove(&key).is_some();
            metadata.remove(&key);
            Some(removed)
        });
        if let Ok(mut gates) = self.operation_gates.lock() {
            gates.remove(&key);
        }
        if removed == Some(true) {
            self.membership_generation.fetch_add(1, Ordering::Release);
        }
        removed.unwrap_or(false)
    }

    /// The first store (the default first, then the registered ones in name order) that
    /// satisfies `pred`.
    pub fn find(&self, pred: impl Fn(&AuthStore) -> bool) -> Option<Arc<Mutex<AuthStore>>> {
        if self.default.lock().is_ok_and(|s| pred(&s)) {
            return Some(self.default.clone());
        }
        let projects = self.projects.lock().ok()?;
        if let Some(found) = projects
            .registered
            .values()
            .find(|s| s.lock().is_ok_and(|s| pred(&s)))
            .cloned()
        {
            return Some(found);
        }
        if let Some(found) = projects
            .routed
            .values()
            .find(|s| s.lock().is_ok_and(|s| pred(&s)))
            .cloned()
        {
            return Some(found);
        }
        drop(projects);
        self.tenants
            .lock()
            .ok()?
            .values()
            .find(|s| s.lock().is_ok_and(|s| pred(&s)))
            .cloned()
    }

    /// Resolves a refresh token without scanning for tokens issued by this version. The token's
    /// length-delimited namespace prefix selects one store directly; legacy and imported tokens
    /// fall back to a complete ambiguity-detecting scan.
    #[must_use]
    pub fn store_for_refresh_token(&self, token: &str) -> RefreshTokenStoreMatch {
        if self.scoped_refresh_routing {
            if let Some((project, tenant)) = refresh_token_namespace(token) {
                let generation = self.membership_generation.load(Ordering::Acquire);
                let selected = match tenant {
                    Some(tenant) => match self.tenants.lock() {
                        Ok(tenants) => tenants
                            .get(&(project.to_owned(), tenant.to_owned()))
                            .cloned(),
                        Err(_) => return RefreshTokenStoreMatch::Unavailable,
                    },
                    None if project == self.default_project => Some(self.default.clone()),
                    None => match self.projects.lock() {
                        Ok(projects) => projects
                            .registered
                            .get(project)
                            .or_else(|| projects.routed.get(project))
                            .cloned(),
                        Err(_) => return RefreshTokenStoreMatch::Unavailable,
                    },
                };
                if let Some(store) = selected {
                    let owns_token = match store.lock() {
                        Ok(store) => store.owns_refresh_token(token),
                        Err(_) => return RefreshTokenStoreMatch::Unavailable,
                    };
                    if owns_token
                        && generation == self.membership_generation.load(Ordering::Acquire)
                    {
                        return RefreshTokenStoreMatch::Unique(store);
                    }
                }
            }
        }

        self.scan_for_refresh_token(token)
    }

    fn scan_for_refresh_token(&self, token: &str) -> RefreshTokenStoreMatch {
        #[cfg(test)]
        self.refresh_token_scans.fetch_add(1, Ordering::Relaxed);

        for _ in 0..2 {
            let generation = self.membership_generation.load(Ordering::Acquire);
            let Ok(projects) = self.projects.lock() else {
                return RefreshTokenStoreMatch::Unavailable;
            };
            let Ok(tenants) = self.tenants.lock() else {
                return RefreshTokenStoreMatch::Unavailable;
            };
            let stores = core::iter::once(&self.default)
                .chain(projects.registered.values())
                .chain(projects.routed.values())
                .chain(tenants.values())
                .cloned()
                .collect::<Vec<_>>();
            drop(tenants);
            drop(projects);
            for (index, store) in stores.iter().enumerate() {
                if stores[..index]
                    .iter()
                    .any(|previous| Arc::ptr_eq(previous, store))
                {
                    return RefreshTokenStoreMatch::Unavailable;
                }
            }

            let mut guards = Vec::with_capacity(stores.len());
            for store in &stores {
                match store.lock() {
                    Ok(store) => guards.push(store),
                    Err(_) => return RefreshTokenStoreMatch::Unavailable,
                }
            }
            if generation != self.membership_generation.load(Ordering::Acquire) {
                drop(guards);
                continue;
            }
            let mut owner = None;
            for (index, store) in guards.iter().enumerate() {
                if !store.owns_refresh_token(token) {
                    continue;
                }
                if owner.is_some() {
                    return RefreshTokenStoreMatch::Ambiguous;
                }
                owner = Some(stores[index].clone());
            }
            return owner.map_or(
                RefreshTokenStoreMatch::NotFound,
                RefreshTokenStoreMatch::Unique,
            );
        }
        RefreshTokenStoreMatch::Unavailable
    }

    #[cfg(test)]
    fn refresh_token_scan_count(&self) -> u64 {
        self.refresh_token_scans.load(Ordering::Relaxed)
    }

    /// Every project with a store, the default first.
    #[must_use]
    pub fn projects(&self) -> Vec<String> {
        let mut out = vec![self.default_project.clone()];
        if let Ok(projects) = self.projects.lock() {
            out.extend(projects.registered.keys().cloned());
        }
        out
    }
}

fn valid_routed_project(project: &str) -> bool {
    fireemu_core_types::ids::ProjectId::try_new(project.to_owned()).is_ok()
}

fn refresh_token_namespace(token: &str) -> Option<(&str, Option<&str>)> {
    let body = token.strip_prefix("rt1.")?;
    let (project_len, body) = body.split_once('.')?;
    let (tenant_len, body) = body.split_once('.')?;
    let project_len = project_len.parse::<usize>().ok()?;
    let tenant_len = tenant_len.parse::<usize>().ok()?;
    if project_len > 63 || tenant_len > 1_024 {
        return None;
    }
    let namespace_len = project_len.checked_add(tenant_len)?;
    let namespace = body.get(..namespace_len)?;
    let entropy = body.get(namespace_len..)?.strip_prefix('.')?;
    if entropy.is_empty() {
        return None;
    }
    let project = namespace.get(..project_len)?;
    if project.is_empty() {
        return None;
    }
    let tenant = namespace.get(project_len..)?;
    if fireemu_core_types::ids::ProjectId::try_new(project.to_owned()).is_err()
        || tenant.contains(['/', '\\'])
    {
        return None;
    }
    Some((project, (!tenant.is_empty()).then_some(tenant)))
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

    #[test]
    fn a_cross_namespace_restore_drops_refresh_credentials_and_keeps_the_live_namespace() {
        let mut source =
            AuthStore::new("source-project", SplitMix64::new(7), TotpPolicy::default());
        let uid = source
            .create_user(NewUser::email("source@example.test"), AT)
            .unwrap();
        let token = source.issue_refresh_token(&uid, AT).unwrap();
        let snapshot = AuthSnapshot::capture(&source);
        let mut destination = AuthStore::new(
            "destination-project",
            SplitMix64::new(8),
            TotpPolicy::default(),
        );

        snapshot.restore_into(&mut destination);

        assert_eq!(destination.project_id(), "destination-project");
        assert!(matches!(
            destination.redeem_refresh_token(&token),
            Err(super::AuthError::InvalidRefreshToken)
        ));
    }
}

#[cfg(test)]
mod index_invariant_tests {
    use super::{AuthStore, FederatedIdentity, LocalId, NewUser, ProjectAuthConfig};
    use crate::mfa::TotpPolicy;
    use fireemu_core_types::determinism::SplitMix64;
    use fireemu_core_types::time::LogicalInstant;
    use proptest::prelude::*;
    use std::collections::{BTreeMap, BTreeSet};

    const NOW: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

    fn assert_indexes(store: &AuthStore, active_emails: &BTreeMap<String, LocalId>) {
        let mut emails: BTreeMap<String, BTreeSet<LocalId>> = BTreeMap::new();
        let mut phones: BTreeMap<String, BTreeSet<LocalId>> = BTreeMap::new();
        let mut federated: BTreeMap<(String, String), BTreeSet<LocalId>> = BTreeMap::new();
        let mut sequences = BTreeMap::new();
        for (uid, user) in &store.users {
            assert_eq!(uid, &user.local_id);
            if let Some(email) = &user.email {
                emails.entry(email.clone()).or_default().insert(uid.clone());
            }
            if let Some(phone) = &user.phone_number {
                phones.entry(phone.clone()).or_default().insert(uid.clone());
            }
            for identity in &user.federated {
                federated
                    .entry((identity.provider_id.clone(), identity.raw_id.clone()))
                    .or_default()
                    .insert(uid.clone());
            }
            sequences.insert(user.sequence, uid.clone());
        }
        assert_eq!(store.local_ids_for_email, emails);
        assert_eq!(store.local_ids_for_phone, phones);
        assert_eq!(store.local_ids_for_federated, federated);
        assert_eq!(store.by_sequence, sequences);
        assert_eq!(&store.local_id_for_email, active_emails);
        assert!(active_emails.iter().all(|(email, active)| emails
            .get(email)
            .is_some_and(|owners| owners.contains(active))));
    }

    proptest! {
        #[test]
        fn indexes_equal_scans_after_random_mutations(
            allow_duplicate_emails in any::<bool>(),
            operations in prop::collection::vec((0_u8..8, 0_u8..18, 0_u8..16), 1..200)
        ) {
            let mut store = AuthStore::new("demo-app", SplitMix64::new(17), TotpPolicy::default());
            let mut active_emails = BTreeMap::new();
            let mut duplicate_owners = Vec::new();
            store.set_config(ProjectAuthConfig {
                allow_duplicate_emails,
                ..ProjectAuthConfig::default()
            });
            if allow_duplicate_emails {
                for raw_id in ["duplicate-owner-a", "duplicate-owner-b"] {
                    let result = store.sign_in_with_idp(
                        FederatedIdentity {
                            provider_id: "example.test".to_owned(),
                            raw_id: raw_id.to_owned(),
                            email: Some("shared@example.com".to_owned()),
                            display_name: None,
                            photo_url: None,
                        },
                        true,
                        NOW,
                    ).unwrap();
                    let super::IdpSignIn::SignedIn { uid, .. } = result else {
                        unreachable!("new IdP fixture completes sign-in")
                    };
                    duplicate_owners.push(uid);
                }
                active_emails.insert(
                    "shared@example.com".to_owned(),
                    duplicate_owners[1].clone(),
                );
                assert_eq!(store.local_ids_for_email["shared@example.com"].len(), 2);
                assert_indexes(&store, &active_emails);
            }
            for (kind, user_slot, value_slot) in operations {
                let key = match user_slot {
                    16 | 17 if allow_duplicate_emails => {
                        duplicate_owners[usize::from(user_slot - 16)].clone()
                    }
                    _ => LocalId(format!("user-{user_slot}")),
                };
                let uid = key.as_str().to_owned();
                let old_email = store.users.get(&key).and_then(|user| user.email.clone());
                let succeeded = match kind {
                    0 => {
                        store.create_user_with_id(
                            NewUser::email(&format!("email-{user_slot}@example.com")),
                            Some(&uid),
                            NOW,
                        ).is_ok()
                    }
                    1 => {
                        store.set_email(&key, &format!("email-{value_slot}@example.com")).is_ok()
                    }
                    2 => {
                        store.clear_email(&key).is_ok()
                    }
                    3 => {
                        store.set_phone_number(
                            &key,
                            Some(&format!("+1555000{value_slot:04}")),
                        ).is_ok()
                    }
                    4 => {
                        store.set_phone_number(&key, None).is_ok()
                    }
                    5 => {
                        store.link_federated(
                            &key,
                            FederatedIdentity {
                                provider_id: format!("provider-{}.test", value_slot % 3),
                                raw_id: format!("subject-{value_slot}"),
                                email: None,
                                display_name: None,
                                photo_url: None,
                            },
                        ).is_ok()
                    }
                    6 => {
                        let existed = store.users.contains_key(&key);
                        store.record_sign_in(&key, NOW);
                        existed
                    }
                    _ => store.delete_user_by_id(&uid).is_ok(),
                };
                if succeeded {
                    match kind {
                        0 | 1 => {
                            if let Some(old_email) = old_email {
                                active_emails.remove(&old_email);
                            }
                            if let Some(email) = store.users.get(&key).and_then(|u| u.email.clone()) {
                                active_emails.insert(email, key.clone());
                            }
                        }
                        2 | 7 => {
                            if let Some(old_email) = old_email {
                                active_emails.remove(&old_email);
                            }
                        }
                        _ => {
                            if let Some(email) = store.users.get(&key).and_then(|u| u.email.clone()) {
                                active_emails.insert(email, key.clone());
                            }
                        }
                    }
                }
                assert_indexes(&store, &active_emails);
            }
        }
    }
}

#[cfg(test)]
mod compatibility_routing_tests {
    use super::{
        AuthRegistry, AuthStore, CompatibilityUserStoreMatch, NewUser, RefreshTokenStoreMatch,
        RoutedStoreInstall, TenantMetadata,
    };
    use crate::mfa::TotpPolicy;
    use fireemu_core_types::determinism::SplitMix64;
    use fireemu_core_types::time::LogicalInstant;
    use std::sync::{mpsc, Arc, Mutex, TryLockError};
    use std::time::{Duration, Instant};

    const NOW: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

    fn store(project: &str, seed: u64) -> Arc<Mutex<AuthStore>> {
        Arc::new(Mutex::new(AuthStore::new(
            project,
            SplitMix64::new(seed),
            TotpPolicy::default(),
        )))
    }

    #[test]
    fn unique_user_lookup_is_a_coherent_snapshot_during_cross_project_moves() {
        let default = store("demo-app", 1);
        let alpha = store("worker-alpha", 2);
        let beta = store("worker-beta", 3);
        let registry = Arc::new(AuthRegistry::new("demo-app", default));
        assert!(matches!(
            registry.install_routed("worker-alpha", alpha.clone()),
            RoutedStoreInstall::Installed(_)
        ));
        assert!(matches!(
            registry.install_routed("worker-beta", beta.clone()),
            RoutedStoreInstall::Installed(_)
        ));
        beta.lock()
            .unwrap()
            .create_user_with_id(NewUser::email("beta@example.test"), Some("shared-uid"), NOW)
            .unwrap();

        let mut beta_guard = beta.lock().unwrap();
        let lookup_registry = registry.clone();
        let lookup = std::thread::spawn(move || {
            lookup_registry.compatibility_store_for_unique_user("shared-uid")
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match registry.projects.try_lock() {
                Err(TryLockError::WouldBlock) => break,
                Err(TryLockError::Poisoned(_)) => panic!("project registry was poisoned"),
                Ok(guard) => drop(guard),
            }
            assert!(
                Instant::now() < deadline,
                "lookup did not reach the blocked routed store"
            );
            std::thread::yield_now();
        }
        loop {
            match alpha.try_lock() {
                Err(TryLockError::WouldBlock) => break,
                Err(TryLockError::Poisoned(_)) => panic!("alpha store was poisoned"),
                Ok(guard) => drop(guard),
            }
            assert!(
                Instant::now() < deadline,
                "lookup did not retain the earlier routed-store lock"
            );
            std::thread::yield_now();
        }

        let (created_tx, created_rx) = mpsc::sync_channel(1);
        let creator_store = alpha.clone();
        let creator = std::thread::spawn(move || {
            creator_store
                .lock()
                .unwrap()
                .create_user_with_id(
                    NewUser::email("alpha@example.test"),
                    Some("shared-uid"),
                    NOW,
                )
                .unwrap();
            created_tx.send(()).unwrap();
        });
        let created_before_snapshot = created_rx.recv_timeout(Duration::from_millis(100)).is_ok();
        if created_before_snapshot {
            beta_guard.delete_user_by_id("shared-uid").unwrap();
        }
        drop(beta_guard);

        let selected = lookup.join().unwrap();
        creator.join().unwrap();
        assert!(
            !created_before_snapshot,
            "a user mutation interleaved with a cross-project lookup"
        );
        assert!(matches!(
            selected,
            CompatibilityUserStoreMatch::Unique(store) if Arc::ptr_eq(&store, &beta)
        ));
    }

    #[test]
    fn routed_store_installation_rejects_mutex_aliases_before_lookup() {
        let default = store("demo-app", 1);
        let cloned_default = Arc::new(Mutex::new(default.lock().unwrap().clone()));
        let registry = Arc::new(AuthRegistry::new("demo-app", default.clone()));
        assert!(matches!(
            registry.install_routed("worker-default-alias", default),
            RoutedStoreInstall::InvalidStore
        ));
        assert!(matches!(
            registry.install_routed("demo-app", cloned_default),
            RoutedStoreInstall::RegisteredConflict
        ));

        let shared = store("worker-alpha", 2);
        assert!(matches!(
            registry.install_routed("worker-alpha", shared.clone()),
            RoutedStoreInstall::Installed(_)
        ));
        assert!(matches!(
            registry.install_routed("worker-beta", shared),
            RoutedStoreInstall::InvalidStore
        ));
        assert!(matches!(
            registry.install_routed("worker-gamma", store("different-project", 3)),
            RoutedStoreInstall::InvalidStore
        ));

        let lookup_registry = registry.clone();
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            result_tx
                .send(lookup_registry.compatibility_store_for_unique_user("missing"))
                .unwrap();
        });
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            CompatibilityUserStoreMatch::NotFound
        ));
    }

    #[test]
    fn restrictive_tenant_creation_never_publishes_a_store_before_its_policy() {
        let registry = Arc::new(AuthRegistry::new("demo-app", store("demo-app", 1)));
        let metadata_guard = registry.tenant_metadata.lock().unwrap();
        let creator_registry = registry.clone();
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let creator = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            creator_registry.create_tenant(
                "demo-app",
                TenantMetadata {
                    allow_password_signup: false,
                    enable_email_link_signin: false,
                    enable_anonymous_user: false,
                    disable_auth: true,
                    ..TenantMetadata::default()
                },
            )
        });
        started_rx.recv().unwrap();

        let key = (
            "demo-app".to_owned(),
            "fireemu-00000000000000000001".to_owned(),
        );
        let deadline = Instant::now() + Duration::from_millis(250);
        let mut reached_publication = false;
        let published_without_policy = loop {
            match registry.tenants.try_lock() {
                Ok(stores) if stores.contains_key(&key) => {
                    reached_publication = true;
                    break true;
                }
                Ok(stores) => drop(stores),
                Err(TryLockError::WouldBlock) => reached_publication = true,
                Err(TryLockError::Poisoned(_)) => panic!("tenant registry was poisoned"),
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::yield_now();
        };

        drop(metadata_guard);
        let tenant = creator.join().unwrap().unwrap();
        assert_eq!(tenant, key.1);
        assert!(
            reached_publication,
            "the creator did not reach the tenant publication boundary"
        );
        assert!(
            !published_without_policy,
            "the tenant store became observable before restrictive metadata was installed"
        );
        assert_eq!(
            registry.tenant_metadata("demo-app", &tenant),
            Some(TenantMetadata {
                allow_password_signup: false,
                enable_email_link_signin: false,
                enable_anonymous_user: false,
                disable_auth: true,
                ..TenantMetadata::default()
            })
        );
    }

    #[test]
    fn an_existing_tenant_without_metadata_fails_closed() {
        let registry = AuthRegistry::new("demo-app", store("demo-app", 1));
        registry.ensure_tenant("demo-app", "customer").unwrap();
        registry
            .tenant_metadata
            .lock()
            .unwrap()
            .remove(&("demo-app".to_owned(), "customer".to_owned()));

        assert!(registry.ensure_tenant("demo-app", "customer").is_none());
    }

    #[test]
    fn poisoned_tenant_metadata_never_leaves_a_published_store() {
        let registry = Arc::new(AuthRegistry::new("demo-app", store("demo-app", 1)));
        let poison = registry.clone();
        assert!(std::thread::spawn(move || {
            let _guard = poison.tenant_metadata.lock().unwrap();
            panic!("poison tenant metadata");
        })
        .join()
        .is_err());

        assert!(registry
            .create_tenant("demo-app", TenantMetadata::default())
            .is_none());
        assert!(registry
            .tenant_store("demo-app", "fireemu-00000000000000000001")
            .is_none());
    }

    #[test]
    fn scoped_refresh_token_routing_selects_one_namespace_without_a_scan() {
        let default = store("demo-app", 1);
        let registry = AuthRegistry::new("demo-app", default);
        assert!(registry.register(
            "worker-alpha",
            AuthStore::new("worker-alpha", SplitMix64::new(2), TotpPolicy::default(),)
        ));
        let registered = registry.store_for("worker-alpha").unwrap();
        let token = {
            let mut worker = registered.lock().unwrap();
            let uid = worker
                .create_user(NewUser::email("worker@example.test"), NOW)
                .unwrap();
            worker.issue_refresh_token(&uid, NOW).unwrap()
        };

        assert!(matches!(
            registry.store_for_refresh_token(&token),
            RefreshTokenStoreMatch::Unique(store) if Arc::ptr_eq(&store, &registered)
        ));
        assert_eq!(registry.refresh_token_scan_count(), 0);

        assert!(registry.remove("worker-alpha"));
        assert!(registry.register(
            "worker-alpha",
            AuthStore::new("worker-alpha", SplitMix64::new(3), TotpPolicy::default())
        ));
        assert!(matches!(
            registry.store_for_refresh_token(&token),
            RefreshTokenStoreMatch::NotFound
        ));
        assert_eq!(registry.refresh_token_scan_count(), 1);
    }

    #[test]
    fn scoped_refresh_token_routing_revalidates_a_revoked_token() {
        let default = store("demo-app", 1);
        let registry = AuthRegistry::new("demo-app", default.clone());
        let (uid, token) = {
            let mut store = default.lock().unwrap();
            let uid = store
                .create_user(NewUser::email("default@example.test"), NOW)
                .unwrap();
            let token = store.issue_refresh_token(&uid, NOW).unwrap();
            (uid, token)
        };

        assert!(matches!(
            registry.store_for_refresh_token(&token),
            RefreshTokenStoreMatch::Unique(_)
        ));
        assert_eq!(registry.refresh_token_scan_count(), 0);

        default.lock().unwrap().revoke_refresh_tokens(&uid);
        assert!(matches!(
            registry.store_for_refresh_token(&token),
            RefreshTokenStoreMatch::NotFound
        ));
        assert_eq!(
            registry.refresh_token_scan_count(),
            1,
            "a revoked scoped token must fall back to an authoritative scan"
        );
    }

    #[test]
    fn generated_refresh_tokens_are_scoped_even_with_identical_rng_state() {
        let mut alpha = AuthStore::new("worker-alpha", SplitMix64::new(7), TotpPolicy::default());
        let mut beta = AuthStore::new("worker-beta", SplitMix64::new(7), TotpPolicy::default());
        let alpha_uid = alpha
            .create_user_with_id(NewUser::email("alpha@example.test"), Some("same"), NOW)
            .unwrap();
        let beta_uid = beta
            .create_user_with_id(NewUser::email("beta@example.test"), Some("same"), NOW)
            .unwrap();

        let alpha_token = alpha.issue_refresh_token(&alpha_uid, NOW).unwrap();
        let beta_token = beta.issue_refresh_token(&beta_uid, NOW).unwrap();

        assert_ne!(alpha_token, beta_token);
        assert_eq!(
            super::refresh_token_namespace(&alpha_token),
            Some(("worker-alpha", None))
        );
        assert_eq!(
            super::refresh_token_namespace(&beta_token),
            Some(("worker-beta", None))
        );
    }

    #[test]
    fn duplicate_legacy_refresh_tokens_are_rejected_as_ambiguous() {
        let default = store("demo-app", 1);
        let registry = AuthRegistry::new("demo-app", default.clone());
        assert!(registry.register(
            "worker-alpha",
            AuthStore::new("worker-alpha", SplitMix64::new(2), TotpPolicy::default())
        ));
        let worker = registry.store_for("worker-alpha").unwrap();
        install_legacy_refresh_token(&default, "default@example.test", "rt-legacy");
        install_legacy_refresh_token(&worker, "worker@example.test", "rt-legacy");

        assert!(matches!(
            registry.store_for_refresh_token("rt-legacy"),
            RefreshTokenStoreMatch::Ambiguous
        ));
    }

    #[test]
    fn syntactically_scoped_copies_are_scanned_when_the_default_namespace_is_invalid() {
        let mut original =
            AuthStore::new("worker-alpha", SplitMix64::new(7), TotpPolicy::default());
        let uid = original
            .create_user(NewUser::email("worker@example.test"), NOW)
            .unwrap();
        let token = original.issue_refresh_token(&uid, NOW).unwrap();
        let copy = original.clone();
        let registry = AuthRegistry::new("demo-app", Arc::new(Mutex::new(original)));
        assert!(registry.register("worker-alpha", copy));

        assert!(matches!(
            registry.store_for_refresh_token(&token),
            RefreshTokenStoreMatch::Ambiguous
        ));
        assert_eq!(registry.refresh_token_scan_count(), 1);
    }

    #[test]
    fn registration_rejects_store_namespace_mismatches() {
        let default = store("demo-app", 1);
        let registry = AuthRegistry::new("demo-app", default);
        assert!(!registry.register(
            "worker-beta",
            AuthStore::new("worker-alpha", SplitMix64::new(2), TotpPolicy::default())
        ));
        assert!(!registry.register(
            "worker-alpha",
            AuthStore::new_tenant(
                "worker-alpha",
                "customer",
                SplitMix64::new(3),
                TotpPolicy::default(),
            )
        ));
    }

    #[test]
    fn a_poisoned_operation_gate_registry_never_returns_an_unshared_gate() {
        let registry = Arc::new(AuthRegistry::new("demo-app", store("demo-app", 1)));
        let poison = registry.clone();
        assert!(std::thread::spawn(move || {
            let _guard = poison.operation_gates.lock().unwrap();
            panic!("poison operation gate registry");
        })
        .join()
        .is_err());

        assert!(registry.operation_gate("demo-app", None).is_none());
    }

    #[test]
    fn operation_gates_are_shared_by_namespace_and_prune_inactive_entries() {
        let registry = AuthRegistry::new("demo-app", store("demo-app", 1));
        let default = registry.operation_gate("demo-app", None).unwrap();
        let same_default = registry.operation_gate("demo-app", None).unwrap();
        let tenant = registry
            .operation_gate("demo-app", Some("customer"))
            .unwrap();

        assert!(Arc::ptr_eq(&default, &same_default));
        assert!(!Arc::ptr_eq(&default, &tenant));
        drop(default);
        drop(same_default);
        let worker = registry.operation_gate("worker-alpha", None).unwrap();

        let gates = registry.operation_gates.lock().unwrap();
        assert_eq!(gates.len(), 2);
        assert!(!gates.contains_key(&("demo-app".to_owned(), String::new())));
        assert!(gates.contains_key(&("demo-app".to_owned(), "customer".to_owned())));
        assert!(gates.contains_key(&("worker-alpha".to_owned(), String::new())));
        drop(gates);
        drop(tenant);
        drop(worker);
    }

    #[test]
    fn malformed_scoped_refresh_tokens_never_select_a_namespace() {
        for token in [
            "rt1.0.0..entropy",
            "rt1.184467440737095516160.0.demo-app.entropy",
            "rt1.63.18446744073709551615.demo-app.entropy",
            "rt1.8.0.demo.entropy",
            "rt1.8.0.demo-app.",
            "rt1.8.0.démo-ap.entropy",
            "rt1.8.2.demo-appx/.entropy",
        ] {
            assert_eq!(super::refresh_token_namespace(token), None, "{token}");
        }
    }

    #[test]
    fn routed_and_tenant_refresh_tokens_use_their_exact_namespace() {
        let default = store("demo-app", 1);
        let registry = AuthRegistry::new("demo-app", default);
        let routed = store("worker-alpha", 2);
        assert!(matches!(
            registry.install_routed("worker-alpha", routed.clone()),
            RoutedStoreInstall::Installed(_)
        ));
        let tenant = registry.ensure_tenant("demo-app", "customer").unwrap();
        let routed_token = issue_token(&routed, "routed@example.test");
        let tenant_token = issue_token(&tenant, "tenant@example.test");

        assert!(matches!(
            registry.store_for_refresh_token(&routed_token),
            RefreshTokenStoreMatch::Unique(store) if Arc::ptr_eq(&store, &routed)
        ));
        assert!(matches!(
            registry.store_for_refresh_token(&tenant_token),
            RefreshTokenStoreMatch::Unique(store) if Arc::ptr_eq(&store, &tenant)
        ));
        assert_eq!(registry.refresh_token_scan_count(), 0);

        assert!(registry.delete_tenant("demo-app", "customer"));
        assert!(matches!(
            registry.store_for_refresh_token(&tenant_token),
            RefreshTokenStoreMatch::NotFound
        ));
        registry.clear_routed();
        assert!(matches!(
            registry.store_for_refresh_token(&routed_token),
            RefreshTokenStoreMatch::NotFound
        ));
    }

    #[test]
    fn a_poisoned_project_membership_refuses_scoped_token_routing() {
        let default = store("demo-app", 1);
        let registry = Arc::new(AuthRegistry::new("demo-app", default));
        assert!(registry.register(
            "worker-alpha",
            AuthStore::new("worker-alpha", SplitMix64::new(2), TotpPolicy::default())
        ));
        let worker = registry.store_for("worker-alpha").unwrap();
        let token = issue_token(&worker, "worker@example.test");
        let poison = registry.clone();
        assert!(std::thread::spawn(move || {
            let _guard = poison.projects.lock().unwrap();
            panic!("poison project membership");
        })
        .join()
        .is_err());

        assert!(matches!(
            registry.store_for_refresh_token(&token),
            RefreshTokenStoreMatch::Unavailable
        ));
    }

    fn issue_token(store: &Arc<Mutex<AuthStore>>, email: &str) -> String {
        let mut store = store.lock().unwrap();
        let uid = store.create_user(NewUser::email(email), NOW).unwrap();
        store.issue_refresh_token(&uid, NOW).unwrap()
    }

    fn install_legacy_refresh_token(store: &Arc<Mutex<AuthStore>>, email: &str, legacy: &str) {
        let mut store = store.lock().unwrap();
        let uid = store.create_user(NewUser::email(email), NOW).unwrap();
        let generated = store.issue_refresh_token(&uid, NOW).unwrap();
        let session = Arc::make_mut(&mut store.refresh_tokens)
            .remove(&generated)
            .unwrap();
        Arc::make_mut(&mut store.refresh_tokens).insert(legacy.to_owned(), session);
        let owned = Arc::make_mut(&mut store.tokens_by_user)
            .get_mut(&uid)
            .unwrap();
        owned.remove(&generated);
        owned.insert(legacy.to_owned());
    }
}
