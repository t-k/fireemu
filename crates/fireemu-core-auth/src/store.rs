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
use fireemu_core_types::hash::sha256;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

use crate::claims::{CustomClaims, FirebaseClaims, IdTokenClaims};
use crate::federation::PendingIdpCache;
use crate::mfa::{
    match_code, CodeMatch, EnrolledFactor, MfaError, MfaState, PendingEnrollment, PendingSignIn,
    PendingSignInContext, PhoneFactor, TotpEnrollmentMaterial, TotpFactor, TotpPolicy, TotpSecret,
    MAX_FACTORS_PER_USER,
};

/// Reservations grouped by generated UID, reset generation, and request ticket.
///
/// The request ticket makes reservation ownership one-shot even when a failed commit consumes a
/// reservation before its outer guard is dropped and a later request reuses the same UID and
/// reset generation.
type GeneratedLocalIdReservations = BTreeMap<LocalId, BTreeSet<(u64, u64)>>;
use crate::password_policy::{Operation as PasswordPolicyOperation, PasswordPolicy, ViolationCode};
use crate::signup_quota::{QuotaError, SignupQuota, SignupQuotaConfig, SignupReservation};

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
    /// Provider ID as it appears in `providerUserInfo`, the `createAuthUri` sign-in methods
    /// and the sign-in method Blocking Functions see.
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

    /// Provider ID as it appears in `firebase.sign_in_provider`. An email-link sign-in is a
    /// `password` sign-in for the token: `emailLink` is not one of the values the Rules
    /// reference lists, and it stays the sign-in method rather than the provider.
    #[must_use]
    pub fn sign_in_provider_claim(&self) -> &str {
        match self {
            Self::EmailLink => "password",
            other => other.id(),
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

impl FederatedIdentity {
    /// Refuses a field carrying a NUL or another control character.
    ///
    /// Three writers reach these fields: a `linkProviderUserInfo` request, an
    /// identity-provider assertion and an artifact import row. The check lives here so they
    /// cannot drift, and every store entry point that writes an identity calls it before it
    /// mutates anything. Production's refusal shape for this input is unobserved.
    pub fn validate(&self) -> Result<(), AuthError> {
        for (field, value) in [
            ("providerId", Some(self.provider_id.as_str())),
            ("rawId", Some(self.raw_id.as_str())),
            ("email", self.email.as_deref()),
            ("displayName", self.display_name.as_deref()),
            ("photoUrl", self.photo_url.as_deref()),
        ] {
            if value.is_some_and(|value| value.chars().any(char::is_control)) {
                return Err(AuthError::ControlCharacterInText(field));
            }
        }
        Ok(())
    }
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
// The flags mirror independent fields of the Identity Toolkit account record.
#[allow(clippy::struct_excessive_bools)]
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
    /// Last successful ID token issuance (never advanced by lookup).
    pub last_refresh_at: Option<LogicalInstant>,
    /// Last sign-in.
    pub last_sign_in_at: Option<LogicalInstant>,
    /// Tokens issued before this instant are revoked.
    pub tokens_valid_after: LogicalInstant,
    /// Whether tokens were ever revoked after creation: production reports `validSince` only
    /// then (or once a password is set), so a lookup of a fresh account carries none.
    pub tokens_revoked: bool,
    /// Linked federated identities.
    pub federated: Vec<FederatedIdentity>,
    /// Whether the account was created through the Admin API (create or import). Production
    /// then reports `disabled` and `validSince` in every read of it.
    pub admin_created: bool,
    /// Whether a custom-token sign-in created the account. Production then reports
    /// `customAuth` and `validSince` in every read of it (sandbox recording 2026-09-24).
    pub custom_auth: bool,
    /// `passwordUpdatedAt` of a password credential that was since removed: production keeps
    /// reporting it (sandbox recording 2026-09-23, auth-account/provider).
    pub removed_password_updated_at: Option<LogicalInstant>,
    /// Whether an import recorded `emailVerified` explicitly: production then reports it
    /// even for an account without an address (sandbox recording 2026-09-23).
    pub email_verified_recorded: bool,
    /// Salted password digest (local test hashing, not Firebase's scrypt). `None` for users
    /// without a password credential.
    password: Option<PasswordDigest>,
}

/// Field used by the bounded administrator account query.
///
/// The adapter selects the namespace and validates wire enums before using this API.
/// Missing values sort before present values in ascending order; equal primary keys use
/// local ID as a deterministic tie-breaker. These tie/null rules are local policy, not
/// production-observed ordering. Times use the millisecond precision exposed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserSortField {
    /// Canonical local ID.
    LocalId,
    /// Display name (`NAME`).
    Name,
    /// Account creation time (`CREATED_AT`).
    CreatedAt,
    /// Last successful sign-in time (`LAST_LOGIN_AT`).
    LastLoginAt,
    /// Account email (`USER_EMAIL`).
    Email,
}

/// A validated administrator account lookup predicate.
///
/// Each predicate is an exact match. Emails follow the store's case-insensitive ownership
/// rule; phone numbers and local IDs are case-sensitive. Multiple predicates are combined
/// as a de-duplicated union (an explicitly local policy pending production observation).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum UserQueryExpression {
    /// Account email, canonicalized by the matcher.
    Email(String),
    /// Exact phone number.
    PhoneNumber(String),
    /// Exact local ID.
    UserId(String),
}

impl UserQueryExpression {
    fn matches(&self, user: &UserRecord) -> bool {
        match self {
            Self::Email(email) => user
                .email
                .as_deref()
                .is_some_and(|value| value.to_lowercase() == email.to_lowercase()),
            Self::PhoneNumber(phone) => user.phone_number.as_ref() == Some(phone),
            Self::UserId(id) => user.local_id.as_str() == id.as_str(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum UserSortValue<'a> {
    Text(Option<&'a str>),
    Milliseconds(Option<i128>),
}

impl UserSortField {
    fn value(self, user: &UserRecord) -> UserSortValue<'_> {
        match self {
            Self::LocalId => UserSortValue::Text(Some(user.local_id.as_str())),
            Self::Name => UserSortValue::Text(user.display_name.as_deref()),
            Self::CreatedAt => {
                UserSortValue::Milliseconds(Some(user.created_at.as_nanos() / 1_000_000))
            }
            Self::LastLoginAt => UserSortValue::Milliseconds(
                user.last_sign_in_at.map(|time| time.as_nanos() / 1_000_000),
            ),
            Self::Email => UserSortValue::Text(user.email.as_deref()),
        }
    }
}

/// The digit an ASCII upper-case letter carries on a phone keypad.
fn keypad_digit(letter: char) -> char {
    match letter {
        'A'..='C' => '2',
        'D'..='F' => '3',
        'G'..='I' => '4',
        'J'..='L' => '5',
        'M'..='O' => '6',
        'P'..='S' => '7',
        'T'..='V' => '8',
        _ => '9',
    }
}

/// Whether an address can be stored: it has an `@` and no control or whitespace character
/// (a leading space is `INVALID_EMAIL`, sandbox recording 2026-09-23).
fn storable_email(email: &str) -> bool {
    email.contains('@') && !email.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// A password hash imported in one of production's foreign formats (`accounts:batchCreate`
/// with `hashAlgorithm`). The core has no cryptography of its own, so it keeps the hash
/// opaquely: `spec` is the importing adapter's canonical description of the algorithm and its
/// parameters, and only an [`ImportedHashVerifier`] from that adapter can check a password
/// against it.
#[derive(Clone, PartialEq, Eq)]
pub struct ImportedPasswordHash {
    /// The adapter's canonical algorithm-and-parameters description.
    pub spec: String,
    /// The imported hash bytes.
    pub hash: Vec<u8>,
    /// The imported salt bytes (empty when the format carries none).
    pub salt: Vec<u8>,
}

impl fmt::Debug for ImportedPasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ImportedPasswordHash([redacted])")
    }
}

/// Checks a password against an [`ImportedPasswordHash`].
pub trait ImportedHashVerifier {
    /// Whether `password` matches `imported`; `Err` when the imported parameters cannot be
    /// evaluated at all (production fails the sign-in with an internal error then).
    fn verify(
        &self,
        imported: &ImportedPasswordHash,
        password: &str,
    ) -> Result<bool, ImportedHashFailure>;
}

/// An imported hash whose parameters cannot be evaluated (for example an HMAC without a key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportedHashFailure;

/// The verifier of a caller that imports no foreign hashes: nothing matches.
struct NoImportedHashes;

impl ImportedHashVerifier for NoImportedHashes {
    fn verify(
        &self,
        _imported: &ImportedPasswordHash,
        _password: &str,
    ) -> Result<bool, ImportedHashFailure> {
        Ok(false)
    }
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
    /// When the password was last set through the API (`passwordUpdatedAt`); `None` for an
    /// imported credential whose history the artifact did not carry.
    updated_at: Option<LogicalInstant>,
    /// A foreign hash this credential was imported as, until the first successful sign-in
    /// replaces it with fireemu's own digest.
    imported: Option<ImportedPasswordHash>,
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
            updated_at: None,
            imported: None,
        }
    }

    fn from_imported(imported: ImportedPasswordHash) -> Self {
        Self {
            salt: [0; 16],
            digest: [0; 20],
            emulator: None,
            updated_at: None,
            imported: Some(imported),
        }
    }

    fn verify(&self, password: &str) -> bool {
        self.verify_with(password, &NoImportedHashes)
            .unwrap_or(false)
    }

    fn verify_with(
        &self,
        password: &str,
        verifier: &dyn ImportedHashVerifier,
    ) -> Result<bool, ImportedHashFailure> {
        if let Some(imported) = &self.imported {
            return verifier.verify(imported, password);
        }
        let candidate = Self::new(self.salt, password).digest;
        Ok(candidate
            .iter()
            .zip(self.digest.iter())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0)
    }

    /// The stored hash and salt bytes (fireemu's own digest, or the imported foreign hash).
    #[must_use]
    pub fn stored_material(&self) -> (Vec<u8>, Vec<u8>) {
        self.imported.as_ref().map_or_else(
            || (self.digest.to_vec(), self.salt.to_vec()),
            |imported| (imported.hash.clone(), imported.salt.clone()),
        )
    }

    /// The emulator salt and plaintext an export has to write back, when the credential
    /// The foreign hash an import installed, while no sign-in has replaced it.
    #[must_use]
    pub const fn imported_hash(&self) -> Option<&ImportedPasswordHash> {
        self.imported.as_ref()
    }

    /// came from one.
    #[must_use]
    pub fn emulator_form(&self) -> Option<(&str, &str)> {
        self.emulator
            .as_ref()
            .map(|(salt, password)| (salt.as_str(), password.as_str()))
    }
}

/// The project's sign-in providers (Admin v2 `signIn.email`, `signIn.anonymous` and
/// `signIn.phoneNumber`). fireemu starts with every provider enabled and email-link sign-in
/// allowed, as the emulator does; production starts with none (sandbox recording 2026-09-23).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct SignInConfig {
    /// `signIn.email.enabled`: password and email-link accounts.
    pub email_enabled: bool,
    /// `signIn.email.passwordRequired`: when set, email-link sign-in is off.
    pub password_required: bool,
    /// `signIn.anonymous.enabled`.
    pub anonymous_enabled: bool,
    /// `signIn.phoneNumber.enabled`.
    pub phone_enabled: bool,
    /// `signIn.phoneNumber.testPhoneNumbers`: E.164 number to its fixed six-digit code. No
    /// message is sent for these numbers and the code never changes.
    pub test_phone_numbers: BTreeMap<String, String>,
}

impl Default for SignInConfig {
    fn default() -> Self {
        Self {
            email_enabled: true,
            password_required: false,
            anonymous_enabled: true,
            phone_enabled: true,
            test_phone_numbers: BTreeMap::new(),
        }
    }
}

impl SignInConfig {
    /// Identity Platform documents at most ten test phone numbers per project.
    pub const MAX_TEST_PHONE_NUMBERS: usize = 10;

    /// Whether every test number is valid E.164 with a six-digit code, within the documented
    /// count.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.test_phone_numbers.len() <= Self::MAX_TEST_PHONE_NUMBERS
            && self.test_phone_numbers.iter().all(|(number, code)| {
                AuthStore::validate_phone_number(number).is_ok()
                    && code.len() == 6
                    && code.bytes().all(|b| b.is_ascii_digit())
            })
    }
}

/// The project-level Auth configuration `auth_export/config.json` carries.
///
/// fireemu records it so that an import followed by an export does not lose it. Both switches
/// also affect the matching and error behavior of the emulated Identity Toolkit surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProjectAuthConfig {
    /// `signIn.allowDuplicateEmails`.
    pub allow_duplicate_emails: bool,
    /// `emailPrivacyConfig.enableImprovedEmailPrivacy`.
    pub enable_improved_email_privacy: bool,
    /// Whether end-user account creation is disabled. Admin operations bypass this switch.
    pub disabled_user_signup: bool,
    /// Whether end-user self-deletion is disabled. Admin operations bypass this switch.
    pub disabled_user_deletion: bool,
}

/// Validated partial update to inherited project Auth settings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProjectAuthConfigPatch {
    /// `None` preserves the current duplicate-email setting.
    pub allow_duplicate_emails: Option<bool>,
    /// `None` preserves the current email-privacy setting.
    pub enable_improved_email_privacy: Option<bool>,
    /// `None` preserves the current end-user signup permission.
    pub disabled_user_signup: Option<bool>,
    /// `None` preserves the current end-user deletion permission.
    pub disabled_user_deletion: Option<bool>,
}

/// The trust boundary used by operations affected by client permission settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPrincipal {
    /// A user request carrying an end-user credential.
    EndUser,
    /// An owner or Admin SDK request already authorized by the adapter.
    Admin,
}

impl ProjectAuthConfigPatch {
    /// Whether the patch has no selected values and must perform no writes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.allow_duplicate_emails.is_none()
            && self.enable_improved_email_privacy.is_none()
            && self.disabled_user_signup.is_none()
            && self.disabled_user_deletion.is_none()
    }

    /// Applies validated selected values to the current configuration.
    #[must_use]
    pub fn apply_to(self, mut config: ProjectAuthConfig) -> ProjectAuthConfig {
        if let Some(value) = self.allow_duplicate_emails {
            config.allow_duplicate_emails = value;
        }
        if let Some(value) = self.enable_improved_email_privacy {
            config.enable_improved_email_privacy = value;
        }
        if let Some(value) = self.disabled_user_signup {
            config.disabled_user_signup = value;
        }
        if let Some(value) = self.disabled_user_deletion {
            config.disabled_user_deletion = value;
        }
        config
    }
}

/// The non-password settings represented for one namespace.
///
/// `auth.configOverrides` currently populates the client permission and improved email privacy
/// fields. Tenant management patches can additionally select duplicate-email behavior. Password
/// policy remains a separate setting group, and `None` preserves the current value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthNamespaceConfigPatch {
    /// Whether duplicate email accounts are allowed.
    pub allow_duplicate_emails: Option<bool>,
    /// Whether end-user account creation is disabled.
    pub disabled_user_signup: Option<bool>,
    /// Whether end-user self-deletion is disabled.
    pub disabled_user_deletion: Option<bool>,
    /// Whether improved email privacy is enabled.
    pub enable_improved_email_privacy: Option<bool>,
}

impl AuthNamespaceConfigPatch {
    /// Whether this override selects no values.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.allow_duplicate_emails.is_none()
            && self.disabled_user_signup.is_none()
            && self.disabled_user_deletion.is_none()
            && self.enable_improved_email_privacy.is_none()
    }

    /// Applies the selected values to a project or tenant store configuration.
    #[must_use]
    pub fn apply_to(self, mut config: ProjectAuthConfig) -> ProjectAuthConfig {
        if let Some(value) = self.allow_duplicate_emails {
            config.allow_duplicate_emails = value;
        }
        if let Some(value) = self.disabled_user_signup {
            config.disabled_user_signup = value;
        }
        if let Some(value) = self.disabled_user_deletion {
            config.disabled_user_deletion = value;
        }
        if let Some(value) = self.enable_improved_email_privacy {
            config.enable_improved_email_privacy = value;
        }
        config
    }

    fn apply_to_metadata(self, metadata: &mut TenantMetadata) {
        if let Some(value) = self.disabled_user_signup {
            metadata.disabled_user_signup = value;
        }
        if let Some(value) = self.disabled_user_deletion {
            metadata.disabled_user_deletion = value;
        }
        if let Some(value) = self.enable_improved_email_privacy {
            metadata.enable_improved_email_privacy = value;
        }
    }

    fn merge(self, update: Self) -> Self {
        Self {
            allow_duplicate_emails: update
                .allow_duplicate_emails
                .or(self.allow_duplicate_emails),
            disabled_user_signup: update.disabled_user_signup.or(self.disabled_user_signup),
            disabled_user_deletion: update
                .disabled_user_deletion
                .or(self.disabled_user_deletion),
            enable_improved_email_privacy: update
                .enable_improved_email_privacy
                .or(self.enable_improved_email_privacy),
        }
    }
}

/// The response mode requested from an OAuth/OIDC provider.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OAuthResponseType {
    /// Whether the provider returns an ID token.
    pub id_token: bool,
    /// Whether the provider returns an authorization code.
    pub code: bool,
    /// The deprecated implicit token response mode.
    pub token: bool,
}

/// A project or tenant OAuth/OIDC provider configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct OidcProviderConfig {
    /// Provider configuration ID.
    pub id: String,
    /// Developer supplied display name.
    pub display_name: Option<String>,
    /// Whether sign-in with this provider is enabled.
    pub enabled: bool,
    /// OAuth client ID.
    pub client_id: String,
    /// OIDC issuer URL.
    pub issuer: String,
    /// OAuth client secret, when supplied.
    pub client_secret: Option<String>,
    /// OAuth response mode.
    pub response_type: OAuthResponseType,
}

impl fmt::Debug for OidcProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcProviderConfig")
            .field("id", &self.id)
            .field("display_name", &self.display_name)
            .field("enabled", &self.enabled)
            .field("client_id", &self.client_id)
            .field("issuer", &self.issuer)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("response_type", &self.response_type)
            .finish()
    }
}

/// A project or tenant inbound SAML provider configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSamlProviderConfig {
    /// Provider configuration ID.
    pub id: String,
    /// Developer supplied display name.
    pub display_name: Option<String>,
    /// Whether sign-in with this provider is enabled.
    pub enabled: bool,
    /// SAML identity provider entity ID.
    pub idp_entity_id: String,
    /// SAML identity provider SSO URL.
    pub sso_url: String,
    /// Identity provider certificates used to verify assertions.
    pub idp_certificates: Vec<String>,
    /// Whether outbound SAML requests are signed.
    pub sign_request: bool,
    /// SAML service provider entity ID.
    pub sp_entity_id: String,
    /// SAML assertion callback URI.
    pub callback_uri: String,
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
    /// Last successful token issuance retained by the import artifact.
    pub last_refresh_at: Option<LogicalInstant>,
    /// When the account last signed in.
    pub last_sign_in_at: Option<LogicalInstant>,
    /// Tokens minted before this instant are refused.
    pub tokens_valid_after: LogicalInstant,
    /// Linked federated identities.
    pub federated: Vec<FederatedIdentity>,
    /// The emulator salt and plaintext password, when the account has a password
    /// credential.
    pub password: Option<(String, String)>,
    /// A password hash in one of production's foreign formats, when the account was imported
    /// with one instead of a plaintext password.
    pub imported_password: Option<ImportedPasswordHash>,
    /// Whether the address may already belong to another account: production's batchCreate
    /// does not check it (sandbox recording 2026-09-23); an artifact import still does.
    pub allow_shared_email: bool,
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
    /// Password exceeds the configured UTF-16 length limit.
    PasswordTooLong,
    /// Password meets the API hard limits but violates an enabled custom policy.
    PasswordPolicyViolation(crate::password_policy::PolicyRefusal),
    /// End-user account creation is disabled by the namespace client permissions.
    UserSignupDisabled,
    /// End-user self-deletion is disabled by the namespace client permissions.
    UserDeletionDisabled,
    /// Local sign-up quota rejected an end-user reservation.
    SignupQuotaExceeded,
    /// The local sign-up quota could not make a safe decision.
    SignupQuotaUnavailable,
    /// Unknown email or wrong password, undistinguished (the improved email privacy mode).
    InvalidCredentials,
    /// Wrong password, or no password credential, for a known email (the default mode of
    /// the official emulator, which distinguishes it from an unknown email).
    InvalidPassword,
    /// The user is disabled.
    UserDisabled,
    /// Unknown or removed refresh token.
    InvalidRefreshToken,
    /// Known session issued before the user's revocation threshold.
    ExpiredRefreshToken,
    /// Caller-chosen user ID is malformed.
    InvalidLocalId,
    /// An imported password hash whose parameters cannot be evaluated.
    ImportedHashFailure,
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
    /// A stored text field carries a NUL or another control character. The payload names the
    /// field as the request spells it.
    ControlCharacterInText(&'static str),
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
            Self::PasswordTooLong => f.write_str("password exceeds the maximum length"),
            Self::PasswordPolicyViolation(_) => f.write_str("password does not meet requirements"),
            Self::UserSignupDisabled => f.write_str("user signup is disabled"),
            Self::UserDeletionDisabled => f.write_str("user deletion is disabled"),
            Self::SignupQuotaExceeded => f.write_str("sign-up quota exceeded"),
            Self::SignupQuotaUnavailable => f.write_str("sign-up quota unavailable"),
            Self::InvalidCredentials => f.write_str("invalid email or password"),
            Self::InvalidPassword => f.write_str("invalid password"),
            Self::UserDisabled => f.write_str("user is disabled"),
            Self::InvalidRefreshToken => f.write_str("invalid refresh token"),
            Self::ExpiredRefreshToken => f.write_str("expired refresh token"),
            Self::InvalidLocalId => f.write_str("invalid local id"),
            Self::ImportedHashFailure => f.write_str("imported password hash cannot be verified"),
            Self::LocalIdExists => f.write_str("local id already exists"),
            Self::PhoneNumberExists => f.write_str("phone number already exists"),
            Self::InvalidPhoneNumber => f.write_str("invalid phone number"),
            Self::EmailNotFound => f.write_str("email not found"),
            Self::InvalidOobCode => f.write_str("invalid action code"),
            Self::InvalidSessionInfo => f.write_str("invalid verification session"),
            Self::InvalidVerificationCode => f.write_str("invalid verification code"),
            Self::ControlCharacterInText(field) => {
                write!(f, "{field} must not contain control characters")
            }
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

/// One opaque fireemu control-session incarnation of an Auth namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthLifecycleEpoch([u8; 32]);

impl AuthLifecycleEpoch {
    fn initial(daemon_incarnation: u128, serial: u64) -> Self {
        let mut input = Vec::with_capacity(24 + 32);
        input.extend_from_slice(b"fireemu.auth.lifecycle.v1\0");
        input.extend_from_slice(&daemon_incarnation.to_be_bytes());
        input.extend_from_slice(&serial.to_be_bytes());
        Self(fireemu_core_types::hash::sha256(&input))
    }

    fn next(self) -> Self {
        let mut input = Vec::with_capacity(32 + 32);
        input.extend_from_slice(b"fireemu.auth.lifecycle.next.v1\0");
        input.extend_from_slice(&self.0);
        Self(fireemu_core_types::hash::sha256(&input))
    }

    fn wire_value(self) -> String {
        fireemu_core_types::hash::hex_lower(&self.0)
    }
}

/// Deterministic in-memory auth store for one project.
#[derive(Debug, Clone)]
pub struct AuthStore {
    project_id: String,
    project_number: Option<u64>,
    tenant_id: Option<String>,
    rng: SplitMix64,
    policy: TotpPolicy,
    /// Effective password policy for this project or tenant namespace.
    password_policy: PasswordPolicy,
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
    /// Rejection-only identities of refresh credentials retired by user deletion. No raw
    /// tokens, user IDs or claims. Retained until reset (no TTL or silent eviction); memory
    /// grows with deleted issued credentials and is included in snapshot byte accounting.
    deleted_refresh_digests: Arc<BTreeMap<[u8; 32], [u8; 32]>>,
    /// Refresh-token values owned by each user. Revocation and deletion touch one user's
    /// sessions instead of scanning every live session.
    tokens_by_user: Arc<BTreeMap<LocalId, BTreeSet<String>>>,
    next_id_override: Option<String>,
    next_sequence: u64,
    /// Shared generation invalidated by an Auth clear or restore. Blocking candidates capture
    /// this value before an external callback and must not commit after it changes.
    reset_generation: Arc<AtomicU64>,
    signer: Option<Arc<dyn crate::jwt::IdTokenSigner>>,
    /// Hidden lifecycle material for generated credential and action handles. Unlike
    /// `lifecycle_epoch`, this is never emitted in an ID token.
    credential_epoch: Option<AuthLifecycleEpoch>,
    /// Optional fireemu control-session incarnation. It is absent from ordinary stores so
    /// production-shaped tokens do not gain a local-only claim unless session isolation needs it.
    lifecycle_epoch: Option<AuthLifecycleEpoch>,
    /// Whether this store has issued a legacy Identity Toolkit token. Only then does it honour
    /// one, so a store that never issues them (the emulator profile) refuses a forged one.
    legacy_tokens_issued: bool,
    oob_codes: Arc<BTreeMap<String, OobCode>>,
    verification_codes: Arc<BTreeMap<String, VerificationCode>>,
    /// Outstanding phone `temporaryProof`s: proof to the verified number and its issue time.
    temporary_proofs: BTreeMap<String, (String, LogicalInstant)>,
    /// Which user owns each outstanding pending sign-in (`mfaPendingCredential`), so a
    /// credential is resolved directly rather than by scanning every user
    /// (`AUTH-TRANSIENT-04`). Kept in step with the users' own pending maps.
    pending_sign_in_owners: Arc<BTreeMap<String, LocalId>>,
    /// Process-local raw `IdP` requests; detached from default snapshots and restore.
    pending_idp: PendingIdpCache,
    /// Generated IDs held by in-flight blocking Auth candidates, grouped by reset generation and
    /// request ticket. This registry is shared by snapshots so concurrent candidates avoid each
    /// other's IDs without advancing the live random stream that ordinary nested Admin requests
    /// use.
    generated_local_id_reservations: Arc<Mutex<GeneratedLocalIdReservations>>,
    /// Monotonic request tickets that identify one generated-ID reservation owner.
    generated_local_id_reservation_ticket: Arc<AtomicU64>,
    /// Monotonic count of ordinary generated-ID allocations that skipped an in-flight blocking
    /// reservation. A blocking candidate captures this before its hook runs; a change at commit
    /// means a nested ordinary Admin allocation changed the identity allocation boundary.
    generated_id_interference: Arc<AtomicU64>,
    /// Users that currently own a pending enrollment or sign-in. Credential sweeping only
    /// visits this bounded subset instead of cloning or scanning every account.
    pending_user_ids: BTreeSet<LocalId>,
    created_users: Vec<LocalId>,
    deleted_users: Vec<UserRecord>,
    /// Codes issued since the last drain (see [`CredentialNotice`]).
    credential_notices: Vec<CredentialNotice>,
    /// The project-level Auth configuration an import carried, kept so an export can write
    /// it back.
    config: ProjectAuthConfig,
    /// The project's sign-in providers and test phone numbers.
    sign_in: SignInConfig,
    /// Deterministic, local-only sign-up quota state. Admin/import paths do not use it unless
    /// their caller explicitly requests a reservation through the typed API.
    signup_quota: SignupQuota,
    /// OAuth/OIDC provider configurations in this namespace.
    oidc_configs: BTreeMap<String, OidcProviderConfig>,
    /// OAuth/OIDC configuration IDs in creation order.
    oidc_order: Vec<String>,
    /// Inbound SAML provider configurations in this namespace.
    saml_configs: BTreeMap<String, InboundSamlProviderConfig>,
    /// Inbound SAML configuration IDs in creation order.
    saml_order: Vec<String>,
}

/// What a phone verification code was issued for, as the official emulator names it in
/// its console line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhoneCodeUse {
    /// `accounts:sendVerificationCode` (phone sign-in or linking).
    SignIn,
    /// `mfaEnrollment:start` with a phone factor.
    MfaEnrollment,
    /// `mfaSignIn:start` with a phone factor.
    MfaSignIn,
}

/// A credential the official Auth emulator prints to its console instead of mailing or
/// texting it (`firebase-tools/lib/emulator/auth/operations.js`, the `BULLET` log lines).
/// Recorded by the request that issued the code and drained once by the shell after the
/// request, so each issue is announced exactly once and a refused request announces nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialNotice {
    /// An email action link (`accounts:sendOobCode` without `returnOobLink`).
    EmailAction {
        /// The action.
        request_type: OobRequestType,
        /// The address the mail would have gone to.
        email: String,
        /// The new address of `VERIFY_AND_CHANGE_EMAIL`.
        new_email: Option<String>,
        /// The action link, as the client would follow it.
        link: String,
    },
    /// An SMS code.
    PhoneCode {
        /// The number the SMS would have gone to.
        phone_number: String,
        /// The six-digit code.
        code: String,
        /// Which flow issued it.
        purpose: PhoneCodeUse,
    },
}

impl CredentialNotice {
    /// The official emulator's console line for this credential, verbatim.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::EmailAction {
                request_type,
                email,
                new_email,
                link,
            } => match request_type {
                OobRequestType::EmailSignIn => {
                    format!("To sign in as {email}, follow this link: {link}")
                }
                OobRequestType::PasswordReset => format!(
                    "To reset the password for {email}, follow this link: {link}&newPassword=NEW_PASSWORD_HERE"
                ),
                OobRequestType::VerifyEmail => {
                    format!("To verify the email address {email}, follow this link: {link}")
                }
                OobRequestType::VerifyAndChangeEmail => format!(
                    "To verify and change the email address from {email} to {}, follow this link: {link}",
                    new_email.as_deref().unwrap_or_default()
                ),
            },
            Self::PhoneCode {
                phone_number,
                code,
                purpose,
            } => match purpose {
                PhoneCodeUse::SignIn => {
                    format!("To verify the phone number {phone_number}, use the code {code}.")
                }
                PhoneCodeUse::MfaEnrollment => {
                    format!("To enroll MFA with {phone_number}, use the code {code}.")
                }
                PhoneCodeUse::MfaSignIn => {
                    format!("To sign in with MFA using {phone_number}, use the code {code}.")
                }
            },
        }
    }
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

/// The longest caller-chosen user id production stores, in UTF-16 units: 256 is accepted and
/// 257 is an internal error (sandbox exploration 2026-09-24).
pub const MAX_LOCAL_ID_UTF16_UNITS: usize = 256;

/// Lifetime of a phone `temporaryProof` (`temporaryProofExpiresIn`, sandbox recording
/// 2026-09-23).
pub const TEMPORARY_PROOF_TTL_SECONDS: i64 = 3_600;

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

    fn rekey_generated_values(&mut self, epoch: AuthLifecycleEpoch) {
        let mut seed = [0_u8; 8];
        seed.copy_from_slice(&epoch.0[..8]);
        // Every generated credential and opaque handle draws from this stream. Re-keying it
        // before a lifecycle-enabled namespace is published prevents a deleted/recreated
        // project or tenant from issuing the same refresh token, OOB code, MFA handle, or
        // verification session merely because its configured deterministic seed repeats.
        self.rng = SplitMix64::new(u64::from_be_bytes(seed));
        self.credential_epoch = Some(epoch);
    }

    fn set_lifecycle_epoch(&mut self, epoch: AuthLifecycleEpoch) {
        self.rekey_generated_values(epoch);
        self.lifecycle_epoch = Some(epoch);
    }

    /// Whether this store has issued a legacy Identity Toolkit token.
    #[must_use]
    pub const fn legacy_tokens_issued(&self) -> bool {
        self.legacy_tokens_issued
    }

    /// The claims of a legacy Identity Toolkit token for `uid` issued at `iat`, carrying the
    /// account's address and this store's session epoch when it has them; from now on the store
    /// honours legacy tokens.
    ///
    /// # Errors
    /// [`AuthError::UserNotFound`] for an unknown account.
    pub fn legacy_token_payload(
        &mut self,
        uid: &LocalId,
        iat: i64,
        sign_in_provider: &str,
        developer_claims: Option<&CustomClaims>,
    ) -> Result<String, AuthError> {
        let user = self.users.get(uid).ok_or(AuthError::UserNotFound)?;
        let epoch = self.lifecycle_epoch_claim();
        let payload = crate::jwt::legacy_token_payload(
            &self.project_id,
            iat,
            &crate::jwt::LegacyToken {
                uid: uid.as_str(),
                sign_in_provider,
                email: user
                    .email
                    .as_deref()
                    .map(|email| (email, user.email_verified)),
                extra_claims: developer_claims.map(CustomClaims::entries_map),
                session_epoch: epoch.as_deref(),
            },
        );
        self.legacy_tokens_issued = true;
        Ok(payload)
    }

    /// The private control-session incarnation expected in locally issued ID tokens.
    #[must_use]
    pub(crate) fn lifecycle_epoch_claim(&self) -> Option<String> {
        self.lifecycle_epoch.map(AuthLifecycleEpoch::wire_value)
    }

    /// Creates a store for `project_id`.
    #[must_use]
    pub fn new(project_id: &str, rng: SplitMix64, policy: TotpPolicy) -> Self {
        Self {
            project_id: project_id.to_owned(),
            project_number: None,
            tenant_id: None,
            rng,
            policy,
            password_policy: PasswordPolicy::default(),
            users: BTreeMap::new(),
            local_id_for_email: BTreeMap::new(),
            local_ids_for_email: BTreeMap::new(),
            local_ids_for_phone: BTreeMap::new(),
            local_ids_for_federated: BTreeMap::new(),
            by_sequence: BTreeMap::new(),
            counter: 0,
            refresh_tokens: Arc::new(BTreeMap::new()),
            deleted_refresh_digests: Arc::new(BTreeMap::new()),
            tokens_by_user: Arc::new(BTreeMap::new()),
            next_id_override: None,
            next_sequence: 0,
            reset_generation: Arc::new(AtomicU64::new(0)),
            signer: None,
            credential_epoch: None,
            lifecycle_epoch: None,
            legacy_tokens_issued: false,
            oob_codes: Arc::new(BTreeMap::new()),
            verification_codes: Arc::new(BTreeMap::new()),
            temporary_proofs: BTreeMap::new(),
            pending_sign_in_owners: Arc::new(BTreeMap::new()),
            pending_idp: PendingIdpCache::default(),
            generated_local_id_reservations: Arc::new(Mutex::new(BTreeMap::new())),
            generated_local_id_reservation_ticket: Arc::new(AtomicU64::new(0)),
            generated_id_interference: Arc::new(AtomicU64::new(0)),
            pending_user_ids: BTreeSet::new(),
            created_users: Vec::new(),
            deleted_users: Vec::new(),
            credential_notices: Vec::new(),
            config: ProjectAuthConfig::default(),
            sign_in: SignInConfig::default(),
            signup_quota: SignupQuota::default(),
            oidc_configs: BTreeMap::new(),
            oidc_order: Vec::new(),
            saml_configs: BTreeMap::new(),
            saml_order: Vec::new(),
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

    /// Records a code the request just issued, for the shell to announce once.
    pub fn push_credential_notice(&mut self, notice: CredentialNotice) {
        self.credential_notices.push(notice);
    }

    /// The codes issued since the last call, in issue order; the queue is emptied.
    pub fn take_credential_notices(&mut self) -> Vec<CredentialNotice> {
        std::mem::take(&mut self.credential_notices)
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

    /// Explicit numeric identity for API response metadata; JWT audience remains project ID.
    pub fn set_project_number(&mut self, number: Option<u64>) {
        self.project_number = number;
    }

    /// Numeric project identity, when configured by the owning namespace.
    #[must_use]
    pub const fn project_number(&self) -> Option<u64> {
        self.project_number
    }

    /// Looks up a user by its ID text.
    #[must_use]
    pub fn user_by_id(&self, uid: &str) -> Option<&UserRecord> {
        self.users.get(uid).map(Arc::as_ref)
    }

    /// Identity Toolkit treats email addresses case-insensitively and stores their canonical
    /// lowercase representation. Keep this normalization at the ownership/index boundary so
    /// every route (including imports and email actions) uses the same key without affecting
    /// local IDs or other selectors.
    fn canonicalize_email(email: &str) -> String {
        email.to_lowercase()
    }

    fn email_owned_by_other(&self, email: &str, uid: Option<&LocalId>) -> bool {
        let email = Self::canonicalize_email(email);
        self.local_ids_for_email
            .get(&email)
            .is_some_and(|owners| owners.iter().any(|owner| Some(owner) != uid))
    }

    fn add_email_owner(&mut self, email: &str, uid: &LocalId) {
        let email = Self::canonicalize_email(email);
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
            let email = Self::canonicalize_email(&email);
            self.local_id_for_email.insert(email, uid.clone());
        }
    }

    fn remove_email_owner(&mut self, email: &str, uid: &LocalId) {
        let email = Self::canonicalize_email(email);
        if let Some(owners) = self.local_ids_for_email.get_mut(&email) {
            owners.remove(uid);
        }
        if self
            .local_ids_for_email
            .get(&email)
            .is_some_and(BTreeSet::is_empty)
        {
            self.local_ids_for_email.remove(&email);
        }
        // The official Auth Emulator deletes the single active email index entry whenever
        // any duplicate owner is removed; it does not restore another owner automatically.
        self.local_id_for_email.remove(&email);
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
                // Production stores an empty id and ids up to 256 characters (sandbox
                // exploration 2026-09-24).
                if id.encode_utf16().count() > MAX_LOCAL_ID_UTF16_UNITS
                    || id.chars().any(char::is_control)
                {
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

    /// Deletes a user and live refresh sessions, retaining only rejection digests.
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
        if let Some(tokens) = self.tokens_by_user.get(&key) {
            // The owner is kept only as a digest, so a reused UID can be recognised without
            // retaining the identifier itself.
            let owner = sha256(key.as_str().as_bytes());
            let deleted = Arc::make_mut(&mut self.deleted_refresh_digests);
            for token in tokens {
                deleted.insert(sha256(token.as_bytes()), owner);
            }
        }
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
        self.deleted_refresh_digests = Arc::new(BTreeMap::new());
        self.tokens_by_user = Arc::new(BTreeMap::new());
        self.oob_codes = Arc::new(BTreeMap::new());
        self.verification_codes = Arc::new(BTreeMap::new());
        self.temporary_proofs.clear();
        self.pending_sign_in_owners = Arc::new(BTreeMap::new());
        self.pending_idp = PendingIdpCache::default();
        self.reset_generation.fetch_add(1, Ordering::AcqRel);
        self.pending_user_ids.clear();
        if let Some(epoch) = self.credential_epoch {
            self.rekey_generated_values(epoch.next());
        }
        if let Some(epoch) = self.lifecycle_epoch {
            self.lifecycle_epoch = Some(epoch.next());
        }
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
        self.pending_idp.sweep(now);
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
        self.temporary_proofs
            .retain(|_, (_, issued)| !Self::expired(*issued, TEMPORARY_PROOF_TTL_SECONDS, now));
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

    /// Retains a previously resolved `IdP` request under a namespace-bound opaque handle.
    ///
    /// The adapter supplies only original provider credentials, never a linking user's ID
    /// token. Authority binds the assertion validation mode/trust pin. Full caches omit this
    /// optional response field rather than failing after account mutation. Nothing is evicted
    /// while still live. This local TTL and capacity are not production quotas.
    pub fn remember_idp_sign_in(
        &mut self,
        request: String,
        authority: String,
        now: LogicalInstant,
    ) -> Option<String> {
        self.pending_idp.sweep(now);
        if !self.pending_idp.can_insert(&request, &authority, now) {
            return None;
        }
        // Include the exact namespace so identical deterministic seeds in different stores
        // cannot make a token for one tenant resolve to a different tenant's cached identity.
        // A restore can rewind RNG/counter state, so also bind the live reset generation;
        // old handles cannot be reassigned to a newly issued assertion after restore.
        let tenant = self.tenant_id.as_deref().unwrap_or_default();
        let namespace = format!(
            "{}:{}{}:{}",
            self.project_id.len(),
            self.project_id,
            tenant.len(),
            tenant
        );
        // Also commit to the credential material and verification authority. A public
        // deterministic seed/counter alone must not identify someone else's cached signed
        // assertion. This is an opaque local handle, not a Google-issued token format.
        let material = format!(
            "{}:{}{}:{}",
            request.len(),
            request,
            authority.len(),
            authority
        );
        let prefix = format!(
            "pidp1-{}-{:016x}-{}-",
            fireemu_core_types::hash::hex_lower(&sha256(namespace.as_bytes())),
            self.reset_generation(),
            fireemu_core_types::hash::hex_lower(&sha256(material.as_bytes())),
        );
        let token = self.next_id(&prefix);
        self.pending_idp
            .insert(token.clone(), request, authority, now)
            .then_some(token)
    }

    /// Returns raw cached provider credentials only for the same authority and active time.
    /// No account mutation, expiry extension or consumption occurs. The adapter must still
    /// verify current namespace/provider policy and, in signed mode, the original signature.
    #[must_use]
    pub fn pending_idp_sign_in(
        &self,
        token: &str,
        authority: &str,
        now: LogicalInstant,
    ) -> Option<&str> {
        self.pending_idp.get(token, authority, now)
    }

    /// Number of retained `IdP` continuation handles in this namespace.
    #[must_use]
    pub fn pending_idp_count(&self) -> usize {
        self.pending_idp.len()
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

    /// The project's sign-in providers and test phone numbers.
    #[must_use]
    pub const fn sign_in_config(&self) -> &SignInConfig {
        &self.sign_in
    }

    /// Replaces the sign-in providers and test phone numbers; an invalid configuration is
    /// refused and changes nothing.
    pub fn set_sign_in_config(&mut self, config: SignInConfig) -> Result<(), AuthError> {
        if !config.is_valid() {
            return Err(AuthError::InvalidPhoneNumber);
        }
        self.sign_in = config;
        Ok(())
    }

    /// Whether a principal may create an end-user account in this namespace.
    #[must_use]
    pub const fn allows_user_signup(&self, principal: AuthPrincipal) -> bool {
        matches!(principal, AuthPrincipal::Admin) || !self.config.disabled_user_signup
    }

    /// Whether a principal may delete an end-user account in this namespace.
    #[must_use]
    pub const fn allows_user_deletion(&self, principal: AuthPrincipal) -> bool {
        matches!(principal, AuthPrincipal::Admin) || !self.config.disabled_user_deletion
    }

    /// Creates a user after applying the namespace's end-user signup permission.
    pub fn create_user_as(
        &mut self,
        principal: AuthPrincipal,
        new: NewUser,
        now: LogicalInstant,
    ) -> Result<LocalId, AuthError> {
        if !self.allows_user_signup(principal) {
            return Err(AuthError::UserSignupDisabled);
        }
        self.create_user(new, now)
    }

    /// Creates a caller-selected user ID after applying the namespace's signup permission.
    pub fn create_user_with_id_as(
        &mut self,
        principal: AuthPrincipal,
        new: NewUser,
        id: Option<&str>,
        now: LogicalInstant,
    ) -> Result<LocalId, AuthError> {
        if !self.allows_user_signup(principal) {
            return Err(AuthError::UserSignupDisabled);
        }
        self.create_user_with_id(new, id, now)
    }

    /// Creates a password user after applying the namespace's signup permission.
    pub fn create_user_with_password_as(
        &mut self,
        principal: AuthPrincipal,
        new: NewUser,
        password: &str,
        now: LogicalInstant,
    ) -> Result<LocalId, AuthError> {
        if !self.allows_user_signup(principal) {
            return Err(AuthError::UserSignupDisabled);
        }
        self.create_user_with_password(new, password, now)
    }

    /// Deletes a user after applying the namespace's end-user self-deletion permission.
    pub fn delete_user_by_id_as(
        &mut self,
        principal: AuthPrincipal,
        uid: &str,
    ) -> Result<(), AuthError> {
        if !self.allows_user_deletion(principal) {
            return Err(AuthError::UserDeletionDisabled);
        }
        self.delete_user_by_id(uid)
    }

    /// The local sign-up quota simulator for this namespace.
    #[must_use]
    pub const fn signup_quota(&self) -> &SignupQuota {
        &self.signup_quota
    }

    /// Replaces the local sign-up quota simulator configuration without changing usage.
    pub fn set_signup_quota_config(
        &mut self,
        config: SignupQuotaConfig,
    ) -> Result<(), crate::signup_quota::QuotaConfigError> {
        self.signup_quota.set_config(config)
    }

    /// Reserves one end-user account creation against the trusted peer address.
    pub fn reserve_signup(
        &mut self,
        principal: AuthPrincipal,
        peer_ip: &str,
        now: LogicalInstant,
    ) -> Result<SignupReservation, AuthError> {
        if !self.allows_user_signup(principal) {
            return Err(AuthError::UserSignupDisabled);
        }
        self.signup_quota
            .reserve(&self.project_id, peer_ip, now)
            .map_err(Self::quota_error)
    }

    /// Commits a sign-up quota reservation once the account creation succeeded.
    pub fn commit_signup(
        &mut self,
        reservation: SignupReservation,
        now: LogicalInstant,
    ) -> Result<(), AuthError> {
        self.signup_quota
            .commit(reservation, now)
            .map_err(Self::quota_error)
    }

    /// Releases a sign-up quota reservation after account creation failed.
    pub fn release_signup(&mut self, reservation: SignupReservation) -> Result<(), AuthError> {
        self.signup_quota
            .release(reservation)
            .map_err(Self::quota_error)
    }

    fn quota_error(error: QuotaError) -> AuthError {
        match error {
            QuotaError::Exceeded => AuthError::SignupQuotaExceeded,
            QuotaError::InvalidPeerAddress
            | QuotaError::BucketCapacity
            | QuotaError::InvalidConfiguration(_)
            | QuotaError::InvalidReservation
            | QuotaError::StaleReservation => AuthError::SignupQuotaUnavailable,
        }
    }

    /// The effective password policy for this Auth namespace.
    #[must_use]
    pub const fn password_policy(&self) -> &PasswordPolicy {
        &self.password_policy
    }

    /// Atomically replaces the effective password policy. Callers should construct it with
    /// [`PasswordPolicy::try_new`] so invalid settings never become active.
    pub fn set_password_policy(&mut self, policy: PasswordPolicy) {
        self.password_policy = policy;
    }

    /// Lists OAuth/OIDC configurations in creation order.
    pub fn oidc_configs(&self) -> impl Iterator<Item = &OidcProviderConfig> {
        self.oidc_order
            .iter()
            .filter_map(|id| self.oidc_configs.get(id))
    }

    /// Gets one OAuth/OIDC configuration by ID.
    #[must_use]
    pub fn oidc_config(&self, id: &str) -> Option<&OidcProviderConfig> {
        self.oidc_configs.get(id)
    }

    /// Creates an OAuth/OIDC configuration. Returns `false` when its ID is already used.
    pub fn create_oidc_config(&mut self, config: OidcProviderConfig) -> bool {
        if self.oidc_configs.contains_key(&config.id) {
            return false;
        }
        self.oidc_order.push(config.id.clone());
        self.oidc_configs.insert(config.id.clone(), config);
        true
    }

    /// Replaces an OAuth/OIDC configuration. Returns `false` when its ID is unknown.
    pub fn replace_oidc_config(&mut self, config: OidcProviderConfig) -> bool {
        if !self.oidc_configs.contains_key(&config.id) {
            return false;
        }
        self.oidc_configs.insert(config.id.clone(), config);
        true
    }

    /// Deletes an OAuth/OIDC configuration. Returns `false` when its ID is unknown.
    pub fn delete_oidc_config(&mut self, id: &str) -> bool {
        if self.oidc_configs.remove(id).is_none() {
            return false;
        }
        self.oidc_order.retain(|candidate| candidate != id);
        true
    }

    /// Lists inbound SAML configurations in creation order.
    pub fn saml_configs(&self) -> impl Iterator<Item = &InboundSamlProviderConfig> {
        self.saml_order
            .iter()
            .filter_map(|id| self.saml_configs.get(id))
    }

    /// Gets one inbound SAML configuration by ID.
    #[must_use]
    pub fn saml_config(&self, id: &str) -> Option<&InboundSamlProviderConfig> {
        self.saml_configs.get(id)
    }

    /// Creates an inbound SAML configuration. Returns `false` when its ID is already used.
    pub fn create_saml_config(&mut self, config: InboundSamlProviderConfig) -> bool {
        if self.saml_configs.contains_key(&config.id) {
            return false;
        }
        self.saml_order.push(config.id.clone());
        self.saml_configs.insert(config.id.clone(), config);
        true
    }

    /// Replaces an inbound SAML configuration. Returns `false` when its ID is unknown.
    pub fn replace_saml_config(&mut self, config: InboundSamlProviderConfig) -> bool {
        if !self.saml_configs.contains_key(&config.id) {
            return false;
        }
        self.saml_configs.insert(config.id.clone(), config);
        true
    }

    /// Deletes an inbound SAML configuration. Returns `false` when its ID is unknown.
    pub fn delete_saml_config(&mut self, id: &str) -> bool {
        if self.saml_configs.remove(id).is_none() {
            return false;
        }
        self.saml_order.retain(|candidate| candidate != id);
        true
    }

    /// The password credential of a user, when it has one. An export reads it to write the
    /// emulator's `passwordHash` and `salt` back out.
    #[must_use]
    pub fn password_digest(&self, uid: &LocalId) -> Option<&PasswordDigest> {
        self.users.get(uid).and_then(|u| u.password.as_ref())
    }

    /// Installs a user from an import request. The password is stored as given: production
    /// applies neither the minimum length nor the project's password policy to
    /// `accounts:batchCreate` (sandbox recording 2026-09-23); callers bound its size.
    pub fn import_user(&mut self, user: ImportedUser) -> Result<LocalId, ImportUserError> {
        if let Some((_, plaintext)) = &user.password {
            Self::validate_imported_password(plaintext).map_err(ImportUserError::Account)?;
        }
        self.import_user_record(user)
    }

    /// Restores a user from a previously exported artifact, exactly as it was recorded.
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
    /// Password policy is deliberately not applied here: the artifact already contains a
    /// credential accepted by an earlier runtime, and restoring it must not rewrite or reject
    /// that credential as if it were a new password.
    pub fn import_user_trusted(&mut self, user: ImportedUser) -> Result<LocalId, ImportUserError> {
        self.import_user_record(user)
    }

    #[allow(clippy::too_many_lines)]
    fn import_user_record(&mut self, mut user: ImportedUser) -> Result<LocalId, ImportUserError> {
        if user.local_id.is_empty()
            || user.local_id.encode_utf16().count() > MAX_LOCAL_ID_UTF16_UNITS
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
        if let Some(email) = user.email.as_mut() {
            *email = Self::canonicalize_email(email);
            if !storable_email(email) {
                return Err(ImportUserError::Account(AuthError::InvalidEmail));
            }
            if !self.config.allow_duplicate_emails
                && !user.allow_shared_email
                && self.email_owned_by_other(email, None)
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
        for identity in &user.federated {
            identity.validate().map_err(ImportUserError::Account)?;
        }
        user.custom_claims
            .check_size()
            .map_err(|e| ImportUserError::Account(AuthError::LimitExceeded(e)))?;
        let password = match user.password {
            Some((salt, plaintext)) => {
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
            None => user.imported_password.map(PasswordDigest::from_imported),
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
                last_refresh_at: user.last_refresh_at,
                tokens_valid_after: user.tokens_valid_after,
                tokens_revoked: user.tokens_valid_after > Self::whole_second(user.created_at),
                federated: user.federated,
                admin_created: true,
                custom_auth: false,
                removed_password_updated_at: None,
                email_verified_recorded: true,
                password,
            }),
        );
        self.by_sequence.insert(sequence, local_id.clone());
        if let Some(email) = email {
            self.add_email_owner(&email, &local_id);
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

    /// At most `limit` users whose id sorts after `after` (all users when `None`), in user-id
    /// order: the `accounts:batchGet` listing, whose page token is the last id of a page.
    #[must_use]
    pub fn users_after_local_id(&self, after: Option<&str>, limit: usize) -> Vec<&UserRecord> {
        use std::ops::Bound::{Excluded, Unbounded};

        let lower = after.map_or(Unbounded, Excluded);
        self.users
            .range::<str, _>((lower, Unbounded))
            .take(limit)
            .map(|(_, user)| user.as_ref())
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

    /// Validates an email update without changing the store.
    pub fn validate_email_update(&self, uid: &LocalId, email: &str) -> Result<(), AuthError> {
        let email = Self::canonicalize_email(email);
        if !storable_email(&email) {
            return Err(AuthError::InvalidEmail);
        }
        if !self.config.allow_duplicate_emails && self.email_owned_by_other(&email, Some(uid)) {
            return Err(AuthError::EmailExists);
        }
        // Duplicate-email mode never gives an address two password accounts: production
        // refuses a second one at creation (sandbox recording 2026-09-23), and a move onto the
        // address would take its holder's password sign-in (closure security review
        // 2026-09-24).
        let moves_a_password = self.users.get(uid).is_some_and(|u| u.password.is_some());
        if moves_a_password
            && self
                .users_by_email(&email)
                .iter()
                .any(|other| &other.local_id != uid && other.password.is_some())
        {
            return Err(AuthError::EmailExists);
        }
        Ok(())
    }

    /// Changes the email, enforcing uniqueness unless the project enables duplicate emails.
    pub fn set_email(&mut self, uid: &LocalId, email: &str) -> Result<(), AuthError> {
        let email = Self::canonicalize_email(email);
        self.validate_email_update(uid, &email)?;
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
        let old = user.email.replace(email.clone());
        if let Some(old) = old {
            self.remove_email_owner(&old, uid);
        }
        self.add_email_owner(&email, uid);
        Ok(())
    }

    /// Normalizes a phone number the way production stores it: formatting punctuation and
    /// spaces are dropped and letters map through the phone keypad (`+1 650-555-0104` and
    /// `+1650555ABCD` are accepted, sandbox recording 2026-09-23). A zero country code, a
    /// missing `+` or any other character is refused, and the result must be valid E.164.
    pub fn normalize_phone_number(phone: &str) -> Result<String, AuthError> {
        let rest = phone
            .strip_prefix('+')
            .ok_or(AuthError::InvalidPhoneNumber)?;
        let mut normalized = String::with_capacity(phone.len());
        normalized.push('+');
        for c in rest.chars() {
            match c {
                '0'..='9' => normalized.push(c),
                ' ' | '-' | '(' | ')' | '.' | '/' => {}
                'A'..='Z' | 'a'..='z' => normalized.push(keypad_digit(c.to_ascii_uppercase())),
                _ => return Err(AuthError::InvalidPhoneNumber),
            }
        }
        if normalized.as_bytes().get(1) == Some(&b'0') {
            return Err(AuthError::InvalidPhoneNumber);
        }
        Self::validate_phone_number(&normalized)?;
        Ok(normalized)
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

    /// A read-only page sorted by an administrator-selected field.
    ///
    /// Keeps at most `min(user_count, offset + limit) + 1` borrowed candidates during
    /// selection, with saturating arithmetic and no account/credential payload clones.
    /// The canonical local-ID path retains its allocation-bounded iterator fast path.
    /// Non-ID fields scan the namespace once; they do not maintain stale secondary indexes.
    #[must_use]
    pub fn users_sorted_page(
        &self,
        field: UserSortField,
        offset: usize,
        limit: usize,
        descending: bool,
    ) -> Vec<&UserRecord> {
        self.users_matching_sorted_page(&[], field, offset, limit, descending)
    }

    /// Counts the union of exact predicates; an empty predicate list selects all users.
    /// Duplicate or overlapping predicates never duplicate a user. This is read-only.
    #[must_use]
    pub fn matching_user_count(&self, expressions: &[UserQueryExpression]) -> usize {
        if expressions.is_empty() {
            return self.users.len();
        }
        self.users
            .values()
            .filter(|user| Self::matches_user_query(user, expressions))
            .count()
    }

    fn matches_user_query(user: &UserRecord, expressions: &[UserQueryExpression]) -> bool {
        expressions.is_empty()
            || expressions
                .iter()
                .any(|expression| expression.matches(user))
    }

    /// Filters within this namespace before ordering, offset and limit.
    ///
    /// The local-ID iterator needs only a page allocation. Other sorts retain at most
    /// `min(user_count, offset + limit) + 1` borrowed candidates, never full user clones.
    /// Email matching and the union rule are documented by [`UserQueryExpression`].
    #[must_use]
    pub fn users_matching_sorted_page(
        &self,
        expressions: &[UserQueryExpression],
        field: UserSortField,
        offset: usize,
        limit: usize,
        descending: bool,
    ) -> Vec<&UserRecord> {
        if limit == 0 || offset >= self.users.len() {
            return Vec::new();
        }
        if field == UserSortField::LocalId {
            if descending {
                return self
                    .users
                    .values()
                    .rev()
                    .map(Arc::as_ref)
                    .filter(|user| Self::matches_user_query(user, expressions))
                    .skip(offset)
                    .take(limit)
                    .collect();
            }
            return self
                .users
                .values()
                .map(Arc::as_ref)
                .filter(|user| Self::matches_user_query(user, expressions))
                .skip(offset)
                .take(limit)
                .collect();
        }
        let keep = offset.saturating_add(limit).min(self.users.len());
        let matching = self
            .users
            .values()
            .map(Arc::as_ref)
            .filter(|user| Self::matches_user_query(user, expressions));
        // Ties keep ascending user-id order in both directions: production reverses only the
        // sort field (sandbox recording 2026-09-23, `auth-account/admin/query#sort-name-desc`).
        if descending {
            Self::first_sorted(
                matching,
                |user| (std::cmp::Reverse(field.value(user)), &user.local_id),
                keep,
            )
        } else {
            Self::first_sorted(matching, |user| (field.value(user), &user.local_id), keep)
        }
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect()
    }

    /// The `keep` smallest users by `key`, in order, holding at most `keep + 1` at a time.
    fn first_sorted<'a, K: Ord>(
        users: impl Iterator<Item = &'a UserRecord>,
        key: impl Fn(&'a UserRecord) -> K,
        keep: usize,
    ) -> Vec<&'a UserRecord> {
        let mut candidates = BTreeMap::new();
        for user in users {
            candidates.insert(key(user), user);
            if candidates.len() > keep {
                candidates.pop_last();
            }
        }
        candidates.into_values().collect()
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
            .saturating_add((self.deleted_refresh_digests.len() as u64).saturating_mul(96))
            .saturating_add(oob)
            .saturating_add(verification)
            .saturating_add(refresh_owners)
            .saturating_add((self.pending_sign_in_owners.len() as u64).saturating_mul(64))
            .saturating_add(u64::try_from(self.pending_idp.bytes()).unwrap_or(u64::MAX))
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
    /// The seven registries are refresh sessions, deletion digests, their per-user index,
    /// email action codes, phone verification codes, pending-MFA owners, and `IdP`
    /// continuations. Issuing a refresh session leaves the other five allocations shared.
    #[must_use]
    pub fn transient_registries_shared_with(&self, other: &Self) -> usize {
        usize::from(Arc::ptr_eq(&self.refresh_tokens, &other.refresh_tokens))
            + usize::from(Arc::ptr_eq(
                &self.deleted_refresh_digests,
                &other.deleted_refresh_digests,
            ))
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
            + usize::from(self.pending_idp.shared_with(&other.pending_idp))
    }

    /// Creates a user.
    pub fn create_user(&mut self, new: NewUser, now: LogicalInstant) -> Result<LocalId, AuthError> {
        self.create_user_with_email_policy(new, now, true)
    }

    /// The shared generation used to reject a blocking candidate that straddled a reset.
    #[must_use]
    pub fn reset_generation(&self) -> u64 {
        self.reset_generation.load(Ordering::Acquire)
    }

    /// Returns the monotonic count of ordinary generated-ID allocations that crossed an
    /// in-flight blocking candidate reservation.
    #[must_use]
    pub fn generated_id_interference_count(&self) -> u64 {
        self.generated_id_interference.load(Ordering::Acquire)
    }

    /// Reserves the next generated local ID for a speculative blocking request.
    ///
    /// The reservation is shared by snapshots, but the live random stream is unchanged. This
    /// keeps concurrent blocking candidates distinct while preserving the established identity
    /// change check when an ordinary nested Admin request consumes the same generated ID.
    pub fn reserve_next_generated_local_id(&mut self) -> String {
        self.reserve_next_generated_local_id_with_generation().0
    }

    /// Reserves the next generated local ID and returns the reset generation that owns it.
    ///
    /// The generation identifies the reset epoch so a guard from before a reset cannot release a
    /// same-ID reservation created after that reset. Callers that need request ownership should
    /// use [`Self::reserve_next_generated_local_id_with_ticket`].
    pub fn reserve_next_generated_local_id_with_generation(&mut self) -> (String, u64) {
        let (id, generation, _) = self.reserve_next_generated_local_id_with_ticket();
        (id, generation)
    }

    /// Reserves the next generated local ID and returns its reset generation and request ticket.
    ///
    /// The ticket is unique across snapshots sharing this store's reservation ledger. A
    /// reservation remains distinct from a later request in the same reset generation even if a
    /// failed commit has already consumed its generated ID override.
    pub fn reserve_next_generated_local_id_with_ticket(&mut self) -> (String, u64, u64) {
        let generation = self.reset_generation();
        let ticket = self
            .generated_local_id_reservation_ticket
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        loop {
            let candidate = LocalId(self.random_id28());
            if self.users.contains_key(&candidate) {
                continue;
            }
            let mut reservations = self
                .generated_local_id_reservations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entries = reservations.entry(candidate.clone()).or_default();
            if entries
                .iter()
                .any(|(reserved_generation, _)| *reserved_generation == generation)
            {
                continue;
            }
            if entries.insert((generation, ticket)) {
                self.next_id_override = Some(candidate.as_str().to_owned());
                return (candidate.as_str().to_owned(), generation, ticket);
            }
        }
    }

    /// Uses a previously reserved ID for the next generated account and retires one reservation
    /// from the current generation. New blocking requests use the ticketed variant below so a
    /// later guard release cannot affect another request's reservation.
    pub fn use_reserved_generated_local_id(&mut self, id: &str) {
        let generation = self.reset_generation();
        let mut reservations = self
            .generated_local_id_reservations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::release_reservation_generation(&mut reservations, id, generation);
        self.next_id_override = Some(id.to_owned());
    }

    /// Uses and retires exactly one request-owned generated ID reservation.
    pub fn use_reserved_generated_local_id_with_ticket(
        &mut self,
        id: &str,
        generation: u64,
        ticket: u64,
    ) -> bool {
        if self.reset_generation() != generation {
            return false;
        }
        let mut reservations = self
            .generated_local_id_reservations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let removed = Self::release_reservation_ticket(&mut reservations, id, generation, ticket);
        if removed {
            self.next_id_override = Some(id.to_owned());
        }
        removed
    }

    /// Releases a generated ID held by an in-flight blocking candidate. When the same ID was
    /// reserved across a reset, retire the oldest generation first so an old guard cannot remove
    /// the current generation's reservation.
    pub fn release_reserved_generated_local_id(&self, id: &str) {
        let mut reservations = self
            .generated_local_id_reservations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = LocalId(id.to_owned());
        let Some(generations) = reservations.get_mut(&key) else {
            return;
        };
        let Some((generation, ticket)) = generations.iter().next().copied() else {
            return;
        };
        generations.remove(&(generation, ticket));
        if generations.is_empty() {
            reservations.remove(&key);
        }
    }

    /// Releases exactly the reservation identified by its generated ID and reset generation.
    pub fn release_reserved_generated_local_id_at_generation(&self, id: &str, generation: u64) {
        let mut reservations = self
            .generated_local_id_reservations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::release_reservation_generation(&mut reservations, id, generation);
    }

    /// Releases exactly one request-owned generated ID reservation.
    pub fn release_reserved_generated_local_id_at_ticket(
        &self,
        id: &str,
        generation: u64,
        ticket: u64,
    ) {
        let mut reservations = self
            .generated_local_id_reservations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::release_reservation_ticket(&mut reservations, id, generation, ticket);
    }

    fn release_reservation_generation(
        reservations: &mut GeneratedLocalIdReservations,
        id: &str,
        generation: u64,
    ) {
        let key = LocalId(id.to_owned());
        let Some(generations) = reservations.get_mut(&key) else {
            return;
        };
        let Some(ticket) = generations
            .iter()
            .find_map(|(reserved_generation, ticket)| {
                (*reserved_generation == generation).then_some(*ticket)
            })
        else {
            return;
        };
        generations.remove(&(generation, ticket));
        if generations.is_empty() {
            reservations.remove(&key);
        }
    }

    fn release_reservation_ticket(
        reservations: &mut GeneratedLocalIdReservations,
        id: &str,
        generation: u64,
        ticket: u64,
    ) -> bool {
        let key = LocalId(id.to_owned());
        let Some(generations) = reservations.get_mut(&key) else {
            return false;
        };
        let removed = generations.remove(&(generation, ticket));
        if generations.is_empty() {
            reservations.remove(&key);
        }
        removed
    }

    /// Creates the provider-scoped account used by `IdP` sign-in when email uniqueness is off.
    fn create_idp_user(&mut self, new: NewUser, now: LogicalInstant) -> Result<LocalId, AuthError> {
        self.create_user_with_email_policy(new, now, false)
    }

    fn create_user_with_email_policy(
        &mut self,
        mut new: NewUser,
        now: LogicalInstant,
        enforce_unique_email: bool,
    ) -> Result<LocalId, AuthError> {
        if let Some(email) = new.email.take() {
            new.email = Some(Self::canonicalize_email(&email));
        }
        if let Some(email) = &new.email {
            if !storable_email(email) {
                return Err(AuthError::InvalidEmail);
            }
            // `allowDuplicateEmails` does not extend to password or Admin-created accounts:
            // production refuses them with EMAIL_EXISTS (sandbox recording 2026-09-23).
            if enforce_unique_email && self.email_owned_by_other(email, None) {
                return Err(AuthError::EmailExists);
            }
        }
        let local_id = match self.next_id_override.take() {
            Some(id) => LocalId(id),
            None => loop {
                // Generated IDs share the namespace with caller-chosen ones: skip collisions.
                let candidate = LocalId(self.random_id28());
                let reserved = self
                    .generated_local_id_reservations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&candidate)
                    .is_some_and(|entries| {
                        entries
                            .iter()
                            .any(|(generation, _)| *generation == self.reset_generation())
                    });
                if reserved {
                    self.generated_id_interference
                        .fetch_add(1, Ordering::AcqRel);
                    continue;
                }
                if !self.users.contains_key(&candidate) && !reserved {
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
            last_refresh_at: None,
            tokens_valid_after: Self::whole_second(now),
            tokens_revoked: false,
            federated: Vec::new(),
            admin_created: false,
            custom_auth: false,
            removed_password_updated_at: None,
            email_verified_recorded: false,
            password: None,
        }));
        if let Some(email) = email {
            self.add_email_owner(&email, &local_id);
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
        let email = Self::canonicalize_email(email);
        let new_email = new_email.map(|value| Self::canonicalize_email(&value));
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
                email,
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
        // A test number always takes its configured code (sandbox recording 2026-09-23).
        let random = self.rng.next_u64() % 1_000_000;
        let code = self
            .sign_in
            .test_phone_numbers
            .get(phone)
            .cloned()
            .unwrap_or_else(|| format!("{random:06}"));
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

    /// Issues a `temporaryProof` for a verified number another account holds: production
    /// answers a link to a taken number with one (sandbox recording 2026-09-23). The proof
    /// signs in to the number's owner within [`TEMPORARY_PROOF_TTL_SECONDS`].
    pub fn issue_temporary_proof(
        &mut self,
        phone: &str,
        now: LogicalInstant,
    ) -> Result<String, AuthError> {
        self.sweep_transient_credentials(now);
        if self.temporary_proofs.len() >= MAX_OUTSTANDING_CODES {
            return Err(AuthError::TooManyOutstandingCodes);
        }
        let proof = format!("{}{:016x}", self.next_id("proof-"), self.rng.next_u64());
        self.temporary_proofs
            .insert(proof.clone(), (phone.to_owned(), now));
        Ok(proof)
    }

    /// Whether `proof` is a live `temporaryProof` issued for `phone`. A proof stays usable
    /// until it expires (corpus v2 recording 2026-09-24, a second sign-in with it succeeds).
    pub fn check_temporary_proof(&mut self, proof: &str, phone: &str, now: LogicalInstant) -> bool {
        self.sweep_transient_credentials(now);
        self.temporary_proofs
            .get(proof)
            .is_some_and(|(number, _)| number == phone)
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
        identity.validate()?;
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
        // Before anything is created, recycled or copied into a profile.
        identity.validate()?;
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
                    if !owner_email_verified {
                        self.recycle_account_for_verified_idp_email(
                            &uid,
                            &identity.provider_id,
                            now,
                        );
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

    /// A verified identity-provider email over an unverified-email account recycles it: the
    /// password, phone number and any other providers are dropped and its tokens are
    /// invalidated, so nothing minted under the old owner survives. This is what the official
    /// emulator does.
    fn recycle_account_for_verified_idp_email(
        &mut self,
        uid: &LocalId,
        provider_id: &str,
        now: LogicalInstant,
    ) {
        let old_phone = self
            .users
            .get(uid)
            .and_then(|user| user.phone_number.clone());
        let old_identities: Vec<(String, String)> = self
            .users
            .get(uid)
            .map(|user| {
                user.federated
                    .iter()
                    .map(|identity| (identity.provider_id.clone(), identity.raw_id.clone()))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(user) = self.users.get_mut(uid).map(Arc::make_mut) {
            user.password = None;
            user.phone_number = None;
            user.federated.clear();
            user.provider = Provider::Federated(provider_id.to_owned());
            user.tokens_valid_after = Self::whole_second(now);
            user.tokens_revoked = true;
        }
        if let Some(phone) = old_phone {
            Self::remove_index_owner(&mut self.local_ids_for_phone, &phone, uid);
        }
        for identity in &old_identities {
            Self::remove_index_owner(&mut self.local_ids_for_federated, identity, uid);
        }
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
        // Before the enrollment id is drawn: a refused request must not advance the random
        // stream or touch the account.
        crate::mfa::validate_factor_display_name(display_name.as_deref())?;
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

    /// Every condition on which [`Self::set_phone_factors`] refuses a list, decided without
    /// touching the store.
    ///
    /// A caller that writes something else before it replaces the factors has to run this
    /// first, so a refused request applies none of itself: the Admin `accounts:update` route
    /// saves custom claims and links providers before it reaches the factors.
    ///
    /// # Errors
    ///
    /// The refusal `set_phone_factors` would return for the same list.
    pub fn check_phone_factors(
        &self,
        uid: &LocalId,
        factors: &[(String, Option<String>)],
    ) -> Result<(), MfaError> {
        // The whole list is checked before the existing factors are dropped: `enroll_phone_factor`
        // refuses an entry on its own, but by then the clear has already happened.
        for (phone, display_name) in factors {
            Self::validate_phone_number(phone).map_err(|_| MfaError::InvalidCode)?;
            crate::mfa::validate_factor_display_name(display_name.as_deref())?;
        }
        // The account conditions `enroll_phone_factor` refuses on, decided here so the clear
        // below does not run first. An empty list enrolls nothing, so it is not an
        // enrollment and is not held to them: a disabled account can still have its factors
        // cleared, and creating one carries an empty list.
        if !factors.is_empty() {
            let user = self.users.get(uid).ok_or(MfaError::UserNotFound)?;
            if user.disabled {
                return Err(MfaError::UserDisabled);
            }
            // The list replaces the phone factors, so it competes for the budget with the
            // TOTP factors it keeps.
            if user.mfa.totp_factors().len() + factors.len() > MAX_FACTORS_PER_USER {
                return Err(MfaError::TooManyFactors);
            }
        }
        Ok(())
    }

    /// Replaces the phone factors (Admin `mfa.enrollments`).
    ///
    /// # Errors
    ///
    /// See [`Self::check_phone_factors`]; a refused list leaves the account unchanged.
    pub fn set_phone_factors(
        &mut self,
        uid: &LocalId,
        factors: Vec<(String, Option<String>)>,
        now: LogicalInstant,
    ) -> Result<(), MfaError> {
        self.check_phone_factors(uid, &factors)?;
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
        if user.mfa.pending_sign_in(&pending.0).is_none() {
            return Err(MfaError::PendingSignInUnknown);
        }
        // Disabled after the first factor: refused before anything is consumed, so the
        // pending credential and its code survive a later re-enablement.
        if user.disabled {
            return Err(MfaError::UserDisabled);
        }
        if !user
            .mfa
            .phone_factors()
            .iter()
            .any(|f| f.mfa_enrollment_id == enrollment_id)
        {
            return Err(MfaError::NoEnrolledFactor);
        }
        user.mfa.pending_sign_ins_mut().remove(&pending.0);
        Arc::make_mut(&mut self.pending_sign_in_owners).remove(&pending.0);
        if user.mfa.pending_count() == 0 {
            self.pending_user_ids.remove(uid);
        }
        user.last_sign_in_at = Some(now);
        self.activate_email_owner(uid);
        Ok(SecondFactorAssertion {
            sign_in_second_factor: "phone".to_owned(),
            second_factor_identifier: enrollment_id.to_owned(),
            verified_at: now,
        })
    }

    /// Minimum password length enforced by Firebase, in UTF-16 units like the maximum
    /// (three astral characters pass, sandbox recording 2026-09-23).
    pub const MIN_PASSWORD_CHARS: usize = 6;
    /// Maximum password length enforced by Firebase's default password policy.
    pub const MAX_PASSWORD_UTF16_UNITS: usize = 4096;

    /// Validates an imported raw password: production stores one below the minimum length
    /// (sandbox recording 2026-09-23); the maximum and the control-character refusal remain
    /// local bounds.
    pub fn validate_imported_password(password: &str) -> Result<(), AuthError> {
        if password.encode_utf16().count() > Self::MAX_PASSWORD_UTF16_UNITS {
            return Err(AuthError::PasswordTooLong);
        }
        if password.chars().any(char::is_control) {
            return Err(AuthError::WeakPassword);
        }
        Ok(())
    }

    /// Validates a password without storing it (lets callers fail before mutating).
    pub fn validate_password(password: &str) -> Result<(), AuthError> {
        if password.encode_utf16().count() < Self::MIN_PASSWORD_CHARS {
            return Err(AuthError::WeakPassword);
        }
        if password.encode_utf16().count() > Self::MAX_PASSWORD_UTF16_UNITS {
            return Err(AuthError::PasswordTooLong);
        }
        if password.chars().any(char::is_control) {
            return Err(AuthError::WeakPassword);
        }
        Ok(())
    }

    /// Validates a password against the API hard limits and this namespace's policy. This is
    /// side-effect free and can be called before any account, token, MFA, or OOB mutation.
    pub fn validate_password_for(
        &self,
        operation: PasswordPolicyOperation,
        password: &str,
    ) -> Result<Vec<ViolationCode>, AuthError> {
        Self::validate_password(password)?;
        let violations = if self.password_policy.enforcement_state
            == crate::password_policy::EnforcementState::Enforce
        {
            self.password_policy.violations(password)
        } else {
            Vec::new()
        };
        if self.password_policy.rejects(operation, password) {
            if violations.contains(&ViolationCode::MinimumPasswordLength)
                && password.encode_utf16().count() < Self::MIN_PASSWORD_CHARS
            {
                return Err(AuthError::WeakPassword);
            }
            return Err(AuthError::PasswordPolicyViolation(
                self.policy_refusal(violations),
            ));
        }
        Ok(violations)
    }

    fn policy_refusal(
        &self,
        violations: Vec<ViolationCode>,
    ) -> crate::password_policy::PolicyRefusal {
        crate::password_policy::PolicyRefusal {
            violations,
            min_length: self.password_policy.min_length,
            max_length: self.password_policy.max_length,
        }
    }

    /// Evaluates only the configured policy for an already stored credential. Existing
    /// credentials may predate the current API hard input bound, so sign-in must not reuse the
    /// new-password hard-limit check.
    pub fn validate_existing_password_for_signin(
        &self,
        password: &str,
    ) -> Result<Vec<ViolationCode>, AuthError> {
        let violations = if self.password_policy.enforcement_state
            == crate::password_policy::EnforcementState::Enforce
        {
            self.password_policy.violations(password)
        } else {
            Vec::new()
        };
        if self
            .password_policy
            .rejects(PasswordPolicyOperation::SignIn, password)
        {
            return Err(AuthError::PasswordPolicyViolation(
                self.policy_refusal(violations),
            ));
        }
        Ok(violations)
    }

    /// Creates a password account as one transition. If credential installation fails, the
    /// newly allocated account is removed before the error is returned.
    pub fn create_user_with_password(
        &mut self,
        new: NewUser,
        password: &str,
        now: LogicalInstant,
    ) -> Result<LocalId, AuthError> {
        self.validate_password_for(PasswordPolicyOperation::Registration, password)?;
        let uid = self.create_user(new, now)?;
        if let Err(error) = self.set_password(&uid, password, now) {
            let _ = self.delete_user_by_id(uid.as_str());
            return Err(error);
        }
        Ok(uid)
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
    pub fn set_password(
        &mut self,
        uid: &LocalId,
        password: &str,
        now: LogicalInstant,
    ) -> Result<(), AuthError> {
        self.set_password_for(uid, password, now, PasswordPolicyOperation::Change)
    }

    /// Sets a password after evaluating the policy for the operation that requested it. The
    /// operation is explicit so Admin restore/import callers can keep their separate contract.
    pub fn set_password_for(
        &mut self,
        uid: &LocalId,
        password: &str,
        now: LogicalInstant,
        operation: PasswordPolicyOperation,
    ) -> Result<(), AuthError> {
        self.validate_password_for(operation, password)?;
        let mut salt = [0u8; 16];
        salt[..8].copy_from_slice(&self.rng.next_u64().to_be_bytes());
        salt[8..].copy_from_slice(&self.rng.next_u64().to_be_bytes());
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
        let mut digest = PasswordDigest::new(salt, password);
        digest.updated_at = Some(now);
        user.password = Some(digest);
        // A password change revokes every token issued in an earlier second, as production's
        // validSince does (an Admin password update left a refresh token TOKEN_EXPIRED in the
        // sandbox recording of 2026-09-23).
        user.tokens_valid_after = user.tokens_valid_after.max(Self::whole_second(now));
        self.activate_email_owner(uid);
        Ok(())
    }

    /// Restores the recorded `passwordUpdatedAt` of an imported password credential; a
    /// no-op without a password.
    pub fn set_password_updated_at(&mut self, uid: &LocalId, at: LogicalInstant) {
        if let Some(digest) = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .and_then(|u| u.password.as_mut())
        {
            digest.updated_at = Some(at);
        }
    }

    /// When `uid`'s password was last set through the API (`passwordUpdatedAt`); `None`
    /// without a password or for an imported credential.
    #[must_use]
    pub fn password_updated_at(&self, uid: &LocalId) -> Option<LogicalInstant> {
        self.users.get(uid).and_then(|u| {
            u.password
                .as_ref()
                .and_then(|p| p.updated_at)
                .or(u.removed_password_updated_at)
        })
    }

    /// Removes the password credential (`deleteProvider: password`, `deleteAttribute:
    /// PASSWORD`); `true` when there was one.
    pub fn clear_password(&mut self, uid: &LocalId) -> Result<bool, AuthError> {
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
        let removed = user.password.take();
        let changed = removed.is_some();
        if let Some(updated_at) = removed.and_then(|p| p.updated_at) {
            user.removed_password_updated_at = Some(updated_at);
        }
        if changed && matches!(&user.provider, Provider::Password) {
            user.provider = user
                .federated
                .first()
                .map(|identity| Provider::Federated(identity.provider_id.clone()))
                .or_else(|| user.phone_number.as_ref().map(|_| Provider::Phone))
                .unwrap_or(Provider::Anonymous);
        }
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

    /// Verifies an email + password sign-in and returns policy notifications, if any.
    ///
    /// Credential verification is deliberately completed before the policy is evaluated. This
    /// preserves credential-error precedence and prevents policy configuration from revealing
    /// information about unknown users or incorrect passwords. The returned violation codes are
    /// metadata only and never contain the candidate password.
    ///
    /// The refusal follows the project's email privacy setting the way the official emulator's
    /// does: by default an unknown email is [`AuthError::EmailNotFound`] and a wrong password
    /// [`AuthError::InvalidPassword`]; with `enableImprovedEmailPrivacy` both collapse into
    /// [`AuthError::InvalidCredentials`] so the response no longer reveals whether the email
    /// is registered.
    pub fn verify_password_with_policy(
        &mut self,
        email: &str,
        password: &str,
        now: LogicalInstant,
    ) -> Result<(LocalId, Vec<ViolationCode>), AuthError> {
        self.verify_password_with_imports(email, password, now, &NoImportedHashes)
    }

    /// [`Self::verify_password_with_policy`] for a store whose accounts may carry imported
    /// foreign hashes: `verifier` checks those. The first successful sign-in against an
    /// imported hash replaces it with fireemu's own digest of the now-known password.
    pub fn verify_password_with_imports(
        &mut self,
        email: &str,
        password: &str,
        now: LogicalInstant,
        verifier: &dyn ImportedHashVerifier,
    ) -> Result<(LocalId, Vec<ViolationCode>), AuthError> {
        let private = self.config.enable_improved_email_privacy;
        let Some(user) = self.password_owner_by_email(email) else {
            if private {
                let dummy = PasswordDigest {
                    salt: [0_u8; 16],
                    digest: [0_u8; 20],
                    emulator: None,
                    updated_at: None,
                    imported: None,
                };
                let _ = dummy.verify(password);
                return Err(AuthError::InvalidCredentials);
            }
            return Err(AuthError::EmailNotFound);
        };
        let (uid, disabled, checked) = (
            user.local_id.clone(),
            user.disabled,
            user.password
                .as_ref()
                .map_or(Ok(false), |p| p.verify_with(password, verifier)),
        );
        // The official emulator reports a disabled account before it checks the password.
        if disabled {
            return Err(AuthError::UserDisabled);
        }
        // Production fails a sign-in against unevaluable imported parameters internally
        // (sandbox recording 2026-09-23).
        let ok = checked.map_err(|ImportedHashFailure| AuthError::ImportedHashFailure)?;
        if !ok {
            return Err(if private {
                AuthError::InvalidCredentials
            } else {
                AuthError::InvalidPassword
            });
        }
        // Authenticate first, then apply the optional sign-in upgrade policy. A policy
        // refusal therefore cannot advance sign-in timestamps or issue/retire credentials.
        let violations = self.validate_existing_password_for_signin(password)?;
        let rehash = self
            .users
            .get(&uid)
            .and_then(|u| u.password.as_ref())
            .is_some_and(|p| p.imported.is_some());
        let salt = if rehash {
            let mut salt = [0u8; 16];
            salt[..8].copy_from_slice(&self.rng.next_u64().to_be_bytes());
            salt[8..].copy_from_slice(&self.rng.next_u64().to_be_bytes());
            Some(salt)
        } else {
            None
        };
        if let Some(u) = self.users.get_mut(&uid).map(Arc::make_mut) {
            u.last_sign_in_at = Some(now);
            if let (Some(salt), Some(previous)) = (salt, u.password.as_ref()) {
                let mut digest = PasswordDigest::new(salt, password);
                digest.updated_at = previous.updated_at;
                u.password = Some(digest);
            }
        }
        self.activate_email_owner(&uid);
        Ok((uid, violations))
    }

    /// Verifies an email + password sign-in; returns the user ID.
    ///
    /// This compatibility wrapper preserves the historical API for callers that do not need
    /// password-policy notification metadata.
    pub fn verify_password(
        &mut self,
        email: &str,
        password: &str,
        now: LogicalInstant,
    ) -> Result<LocalId, AuthError> {
        self.verify_password_with_policy(email, password, now)
            .map(|(uid, _violations)| uid)
    }

    /// Every account holding `email`, in creation order.
    #[must_use]
    pub fn users_by_email(&self, email: &str) -> Vec<&UserRecord> {
        let email = Self::canonicalize_email(email);
        let mut owners: Vec<&UserRecord> = self
            .local_ids_for_email
            .get(&email)
            .into_iter()
            .flatten()
            .filter_map(|uid| self.users.get(uid).map(Arc::as_ref))
            .collect();
        owners.sort_by_key(|user| user.sequence);
        owners
    }

    /// The account a password sign-in with `email` reaches: the active owner when it holds a
    /// password, else the earliest owner that does (an imported duplicate without a password
    /// does not hide the password account, sandbox recording 2026-09-23).
    fn password_owner_by_email(&self, email: &str) -> Option<&UserRecord> {
        let active = self.user_by_email(email)?;
        if active.password.is_some() {
            return Some(active);
        }
        Some(
            self.users_by_email(email)
                .into_iter()
                .find(|user| user.password.is_some())
                .unwrap_or(active),
        )
    }

    /// User by email: the active owner of the address.
    #[must_use]
    pub fn user_by_email(&self, email: &str) -> Option<&UserRecord> {
        let email = Self::canonicalize_email(email);
        self.local_id_for_email
            .get(&email)
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
    /// disablement or user deletion as absence; ownership never implies acceptance.
    #[must_use]
    pub fn owns_refresh_token(&self, token: &str) -> bool {
        self.refresh_tokens.contains_key(token)
            || self
                .deleted_refresh_digests
                .contains_key(&sha256(token.as_bytes()))
    }

    /// Records a completed issuance by its exact refresh session, without activating
    /// email ownership. Deleted/replaced sessions cannot mutate a reused UID.
    pub fn record_token_issuance(&mut self, token: &str, at: LogicalInstant) {
        let Ok(session) = self.stateless_refresh_session(token) else {
            return;
        };
        let uid = session.uid.clone();
        if let Some(user) = self.users.get_mut(&uid).map(Arc::make_mut) {
            user.last_refresh_at = Some(user.last_refresh_at.map_or(at, |old| old.max(at)));
        }
    }

    /// ID token claims for a refreshed session.
    pub fn id_token_claims_for_session(
        &self,
        session: &RefreshSession,
        now: LogicalInstant,
    ) -> Result<IdTokenClaims, AuthError> {
        let mut claims = self.id_token_claims_with_auth_time(
            &session.uid,
            session.second_factor.as_ref(),
            now,
            session.issued_at,
        )?;
        if let Some(p) = &session.provider {
            p.sign_in_provider_claim()
                .clone_into(&mut claims.firebase.sign_in_provider);
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
        // A deleted account's refresh token never becomes valid again. When an administrator
        // has since reused the UID, production answers TOKEN_EXPIRED (the new account's
        // validSince postdates the token); otherwise USER_NOT_FOUND.
        if let Some(owner) = self.deleted_refresh_digests.get(&sha256(token.as_bytes())) {
            let reused = self
                .users
                .keys()
                .any(|uid| sha256(uid.as_str().as_bytes()) == *owner);
            return Err(if reused {
                AuthError::ExpiredRefreshToken
            } else {
                AuthError::UserNotFound
            });
        }
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
            return Err(AuthError::ExpiredRefreshToken);
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
        // Disabled while the enrollment was pending: refused before the code is matched, so
        // the pending enrollment survives a later re-enablement. Same class as the sign-in
        // finalizers.
        if user.disabled {
            return Err(MfaError::UserDisabled);
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

    /// Drops raw credentials retained by a pending second-factor sign-in without consuming its
    /// pending credential or non-secret first-factor provenance.
    pub fn clear_pending_sign_in_credentials(&mut self, pending: &PendingSignInId) -> bool {
        let Some(owner) = self.pending_sign_in_owners.get(&pending.0).cloned() else {
            return false;
        };
        self.users
            .get_mut(&owner)
            .map(Arc::make_mut)
            .is_some_and(|user| user.mfa.clear_pending_sign_in_credentials(&pending.0))
    }

    /// Completes a TOTP second-factor sign-in for the factor named by `enrollment_id`.
    ///
    /// The pending credential and replay state are changed only after the selected factor
    /// accepts the code. This keeps a failed retry usable and prevents another enrolled factor
    /// from satisfying a request intended for a different factor.
    pub fn finalize_mfa_sign_in_for_factor(
        &mut self,
        uid: &LocalId,
        pending: &PendingSignInId,
        enrollment_id: &str,
        code: u32,
        now: LogicalInstant,
    ) -> Result<SecondFactorAssertion, MfaError> {
        let policy = self.policy;
        let (accepted_identifier, accepted_step) = {
            let user = self
                .users
                .get(uid)
                .map(Arc::as_ref)
                .ok_or(MfaError::UserNotFound)?;
            if user.mfa.pending_sign_in(&pending.0).is_none() {
                return Err(MfaError::PendingSignInUnknown);
            }
            // Disabled after the first factor: refused before the code is matched, so
            // neither the pending credential nor the code's step is consumed.
            if user.disabled {
                return Err(MfaError::UserDisabled);
            }

            let mut replayed = false;
            let mut accepted = None;
            let factor = user
                .mfa
                .totp_factors()
                .iter()
                .find(|factor| factor.mfa_enrollment_id == enrollment_id)
                .ok_or(MfaError::NoEnrolledFactor)?;
            match match_code(
                &factor.secret,
                &policy.params(),
                policy.window_steps,
                factor.last_accepted_step,
                code,
                now,
            ) {
                CodeMatch::Accepted { step } => {
                    accepted = Some((factor.mfa_enrollment_id.clone(), step));
                }
                CodeMatch::Replayed => replayed = true,
                CodeMatch::NoMatch => {}
            }
            accepted.ok_or(if replayed {
                MfaError::CodeAlreadyUsed
            } else {
                MfaError::InvalidCode
            })?
        };

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
        let factor = user
            .mfa
            .totp_factors_mut()
            .iter_mut()
            .find(|factor| factor.mfa_enrollment_id == accepted_identifier)
            .expect("accepted TOTP factor must remain enrolled");
        factor.last_accepted_step = Some(accepted_step);
        user.last_sign_in_at = Some(now);
        self.activate_email_owner(uid);
        Ok(SecondFactorAssertion {
            sign_in_second_factor: "totp".to_owned(),
            second_factor_identifier: accepted_identifier,
            verified_at: now,
        })
    }

    /// Builds ID token claims for `uid`, optionally with a verified second factor.
    pub fn id_token_claims(
        &self,
        uid: &LocalId,
        second_factor: Option<&SecondFactorAssertion>,
        now: LogicalInstant,
    ) -> Result<IdTokenClaims, AuthError> {
        self.id_token_claims_with_auth_time(uid, second_factor, now, now)
    }

    /// Builds ID token claims with an explicit authentication instant. New sign-ins use their
    /// issuance time, while refresh sessions retain the instant at which the session started.
    fn id_token_claims_with_auth_time(
        &self,
        uid: &LocalId,
        second_factor: Option<&SecondFactorAssertion>,
        now: LogicalInstant,
        auth_time: LogicalInstant,
    ) -> Result<IdTokenClaims, AuthError> {
        let user = self.users.get(uid).ok_or(AuthError::UserNotFound)?;
        let iat = i64::try_from(now.as_nanos().div_euclid(1_000_000_000)).unwrap_or(i64::MAX);
        let auth_time =
            i64::try_from(auth_time.as_nanos().div_euclid(1_000_000_000)).unwrap_or(i64::MAX);
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
            auth_time,
            user_id: uid.as_str().to_owned(),
            sub: uid.as_str().to_owned(),
            iat,
            exp: iat.saturating_add(ID_TOKEN_TTL_SECONDS),
            email: user.email.clone(),
            email_verified: user.email_verified,
            phone_number: user.phone_number.clone(),
            display_name: user.display_name.clone(),
            photo_url: user.photo_url.clone(),
            provider_id: (user.provider == Provider::Anonymous).then(|| "anonymous".to_owned()),
            firebase: FirebaseClaims {
                identities,
                sign_in_provider: user.provider.sign_in_provider_claim().to_owned(),
                sign_in_second_factor: second.map(|a| a.sign_in_second_factor.clone()),
                second_factor_identifier: second.map(|a| a.second_factor_identifier.clone()),
                tenant: self.tenant_id.clone(),
                sign_in_attributes: None,
                fireemu_session_epoch: self.lifecycle_epoch.map(AuthLifecycleEpoch::wire_value),
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
        user.tokens_revoked = true;
        self.activate_email_owner(uid);
        Ok(())
    }

    /// Sets `validSince` to exactly `at` (floored to its second), earlier or later than before:
    /// production evaluates it against each session's `auth_time` whenever the session is used,
    /// so moving it back honours older sessions again (sandbox recording 2026-09-24).
    pub fn set_valid_since(&mut self, uid: &LocalId, at: LogicalInstant) -> Result<(), AuthError> {
        let user = self
            .users
            .get_mut(uid)
            .map(Arc::make_mut)
            .ok_or(AuthError::UserNotFound)?;
        user.tokens_valid_after = Self::whole_second(at);
        user.tokens_revoked = true;
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
        copy.pending_idp = PendingIdpCache::default();
        // Provider configurations are process-local control-plane state. In particular,
        // OIDC client secrets must never become transferable snapshot material.
        copy.oidc_configs.clear();
        copy.oidc_order.clear();
        copy.saml_configs.clear();
        copy.saml_order.clear();
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
        restored.pending_idp = PendingIdpCache::default();
        // A restore is a lifecycle boundary just like clear. Keep the destination's shared
        // generation cell so blocking candidates captured from the live namespace cannot commit
        // after this replacement, including when the snapshot came from another namespace.
        live.reset_generation.fetch_add(1, Ordering::AcqRel);
        restored.reset_generation = live.reset_generation.clone();
        // Reservations belong to the live operation epoch, never to an imported snapshot. Keep
        // the destination ledger so old guards can retire their entries without touching a new
        // generation, while discarding reservations captured from the source snapshot.
        restored.generated_local_id_reservations = live.generated_local_id_reservations.clone();
        restored.generated_local_id_reservation_ticket =
            live.generated_local_id_reservation_ticket.clone();
        restored.generated_id_interference = live.generated_id_interference.clone();
        // A snapshot intentionally has no provider configurations. Preserve the destination's
        // control-plane state instead of allowing a cross-project restore to transfer it.
        restored.oidc_configs = live.oidc_configs.clone();
        restored.oidc_order.clone_from(&live.oidc_order);
        restored.saml_configs = live.saml_configs.clone();
        restored.saml_order.clone_from(&live.saml_order);
        let namespace_matches =
            restored.project_id == live.project_id && restored.tenant_id == live.tenant_id;
        if !namespace_matches {
            restored.refresh_tokens = Arc::new(BTreeMap::new());
            restored.deleted_refresh_digests = Arc::new(BTreeMap::new());
            restored.tokens_by_user = Arc::new(BTreeMap::new());
            // A cross-namespace restore must not transfer control-plane policy from the
            // captured namespace. The destination policy belongs to the destination namespace
            // and remains effective until an explicit policy update changes it.
            restored.password_policy = live.password_policy.clone();
            // Client permission and email privacy settings are control-plane state owned by
            // the destination namespace as well. A cross-namespace data restore must not
            // silently transfer those settings.
            restored.config = live.config;
            restored.sign_in = live.sign_in.clone();
            // A temporary proof is a credential of the captured namespace.
            restored.temporary_proofs.clear();
            // The local sign-up quota is namespace-owned control state as well. Preserve both
            // its configuration and already-counted destination usage instead of transferring
            // the source project's quota window into a different project or tenant.
            restored.signup_quota = live.signup_quota.clone();
        }
        live.project_id.clone_into(&mut restored.project_id);
        restored.project_number = live.project_number;
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
        // A restore creates a new live incarnation. Derive it from the destination session's
        // epoch rather than importing the snapshot's before restored users reappear.
        if let Some(epoch) = live.credential_epoch {
            restored.rekey_generated_values(epoch.next());
        } else {
            restored.credential_epoch = None;
        }
        restored.lifecycle_epoch = live.lifecycle_epoch.map(AuthLifecycleEpoch::next);
        *live = restored;
        report
    }
}

/// A consistent export view of one Auth project and all of its published tenants.
///
/// The view is captured while the project's operation gate and every participating store lock
/// are held. Callers can then serialize the owned copies without keeping registry locks or
/// blocking Auth mutations during file I/O.
#[derive(Debug)]
pub struct AuthExportSnapshot {
    project: String,
    default: AuthStore,
    tenants: Vec<(String, AuthStore)>,
    tenant_metadata: BTreeMap<String, TenantMetadata>,
    tenant_config_overrides: BTreeMap<String, AuthNamespaceConfigPatch>,
}

impl AuthExportSnapshot {
    /// The project captured by this view.
    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project
    }

    /// The project-level Auth store captured by this view.
    #[must_use]
    pub const fn default_store(&self) -> &AuthStore {
        &self.default
    }

    /// Tenant stores captured by this view in lexical tenant-ID order.
    pub fn tenant_stores(&self) -> impl Iterator<Item = (&str, &AuthStore)> {
        self.tenants
            .iter()
            .map(|(tenant, store)| (tenant.as_str(), store))
    }

    /// The complete authorization metadata captured for a tenant, if it was published with the
    /// tenant store.
    #[must_use]
    pub fn tenant_metadata(&self, tenant: &str) -> Option<&TenantMetadata> {
        self.tenant_metadata.get(tenant)
    }

    /// The explicitly configured non-password settings for a tenant, if any.
    ///
    /// An absent value means the tenant inherits the project configuration. Effective values
    /// are intentionally not returned here: exporting those as explicit overrides would change
    /// the behavior of a later project update after import.
    #[must_use]
    pub fn tenant_config_override(&self, tenant: &str) -> Option<AuthNamespaceConfigPatch> {
        self.tenant_config_overrides.get(tenant).copied()
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
    pending_sessions: BTreeMap<String, PendingSessionRegistration>,
}

#[derive(Debug)]
struct PendingSessionRegistration {
    registered: SharedAuthStore,
    displaced: Option<SharedAuthStore>,
}

/// Outcome of rolling back a session registration that has not completed its initial reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRegistrationRollback {
    /// No provisional registration exists for this project.
    NotPending,
    /// The exact registered store was removed and its displaced routed store was restored.
    Restored,
    /// Another store replaced the provisional registration, so rollback refused the ABA change.
    Conflict,
    /// The project registry could not be inspected.
    Unavailable,
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
    project_numbers: BTreeMap<String, u64>,
    default: SharedAuthStore,
    scoped_refresh_routing: bool,
    projects: Mutex<ProjectStores>,
    /// Explicit project policies configured before a project session is registered. An entry
    /// does not create or route the project; it is applied to the matching namespace when it
    /// later appears.
    project_password_policy_overrides: Mutex<BTreeMap<String, PasswordPolicy>>,
    /// Explicit non-password settings configured before a project namespace is registered.
    /// Entries never create a project or apply to another namespace.
    project_config_overrides: Mutex<BTreeMap<String, AuthNamespaceConfigPatch>>,
    tenants: Mutex<BTreeMap<TenantKey, SharedAuthStore>>,
    tenant_metadata: Mutex<BTreeMap<TenantKey, TenantMetadata>>,
    /// Explicit password policies configured for tenants that may not exist yet. An entry is
    /// a pending namespace override, not a request to create the tenant or to inherit the
    /// project policy.
    password_policy_overrides: Mutex<BTreeMap<TenantKey, PasswordPolicy>>,
    /// Explicit non-password settings configured before a tenant namespace is published.
    tenant_config_overrides: Mutex<BTreeMap<TenantKey, AuthNamespaceConfigPatch>>,
    /// Non-password settings changed through the tenant management API. These are scoped to the
    /// current tenant lifetime and are discarded when that tenant is deleted.
    tenant_runtime_config_overrides: Mutex<BTreeMap<TenantKey, AuthNamespaceConfigPatch>>,
    operation_gates: Mutex<BTreeMap<TenantKey, Weak<Mutex<()>>>>,
    membership_generation: AtomicU64,
    lifecycle_incarnation: Option<u128>,
    next_lifecycle_serial: AtomicU64,
    next_tenant_id: AtomicU64,
    #[cfg(test)]
    refresh_token_scans: AtomicU64,
}

/// A project-scoped Auth reset prepared without mutating registry or credential state.
/// The opaque membership generation and `Arc` identities prevent applying the probe after
/// another namespace transition changed its meaning.
#[derive(Debug)]
pub struct PreparedAuthProjectReset {
    project: String,
    membership_generation: u64,
    parent: SharedAuthStore,
    tenants: Vec<(TenantKey, SharedAuthStore)>,
}

/// A default-scope Auth reset prepared without mutating the default, routed, or tenant stores.
#[derive(Debug)]
pub struct PreparedAuthDefaultScopeReset {
    membership_generation: u64,
    default: SharedAuthStore,
    routed: Vec<(String, SharedAuthStore)>,
    tenants: Vec<(TenantKey, SharedAuthStore)>,
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
    /// Whether end-user account creation is disabled in this tenant.
    pub disabled_user_signup: bool,
    /// Whether end-user self-deletion is disabled in this tenant.
    pub disabled_user_deletion: bool,
    /// Whether email enumeration protection is enabled in this tenant.
    pub enable_improved_email_privacy: bool,
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
    /// `None` leaves the tenant duplicate-email setting unchanged.
    pub allow_duplicate_emails: Option<bool>,
    /// `None` leaves the end-user signup permission unchanged.
    pub disabled_user_signup: Option<bool>,
    /// `None` leaves the end-user deletion permission unchanged.
    pub disabled_user_deletion: Option<bool>,
    /// `None` leaves the tenant email privacy setting unchanged.
    pub enable_improved_email_privacy: Option<bool>,
}

impl TenantMetadataPatch {
    fn apply_to(&self, value: &mut TenantMetadata) {
        if let Some(display_name) = &self.display_name {
            value.display_name.clone_from(display_name);
        }
        if let Some(setting) = self.allow_password_signup {
            value.allow_password_signup = setting;
        }
        if let Some(setting) = self.enable_email_link_signin {
            value.enable_email_link_signin = setting;
        }
        if let Some(setting) = self.enable_anonymous_user {
            value.enable_anonymous_user = setting;
        }
        if let Some(setting) = self.disable_auth {
            value.disable_auth = setting;
        }
        if let Some(setting) = self.disabled_user_signup {
            value.disabled_user_signup = setting;
        }
        if let Some(setting) = self.disabled_user_deletion {
            value.disabled_user_deletion = setting;
        }
        if let Some(setting) = self.enable_improved_email_privacy {
            value.enable_improved_email_privacy = setting;
        }
    }

    fn apply_to_project_config(&self, config: &mut ProjectAuthConfig) {
        if let Some(setting) = self.allow_duplicate_emails {
            config.allow_duplicate_emails = setting;
        }
        if let Some(setting) = self.disabled_user_signup {
            config.disabled_user_signup = setting;
        }
        if let Some(setting) = self.disabled_user_deletion {
            config.disabled_user_deletion = setting;
        }
        if let Some(setting) = self.enable_improved_email_privacy {
            config.enable_improved_email_privacy = setting;
        }
    }

    fn config_override(&self) -> AuthNamespaceConfigPatch {
        AuthNamespaceConfigPatch {
            allow_duplicate_emails: self.allow_duplicate_emails,
            disabled_user_signup: self.disabled_user_signup,
            disabled_user_deletion: self.disabled_user_deletion,
            enable_improved_email_privacy: self.enable_improved_email_privacy,
        }
    }
}

impl TenantMetadata {
    /// Keeps the tenant's published metadata aligned with its effective runtime configuration.
    ///
    /// These fields are read by the adapter before an end-user operation, while the same values
    /// are enforced by the tenant store. Keeping them in sync is part of the publication
    /// boundary; omitted settings inherit from the project, whereas an explicit `false` remains
    /// false in the candidate passed by the caller.
    fn apply_effective_config(&mut self, config: ProjectAuthConfig) {
        self.disabled_user_signup = config.disabled_user_signup;
        self.disabled_user_deletion = config.disabled_user_deletion;
        self.enable_improved_email_privacy = config.enable_improved_email_privacy;
    }
}

impl AuthRegistry {
    fn next_lifecycle_epoch(&self) -> Option<AuthLifecycleEpoch> {
        let incarnation = self.lifecycle_incarnation?;
        self.next_lifecycle_serial
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .ok()
            .map(|serial| AuthLifecycleEpoch::initial(incarnation, serial))
    }

    /// Configured project numbers are isolated by project ID, including routed stores.
    #[must_use]
    pub fn with_project_numbers(
        default_project: &str,
        default: SharedAuthStore,
        numbers: BTreeMap<String, u64>,
    ) -> Self {
        if let Ok(mut store) = default.lock() {
            store.set_project_number(numbers.get(default_project).copied());
        }
        let mut registry = Self::new(default_project, default);
        registry.project_numbers = numbers;
        registry
    }

    /// A registry whose explicit and compatibility-routed namespaces receive opaque
    /// credentials tied to this daemon incarnation.
    #[must_use]
    pub fn with_project_numbers_and_lifecycle_incarnation(
        default_project: &str,
        default: SharedAuthStore,
        numbers: BTreeMap<String, u64>,
        lifecycle_incarnation: u128,
    ) -> Self {
        let mut registry = Self::with_project_numbers(default_project, default, numbers);
        registry.lifecycle_incarnation = Some(lifecycle_incarnation);
        if let Ok(mut default) = registry.default.lock() {
            default.rekey_generated_values(AuthLifecycleEpoch::initial(lifecycle_incarnation, 0));
        }
        registry
    }

    /// A registry around the default project's store.
    #[must_use]
    pub fn new(default_project: &str, default: Arc<Mutex<AuthStore>>) -> Self {
        let scoped_refresh_routing = default.lock().is_ok_and(|store| {
            store.project_id() == default_project && store.tenant_id().is_none()
        });
        Self {
            default_project: default_project.to_owned(),
            project_numbers: BTreeMap::new(),
            default,
            scoped_refresh_routing,
            projects: Mutex::new(ProjectStores::default()),
            project_password_policy_overrides: Mutex::new(BTreeMap::new()),
            project_config_overrides: Mutex::new(BTreeMap::new()),
            tenants: Mutex::new(BTreeMap::new()),
            tenant_metadata: Mutex::new(BTreeMap::new()),
            password_policy_overrides: Mutex::new(BTreeMap::new()),
            tenant_config_overrides: Mutex::new(BTreeMap::new()),
            tenant_runtime_config_overrides: Mutex::new(BTreeMap::new()),
            operation_gates: Mutex::new(BTreeMap::new()),
            membership_generation: AtomicU64::new(0),
            lifecycle_incarnation: None,
            next_lifecycle_serial: AtomicU64::new(1),
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
        let lifecycle_epoch = match self.lifecycle_incarnation {
            Some(_) => Some(self.next_lifecycle_epoch()?),
            None => None,
        };
        // Registry override locks are acquired before any AuthStore lock throughout the
        // routing path. Taking the snapshots first prevents a concurrent project PATCH (which
        // updates an override while holding the namespace gate) from deadlocking a routed
        // request that is reading the default store.
        let explicit_password_policy = self
            .project_password_policy_overrides
            .lock()
            .ok()?
            .get(project)
            .cloned();
        let explicit_config = self
            .project_config_overrides
            .lock()
            .ok()?
            .get(project)
            .copied();
        let (policy, config, quota, signer) = {
            let default = self.default.lock().ok()?;
            (
                *default.policy(),
                default.config(),
                // Quota simulation defaults are safe to share across projects, but a
                // temporary override is project-scoped and must never leak into a routed
                // candidate for another project.
                SignupQuotaConfig {
                    temporary: None,
                    ..default.signup_quota().config().clone()
                },
                default.signer_arc(),
            )
        };
        let seed = project
            .bytes()
            .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
                hash.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte)
            });
        let mut store = AuthStore::new(project, SplitMix64::new(seed), policy);
        if let Some(policy) = explicit_password_policy {
            store.set_password_policy(policy);
        }
        if let Some(epoch) = lifecycle_epoch {
            store.set_lifecycle_epoch(epoch);
        }
        store.set_config(explicit_config.map_or(config, |patch| patch.apply_to(config)));
        store.set_signup_quota_config(quota).ok()?;
        store.set_project_number(self.project_numbers.get(project).copied());
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
        let Ok(mut candidate) = store.lock() else {
            return RoutedStoreInstall::InvalidStore;
        };
        if candidate.project_id() != project || candidate.tenant_id().is_some() {
            return RoutedStoreInstall::InvalidStore;
        }
        if candidate.lifecycle_epoch.is_none() && self.lifecycle_incarnation.is_some() {
            let Some(epoch) = self.next_lifecycle_epoch() else {
                return RoutedStoreInstall::Capacity;
            };
            candidate.set_lifecycle_epoch(epoch);
        }
        if let Some(policy) = self
            .project_password_policy_overrides
            .lock()
            .ok()
            .and_then(|overrides| overrides.get(project).cloned())
        {
            candidate.set_password_policy(policy);
        }
        if let Some(patch) = self
            .project_config_overrides
            .lock()
            .ok()
            .and_then(|overrides| overrides.get(project).copied())
        {
            let next_config = patch.apply_to(candidate.config());
            candidate.set_config(next_config);
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
    pub fn clear_routed(&self) -> Result<(), &'static str> {
        let mut projects = self
            .projects
            .lock()
            .map_err(|_| "project registry is poisoned")?;
        if !projects.pending_sessions.is_empty() {
            return Err("a session registration is still provisional");
        }
        let mut tenants = self
            .tenants
            .lock()
            .map_err(|_| "tenant registry is poisoned")?;
        let mut metadata = self
            .tenant_metadata
            .lock()
            .map_err(|_| "tenant metadata registry is poisoned")?;
        let mut gates = self
            .operation_gates
            .lock()
            .map_err(|_| "tenant operation-gate registry is poisoned")?;
        let mut runtime_overrides = self
            .tenant_runtime_config_overrides
            .lock()
            .map_err(|_| "tenant runtime config override registry is poisoned")?;
        let removed = projects.routed.keys().cloned().collect::<BTreeSet<_>>();
        let routed_stores = projects.routed.values().cloned().collect::<Vec<_>>();
        let tenant_stores = tenants
            .iter()
            .filter(|((project, _), _)| removed.contains(project))
            .map(|(_, store)| store.clone())
            .collect::<Vec<_>>();
        let mut guards = Vec::with_capacity(routed_stores.len() + tenant_stores.len());
        for store in routed_stores.iter().chain(&tenant_stores) {
            guards.push(store.lock().map_err(|_| "an Auth store is poisoned")?);
        }
        for store in &mut guards {
            store.clear();
        }
        projects.routed.clear();
        tenants.retain(|(project, _), _| !removed.contains(project));
        metadata.retain(|(project, _), _| !removed.contains(project));
        runtime_overrides.retain(|(project, _), _| !removed.contains(project));
        gates.retain(|(project, _), gate| !removed.contains(project) && gate.strong_count() > 0);
        if !removed.is_empty() {
            self.membership_generation.fetch_add(1, Ordering::Release);
        }
        Ok(())
    }

    /// Probes the default Auth store and every compatibility-routed namespace before a
    /// default-scope reset. No store or registry membership is changed.
    pub fn prepare_default_scope_reset(
        &self,
    ) -> Result<PreparedAuthDefaultScopeReset, &'static str> {
        let projects = self
            .projects
            .lock()
            .map_err(|_| "project registry is poisoned")?;
        if !projects.pending_sessions.is_empty() {
            return Err("a session registration is still provisional");
        }
        let tenants = self
            .tenants
            .lock()
            .map_err(|_| "tenant registry is poisoned")?;
        let metadata = self
            .tenant_metadata
            .lock()
            .map_err(|_| "tenant metadata registry is poisoned")?;
        let _gates = self
            .operation_gates
            .lock()
            .map_err(|_| "tenant operation-gate registry is poisoned")?;
        let routed = projects
            .routed
            .iter()
            .map(|(project, store)| (project.clone(), store.clone()))
            .collect::<Vec<_>>();
        let mut owned_projects = routed
            .iter()
            .map(|(project, _)| project.as_str())
            .collect::<BTreeSet<_>>();
        owned_projects.insert(self.default_project.as_str());
        let owned_tenants = tenants
            .iter()
            .filter(|((project, _), _)| owned_projects.contains(project.as_str()))
            .map(|(key, store)| (key.clone(), store.clone()))
            .collect::<Vec<_>>();
        if owned_tenants
            .iter()
            .any(|(key, _)| !metadata.contains_key(key))
            || metadata.keys().any(|(project, tenant)| {
                owned_projects.contains(project.as_str())
                    && !tenants.contains_key(&(project.clone(), tenant.clone()))
            })
        {
            return Err("default-scope tenant store and metadata membership differ");
        }
        {
            let _default_probe = self
                .default
                .lock()
                .map_err(|_| "the default Auth store is poisoned")?;
            for (_, store) in &routed {
                let _store_probe = store
                    .lock()
                    .map_err(|_| "a routed Auth store is poisoned")?;
            }
            for (_, store) in &owned_tenants {
                let _store_probe = store
                    .lock()
                    .map_err(|_| "a default-scope tenant Auth store is poisoned")?;
            }
        }
        Ok(PreparedAuthDefaultScopeReset {
            membership_generation: self.membership_generation.load(Ordering::Acquire),
            default: self.default.clone(),
            routed,
            tenants: owned_tenants,
        })
    }

    /// Applies a prepared default-scope reset as one Auth transition.
    pub fn apply_default_scope_reset(
        &self,
        prepared: &PreparedAuthDefaultScopeReset,
    ) -> Result<(), &'static str> {
        let mut projects = self
            .projects
            .lock()
            .map_err(|_| "project registry is poisoned")?;
        if self.membership_generation.load(Ordering::Acquire) != prepared.membership_generation
            || !Arc::ptr_eq(&self.default, &prepared.default)
            || !projects.pending_sessions.is_empty()
            || projects.routed.len() != prepared.routed.len()
            || prepared.routed.iter().any(|(project, expected)| {
                !projects
                    .routed
                    .get(project)
                    .is_some_and(|current| Arc::ptr_eq(current, expected))
            })
        {
            return Err("Auth default-scope membership changed after the reset probe");
        }
        let mut tenants = self
            .tenants
            .lock()
            .map_err(|_| "tenant registry is poisoned")?;
        let mut metadata = self
            .tenant_metadata
            .lock()
            .map_err(|_| "tenant metadata registry is poisoned")?;
        let mut gates = self
            .operation_gates
            .lock()
            .map_err(|_| "tenant operation-gate registry is poisoned")?;
        let mut runtime_overrides = self
            .tenant_runtime_config_overrides
            .lock()
            .map_err(|_| "tenant runtime config override registry is poisoned")?;
        let mut owned_projects = prepared
            .routed
            .iter()
            .map(|(project, _)| project.as_str())
            .collect::<BTreeSet<_>>();
        owned_projects.insert(self.default_project.as_str());
        let actual_tenant_count = tenants
            .keys()
            .filter(|(project, _)| owned_projects.contains(project.as_str()))
            .count();
        let actual_metadata_count = metadata
            .keys()
            .filter(|(project, _)| owned_projects.contains(project.as_str()))
            .count();
        if actual_tenant_count != prepared.tenants.len()
            || actual_metadata_count != prepared.tenants.len()
            || prepared.tenants.iter().any(|(key, expected)| {
                !tenants
                    .get(key)
                    .is_some_and(|current| Arc::ptr_eq(current, expected))
                    || !metadata.contains_key(key)
            })
        {
            return Err("Auth default-scope tenant membership changed after the reset probe");
        }
        let mut default = prepared
            .default
            .lock()
            .map_err(|_| "the default Auth store is poisoned")?;
        let mut routed_guards = Vec::with_capacity(prepared.routed.len());
        for (_, store) in &prepared.routed {
            routed_guards.push(
                store
                    .lock()
                    .map_err(|_| "a routed Auth store is poisoned")?,
            );
        }
        let mut tenant_guards = Vec::with_capacity(prepared.tenants.len());
        for (_, store) in &prepared.tenants {
            tenant_guards.push(
                store
                    .lock()
                    .map_err(|_| "a default-scope tenant Auth store is poisoned")?,
            );
        }
        default.clear();
        for store in &mut routed_guards {
            store.clear();
        }
        for store in &mut tenant_guards {
            store.clear();
        }
        projects.routed.clear();
        tenants.retain(|(project, _), _| !owned_projects.contains(project.as_str()));
        metadata.retain(|(project, _), _| !owned_projects.contains(project.as_str()));
        runtime_overrides.retain(|(project, _), _| !owned_projects.contains(project.as_str()));
        gates.retain(|(project, _), gate| {
            !owned_projects.contains(project.as_str()) && gate.strong_count() > 0
        });
        // The prepared handle is single-use even when the default store was the only member.
        self.membership_generation.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Probes a registered project and every tenant store it owns before a reset.
    pub fn prepare_project_reset(
        &self,
        project: &str,
    ) -> Result<Option<PreparedAuthProjectReset>, &'static str> {
        let projects = self
            .projects
            .lock()
            .map_err(|_| "project registry is poisoned")?;
        let Some(parent) = projects.registered.get(project).cloned() else {
            return Ok(None);
        };
        let tenants = self
            .tenants
            .lock()
            .map_err(|_| "tenant registry is poisoned")?;
        let metadata = self
            .tenant_metadata
            .lock()
            .map_err(|_| "tenant metadata registry is poisoned")?;
        let _gates = self
            .operation_gates
            .lock()
            .map_err(|_| "tenant operation-gate registry is poisoned")?;
        let owned = tenants
            .iter()
            .filter(|((candidate, _), _)| candidate == project)
            .map(|(key, store)| (key.clone(), store.clone()))
            .collect::<Vec<_>>();
        if owned.iter().any(|(key, _)| !metadata.contains_key(key))
            || metadata.keys().any(|(candidate, tenant)| {
                candidate == project && !tenants.contains_key(&(candidate.clone(), tenant.clone()))
            })
        {
            return Err("tenant store and metadata membership differ");
        }
        {
            let _parent_probe = parent
                .lock()
                .map_err(|_| "the parent Auth store is poisoned")?;
            for (_, store) in &owned {
                let _tenant_probe = store
                    .lock()
                    .map_err(|_| "a tenant Auth store is poisoned")?;
            }
        }
        Ok(Some(PreparedAuthProjectReset {
            project: project.to_owned(),
            membership_generation: self.membership_generation.load(Ordering::Acquire),
            parent,
            tenants: owned,
        }))
    }

    /// Applies a prepared project reset and removes every tenant namespace atomically.
    pub fn apply_project_reset(
        &self,
        prepared: &PreparedAuthProjectReset,
    ) -> Result<(), &'static str> {
        let projects = self
            .projects
            .lock()
            .map_err(|_| "project registry is poisoned")?;
        if self.membership_generation.load(Ordering::Acquire) != prepared.membership_generation
            || !projects
                .registered
                .get(&prepared.project)
                .is_some_and(|current| Arc::ptr_eq(current, &prepared.parent))
        {
            return Err("Auth project membership changed after the reset probe");
        }
        let mut tenants = self
            .tenants
            .lock()
            .map_err(|_| "tenant registry is poisoned")?;
        let mut metadata = self
            .tenant_metadata
            .lock()
            .map_err(|_| "tenant metadata registry is poisoned")?;
        let mut gates = self
            .operation_gates
            .lock()
            .map_err(|_| "tenant operation-gate registry is poisoned")?;
        let mut runtime_overrides = self
            .tenant_runtime_config_overrides
            .lock()
            .map_err(|_| "tenant runtime config override registry is poisoned")?;
        let actual = tenants
            .iter()
            .filter(|((project, _), _)| project == &prepared.project)
            .collect::<Vec<_>>();
        if actual.len() != prepared.tenants.len()
            || prepared.tenants.iter().any(|(key, expected)| {
                !tenants
                    .get(key)
                    .is_some_and(|current| Arc::ptr_eq(current, expected))
                    || !metadata.contains_key(key)
            })
        {
            return Err("Auth tenant membership changed after the reset probe");
        }
        let mut parent = prepared
            .parent
            .lock()
            .map_err(|_| "the parent Auth store is poisoned")?;
        let mut tenant_guards = Vec::with_capacity(prepared.tenants.len());
        for (_, store) in &prepared.tenants {
            tenant_guards.push(
                store
                    .lock()
                    .map_err(|_| "a tenant Auth store is poisoned")?,
            );
        }
        parent.clear();
        for store in &mut tenant_guards {
            store.clear();
        }
        tenants.retain(|(project, _), _| project != &prepared.project);
        metadata.retain(|(project, _), _| project != &prepared.project);
        runtime_overrides.retain(|(project, _), _| project != &prepared.project);
        gates.retain(|(project, _), _| project != &prepared.project);
        self.membership_generation.fetch_add(1, Ordering::Release);
        drop(projects);
        Ok(())
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
    pub fn register(&self, project: &str, mut store: AuthStore) -> bool {
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
        if self.lifecycle_incarnation.is_some() {
            let Some(epoch) = self.next_lifecycle_epoch() else {
                return false;
            };
            store.set_lifecycle_epoch(epoch);
        }
        if let Some(policy) = self
            .project_password_policy_overrides
            .lock()
            .ok()
            .and_then(|overrides| overrides.get(project).cloned())
        {
            store.set_password_policy(policy);
        }
        if let Some(patch) = self
            .project_config_overrides
            .lock()
            .ok()
            .and_then(|overrides| overrides.get(project).copied())
        {
            let next_config = patch.apply_to(store.config());
            store.set_config(next_config);
        }
        store.set_project_number(self.project_numbers.get(project).copied());
        projects
            .registered
            .insert(project.to_owned(), Arc::new(Mutex::new(store)));
        self.membership_generation.fetch_add(1, Ordering::Release);
        true
    }

    /// Provisionally registers an explicit session project, atomically displacing a
    /// compatibility-routed namespace of the same project. The initial reset must call
    /// [`Self::commit_session`] on success. A failed creation calls [`Self::rollback_session`]
    /// to restore the exact displaced store. Callers hold the daemon's exclusive transition
    /// barrier while this registration is pending.
    pub fn register_session(&self, project: &str, mut store: AuthStore) -> bool {
        if project == self.default_project
            || store.project_id() != project
            || store.tenant_id().is_some()
        {
            return false;
        }
        let Ok(mut projects) = self.projects.lock() else {
            return false;
        };
        let Ok(tenants) = self.tenants.lock() else {
            return false;
        };
        let Ok(metadata) = self.tenant_metadata.lock() else {
            return false;
        };
        if projects.registered.contains_key(project)
            || projects.pending_sessions.contains_key(project)
            || tenants.keys().any(|(candidate, _)| candidate == project)
            || metadata.keys().any(|(candidate, _)| candidate == project)
        {
            return false;
        }
        if self.lifecycle_incarnation.is_some() {
            let Some(epoch) = self.next_lifecycle_epoch() else {
                return false;
            };
            store.set_lifecycle_epoch(epoch);
        }
        if let Some(policy) = self
            .project_password_policy_overrides
            .lock()
            .ok()
            .and_then(|overrides| overrides.get(project).cloned())
        {
            store.set_password_policy(policy);
        }
        if let Some(patch) = self
            .project_config_overrides
            .lock()
            .ok()
            .and_then(|overrides| overrides.get(project).copied())
        {
            let next_config = patch.apply_to(store.config());
            store.set_config(next_config);
        }
        store.set_project_number(self.project_numbers.get(project).copied());
        let displaced = projects.routed.remove(project);
        drop(metadata);
        drop(tenants);
        let registered = Arc::new(Mutex::new(store));
        projects
            .registered
            .insert(project.to_owned(), registered.clone());
        projects.pending_sessions.insert(
            project.to_owned(),
            PendingSessionRegistration {
                registered,
                displaced,
            },
        );
        self.membership_generation.fetch_add(1, Ordering::Release);
        true
    }

    /// Commits a provisional session after its initial reset completed.
    ///
    /// `false` means the registered store changed while the caller claimed exclusive control.
    pub fn commit_session(&self, project: &str) -> bool {
        let Ok(mut projects) = self.projects.lock() else {
            return false;
        };
        let Some(pending) = projects.pending_sessions.remove(project) else {
            return true;
        };
        if projects
            .registered
            .get(project)
            .is_some_and(|current| Arc::ptr_eq(current, &pending.registered))
        {
            true
        } else {
            projects
                .pending_sessions
                .insert(project.to_owned(), pending);
            false
        }
    }

    /// Rolls back a provisional session without reconstructing any displaced Auth state.
    pub fn rollback_session(&self, project: &str) -> SessionRegistrationRollback {
        let Ok(mut projects) = self.projects.lock() else {
            return SessionRegistrationRollback::Unavailable;
        };
        let Some(pending) = projects.pending_sessions.remove(project) else {
            return SessionRegistrationRollback::NotPending;
        };
        if !projects
            .registered
            .get(project)
            .is_some_and(|current| Arc::ptr_eq(current, &pending.registered))
        {
            projects
                .pending_sessions
                .insert(project.to_owned(), pending);
            return SessionRegistrationRollback::Conflict;
        }
        projects.registered.remove(project);
        if let Some(displaced) = pending.displaced {
            projects.routed.insert(project.to_owned(), displaced);
        }
        self.membership_generation.fetch_add(1, Ordering::Release);
        SessionRegistrationRollback::Restored
    }

    /// Removes a registered project; `false` when it was not registered.
    pub fn remove(&self, project: &str) -> bool {
        let Ok(mut projects) = self.projects.lock() else {
            return false;
        };
        if projects.pending_sessions.contains_key(project) {
            return false;
        }
        let Some(parent) = projects.registered.get(project).cloned() else {
            return false;
        };
        let Ok(mut tenants) = self.tenants.lock() else {
            return false;
        };
        let Ok(mut metadata) = self.tenant_metadata.lock() else {
            return false;
        };
        let Ok(mut gates) = self.operation_gates.lock() else {
            return false;
        };
        let Ok(mut runtime_overrides) = self.tenant_runtime_config_overrides.lock() else {
            return false;
        };
        let tenant_stores = tenants
            .iter()
            .filter(|((candidate, _), _)| candidate == project)
            .map(|(_, store)| store.clone())
            .collect::<Vec<_>>();
        let Ok(mut parent) = parent.lock() else {
            return false;
        };
        let mut tenant_guards = Vec::with_capacity(tenant_stores.len());
        for store in &tenant_stores {
            let Ok(guard) = store.lock() else {
                return false;
            };
            tenant_guards.push(guard);
        }
        parent.clear();
        for store in &mut tenant_guards {
            store.clear();
        }
        projects.registered.remove(project);
        tenants.retain(|(candidate, _), _| candidate != project);
        metadata.retain(|(candidate, _), _| candidate != project);
        runtime_overrides.retain(|(candidate, _), _| candidate != project);
        gates.retain(|(candidate, _), _| candidate != project);
        self.membership_generation.fetch_add(1, Ordering::Release);
        true
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

    /// Builds a fresh tenant store for an import without publishing it in the registry.
    ///
    /// Import preparation must be able to construct every replacement before changing live
    /// membership. The store is initialized with the same inherited configuration as
    /// `ensure_tenant`, but lifecycle epochs are assigned by the publication transaction so a
    /// failed preparation cannot consume a lifecycle serial.
    pub fn tenant_import_candidate(&self, project: &str, tenant: &str) -> Option<AuthStore> {
        if project.is_empty()
            || project.contains(['/', '\\'])
            || tenant.is_empty()
            || tenant.contains(['/', '\\'])
        {
            return None;
        }
        let gate = self.operation_gate(project, None)?;
        let _operation = gate.lock().ok()?;
        let projects = self.projects.lock().ok()?;
        let parent = if project == self.default_project {
            &self.default
        } else {
            projects.registered.get(project)?
        };
        self.build_tenant_import_candidate(project, tenant, parent)
    }

    fn validate_default_scope_import_candidates(
        &self,
        project: &str,
        default: &AuthStore,
        tenants: &[(String, AuthStore, TenantMetadata)],
    ) -> Result<(), &'static str> {
        if project != self.default_project
            || default.project_id() != project
            || default.tenant_id().is_some()
        {
            return Err("invalid default Auth import candidate");
        }
        let mut tenant_ids = BTreeSet::new();
        for (tenant, store, _) in tenants {
            if tenant.is_empty()
                || tenant.contains(['/', '\\'])
                || !tenant_ids.insert(tenant.clone())
                || store.project_id() != project
                || store.tenant_id() != Some(tenant.as_str())
            {
                return Err("invalid tenant Auth import candidate");
            }
        }
        Ok(())
    }

    fn reserve_import_lifecycle_epochs(
        &self,
        count: usize,
    ) -> Result<Option<Vec<AuthLifecycleEpoch>>, &'static str> {
        let Some(incarnation) = self.lifecycle_incarnation else {
            return Ok(None);
        };
        let count = u64::try_from(count).map_err(|_| "too many tenant Auth import candidates")?;
        let start = self
            .next_lifecycle_serial
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(count)
            })
            .map_err(|_| "Auth lifecycle serial capacity exhausted")?;
        Ok(Some(
            (0..count)
                .map(|offset| AuthLifecycleEpoch::initial(incarnation, start + offset))
                .collect(),
        ))
    }

    /// Atomically replaces the default project and all of its imported tenant namespaces.
    ///
    /// All candidate stores and metadata must be prepared before this method is called. The
    /// method acquires every live lock that could be affected before publishing any candidate,
    /// so a poisoned store or inconsistent membership leaves the existing Auth state intact.
    pub fn replace_default_scope(
        &self,
        project: &str,
        default: AuthStore,
        tenants: Vec<(String, AuthStore, TenantMetadata)>,
    ) -> Result<(), &'static str> {
        self.replace_default_scope_with_config_overrides(
            project,
            default,
            tenants,
            &BTreeMap::new(),
        )
    }

    /// Atomically replaces the default project and imported tenants, restoring the explicit
    /// non-password settings that were serialized for each tenant. A missing entry preserves
    /// inheritance from the replacement project configuration.
    #[allow(clippy::too_many_lines)]
    pub fn replace_default_scope_with_config_overrides(
        &self,
        project: &str,
        default: AuthStore,
        tenants: Vec<(String, AuthStore, TenantMetadata)>,
        config_overrides: &BTreeMap<String, AuthNamespaceConfigPatch>,
    ) -> Result<(), &'static str> {
        self.validate_default_scope_import_candidates(project, &default, &tenants)?;

        let tenant_ids = tenants
            .iter()
            .map(|(tenant, _, _)| tenant.as_str())
            .collect::<BTreeSet<_>>();
        if config_overrides
            .keys()
            .any(|tenant| !tenant_ids.contains(tenant.as_str()))
            || config_overrides.values().any(|patch| patch.is_empty())
        {
            return Err("invalid tenant Auth config override");
        }

        let gate = self
            .operation_gate(project, None)
            .ok_or("tenant operation-gate registry is poisoned")?;
        let _operation = gate
            .lock()
            .map_err(|_| "the Auth operation gate is poisoned")?;
        let projects = self
            .projects
            .lock()
            .map_err(|_| "project registry is poisoned")?;
        if !projects.pending_sessions.is_empty() {
            return Err("a session registration is still provisional");
        }
        let mut live_tenants = self
            .tenants
            .lock()
            .map_err(|_| "tenant registry is poisoned")?;
        let mut live_metadata = self
            .tenant_metadata
            .lock()
            .map_err(|_| "tenant metadata registry is poisoned")?;
        let mut operation_gates = self
            .operation_gates
            .lock()
            .map_err(|_| "tenant operation-gate registry is poisoned")?;
        let mut runtime_overrides = self
            .tenant_runtime_config_overrides
            .lock()
            .map_err(|_| "tenant runtime config override registry is poisoned")?;
        let mut startup_overrides = self
            .tenant_config_overrides
            .lock()
            .map_err(|_| "tenant config override registry is poisoned")?;
        let current_tenant_keys = live_tenants
            .keys()
            .filter(|(candidate, _)| candidate == project)
            .cloned()
            .collect::<Vec<_>>();
        let current_metadata_keys = live_metadata
            .keys()
            .filter(|(candidate, _)| candidate == project)
            .cloned()
            .collect::<Vec<_>>();
        if current_tenant_keys != current_metadata_keys {
            return Err("tenant store and metadata membership differ");
        }
        let current_stores = current_tenant_keys
            .iter()
            .map(|key| {
                live_tenants
                    .get(key)
                    .cloned()
                    .ok_or("tenant store disappeared during Auth import")
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut default_store = self
            .default
            .lock()
            .map_err(|_| "the default Auth store is poisoned")?;
        let _current_store_guards = current_stores
            .iter()
            .map(|store| store.lock().map_err(|_| "an Auth tenant store is poisoned"))
            .collect::<Result<Vec<_>, _>>()?;

        // The replacement arcs are created before mutation. BTreeMap insertion below is the
        // only remaining publication work and cannot return an application-level error.
        let lifecycle_epochs = self.reserve_import_lifecycle_epochs(tenants.len())?;
        let mut replacement_stores = Vec::with_capacity(tenants.len());
        for (index, (tenant, mut store, metadata)) in tenants.into_iter().enumerate() {
            if let Some(epoch) = lifecycle_epochs
                .as_ref()
                .and_then(|epochs| epochs.get(index))
            {
                store.set_lifecycle_epoch(*epoch);
            }
            replacement_stores.push((
                (project.to_owned(), tenant),
                Arc::new(Mutex::new(store)),
                metadata,
            ));
        }
        *default_store = default;
        live_tenants.retain(|(candidate, _), _| candidate != project);
        live_metadata.retain(|(candidate, _), _| candidate != project);
        startup_overrides.retain(|(candidate, _), _| candidate != project);
        runtime_overrides.retain(|(candidate, _), _| candidate != project);
        operation_gates.retain(|(candidate, tenant), _| candidate != project || tenant.is_empty());
        for (key, store, metadata) in replacement_stores {
            live_tenants.insert(key.clone(), store);
            live_metadata.insert(key, metadata);
        }
        for (tenant, patch) in config_overrides {
            startup_overrides.insert((project.to_owned(), tenant.clone()), *patch);
        }
        self.membership_generation.fetch_add(1, Ordering::Release);
        Ok(())
    }

    fn existing_tenant_with_metadata(&self, key: &TenantKey) -> Option<Arc<Mutex<AuthStore>>> {
        let tenants = self.tenants.lock().ok()?;
        let metadata = self.tenant_metadata.lock().ok()?;
        metadata
            .contains_key(key)
            .then(|| tenants.get(key).cloned())
            .flatten()
    }

    fn build_tenant_store(
        &self,
        project: &str,
        tenant: &str,
        parent: &SharedAuthStore,
    ) -> Option<Arc<Mutex<AuthStore>>> {
        let key = (project.to_owned(), tenant.to_owned());
        // Snapshot namespace overrides before locking the inherited parent store. This is the
        // same registry-wide lock order used by routed candidates and project PATCHes.
        let explicit_password_policy = self
            .password_policy_overrides
            .lock()
            .ok()?
            .get(&key)
            .cloned();
        let explicit_config = self.effective_tenant_config_override(&key);
        let (policy, config, signer, number, lifecycle_enabled) = {
            let parent = parent.lock().ok()?;
            (
                *parent.policy(),
                parent.config(),
                parent.signer_arc(),
                parent.project_number(),
                parent.lifecycle_epoch.is_some(),
            )
        };
        let seed = project
            .bytes()
            .chain(tenant.bytes())
            .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
                hash.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte)
            });
        let mut store = AuthStore::new_tenant(project, tenant, SplitMix64::new(seed), policy);
        if let Some(policy) = explicit_password_policy {
            store.set_password_policy(policy);
        }
        if self.lifecycle_incarnation.is_some() {
            let epoch = self.next_lifecycle_epoch()?;
            if lifecycle_enabled {
                store.set_lifecycle_epoch(epoch);
            } else {
                store.rekey_generated_values(epoch);
            }
        }
        store.set_config(explicit_config.map_or(config, |patch| patch.apply_to(config)));
        store.set_project_number(number);
        if let Some(signer) = signer {
            store.set_signer(signer);
        }
        Some(Arc::new(Mutex::new(store)))
    }

    fn build_tenant_import_candidate(
        &self,
        project: &str,
        tenant: &str,
        parent: &SharedAuthStore,
    ) -> Option<AuthStore> {
        let key = (project.to_owned(), tenant.to_owned());
        let explicit_password_policy = self
            .password_policy_overrides
            .lock()
            .ok()?
            .get(&key)
            .cloned();
        let explicit_config = self.effective_tenant_config_override(&key);
        let (policy, config, signer, number) = {
            let parent = parent.lock().ok()?;
            (
                *parent.policy(),
                parent.config(),
                parent.signer_arc(),
                parent.project_number(),
            )
        };
        let seed = project
            .bytes()
            .chain(tenant.bytes())
            .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
                hash.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte)
            });
        let mut store = AuthStore::new_tenant(project, tenant, SplitMix64::new(seed), policy);
        if let Some(policy) = explicit_password_policy {
            store.set_password_policy(policy);
        }
        store.set_config(explicit_config.map_or(config, |patch| patch.apply_to(config)));
        store.set_project_number(number);
        if let Some(signer) = signer {
            store.set_signer(signer);
        }
        Some(store)
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
        if tenant_metadata.contains_key(&key) {
            return TenantPublication::Unavailable;
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

    /// Captures the project store and every published tenant store as one export view.
    ///
    /// The project operation gate excludes configuration and tenant-publication transitions
    /// while the membership registries are inspected. Every participating store is then locked
    /// before any clone is made, so user records and namespace settings come from one coherent
    /// point in time. The locks are released before the caller serializes the copies. A
    /// provisional session is rejected rather than exporting an uncommitted namespace.
    pub fn capture_export_snapshot(
        &self,
        project: &str,
    ) -> Result<Option<AuthExportSnapshot>, &'static str> {
        let gate = self
            .operation_gate(project, None)
            .ok_or("the Auth operation-gate registry is poisoned")?;
        let _operation = gate
            .lock()
            .map_err(|_| "the Auth operation gate is poisoned")?;
        let projects = self
            .projects
            .lock()
            .map_err(|_| "project registry is poisoned")?;
        if projects.pending_sessions.contains_key(project) {
            return Err("an Auth project session is still provisional");
        }
        let default = if project == self.default_project {
            self.default.clone()
        } else {
            let Some(store) = projects
                .registered
                .get(project)
                .or_else(|| projects.routed.get(project))
                .cloned()
            else {
                return Ok(None);
            };
            store
        };
        let tenants = self
            .tenants
            .lock()
            .map_err(|_| "tenant registry is poisoned")?;
        let tenant_entries = tenants
            .iter()
            .filter(|((candidate, _), _)| candidate == project)
            .map(|((_, tenant), store)| (tenant.clone(), store.clone()))
            .collect::<Vec<_>>();

        let default_guard = default
            .lock()
            .map_err(|_| "the project Auth store is poisoned")?;
        let tenant_guards = tenant_entries
            .iter()
            .map(|(_, store)| store.lock().map_err(|_| "an Auth tenant store is poisoned"))
            .collect::<Result<Vec<_>, _>>()?;
        // Authentication reads hold a namespace store before reading tenant metadata. Keep the
        // same order here so an in-flight request cannot hold a store while waiting for metadata
        // that an export is holding while waiting for that store.
        let metadata = self
            .tenant_metadata
            .lock()
            .map_err(|_| "tenant metadata registry is poisoned")?;
        let tenant_ids = tenant_entries
            .iter()
            .map(|(tenant, _)| tenant.clone())
            .collect::<Vec<_>>();
        let tenant_metadata = Self::export_tenant_metadata(project, &tenant_ids, &metadata)?;
        let startup_overrides = self
            .tenant_config_overrides
            .lock()
            .map_err(|_| "tenant config override registry is poisoned")?;
        let runtime_overrides = self
            .tenant_runtime_config_overrides
            .lock()
            .map_err(|_| "tenant runtime config override registry is poisoned")?;
        let tenant_config_overrides = Self::export_tenant_config_overrides(
            project,
            &tenant_ids,
            &startup_overrides,
            &runtime_overrides,
        );
        // Export views are serialization inputs, not a way to transfer raw IdP
        // continuation credentials between processes/namespaces.
        let mut exported_default = default_guard.clone();
        exported_default.pending_idp = PendingIdpCache::default();
        let snapshot = AuthExportSnapshot {
            project: project.to_owned(),
            default: exported_default,
            tenants: tenant_entries
                .iter()
                .zip(&tenant_guards)
                .map(|((tenant, _), store)| {
                    let mut exported = (*store).clone();
                    exported.pending_idp = PendingIdpCache::default();
                    (tenant.clone(), exported)
                })
                .collect(),
            tenant_metadata,
            tenant_config_overrides,
        };
        Ok(Some(snapshot))
    }

    /// Projects the published tenant metadata of `project` for an export view.
    ///
    /// The tenant store membership must match the metadata membership exactly; a mismatch
    /// means a tenant publication is mid-flight and the export is rejected.
    fn export_tenant_metadata(
        project: &str,
        tenant_ids: &[String],
        metadata: &BTreeMap<TenantKey, TenantMetadata>,
    ) -> Result<BTreeMap<String, TenantMetadata>, &'static str> {
        let metadata_tenants = metadata
            .keys()
            .filter(|(candidate, _)| candidate == project)
            .map(|(_, tenant)| tenant.clone())
            .collect::<Vec<_>>();
        if tenant_ids != metadata_tenants {
            return Err("tenant store and metadata membership differ");
        }
        tenant_ids
            .iter()
            .map(|tenant| {
                metadata
                    .get(&(project.to_owned(), tenant.clone()))
                    .cloned()
                    .map(|value| (tenant.clone(), value))
                    .ok_or("tenant metadata disappeared during Auth export")
            })
            .collect()
    }

    /// Merges the startup and runtime tenant config overrides of `project` for an export view.
    ///
    /// Tenants without an effective override are omitted.
    fn export_tenant_config_overrides(
        project: &str,
        tenant_ids: &[String],
        startup_overrides: &BTreeMap<TenantKey, AuthNamespaceConfigPatch>,
        runtime_overrides: &BTreeMap<TenantKey, AuthNamespaceConfigPatch>,
    ) -> BTreeMap<String, AuthNamespaceConfigPatch> {
        tenant_ids
            .iter()
            .filter_map(|tenant| {
                let key = (project.to_owned(), tenant.clone());
                let startup = startup_overrides.get(&key).copied().unwrap_or_default();
                let runtime = runtime_overrides.get(&key).copied().unwrap_or_default();
                let merged = startup.merge(runtime);
                (!merged.is_empty()).then_some((tenant.clone(), merged))
            })
            .collect()
    }

    fn effective_tenant_config_override(
        &self,
        key: &TenantKey,
    ) -> Option<AuthNamespaceConfigPatch> {
        let startup = self
            .tenant_config_overrides
            .lock()
            .ok()?
            .get(key)
            .copied()
            .unwrap_or_default();
        let runtime = self
            .tenant_runtime_config_overrides
            .lock()
            .ok()?
            .get(key)
            .copied()
            .unwrap_or_default();
        let merged = startup.merge(runtime);
        (!merged.is_empty()).then_some(merged)
    }

    /// Returns a tenant store, creating its isolated namespace on first use.
    pub fn ensure_tenant(&self, project: &str, tenant: &str) -> Option<Arc<Mutex<AuthStore>>> {
        if tenant.is_empty() || tenant.contains(['/', '\\']) {
            return None;
        }
        let gate = self.operation_gate(project, None)?;
        let _operation = gate.lock().ok()?;
        let projects = self.projects.lock().ok()?;
        let parent = if project == self.default_project {
            &self.default
        } else {
            projects.registered.get(project)?
        };
        let key = (project.to_owned(), tenant.to_owned());
        if let Some(store) = self.existing_tenant_with_metadata(&key) {
            return Some(store);
        }
        let store = self.build_tenant_store(project, tenant, parent)?;
        let mut tenant_metadata = TenantMetadata {
            allow_password_signup: true,
            enable_email_link_signin: true,
            enable_anonymous_user: true,
            ..TenantMetadata::default()
        };
        if let Some(patch) = self.effective_tenant_config_override(&key) {
            patch.apply_to_metadata(&mut tenant_metadata);
        }
        let effective_config = store.lock().ok()?.config();
        tenant_metadata.apply_effective_config(effective_config);
        match self.publish_tenant(key, store, tenant_metadata) {
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
        self.create_tenant_with_password_policy(
            project,
            metadata,
            TenantMetadataPatch::default(),
            None,
        )
        .map(|(tenant, _, _)| tenant)
    }

    /// Creates an explicitly configured tenant and publishes its metadata, inherited config,
    /// and password policy under one project operation gate.
    ///
    /// The metadata patch contains only fields explicitly supplied by the caller. This is
    /// important for inherited project settings: an omitted field must not be represented by a
    /// default `false` and overwrite a project update that committed before publication.
    #[allow(clippy::needless_pass_by_value)]
    pub fn create_tenant_with_password_policy(
        &self,
        project: &str,
        metadata: TenantMetadata,
        patch: TenantMetadataPatch,
        password_policy: Option<PasswordPolicy>,
    ) -> Option<(String, TenantMetadata, PasswordPolicy)> {
        if project.is_empty() || project.contains(['/', '\\']) {
            return None;
        }
        let gate = self.operation_gate(project, None)?;
        let _operation = gate.lock().ok()?;
        let projects = self.projects.lock().ok()?;
        let parent = if project == self.default_project {
            &self.default
        } else {
            projects.registered.get(project)?
        };
        let mut metadata = metadata;
        loop {
            let sequence = self.next_tenant_id.fetch_add(1, Ordering::Relaxed);
            let tenant = format!("fireemu-{sequence:020}");
            let store = self.build_tenant_store(project, &tenant, parent)?;
            if let Some(patch) =
                self.effective_tenant_config_override(&(project.to_owned(), tenant.clone()))
            {
                patch.apply_to_metadata(&mut metadata);
            }
            let mut next_metadata = metadata.clone();
            patch.apply_to(&mut next_metadata);
            let mut store_guard = store.lock().ok()?;
            let mut next_config = store_guard.config();
            patch.apply_to_project_config(&mut next_config);
            store_guard.set_config(next_config);
            next_metadata.apply_effective_config(next_config);
            let next_policy = password_policy
                .clone()
                .unwrap_or_else(|| store_guard.password_policy.clone());
            if let Some(policy) = &password_policy {
                store_guard.set_password_policy(policy.clone());
            }
            drop(store_guard);
            match self.publish_tenant(
                (project.to_owned(), tenant.clone()),
                store,
                next_metadata.clone(),
            ) {
                TenantPublication::Published(_) => {
                    return Some((tenant, next_metadata, next_policy));
                }
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
        self.patch_tenant_with_password_policy(project, tenant, patch, None)
            .map(|(metadata, _)| metadata)
    }

    /// Atomically applies a tenant metadata patch and, when supplied, a password policy.
    ///
    /// The tenant store and metadata entry are validated and locked before either is changed.
    /// A policy supplied here is a runtime update; it is intentionally not recorded as a
    /// pending startup override. Non-password values supplied here are retained for the current
    /// tenant lifetime so later project updates preserve them. The returned policy is the newly
    /// supplied policy, or the current policy when this operation only changes metadata.
    #[allow(clippy::needless_pass_by_value)]
    pub fn patch_tenant_with_password_policy(
        &self,
        project: &str,
        tenant: &str,
        patch: TenantMetadataPatch,
        password_policy: Option<PasswordPolicy>,
    ) -> Option<(TenantMetadata, PasswordPolicy)> {
        if project.is_empty()
            || project.contains(['/', '\\'])
            || tenant.is_empty()
            || tenant.contains(['/', '\\'])
        {
            return None;
        }
        let gate = self.operation_gate(project, None)?;
        let _operation = gate.lock().ok()?;
        let key = (project.to_owned(), tenant.to_owned());
        let tenants = self.tenants.lock().ok()?;
        let store = tenants.get(&key).cloned()?;
        let mut metadata = self.tenant_metadata.lock().ok()?;
        let current_metadata = metadata.get(&key)?.clone();
        let config_override = patch.config_override();
        let mut overrides = if config_override.is_empty() {
            None
        } else {
            Some(self.tenant_runtime_config_overrides.lock().ok()?)
        };
        let mut store = store.lock().ok()?;

        let mut next_metadata = current_metadata;
        patch.apply_to(&mut next_metadata);
        let next_policy = password_policy
            .clone()
            .unwrap_or_else(|| store.password_policy.clone());
        let mut next_config = store.config();
        patch.apply_to_project_config(&mut next_config);
        next_metadata.apply_effective_config(next_config);

        *metadata.get_mut(&key)? = next_metadata.clone();
        store.set_config(next_config);
        if let Some(policy) = password_policy {
            store.set_password_policy(policy.clone());
        }
        if let Some(overrides) = &mut overrides {
            let previous = overrides.get(&key).copied().unwrap_or_default();
            overrides.insert(key, previous.merge(config_override));
        }
        Some((next_metadata, next_policy))
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

    /// Replaces inherited project settings through the same atomic boundary as partial updates.
    pub fn set_project_config(&self, project: &str, config: ProjectAuthConfig) -> bool {
        self.patch_project_config(
            project,
            ProjectAuthConfigPatch {
                allow_duplicate_emails: Some(config.allow_duplicate_emails),
                enable_improved_email_privacy: Some(config.enable_improved_email_privacy),
                disabled_user_signup: Some(config.disabled_user_signup),
                disabled_user_deletion: Some(config.disabled_user_deletion),
            },
        )
        .is_some()
    }

    /// Applies selected settings against the current parent and every tenant atomically.
    ///
    /// Publication shares the project gate with every tenant creator. Membership and all
    /// affected stores are retained until commit, so poison or inconsistent tenant metadata
    /// refuses the entire update before any namespace changes. An empty patch only reads.
    pub fn patch_project_config(
        &self,
        project: &str,
        patch: ProjectAuthConfigPatch,
    ) -> Option<ProjectAuthConfig> {
        self.patch_project_config_with_password_policy(project, patch, None)
    }

    /// Applies a project Auth configuration patch and password-policy replacement as one
    /// namespace transition. Project configuration continues to propagate to every existing
    /// tenant, while the password policy remains scoped to the selected project namespace.
    /// Supplying a policy also records the explicit project override for namespaces that are
    /// registered or routed later. All locks and membership checks complete before any state is
    /// changed, so a failed transition cannot publish only part of the update.
    pub fn patch_project_config_with_password_policy(
        &self,
        project: &str,
        patch: ProjectAuthConfigPatch,
        password_policy: Option<PasswordPolicy>,
    ) -> Option<ProjectAuthConfig> {
        self.patch_project_config_with_password_policy_and_quota(
            project,
            patch,
            password_policy,
            None,
        )
    }

    /// Applies a project Auth configuration, password-policy, and local sign-up quota update
    /// under one namespace gate. The quota is project-scoped and is intentionally not copied to
    /// existing tenants. A supplied quota is validated before any setting is published, so an
    /// invalid candidate cannot leave a partially applied configuration behind.
    pub fn patch_project_config_with_password_policy_and_quota(
        &self,
        project: &str,
        patch: ProjectAuthConfigPatch,
        password_policy: Option<PasswordPolicy>,
        signup_quota: Option<SignupQuotaConfig>,
    ) -> Option<ProjectAuthConfig> {
        self.patch_project_config_with_current_settings(project, patch, |_, _| {
            Ok::<_, ()>((password_policy, signup_quota))
        })
        .ok()
        .flatten()
    }

    /// Replaces a project's sign-in configuration under the project's operation gate.
    /// `update` computes the new configuration from the current one; an invalid result is
    /// refused (`Ok(None)`) and changes nothing.
    pub fn update_project_sign_in_config<F, E>(
        &self,
        project: &str,
        update: F,
    ) -> Result<Option<SignInConfig>, E>
    where
        F: FnOnce(&SignInConfig) -> Result<SignInConfig, E>,
    {
        let Some(gate) = self.operation_gate(project, None) else {
            return Ok(None);
        };
        let Ok(_operation) = gate.lock() else {
            return Ok(None);
        };
        let Some(parent) = self.project_store(project) else {
            return Ok(None);
        };
        let Ok(mut parent) = parent.lock() else {
            return Ok(None);
        };
        let next = update(parent.sign_in_config())?;
        if parent.set_sign_in_config(next.clone()).is_err() {
            return Ok(None);
        }
        Ok(Some(next))
    }

    /// Applies a project settings update after taking the namespace gate and reading the
    /// current policy and quota under that same gate. The callback is used by adapters that
    /// decode a masked replacement from the current value; keeping that merge inside the gate
    /// prevents two disjoint concurrent PATCH requests from overwriting each other's fields.
    /// A callback error is returned to the caller without publishing any state.
    pub fn patch_project_config_with_current_settings<F, E>(
        &self,
        project: &str,
        patch: ProjectAuthConfigPatch,
        update: F,
    ) -> Result<Option<ProjectAuthConfig>, E>
    where
        F: FnOnce(
            &PasswordPolicy,
            &SignupQuotaConfig,
        ) -> Result<(Option<PasswordPolicy>, Option<SignupQuotaConfig>), E>,
    {
        let Some(gate) = self.operation_gate(project, None) else {
            return Ok(None);
        };
        let Ok(_operation) = gate.lock() else {
            return Ok(None);
        };
        let Some(parent) = self.project_store(project) else {
            return Ok(None);
        };
        let (current_policy, current_quota) = {
            let Ok(parent) = parent.lock() else {
                return Ok(None);
            };
            (
                parent.password_policy().clone(),
                parent.signup_quota().config().clone(),
            )
        };
        let (password_policy, signup_quota) = update(&current_policy, &current_quota)?;
        if let Some(quota) = signup_quota.as_ref() {
            if SignupQuota::new(quota.clone()).is_err() {
                return Ok(None);
            }
        }
        Ok(self.patch_project_config_under_gate(project, patch, password_policy, signup_quota))
    }

    /// Registers a non-password Auth config override without creating the project namespace.
    ///
    /// The selected fields are applied immediately when the exact project already exists, or at
    /// the publication boundary when it is registered later. The override is never copied to a
    /// different project or directly to a tenant.
    pub fn register_project_config_override(
        &self,
        project: &str,
        patch: AuthNamespaceConfigPatch,
    ) -> bool {
        if project.is_empty() || project.contains(['/', '\\']) || patch.is_empty() {
            return false;
        }
        let Some(gate) = self.operation_gate(project, None) else {
            return false;
        };
        let Ok(_operation) = gate.lock() else {
            return false;
        };
        let Ok(projects) = self.projects.lock() else {
            return false;
        };
        let existing = if project == self.default_project {
            Some(self.default.clone())
        } else {
            projects
                .registered
                .get(project)
                .or_else(|| projects.routed.get(project))
                .cloned()
        };
        let Ok(mut overrides) = self.project_config_overrides.lock() else {
            return false;
        };
        if let Some(store) = existing {
            let Ok(mut store) = store.lock() else {
                return false;
            };
            let next_config = patch.apply_to(store.config());
            store.set_config(next_config);
        }
        overrides.insert(project.to_owned(), patch);
        true
    }

    /// Registers an explicit project password policy without creating that project namespace.
    ///
    /// The policy is applied immediately when the namespace already exists and is applied at
    /// the publication boundary when a routed or explicit project store is later registered.
    /// This does not create a project and never applies the policy to another project.
    pub fn register_project_password_policy_override(
        &self,
        project: &str,
        policy: PasswordPolicy,
    ) -> bool {
        if project.is_empty() || project.contains(['/', '\\']) {
            return false;
        }
        let Some(gate) = self.operation_gate(project, None) else {
            return false;
        };
        let Ok(_operation) = gate.lock() else {
            return false;
        };
        let Ok(projects) = self.projects.lock() else {
            return false;
        };
        let existing = if project == self.default_project {
            Some(self.default.clone())
        } else {
            projects
                .registered
                .get(project)
                .or_else(|| projects.routed.get(project))
                .cloned()
        };
        let Ok(mut overrides) = self.project_password_policy_overrides.lock() else {
            return false;
        };
        if let Some(store) = existing {
            let Ok(mut store) = store.lock() else {
                return false;
            };
            store.set_password_policy(policy.clone());
        }
        overrides.insert(project.to_owned(), policy);
        true
    }

    /// Replaces only the default project namespace's password policy. Tenant policies are
    /// deliberately not inherited: callers must publish them through
    /// [`Self::set_tenant_password_policy`] after resolving an explicit tenant override.
    pub fn set_project_password_policy(&self, project: &str, policy: PasswordPolicy) -> bool {
        if project == self.default_project {
            return self.register_project_password_policy_override(project, policy);
        }
        let Some(gate) = self.operation_gate(project, None) else {
            return false;
        };
        let Ok(_operation) = gate.lock() else {
            return false;
        };
        let Ok(projects) = self.projects.lock() else {
            return false;
        };
        let Some(store) = projects
            .registered
            .get(project)
            .or_else(|| projects.routed.get(project))
            .cloned()
        else {
            return false;
        };
        let Ok(mut overrides) = self.project_password_policy_overrides.lock() else {
            return false;
        };
        let Ok(mut store) = store.lock() else {
            return false;
        };
        store.set_password_policy(policy.clone());
        overrides.insert(project.to_owned(), policy);
        true
    }

    /// Replaces one explicitly selected tenant's password policy. This operation does not
    /// create a tenant and cannot cross a project boundary.
    pub fn set_tenant_password_policy(
        &self,
        project: &str,
        tenant: &str,
        policy: PasswordPolicy,
    ) -> bool {
        self.patch_tenant_with_password_policy(
            project,
            tenant,
            TenantMetadataPatch::default(),
            Some(policy),
        )
        .is_some()
    }

    /// Registers an explicit password policy for a tenant without creating that tenant.
    ///
    /// The policy is applied immediately when the namespace already exists and is applied at
    /// the publication boundary when [`Self::ensure_tenant`] or [`Self::create_tenant`] later
    /// creates the exact `(project, tenant)` namespace. No project policy is inherited.
    pub fn register_tenant_password_policy_override(
        &self,
        project: &str,
        tenant: &str,
        policy: PasswordPolicy,
    ) -> bool {
        if project.is_empty()
            || project.contains(['/', '\\'])
            || tenant.is_empty()
            || tenant.contains(['/', '\\'])
        {
            return false;
        }
        let Some(gate) = self.operation_gate(project, None) else {
            return false;
        };
        let Ok(_operation) = gate.lock() else {
            return false;
        };
        let key = (project.to_owned(), tenant.to_owned());
        let tenants = self.tenants.lock().ok();
        let Some(tenants) = tenants else {
            return false;
        };
        let existing = tenants.get(&key).cloned();
        let Ok(mut overrides) = self.password_policy_overrides.lock() else {
            return false;
        };
        if let Some(store) = existing {
            let Ok(mut store) = store.lock() else {
                return false;
            };
            store.set_password_policy(policy.clone());
        }
        overrides.insert(key, policy);
        true
    }

    /// Registers a non-password Auth config override without creating the tenant namespace.
    ///
    /// An existing tenant receives the selected settings atomically in both its metadata and
    /// store. A future tenant receives them only when the exact `(project, tenant)` namespace is
    /// published; no project setting or sibling tenant is consulted.
    pub fn register_tenant_config_override(
        &self,
        project: &str,
        tenant: &str,
        patch: AuthNamespaceConfigPatch,
    ) -> bool {
        if project.is_empty()
            || project.contains(['/', '\\'])
            || tenant.is_empty()
            || tenant.contains(['/', '\\'])
            || patch.is_empty()
        {
            return false;
        }
        let Some(gate) = self.operation_gate(project, None) else {
            return false;
        };
        let Ok(_operation) = gate.lock() else {
            return false;
        };
        let key = (project.to_owned(), tenant.to_owned());
        let Ok(tenants) = self.tenants.lock() else {
            return false;
        };
        let existing = tenants.get(&key).cloned();
        let Ok(mut metadata) = self.tenant_metadata.lock() else {
            return false;
        };
        let Ok(mut overrides) = self.tenant_config_overrides.lock() else {
            return false;
        };
        let previous = overrides.get(&key).copied().unwrap_or_default();
        let merged = previous.merge(patch);
        if let Some(store) = existing {
            let Some(current_metadata) = metadata.get(&key).cloned() else {
                return false;
            };
            let Ok(mut store) = store.lock() else {
                return false;
            };
            let next_config = merged.apply_to(store.config());
            let mut next_metadata = current_metadata;
            merged.apply_to_metadata(&mut next_metadata);
            let Some(metadata) = metadata.get_mut(&key) else {
                return false;
            };
            *metadata = next_metadata;
            store.set_config(next_config);
        }
        overrides.insert(key, merged);
        true
    }

    fn patch_project_config_under_gate(
        &self,
        project: &str,
        patch: ProjectAuthConfigPatch,
        password_policy: Option<PasswordPolicy>,
        signup_quota: Option<SignupQuotaConfig>,
    ) -> Option<ProjectAuthConfig> {
        let projects = self.projects.lock().ok()?;
        let parent = if project == self.default_project {
            &self.default
        } else {
            projects
                .registered
                .get(project)
                .or_else(|| projects.routed.get(project))?
        };
        if patch.is_empty() && password_policy.is_none() && signup_quota.is_none() {
            return Some(parent.lock().ok()?.config());
        }
        if !patch.is_empty() {
            let tenants = self.tenants.lock().ok()?;
            let mut metadata = self.tenant_metadata.lock().ok()?;
            if tenants
                .keys()
                .filter(|(candidate, _)| candidate == project)
                .ne(metadata
                    .keys()
                    .filter(|(candidate, _)| candidate == project))
            {
                return None;
            }
            // A project update changes inherited fields on every tenant, but must reapply each
            // tenant's own override so an unrelated project PATCH cannot enable a disabled
            // tenant. The registry lock order is membership -> tenant metadata -> overrides ->
            // stores; take a snapshot before acquiring any store lock.
            let startup_overrides = self.tenant_config_overrides.lock().ok()?;
            let runtime_overrides = self.tenant_runtime_config_overrides.lock().ok()?;
            let tenant_stores = tenants
                .iter()
                .filter(|((candidate, _), _)| candidate == project)
                .map(|(key, store)| (key.clone(), store))
                .collect::<Vec<_>>();
            let tenant_overrides = tenant_stores
                .iter()
                .map(|(key, _)| {
                    let startup = startup_overrides.get(key).copied().unwrap_or_default();
                    let runtime = runtime_overrides.get(key).copied().unwrap_or_default();
                    (key.clone(), startup.merge(runtime))
                })
                .collect::<BTreeMap<_, _>>();
            if tenant_stores
                .iter()
                .any(|(key, _)| !metadata.contains_key(key))
            {
                return None;
            }
            let mut overrides = match password_policy.as_ref() {
                Some(_) => Some(self.project_password_policy_overrides.lock().ok()?),
                None => None,
            };
            let mut parent = parent.lock().ok()?;
            let config = patch.apply_to(parent.config());
            let mut tenant_guards = Vec::with_capacity(tenant_stores.len());
            for (_, store) in &tenant_stores {
                tenant_guards.push(store.lock().ok()?);
            }
            parent.set_config(config);
            for ((key, _), tenant) in tenant_stores.iter().zip(&mut tenant_guards) {
                let tenant_config = tenant_overrides
                    .get(key)
                    .copied()
                    .map_or(config, |override_patch| override_patch.apply_to(config));
                tenant.set_config(tenant_config);
            }
            for (key, _) in &tenant_stores {
                let tenant_config = tenant_overrides
                    .get(key)
                    .copied()
                    .map_or(config, |override_patch| override_patch.apply_to(config));
                metadata.get_mut(key)?.apply_effective_config(tenant_config);
            }
            if let Some(password_policy) = password_policy {
                parent.set_password_policy(password_policy.clone());
                overrides
                    .as_mut()
                    .expect("a password policy patch holds the override lock")
                    .insert(project.to_owned(), password_policy);
            }
            if let Some(quota) = signup_quota {
                parent.set_signup_quota_config(quota).ok()?;
            }
            return Some(config);
        }
        let mut overrides = match password_policy.as_ref() {
            Some(_) => Some(self.project_password_policy_overrides.lock().ok()?),
            None => None,
        };
        let mut parent = parent.lock().ok()?;
        let config = patch.apply_to(parent.config());
        if let Some(password_policy) = password_policy {
            parent.set_password_policy(password_policy.clone());
            overrides
                .as_mut()
                .expect("a password policy patch holds the override lock")
                .insert(project.to_owned(), password_policy);
        }
        if let Some(quota) = signup_quota {
            parent.set_signup_quota_config(quota).ok()?;
        }
        Some(config)
    }

    fn project_store(&self, project: &str) -> Option<SharedAuthStore> {
        if project == self.default_project {
            return Some(self.default.clone());
        }
        let projects = self.projects.lock().ok()?;
        projects
            .registered
            .get(project)
            .or_else(|| projects.routed.get(project))
            .cloned()
    }

    /// Deletes a tenant namespace and its metadata.
    pub fn delete_tenant(&self, project: &str, tenant: &str) -> bool {
        // Tenant authentication and tenant configuration updates use the project gate. Hold the
        // same gate before inspecting membership so deletion cannot detach a namespace while an
        // in-flight request is committing against its previously selected store.
        let Some(gate) = self.operation_gate(project, None) else {
            return false;
        };
        let Ok(_operation) = gate.lock() else {
            return false;
        };
        let key = (project.to_owned(), tenant.to_owned());
        let removed = self.tenants.lock().ok().and_then(|mut stores| {
            let mut metadata = self.tenant_metadata.lock().ok()?;
            let mut runtime_overrides = self.tenant_runtime_config_overrides.lock().ok()?;
            let removed = stores.remove(&key).is_some();
            metadata.remove(&key);
            if removed {
                runtime_overrides.remove(&key);
            }
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

    use super::{
        AuthLifecycleEpoch, AuthSnapshot, AuthStore, LocalId, NewUser, OAuthResponseType,
        OidcProviderConfig,
    };
    use crate::jwt::{
        encode_unsigned, verify_id_token, verify_rules_token, JwtError, TokenAcceptance,
    };
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

    #[test]
    fn provider_config_credentials_are_never_captured_or_restored_across_namespaces() {
        let mut source = AuthStore::new("source", SplitMix64::new(1), TotpPolicy::default());
        assert!(source.create_oidc_config(OidcProviderConfig {
            id: "oidc.source".to_owned(),
            display_name: Some("Source".to_owned()),
            enabled: true,
            client_id: "client".to_owned(),
            issuer: "https://issuer.example".to_owned(),
            client_secret: Some("raw-secret-must-not-travel".to_owned()),
            response_type: OAuthResponseType {
                code: true,
                ..OAuthResponseType::default()
            },
        }));
        let mut destination =
            AuthStore::new("destination", SplitMix64::new(2), TotpPolicy::default());
        assert!(destination.create_oidc_config(OidcProviderConfig {
            id: "oidc.destination".to_owned(),
            display_name: None,
            enabled: false,
            client_id: "destination-client".to_owned(),
            issuer: "https://destination.example".to_owned(),
            client_secret: None,
            response_type: OAuthResponseType::default(),
        }));

        let snapshot = AuthSnapshot::capture(&source);
        assert!(snapshot.0.oidc_configs.is_empty());
        assert!(!format!("{source:?}").contains("raw-secret-must-not-travel"));
        snapshot.restore_into(&mut destination);
        assert!(destination.oidc_config("oidc.source").is_none());
        assert!(destination.oidc_config("oidc.destination").is_some());
    }

    /// A legacy token carries its store's session epoch and is refused by a later incarnation
    /// or by a tenant store, as ID tokens are (closure review S1).
    #[test]
    fn legacy_tokens_are_bound_to_their_session_epoch_and_namespace() {
        let mut live = store();
        live.set_lifecycle_epoch(AuthLifecycleEpoch::initial(17, 1));
        let uid = live
            .create_user_with_id(NewUser::email("legacy@example.test"), Some("legacy"), AT)
            .unwrap();
        let at_secs = i64::try_from(AT.as_nanos().div_euclid(1_000_000_000)).unwrap();
        let payload = live
            .legacy_token_payload(&uid, at_secs, "password", None)
            .unwrap();
        assert!(payload.contains("fireemu_session_epoch"), "{payload}");
        let token =
            crate::jwt::encode_payload_shaped(&payload, None, crate::jwt::HeaderShape::Untyped);
        assert!(crate::jwt::verify_legacy_token(&token, &live, AT, 0).is_ok());
        let mut stripped = live.clone();
        stripped.set_lifecycle_epoch(AuthLifecycleEpoch::initial(17, 2));
        assert!(matches!(
            crate::jwt::verify_legacy_token(&token, &stripped, AT, 0),
            Err(JwtError::WrongSessionEpoch { .. })
        ));
        let mut tenant = AuthStore::new_tenant(
            "demo",
            "tenant-a",
            SplitMix64::new(9),
            TotpPolicy::default(),
        );
        let tenant_uid = tenant
            .create_user_with_id(NewUser::email("t@example.test"), Some("legacy"), AT)
            .unwrap();
        let tenant_payload = tenant
            .legacy_token_payload(&tenant_uid, at_secs, "password", None)
            .unwrap();
        let tenant_token = crate::jwt::encode_payload_shaped(
            &tenant_payload,
            None,
            crate::jwt::HeaderShape::Untyped,
        );
        assert!(matches!(
            crate::jwt::verify_legacy_token(&tenant_token, &tenant, AT, 0),
            Err(JwtError::WrongTenant { .. })
        ));
    }

    #[test]
    fn clearing_a_session_store_invalidates_same_second_id_and_refresh_credentials() {
        let mut live = store();
        live.set_lifecycle_epoch(AuthLifecycleEpoch::initial(17, 1));
        let uid = live
            .create_user_with_id(
                NewUser::email("before-reset@example.test"),
                Some("same-user"),
                AT,
            )
            .unwrap();
        let stale_id = encode_unsigned(&live.id_token_claims(&uid, None, AT).unwrap());
        let mut stripped_claims = live.id_token_claims(&uid, None, AT).unwrap();
        stripped_claims.firebase.fireemu_session_epoch = None;
        let stripped_mock = encode_unsigned(&stripped_claims);
        let stale_refresh = live.issue_refresh_token(&uid, AT).unwrap();

        live.clear();
        let recreated = live
            .create_user_with_id(
                NewUser::email("after-reset@example.test"),
                Some("same-user"),
                AT,
            )
            .unwrap();
        let fresh_id = encode_unsigned(&live.id_token_claims(&recreated, None, AT).unwrap());
        let fresh_refresh = live.issue_refresh_token(&recreated, AT).unwrap();

        assert!(matches!(
            verify_id_token(&stale_id, &live, AT),
            Err(JwtError::WrongSessionEpoch { .. })
        ));
        assert!(
            verify_rules_token(&stale_id, &live, AT, TokenAcceptance::EmulatorMock).is_ok(),
            "an unsigned emulator mock is caller-provided identity, not an issued credential"
        );
        assert!(matches!(
            verify_id_token(&stripped_mock, &live, AT),
            Err(JwtError::WrongSessionEpoch { actual: None, .. })
        ));
        assert!(
            verify_rules_token(&stripped_mock, &live, AT, TokenAcceptance::EmulatorMock).is_ok(),
            "the mock profile deliberately accepts an unsigned caller-provided identity"
        );
        assert!(verify_id_token(&fresh_id, &live, AT).is_ok());
        assert!(matches!(
            live.redeem_refresh_token(&stale_refresh),
            Err(super::AuthError::InvalidRefreshToken)
        ));
        assert!(live.redeem_refresh_token(&fresh_refresh).is_ok());
    }

    #[test]
    fn restoring_a_session_snapshot_invalidates_every_pre_restore_id_token() {
        let mut live = store();
        live.set_lifecycle_epoch(AuthLifecycleEpoch::initial(23, 1));
        let uid = live
            .create_user_with_id(
                NewUser::email("snapshot@example.test"),
                Some("snapshot-user"),
                AT,
            )
            .unwrap();
        let snapshot_refresh = live.issue_refresh_token(&uid, AT).unwrap();
        let snapshot_id = encode_unsigned(&live.id_token_claims(&uid, None, AT).unwrap());
        let snapshot = AuthSnapshot::capture(&live);
        let later = AT
            .checked_add(fireemu_core_types::time::LogicalDuration::from_seconds(1))
            .unwrap();
        let live_id = encode_unsigned(&live.id_token_claims(&uid, None, later).unwrap());

        snapshot.restore_into(&mut live);

        for stale in [&snapshot_id, &live_id] {
            assert!(matches!(
                verify_id_token(stale, &live, later),
                Err(JwtError::WrongSessionEpoch { .. })
            ));
        }
        let fresh = encode_unsigned(&live.id_token_claims(&uid, None, later).unwrap());
        assert!(verify_id_token(&fresh, &live, later).is_ok());
        assert!(
            live.redeem_refresh_token(&snapshot_refresh).is_ok(),
            "a same-namespace snapshot intentionally restores its captured refresh credential"
        );
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
        AuthRegistry, AuthStore, CompatibilityUserStoreMatch, NewUser, ProjectAuthConfig,
        RefreshTokenStoreMatch, RoutedStoreInstall, TenantMetadata, TenantMetadataPatch,
    };
    use crate::jwt::{encode_unsigned, verify_id_token, verify_rules_token, TokenAcceptance};
    use crate::mfa::TotpPolicy;
    use fireemu_core_types::determinism::SplitMix64;
    use fireemu_core_types::time::LogicalInstant;
    use std::collections::BTreeMap;
    use std::sync::atomic::Ordering;
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
    fn default_scope_import_publishes_default_and_tenants_together() {
        let default = store("demo-app", 1);
        default
            .lock()
            .unwrap()
            .create_user(NewUser::email("before@example.test"), NOW)
            .unwrap();
        let registry = AuthRegistry::new("demo-app", default.clone());
        let old_tenant = registry.ensure_tenant("demo-app", "old").unwrap();
        old_tenant
            .lock()
            .unwrap()
            .create_user(NewUser::email("old@example.test"), NOW)
            .unwrap();

        let mut default_candidate =
            AuthStore::new("demo-app", SplitMix64::new(10), TotpPolicy::default());
        default_candidate
            .create_user(NewUser::email("after@example.test"), NOW)
            .unwrap();
        let mut tenant_candidate = AuthStore::new_tenant(
            "demo-app",
            "new",
            SplitMix64::new(11),
            TotpPolicy::default(),
        );
        tenant_candidate
            .create_user(NewUser::email("new@example.test"), NOW)
            .unwrap();

        registry
            .replace_default_scope(
                "demo-app",
                default_candidate,
                vec![(
                    "new".to_owned(),
                    tenant_candidate,
                    TenantMetadata::default(),
                )],
            )
            .unwrap();

        assert_eq!(default.lock().unwrap().user_count(), 1);
        assert!(default
            .lock()
            .unwrap()
            .user_by_email("before@example.test")
            .is_none());
        assert!(default
            .lock()
            .unwrap()
            .user_by_email("after@example.test")
            .is_some());
        assert_eq!(registry.tenants("demo-app"), vec!["new".to_owned()]);
        assert!(registry.tenant_store("demo-app", "old").is_none());
        assert_eq!(
            registry
                .tenant_store("demo-app", "new")
                .unwrap()
                .lock()
                .unwrap()
                .user_count(),
            1
        );
    }

    #[test]
    fn failed_default_scope_import_preserves_every_live_namespace() {
        let default = store("demo-app", 1);
        default
            .lock()
            .unwrap()
            .create_user(NewUser::email("before@example.test"), NOW)
            .unwrap();
        let registry = Arc::new(AuthRegistry::new("demo-app", default.clone()));
        let tenant = registry.ensure_tenant("demo-app", "existing").unwrap();
        tenant
            .lock()
            .unwrap()
            .create_user(NewUser::email("tenant@example.test"), NOW)
            .unwrap();
        let generation = registry.membership_generation.load(Ordering::Acquire);
        let default_user_count = default.lock().unwrap().user_count();
        let tenant_user_count = tenant.lock().unwrap().user_count();

        // A malformed staged tenant candidate is rejected before any registry lock is changed.
        let invalid = AuthStore::new_tenant(
            "other-project",
            "replacement",
            SplitMix64::new(12),
            TotpPolicy::default(),
        );
        assert_eq!(
            registry.replace_default_scope(
                "demo-app",
                AuthStore::new("demo-app", SplitMix64::new(13), TotpPolicy::default()),
                vec![("replacement".to_owned(), invalid, TenantMetadata::default())],
            ),
            Err("invalid tenant Auth import candidate")
        );
        assert_eq!(default.lock().unwrap().user_count(), default_user_count);
        assert_eq!(tenant.lock().unwrap().user_count(), tenant_user_count);
        assert_eq!(registry.tenants("demo-app"), vec!["existing".to_owned()]);
        assert_eq!(
            registry.membership_generation.load(Ordering::Acquire),
            generation
        );

        // A poisoned live tenant is discovered while all affected stores are still untouched.
        let poison = tenant.clone();
        assert!(std::thread::spawn(move || {
            let _guard = poison.lock().unwrap();
            panic!("poison tenant during import publication");
        })
        .join()
        .is_err());
        let candidate = AuthStore::new_tenant(
            "demo-app",
            "replacement",
            SplitMix64::new(14),
            TotpPolicy::default(),
        );
        assert_eq!(
            registry.replace_default_scope(
                "demo-app",
                AuthStore::new("demo-app", SplitMix64::new(15), TotpPolicy::default()),
                vec![(
                    "replacement".to_owned(),
                    candidate,
                    TenantMetadata::default()
                )],
            ),
            Err("an Auth tenant store is poisoned")
        );
        assert_eq!(default.lock().unwrap().user_count(), default_user_count);
        assert_eq!(registry.tenants("demo-app"), vec!["existing".to_owned()]);
        assert_eq!(
            registry.membership_generation.load(Ordering::Acquire),
            generation
        );
    }

    #[test]
    fn lifecycle_serial_capacity_refusal_preserves_default_scope_import_state() {
        let default = store("demo-app", 1);
        default
            .lock()
            .unwrap()
            .create_user(NewUser::email("before@example.test"), NOW)
            .unwrap();
        let registry = AuthRegistry::with_project_numbers_and_lifecycle_incarnation(
            "demo-app",
            default.clone(),
            BTreeMap::new(),
            41,
        );
        registry
            .next_lifecycle_serial
            .store(u64::MAX - 1, Ordering::Release);
        let generation = registry.membership_generation.load(Ordering::Acquire);
        let candidates = ["one", "two"]
            .into_iter()
            .map(|tenant| {
                (
                    tenant.to_owned(),
                    AuthStore::new_tenant(
                        "demo-app",
                        tenant,
                        SplitMix64::new(20),
                        TotpPolicy::default(),
                    ),
                    TenantMetadata::default(),
                )
            })
            .collect();

        assert_eq!(
            registry.replace_default_scope(
                "demo-app",
                AuthStore::new("demo-app", SplitMix64::new(21), TotpPolicy::default()),
                candidates,
            ),
            Err("Auth lifecycle serial capacity exhausted")
        );
        assert_eq!(default.lock().unwrap().user_count(), 1);
        assert_eq!(registry.tenants("demo-app"), Vec::<String>::new());
        assert_eq!(
            registry.next_lifecycle_serial.load(Ordering::Acquire),
            u64::MAX - 1
        );
        assert_eq!(
            registry.membership_generation.load(Ordering::Acquire),
            generation
        );
    }

    #[test]
    fn project_config_poisoned_membership_or_store_preserves_every_namespace() {
        for target in ["projects", "tenants", "metadata", "parent", "tenant"] {
            let parent = store("demo-app", 1);
            let registry = Arc::new(AuthRegistry::new("demo-app", parent.clone()));
            let sibling = registry.ensure_tenant("demo-app", "alpha").unwrap();
            let tenant = registry.ensure_tenant("demo-app", "zulu").unwrap();
            let poison = registry.clone();
            let poisoned_parent = parent.clone();
            let poisoned_tenant = tenant.clone();
            assert!(std::thread::spawn(move || {
                match target {
                    "projects" => {
                        let _guard = poison.projects.lock().unwrap();
                        panic!("poison projects");
                    }
                    "tenants" => {
                        let _guard = poison.tenants.lock().unwrap();
                        panic!("poison tenants");
                    }
                    "metadata" => {
                        let _guard = poison.tenant_metadata.lock().unwrap();
                        panic!("poison metadata");
                    }
                    "parent" => {
                        let _guard = poisoned_parent.lock().unwrap();
                        panic!("poison parent");
                    }
                    _ => {
                        let _guard = poisoned_tenant.lock().unwrap();
                        panic!("poison tenant");
                    }
                }
            })
            .join()
            .is_err());
            assert!(
                !registry.set_project_config(
                    "demo-app",
                    super::ProjectAuthConfig {
                        allow_duplicate_emails: true,
                        enable_improved_email_privacy: true,
                        ..super::ProjectAuthConfig::default()
                    }
                ),
                "poisoned {target} must refuse the update"
            );
            for namespace in [&parent, &sibling, &tenant] {
                let guard = namespace
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                assert_eq!(
                    guard.config(),
                    super::ProjectAuthConfig::default(),
                    "poisoned {target}"
                );
            }
        }
    }

    #[test]
    fn direct_tenant_publication_obeys_the_project_operation_gate() {
        for explicit in [false, true] {
            let registry = Arc::new(AuthRegistry::new("demo-app", store("demo-app", 1)));
            let gate = registry.operation_gate("demo-app", None).unwrap();
            let operation = gate.lock().unwrap();
            let creator_registry = registry.clone();
            let (started_tx, started_rx) = mpsc::sync_channel(1);
            let (done_tx, done_rx) = mpsc::sync_channel(1);
            let creator = std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                let tenant = if explicit {
                    creator_registry
                        .create_tenant("demo-app", TenantMetadata::default())
                        .unwrap()
                } else {
                    creator_registry
                        .ensure_tenant("demo-app", "customer")
                        .unwrap();
                    "customer".to_owned()
                };
                done_tx.send(tenant).unwrap();
            });
            started_rx.recv().unwrap();
            let early = done_rx.recv_timeout(Duration::from_millis(100));
            // Model the config commit while publication is excluded by the project gate.
            registry
                .default
                .lock()
                .unwrap()
                .set_config(super::ProjectAuthConfig {
                    allow_duplicate_emails: true,
                    enable_improved_email_privacy: true,
                    ..super::ProjectAuthConfig::default()
                });
            drop(operation);
            let tenant = early
                .as_ref()
                .ok()
                .cloned()
                .unwrap_or_else(|| done_rx.recv_timeout(Duration::from_secs(2)).unwrap());
            creator.join().unwrap();
            assert!(
                early.is_err(),
                "direct tenant publication bypassed the project gate"
            );
            assert_eq!(
                registry
                    .tenant_store("demo-app", &tenant)
                    .unwrap()
                    .lock()
                    .unwrap()
                    .config(),
                registry.default.lock().unwrap().config()
            );
        }
    }

    #[test]
    fn tenant_deletion_waits_for_the_project_operation_gate() {
        let registry = Arc::new(AuthRegistry::new("demo-app", store("demo-app", 2)));
        let tenant = registry.ensure_tenant("demo-app", "customer").unwrap();
        let gate = registry.operation_gate("demo-app", None).unwrap();
        let operation = gate.lock().unwrap();
        let deleting_registry = registry.clone();
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let deletion = std::thread::spawn(move || {
            done_tx
                .send(deleting_registry.delete_tenant("demo-app", "customer"))
                .unwrap();
        });

        assert!(
            done_rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "tenant deletion must not detach a namespace while a project operation is active"
        );
        assert!(registry.tenant_store("demo-app", "customer").is_some());

        drop(operation);
        assert_eq!(done_rx.recv_timeout(Duration::from_secs(2)), Ok(true));
        deletion.join().unwrap();
        assert!(registry.tenant_store("demo-app", "customer").is_none());
        drop(tenant);
    }

    #[test]
    fn export_scope_capture_waits_for_the_project_operation_gate() {
        let default = store("demo-app", 1);
        let registry = Arc::new(AuthRegistry::new("demo-app", default.clone()));
        let tenant = registry.ensure_tenant("demo-app", "customer").unwrap();
        let initial_config = ProjectAuthConfig {
            allow_duplicate_emails: true,
            enable_improved_email_privacy: true,
            disabled_user_signup: false,
            disabled_user_deletion: false,
        };
        default.lock().unwrap().set_config(initial_config);
        tenant.lock().unwrap().set_config(initial_config);
        let initial_metadata = TenantMetadata {
            display_name: Some("Customer tenant".to_owned()),
            allow_password_signup: false,
            enable_email_link_signin: false,
            enable_anonymous_user: true,
            disable_auth: false,
            disabled_user_signup: true,
            disabled_user_deletion: false,
            enable_improved_email_privacy: true,
        };
        assert!(registry.update_tenant("demo-app", "customer", initial_metadata.clone()));
        let tenant_operation = tenant.lock().unwrap();
        let gate = registry.operation_gate("demo-app", None).unwrap();
        let operation = gate.lock().unwrap();
        let capture_registry = registry.clone();
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (captured_tx, captured_rx) = mpsc::sync_channel(1);
        let capture = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let snapshot = capture_registry
                .capture_export_snapshot("demo-app")
                .unwrap()
                .unwrap();
            captured_tx.send(snapshot).unwrap();
        });

        started_rx.recv().unwrap();
        assert!(
            captured_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "export capture must wait for the project operation gate"
        );
        drop(operation);

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut default_lock_observed = false;
        while Instant::now() < deadline {
            match default.try_lock() {
                Ok(guard) => drop(guard),
                Err(TryLockError::WouldBlock) => {
                    default_lock_observed = true;
                    break;
                }
                Err(TryLockError::Poisoned(_)) => panic!("default store poisoned"),
            }
            std::thread::yield_now();
        }
        assert!(
            default_lock_observed,
            "capture must retain the project lock while acquiring every tenant lock"
        );

        let next_config = ProjectAuthConfig {
            allow_duplicate_emails: true,
            enable_improved_email_privacy: true,
            disabled_user_signup: true,
            disabled_user_deletion: true,
        };
        let writer_default = default.clone();
        let (writer_done_tx, writer_done_rx) = mpsc::sync_channel(1);
        let writer = std::thread::spawn(move || {
            writer_default.lock().unwrap().set_config(next_config);
            writer_done_tx.send(()).unwrap();
        });
        assert!(
            writer_done_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "a store mutation must wait until the complete export view is captured"
        );
        drop(tenant_operation);

        let snapshot = captured_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("export capture completes after the gate is released");
        capture.join().unwrap();
        writer
            .join()
            .expect("the post-capture store mutation completes");
        assert_eq!(snapshot.default_store().config(), initial_config);
        assert_eq!(
            snapshot
                .tenant_stores()
                .find(|(id, _)| *id == "customer")
                .map(|(_, store)| store.config()),
            Some(initial_config)
        );
        assert_eq!(
            snapshot.tenant_metadata("customer"),
            Some(&initial_metadata)
        );
    }

    #[test]
    fn created_tenant_preserves_inherited_config_for_omitted_initial_fields() {
        let registry = AuthRegistry::new("demo-app", store("demo-app", 1));
        assert!(registry
            .patch_project_config(
                "demo-app",
                super::ProjectAuthConfigPatch {
                    enable_improved_email_privacy: Some(true),
                    ..super::ProjectAuthConfigPatch::default()
                }
            )
            .is_some());

        let (tenant, _, _) = registry
            .create_tenant_with_password_policy(
                "demo-app",
                TenantMetadata::default(),
                TenantMetadataPatch::default(),
                None,
            )
            .unwrap();
        let runtime = registry
            .tenant_store("demo-app", &tenant)
            .unwrap()
            .lock()
            .unwrap()
            .config();
        let metadata = registry.tenant_metadata("demo-app", &tenant).unwrap();
        assert!(runtime.enable_improved_email_privacy);
        assert_eq!(
            metadata.enable_improved_email_privacy,
            runtime.enable_improved_email_privacy
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn tenant_effective_config_preserves_explicit_false_and_project_isolation() {
        let default = store("demo-app", 1);
        let registry = AuthRegistry::new("demo-app", default.clone());
        registry.ensure_tenant("demo-app", "existing").unwrap();
        let inherited = super::ProjectAuthConfig {
            enable_improved_email_privacy: true,
            disabled_user_signup: true,
            disabled_user_deletion: true,
            ..super::ProjectAuthConfig::default()
        };
        assert!(registry.set_project_config("demo-app", inherited));
        let existing_config = registry
            .tenant_store("demo-app", "existing")
            .unwrap()
            .lock()
            .unwrap()
            .config();
        let existing_metadata = registry.tenant_metadata("demo-app", "existing").unwrap();
        assert_eq!(
            existing_metadata.disabled_user_signup,
            existing_config.disabled_user_signup
        );
        assert_eq!(
            existing_metadata.disabled_user_deletion,
            existing_config.disabled_user_deletion
        );
        assert_eq!(
            existing_metadata.enable_improved_email_privacy,
            existing_config.enable_improved_email_privacy
        );

        let (inherited_tenant, _, _) = registry
            .create_tenant_with_password_policy(
                "demo-app",
                TenantMetadata::default(),
                TenantMetadataPatch::default(),
                None,
            )
            .unwrap();
        let inherited_store = registry
            .tenant_store("demo-app", &inherited_tenant)
            .unwrap();
        let inherited_store_config = inherited_store.lock().unwrap().config();
        let inherited_metadata = registry
            .tenant_metadata("demo-app", &inherited_tenant)
            .unwrap();
        assert_eq!(
            inherited_metadata.enable_improved_email_privacy,
            inherited_store_config.enable_improved_email_privacy
        );
        assert_eq!(
            inherited_metadata.disabled_user_signup,
            inherited_store_config.disabled_user_signup
        );
        assert_eq!(
            inherited_metadata.disabled_user_deletion,
            inherited_store_config.disabled_user_deletion
        );

        let (explicit_false_tenant, _, _) = registry
            .create_tenant_with_password_policy(
                "demo-app",
                TenantMetadata::default(),
                TenantMetadataPatch {
                    enable_improved_email_privacy: Some(false),
                    disabled_user_signup: Some(false),
                    disabled_user_deletion: Some(false),
                    ..TenantMetadataPatch::default()
                },
                None,
            )
            .unwrap();
        let explicit_false_store = registry
            .tenant_store("demo-app", &explicit_false_tenant)
            .unwrap();
        let explicit_false_config = explicit_false_store.lock().unwrap().config();
        let explicit_false_metadata = registry
            .tenant_metadata("demo-app", &explicit_false_tenant)
            .unwrap();
        assert_eq!(explicit_false_config, super::ProjectAuthConfig::default());
        assert_eq!(
            explicit_false_metadata.enable_improved_email_privacy,
            explicit_false_config.enable_improved_email_privacy
        );
        assert_eq!(
            explicit_false_metadata.disabled_user_signup,
            explicit_false_config.disabled_user_signup
        );
        assert_eq!(
            explicit_false_metadata.disabled_user_deletion,
            explicit_false_config.disabled_user_deletion
        );

        let other = AuthStore::new("other-project", SplitMix64::new(2), TotpPolicy::default());
        assert!(registry.register("other-project", other));
        let (other_tenant, _, _) = registry
            .create_tenant_with_password_policy(
                "other-project",
                TenantMetadata::default(),
                TenantMetadataPatch::default(),
                None,
            )
            .unwrap();
        let other_store = registry
            .tenant_store("other-project", &other_tenant)
            .unwrap();
        assert_eq!(
            other_store.lock().unwrap().config(),
            super::ProjectAuthConfig::default()
        );
        assert!(
            !registry
                .tenant_metadata("other-project", &other_tenant)
                .unwrap()
                .enable_improved_email_privacy
        );
    }

    #[test]
    fn project_config_patch_waits_for_direct_tenant_publication() {
        for explicit in [false, true] {
            let registry = Arc::new(AuthRegistry::new("demo-app", store("demo-app", 1)));
            let gate = registry.operation_gate("demo-app", None).unwrap();
            let metadata = registry.tenant_metadata.lock().unwrap();
            let creator_registry = registry.clone();
            let creator = std::thread::spawn(move || {
                if explicit {
                    creator_registry
                        .create_tenant("demo-app", TenantMetadata::default())
                        .unwrap()
                } else {
                    creator_registry
                        .ensure_tenant("demo-app", "customer")
                        .unwrap();
                    "customer".to_owned()
                }
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match registry.tenants.try_lock() {
                    Err(TryLockError::WouldBlock) => break,
                    Err(TryLockError::Poisoned(_)) => panic!("tenant registry poisoned"),
                    Ok(guard) => drop(guard),
                }
                assert!(
                    Instant::now() < deadline,
                    "creator did not reach membership boundary"
                );
                std::thread::yield_now();
            }
            let patch_registry = registry.clone();
            let patcher = std::thread::spawn(move || {
                patch_registry.patch_project_config(
                    "demo-app",
                    super::ProjectAuthConfigPatch {
                        allow_duplicate_emails: Some(true),
                        enable_improved_email_privacy: Some(true),
                        disabled_user_signup: None,
                        disabled_user_deletion: None,
                    },
                )
            });
            while Arc::strong_count(&gate) < 3 {
                assert!(
                    Instant::now() < deadline,
                    "patch did not reach the shared project gate"
                );
                std::thread::yield_now();
            }
            assert_eq!(
                registry.default.lock().unwrap().config(),
                super::ProjectAuthConfig::default()
            );
            drop(metadata);
            let tenant = creator.join().unwrap();
            let config = patcher.join().unwrap().unwrap();
            assert!(config.enable_improved_email_privacy && config.allow_duplicate_emails);
            assert_eq!(
                registry
                    .tenant_store("demo-app", &tenant)
                    .unwrap()
                    .lock()
                    .unwrap()
                    .config(),
                config
            );
        }
    }

    #[test]
    fn project_config_patch_rejects_inconsistent_tenant_membership_before_writing() {
        for missing_store in [false, true] {
            let registry = AuthRegistry::new("demo-app", store("demo-app", 1));
            let tenant = registry.ensure_tenant("demo-app", "customer").unwrap();
            let key = ("demo-app".to_owned(), "customer".to_owned());
            if missing_store {
                registry.tenants.lock().unwrap().remove(&key);
            } else {
                registry.tenant_metadata.lock().unwrap().remove(&key);
            }
            assert!(registry
                .patch_project_config(
                    "demo-app",
                    super::ProjectAuthConfigPatch {
                        enable_improved_email_privacy: Some(true),
                        ..super::ProjectAuthConfigPatch::default()
                    }
                )
                .is_none());
            assert_eq!(
                registry.default.lock().unwrap().config(),
                super::ProjectAuthConfig::default()
            );
            assert_eq!(
                tenant.lock().unwrap().config(),
                super::ProjectAuthConfig::default()
            );
        }
    }

    #[test]
    fn project_config_empty_patch_reads_without_rewriting_tenants() {
        let registry = AuthRegistry::new("demo-app", store("demo-app", 1));
        let tenant = registry.ensure_tenant("demo-app", "customer").unwrap();
        tenant.lock().unwrap().set_config(super::ProjectAuthConfig {
            allow_duplicate_emails: true,
            enable_improved_email_privacy: true,
            ..super::ProjectAuthConfig::default()
        });
        assert_eq!(
            registry.patch_project_config("demo-app", super::ProjectAuthConfigPatch::default()),
            Some(super::ProjectAuthConfig::default())
        );
        assert!(
            tenant
                .lock()
                .unwrap()
                .config()
                .enable_improved_email_privacy
        );
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
    fn session_registration_replaces_only_the_exact_routed_namespace() {
        let default = store("demo-app", 1);
        let registry = AuthRegistry::with_project_numbers(
            "demo-app",
            default,
            BTreeMap::from([("worker-alpha".to_owned(), 222)]),
        );
        let mut routed = registry.routed_candidate("worker-alpha").unwrap();
        let uid = routed
            .create_user(NewUser::email("routed@example.test"), NOW)
            .unwrap();
        let routed_token = routed.issue_refresh_token(&uid, NOW).unwrap();
        assert!(matches!(
            registry.install_routed("worker-alpha", Arc::new(Mutex::new(routed))),
            RoutedStoreInstall::Installed(_)
        ));

        assert!(!registry.register_session(
            "worker-alpha",
            AuthStore::new("worker-beta", SplitMix64::new(3), TotpPolicy::default())
        ));
        assert!(registry.routed_store_for("worker-alpha").is_some());

        assert!(registry.register_session(
            "worker-alpha",
            AuthStore::new("worker-alpha", SplitMix64::new(4), TotpPolicy::default())
        ));
        assert!(registry.commit_session("worker-alpha"));
        assert!(registry.routed_store_for("worker-alpha").is_none());
        assert_eq!(registry.routed_count(), 0);
        let registered = registry.store_for("worker-alpha").unwrap();
        let registered = registered.lock().unwrap();
        assert_eq!(registered.project_number(), Some(222));
        assert_eq!(registered.user_count(), 0);
        drop(registered);
        assert!(matches!(
            registry.store_for_refresh_token(&routed_token),
            RefreshTokenStoreMatch::NotFound
        ));
    }

    #[test]
    fn session_registration_rejects_a_routed_id_token_for_a_recreated_uid_in_the_same_second() {
        let default = store("demo-app", 1);
        let registry = AuthRegistry::with_project_numbers_and_lifecycle_incarnation(
            "demo-app",
            default,
            BTreeMap::new(),
            41,
        );
        let mut routed = registry.routed_candidate("worker-alpha").unwrap();
        let uid = routed
            .create_user_with_id(
                NewUser::email("routed@example.test"),
                Some("same-user"),
                NOW,
            )
            .unwrap();
        let old_token = encode_unsigned(&routed.id_token_claims(&uid, None, NOW).unwrap());
        let old_refresh = routed.issue_refresh_token(&uid, NOW).unwrap();
        assert!(matches!(
            registry.install_routed("worker-alpha", Arc::new(Mutex::new(routed))),
            RoutedStoreInstall::Installed(_)
        ));

        assert!(registry.register_session(
            "worker-alpha",
            AuthStore::new("worker-alpha", SplitMix64::new(2), TotpPolicy::default())
        ));
        assert!(registry.commit_session("worker-alpha"));
        let registered = registry.store_for("worker-alpha").unwrap();
        let mut registered = registered.lock().unwrap();
        let recreated = registered
            .create_user_with_id(NewUser::email("new@example.test"), Some("same-user"), NOW)
            .unwrap();
        let new_token =
            encode_unsigned(&registered.id_token_claims(&recreated, None, NOW).unwrap());

        assert!(matches!(
            verify_id_token(&old_token, &registered, NOW),
            Err(crate::jwt::JwtError::WrongSessionEpoch { .. })
        ));
        assert!(
            verify_rules_token(&old_token, &registered, NOW, TokenAcceptance::EmulatorMock).is_ok(),
            "unsigned EmulatorMock identity is not an issued credential"
        );
        assert!(verify_id_token(&new_token, &registered, NOW).is_ok());
        let new_refresh = registered.issue_refresh_token(&recreated, NOW).unwrap();
        drop(registered);
        assert!(matches!(
            registry.store_for_refresh_token(&old_refresh),
            RefreshTokenStoreMatch::NotFound
        ));
        assert!(matches!(
            registry.store_for_refresh_token(&new_refresh),
            RefreshTokenStoreMatch::Unique(_)
        ));
        assert_eq!(
            registry.rollback_session("worker-alpha"),
            super::SessionRegistrationRollback::NotPending
        );
    }

    #[test]
    fn lifecycle_serial_exhaustion_refuses_before_publishing_a_namespace() {
        let default = store("demo-app", 1);
        let registry = AuthRegistry::with_project_numbers_and_lifecycle_incarnation(
            "demo-app",
            default,
            BTreeMap::new(),
            41,
        );
        registry
            .next_lifecycle_serial
            .store(u64::MAX, Ordering::Release);

        assert!(registry.routed_candidate("worker-alpha").is_none());
        assert!(!registry.register(
            "worker-alpha",
            AuthStore::new("worker-alpha", SplitMix64::new(2), TotpPolicy::default())
        ));
        assert!(registry.store_for("worker-alpha").is_none());
        assert_eq!(registry.routed_count(), 0);
    }

    #[test]
    fn poisoned_tenant_refuses_project_reset_before_mutating_any_namespace() {
        let registry = Arc::new(
            AuthRegistry::with_project_numbers_and_lifecycle_incarnation(
                "demo-app",
                store("demo-app", 1),
                BTreeMap::new(),
                41,
            ),
        );
        assert!(registry.register(
            "worker-alpha",
            AuthStore::new("worker-alpha", SplitMix64::new(2), TotpPolicy::default())
        ));
        let parent = registry.store_for("worker-alpha").unwrap();
        parent
            .lock()
            .unwrap()
            .create_user(NewUser::email("parent@example.test"), NOW)
            .unwrap();
        let poisoned = registry
            .ensure_tenant("worker-alpha", "customer-a")
            .unwrap();
        let sibling = registry
            .ensure_tenant("worker-alpha", "customer-b")
            .unwrap();
        sibling
            .lock()
            .unwrap()
            .create_user(NewUser::email("sibling@example.test"), NOW)
            .unwrap();
        let generation = registry.membership_generation.load(Ordering::Acquire);

        let poison = poisoned.clone();
        assert!(std::thread::spawn(move || {
            let _guard = poison.lock().unwrap();
            panic!("poison tenant store");
        })
        .join()
        .is_err());

        assert_eq!(
            registry.prepare_project_reset("worker-alpha").unwrap_err(),
            "a tenant Auth store is poisoned"
        );
        assert_eq!(parent.lock().unwrap().user_count(), 1);
        assert_eq!(sibling.lock().unwrap().user_count(), 1);
        assert!(Arc::ptr_eq(
            &registry.tenant_store("worker-alpha", "customer-a").unwrap(),
            &poisoned
        ));
        assert!(registry
            .tenant_metadata("worker-alpha", "customer-a")
            .is_some());
        assert!(registry
            .tenant_metadata("worker-alpha", "customer-b")
            .is_some());
        assert_eq!(
            registry.membership_generation.load(Ordering::Acquire),
            generation
        );
    }

    #[test]
    fn session_rollback_refuses_an_aba_replacement_and_retains_the_recovery_handle() {
        let default = store("demo-app", 1);
        let registry = AuthRegistry::new("demo-app", default);
        let routed = Arc::new(Mutex::new(
            registry.routed_candidate("worker-alpha").unwrap(),
        ));
        assert!(matches!(
            registry.install_routed("worker-alpha", routed),
            RoutedStoreInstall::Installed(_)
        ));
        assert!(registry.register_session(
            "worker-alpha",
            AuthStore::new("worker-alpha", SplitMix64::new(2), TotpPolicy::default())
        ));
        let replacement = store("worker-alpha", 3);
        registry
            .projects
            .lock()
            .unwrap()
            .registered
            .insert("worker-alpha".to_owned(), replacement.clone());

        assert_eq!(
            registry.rollback_session("worker-alpha"),
            super::SessionRegistrationRollback::Conflict
        );
        assert!(Arc::ptr_eq(
            &registry.store_for("worker-alpha").unwrap(),
            &replacement
        ));
        assert!(registry.routed_store_for("worker-alpha").is_none());
        assert!(registry
            .projects
            .lock()
            .unwrap()
            .pending_sessions
            .contains_key("worker-alpha"));
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
    fn a_poisoned_operation_gate_registry_refuses_project_reset_during_preflight() {
        let registry = Arc::new(
            AuthRegistry::with_project_numbers_and_lifecycle_incarnation(
                "demo-app",
                store("demo-app", 1),
                BTreeMap::new(),
                41,
            ),
        );
        assert!(registry.register(
            "worker-alpha",
            AuthStore::new("worker-alpha", SplitMix64::new(2), TotpPolicy::default())
        ));
        let parent = registry.store_for("worker-alpha").unwrap();
        parent
            .lock()
            .unwrap()
            .create_user(NewUser::email("parent@example.test"), NOW)
            .unwrap();
        let poison = registry.clone();
        assert!(std::thread::spawn(move || {
            let _guard = poison.operation_gates.lock().unwrap();
            panic!("poison operation gate registry");
        })
        .join()
        .is_err());

        assert_eq!(
            registry.prepare_project_reset("worker-alpha").unwrap_err(),
            "tenant operation-gate registry is poisoned"
        );
        assert_eq!(parent.lock().unwrap().user_count(), 1);
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
        registry.clear_routed().unwrap();
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

    #[test]
    fn deleted_refresh_routing_retains_exact_namespace_and_legacy_ambiguity() {
        let default = store("demo-app", 1);
        let registry = AuthRegistry::new("demo-app", default.clone());
        let routed = store("worker-alpha", 2);
        assert!(matches!(
            registry.install_routed("worker-alpha", routed.clone()),
            RoutedStoreInstall::Installed(_)
        ));
        let tenant = registry.ensure_tenant("demo-app", "customer").unwrap();
        for owned in [&default, &routed, &tenant] {
            let token = issue_token(owned, "deleted@example.test");
            {
                let mut source = owned.lock().unwrap();
                let uid = source.redeem_refresh_token(&token).unwrap();
                source.delete_user_by_id(uid.as_str()).unwrap();
                assert!(!source.refresh_tokens.contains_key(&token));
                assert!(!source.tokens_by_user.contains_key(&uid));
                assert_eq!(source.deleted_refresh_digests.len(), 1);
                assert_eq!(
                    source.redeem_refresh_token(&token),
                    Err(super::AuthError::UserNotFound)
                );
            }
            assert!(
                matches!(registry.store_for_refresh_token(&token), RefreshTokenStoreMatch::Unique(found) if Arc::ptr_eq(&found, owned))
            );
        }
        assert_eq!(registry.refresh_token_scan_count(), 0);
        install_legacy_refresh_token(&default, "legacy-a@example.test", "legacy-duplicate");
        install_legacy_refresh_token(&routed, "legacy-b@example.test", "legacy-duplicate");
        {
            let mut source = default.lock().unwrap();
            let uid = source.redeem_refresh_token("legacy-duplicate").unwrap();
            source.delete_user_by_id(uid.as_str()).unwrap();
        }
        assert!(matches!(
            registry.store_for_refresh_token("legacy-duplicate"),
            RefreshTokenStoreMatch::Ambiguous
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

#[cfg(test)]
mod broad_project_number_tests {
    use super::*;

    #[test]
    fn configured_numbers_follow_namespace_not_default_or_snapshot_source() {
        let default = Arc::new(Mutex::new(AuthStore::new(
            "demo-one",
            SplitMix64::new(1),
            TotpPolicy::default(),
        )));
        let registry = AuthRegistry::with_project_numbers(
            "demo-one",
            default.clone(),
            BTreeMap::from([("demo-one".to_owned(), 111), ("demo-two".to_owned(), 222)]),
        );
        assert_eq!(default.lock().unwrap().project_number(), Some(111));
        let second = registry.routed_candidate("demo-two").unwrap();
        assert_eq!(second.project_number(), Some(222));
        assert_eq!(
            registry
                .routed_candidate("demo-unset")
                .unwrap()
                .project_number(),
            None
        );
        assert!(registry.register("demo-two", second));
        let tenant = registry.ensure_tenant("demo-two", "tenant").unwrap();
        assert_eq!(tenant.lock().unwrap().project_number(), Some(222));
        let snapshot = AuthSnapshot::capture(&default.lock().unwrap());
        snapshot.restore_into(&mut tenant.lock().unwrap());
        assert_eq!(tenant.lock().unwrap().project_number(), Some(222));
        assert_eq!(tenant.lock().unwrap().project_id(), "demo-two");
    }
    #[test]
    fn issuance_metadata_does_not_activate_email_owner_or_touch_recreated_uid() {
        let mut store = AuthStore::new("demo-one", SplitMix64::new(1), TotpPolicy::default());
        store.set_config(ProjectAuthConfig {
            allow_duplicate_emails: true,
            ..ProjectAuthConfig::default()
        });
        let at = LogicalInstant::from_unix_seconds(100);
        let a = store
            .create_user_with_id(NewUser::email("shared@example.com"), Some("a"), at)
            .unwrap();
        let token = store
            .issue_refresh_session(&a, at, None, CustomClaims::default(), None)
            .unwrap();
        // Only a provider-scoped account may share the address in duplicate-email mode.
        let b = store
            .create_idp_user(NewUser::email("shared@example.com"), at)
            .unwrap();
        assert_eq!(
            store.user_by_email("shared@example.com").unwrap().local_id,
            b
        );
        store.record_token_issuance(&token, at);
        assert_eq!(store.user(&a).unwrap().last_refresh_at, Some(at));
        assert_eq!(
            store.user_by_email("shared@example.com").unwrap().local_id,
            b
        );
        store.delete_user_by_id("a").unwrap();
        let replacement = store
            .create_user_with_id(NewUser::anonymous(), Some("a"), at)
            .unwrap();
        store.record_token_issuance(&token, at);
        assert_eq!(store.user(&replacement).unwrap().last_refresh_at, None);
    }

    #[test]
    fn mutable_user_reactivation_keeps_email_index_canonical() {
        let mut store = AuthStore::new("demo-one", SplitMix64::new(1), TotpPolicy::default());
        let at = LogicalInstant::from_unix_seconds(100);
        let uid = store
            .create_user_with_id(NewUser::email("owner@example.com"), Some("owner"), at)
            .unwrap();
        {
            let user = store.user_mut(&uid).unwrap();
            user.email = Some("MixedCase@example.com".to_owned());
        }
        let _ = store.user_mut(&uid);
        assert_eq!(
            store.local_id_for_email.get("mixedcase@example.com"),
            Some(&uid)
        );
        assert!(!store
            .local_id_for_email
            .contains_key("MixedCase@example.com"));
    }
}

#[cfg(test)]
mod password_policy_namespace_tests {
    use super::{
        AuthNamespaceConfigPatch, AuthPrincipal, AuthRegistry, AuthSnapshot, AuthStore,
        ProjectAuthConfig, ProjectAuthConfigPatch, RoutedStoreInstall, TenantMetadata,
        TenantMetadataPatch,
    };
    use crate::mfa::TotpPolicy;
    use crate::password_policy::{EnforcementState, PasswordPolicy};
    use crate::signup_quota::{QuotaAlgorithm, QuotaMode, SignupQuotaConfig};
    use fireemu_core_types::determinism::SplitMix64;
    use fireemu_core_types::time::LogicalInstant;
    use std::sync::{Arc, Barrier, Mutex};

    fn store(project: &str, seed: u64) -> Arc<Mutex<AuthStore>> {
        Arc::new(Mutex::new(AuthStore::new(
            project,
            SplitMix64::new(seed),
            TotpPolicy::default(),
        )))
    }

    fn strict_policy() -> PasswordPolicy {
        PasswordPolicy::try_new(
            EnforcementState::Enforce,
            true,
            12,
            Some(30),
            true,
            true,
            true,
            true,
            crate::password_policy::default_allowed_non_alphanumeric(),
        )
        .expect("the policy is valid")
    }

    #[test]
    fn auth_snapshot_restores_the_effective_password_policy() {
        let mut store = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
        let policy = strict_policy();
        store.set_password_policy(policy.clone());
        let snapshot = AuthSnapshot::capture(&store);

        store.set_password_policy(PasswordPolicy::default());
        snapshot.restore_into(&mut store);

        assert_eq!(store.password_policy(), &policy);
    }

    #[test]
    fn cross_namespace_snapshot_restore_preserves_destination_password_policy() {
        let mut source =
            AuthStore::new("source-project", SplitMix64::new(1), TotpPolicy::default());
        source.set_password_policy(strict_policy());
        let snapshot = AuthSnapshot::capture(&source);

        let mut destination = AuthStore::new(
            "destination-project",
            SplitMix64::new(2),
            TotpPolicy::default(),
        );
        let destination_policy = PasswordPolicy::try_new(
            EnforcementState::Enforce,
            false,
            8,
            Some(20),
            false,
            true,
            false,
            false,
            crate::password_policy::default_allowed_non_alphanumeric(),
        )
        .expect("the policy is valid");
        destination.set_password_policy(destination_policy.clone());

        snapshot.restore_into(&mut destination);

        assert_eq!(destination.password_policy(), &destination_policy);
    }

    #[test]
    fn cross_tenant_snapshot_restore_preserves_destination_password_policy() {
        let mut source = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
        source.tenant_id = Some("tenant-a".to_owned());
        source.set_password_policy(strict_policy());
        let snapshot = AuthSnapshot::capture(&source);

        let mut destination = AuthStore::new("demo-app", SplitMix64::new(2), TotpPolicy::default());
        destination.tenant_id = Some("tenant-b".to_owned());
        let destination_policy = PasswordPolicy::try_new(
            EnforcementState::Enforce,
            false,
            8,
            Some(20),
            false,
            true,
            false,
            false,
            crate::password_policy::default_allowed_non_alphanumeric(),
        )
        .expect("the policy is valid");
        destination.set_password_policy(destination_policy.clone());

        snapshot.restore_into(&mut destination);

        assert_eq!(destination.password_policy(), &destination_policy);
    }

    #[test]
    fn tenant_password_policy_isolated_until_an_explicit_override() {
        let default = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(1),
            TotpPolicy::default(),
        )));
        let project_policy = strict_policy();
        default
            .lock()
            .expect("default store")
            .set_password_policy(project_policy);
        let registry = AuthRegistry::new("demo-app", default);
        let tenant_policy = PasswordPolicy::try_new(
            EnforcementState::Enforce,
            false,
            10,
            None,
            false,
            true,
            true,
            false,
            crate::password_policy::default_allowed_non_alphanumeric(),
        )
        .expect("the policy is valid");

        assert!(registry.tenant_store("demo-app", "tenant-a").is_none());
        assert!(registry.register_tenant_password_policy_override(
            "demo-app",
            "tenant-a",
            tenant_policy.clone(),
        ));
        assert!(registry.tenant_store("demo-app", "tenant-a").is_none());

        let tenant = registry
            .ensure_tenant("demo-app", "tenant-a")
            .expect("tenant is created by the normal route");
        assert_eq!(
            tenant.lock().expect("tenant store").password_policy(),
            &tenant_policy
        );

        let other = registry
            .ensure_tenant("demo-app", "tenant-b")
            .expect("tenant is created by the normal route");
        assert_eq!(
            other.lock().expect("tenant store").password_policy(),
            &PasswordPolicy::default()
        );
    }

    #[test]
    fn runtime_tenant_updates_do_not_reappear_after_delete_and_recreate() {
        let registry = AuthRegistry::new(
            "demo-app",
            Arc::new(Mutex::new(AuthStore::new(
                "demo-app",
                SplitMix64::new(1),
                TotpPolicy::default(),
            ))),
        );
        registry
            .ensure_tenant("demo-app", "tenant-a")
            .expect("tenant is created");
        let runtime_policy = strict_policy();
        assert!(registry
            .patch_tenant_with_password_policy(
                "demo-app",
                "tenant-a",
                TenantMetadataPatch {
                    disabled_user_signup: Some(true),
                    ..TenantMetadataPatch::default()
                },
                Some(runtime_policy.clone()),
            )
            .is_some());

        assert!(registry.delete_tenant("demo-app", "tenant-a"));
        let recreated = registry
            .ensure_tenant("demo-app", "tenant-a")
            .expect("same tenant ID can be recreated");
        assert_eq!(
            recreated.lock().expect("tenant store").password_policy(),
            &PasswordPolicy::default(),
            "a runtime policy update must not become a startup override"
        );
        assert!(
            !recreated
                .lock()
                .expect("tenant store")
                .config()
                .disabled_user_signup
        );
        assert!(
            !registry
                .tenant_metadata("demo-app", "tenant-a")
                .expect("tenant metadata")
                .disabled_user_signup
        );
    }

    #[test]
    fn runtime_tenant_updates_are_removed_by_default_scope_reset() {
        let registry = AuthRegistry::new("demo-app", store("demo-app", 1));
        registry.ensure_tenant("demo-app", "tenant-a").unwrap();
        assert!(registry
            .patch_tenant(
                "demo-app",
                "tenant-a",
                TenantMetadataPatch {
                    disabled_user_signup: Some(true),
                    ..TenantMetadataPatch::default()
                },
            )
            .is_some());

        let prepared = registry.prepare_default_scope_reset().unwrap();
        registry.apply_default_scope_reset(&prepared).unwrap();
        assert!(!registry
            .tenant_runtime_config_overrides
            .lock()
            .unwrap()
            .contains_key(&("demo-app".to_owned(), "tenant-a".to_owned())));

        let recreated = registry
            .ensure_tenant("demo-app", "tenant-a")
            .expect("tenant is recreated");
        assert!(!recreated.lock().unwrap().config().disabled_user_signup);
    }

    #[test]
    fn runtime_tenant_updates_are_removed_by_project_reset() {
        let registry = AuthRegistry::new("demo-app", store("demo-app", 1));
        assert!(registry.register(
            "worker-alpha",
            AuthStore::new("worker-alpha", SplitMix64::new(2), TotpPolicy::default())
        ));
        registry.ensure_tenant("worker-alpha", "tenant-a").unwrap();
        assert!(registry
            .patch_tenant(
                "worker-alpha",
                "tenant-a",
                TenantMetadataPatch {
                    disabled_user_signup: Some(true),
                    ..TenantMetadataPatch::default()
                },
            )
            .is_some());

        let prepared = registry
            .prepare_project_reset("worker-alpha")
            .unwrap()
            .expect("registered project reset");
        registry.apply_project_reset(&prepared).unwrap();
        assert!(!registry
            .tenant_runtime_config_overrides
            .lock()
            .unwrap()
            .contains_key(&("worker-alpha".to_owned(), "tenant-a".to_owned())));

        let recreated = registry
            .ensure_tenant("worker-alpha", "tenant-a")
            .expect("tenant is recreated");
        assert!(!recreated.lock().unwrap().config().disabled_user_signup);
    }

    #[test]
    fn runtime_tenant_updates_are_removed_when_a_project_is_removed() {
        let registry = AuthRegistry::new("demo-app", store("demo-app", 1));
        assert!(registry.register(
            "worker-alpha",
            AuthStore::new("worker-alpha", SplitMix64::new(2), TotpPolicy::default())
        ));
        registry.ensure_tenant("worker-alpha", "tenant-a").unwrap();
        assert!(registry
            .patch_tenant(
                "worker-alpha",
                "tenant-a",
                TenantMetadataPatch {
                    disabled_user_signup: Some(true),
                    ..TenantMetadataPatch::default()
                },
            )
            .is_some());

        assert!(registry.remove("worker-alpha"));
        assert!(!registry
            .tenant_runtime_config_overrides
            .lock()
            .unwrap()
            .contains_key(&("worker-alpha".to_owned(), "tenant-a".to_owned())));

        assert!(registry.register(
            "worker-alpha",
            AuthStore::new("worker-alpha", SplitMix64::new(3), TotpPolicy::default())
        ));
        let recreated = registry
            .ensure_tenant("worker-alpha", "tenant-a")
            .expect("tenant is recreated");
        assert!(!recreated.lock().unwrap().config().disabled_user_signup);
    }

    #[test]
    fn runtime_tenant_updates_are_removed_when_default_scope_is_replaced() {
        let registry = AuthRegistry::new("demo-app", store("demo-app", 1));
        registry.ensure_tenant("demo-app", "tenant-a").unwrap();
        assert!(registry
            .patch_tenant(
                "demo-app",
                "tenant-a",
                TenantMetadataPatch {
                    disabled_user_signup: Some(true),
                    ..TenantMetadataPatch::default()
                },
            )
            .is_some());

        registry
            .replace_default_scope(
                "demo-app",
                AuthStore::new("demo-app", SplitMix64::new(2), TotpPolicy::default()),
                vec![(
                    "tenant-a".to_owned(),
                    AuthStore::new_tenant(
                        "demo-app",
                        "tenant-a",
                        SplitMix64::new(3),
                        TotpPolicy::default(),
                    ),
                    TenantMetadata::default(),
                )],
            )
            .unwrap();
        assert!(!registry
            .tenant_runtime_config_overrides
            .lock()
            .unwrap()
            .contains_key(&("demo-app".to_owned(), "tenant-a".to_owned())));

        registry
            .patch_project_config(
                "demo-app",
                super::ProjectAuthConfigPatch {
                    disabled_user_signup: Some(false),
                    ..super::ProjectAuthConfigPatch::default()
                },
            )
            .expect("project patch succeeds");
        assert!(
            !registry
                .tenant_store("demo-app", "tenant-a")
                .unwrap()
                .lock()
                .unwrap()
                .config()
                .disabled_user_signup
        );
    }

    #[test]
    fn runtime_tenant_updates_are_removed_when_routed_scopes_are_cleared() {
        let registry = AuthRegistry::new("demo-app", store("demo-app", 1));
        let routed = registry.routed_candidate("worker-alpha").unwrap();
        assert!(matches!(
            registry.install_routed("worker-alpha", Arc::new(Mutex::new(routed))),
            RoutedStoreInstall::Installed(_)
        ));
        let key = ("worker-alpha".to_owned(), "tenant-a".to_owned());
        let tenant = Arc::new(Mutex::new(AuthStore::new_tenant(
            "worker-alpha",
            "tenant-a",
            SplitMix64::new(3),
            TotpPolicy::default(),
        )));
        registry.tenants.lock().unwrap().insert(key.clone(), tenant);
        registry
            .tenant_metadata
            .lock()
            .unwrap()
            .insert(key.clone(), TenantMetadata::default());
        assert!(registry
            .patch_tenant(
                "worker-alpha",
                "tenant-a",
                TenantMetadataPatch {
                    disabled_user_signup: Some(true),
                    ..TenantMetadataPatch::default()
                },
            )
            .is_some());

        registry.clear_routed().unwrap();
        assert!(!registry
            .tenant_runtime_config_overrides
            .lock()
            .unwrap()
            .contains_key(&key));
    }

    #[test]
    fn startup_tenant_overrides_survive_delete_and_runtime_update() {
        let registry = AuthRegistry::new(
            "demo-app",
            Arc::new(Mutex::new(AuthStore::new(
                "demo-app",
                SplitMix64::new(1),
                TotpPolicy::default(),
            ))),
        );
        let startup_policy = strict_policy();
        assert!(registry.register_tenant_password_policy_override(
            "demo-app",
            "tenant-a",
            startup_policy.clone(),
        ));
        assert!(registry.register_tenant_config_override(
            "demo-app",
            "tenant-a",
            AuthNamespaceConfigPatch {
                disabled_user_signup: Some(true),
                ..AuthNamespaceConfigPatch::default()
            },
        ));
        registry
            .ensure_tenant("demo-app", "tenant-a")
            .expect("tenant is created");

        assert!(registry
            .patch_tenant_with_password_policy(
                "demo-app",
                "tenant-a",
                TenantMetadataPatch {
                    disabled_user_signup: Some(false),
                    ..TenantMetadataPatch::default()
                },
                Some(PasswordPolicy::default()),
            )
            .is_some());
        assert!(registry.delete_tenant("demo-app", "tenant-a"));

        let recreated = registry
            .ensure_tenant("demo-app", "tenant-a")
            .expect("same tenant ID can be recreated");
        assert_eq!(
            recreated.lock().expect("tenant store").password_policy(),
            &startup_policy,
            "explicit startup policy remains authoritative after deletion"
        );
        assert!(
            recreated
                .lock()
                .expect("tenant store")
                .config()
                .disabled_user_signup
        );
        assert!(
            registry
                .tenant_metadata("demo-app", "tenant-a")
                .expect("tenant metadata")
                .disabled_user_signup
        );
    }

    #[test]
    fn tenant_metadata_and_password_policy_patch_commit_as_one_update() {
        let registry = AuthRegistry::new(
            "demo-app",
            Arc::new(Mutex::new(AuthStore::new(
                "demo-app",
                SplitMix64::new(1),
                TotpPolicy::default(),
            ))),
        );
        registry
            .ensure_tenant("demo-app", "tenant-a")
            .expect("tenant is created");
        let policy = strict_policy();

        let (metadata, returned_policy) = registry
            .patch_tenant_with_password_policy(
                "demo-app",
                "tenant-a",
                TenantMetadataPatch {
                    display_name: Some(Some("Tenant A".to_owned())),
                    disable_auth: Some(true),
                    ..TenantMetadataPatch::default()
                },
                Some(policy.clone()),
            )
            .expect("existing tenant patch succeeds");

        assert_eq!(metadata.display_name.as_deref(), Some("Tenant A"));
        assert!(metadata.disable_auth);
        assert_eq!(returned_policy, policy);
        assert_eq!(
            registry.tenant_metadata("demo-app", "tenant-a"),
            Some(metadata)
        );
        assert_eq!(
            registry
                .tenant_store("demo-app", "tenant-a")
                .expect("tenant store")
                .lock()
                .expect("tenant store lock")
                .password_policy(),
            &policy
        );
    }

    #[test]
    fn project_config_and_password_policy_patch_commit_as_one_update() {
        let registry = AuthRegistry::new(
            "demo-app",
            Arc::new(Mutex::new(AuthStore::new(
                "demo-app",
                SplitMix64::new(1),
                TotpPolicy::default(),
            ))),
        );
        let tenant = registry
            .ensure_tenant("demo-app", "tenant-a")
            .expect("tenant is created");
        let policy = strict_policy();

        let config = registry
            .patch_project_config_with_password_policy(
                "demo-app",
                ProjectAuthConfigPatch {
                    allow_duplicate_emails: Some(true),
                    enable_improved_email_privacy: Some(true),
                    disabled_user_signup: Some(true),
                    disabled_user_deletion: Some(true),
                },
                Some(policy.clone()),
            )
            .expect("project patch succeeds");

        let expected = ProjectAuthConfig {
            allow_duplicate_emails: true,
            enable_improved_email_privacy: true,
            disabled_user_signup: true,
            disabled_user_deletion: true,
        };
        assert_eq!(config, expected);
        assert_eq!(registry.default_store().lock().unwrap().config(), expected);
        assert_eq!(
            registry.default_store().lock().unwrap().password_policy(),
            &policy
        );
        assert_eq!(tenant.lock().unwrap().config(), expected);
        assert_eq!(
            tenant.lock().unwrap().password_policy(),
            &PasswordPolicy::default(),
            "project password policy must not be implicitly inherited by a tenant"
        );
        assert_eq!(
            registry
                .project_password_policy_overrides
                .lock()
                .unwrap()
                .get("demo-app"),
            Some(&policy)
        );
    }

    #[test]
    fn project_config_patch_preserves_explicit_tenant_overrides() {
        let registry = AuthRegistry::new(
            "demo-app",
            Arc::new(Mutex::new(AuthStore::new(
                "demo-app",
                SplitMix64::new(1),
                TotpPolicy::default(),
            ))),
        );
        let tenant = registry
            .ensure_tenant("demo-app", "tenant-a")
            .expect("tenant is created");
        assert!(registry.register_tenant_config_override(
            "demo-app",
            "tenant-a",
            AuthNamespaceConfigPatch {
                disabled_user_signup: Some(true),
                ..AuthNamespaceConfigPatch::default()
            },
        ));
        registry
            .patch_tenant(
                "demo-app",
                "tenant-a",
                TenantMetadataPatch {
                    enable_improved_email_privacy: Some(false),
                    ..TenantMetadataPatch::default()
                },
            )
            .expect("tenant patch succeeds");

        registry
            .patch_project_config_with_password_policy(
                "demo-app",
                ProjectAuthConfigPatch {
                    disabled_user_signup: Some(false),
                    disabled_user_deletion: Some(true),
                    enable_improved_email_privacy: Some(true),
                    ..ProjectAuthConfigPatch::default()
                },
                None,
            )
            .expect("project patch succeeds");

        assert_eq!(
            tenant.lock().unwrap().config(),
            ProjectAuthConfig {
                disabled_user_signup: true,
                disabled_user_deletion: true,
                enable_improved_email_privacy: false,
                ..ProjectAuthConfig::default()
            }
        );
        assert!(
            registry
                .tenant_metadata("demo-app", "tenant-a")
                .expect("tenant metadata")
                .disabled_user_signup,
            "the explicit tenant override remains effective after a project update"
        );
    }

    #[test]
    fn tenant_metadata_patch_preserves_effective_config_after_project_update() {
        let registry = AuthRegistry::new(
            "demo-app",
            Arc::new(Mutex::new(AuthStore::new(
                "demo-app",
                SplitMix64::new(1),
                TotpPolicy::default(),
            ))),
        );
        let tenant = registry
            .ensure_tenant("demo-app", "tenant-a")
            .expect("tenant is created");
        tenant.lock().unwrap().set_config(ProjectAuthConfig {
            allow_duplicate_emails: true,
            enable_improved_email_privacy: true,
            disabled_user_signup: true,
            disabled_user_deletion: true,
        });

        registry
            .patch_tenant(
                "demo-app",
                "tenant-a",
                TenantMetadataPatch {
                    allow_duplicate_emails: Some(true),
                    disabled_user_signup: Some(true),
                    disabled_user_deletion: Some(true),
                    enable_improved_email_privacy: Some(true),
                    ..TenantMetadataPatch::default()
                },
            )
            .expect("tenant patch succeeds");
        registry
            .patch_project_config(
                "demo-app",
                ProjectAuthConfigPatch {
                    allow_duplicate_emails: Some(false),
                    enable_improved_email_privacy: Some(false),
                    disabled_user_signup: Some(false),
                    disabled_user_deletion: Some(false),
                },
            )
            .expect("project patch succeeds");

        assert_eq!(
            tenant.lock().unwrap().config(),
            ProjectAuthConfig {
                allow_duplicate_emails: true,
                enable_improved_email_privacy: true,
                disabled_user_signup: true,
                disabled_user_deletion: true,
            }
        );
        assert!(
            !tenant
                .lock()
                .unwrap()
                .allows_user_signup(AuthPrincipal::EndUser),
            "the tenant permission remains enforced after project propagation"
        );
    }

    #[test]
    fn combined_project_patch_rejects_inconsistent_membership_before_any_write() {
        let registry = AuthRegistry::new(
            "demo-app",
            Arc::new(Mutex::new(AuthStore::new(
                "demo-app",
                SplitMix64::new(1),
                TotpPolicy::default(),
            ))),
        );
        let tenant = registry
            .ensure_tenant("demo-app", "tenant-a")
            .expect("tenant is created");
        registry
            .tenant_metadata
            .lock()
            .unwrap()
            .remove(&("demo-app".to_owned(), "tenant-a".to_owned()));

        assert!(registry
            .patch_project_config_with_password_policy(
                "demo-app",
                ProjectAuthConfigPatch {
                    disabled_user_signup: Some(true),
                    ..ProjectAuthConfigPatch::default()
                },
                Some(strict_policy()),
            )
            .is_none());
        assert_eq!(
            registry.default_store().lock().unwrap().config(),
            ProjectAuthConfig::default()
        );
        assert_eq!(
            registry.default_store().lock().unwrap().password_policy(),
            &PasswordPolicy::default()
        );
        assert_eq!(
            tenant.lock().unwrap().config(),
            ProjectAuthConfig::default()
        );
        assert_eq!(
            tenant.lock().unwrap().password_policy(),
            &PasswordPolicy::default()
        );
        assert!(registry
            .project_password_policy_overrides
            .lock()
            .unwrap()
            .get("demo-app")
            .is_none());
    }

    #[test]
    fn tenant_patch_refuses_without_mutation_when_tenant_store_registry_is_poisoned() {
        let registry = Arc::new(AuthRegistry::new(
            "demo-app",
            Arc::new(Mutex::new(AuthStore::new(
                "demo-app",
                SplitMix64::new(1),
                TotpPolicy::default(),
            ))),
        ));
        registry
            .ensure_tenant("demo-app", "tenant-a")
            .expect("tenant is created");
        let before_metadata = registry
            .tenant_metadata("demo-app", "tenant-a")
            .expect("tenant metadata");
        let tenant_store = registry
            .tenant_store("demo-app", "tenant-a")
            .expect("tenant store");
        let before_policy = tenant_store
            .lock()
            .expect("tenant store lock")
            .password_policy()
            .clone();

        let poison = registry.clone();
        assert!(std::thread::spawn(move || {
            let _guard = poison.tenants.lock().unwrap();
            panic!("poison tenant store registry");
        })
        .join()
        .is_err());

        assert!(registry
            .patch_tenant_with_password_policy(
                "demo-app",
                "tenant-a",
                TenantMetadataPatch {
                    disable_auth: Some(true),
                    ..TenantMetadataPatch::default()
                },
                Some(strict_policy()),
            )
            .is_none());
        assert_eq!(
            registry.tenant_metadata("demo-app", "tenant-a"),
            Some(before_metadata)
        );
        assert_eq!(
            tenant_store
                .lock()
                .expect("tenant store lock")
                .password_policy(),
            &before_policy
        );
    }

    #[test]
    fn project_policy_update_refuses_without_mutation_when_override_lock_is_poisoned() {
        let registry = Arc::new(AuthRegistry::new(
            "demo-app",
            Arc::new(Mutex::new(AuthStore::new(
                "demo-app",
                SplitMix64::new(1),
                TotpPolicy::default(),
            ))),
        ));
        let before = registry
            .default_store()
            .lock()
            .expect("default store")
            .password_policy()
            .clone();
        let poison = registry.clone();
        assert!(std::thread::spawn(move || {
            let _guard = poison.project_password_policy_overrides.lock().unwrap();
            panic!("poison project password policy overrides");
        })
        .join()
        .is_err());

        assert!(!registry.register_project_password_policy_override("demo-app", strict_policy()));
        assert_eq!(
            registry
                .default_store()
                .lock()
                .expect("default store")
                .password_policy(),
            &before
        );
    }

    #[test]
    fn project_password_policy_override_waits_for_namespace_registration() {
        let default = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(1),
            TotpPolicy::default(),
        )));
        let registry = AuthRegistry::new("demo-app", default);
        let policy = strict_policy();

        assert!(
            registry.register_project_password_policy_override("future-project", policy.clone(),)
        );
        assert!(registry.store_for("future-project").is_none());

        let candidate = registry
            .routed_candidate("future-project")
            .expect("a valid routed project can be prepared");
        assert_eq!(candidate.password_policy(), &policy);
        assert!(matches!(
            registry.install_routed("future-project", Arc::new(Mutex::new(candidate)),),
            super::RoutedStoreInstall::Installed(_)
        ));
        assert_eq!(
            registry
                .routed_store_for("future-project")
                .expect("registered routed store")
                .lock()
                .expect("routed store")
                .password_policy(),
            &policy
        );
    }

    #[test]
    fn concurrent_project_setting_updates_preserve_disjoint_changes() {
        let registry = Arc::new(AuthRegistry::new(
            "demo-app",
            Arc::new(Mutex::new(AuthStore::new(
                "demo-app",
                SplitMix64::new(1),
                TotpPolicy::default(),
            ))),
        ));
        let ready = Arc::new(Barrier::new(3));
        let policy_registry = Arc::clone(&registry);
        let policy_ready = Arc::clone(&ready);
        let policy_thread = std::thread::spawn(move || {
            policy_ready.wait();
            policy_registry
                .patch_project_config_with_current_settings(
                    "demo-app",
                    ProjectAuthConfigPatch::default(),
                    |current_policy, _| {
                        let mut policy = current_policy.clone();
                        policy.force_upgrade_on_signin = true;
                        Ok::<_, ()>((Some(policy), None))
                    },
                )
                .expect("policy update is accepted")
                .expect("project exists");
        });
        let quota_registry = Arc::clone(&registry);
        let quota_ready = Arc::clone(&ready);
        let quota_thread = std::thread::spawn(move || {
            quota_ready.wait();
            quota_registry
                .patch_project_config_with_current_settings(
                    "demo-app",
                    ProjectAuthConfigPatch::default(),
                    |_, current_quota| {
                        let mut quota = current_quota.clone();
                        quota.mode = QuotaMode::Enforce;
                        quota.default_quota_per_hour = 7;
                        quota.algorithm = QuotaAlgorithm::FixedWindowV1;
                        quota.max_tracked_buckets = 16;
                        quota.temporary = Some(
                            crate::signup_quota::TemporaryQuota::new(
                                3,
                                LogicalInstant::UNIX_EPOCH,
                                fireemu_core_types::time::LogicalDuration::from_seconds(60),
                            )
                            .expect("temporary quota is valid"),
                        );
                        Ok::<_, ()>((None, Some(quota)))
                    },
                )
                .expect("quota update is accepted")
                .expect("project exists");
        });
        ready.wait();
        policy_thread.join().expect("policy thread");
        quota_thread.join().expect("quota thread");

        let store = registry.default_store();
        let store = store.lock().expect("default store");
        assert!(store.password_policy().force_upgrade_on_signin);
        assert_eq!(
            store.signup_quota().config(),
            &SignupQuotaConfig {
                mode: QuotaMode::Enforce,
                algorithm: QuotaAlgorithm::FixedWindowV1,
                default_quota_per_hour: 7,
                max_tracked_buckets: 16,
                temporary: Some(
                    crate::signup_quota::TemporaryQuota::new(
                        3,
                        LogicalInstant::UNIX_EPOCH,
                        fireemu_core_types::time::LogicalDuration::from_seconds(60),
                    )
                    .expect("temporary quota is valid"),
                ),
            }
        );
    }

    #[test]
    fn routed_candidate_inherits_default_quota_configuration_without_usage() {
        let default = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(1),
            TotpPolicy::default(),
        )));
        let quota = SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            algorithm: QuotaAlgorithm::FixedWindowV1,
            default_quota_per_hour: 1,
            max_tracked_buckets: 16,
            temporary: Some(
                crate::signup_quota::TemporaryQuota::new(
                    2,
                    LogicalInstant::UNIX_EPOCH,
                    fireemu_core_types::time::LogicalDuration::from_seconds(60),
                )
                .expect("temporary quota is valid"),
            ),
        };
        default
            .lock()
            .expect("default store")
            .set_signup_quota_config(quota.clone())
            .expect("quota is valid");
        let registry = AuthRegistry::new("demo-app", Arc::clone(&default));
        let reservation = default
            .lock()
            .expect("default store")
            .reserve_signup(
                AuthPrincipal::EndUser,
                "192.0.2.1",
                LogicalInstant::UNIX_EPOCH,
            )
            .expect("default reservation succeeds");
        default
            .lock()
            .expect("default store")
            .commit_signup(reservation, LogicalInstant::UNIX_EPOCH)
            .expect("default reservation commits");

        let candidate = registry
            .routed_candidate("worker-alpha")
            .expect("routed candidate");
        assert_eq!(
            candidate.signup_quota().config(),
            &SignupQuotaConfig {
                temporary: None,
                ..quota
            },
            "temporary quota overrides are scoped to the source project",
        );
        assert_eq!(
            candidate
                .signup_quota()
                .usage("worker-alpha", "192.0.2.1", LogicalInstant::UNIX_EPOCH),
            (0, 0),
            "routed projects inherit quota configuration, not counters"
        );
    }
}

#[cfg(test)]
mod generated_id_tests {
    use super::{AuthSnapshot, AuthStore, LocalId, NewUser};
    use crate::mfa::TotpPolicy;
    use fireemu_core_types::determinism::SplitMix64;
    use fireemu_core_types::time::LogicalInstant;

    const NOW: LogicalInstant = LogicalInstant::UNIX_EPOCH;

    #[test]
    fn ordinary_generated_accounts_skip_ids_reserved_by_blocking_candidates() {
        let mut live = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let mut candidate = live.clone();
        let reserved = candidate.reserve_next_generated_local_id();

        let nested_admin = live
            .create_user(NewUser::email("nested@example.test"), NOW)
            .expect("nested Admin creation succeeds");

        assert_ne!(nested_admin.as_str(), reserved);
    }

    #[test]
    fn clearing_a_store_releases_reservations() {
        let mut live = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let mut candidate = live.clone();
        let reserved = candidate.reserve_next_generated_local_id();
        live.clear();

        let fresh_reserved = live.clone().reserve_next_generated_local_id();
        assert_eq!(fresh_reserved, reserved);
    }

    #[test]
    fn restoring_a_snapshot_releases_stale_reservations() {
        let mut live = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let mut candidate = live.clone();
        let reserved = candidate.reserve_next_generated_local_id();
        let snapshot = AuthSnapshot::capture(&live);
        let report = snapshot.restore_into(&mut live);
        assert_eq!(report, super::RestoreReport::default());
        let fresh_reserved = live.clone().reserve_next_generated_local_id();
        assert_eq!(fresh_reserved, reserved);
        live.release_reserved_generated_local_id(&reserved);
        let next_reserved = live.clone().reserve_next_generated_local_id();
        assert_ne!(next_reserved, fresh_reserved);
    }

    #[test]
    fn releasing_a_pre_reset_reservation_keeps_the_new_same_id_reservation() {
        let mut live = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let old_reservation = live.clone().reserve_next_generated_local_id();

        live.clear();
        let new_reservation = live.clone().reserve_next_generated_local_id();
        assert_eq!(new_reservation, old_reservation);

        live.release_reserved_generated_local_id(&old_reservation);
        let next_reservation = live.clone().reserve_next_generated_local_id();
        assert_ne!(next_reservation, new_reservation);
    }

    #[test]
    fn exact_generation_release_does_not_remove_a_newer_reservation() {
        let mut live = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let (old_id, old_generation) = live
            .clone()
            .reserve_next_generated_local_id_with_generation();

        live.clear();
        let (new_id, new_generation) = live
            .clone()
            .reserve_next_generated_local_id_with_generation();
        assert_eq!(new_id, old_id);
        assert_ne!(new_generation, old_generation);

        // This models the old guard being dropped after the newer reservation was created.
        live.release_reserved_generated_local_id_at_generation(&old_id, old_generation);
        let (next_id, next_generation) = live
            .clone()
            .reserve_next_generated_local_id_with_generation();
        assert_ne!(next_id, new_id);

        live.release_reserved_generated_local_id_at_generation(&new_id, new_generation);
        live.release_reserved_generated_local_id_at_generation(&next_id, next_generation);
    }

    #[test]
    fn reverse_generation_release_preserves_the_older_reservation_until_it_drops() {
        let mut live = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let (old_id, old_generation) = live
            .clone()
            .reserve_next_generated_local_id_with_generation();

        live.clear();
        let (new_id, new_generation) = live
            .clone()
            .reserve_next_generated_local_id_with_generation();
        assert_eq!(new_id, old_id);

        // The newer guard may be dropped before the older one. Its exact ticket must not be
        // confused with the older reservation, which remains in the shared ledger.
        live.release_reserved_generated_local_id_at_generation(&new_id, new_generation);
        assert!(live
            .generated_local_id_reservations
            .lock()
            .unwrap()
            .get(&LocalId(old_id.clone()))
            .is_some_and(|generations| {
                generations.len() == 1
                    && generations
                        .iter()
                        .all(|(generation, _)| *generation == old_generation)
            }));

        live.release_reserved_generated_local_id_at_generation(&old_id, old_generation);
        assert!(!live
            .generated_local_id_reservations
            .lock()
            .unwrap()
            .contains_key(&LocalId(old_id)));
    }

    #[test]
    fn stale_same_generation_release_does_not_remove_a_replacement_reservation() {
        let live = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let (old_id, generation, old_ticket) =
            live.clone().reserve_next_generated_local_id_with_ticket();
        let mut committed = live.clone();
        assert!(
            committed.use_reserved_generated_local_id_with_ticket(&old_id, generation, old_ticket,)
        );

        let (new_id, new_generation, new_ticket) =
            live.clone().reserve_next_generated_local_id_with_ticket();
        assert_eq!(new_id, old_id);
        assert_eq!(new_generation, generation);

        // A failed commit drops the old guard after a replacement reservation was created.
        live.release_reserved_generated_local_id_at_ticket(&old_id, generation, old_ticket);
        let (next_id, next_generation, next_ticket) =
            live.clone().reserve_next_generated_local_id_with_ticket();
        assert_ne!(next_id, new_id);

        live.release_reserved_generated_local_id_at_ticket(&new_id, new_generation, new_ticket);
        live.release_reserved_generated_local_id_at_ticket(&next_id, next_generation, next_ticket);
    }
}

#[cfg(test)]
mod quota_snapshot_tests {
    use super::{AuthPrincipal, AuthSnapshot, AuthStore};
    use crate::mfa::TotpPolicy;
    use crate::signup_quota::{QuotaAlgorithm, QuotaMode, SignupQuotaConfig};
    use fireemu_core_types::determinism::SplitMix64;
    use fireemu_core_types::time::LogicalInstant;

    const NOW: LogicalInstant = LogicalInstant::UNIX_EPOCH;

    fn quota(mode: QuotaMode, default_quota_per_hour: u64) -> SignupQuotaConfig {
        SignupQuotaConfig {
            mode,
            algorithm: QuotaAlgorithm::FixedWindowV1,
            default_quota_per_hour,
            max_tracked_buckets: 64,
            temporary: None,
        }
    }

    #[test]
    fn cross_project_snapshot_restore_preserves_destination_quota_config_and_usage() {
        let mut source =
            AuthStore::new("source-project", SplitMix64::new(1), TotpPolicy::default());
        source
            .set_signup_quota_config(quota(QuotaMode::Enforce, 1))
            .expect("source quota is valid");
        let source_reservation = source
            .reserve_signup(AuthPrincipal::EndUser, "192.0.2.1", NOW)
            .expect("source reservation succeeds");
        source
            .commit_signup(source_reservation, NOW)
            .expect("source reservation commits");
        let snapshot = AuthSnapshot::capture(&source);

        let mut destination = AuthStore::new(
            "destination-project",
            SplitMix64::new(2),
            TotpPolicy::default(),
        );
        let destination_config = quota(QuotaMode::Observe, 7);
        destination
            .set_signup_quota_config(destination_config.clone())
            .expect("destination quota is valid");
        let destination_reservation = destination
            .reserve_signup(AuthPrincipal::EndUser, "192.0.2.1", NOW)
            .expect("destination reservation succeeds");
        destination
            .commit_signup(destination_reservation, NOW)
            .expect("destination reservation commits");

        snapshot.restore_into(&mut destination);

        assert_eq!(destination.signup_quota().config(), &destination_config);
        assert_eq!(
            destination
                .signup_quota()
                .usage("destination-project", "192.0.2.1", NOW),
            (1, 0),
            "destination quota usage must survive a cross-project data restore"
        );
    }

    #[test]
    fn cross_tenant_snapshot_restore_does_not_transfer_source_quota_state() {
        let mut source = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
        source.tenant_id = Some("tenant-a".to_owned());
        source
            .set_signup_quota_config(quota(QuotaMode::Enforce, 1))
            .expect("source quota is valid");
        let source_reservation = source
            .reserve_signup(AuthPrincipal::EndUser, "192.0.2.2", NOW)
            .expect("source reservation succeeds");
        source
            .commit_signup(source_reservation, NOW)
            .expect("source reservation commits");
        let snapshot = AuthSnapshot::capture(&source);

        let mut destination = AuthStore::new("demo-app", SplitMix64::new(2), TotpPolicy::default());
        destination.tenant_id = Some("tenant-b".to_owned());
        let destination_config = quota(QuotaMode::Observe, 9);
        destination
            .set_signup_quota_config(destination_config.clone())
            .expect("destination quota is valid");

        snapshot.restore_into(&mut destination);

        assert_eq!(destination.signup_quota().config(), &destination_config);
        assert_eq!(
            destination
                .signup_quota()
                .usage("demo-app", "192.0.2.2", NOW),
            (0, 0),
            "tenant quota usage must remain isolated across tenant restore"
        );
    }
}
