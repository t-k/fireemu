//! Password policy validation shared by the Auth operation adapters.
//!
//! This module intentionally contains no request or credential state.  Callers evaluate a
//! candidate first and only commit an account mutation after the result is accepted.  The
//! policy's custom maximum is separate from the Auth API's hard input limit.

use std::collections::BTreeSet;

/// The two public Identity Platform password-policy states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementState {
    /// A configured policy is retained but does not reject passwords.
    Off,
    /// New passwords are checked against the configured constraints.
    Enforce,
}

/// Operation whose password is being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// New account registration.
    Registration,
    /// Adding a password credential to an existing account.
    CredentialAddition,
    /// Changing an existing password.
    Change,
    /// Confirming a password reset.
    Reset,
    /// Signing in with an existing password credential.
    SignIn,
}

/// A password-policy notification code.  Codes are stable wire-level identifiers; this type
/// does not contain the candidate password or any other secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationCode {
    /// At least one ASCII lower-case character is required.
    MissingLowercaseCharacter,
    /// At least one ASCII upper-case character is required.
    MissingUppercaseCharacter,
    /// At least one ASCII decimal digit is required.
    MissingNumericCharacter,
    /// At least one configured punctuation character is required.
    MissingNonAlphanumericCharacter,
    /// The candidate is shorter than the configured minimum.
    MinimumPasswordLength,
    /// The candidate is longer than the configured custom maximum.
    MaximumPasswordLength,
}

impl ViolationCode {
    /// Identity Toolkit notification identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingLowercaseCharacter => "MISSING_LOWERCASE_CHARACTER",
            Self::MissingUppercaseCharacter => "MISSING_UPPERCASE_CHARACTER",
            Self::MissingNumericCharacter => "MISSING_NUMERIC_CHARACTER",
            Self::MissingNonAlphanumericCharacter => "MISSING_NON_ALPHANUMERIC_CHARACTER",
            Self::MinimumPasswordLength => "MINIMUM_PASSWORD_LENGTH",
            Self::MaximumPasswordLength => "MAXIMUM_PASSWORD_LENGTH",
        }
    }
}

/// Why a password was refused under a custom policy: the unmet requirements and the bounds
/// they refer to, enough for an adapter to word the refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRefusal {
    /// Unmet requirements, in evaluation order.
    pub violations: Vec<ViolationCode>,
    /// The policy's inclusive minimum length in UTF-16 units.
    pub min_length: usize,
    /// The policy's inclusive custom maximum in UTF-16 units.
    pub max_length: Option<usize>,
}

/// A validated password-policy definition.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct PasswordPolicy {
    /// Whether the policy is applied to password operations.
    pub enforcement_state: EnforcementState,
    /// Whether a non-compliant existing password blocks sign-in.
    pub force_upgrade_on_signin: bool,
    /// Inclusive minimum in UTF-16 code units.
    pub min_length: usize,
    /// Optional inclusive custom maximum in UTF-16 code units.
    pub max_length: Option<usize>,
    /// Require an ASCII upper-case character.
    pub require_uppercase: bool,
    /// Require an ASCII lower-case character.
    pub require_lowercase: bool,
    /// Require an ASCII decimal digit.
    pub require_numeric: bool,
    /// Require one character from `allowed_non_alphanumeric`.
    pub require_non_alphanumeric: bool,
    /// The server-provided punctuation set used by the SDK projection.
    pub allowed_non_alphanumeric: BTreeSet<char>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            enforcement_state: EnforcementState::Off,
            force_upgrade_on_signin: false,
            min_length: 6,
            max_length: None,
            require_uppercase: false,
            require_lowercase: false,
            require_numeric: false,
            require_non_alphanumeric: false,
            allowed_non_alphanumeric: default_allowed_non_alphanumeric(),
        }
    }
}

/// Invalid policy configuration, before it can be published to an Auth namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// The minimum is outside the public range 6..=30.
    InvalidMinimumLength,
    /// The custom maximum is outside min..=4096.
    InvalidMaximumLength,
    /// A configured punctuation set contains a non-ASCII, alphanumeric, or control character.
    InvalidAllowedCharacter,
}

impl PasswordPolicy {
    /// Builds and validates a policy definition.
    #[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
    pub fn try_new(
        enforcement_state: EnforcementState,
        force_upgrade_on_signin: bool,
        min_length: usize,
        max_length: Option<usize>,
        require_uppercase: bool,
        require_lowercase: bool,
        require_numeric: bool,
        require_non_alphanumeric: bool,
        allowed_non_alphanumeric: BTreeSet<char>,
    ) -> Result<Self, ConfigError> {
        if !(6..=30).contains(&min_length) {
            return Err(ConfigError::InvalidMinimumLength);
        }
        if max_length.is_some_and(|max| max < min_length || max > 4096) {
            return Err(ConfigError::InvalidMaximumLength);
        }
        if allowed_non_alphanumeric.iter().any(|character| {
            !character.is_ascii() || character.is_ascii_alphanumeric() || character.is_control()
        }) {
            return Err(ConfigError::InvalidAllowedCharacter);
        }
        Ok(Self {
            enforcement_state,
            force_upgrade_on_signin,
            min_length,
            max_length,
            require_uppercase,
            require_lowercase,
            require_numeric,
            require_non_alphanumeric,
            allowed_non_alphanumeric,
        })
    }

    /// Returns the ordered violations for `password`.  The result is pure and never mutates
    /// credentials, tokens, OOB codes, or account timestamps.
    #[must_use]
    pub fn violations(&self, password: &str) -> Vec<ViolationCode> {
        let length = password.encode_utf16().count();
        let mut violations = Vec::new();
        if length < self.min_length {
            violations.push(ViolationCode::MinimumPasswordLength);
        }
        if self.max_length.is_some_and(|max| length > max) {
            violations.push(ViolationCode::MaximumPasswordLength);
        }
        if self.require_lowercase && !password.bytes().any(|byte| byte.is_ascii_lowercase()) {
            violations.push(ViolationCode::MissingLowercaseCharacter);
        }
        if self.require_uppercase && !password.bytes().any(|byte| byte.is_ascii_uppercase()) {
            violations.push(ViolationCode::MissingUppercaseCharacter);
        }
        if self.require_numeric && !password.bytes().any(|byte| byte.is_ascii_digit()) {
            violations.push(ViolationCode::MissingNumericCharacter);
        }
        if self.require_non_alphanumeric
            && !password
                .chars()
                .any(|character| self.allowed_non_alphanumeric.contains(&character))
        {
            violations.push(ViolationCode::MissingNonAlphanumericCharacter);
        }
        violations
    }

    /// Whether this operation is rejected by the policy.  Sign-in is special: an existing
    /// credential is checked only when `force_upgrade_on_signin` is enabled.
    #[must_use]
    pub fn rejects(&self, operation: Operation, password: &str) -> bool {
        self.enforcement_state == EnforcementState::Enforce
            && (operation != Operation::SignIn || self.force_upgrade_on_signin)
            && !self.violations(password).is_empty()
    }
}

/// Production's default punctuation set: ASCII punctuation except `+` and `=`. Unicode
/// letters, whitespace, emoji, and arbitrary non-ASCII symbols do not satisfy the requirement
/// without an explicitly supplied server set.
#[must_use]
pub fn default_allowed_non_alphanumeric() -> BTreeSet<char> {
    DEFAULT_NON_ALPHANUMERIC_ORDER.chars().collect()
}

/// Production's non-alphanumeric characters in the order `v2/passwordPolicy` lists them. `+`
/// and `=` are not among them (sandbox recording 2026-09-23, `policy/enforce-custom`).
pub const DEFAULT_NON_ALPHANUMERIC_ORDER: &str = r#"^$*.[]{}()?"!@#%&/\,><':;|_~`-"#;

#[cfg(test)]
mod tests {
    use super::{
        default_allowed_non_alphanumeric, ConfigError, EnforcementState, Operation, PasswordPolicy,
        ViolationCode,
    };

    fn strict() -> PasswordPolicy {
        PasswordPolicy::try_new(
            EnforcementState::Enforce,
            true,
            12,
            Some(30),
            true,
            true,
            true,
            true,
            default_allowed_non_alphanumeric(),
        )
        .unwrap()
    }

    #[test]
    fn validates_lengths_and_ascii_character_classes() {
        let policy = strict();
        assert_eq!(
            policy.violations("short"),
            vec![
                ViolationCode::MinimumPasswordLength,
                ViolationCode::MissingUppercaseCharacter,
                ViolationCode::MissingNumericCharacter,
                ViolationCode::MissingNonAlphanumericCharacter,
            ]
        );
        assert!(policy.violations("ValidPassword9!").is_empty());
        assert!(policy
            .violations(&"A1!".repeat(11))
            .contains(&ViolationCode::MaximumPasswordLength));
    }

    #[test]
    fn uses_utf16_units_without_normalizing_input() {
        let policy = PasswordPolicy::try_new(
            EnforcementState::Enforce,
            false,
            6,
            Some(6),
            false,
            false,
            false,
            false,
            default_allowed_non_alphanumeric(),
        )
        .unwrap();
        assert!(policy.violations("😀😀😀").is_empty());
        assert_eq!(
            policy.violations("😀😀😀😀")[0],
            ViolationCode::MaximumPasswordLength
        );
    }

    #[test]
    fn off_and_non_forced_signin_are_non_rejecting() {
        let mut policy = strict();
        policy.enforcement_state = EnforcementState::Off;
        assert!(!policy.rejects(Operation::Registration, "short"));
        policy.enforcement_state = EnforcementState::Enforce;
        policy.force_upgrade_on_signin = false;
        assert!(!policy.rejects(Operation::SignIn, "short"));
        assert!(policy.rejects(Operation::Change, "short"));
    }

    #[test]
    fn rejects_invalid_configuration() {
        let allowed = default_allowed_non_alphanumeric();
        assert_eq!(
            PasswordPolicy::try_new(
                EnforcementState::Off,
                false,
                5,
                None,
                false,
                false,
                false,
                false,
                allowed.clone()
            ),
            Err(ConfigError::InvalidMinimumLength)
        );
        assert_eq!(
            PasswordPolicy::try_new(
                EnforcementState::Off,
                false,
                10,
                Some(9),
                false,
                false,
                false,
                false,
                allowed
            ),
            Err(ConfigError::InvalidMaximumLength)
        );
    }
}
