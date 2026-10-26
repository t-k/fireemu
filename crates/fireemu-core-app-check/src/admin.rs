//! The verdict an Admin SDK `verifyToken` call inside a Functions runner is answered with.
//!
//! The runner keeps the SDK's own decoding and claim checks and replaces only its signature
//! step with a question to the daemon, which answers from the very same [`verify_token_with`]
//! the callable boundary uses, against the project's current epoch and app registry, under one
//! registry read (`INV-APPCHECK-005`). This module owns the decision and the wire vocabulary;
//! the runner maps each reason onto the SDK error the analogous production condition raises.
//!
//! Two production-parity questions were owner decisions (ledger 1795 and 1796), and both are
//! settled in [`AdminPolicy::OWNER_RULINGS`] alone:
//!
//! - `D2`: production accepts a token naming an unregistered or disabled app until it expires;
//!   here such a token is refused in every profile (a stated difference from production);
//! - `D3`: production does not compare `iat` with the clock; here a future `iat` is accepted in
//!   every profile.

use fireemu_core_types::time::LogicalInstant;

use crate::crypto::AppCheckSigner;
use crate::registry::AppCheckRegistry;
use crate::verify::{verify_token_with, AppCheckFailure, VerifyOptions};

/// What the instrumentation lets through beyond the strict callable checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminPolicy {
    /// `D3`: accept a token whose `iat` is after the clock, as production does.
    pub accept_future_iat: bool,
}

impl AdminPolicy {
    /// Every strict check: the callable boundary's policy.
    pub const STRICT: Self = Self {
        accept_future_iat: false,
    };

    /// The policy of every run, in every profile. `D3` follows production (owner ruling 1796):
    /// a token issued in the future verifies. `D2` needs no switch: a token naming an unknown or
    /// disabled app is refused (owner ruling 1795), exactly as the callable boundary refuses it.
    pub const OWNER_RULINGS: Self = Self {
        accept_future_iat: true,
    };

    pub(crate) const fn options(self) -> VerifyOptions {
        VerifyOptions {
            allow_future_iat: self.accept_future_iat,
        }
    }
}

/// Why the daemon refused a token, in the vocabulary the runner maps onto SDK errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AdminRejection {
    /// The `kid` names no key this daemon holds, or the token belongs to a replaced session
    /// epoch. Production raises `NO_MATCHING_KID` after a signing-key rotation, which is the
    /// closest production analogue of an epoch change.
    NoMatchingKid,
    /// The signature does not verify.
    InvalidSignature,
    /// `now >= exp` on the daemon's clock.
    TokenExpired,
    /// The token is not decodable the way the verifier requires.
    Malformed,
    /// Issuer, audience or project does not match the target project.
    Claims,
    /// `iat` is after the clock; only under a policy that does not accept it (`D3`).
    NotYetValid,
    /// The subject names no registered, enabled app of the project (`D2`, refused in every
    /// profile).
    UnknownApp,
}

impl AdminRejection {
    /// Every reason, for exhaustive tests.
    pub const ALL: [Self; 7] = [
        Self::NoMatchingKid,
        Self::InvalidSignature,
        Self::TokenExpired,
        Self::Malformed,
        Self::Claims,
        Self::NotYetValid,
        Self::UnknownApp,
    ];

    /// The stable wire name carried in the verdict frame.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::NoMatchingKid => "no-matching-kid",
            Self::InvalidSignature => "invalid-signature",
            Self::TokenExpired => "token-expired",
            Self::Malformed => "malformed",
            Self::Claims => "claims",
            Self::NotYetValid => "not-yet-valid",
            Self::UnknownApp => "unknown-app",
        }
    }

    /// The reason a wire name stands for.
    #[must_use]
    pub fn parse_wire(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.wire() == name)
    }
}

/// The answer to one verification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminVerdict {
    /// The token verified under the project's current state.
    Accept,
    /// The token did not.
    Reject(AdminRejection),
}

/// How an internal failure is reported to the SDK.
#[must_use]
pub const fn admin_rejection_for(failure: AppCheckFailure) -> AdminRejection {
    match failure {
        AppCheckFailure::Malformed | AppCheckFailure::UnsupportedAlgorithm => {
            AdminRejection::Malformed
        }
        AppCheckFailure::UnknownKeyId | AppCheckFailure::WrongEpoch => {
            AdminRejection::NoMatchingKid
        }
        AppCheckFailure::BadSignature => AdminRejection::InvalidSignature,
        AppCheckFailure::Expired => AdminRejection::TokenExpired,
        AppCheckFailure::NotYetValid => AdminRejection::NotYetValid,
        AppCheckFailure::WrongIssuer
        | AppCheckFailure::WrongAudience
        | AppCheckFailure::WrongProject => AdminRejection::Claims,
        AppCheckFailure::UnknownApp | AppCheckFailure::AppDisabled => AdminRejection::UnknownApp,
    }
}

/// Decides one token against one registry snapshot.
#[must_use]
pub fn admin_verdict(
    token: &str,
    registry: &AppCheckRegistry,
    project_id: &str,
    signer: &dyn AppCheckSigner,
    now: LogicalInstant,
    policy: AdminPolicy,
) -> AdminVerdict {
    match verify_token_with(token, registry, project_id, signer, now, policy.options()) {
        Ok(_) => AdminVerdict::Accept,
        Err(failure) => AdminVerdict::Reject(admin_rejection_for(failure)),
    }
}
