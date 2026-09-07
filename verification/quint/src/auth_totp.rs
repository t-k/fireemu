//! Quint Connect driver for production TOTP enrollment and verification.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use fireemu_core_auth::base32;
use fireemu_core_auth::mfa::{MfaError, TotpPolicy};
use fireemu_core_auth::store::{AuthStore, LocalId, NewUser, SecondFactorAssertion};
use fireemu_core_auth::totp::{time_step, totp_at};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use quint_connect::{switch, Config, Driver, Result, State, Step};
use serde::Deserialize;

/// Actions exercised through the production TOTP lifecycle.
pub const MODELED_ACTIONS: [&str; 5] = [
    "Tick",
    "StartEnrollment",
    "FinalizeEnrollment",
    "ExpireEnrollment",
    "Verify",
];

/// Reproducible seeds used by generated conformance campaigns.
pub const GENERATED_TRACE_SEEDS: [&str; 4] = ["0x1", "0x2", "0x3", "0x4"];

const MAX_STEP: u64 = 4;
const NO_STEP: i64 = 5;
const PERIOD_SECONDS: i64 = 30;
const SESSION_TTL_SECONDS: i64 = 60;

/// Production-derived state compared after every action.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthTotpState {
    /// Number of real enrolled factors.
    pub factor_count: usize,
    /// Number of real pending enrollment and sign-in sessions.
    pub pending_count: usize,
    /// Highest accepted real TOTP step, or the bounded no-step sentinel.
    pub last_accepted_step: i64,
    /// Stable classification of the latest production result.
    pub last_result: String,
    /// Validity classification of the real second-factor token claims.
    pub second_factor_claim: String,
}

/// Test-only perturbation after reading production state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionFault {
    /// Change only the factor count.
    FactorCount,
    /// Change only the pending-session count.
    PendingCount,
    /// Change only the replay boundary.
    LastAcceptedStep,
    /// Change only the latest result classification.
    LastResult,
    /// Change only second-factor claim presence.
    SecondFactorClaim,
}

impl ProjectionFault {
    /// Returns the serialized production field affected by this fault.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::FactorCount => "factorCount",
            Self::PendingCount => "pendingCount",
            Self::LastAcceptedStep => "lastAcceptedStep",
            Self::LastResult => "lastResult",
            Self::SecondFactorClaim => "secondFactorClaim",
        }
    }
}

/// Stateful adapter around one real `AuthStore` and one user.
pub struct AuthTotpDriver {
    store: AuthStore,
    uid: LocalId,
    now: LogicalInstant,
    enrollment: Option<fireemu_core_auth::mfa::TotpEnrollmentMaterial>,
    assertion: Option<SecondFactorAssertion>,
    last_result: String,
    projection_fault: Option<ProjectionFault>,
    action_recorder: Option<Arc<Mutex<BTreeSet<String>>>>,
}

impl Default for AuthTotpDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthTotpDriver {
    /// Builds a fresh bounded production driver.
    #[must_use]
    pub fn new() -> Self {
        let (store, uid) = fresh_store();
        Self {
            store,
            uid,
            now: LogicalInstant::UNIX_EPOCH,
            enrollment: None,
            assertion: None,
            last_result: "Initial".to_owned(),
            projection_fault: None,
            action_recorder: None,
        }
    }

    /// Records every successfully dispatched action.
    #[must_use]
    pub fn with_action_recorder(mut self, recorder: Arc<Mutex<BTreeSet<String>>>) -> Self {
        self.action_recorder = Some(recorder);
        self
    }

    /// Applies one projection-only fault.
    #[must_use]
    pub fn with_projection_fault(mut self, fault: ProjectionFault) -> Self {
        self.projection_fault = Some(fault);
        self
    }

    /// Changes the projection-only fault without mutating production state.
    pub fn set_projection_fault(&mut self, fault: ProjectionFault) {
        self.projection_fault = Some(fault);
    }

    /// Recreates the real store and user.
    pub fn init(&mut self) -> Result {
        let (store, uid) = fresh_store();
        self.store = store;
        self.uid = uid;
        self.now = LogicalInstant::UNIX_EPOCH;
        self.enrollment = None;
        self.assertion = None;
        "Initial".clone_into(&mut self.last_result);
        Ok(())
    }

    /// Advances the production virtual clock by one modeled TOTP period.
    pub fn tick(&mut self) -> Result {
        if self.clock_step() >= MAX_STEP {
            return Err(invalid_data("bounded TOTP clock is exhausted"));
        }
        self.advance_seconds(PERIOD_SECONDS)?;
        self.record_action("Tick")
    }

    /// Advances the production virtual clock by an exact number of seconds.
    pub fn advance_seconds(&mut self, seconds: i64) -> Result {
        self.now = self
            .now
            .checked_add(LogicalDuration::from_seconds(seconds))
            .ok_or_else(|| invalid_data("virtual clock overflow"))?;
        Ok(())
    }

    /// Starts a real TOTP enrollment.
    pub fn start_enrollment(&mut self) -> Result {
        if self.enrollment.is_some() {
            return Err(invalid_data("an enrollment is already pending"));
        }
        let material = self
            .store
            .start_totp_enrollment(&self.uid, self.now)
            .map_err(|error| classified_mfa_error(&error))?;
        self.enrollment = Some(material);
        self.assertion = None;
        "EnrollmentStarted".clone_into(&mut self.last_result);
        self.record_action("StartEnrollment")
    }

    /// Attempts to finalize a real enrollment using the chosen bounded TOTP step.
    pub fn finalize_enrollment(&mut self, code_step: i64) -> Result {
        let (session_id, secret) = self.pending_material()?;
        let code = self.code_for_step(&secret, code_step)?;
        match self
            .store
            .finalize_totp_enrollment(&self.uid, &session_id, code, self.now)
        {
            Ok(_) => {
                self.enrollment = None;
                "EnrollmentAccepted".clone_into(&mut self.last_result);
            }
            Err(MfaError::InvalidCode) => {
                "EnrollmentInvalid".clone_into(&mut self.last_result);
            }
            Err(MfaError::EnrollmentSessionExpired) => {
                self.enrollment = None;
                "EnrollmentExpired".clone_into(&mut self.last_result);
            }
            Err(error) => return Err(classified_mfa_error(&error)),
        }
        self.record_action("FinalizeEnrollment")
    }

    /// Observes expiry through the real late-finalization path.
    pub fn expire_enrollment(&mut self) -> Result {
        let (session_id, secret) = self.pending_material()?;
        let expires_at = self
            .enrollment
            .as_ref()
            .map(|material| material.expires_at)
            .ok_or_else(|| invalid_data("no enrollment is pending"))?;
        if self.now <= expires_at {
            return Err(invalid_data("enrollment has not expired"));
        }
        let code = totp_at(&secret, &self.store.policy().params(), self.now);
        match self
            .store
            .finalize_totp_enrollment(&self.uid, &session_id, code, self.now)
        {
            Err(MfaError::EnrollmentSessionExpired) => {
                self.enrollment = None;
                "EnrollmentExpired".clone_into(&mut self.last_result);
                self.record_action("ExpireEnrollment")
            }
            Ok(_) => Err(invalid_data("expired enrollment was accepted")),
            Err(error) => Err(classified_mfa_error(&error)),
        }
    }

    /// Attempts a real MFA sign-in using a code from the chosen bounded TOTP step.
    pub fn verify(&mut self, code_step: i64) -> Result {
        self.assertion = None;
        let pending = match self.store.start_mfa_sign_in(&self.uid, self.now) {
            Ok(pending) => pending,
            Err(MfaError::NoEnrolledFactor) => {
                "NoEnrolledFactor".clone_into(&mut self.last_result);
                return self.record_action("Verify");
            }
            Err(error) => return Err(classified_mfa_error(&error)),
        };
        let (enrollment_id, secret) = self
            .store
            .user(&self.uid)
            .and_then(|user| user.mfa.totp_factors().first())
            .map(|factor| {
                (
                    factor.mfa_enrollment_id.clone(),
                    factor.secret.expose_for_enrollment().to_vec(),
                )
            })
            .ok_or_else(|| invalid_data("enrolled TOTP secret is unavailable"))?;
        let code = self.code_for_step(&secret, code_step)?;
        match self.store.finalize_mfa_sign_in_for_factor(
            &self.uid,
            &pending,
            &enrollment_id,
            code,
            self.now,
        ) {
            Ok(assertion) => {
                self.assertion = Some(assertion);
                "VerificationAccepted".clone_into(&mut self.last_result);
            }
            Err(MfaError::CodeAlreadyUsed) => {
                "VerificationReplayed".clone_into(&mut self.last_result);
            }
            Err(MfaError::InvalidCode) => {
                "VerificationInvalid".clone_into(&mut self.last_result);
            }
            Err(error) => return Err(classified_mfa_error(&error)),
        }
        self.record_action("Verify")
    }

    /// Projects only values read from the production store and token claims.
    pub fn project(&self) -> Result<AuthTotpState> {
        let user = self
            .store
            .user(&self.uid)
            .ok_or_else(|| invalid_data("driver user disappeared"))?;
        let claims = self
            .store
            .id_token_claims(&self.uid, self.assertion.as_ref(), self.now)
            .map_err(|error| invalid_data(&format!("token claim construction failed: {error}")))?;
        let second_factor_claim = match (
            claims.firebase.sign_in_second_factor.as_deref(),
            claims.firebase.second_factor_identifier.as_deref(),
        ) {
            (None, None) => "None",
            (Some("totp"), Some(identifier)) if user.mfa.has_factor(identifier) => "ValidTotp",
            _ => "Invalid",
        };
        let mut projected = AuthTotpState {
            factor_count: user.mfa.factor_count(),
            pending_count: user.mfa.pending_count(),
            last_accepted_step: user
                .mfa
                .totp_factors()
                .first()
                .and_then(|factor| factor.last_accepted_step)
                .and_then(|step| i64::try_from(step).ok())
                .unwrap_or(NO_STEP),
            last_result: self.last_result.clone(),
            second_factor_claim: second_factor_claim.to_owned(),
        };
        match self.projection_fault {
            None => {}
            Some(ProjectionFault::FactorCount) => {
                projected.factor_count = projected.factor_count.saturating_add(1);
            }
            Some(ProjectionFault::PendingCount) => {
                projected.pending_count = projected.pending_count.saturating_add(1);
            }
            Some(ProjectionFault::LastAcceptedStep) => {
                projected.last_accepted_step = if projected.last_accepted_step == NO_STEP {
                    0
                } else {
                    projected.last_accepted_step.saturating_add(1)
                }
            }
            Some(ProjectionFault::LastResult) => {
                "Faulted".clone_into(&mut projected.last_result);
            }
            Some(ProjectionFault::SecondFactorClaim) => {
                "Invalid".clone_into(&mut projected.second_factor_claim);
            }
        }
        Ok(projected)
    }

    /// Checks diagnostics and projections against the live enrollment material without
    /// returning that material to the caller.
    pub fn redaction_holds_for_test(&self) -> Result<bool> {
        let material = self
            .enrollment
            .as_ref()
            .ok_or_else(|| invalid_data("no enrollment is pending"))?;
        let sensitive = [
            base32::encode(material.secret_for_test()),
            material.otpauth_uri.clone(),
            format!(
                "{:06}",
                totp_at(
                    material.secret_for_test(),
                    &self.store.policy().params(),
                    self.now
                )
            ),
        ];
        let diagnostic = self.redacted_diagnostic()?;
        let projection = format!("{:?}", self.project()?);
        Ok(sensitive
            .iter()
            .all(|value| !diagnostic.contains(value) && !projection.contains(value)))
    }

    /// Formats production state through redacting `Debug` implementations.
    pub fn redacted_diagnostic(&self) -> Result<String> {
        let material = self
            .enrollment
            .as_ref()
            .ok_or_else(|| invalid_data("no enrollment is pending"))?;
        let user = self
            .store
            .user(&self.uid)
            .ok_or_else(|| invalid_data("driver user disappeared"))?;
        Ok(format!("material={material:?}, user={user:?}"))
    }

    fn clock_step(&self) -> u64 {
        time_step(&self.store.policy().params(), self.now)
    }

    fn pending_material(&self) -> Result<(String, Vec<u8>)> {
        self.enrollment
            .as_ref()
            .map(|material| {
                (
                    material.session_id.clone(),
                    material.secret_for_test().to_vec(),
                )
            })
            .ok_or_else(|| invalid_data("no enrollment is pending"))
    }

    fn code_for_step(&self, secret: &[u8], code_step: i64) -> Result<u32> {
        if !(0..=i64::try_from(MAX_STEP).unwrap_or(i64::MAX)).contains(&code_step) {
            return Err(invalid_data("code step is outside the bounded model"));
        }
        let at = LogicalInstant::UNIX_EPOCH
            .checked_add(LogicalDuration::from_seconds(
                code_step.saturating_mul(PERIOD_SECONDS),
            ))
            .ok_or_else(|| invalid_data("code time overflow"))?;
        Ok(totp_at(secret, &self.store.policy().params(), at))
    }

    fn record_action(&self, action: &str) -> Result {
        if let Some(recorder) = &self.action_recorder {
            recorder
                .lock()
                .map_err(|_| invalid_data("action recorder lock is poisoned"))?
                .insert(action.to_owned());
        }
        Ok(())
    }
}

impl State<AuthTotpDriver> for AuthTotpState {
    fn from_driver(driver: &AuthTotpDriver) -> Result<Self> {
        driver.project()
    }
}

impl Driver for AuthTotpDriver {
    type State = AuthTotpState;

    fn config() -> Config {
        Config {
            state: &["AuthTotpScenarios::AuthTotp::observable"],
            nondet: &["AuthTotpScenarios::AuthTotp::actionTaken"],
        }
    }

    #[allow(non_snake_case)]
    fn step(&mut self, step: &Step) -> Result {
        switch!(step {
            init => self.init()?,
            Tick => self.tick()?,
            StartEnrollment => self.start_enrollment()?,
            FinalizeEnrollment(codeStep: i64) => self.finalize_enrollment(codeStep)?,
            ExpireEnrollment => self.expire_enrollment()?,
            Verify(codeStep: i64) => self.verify(codeStep)?,
        })
    }
}

/// Driver configured for generated traces.
pub struct AuthTotpConnectDriver {
    inner: AuthTotpDriver,
}

impl Default for AuthTotpConnectDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthTotpConnectDriver {
    /// Builds a fresh generated-trace driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: AuthTotpDriver::new(),
        }
    }
}

impl State<AuthTotpConnectDriver> for AuthTotpState {
    fn from_driver(driver: &AuthTotpConnectDriver) -> Result<Self> {
        driver.inner.project()
    }
}

impl Driver for AuthTotpConnectDriver {
    type State = AuthTotpState;

    fn config() -> Config {
        Config {
            state: &["AuthTotpConnect::AuthTotp::observable"],
            nondet: &["AuthTotpConnect::AuthTotp::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        self.inner.step(step)
    }
}

fn fresh_store() -> (AuthStore, LocalId) {
    let policy = TotpPolicy {
        enrollment_session_ttl: LogicalDuration::from_seconds(SESSION_TTL_SECONDS),
        ..TotpPolicy::default()
    };
    let mut store = AuthStore::new("demo-project", SplitMix64::new(0xA17), policy);
    let uid = store
        .create_user(
            NewUser::email("quint-connect@example.invalid"),
            LogicalInstant::UNIX_EPOCH,
        )
        .unwrap_or_else(|error| panic!("fixed driver user must be valid: {error}"));
    (store, uid)
}

fn classified_mfa_error(error: &MfaError) -> anyhow::Error {
    let class = match error {
        MfaError::UserNotFound => "UserNotFound",
        MfaError::UserDisabled => "UserDisabled",
        MfaError::InvalidCode => "InvalidCode",
        MfaError::CodeAlreadyUsed => "CodeAlreadyUsed",
        MfaError::EnrollmentSessionExpired => "EnrollmentSessionExpired",
        MfaError::EnrollmentSessionUnknown => "EnrollmentSessionUnknown",
        MfaError::PendingSignInUnknown => "PendingSignInUnknown",
        MfaError::NoEnrolledFactor => "NoEnrolledFactor",
        MfaError::TooManyFactors => "TooManyFactors",
        MfaError::TooManyPending => "TooManyPending",
        MfaError::LimitExceeded(_) => "LimitExceeded",
    };
    invalid_data(class)
}

fn invalid_data(message: &str) -> anyhow::Error {
    anyhow::anyhow!(message.to_owned())
}
