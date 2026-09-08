//! The one transport-neutral admission decision (specification sections 7.4, 12.1 and 12.2).
//!
//! Firestore gRPC, Firestore REST, Storage and Firebase Auth all reach the same function
//! here. An adapter's whole job is to
//!
//! 1. resolve its route and its target project,
//! 2. verify its own privileged credential and name the resulting [`PrivilegedBypass`],
//! 3. hand over the App Check field values its transport received, and
//! 4. render the returned [`AdmissionDecision`] in its own wire format.
//!
//! No adapter reimplements JWT semantics, the mode table or the observation shape, so the
//! enforcement matrix of section 19 is decided in one place and the transports differ only in
//! how a denial looks on the wire (section 17).
//!
//! `off` is not represented here at all: [`ServiceAdmission::new`] returns `None` for it, so a
//! service whose baseline mode is `off` structurally cannot parse a header
//! ([`crate::verify::BaselineMode::Off`], "no token work").

use std::sync::{Arc, PoisonError, RwLock};

use fireemu_core_types::time::LogicalInstant;

use crate::crypto::AppCheckSigner;
use crate::header::HeaderClassification;
use crate::observe::Observation;
use crate::registry::{AppCheckRegistry, ProjectEpoch};
use crate::verify::{classify, AdmissionDecision, AppCheckCredentialState, BaselineMode};

/// The privileged credential a route verified before asking for a bypass (section 12.2).
///
/// A bypass is never inferred from a header shape, a path fragment or a query parameter: each
/// variant records which separate credential the adapter already authenticated, so the bypass
/// table is enumerable and testable rather than a boolean nobody can audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegedBypass {
    /// No privileged credential; the App Check credential decides.
    None,
    /// Firestore resolved a method and a target database and the caller presented the
    /// emulator's exact owner credential.
    FirestoreOwner,
    /// An Identity Toolkit Admin-only route with a verified owner principal.
    IdentityToolkitAdmin,
    /// Storage classified the request as the privileged JSON API / Admin dialect.
    StorageJsonApi,
    /// A Firebase Storage download URL whose download token is bound, in constant time, to the
    /// resolved bucket, object name and current generation.
    StorageDownloadToken,
    /// The control API, the Emulator UI API, the App Check exchange and the JWKS endpoints.
    ControlApi,
    /// The Identity Toolkit email action link (`/emulator/action`), the emulator's stand-in
    /// for the Firebase-hosted action page: the OOB code is the capability and a browser
    /// navigation carries no App Check credential.
    IdentityToolkitActionLink,
}

impl PrivilegedBypass {
    /// Whether the route authenticated a privileged credential.
    #[must_use]
    pub const fn is_privileged(self) -> bool {
        !matches!(self, Self::None)
    }

    /// The stable name of the privileged credential, for the published bypass table and for
    /// privileged observations.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::None => "",
            Self::FirestoreOwner => "firestore-owner",
            Self::IdentityToolkitAdmin => "identity-toolkit-admin",
            Self::StorageJsonApi => "storage-json-api",
            Self::StorageDownloadToken => "storage-download-token",
            Self::ControlApi => "control-api",
            Self::IdentityToolkitActionLink => "identity-toolkit-action-link",
        }
    }
}

/// One request as an adapter presents it for admission.
#[derive(Debug, Clone, Copy)]
pub struct AdmissionRequest<'a> {
    /// The resolved target project. An unresolvable project fails closed: no registered
    /// project means no issuer, so a presented token cannot verify.
    pub project_id: &'a str,
    /// Transport label for observations: `grpc`, `http` or `webchannel`.
    pub transport: &'static str,
    /// Operation or method name for observations.
    pub operation: &'a str,
    /// The privileged credential this route already verified.
    pub bypass: PrivilegedBypass,
    /// The canonical classification of the App Check field values the transport received.
    pub header: &'a HeaderClassification,
    /// The virtual-clock instant the request is decided at.
    pub now: LogicalInstant,
}

/// The shared handle on the App Check registry and this instance's signer.
///
/// Cloning is cheap: both members are reference-counted, and every adapter and the lifecycle
/// hooks hold the same registry, so a rotation is visible to all of them at once.
#[derive(Clone)]
pub struct AppCheckGate {
    registry: Arc<RwLock<AppCheckRegistry>>,
    signer: Arc<dyn AppCheckSigner>,
}

impl core::fmt::Debug for AppCheckGate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AppCheckGate")
            .field("kid", &self.signer.kid())
            .finish_non_exhaustive()
    }
}

impl AppCheckGate {
    /// A gate over one registry and one instance signer.
    #[must_use]
    pub const fn new(
        registry: Arc<RwLock<AppCheckRegistry>>,
        signer: Arc<dyn AppCheckSigner>,
    ) -> Self {
        Self { registry, signer }
    }

    /// The shared registry.
    #[must_use]
    pub const fn registry(&self) -> &Arc<RwLock<AppCheckRegistry>> {
        &self.registry
    }

    /// This instance's App Check signer.
    #[must_use]
    pub const fn signer(&self) -> &Arc<dyn AppCheckSigner> {
        &self.signer
    }

    /// The registered projects `accept` admits, each named once.
    ///
    /// Rotating an epoch is deliberately two calls rather than one. The daemon's epoch source
    /// is the operating system CSPRNG and can fail, so a caller asks for the projects first,
    /// draws one epoch per project while the session is still intact, and only then installs
    /// them with [`Self::set_epochs`]. A single call taking an infallible closure would invite
    /// exactly the failure this ordering prevents: a half-torn-down session left running on
    /// its old epoch, still admitting every token issued before the transition
    /// (`INV-APPCHECK-007`).
    #[must_use]
    pub fn projects<A: Fn(&str) -> bool>(&self, accept: A) -> Vec<String> {
        let registry = self.registry.read().unwrap_or_else(PoisonError::into_inner);
        let mut out: Vec<String> = Vec::new();
        for app in registry.apps() {
            let project = app.project_id();
            if accept(project) && !out.iter().any(|seen| seen == project) {
                out.push(project.to_owned());
            }
        }
        out
    }

    /// Installs one epoch per named project under a single write, so a request sees either the
    /// whole old set or the whole new one (`INV-APPCHECK-005`).
    ///
    /// Every token issued under a replaced epoch then fails with
    /// [`crate::verify::AppCheckFailure::WrongEpoch`] at its next verification, and each
    /// rotated project's non-secret policy generation is bumped. Callers hold the session
    /// admission barrier exclusively, so no request straddles the swap.
    pub fn set_epochs(&self, epochs: &[(String, ProjectEpoch)]) {
        let mut registry = self
            .registry
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        for (project, epoch) in epochs {
            registry.set_project_epoch(project, *epoch);
        }
    }

    /// Captures the dynamic debug tokens of every project `accept` returns true for.
    #[must_use]
    pub fn capture_dynamic_debug_tokens<A: Fn(&str) -> bool>(
        &self,
        accept: A,
    ) -> crate::registry::DynamicDebugTokens {
        self.registry
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .capture_dynamic_debug_tokens(accept)
    }

    /// Replaces the dynamic debug tokens of every project `accept` returns true for.
    pub fn restore_dynamic_debug_tokens<A: Fn(&str) -> bool>(
        &self,
        accept: A,
        captured: &crate::registry::DynamicDebugTokens,
    ) {
        self.registry
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .restore_dynamic_debug_tokens(accept, captured);
    }

    /// Drops the ring and the counters of every project `accept` returns true for: counters
    /// reset with the project state they describe, and a deleted project keeps nothing at all
    /// (section 14). Another project's ring is never touched.
    pub fn clear_observations<A: Fn(&str) -> bool>(&self, accept: A) {
        self.registry
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clear_observations(accept);
    }

    /// Drops the dynamic debug tokens of every project `accept` returns true for.
    pub fn clear_dynamic_debug_tokens<A: Fn(&str) -> bool>(&self, accept: A) {
        let mut registry = self
            .registry
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let projects: Vec<String> = registry
            .apps()
            .map(|app| app.project_id().to_owned())
            .filter(|project| accept(project))
            .collect();
        for project in &projects {
            registry.clear_dynamic_debug_tokens(project);
        }
    }
}

/// One product's baseline policy: the shared gate plus the service's configured mode.
///
/// The daemon builds one of these per product from `appCheck.services.*` and the `--only`
/// selection; an adapter that holds `None` does no App Check work whatsoever.
#[derive(Debug, Clone)]
pub struct ServiceAdmission {
    gate: AppCheckGate,
    service: &'static str,
    mode: BaselineMode,
}

impl ServiceAdmission {
    /// A product policy, or `None` when the effective baseline mode is `off`.
    ///
    /// Returning `None` for `off` is the point: the adapter then never collects a header and
    /// never records an observation, which is exactly what section 12.1 requires.
    #[must_use]
    pub fn new(gate: AppCheckGate, service: &'static str, mode: BaselineMode) -> Option<Self> {
        mode.classifies().then_some(Self {
            gate,
            service,
            mode,
        })
    }

    /// The shared gate.
    #[must_use]
    pub const fn gate(&self) -> &AppCheckGate {
        &self.gate
    }

    /// The product this policy belongs to.
    #[must_use]
    pub const fn service(&self) -> &'static str {
        self.service
    }

    /// The baseline mode; never [`BaselineMode::Off`].
    #[must_use]
    pub const fn mode(&self) -> BaselineMode {
        self.mode
    }

    /// Decides one request and records one secret-free observation.
    ///
    /// The credential is classified under a single read of the registry, so the request sees
    /// one coherent mode, registry view and epoch (`INV-APPCHECK-005`). A privileged bypass
    /// short-circuits classification entirely: the presented value is not parsed, because the
    /// route already authenticated a stronger credential.
    #[must_use]
    pub fn admit(&self, request: &AdmissionRequest<'_>) -> AdmissionDecision {
        self.admit_bound(request).0
    }

    /// Decides one request and reports, under the very same registry read, the project session
    /// epoch the decision was taken under.
    ///
    /// A long-lived operation — an admitted gRPC stream, a `WebChannel` channel, a resumable
    /// upload session — remembers the app it was admitted for and has to remember *which*
    /// epoch that admission belonged to, so that a later request cannot inherit an admission
    /// taken before a reset. Reading the epoch in a second call would be a second snapshot;
    /// this returns both halves of one (`INV-APPCHECK-005`).
    ///
    /// The epoch is `None` for a project the registry does not know, which is also the only
    /// case where no token can verify at all.
    #[must_use]
    pub fn admit_bound(
        &self,
        request: &AdmissionRequest<'_>,
    ) -> (AdmissionDecision, Option<ProjectEpoch>) {
        let registry = self
            .gate
            .registry
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let state = if request.bypass.is_privileged() {
            AppCheckCredentialState::Bypass
        } else {
            classify(
                request.header,
                &registry,
                request.project_id,
                self.gate.signer.as_ref(),
                request.now,
            )
        };
        let decision = AdmissionDecision::decide(self.mode, state);
        registry.record_observation(Observation::new(
            request.project_id,
            self.service,
            request.transport,
            request.operation,
            self.mode,
            &decision.state,
            request.now,
            registry.policy_generation(request.project_id),
            decision.allowed,
        ));
        let epoch = registry.project_epoch(request.project_id);
        (decision, epoch)
    }
}
