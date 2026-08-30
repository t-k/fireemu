//! Sessions other than the default one: isolated by project. Each gets its own Auth
//! store (registered with the shared verifier); a reset wipes what the session's scope
//! owns (its Firestore databases, its buckets, its users) and nothing else.
//!
//! A reset and a deletion touch three stores at once, so both start with a probe: every
//! store they will write is taken and released before the first of them is wiped. The only
//! failure these locks have is poisoning, which is permanent, so a probe that passes means
//! the wipe that follows cannot fail on a lock, and a probe that fails leaves the project
//! exactly as it was for the control route to report.

use std::sync::{Arc, Mutex};

use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_http::control::{ProjectHooks, TransitionFailure};
use ftd_core_auth::mfa::TotpPolicy;
use ftd_core_auth::store::{AuthRegistry, AuthStore};
use ftd_core_session::tenancy::Scope;
use ftd_core_types::determinism::SplitMix64;

/// The daemon's per-project hooks.
pub struct Projects {
    /// Firestore.
    pub backend: Arc<LocalBackend>,
    /// Storage.
    pub storage: Arc<ftd_adapter_http::storage::StorageState>,
    /// Auth stores.
    pub registry: Arc<AuthRegistry>,
    /// Session seed (each project's generator derives from it and the project name).
    pub seed: u64,
    /// The App Check registry, when App Check is enabled. Creating, resetting and deleting a
    /// project replaces its session epoch, so every token issued before the transition fails
    /// with `WrongEpoch` at its next verification (`AC-LIFE-001`, specification section 14).
    pub app_check: Option<ftd_core_app_check::AppCheckGate>,
}

/// The App Check epochs a transition will install, drawn before anything is destroyed.
///
/// This is the probe half of the probe-then-apply protocol the other stores already use: the
/// operating system CSPRNG can fail, and a failure has to be reported while the session is
/// still intact. A transition that has already wiped a store cannot report "no epoch", and
/// leaving the old epoch in place would keep every pre-transition token valid
/// (`INV-APPCHECK-007`).
type PendingEpochs = Vec<(String, ftd_core_app_check::ProjectEpoch)>;

fn draw_app_check_epochs(
    gate: Option<&ftd_core_app_check::AppCheckGate>,
    accept: impl Fn(&str) -> bool,
) -> Result<PendingEpochs, String> {
    let Some(gate) = gate else {
        return Ok(Vec::new());
    };
    let projects = gate.projects(accept);
    let mut epochs = Vec::with_capacity(projects.len());
    for project in projects {
        epochs.push((project, crate::random_epoch()?));
    }
    Ok(epochs)
}

/// The apply half: installs the drawn epochs in one write (`INV-APPCHECK-005`) and drops the
/// observations that described the state being replaced. Callers hold the exclusive admission
/// barrier, so no request straddles the swap. This cannot fail.
fn install_app_check_epochs(
    gate: Option<&ftd_core_app_check::AppCheckGate>,
    accept: impl Fn(&str) -> bool,
    epochs: &PendingEpochs,
) {
    let Some(gate) = gate else {
        return;
    };
    gate.set_epochs(epochs);
    gate.clear_observations(accept);
}

impl Projects {
    /// Checks that every store `scope` owns can be written, and returns the Auth store to
    /// wipe (a project that has none has no users to clear: the default session's scope
    /// always has one). Nothing is mutated.
    fn prepare(&self, scope: &Scope) -> Result<Option<Arc<Mutex<AuthStore>>>, TransitionFailure> {
        if self.storage.store.lock().is_err() {
            return Err(TransitionFailure::new(
                "storage",
                "the object store is poisoned",
            ));
        }
        let auth = match scope {
            Scope::Project(p) => self.registry.store_for(p),
            Scope::AllExcept(_) => Some(self.registry.default_store()),
        };
        if let Some(auth) = &auth {
            if auth.lock().is_err() {
                return Err(TransitionFailure::new("auth", "the Auth store is poisoned"));
            }
        }
        Ok(auth)
    }
}

impl ProjectHooks for Projects {
    fn create(&self, project: &str) -> Result<(), String> {
        let mut seed = self.seed;
        for b in project.bytes() {
            seed = (seed ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        let mut store = AuthStore::new(project, SplitMix64::new(seed), TotpPolicy::default());
        if let Some(signer) = self
            .registry
            .default_store()
            .lock()
            .ok()
            .and_then(|s| s.signer_arc())
        {
            store.set_signer(signer);
        }
        // A statically registered project may be reused by a new session; it starts with a
        // fresh epoch, so a token of the previous session never authorizes this one. The
        // epoch is drawn before the store is registered, so a failing draw leaves nothing
        // half-created.
        let epochs = draw_app_check_epochs(self.app_check.as_ref(), |p| p == project)?;
        if !self.registry.register(project, store) {
            return Err(format!("project {project:?} already has an Auth store"));
        }
        install_app_check_epochs(self.app_check.as_ref(), |p| p == project, &epochs);
        Ok(())
    }

    fn reset_scope(&self, scope: &Scope) -> Result<(), TransitionFailure> {
        let auth = self.prepare(scope)?;
        // Part of the probe: the epochs the reset will install are drawn before the first
        // store is wiped, so a failing CSPRNG read leaves the session exactly as it was
        // instead of a wiped session that still admits its old App Check tokens.
        let epochs = draw_app_check_epochs(self.app_check.as_ref(), |p| scope.owns_project(p))
            .map_err(|e| TransitionFailure::new("app check", e))?;
        // Apply: Firestore first (it publishes the new epoch for the default scope), then
        // the stores the probe above proved writable.
        self.backend.reset_scope(scope);
        {
            let mut store =
                self.storage.store.lock().map_err(|_| {
                    TransitionFailure::new("storage", "the object store is poisoned")
                })?;
            store.remove_buckets_where(|bucket| {
                scope.owns_project(&self.storage.project_of_bucket(bucket))
            });
        }
        if let Some(auth) = auth {
            auth.lock()
                .map_err(|_| TransitionFailure::new("auth", "the Auth store is poisoned"))?
                .clear();
        }
        install_app_check_epochs(self.app_check.as_ref(), |p| scope.owns_project(p), &epochs);
        Ok(())
    }

    fn remove(&self, project: &str) -> Result<(), TransitionFailure> {
        let scope = Scope::Project(project.to_owned());
        self.reset_scope(&scope)?;
        self.registry.remove(project);
        // Dynamic debug tokens belong to the session project's registry and go with it; the
        // static configuration registrations survive, as configuration does.
        if let Some(gate) = &self.app_check {
            gate.clear_dynamic_debug_tokens(|p| p == project);
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! `AC-LIFE-001`: a reset, a restore and a project deletion replace the App Check session
    //! epoch, so a token issued before the transition is refused after it (specification
    //! section 14, lifecycle scenario 7).

    use super::{ProjectHooks, Projects, Scope};

    use std::sync::{Arc, Mutex, RwLock};

    use ftd_adapter_grpc::gateway::Gateway;
    use ftd_adapter_grpc::local::LocalBackend;
    use ftd_core_app_check::admission::{
        AdmissionRequest, AppCheckGate, PrivilegedBypass, ServiceAdmission,
    };
    use ftd_core_app_check::crypto::AppCheckSigner;
    use ftd_core_app_check::header::HeaderClassification;
    use ftd_core_app_check::registry::{AppCheckRegistry, AppRegistration, ProjectEpoch};
    use ftd_core_app_check::verify::BaselineMode;
    use ftd_core_auth::mfa::TotpPolicy;
    use ftd_core_auth::store::{AuthRegistry, AuthStore};
    use ftd_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
    use ftd_core_rules::runtime::LoadedRules;
    use ftd_core_session::clock::VirtualClock;
    use ftd_core_types::determinism::{DeterministicRng, SplitMix64};
    use ftd_core_types::edition::{FirestoreApiMode, FirestoreEdition};
    use ftd_core_types::time::LogicalInstant;

    pub(crate) const APP_ID: &str = "1:1234567890:web:local-test-app";
    /// A second registered project, for the routes that create and delete one (the default
    /// project already has an Auth store and cannot be created again).
    const SECOND_PROJECT: &str = "demo-second";
    const SECOND_APP_ID: &str = "1:2222222222:web:second-test-app";
    const AT: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

    /// A deterministic stand-in for the RS256 signer; the real key is exercised by the
    /// `ftd-adapter-http` App Check tests.
    struct TestSigner;

    impl AppCheckSigner for TestSigner {
        fn alg(&self) -> &'static str {
            "RS256"
        }
        fn kid(&self) -> &'static str {
            "ftd-app-check-test"
        }
        fn sign(&self, signing_input: &[u8]) -> Vec<u8> {
            let mut acc = SplitMix64::new(0x5EED).next_u64();
            for byte in signing_input {
                acc = SplitMix64::new(acc ^ u64::from(*byte)).next_u64();
            }
            acc.to_be_bytes().to_vec()
        }
        fn verify(&self, signing_input: &[u8], signature: &[u8]) -> bool {
            signature == self.sign(signing_input)
        }
        fn public_jwk_json(&self) -> String {
            r#"{"kty":"oct","kid":"ftd-app-check-test"}"#.to_owned()
        }
    }

    pub(crate) fn gate() -> AppCheckGate {
        let mut registry = AppCheckRegistry::new(3600).expect("3600s is inside the TTL range");
        registry
            .register_app(AppRegistration {
                project_id: "demo-app".to_owned(),
                project_number: "1234567890".to_owned(),
                app_id: APP_ID.to_owned(),
                enabled: true,
                debug_token_digests: Vec::new(),
            })
            .expect("the demo app registers");
        registry
            .register_app(AppRegistration {
                project_id: SECOND_PROJECT.to_owned(),
                project_number: "2222222222".to_owned(),
                app_id: SECOND_APP_ID.to_owned(),
                enabled: true,
                debug_token_digests: Vec::new(),
            })
            .expect("the second app registers");
        registry.set_project_epoch("demo-app", ProjectEpoch::new(1));
        registry.set_project_epoch(SECOND_PROJECT, ProjectEpoch::new(2));
        AppCheckGate::new(Arc::new(RwLock::new(registry)), Arc::new(TestSigner))
    }

    fn projects(gate: &AppCheckGate) -> Projects {
        let gateway = Gateway {
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::Conservative,
            },
            indexes: IndexSet::default(),
        };
        let clock = Arc::new(Mutex::new(VirtualClock::new(AT)));
        let auth_store = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(3),
            TotpPolicy::default(),
        )));
        Projects {
            backend: Arc::new(LocalBackend::new(gateway, clock.clone(), 7)),
            storage: Arc::new(ftd_adapter_http::storage::StorageState {
                store: Mutex::new(ftd_core_storage::store::StorageState::new(9)),
                clock,
                auth: Arc::new(AuthRegistry::new("demo-app", auth_store.clone())),
                tenancy: None,
                rules: Arc::new(RwLock::new(LoadedRules::default())),
                project: "demo-app".to_owned(),
                events: None,
                barrier: None,
                firestore: None,
                faults: None,
                clock_observer: None,
                app_check_policy: None,
            }),
            registry: Arc::new(AuthRegistry::new("demo-app", auth_store)),
            seed: 1,
            app_check: Some(gate.clone()),
        }
    }

    pub(crate) fn token_for(gate: &AppCheckGate, project: &str, app_id: &str) -> String {
        let registry = gate.registry().read().expect("readable");
        let claims = registry
            .issue_claims(project, app_id, AT)
            .expect("the fixture app may exchange");
        ftd_core_app_check::jwt::encode(&claims, gate.signer().as_ref())
    }

    fn token(gate: &AppCheckGate) -> String {
        token_for(gate, "demo-app", APP_ID)
    }

    pub(crate) fn admits_for(gate: &AppCheckGate, project: &str, token: &str) -> bool {
        ServiceAdmission::new(gate.clone(), "firestore", BaselineMode::Enforced)
            .expect("a non-off mode has an admission")
            .admit(&AdmissionRequest {
                project_id: project,
                transport: "grpc",
                operation: "Commit",
                bypass: PrivilegedBypass::None,
                header: &HeaderClassification::Present(token.to_owned()),
                now: AT,
            })
            .allowed
    }

    fn admits(gate: &AppCheckGate, token: &str) -> bool {
        admits_for(gate, "demo-app", token)
    }

    #[test]
    fn a_reset_invalidates_every_token_from_the_previous_epoch() {
        let gate = gate();
        let hooks = projects(&gate);
        let before = token(&gate);
        assert!(
            admits(&gate, &before),
            "the token verifies before the reset"
        );

        hooks
            .reset_scope(&Scope::Project("demo-app".to_owned()))
            .expect("the reset succeeds");

        assert!(
            !admits(&gate, &before),
            "a pre-reset token is refused afterwards"
        );
        let after = token(&gate);
        assert!(admits(&gate, &after), "a token of the new epoch verifies");
        assert_ne!(before, after);
    }

    #[test]
    fn a_reset_clears_the_observations_of_the_scope_it_wiped() {
        let gate = gate();
        let hooks = projects(&gate);
        let _ = admits(&gate, &token(&gate));
        assert_eq!(
            gate.registry()
                .read()
                .expect("readable")
                .observations()
                .len(),
            1
        );
        hooks
            .reset_scope(&Scope::Project("demo-app".to_owned()))
            .expect("the reset succeeds");
        assert!(gate
            .registry()
            .read()
            .expect("readable")
            .observations()
            .is_empty());
    }

    #[test]
    fn creating_a_session_over_a_configured_project_starts_a_fresh_epoch() {
        let gate = gate();
        let hooks = projects(&gate);
        let before = token_for(&gate, SECOND_PROJECT, SECOND_APP_ID);
        assert!(admits_for(&gate, SECOND_PROJECT, &before));
        hooks
            .create(SECOND_PROJECT)
            .expect("the project is created");
        assert!(
            !admits_for(&gate, SECOND_PROJECT, &before),
            "a token minted before the session existed never authorizes it"
        );
        assert!(
            admits(&gate, &token(&gate)),
            "another project keeps its epoch"
        );
    }

    #[test]
    fn deleting_a_project_drops_its_dynamic_debug_tokens_and_rotates_its_epoch() {
        let gate = gate();
        let hooks = projects(&gate);
        hooks
            .create(SECOND_PROJECT)
            .expect("the project is created");
        let before = token_for(&gate, SECOND_PROJECT, SECOND_APP_ID);
        gate.registry()
            .write()
            .expect("writable")
            .add_debug_token(
                SECOND_PROJECT,
                SECOND_APP_ID,
                "dynamic",
                ftd_core_app_check::DebugTokenDigest::from_bytes([7u8; 32]),
                AT,
            )
            .expect("the app takes a dynamic token");

        hooks
            .remove(SECOND_PROJECT)
            .expect("the project is deleted");

        assert!(!admits_for(&gate, SECOND_PROJECT, &before));
        assert!(
            gate.registry()
                .read()
                .expect("readable")
                .list_debug_tokens(SECOND_PROJECT, SECOND_APP_ID)
                .expect("the static registration survives")
                .is_empty(),
            "the dynamic registrations went with the session project"
        );
    }
}
