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

use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_http::control::{ProjectHooks, TransitionFailure};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthStore, SessionRegistrationRollback};
use fireemu_core_session::tenancy::Scope;
use fireemu_core_types::determinism::SplitMix64;

/// The daemon's per-project hooks.
pub struct Projects {
    /// Firestore.
    pub backend: Arc<LocalBackend>,
    /// Storage.
    pub storage: Arc<fireemu_adapter_http::storage::StorageState>,
    /// Auth stores.
    pub registry: Arc<AuthRegistry>,
    /// Session seed (each project's generator derives from it and the project name).
    pub seed: u64,
    /// The App Check registry, when App Check is enabled. Creating, resetting and deleting a
    /// project replaces its session epoch, so every token issued before the transition fails
    /// with `WrongEpoch` at its next verification (`AC-LIFE-001`, specification section 14).
    pub app_check: Option<fireemu_core_app_check::AppCheckGate>,
    /// Pub/Sub state whose deadline and snapshot retention follow the shared virtual clock.
    pub pubsub: Arc<Mutex<fireemu_core_pubsub::PubSubState>>,
    /// Push dispatcher sharing `pubsub`; reset invalidates work before clearing broker state.
    pub pubsub_handle: fireemu_adapter_pubsub::PubSubHandle,
}

/// The App Check epochs a transition will install, drawn before anything is destroyed.
///
/// This is the probe half of the probe-then-apply protocol the other stores already use: the
/// operating system CSPRNG can fail, and a failure has to be reported while the session is
/// still intact. A transition that has already wiped a store cannot report "no epoch", and
/// leaving the old epoch in place would keep every pre-transition token valid
/// (`INV-APPCHECK-007`).
type PendingEpochs = Vec<(String, fireemu_core_app_check::ProjectEpoch)>;

fn draw_app_check_epochs(
    gate: Option<&fireemu_core_app_check::AppCheckGate>,
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
    gate: Option<&fireemu_core_app_check::AppCheckGate>,
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
        if self.pubsub.lock().is_err() {
            return Err(TransitionFailure::new(
                "pubsub",
                "the Pub/Sub state is poisoned",
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
        self.prepare(&Scope::Project(project.to_owned()))
            .map_err(|failure| failure.to_string())?;
        let mut seed = self.seed;
        for b in project.bytes() {
            seed = (seed ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        let mut store = AuthStore::new(project, SplitMix64::new(seed), TotpPolicy::default());
        if let Ok(default) = self.registry.default_store().lock() {
            store.set_config(default.config());
            store
                .set_signup_quota_config(fireemu_core_auth::signup_quota::SignupQuotaConfig {
                    temporary: None,
                    ..default.signup_quota().config().clone()
                })
                .map_err(|error| format!("cannot copy the default sign-up quota: {error:?}"))?;
            if let Some(signer) = default.signer_arc() {
                store.set_signer(signer);
            }
        }
        if !self.registry.register_session(project, store) {
            return Err(format!("project {project:?} already has an Auth store"));
        }
        Ok(())
    }

    fn reset_scope(&self, scope: &Scope) -> Result<(), TransitionFailure> {
        self.prepare(scope)?;
        let prepared_auth = match scope {
            Scope::Project(project) => self
                .registry
                .prepare_project_reset(project)
                .map_err(|reason| TransitionFailure::new("auth", reason))?,
            Scope::AllExcept(_) => None,
        };
        let prepared_default_auth = match scope {
            Scope::Project(_) => None,
            Scope::AllExcept(_) => Some(
                self.registry
                    .prepare_default_scope_reset()
                    .map_err(|reason| TransitionFailure::new("auth", reason))?,
            ),
        };
        // Part of the probe: the epochs the reset will install are drawn before the first
        // store is wiped, so a failing CSPRNG read leaves the session exactly as it was
        // instead of a wiped session that still admits its old App Check tokens.
        let epochs = draw_app_check_epochs(self.app_check.as_ref(), |p| scope.owns_project(p))
            .map_err(|e| TransitionFailure::new("app check", e))?;
        self.pubsub_handle
            .invalidate_push_workers_where(|project| scope.owns_project(project))
            .map_err(|e| TransitionFailure::new("pubsub push dispatcher", e))?;
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
        match scope {
            Scope::Project(_) => {
                if let Some(prepared) = &prepared_auth {
                    self.registry
                        .apply_project_reset(prepared)
                        .map_err(|reason| TransitionFailure::new("auth", reason))?;
                }
            }
            Scope::AllExcept(_) => {
                self.registry
                    .apply_default_scope_reset(
                        prepared_default_auth
                            .as_ref()
                            .expect("the default Auth reset was prepared"),
                    )
                    .map_err(|reason| TransitionFailure::new("auth", reason))?;
            }
        }
        self.pubsub
            .lock()
            .map_err(|_| TransitionFailure::new("pubsub", "the Pub/Sub state is poisoned"))?
            .clear_projects_where(|project| scope.owns_project(project));
        install_app_check_epochs(self.app_check.as_ref(), |p| scope.owns_project(p), &epochs);
        if let Scope::Project(project) = scope {
            if !self.registry.commit_session(project) {
                return Err(TransitionFailure::new(
                    "auth",
                    "the provisional Auth store changed during session creation",
                ));
            }
        }
        Ok(())
    }

    fn remove(&self, project: &str) -> Result<(), TransitionFailure> {
        match self.registry.rollback_session(project) {
            SessionRegistrationRollback::Restored => return Ok(()),
            SessionRegistrationRollback::Conflict => {
                return Err(TransitionFailure::new(
                    "auth",
                    "the provisional Auth store was replaced before rollback",
                ));
            }
            SessionRegistrationRollback::Unavailable => {
                return Err(TransitionFailure::new(
                    "auth",
                    "the Auth registry is unavailable during rollback",
                ));
            }
            SessionRegistrationRollback::NotPending => {}
        }
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

    fn clock_advanced(&self, now: fireemu_core_types::time::LogicalInstant) {
        self.backend.compact_all(now);
        if let Ok(mut pubsub) = self.pubsub.lock() {
            pubsub.expire_all(now);
        }
        self.pubsub_handle.on_clock_changed();
    }

    fn clock_settled(&self, scope: &Scope, now: fireemu_core_types::time::LogicalInstant) -> usize {
        // Expiry deletes are ordinary writes: they take admission, publish to listeners and
        // deliver triggers, so they run here rather than inside the exclusive clock
        // transition above.
        self.backend.sweep_expired_documents(scope, now)
    }

    fn sweep_expired_documents_now(
        &self,
        scope: &Scope,
        now: fireemu_core_types::time::LogicalInstant,
    ) -> usize {
        self.backend.sweep_expired_documents_now(scope, now)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! `AC-LIFE-001`: a reset, a restore and a project deletion replace the App Check session
    //! epoch, so a token issued before the transition is refused after it (specification
    //! section 14, lifecycle scenario 7).

    use super::{ProjectHooks, Projects, Scope};

    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex, RwLock};

    use fireemu_adapter_grpc::gateway::Gateway;
    use fireemu_adapter_grpc::local::LocalBackend;
    use fireemu_core_app_check::admission::{
        AdmissionRequest, AppCheckGate, PrivilegedBypass, ServiceAdmission,
    };
    use fireemu_core_app_check::crypto::AppCheckSigner;
    use fireemu_core_app_check::header::HeaderClassification;
    use fireemu_core_app_check::registry::{AppCheckRegistry, AppRegistration, ProjectEpoch};
    use fireemu_core_app_check::verify::BaselineMode;
    use fireemu_core_auth::mfa::TotpPolicy;
    use fireemu_core_auth::store::{AuthRegistry, AuthStore, NewUser, RoutedStoreInstall};
    use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
    use fireemu_core_pubsub::state::SNAPSHOT_TTL_SECONDS;
    use fireemu_core_pubsub::{
        Filter, PubsubMessage, PushConfig, SubscriptionConfig, SubscriptionName, TopicName,
    };
    use fireemu_core_session::clock::VirtualClock;
    use fireemu_core_types::determinism::{DeterministicRng, SplitMix64};
    use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
    use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

    pub(crate) const APP_ID: &str = "1:1234567890:web:local-test-app";
    /// A second registered project, for the routes that create and delete one (the default
    /// project already has an Auth store and cannot be created again).
    const SECOND_PROJECT: &str = "demo-second";
    const SECOND_APP_ID: &str = "1:2222222222:web:second-test-app";
    const AT: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

    /// A deterministic stand-in for the RS256 signer; the real key is exercised by the
    /// `fireemu-adapter-http` App Check tests.
    struct TestSigner;

    impl AppCheckSigner for TestSigner {
        fn alg(&self) -> &'static str {
            "RS256"
        }
        fn kid(&self) -> &'static str {
            "fireemu-app-check-test"
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
            r#"{"kty":"oct","kid":"fireemu-app-check-test"}"#.to_owned()
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
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::Production,
            },
            indexes: IndexSet::default(),
        };
        let clock = Arc::new(Mutex::new(VirtualClock::new(AT)));
        let auth_store = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(3),
            TotpPolicy::default(),
        )));
        let pubsub = Arc::new(Mutex::new(fireemu_core_pubsub::PubSubState::new(7)));
        let pubsub_handle =
            fireemu_adapter_pubsub::PubSubHandle::new(pubsub.clone(), clock.clone(), None);
        Projects {
            backend: Arc::new(LocalBackend::new(gateway, clock.clone(), 7)),
            storage: Arc::new(fireemu_adapter_http::storage::StorageState {
                store: Mutex::new(fireemu_core_storage::store::StorageState::new(9)),
                clock,
                auth: Arc::new(
                    AuthRegistry::with_project_numbers_and_lifecycle_incarnation(
                        "demo-app",
                        auth_store.clone(),
                        BTreeMap::new(),
                        7,
                    ),
                ),
                tenancy: None,
                rules: Arc::new(fireemu_adapter_http::storage::StorageRulesRegistry::default()),
                project: "demo-app".to_owned(),
                events: None,
                barrier: None,
                firestore: None,
                faults: None,
                clock_observer: None,
                app_check_policy: None,
                admin_capability: None,
                token_acceptance: fireemu_core_auth::jwt::TokenAcceptance::default(),
                control_token: None,
            }),
            registry: Arc::new(
                AuthRegistry::with_project_numbers_and_lifecycle_incarnation(
                    "demo-app",
                    auth_store,
                    BTreeMap::new(),
                    7,
                ),
            ),
            seed: 1,
            app_check: Some(gate.clone()),
            pubsub,
            pubsub_handle,
        }
    }

    fn lifecycle_registry(
        signer: Arc<dyn fireemu_core_auth::jwt::IdTokenSigner>,
        incarnation: u128,
    ) -> AuthRegistry {
        let default = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(1),
            TotpPolicy::default(),
        )));
        default.lock().unwrap().set_signer(signer);
        AuthRegistry::with_project_numbers_and_lifecycle_incarnation(
            "demo-app",
            default,
            BTreeMap::new(),
            incarnation,
        )
    }

    pub(crate) fn token_for(gate: &AppCheckGate, project: &str, app_id: &str) -> String {
        let registry = gate.registry().read().expect("readable");
        let claims = registry
            .issue_claims(project, app_id, AT)
            .expect("the fixture app may exchange");
        fireemu_core_app_check::jwt::encode(&claims, gate.signer().as_ref())
    }

    fn token(gate: &AppCheckGate) -> String {
        token_for(gate, "demo-app", APP_ID)
    }

    fn populate_pubsub(projects: &Projects, project: &str) -> (TopicName, String) {
        let topic = TopicName::new(project, "events").unwrap();
        let subscription = SubscriptionName::new(project, "events-sub").unwrap();
        let snapshot = format!("projects/{project}/snapshots/retained");
        let mut pubsub = projects.pubsub.lock().unwrap();
        pubsub.create_topic(topic.clone(), BTreeMap::new()).unwrap();
        pubsub
            .create_subscription(SubscriptionConfig {
                name: subscription.clone(),
                topic: topic.clone(),
                ack_deadline_seconds: 10,
                enable_message_ordering: false,
                filter: Filter::always(),
                dead_letter_policy: None,
                retry_policy: None,
                push_config: PushConfig::default(),
            })
            .unwrap();
        pubsub
            .publish(
                &topic,
                vec![PubsubMessage {
                    data: b"retained".to_vec(),
                    ..PubsubMessage::default()
                }],
                AT,
            )
            .unwrap();
        pubsub
            .create_snapshot(&snapshot, &subscription, BTreeMap::new(), AT)
            .unwrap();
        drop(pubsub);
        (topic, snapshot)
    }

    #[test]
    fn project_reset_and_delete_release_only_their_pubsub_retention_roots() {
        let gate = gate();
        let projects = projects(&gate);
        let (default_topic, default_snapshot) = populate_pubsub(&projects, "demo-app");
        let (second_topic, second_snapshot) = populate_pubsub(&projects, SECOND_PROJECT);

        fireemu_adapter_http::control::ProjectHooks::reset_scope(
            &projects,
            &Scope::Project(SECOND_PROJECT.to_owned()),
        )
        .unwrap();
        {
            let mut pubsub = projects.pubsub.lock().unwrap();
            assert!(pubsub.topic_exists(&default_topic));
            assert!(pubsub.get_snapshot(&default_snapshot, AT).is_ok());
            assert!(!pubsub.topic_exists(&second_topic));
            assert!(pubsub.get_snapshot(&second_snapshot, AT).is_err());
        }

        let (second_topic, second_snapshot) = populate_pubsub(&projects, SECOND_PROJECT);
        fireemu_adapter_http::control::ProjectHooks::reset_scope(
            &projects,
            &Scope::AllExcept(BTreeSet::from([SECOND_PROJECT.to_owned()])),
        )
        .unwrap();
        {
            let mut pubsub = projects.pubsub.lock().unwrap();
            assert!(!pubsub.topic_exists(&default_topic));
            assert!(pubsub.get_snapshot(&default_snapshot, AT).is_err());
            assert!(pubsub.topic_exists(&second_topic));
            assert!(pubsub.get_snapshot(&second_snapshot, AT).is_ok());
        }

        fireemu_adapter_http::control::ProjectHooks::remove(&projects, SECOND_PROJECT).unwrap();
        let mut pubsub = projects.pubsub.lock().unwrap();
        assert!(!pubsub.topic_exists(&second_topic));
        assert!(pubsub.get_snapshot(&second_snapshot, AT).is_err());
    }

    #[test]
    fn a_poisoned_pubsub_lock_refuses_reset_before_other_stores_change() {
        let gate = gate();
        let projects = projects(&gate);
        projects
            .registry
            .default_store()
            .lock()
            .unwrap()
            .create_user_with_id(NewUser::anonymous(), Some("sentinel"), AT)
            .unwrap();
        let pubsub = projects.pubsub.clone();
        let _ = std::panic::catch_unwind(move || {
            let _guard = pubsub.lock().unwrap();
            panic!("poison the Pub/Sub fixture lock");
        });

        assert!(fireemu_adapter_http::control::ProjectHooks::reset_scope(
            &projects,
            &Scope::AllExcept(BTreeSet::new()),
        )
        .is_err());
        assert_eq!(
            projects
                .registry
                .default_store()
                .lock()
                .unwrap()
                .user_count(),
            1
        );
    }

    #[test]
    fn advancing_the_shared_clock_reclaims_expired_pubsub_snapshots() {
        let gate = gate();
        let projects = projects(&gate);
        let (_, snapshot) = populate_pubsub(&projects, "demo-app");
        let expires_at = AT
            .checked_add(LogicalDuration::from_seconds(SNAPSHOT_TTL_SECONDS))
            .unwrap();

        fireemu_adapter_http::control::ProjectHooks::clock_advanced(&projects, expires_at);

        assert!(projects
            .pubsub
            .lock()
            .unwrap()
            .get_snapshot(&snapshot, expires_at)
            .is_err());
    }

    /// Writes one document carrying a time-to-live timestamp and enables the policy.
    fn with_expiring_document(projects: &Projects, expires_at: LogicalInstant) {
        let db = "projects/demo-app/databases/(default)";
        projects
            .backend
            .commit(&fireemu_proto_firestore::google::firestore::v1::CommitRequest {
                database: db.to_owned(),
                writes: vec![fireemu_proto_firestore::google::firestore::v1::Write {
                    operation: Some(
                        fireemu_proto_firestore::google::firestore::v1::write::Operation::Update(
                            fireemu_proto_firestore::google::firestore::v1::Document {
                                name: format!("{db}/documents/sessions/s1"),
                                fields: [(
                                    "expiresAt".to_owned(),
                                    fireemu_proto_firestore::google::firestore::v1::Value {
                                        value_type: Some(
                                            fireemu_proto_firestore::google::firestore::v1::value::ValueType::TimestampValue(
                                                fireemu_adapter_grpc::encode::encode_instant(expires_at),
                                            ),
                                        ),
                                    },
                                )]
                                .into_iter()
                                .collect(),
                                ..Default::default()
                            },
                        ),
                    ),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .expect("commit");
        projects
            .backend
            .enable_ttl(
                "demo-app",
                "(default)",
                fireemu_core_types::ids::CollectionId::try_new("sessions").expect("collection"),
                fireemu_core_firestore::field_path::FieldPath::parse("expiresAt").expect("field"),
            )
            .expect("enable ttl");
    }

    #[test]
    fn a_settled_clock_sweeps_documents_whose_time_to_live_elapsed_an_interval_ago() {
        let gate = gate();
        let projects = projects(&gate);
        let expires_at = AT.checked_add(LogicalDuration::from_seconds(60)).unwrap();
        with_expiring_document(&projects, expires_at);

        // Just past expiry, nothing is deleted: the sweep interval has not elapsed.
        let soon = AT.checked_add(LogicalDuration::from_seconds(61)).unwrap();
        assert_eq!(
            fireemu_adapter_http::control::ProjectHooks::clock_settled(
                &projects,
                &Scope::AllExcept(BTreeSet::new()),
                soon
            ),
            0
        );

        let due = AT
            .checked_add(LogicalDuration::from_seconds(86_400))
            .unwrap();
        assert_eq!(
            fireemu_adapter_http::control::ProjectHooks::clock_settled(
                &projects,
                &Scope::AllExcept(BTreeSet::new()),
                due
            ),
            1
        );
    }

    #[test]
    fn an_immediate_sweep_does_not_wait_for_the_interval() {
        let gate = gate();
        let projects = projects(&gate);
        let expires_at = AT.checked_add(LogicalDuration::from_seconds(60)).unwrap();
        with_expiring_document(&projects, expires_at);
        let soon = AT.checked_add(LogicalDuration::from_seconds(61)).unwrap();
        assert_eq!(
            fireemu_adapter_http::control::ProjectHooks::sweep_expired_documents_now(
                &projects,
                &Scope::AllExcept(BTreeSet::new()),
                soon
            ),
            1
        );
        assert_eq!(
            fireemu_adapter_http::control::ProjectHooks::sweep_expired_documents_now(
                &projects,
                &Scope::AllExcept(BTreeSet::new()),
                soon
            ),
            0
        );
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
    fn resetting_the_default_scope_discards_compatibility_routed_projects() {
        let gate = gate();
        let hooks = projects(&gate);
        let candidate = hooks
            .registry
            .routed_candidate("isolated-a")
            .expect("the project name is valid");
        assert!(matches!(
            hooks
                .registry
                .install_routed("isolated-a", Arc::new(Mutex::new(candidate))),
            RoutedStoreInstall::Installed(_)
        ));
        assert_eq!(hooks.registry.routed_count(), 1);

        hooks
            .reset_scope(&Scope::AllExcept(BTreeSet::new()))
            .expect("the reset succeeds");

        assert_eq!(hooks.registry.routed_count(), 0);
    }

    #[test]
    fn resetting_the_default_scope_removes_default_project_tenants_and_credentials() {
        use fireemu_core_auth::store::{AuthError, OobRequestType};

        let gate = gate();
        let hooks = projects(&gate);
        let tenant = hooks
            .registry
            .ensure_tenant("demo-app", "customer")
            .unwrap();
        let (refresh, oob) = {
            let mut tenant = tenant.lock().unwrap();
            let uid = tenant
                .create_user(NewUser::email("tenant@example.test"), AT)
                .unwrap();
            let refresh = tenant.issue_refresh_token(&uid, AT).unwrap();
            let oob = tenant
                .create_oob_code(
                    OobRequestType::PasswordReset,
                    "tenant@example.test",
                    Some(uid),
                    None,
                    AT,
                )
                .unwrap();
            (refresh, oob)
        };

        hooks
            .reset_scope(&Scope::AllExcept(BTreeSet::new()))
            .expect("the reset succeeds");

        assert!(hooks
            .registry
            .tenant_store("demo-app", "customer")
            .is_none());
        assert!(hooks
            .registry
            .tenant_metadata("demo-app", "customer")
            .is_none());
        assert!(matches!(
            hooks.registry.store_for_refresh_token(&refresh),
            fireemu_core_auth::store::RefreshTokenStoreMatch::NotFound
        ));
        let recreated = hooks
            .registry
            .ensure_tenant("demo-app", "customer")
            .unwrap();
        let (fresh_refresh, fresh_oob) = {
            let mut tenant = recreated.lock().unwrap();
            let uid = tenant
                .create_user(NewUser::email("new@example.test"), AT)
                .unwrap();
            let refresh = tenant.issue_refresh_token(&uid, AT).unwrap();
            let oob = tenant
                .create_oob_code(
                    OobRequestType::PasswordReset,
                    "new@example.test",
                    Some(uid),
                    None,
                    AT,
                )
                .unwrap();
            (refresh, oob)
        };
        assert_ne!(refresh, fresh_refresh);
        assert_ne!(oob, fresh_oob);
        assert!(matches!(
            hooks.registry.store_for_refresh_token(&refresh),
            fireemu_core_auth::store::RefreshTokenStoreMatch::NotFound
        ));
        let mut recreated = recreated.lock().unwrap();
        assert_eq!(
            recreated.consume_oob_code(&oob, Some(OobRequestType::PasswordReset), AT),
            Err(AuthError::InvalidOobCode)
        );
        assert!(recreated.oob_code(&fresh_oob).is_some());
    }

    #[test]
    fn poisoned_routed_auth_refuses_default_reset_before_clearing_default_auth() {
        let gate = gate();
        let hooks = projects(&gate);
        hooks
            .registry
            .default_store()
            .lock()
            .unwrap()
            .create_user(NewUser::email("default@example.test"), AT)
            .unwrap();
        let routed = Arc::new(Mutex::new(
            hooks
                .registry
                .routed_candidate("isolated-a")
                .expect("the project name is valid"),
        ));
        assert!(matches!(
            hooks.registry.install_routed("isolated-a", routed.clone()),
            RoutedStoreInstall::Installed(_)
        ));
        assert!(std::thread::spawn(move || {
            let _guard = routed.lock().unwrap();
            panic!("poison routed Auth store");
        })
        .join()
        .is_err());

        assert!(hooks
            .reset_scope(&Scope::AllExcept(BTreeSet::new()))
            .is_err());
        assert_eq!(
            hooks.registry.default_store().lock().unwrap().user_count(),
            1
        );
        assert_eq!(hooks.registry.routed_count(), 1);
    }

    #[test]
    fn creating_a_session_replaces_the_default_scopes_routed_auth_store() {
        let gate = gate();
        let hooks = projects(&gate);
        let mut candidate = hooks
            .registry
            .routed_candidate(SECOND_PROJECT)
            .expect("the project name is valid");
        candidate
            .create_user_with_id(
                NewUser::email("routed@example.test"),
                Some("routed-user"),
                AT,
            )
            .expect("the routed fixture user is created");
        assert!(matches!(
            hooks
                .registry
                .install_routed(SECOND_PROJECT, Arc::new(Mutex::new(candidate))),
            RoutedStoreInstall::Installed(_)
        ));

        hooks
            .create(SECOND_PROJECT)
            .expect("the explicit session takes ownership of the routed namespace");
        hooks
            .reset_scope(&Scope::Project(SECOND_PROJECT.to_owned()))
            .expect("the initial session reset commits ownership");

        assert!(hooks.registry.routed_store_for(SECOND_PROJECT).is_none());
        let registered = hooks
            .registry
            .store_for(SECOND_PROJECT)
            .expect("the session owns a registered store");
        assert_eq!(registered.lock().expect("readable").user_count(), 0);
    }

    #[test]
    fn a_signed_routed_token_never_revives_in_a_same_second_session_uid() {
        use fireemu_adapter_http::signing::RsaSigner;
        use fireemu_core_auth::jwt::{encode_with, verify_id_token};

        let gate = gate();
        let hooks = projects(&gate);
        hooks
            .registry
            .default_store()
            .lock()
            .unwrap()
            .set_signer(RsaSigner::from_seed(17).unwrap());
        let mut candidate = hooks
            .registry
            .routed_candidate(SECOND_PROJECT)
            .expect("the project name is valid");
        let uid = candidate
            .create_user_with_id(NewUser::email("routed@example.test"), Some("same-user"), AT)
            .unwrap();
        let old_token = encode_with(
            &candidate.id_token_claims(&uid, None, AT).unwrap(),
            candidate.signer(),
        );
        assert!(matches!(
            hooks
                .registry
                .install_routed(SECOND_PROJECT, Arc::new(Mutex::new(candidate)),),
            RoutedStoreInstall::Installed(_)
        ));

        hooks.create(SECOND_PROJECT).unwrap();
        hooks
            .reset_scope(&Scope::Project(SECOND_PROJECT.to_owned()))
            .unwrap();
        let registered = hooks.registry.store_for(SECOND_PROJECT).unwrap();
        let mut registered = registered.lock().unwrap();
        let recreated = registered
            .create_user_with_id(NewUser::email("new@example.test"), Some("same-user"), AT)
            .unwrap();
        let new_token = encode_with(
            &registered.id_token_claims(&recreated, None, AT).unwrap(),
            registered.signer(),
        );

        assert!(verify_id_token(&old_token, &registered, AT).is_err());
        assert!(verify_id_token(&new_token, &registered, AT).is_ok());
    }

    #[test]
    fn daemon_incarnation_prevents_same_second_token_revival_after_restart() {
        use fireemu_adapter_http::signing::RsaSigner;
        use fireemu_core_auth::jwt::{encode_with, verify_id_token, JwtError};

        let signer = RsaSigner::from_seed(17).unwrap();
        let first = lifecycle_registry(signer.clone(), 101);
        assert!(first.register(
            SECOND_PROJECT,
            AuthStore::new(SECOND_PROJECT, SplitMix64::new(2), TotpPolicy::default())
        ));
        let first_store = first.store_for(SECOND_PROJECT).unwrap();
        first_store.lock().unwrap().set_signer(signer.clone());
        let uid = first_store
            .lock()
            .unwrap()
            .create_user_with_id(NewUser::email("same@example.test"), Some("same-user"), AT)
            .unwrap();
        let old = {
            let store = first_store.lock().unwrap();
            encode_with(
                &store.id_token_claims(&uid, None, AT).unwrap(),
                store.signer(),
            )
        };
        let first_tenant = first.ensure_tenant(SECOND_PROJECT, "customer").unwrap();
        let tenant_uid = first_tenant
            .lock()
            .unwrap()
            .create_user_with_id(
                NewUser::email("tenant@example.test"),
                Some("same-tenant-user"),
                AT,
            )
            .unwrap();
        let old_tenant = {
            let store = first_tenant.lock().unwrap();
            encode_with(
                &store.id_token_claims(&tenant_uid, None, AT).unwrap(),
                store.signer(),
            )
        };

        let second = lifecycle_registry(signer.clone(), 202);
        assert!(second.register(
            SECOND_PROJECT,
            AuthStore::new(SECOND_PROJECT, SplitMix64::new(2), TotpPolicy::default())
        ));
        let second_store = second.store_for(SECOND_PROJECT).unwrap();
        second_store.lock().unwrap().set_signer(signer);
        let recreated = second_store
            .lock()
            .unwrap()
            .create_user_with_id(NewUser::email("same@example.test"), Some("same-user"), AT)
            .unwrap();
        let fresh = {
            let store = second_store.lock().unwrap();
            encode_with(
                &store.id_token_claims(&recreated, None, AT).unwrap(),
                store.signer(),
            )
        };
        let second_tenant = second.ensure_tenant(SECOND_PROJECT, "customer").unwrap();
        let recreated_tenant_uid = second_tenant
            .lock()
            .unwrap()
            .create_user_with_id(
                NewUser::email("tenant@example.test"),
                Some("same-tenant-user"),
                AT,
            )
            .unwrap();
        let fresh_tenant = {
            let store = second_tenant.lock().unwrap();
            encode_with(
                &store
                    .id_token_claims(&recreated_tenant_uid, None, AT)
                    .unwrap(),
                store.signer(),
            )
        };

        let store = second_store.lock().unwrap();
        assert!(matches!(
            verify_id_token(&old, &store, AT),
            Err(JwtError::WrongSessionEpoch { .. })
        ));
        assert!(verify_id_token(&fresh, &store, AT).is_ok());
        drop(store);
        let tenant = second_tenant.lock().unwrap();
        assert!(matches!(
            verify_id_token(&old_tenant, &tenant, AT),
            Err(JwtError::WrongSessionEpoch { .. })
        ));
        assert!(verify_id_token(&fresh_tenant, &tenant, AT).is_ok());
    }

    #[test]
    fn daemon_incarnation_rekeys_production_shaped_default_credentials() {
        use fireemu_adapter_http::signing::RsaSigner;
        use fireemu_core_auth::store::{AuthError, OobRequestType};

        let signer = RsaSigner::from_seed(17).unwrap();
        let first = lifecycle_registry(signer.clone(), 101);
        let first_store = first.default_store();
        let (old_refresh, old_oob) = {
            let mut store = first_store.lock().unwrap();
            let uid = store
                .create_user_with_id(NewUser::email("old@example.test"), Some("same-user"), AT)
                .unwrap();
            let refresh = store.issue_refresh_token(&uid, AT).unwrap();
            let oob = store
                .create_oob_code(
                    OobRequestType::PasswordReset,
                    "old@example.test",
                    Some(uid),
                    None,
                    AT,
                )
                .unwrap();
            (refresh, oob)
        };

        let second = lifecycle_registry(signer, 202);
        let second_store = second.default_store();
        let (fresh_refresh, fresh_oob) = {
            let mut store = second_store.lock().unwrap();
            let uid = store
                .create_user_with_id(NewUser::email("new@example.test"), Some("same-user"), AT)
                .unwrap();
            let refresh = store.issue_refresh_token(&uid, AT).unwrap();
            let oob = store
                .create_oob_code(
                    OobRequestType::PasswordReset,
                    "new@example.test",
                    Some(uid),
                    None,
                    AT,
                )
                .unwrap();
            (refresh, oob)
        };

        assert_ne!(old_refresh, fresh_refresh);
        assert_ne!(old_oob, fresh_oob);
        assert!(matches!(
            second.store_for_refresh_token(&old_refresh),
            fireemu_core_auth::store::RefreshTokenStoreMatch::NotFound
        ));
        let mut store = second_store.lock().unwrap();
        assert_eq!(
            store.consume_oob_code(&old_oob, Some(OobRequestType::PasswordReset), AT),
            Err(AuthError::InvalidOobCode)
        );
        assert!(store.oob_code(&fresh_oob).is_some());
    }

    #[test]
    fn project_reset_removes_tenant_state_and_invalidates_held_credentials() {
        use fireemu_adapter_http::signing::RsaSigner;
        use fireemu_core_auth::jwt::{encode_with, verify_id_token, JwtError};
        use fireemu_core_auth::store::{AuthError, OobRequestType};

        let gate = gate();
        let hooks = projects(&gate);
        hooks
            .registry
            .default_store()
            .lock()
            .unwrap()
            .set_signer(RsaSigner::from_seed(19).unwrap());
        hooks.create(SECOND_PROJECT).unwrap();
        hooks
            .reset_scope(&Scope::Project(SECOND_PROJECT.to_owned()))
            .unwrap();
        let tenant = hooks
            .registry
            .ensure_tenant(SECOND_PROJECT, "customer")
            .unwrap();
        let uid = tenant
            .lock()
            .unwrap()
            .create_user_with_id(NewUser::email("tenant@example.test"), Some("same-user"), AT)
            .unwrap();
        let (old_id, old_refresh, old_oob) = {
            let mut tenant = tenant.lock().unwrap();
            let id = encode_with(
                &tenant.id_token_claims(&uid, None, AT).unwrap(),
                tenant.signer(),
            );
            let refresh = tenant.issue_refresh_token(&uid, AT).unwrap();
            let oob = tenant
                .create_oob_code(
                    OobRequestType::PasswordReset,
                    "tenant@example.test",
                    Some(uid.clone()),
                    None,
                    AT,
                )
                .unwrap();
            (id, refresh, oob)
        };

        hooks
            .reset_scope(&Scope::Project(SECOND_PROJECT.to_owned()))
            .unwrap();
        assert!(hooks
            .registry
            .tenant_store(SECOND_PROJECT, "customer")
            .is_none());
        assert!(matches!(
            hooks.registry.store_for_refresh_token(&old_refresh),
            fireemu_core_auth::store::RefreshTokenStoreMatch::NotFound
        ));
        let recreated = hooks
            .registry
            .ensure_tenant(SECOND_PROJECT, "customer")
            .unwrap();
        let recreated_uid = recreated
            .lock()
            .unwrap()
            .create_user_with_id(NewUser::email("new@example.test"), Some("same-user"), AT)
            .unwrap();
        let (fresh, fresh_refresh, fresh_oob) = {
            let mut recreated = recreated.lock().unwrap();
            let id = encode_with(
                &recreated.id_token_claims(&recreated_uid, None, AT).unwrap(),
                recreated.signer(),
            );
            let refresh = recreated.issue_refresh_token(&recreated_uid, AT).unwrap();
            let oob = recreated
                .create_oob_code(
                    OobRequestType::PasswordReset,
                    "new@example.test",
                    Some(recreated_uid.clone()),
                    None,
                    AT,
                )
                .unwrap();
            (id, refresh, oob)
        };
        assert_ne!(old_refresh, fresh_refresh);
        assert_ne!(old_oob, fresh_oob);
        assert!(matches!(
            hooks.registry.store_for_refresh_token(&old_refresh),
            fireemu_core_auth::store::RefreshTokenStoreMatch::NotFound
        ));
        let mut recreated = recreated.lock().unwrap();
        assert!(matches!(
            verify_id_token(&old_id, &recreated, AT),
            Err(JwtError::WrongSessionEpoch { .. })
        ));
        assert!(verify_id_token(&fresh, &recreated, AT).is_ok());
        assert_eq!(
            recreated.consume_oob_code(&old_oob, Some(OobRequestType::PasswordReset), AT),
            Err(AuthError::InvalidOobCode)
        );
        assert!(recreated.oob_code(&fresh_oob).is_some());
    }

    #[test]
    fn failed_session_probe_keeps_the_default_scopes_routed_auth_store() {
        let gate = gate();
        let hooks = projects(&gate);
        let candidate = hooks
            .registry
            .routed_candidate(SECOND_PROJECT)
            .expect("the project name is valid");
        assert!(matches!(
            hooks
                .registry
                .install_routed(SECOND_PROJECT, Arc::new(Mutex::new(candidate))),
            RoutedStoreInstall::Installed(_)
        ));
        let storage = hooks.storage.clone();
        assert!(std::thread::spawn(move || {
            let _guard = storage
                .store
                .lock()
                .expect("the fixture lock starts healthy");
            panic!("poison the storage transition probe");
        })
        .join()
        .is_err());

        assert!(hooks.create(SECOND_PROJECT).is_err());
        assert!(hooks.registry.store_for(SECOND_PROJECT).is_none());
        assert!(hooks.registry.routed_store_for(SECOND_PROJECT).is_some());
    }

    #[test]
    fn a_post_registration_failure_restores_the_exact_routed_auth_store() {
        use fireemu_core_auth::jwt::{encode_unsigned, verify_id_token};

        let gate = gate();
        let hooks = projects(&gate);
        let mut candidate = hooks
            .registry
            .routed_candidate(SECOND_PROJECT)
            .expect("the project name is valid");
        let uid = candidate
            .create_user_with_id(
                NewUser::email("routed@example.test"),
                Some("routed-user"),
                AT,
            )
            .expect("the routed fixture user is created");
        let refresh = candidate
            .issue_refresh_token(&uid, AT)
            .expect("the routed fixture refresh token is issued");
        let id_token = encode_unsigned(
            &candidate
                .id_token_claims(&uid, None, AT)
                .expect("the routed fixture ID token is issued"),
        );
        let routed = Arc::new(Mutex::new(candidate));
        assert!(matches!(
            hooks
                .registry
                .install_routed(SECOND_PROJECT, routed.clone()),
            RoutedStoreInstall::Installed(_)
        ));
        hooks
            .create(SECOND_PROJECT)
            .expect("registration succeeds before the later failure");

        let storage = hooks.storage.clone();
        assert!(std::thread::spawn(move || {
            let _guard = storage
                .store
                .lock()
                .expect("the fixture lock starts healthy");
            panic!("poison storage after Auth registration");
        })
        .join()
        .is_err());
        assert!(hooks
            .reset_scope(&Scope::Project(SECOND_PROJECT.to_owned()))
            .is_err());
        hooks
            .remove(SECOND_PROJECT)
            .expect("the failed creation rolls Auth registration back");

        let restored = hooks
            .registry
            .routed_store_for(SECOND_PROJECT)
            .expect("the routed store is restored");
        assert!(Arc::ptr_eq(&restored, &routed));
        assert!(hooks.registry.store_for(SECOND_PROJECT).is_none());
        assert_eq!(restored.lock().expect("readable").user_count(), 1);
        assert!(verify_id_token(&id_token, &restored.lock().expect("readable"), AT).is_ok());
        assert!(matches!(
            hooks.registry.store_for_refresh_token(&refresh),
            fireemu_core_auth::store::RefreshTokenStoreMatch::Unique(store)
                if Arc::ptr_eq(&store, &routed)
        ));
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
                .observations("demo-app")
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
            .observed_projects()
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
        hooks
            .reset_scope(&Scope::Project(SECOND_PROJECT.to_owned()))
            .expect("the initial session reset commits ownership");
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
    fn creating_a_session_project_inherits_quota_configuration_without_usage() {
        use fireemu_core_auth::signup_quota::{
            QuotaAlgorithm, QuotaMode, SignupQuotaConfig, TemporaryQuota,
        };

        let gate = gate();
        let hooks = projects(&gate);
        let quota = SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            algorithm: QuotaAlgorithm::FixedWindowV1,
            default_quota_per_hour: 2,
            max_tracked_buckets: 16,
            temporary: Some(
                TemporaryQuota::new(
                    0,
                    LogicalInstant::UNIX_EPOCH,
                    LogicalDuration::from_seconds(60),
                )
                .expect("temporary quota is valid"),
            ),
        };
        hooks
            .registry
            .default_store()
            .lock()
            .unwrap()
            .set_signup_quota_config(quota.clone())
            .unwrap();

        hooks.create(SECOND_PROJECT).unwrap();
        hooks
            .reset_scope(&Scope::Project(SECOND_PROJECT.to_owned()))
            .unwrap();

        let registered = hooks.registry.store_for(SECOND_PROJECT).unwrap();
        let registered = registered.lock().unwrap();
        assert_eq!(
            registered.signup_quota().config(),
            &SignupQuotaConfig {
                temporary: None,
                ..quota
            },
            "temporary quota overrides are scoped to the source project",
        );
        assert_eq!(
            registered.signup_quota().usage(
                SECOND_PROJECT,
                "127.0.0.1",
                fireemu_core_types::time::LogicalInstant::UNIX_EPOCH,
            ),
            (0, 0),
            "a new session project inherits configuration but not the default project's usage"
        );
    }

    #[test]
    fn deleting_a_project_drops_its_dynamic_debug_tokens_and_rotates_its_epoch() {
        let gate = gate();
        let hooks = projects(&gate);
        hooks
            .create(SECOND_PROJECT)
            .expect("the project is created");
        hooks
            .reset_scope(&Scope::Project(SECOND_PROJECT.to_owned()))
            .expect("the initial session reset commits ownership");
        let before = token_for(&gate, SECOND_PROJECT, SECOND_APP_ID);
        gate.registry()
            .write()
            .expect("writable")
            .add_debug_token(
                SECOND_PROJECT,
                SECOND_APP_ID,
                "dynamic",
                fireemu_core_app_check::DebugTokenDigest::from_bytes([7u8; 32]),
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
