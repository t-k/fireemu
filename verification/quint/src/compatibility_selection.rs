//! Quint Connect driver for compatibility auth routing and Node candidate selection.

use std::collections::BTreeSet;
use std::io;
use std::sync::{mpsc, Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

use fireemu_adapter_functions::node_selection::{select_node_candidate, NodeCandidate};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{
    AuthRegistry, AuthStore, CompatibilityUserStoreMatch, NewUser, RoutedStoreInstall,
};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use quint_connect::{switch, Config, Driver, Result, State, Step};
use serde::Deserialize;

/// Actions exercised through the production compatibility paths.
pub const MODELED_ACTIONS: [&str; 1] = ["Evaluate"];
/// Reproducible seeds used by generated conformance campaigns.
pub const GENERATED_TRACE_SEEDS: [&str; 4] = ["0x1", "0x2", "0x3", "0x4"];

/// Production-derived compatibility decision.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompatibilitySelectionState {
    /// Stable bounded scenario name.
    pub last_case: String,
    /// Project selected for project-less auth, or `deny`.
    pub auth_decision: String,
    /// Automatically ranked Node installation.
    pub automatic_node: String,
    /// Explicitly configured Node installation.
    pub explicit_node: String,
    /// Whether two project namespaces share one store.
    pub store_aliases: bool,
}

/// Test-only perturbation of one production projection field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionFault {
    /// Perturb the auth decision.
    AuthDecision,
    /// Perturb automatic Node selection.
    AutomaticNode,
    /// Perturb explicit Node selection.
    ExplicitNode,
    /// Perturb the store-alias result.
    StoreAliases,
}

impl ProjectionFault {
    /// Serialized field changed by this fault.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::AuthDecision => "authDecision",
            Self::AutomaticNode => "automaticNode",
            Self::ExplicitNode => "explicitNode",
            Self::StoreAliases => "storeAliases",
        }
    }
}

/// Stateful adapter over fresh production registries and pure Node ranking.
pub struct CompatibilitySelectionDriver {
    state: CompatibilitySelectionState,
    projection_fault: Option<ProjectionFault>,
    action_recorder: Option<Arc<Mutex<BTreeSet<String>>>>,
}

impl Default for CompatibilitySelectionDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl CompatibilitySelectionDriver {
    /// Builds an unevaluated compatibility driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: initial_state(),
            projection_fault: None,
            action_recorder: None,
        }
    }

    /// Applies one projection-only fault.
    #[must_use]
    pub fn with_projection_fault(mut self, fault: ProjectionFault) -> Self {
        self.projection_fault = Some(fault);
        self
    }

    /// Changes the projection-only fault.
    pub fn set_projection_fault(&mut self, fault: ProjectionFault) {
        self.projection_fault = Some(fault);
    }

    /// Records each successfully dispatched modeled action.
    #[must_use]
    pub fn with_action_recorder(mut self, recorder: Arc<Mutex<BTreeSet<String>>>) -> Self {
        self.action_recorder = Some(recorder);
        self
    }

    /// Resets the bounded scenario.
    pub fn init(&mut self) -> Result {
        self.state = initial_state();
        Ok(())
    }

    /// Executes one bounded compatibility scenario through production APIs.
    pub fn evaluate(&mut self, case: &str) -> Result {
        if self.state.last_case != "none" {
            return Err(invalid_data("compatibility selection already evaluated"));
        }
        let (registry, worker) = fresh_registry();
        let uid = "shared-user";
        let mut auth_decision = "default".to_owned();
        let mut store_aliases = false;

        match case {
            "unique" => {
                install_worker(&registry, Arc::clone(&worker))?;
                create_user(&worker, uid, "worker@example.invalid")?;
                auth_decision = classify_auth(&registry, uid)?;
            }
            "ambiguous" => {
                install_worker(&registry, Arc::clone(&worker))?;
                create_user(&registry.default_store(), uid, "default@example.invalid")?;
                create_user(&worker, uid, "worker@example.invalid")?;
                auth_decision = classify_auth(&registry, uid)?;
            }
            "concurrentMove" => {
                auth_decision = coherent_move_decision()?;
            }
            "alias" => {
                install_worker(&registry, Arc::clone(&worker))?;
                if !matches!(
                    registry.install_routed("worker-b", worker),
                    RoutedStoreInstall::InvalidStore
                ) {
                    store_aliases = true;
                }
            }
            "default" | "capability" | "runtime" | "engine" | "explicit" => {}
            _ => return Err(invalid_data("unknown compatibility selection case")),
        }

        if case == "default" {
            auth_decision = classify_auth(&registry, uid)?;
        }
        let (automatic_node, explicit_node) = node_decisions(case)?;
        self.state = CompatibilitySelectionState {
            last_case: case.to_owned(),
            auth_decision,
            automatic_node,
            explicit_node,
            store_aliases,
        };
        if let Some(recorder) = &self.action_recorder {
            recorder
                .lock()
                .map_err(|_| invalid_data("action recorder lock poisoned"))?
                .insert("Evaluate".to_owned());
        }
        Ok(())
    }

    /// Projects production-derived compatibility state.
    pub fn project(&self) -> Result<CompatibilitySelectionState> {
        let mut state = self.state.clone();
        match self.projection_fault {
            None => {}
            Some(ProjectionFault::AuthDecision) => "deny".clone_into(&mut state.auth_decision),
            Some(ProjectionFault::AutomaticNode) => {
                "node22old".clone_into(&mut state.automatic_node);
            }
            Some(ProjectionFault::ExplicitNode) => {
                "node22new".clone_into(&mut state.explicit_node);
            }
            Some(ProjectionFault::StoreAliases) => state.store_aliases = !state.store_aliases,
        }
        Ok(state)
    }
}

impl State<CompatibilitySelectionDriver> for CompatibilitySelectionState {
    fn from_driver(driver: &CompatibilitySelectionDriver) -> Result<Self> {
        driver.project()
    }
}

impl Driver for CompatibilitySelectionDriver {
    type State = CompatibilitySelectionState;
    fn config() -> Config {
        Config {
            state: &["observable"],
            nondet: &["actionTaken"],
        }
    }
    fn step(&mut self, step: &Step) -> Result {
        switch!(step { init => self.init()?, Evaluate(case: String) => self.evaluate(&case)?, })
    }
}

fn fresh_registry() -> (AuthRegistry, Arc<Mutex<AuthStore>>) {
    let default = Arc::new(Mutex::new(AuthStore::new(
        "default",
        SplitMix64::new(1),
        TotpPolicy::default(),
    )));
    let worker = Arc::new(Mutex::new(AuthStore::new(
        "worker-a",
        SplitMix64::new(2),
        TotpPolicy::default(),
    )));
    (AuthRegistry::new("default", default), worker)
}

fn install_worker(registry: &AuthRegistry, worker: Arc<Mutex<AuthStore>>) -> Result {
    if matches!(
        registry.install_routed("worker-a", worker),
        RoutedStoreInstall::Installed(_)
    ) {
        Ok(())
    } else {
        Err(invalid_data("worker store was not installed"))
    }
}

fn create_user(store: &Arc<Mutex<AuthStore>>, uid: &str, email: &str) -> Result {
    store
        .lock()
        .map_err(|_| invalid_data("auth store lock poisoned"))?
        .create_user_with_id(NewUser::email(email), Some(uid), LogicalInstant::UNIX_EPOCH)
        .map(|_| ())
        .map_err(|error| invalid_data(&format!("cannot create compatibility user: {error}")))
}

fn classify_auth(registry: &AuthRegistry, uid: &str) -> Result<String> {
    match registry.compatibility_store_for_unique_user(uid) {
        CompatibilityUserStoreMatch::NotFound => Ok("default".to_owned()),
        CompatibilityUserStoreMatch::Unique(store) => store
            .lock()
            .map(|store| store.project_id().to_owned())
            .map_err(|_| invalid_data("selected auth store lock poisoned")),
        CompatibilityUserStoreMatch::Ambiguous => Ok("deny".to_owned()),
        CompatibilityUserStoreMatch::Unavailable => Err(invalid_data("auth routing unavailable")),
    }
}

fn coherent_move_decision() -> Result<String> {
    let default = Arc::new(Mutex::new(AuthStore::new(
        "default",
        SplitMix64::new(10),
        TotpPolicy::default(),
    )));
    let alpha = Arc::new(Mutex::new(AuthStore::new(
        "worker-a",
        SplitMix64::new(11),
        TotpPolicy::default(),
    )));
    let beta = Arc::new(Mutex::new(AuthStore::new(
        "worker-b",
        SplitMix64::new(12),
        TotpPolicy::default(),
    )));
    let registry = Arc::new(AuthRegistry::new("default", default));
    install_worker(&registry, Arc::clone(&alpha))?;
    if !matches!(
        registry.install_routed("worker-b", Arc::clone(&beta)),
        RoutedStoreInstall::Installed(_)
    ) {
        return Err(invalid_data("worker-b store was not installed"));
    }
    create_user(&beta, "shared-user", "beta@example.invalid")?;

    let beta_guard = beta
        .lock()
        .map_err(|_| invalid_data("worker-b store lock poisoned"))?;
    let lookup_registry = Arc::clone(&registry);
    let lookup = std::thread::spawn(move || {
        lookup_registry.compatibility_store_for_unique_user("shared-user")
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match alpha.try_lock() {
            Err(TryLockError::WouldBlock) => break,
            Err(TryLockError::Poisoned(_)) => {
                return Err(invalid_data("worker-a store lock poisoned"));
            }
            Ok(guard) => drop(guard),
        }
        if Instant::now() >= deadline {
            return Err(invalid_data("lookup did not retain the earlier store lock"));
        }
        std::thread::yield_now();
    }

    let (created_tx, created_rx) = mpsc::sync_channel(1);
    let creator_store = Arc::clone(&alpha);
    let creator = std::thread::spawn(move || {
        let result = creator_store.lock().map_err(|_| ()).and_then(|mut store| {
            store
                .create_user_with_id(
                    NewUser::email("alpha@example.invalid"),
                    Some("shared-user"),
                    LogicalInstant::UNIX_EPOCH,
                )
                .map(|_| ())
                .map_err(|_| ())
        });
        let _ = created_tx.send(result);
    });
    if created_rx.recv_timeout(Duration::from_millis(100)).is_ok() {
        return Err(invalid_data(
            "user move interleaved with compatibility lookup",
        ));
    }
    drop(beta_guard);
    let selected = lookup
        .join()
        .map_err(|_| invalid_data("compatibility lookup thread panicked"))?;
    creator
        .join()
        .map_err(|_| invalid_data("compatibility user-move thread panicked"))?;
    match selected {
        CompatibilityUserStoreMatch::Unique(store) => store
            .lock()
            .map(|store| store.project_id().to_owned())
            .map_err(|_| invalid_data("selected moved-user store lock poisoned")),
        _ => Err(invalid_data(
            "coherent lookup did not preserve the old unique route",
        )),
    }
}

fn node_decisions(case: &str) -> Result<(String, String)> {
    let candidates = match case {
        "runtime" => vec![candidate(true, false, true), candidate(true, true, true)],
        "engine" => vec![candidate(true, true, false), candidate(true, true, true)],
        _ => vec![candidate(false, true, true), candidate(true, true, true)],
    };
    let names = match case {
        "runtime" => ["node22new", "node20new"],
        "engine" => ["node20new", "node22new"],
        _ => ["node22old", "node22new"],
    };
    let automatic = select_node_candidate(false, true, &candidates)
        .and_then(|index| names.get(index))
        .ok_or_else(|| invalid_data("automatic Node selection failed"))?;
    let explicit_candidates = [candidate(false, false, false), candidate(true, true, true)];
    let explicit_names = ["node22old", "node22new"];
    let explicit = select_node_candidate(true, true, &explicit_candidates)
        .and_then(|index| explicit_names.get(index))
        .ok_or_else(|| invalid_data("explicit Node selection failed"))?;
    Ok(((*automatic).to_owned(), (*explicit).to_owned()))
}

const fn candidate(
    require_module: bool,
    runtime_matches: bool,
    engine_matches: bool,
) -> NodeCandidate {
    NodeCandidate {
        require_module,
        runtime_matches,
        engine_matches,
    }
}

fn initial_state() -> CompatibilitySelectionState {
    CompatibilitySelectionState {
        last_case: "none".to_owned(),
        auth_decision: "pending".to_owned(),
        automatic_node: "pending".to_owned(),
        explicit_node: "pending".to_owned(),
        store_aliases: false,
    }
}

fn invalid_data(message: &str) -> anyhow::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned()).into()
}
