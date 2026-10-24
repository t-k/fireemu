//! Quint Connect driver for actual Firestore limit refusals and Functions publication roots.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use crate::atomic_commit_outbox::{
    AtomicCommitOutboxDriver, AtomicCommitOutboxState, ProjectionFault,
};
use quint_connect::{switch, Config, Driver, Result, State, Step};

/// Actions exposed by the bounded rejection model.
pub const MODELED_ACTIONS: [&str; 5] = ["Seed", "Begin", "Stage", "Attempt", "Reset"];
/// Production projections shared with the atomic publication bridge.
pub type LimitRejectionState = AtomicCommitOutboxState;

/// Real adapter/runtime bridge; harness metadata never substitutes for publication state.
#[derive(Default)]
pub struct LimitRejectionDriver {
    inner: AtomicCommitOutboxDriver,
    recorder: Option<Arc<Mutex<BTreeSet<String>>>>,
}

impl LimitRejectionDriver {
    /// Creates a fresh production bridge.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Records every successfully dispatched model action.
    #[must_use]
    pub fn with_action_recorder(mut self, recorder: Arc<Mutex<BTreeSet<String>>>) -> Self {
        self.recorder = Some(recorder);
        self
    }
    /// Perturbs exactly one field after production state has been projected.
    #[must_use]
    pub fn with_projection_fault(mut self, fault: ProjectionFault) -> Self {
        self.inner = self.inner.with_projection_fault(fault);
        self
    }
    /// Initializes an empty actual database and runtime accounting.
    pub fn init(&mut self) -> Result {
        self.inner.init()?;
        self.inner.configure_limit_index();
        Ok(())
    }
    /// Number of configured production composites in the fixture catalog.
    #[must_use]
    pub fn configured_index_count(&self) -> usize {
        self.inner.configured_limit_index_count()
    }
    /// Seeds a real preexisting document and its published logical events.
    pub fn seed(&mut self) -> Result {
        self.inner.seed_limit_state()?;
        self.record("Seed")
    }
    /// Opens a batch without changing production state.
    pub fn begin(&mut self) -> Result {
        self.inner.begin_limit_batch()?;
        self.record("Begin")
    }
    /// Stages one valid write and its matching logical event.
    pub fn stage(&mut self, doc: &str) -> Result {
        self.inner.stage_write(doc)?;
        self.inner.stage_outbox(doc)?;
        self.record("Stage")
    }
    /// Executes the actual adapter commit, either valid or with a known limit violation.
    pub fn attempt(&mut self, kind: &str) -> Result {
        if kind == "valid" {
            self.inner.reserve()?;
            self.inner.commit()?;
        } else {
            self.inner.reject_limit(kind)?;
        }
        self.record("Attempt")
    }
    /// Restores the empty bounded starting state through real reset APIs.
    pub fn reset(&mut self) -> Result {
        self.init()?;
        self.record("Reset")
    }
    /// Reads real document versions, outbox changes and reserved/published event accounting.
    pub fn project(&self) -> Result<LimitRejectionState> {
        self.inner.project()
    }
    fn record(&self, action: &str) -> Result {
        if let Some(recorder) = &self.recorder {
            recorder
                .lock()
                .map_err(|_| anyhow::anyhow!("action recorder lock is poisoned"))?
                .insert(action.to_owned());
        }
        Ok(())
    }
}

impl State<LimitRejectionDriver> for LimitRejectionState {
    fn from_driver(driver: &LimitRejectionDriver) -> Result<Self> {
        driver.project()
    }
}
impl Driver for LimitRejectionDriver {
    type State = LimitRejectionState;
    fn config() -> Config {
        Config {
            state: &["LimitRejectionScenarios::LimitRejection::observable"],
            nondet: &["LimitRejectionScenarios::LimitRejection::actionTaken"],
        }
    }
    #[allow(non_snake_case)]
    fn step(&mut self, step: &Step) -> Result {
        switch!(step {
            init => self.init()?,
            Seed => self.seed()?,
            Begin => self.begin()?,
            Stage(doc: String) => self.stage(&doc)?,
            Attempt(kind: String) => self.attempt(&kind)?,
            Reset => self.reset()?,
        })
    }
}

/// Driver configured for bounded generated traces.
#[derive(Default)]
pub struct LimitRejectionConnectDriver(LimitRejectionDriver);
impl State<LimitRejectionConnectDriver> for LimitRejectionState {
    fn from_driver(driver: &LimitRejectionConnectDriver) -> Result<Self> {
        driver.0.project()
    }
}
impl Driver for LimitRejectionConnectDriver {
    type State = LimitRejectionState;
    fn config() -> Config {
        Config {
            state: &["LimitRejectionConnect::LimitRejection::observable"],
            nondet: &["LimitRejectionConnect::LimitRejection::actionTaken"],
        }
    }
    fn step(&mut self, step: &Step) -> Result {
        self.0.step(step)
    }
}
