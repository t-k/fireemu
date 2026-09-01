//! Quint Connect driver for the production session lifecycle and epoch guard.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{Arc, Mutex};

use fireemu_core_session::session::{Session, SessionState, WorkResult};
use fireemu_core_types::ids::{Epoch, SessionId};
use fireemu_core_types::time::LogicalInstant;
use quint_connect::{switch, Config, Driver, Result, State, Step};
use serde::Deserialize;

/// Actions exercised through the production lifecycle and epoch guard.
pub const MODELED_ACTIONS: [&str; 8] = [
    "Activate",
    "BeginReset",
    "CompleteReset",
    "BeginClose",
    "CompleteClose",
    "CaptureWork",
    "ApplyWork",
    "DiscardWork",
];

/// Reproducible seeds used by generated conformance campaigns.
pub const GENERATED_TRACE_SEEDS: [&str; 4] = ["0x1", "0x2", "0x3", "0x4"];

const MAX_EPOCH: u64 = 2;
const WORKERS: [&str; 2] = ["w1", "w2"];

/// Production-derived state compared after every action.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionEpochState {
    /// Current production lifecycle state.
    pub state: String,
    /// Current production epoch.
    pub epoch: u64,
    /// Last production `check_work_epoch` result.
    pub work_epoch_result: String,
}

/// Test-only perturbation after reading production state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionFault {
    /// Change only the lifecycle state.
    State,
    /// Change only the epoch.
    Epoch,
    /// Change only the latest epoch-guard result.
    WorkEpochResult,
}

impl ProjectionFault {
    /// Returns the serialized production field affected by this fault.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::State => "state",
            Self::Epoch => "epoch",
            Self::WorkEpochResult => "workEpochResult",
        }
    }
}

/// Stateful adapter around one real `Session`.
pub struct SessionEpochDriver {
    session: Session,
    work_epochs: BTreeMap<String, Option<Epoch>>,
    applied: BTreeSet<(String, u64, u64)>,
    last_work_result: String,
    projection_fault: Option<ProjectionFault>,
    action_recorder: Option<Arc<Mutex<BTreeSet<String>>>>,
}

impl Default for SessionEpochDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionEpochDriver {
    /// Builds an uninitialized bounded session driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            session: fresh_session(),
            work_epochs: empty_slots(),
            applied: BTreeSet::new(),
            last_work_result: "NotChecked".to_owned(),
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

    /// Changes the projection-only fault without mutating session state.
    pub fn set_projection_fault(&mut self, fault: ProjectionFault) {
        self.projection_fault = Some(fault);
    }

    /// Resets the real session and harness-only work slots.
    pub fn init(&mut self) -> Result {
        self.session = fresh_session();
        self.work_epochs = empty_slots();
        self.applied.clear();
        self.last_work_result = "NotChecked".to_owned();
        Ok(())
    }

    /// Activates the real session.
    pub fn activate(&mut self) -> Result {
        self.session
            .activate()
            .map_err(|error| invalid_data(&error.to_string()))?;
        self.record_action("Activate")
    }

    /// Begins a bounded real epoch switch.
    pub fn begin_reset(&mut self) -> Result {
        if self.session.epoch().value() >= MAX_EPOCH {
            return Err(invalid_data("bounded epoch space is exhausted"));
        }
        self.session
            .begin_reset()
            .map_err(|error| invalid_data(&error.to_string()))?;
        self.record_action("BeginReset")
    }

    /// Completes the real epoch switch.
    pub fn complete_reset(&mut self) -> Result {
        self.session
            .complete_reset()
            .map_err(|error| invalid_data(&error.to_string()))?;
        self.record_action("CompleteReset")
    }

    /// Begins closing the real session, including from Resetting.
    pub fn begin_close(&mut self) -> Result {
        self.session
            .begin_close()
            .map_err(|error| invalid_data(&error.to_string()))?;
        self.record_action("BeginClose")
    }

    /// Completes closing the real session.
    pub fn complete_close(&mut self) -> Result {
        self.session
            .complete_close()
            .map_err(|error| invalid_data(&error.to_string()))?;
        self.record_action("CompleteClose")
    }

    /// Captures the public session epoch into a harness work slot while Active.
    pub fn capture_work(&mut self, worker: &str) -> Result {
        if self.session.state() != SessionState::Active {
            return Err(invalid_data("work capture requires an active session"));
        }
        let epoch = self.session.epoch();
        let slot = self.slot_mut(worker)?;
        if slot.is_some() {
            return Err(invalid_data("worker already owns captured work"));
        }
        *slot = Some(epoch);
        self.record_action("CaptureWork")
    }

    /// Calls the real epoch guard immediately before recording an applied effect.
    pub fn apply_work(&mut self, worker: &str) -> Result {
        let captured = self.captured_epoch(worker)?;
        let result = self.session.check_work_epoch(captured);
        if result != WorkResult::Proceed {
            return Err(invalid_data(
                "production epoch guard rejected work application",
            ));
        }
        self.applied.insert((
            worker.to_owned(),
            captured.value(),
            self.session.epoch().value(),
        ));
        *self.slot_mut(worker)? = None;
        self.last_work_result = work_result_name(result);
        self.record_action("ApplyWork")
    }

    /// Calls the real epoch guard and clears only stale work.
    pub fn discard_work(&mut self, worker: &str) -> Result {
        let captured = self.captured_epoch(worker)?;
        let result = self.session.check_work_epoch(captured);
        if result != WorkResult::DiscardedStaleEpoch {
            return Err(invalid_data(
                "production epoch guard did not classify work as stale",
            ));
        }
        *self.slot_mut(worker)? = None;
        self.last_work_result = work_result_name(result);
        self.record_action("DiscardWork")
    }

    /// Projects only production lifecycle, epoch, and guard-result fields.
    pub fn project(&self) -> Result<SessionEpochState> {
        let mut projected = SessionEpochState {
            state: state_name(self.session.state()).to_owned(),
            epoch: self.session.epoch().value(),
            work_epoch_result: self.last_work_result.clone(),
        };
        match self.projection_fault {
            None => {}
            Some(ProjectionFault::State) => projected.state = "Closed".to_owned(),
            Some(ProjectionFault::Epoch) => projected.epoch = projected.epoch.saturating_add(1),
            Some(ProjectionFault::WorkEpochResult) => {
                projected.work_epoch_result = if projected.work_epoch_result == "Proceed" {
                    "DiscardedStaleEpoch".to_owned()
                } else {
                    "Proceed".to_owned()
                };
            }
        }
        Ok(projected)
    }

    fn slot_mut(&mut self, worker: &str) -> Result<&mut Option<Epoch>> {
        self.work_epochs
            .get_mut(worker)
            .ok_or_else(|| invalid_data(&format!("unknown worker {worker}")))
    }

    fn captured_epoch(&self, worker: &str) -> Result<Epoch> {
        self.work_epochs
            .get(worker)
            .copied()
            .flatten()
            .ok_or_else(|| invalid_data(&format!("worker {worker} has no captured work")))
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

impl State<SessionEpochDriver> for SessionEpochState {
    fn from_driver(driver: &SessionEpochDriver) -> Result<Self> {
        driver.project()
    }
}

impl Driver for SessionEpochDriver {
    type State = SessionEpochState;

    fn config() -> Config {
        Config {
            state: &["SessionEpochScenarios::SessionEpoch::observable"],
            nondet: &["SessionEpochScenarios::SessionEpoch::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        switch!(step {
            init => self.init()?,
            Activate => self.activate()?,
            BeginReset => self.begin_reset()?,
            CompleteReset => self.complete_reset()?,
            BeginClose => self.begin_close()?,
            CompleteClose => self.complete_close()?,
            CaptureWork(worker: String) => self.capture_work(&worker)?,
            ApplyWork(worker: String) => self.apply_work(&worker)?,
            DiscardWork(worker: String) => self.discard_work(&worker)?,
        })
    }
}

/// Driver configured for generated traces.
pub struct SessionEpochConnectDriver {
    inner: SessionEpochDriver,
}

impl Default for SessionEpochConnectDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionEpochConnectDriver {
    /// Builds a fresh generated-trace driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: SessionEpochDriver::new(),
        }
    }
}

impl State<SessionEpochConnectDriver> for SessionEpochState {
    fn from_driver(driver: &SessionEpochConnectDriver) -> Result<Self> {
        driver.inner.project()
    }
}

impl Driver for SessionEpochConnectDriver {
    type State = SessionEpochState;

    fn config() -> Config {
        Config {
            state: &["SessionEpochConnect::SessionEpoch::observable"],
            nondet: &["SessionEpochConnect::SessionEpoch::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        self.inner.step(step)
    }
}

fn fresh_session() -> Session {
    Session::create(SessionId::new(1), 7, LogicalInstant::UNIX_EPOCH)
}

fn empty_slots() -> BTreeMap<String, Option<Epoch>> {
    WORKERS
        .into_iter()
        .map(|worker| (worker.to_owned(), None))
        .collect()
}

const fn state_name(state: SessionState) -> &'static str {
    match state {
        SessionState::Creating => "Creating",
        SessionState::Active => "Active",
        SessionState::Resetting => "Resetting",
        SessionState::Closing => "Closing",
        SessionState::Closed => "Closed",
    }
}

fn work_result_name(result: WorkResult) -> String {
    match result {
        WorkResult::Proceed => "Proceed".to_owned(),
        WorkResult::DiscardedStaleEpoch => "DiscardedStaleEpoch".to_owned(),
        WorkResult::SessionNotActive(state) => format!("SessionNotActive{}", state_name(state)),
    }
}

fn invalid_data(message: &str) -> anyhow::Error {
    anyhow::Error::new(io::Error::new(io::ErrorKind::InvalidData, message))
}
