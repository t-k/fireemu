//! Quint Connect driver for the production causal work ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use fireemu_core_session::idle::{
    AwaitIdleOptions, IdleVerdict, IdleWaitPolicy, WorkKind, WorkLedger, WorkToken,
};
use fireemu_core_types::ids::Epoch;
use quint_connect::{switch, Config, Driver, Result, State, Step};
use serde::Deserialize;

/// Actions exercised through the causal work and fence lifecycle.
pub const MODELED_ACTIONS: [&str; 6] = [
    "BeginExternal",
    "CompleteLeaf",
    "CompleteWithReservation",
    "EnqueueChild",
    "RequestFence",
    "ReturnIdle",
];

/// Reproducible seeds used by generated conformance campaigns.
pub const GENERATED_TRACE_SEEDS: [&str; 4] = ["0x1", "0x2", "0x3", "0x4"];

const ITEMS: [&str; 3] = ["i1", "i2", "i3"];

/// Production ledger state visible at the conformance boundary.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwaitIdleState {
    /// Lifecycle of the modeled fence request.
    pub fence: String,
    /// Active item identity to production work kind.
    pub in_flight: BTreeMap<String, String>,
    /// Parents whose production reservation token is still active.
    pub reservations: BTreeSet<String>,
    /// Whether the fence returned after the production verdict became idle.
    pub returned: bool,
}

/// Test-only perturbation after reading production state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionFault {
    /// Change only the fence lifecycle.
    Fence,
    /// Change only active production work.
    InFlight,
    /// Change only production reservations.
    Reservations,
    /// Change only the returned bit.
    Returned,
}

impl ProjectionFault {
    /// Serialized field changed by this fault.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::Fence => "fence",
            Self::InFlight => "inFlight",
            Self::Reservations => "reservations",
            Self::Returned => "returned",
        }
    }
}

/// Stateful adapter around one real [`WorkLedger`].
pub struct AwaitIdleDriver {
    ledger: WorkLedger,
    options: AwaitIdleOptions,
    fence: String,
    active: BTreeMap<String, (WorkToken, WorkKind)>,
    reservations: BTreeMap<String, WorkToken>,
    used: BTreeSet<String>,
    projection_fault: Option<ProjectionFault>,
    action_recorder: Option<Arc<Mutex<BTreeSet<String>>>>,
}

impl AwaitIdleDriver {
    /// Builds an uninitialized driver with the selected Text Index policy.
    #[must_use]
    pub fn new(ignore_text_index: bool) -> Self {
        Self {
            ledger: WorkLedger::new(Epoch::initial()),
            options: AwaitIdleOptions {
                text_index_builds: if ignore_text_index {
                    IdleWaitPolicy::Ignore
                } else {
                    IdleWaitPolicy::Wait
                },
                ..AwaitIdleOptions::default()
            },
            fence: "none".to_owned(),
            active: BTreeMap::new(),
            reservations: BTreeMap::new(),
            used: BTreeSet::new(),
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

    /// Recreates the production ledger and harness lifecycle.
    pub fn init(&mut self) -> Result {
        self.ledger = WorkLedger::new(Epoch::initial());
        "none".clone_into(&mut self.fence);
        self.active.clear();
        self.reservations.clear();
        self.used.clear();
        Ok(())
    }

    /// Registers fresh external causal work through the production ledger.
    pub fn begin_external(&mut self, item: &str, kind: &str) -> Result {
        Self::require_item(item)?;
        if self.fence != "none" || self.used.contains(item) {
            return Err(invalid_data("external work is not admissible"));
        }
        let kind = parse_kind(kind)?;
        let token = self
            .ledger
            .begin(kind, Epoch::initial())
            .map_err(|error| invalid_data(&error.to_string()))?;
        self.active.insert(item.to_owned(), (token, kind));
        self.used.insert(item.to_owned());
        self.record_action("BeginExternal")
    }

    /// Completes one leaf through the production ledger.
    pub fn complete_leaf(&mut self, item: &str) -> Result {
        let (token, _) = self
            .active
            .remove(item)
            .ok_or_else(|| invalid_data("active item is missing"))?;
        self.ledger
            .end(token)
            .map_err(|error| invalid_data(&error.to_string()))?;
        self.record_action("CompleteLeaf")
    }

    /// Replaces an active parent with a production child-enqueue reservation.
    pub fn complete_with_reservation(&mut self, item: &str) -> Result {
        let (parent, _) = self
            .active
            .remove(item)
            .ok_or_else(|| invalid_data("active parent is missing"))?;
        let reservation = self
            .ledger
            .begin(WorkKind::ChildEnqueueReservation, Epoch::initial())
            .map_err(|error| invalid_data(&error.to_string()))?;
        if let Err(error) = self.ledger.end(parent) {
            let _ = self.ledger.end(reservation);
            return Err(invalid_data(&error.to_string()));
        }
        self.reservations.insert(item.to_owned(), reservation);
        self.record_action("CompleteWithReservation")
    }

    /// Atomically hands a production reservation to its fresh child.
    pub fn enqueue_child(&mut self, parent: &str, child: &str, kind: &str) -> Result {
        Self::require_item(child)?;
        if self.used.contains(child) {
            return Err(invalid_data("child identity was already used"));
        }
        let reservation = self
            .reservations
            .remove(parent)
            .ok_or_else(|| invalid_data("parent reservation is missing"))?;
        let kind = parse_kind(kind)?;
        let token = self
            .ledger
            .handoff(reservation, kind)
            .map_err(|error| invalid_data(&error.to_string()))?;
        self.active.insert(child.to_owned(), (token, kind));
        self.used.insert(child.to_owned());
        self.record_action("EnqueueChild")
    }

    /// Closes this modeled fence to new external work.
    pub fn request_fence(&mut self) -> Result {
        if self.fence != "none" {
            return Err(invalid_data("fence was already requested"));
        }
        "waiting".clone_into(&mut self.fence);
        self.record_action("RequestFence")
    }

    /// Returns only after the production ledger reports no blocking work.
    pub fn return_idle(&mut self) -> Result {
        if self.fence != "waiting" || self.ledger.verdict(&self.options) != IdleVerdict::Idle {
            return Err(invalid_data("fence is not ready to return"));
        }
        "returned".clone_into(&mut self.fence);
        self.record_action("ReturnIdle")
    }

    /// Projects the live production ledger registrations.
    pub fn project(&self) -> Result<AwaitIdleState> {
        let mut state = AwaitIdleState {
            fence: self.fence.clone(),
            in_flight: ITEMS
                .into_iter()
                .map(|item| {
                    let kind = self
                        .active
                        .get(item)
                        .map_or("", |(_, kind)| kind_name(*kind));
                    (item.to_owned(), kind.to_owned())
                })
                .collect(),
            reservations: self.reservations.keys().cloned().collect(),
            returned: self.fence == "returned",
        };
        match self.projection_fault {
            None => {}
            Some(ProjectionFault::Fence) => "faulted".clone_into(&mut state.fence),
            Some(ProjectionFault::InFlight) => {
                state.in_flight.insert("i1".to_owned(), "event".to_owned());
            }
            Some(ProjectionFault::Reservations) => {
                state.reservations.insert("i3".to_owned());
            }
            Some(ProjectionFault::Returned) => state.returned = !state.returned,
        }
        Ok(state)
    }

    fn require_item(item: &str) -> Result {
        if ITEMS.contains(&item) {
            Ok(())
        } else {
            Err(invalid_data("unknown bounded item"))
        }
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

impl State<AwaitIdleDriver> for AwaitIdleState {
    fn from_driver(driver: &AwaitIdleDriver) -> Result<Self> {
        driver.project()
    }
}

impl Driver for AwaitIdleDriver {
    type State = AwaitIdleState;

    fn config() -> Config {
        Config {
            state: &["AwaitIdleScenarios::AwaitIdle::observable"],
            nondet: &["AwaitIdleScenarios::AwaitIdle::actionTaken"],
        }
    }

    #[allow(non_snake_case)]
    fn step(&mut self, step: &Step) -> Result {
        switch!(step {
            init => self.init()?,
            BeginExternal(item: String, kind: String) => self.begin_external(&item, &kind)?,
            CompleteLeaf(item: String) => self.complete_leaf(&item)?,
            CompleteWithReservation(item: String) => self.complete_with_reservation(&item)?,
            EnqueueChild(item: String, child: String, kind: String) => self.enqueue_child(&item, &child, &kind)?,
            RequestFence => self.request_fence()?,
            ReturnIdle => self.return_idle()?,
        })
    }
}

/// Driver configured for generated traces.
pub struct AwaitIdleConnectDriver(AwaitIdleDriver);

impl AwaitIdleConnectDriver {
    /// Builds a fresh generated-trace driver.
    #[must_use]
    pub fn new() -> Self {
        Self(AwaitIdleDriver::new(false))
    }
}

impl Default for AwaitIdleConnectDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl State<AwaitIdleConnectDriver> for AwaitIdleState {
    fn from_driver(driver: &AwaitIdleConnectDriver) -> Result<Self> {
        driver.0.project()
    }
}

impl Driver for AwaitIdleConnectDriver {
    type State = AwaitIdleState;

    fn config() -> Config {
        Config {
            state: &["AwaitIdleConnect::AwaitIdle::observable"],
            nondet: &["AwaitIdleConnect::AwaitIdle::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        self.0.step(step)
    }
}

fn parse_kind(kind: &str) -> Result<WorkKind> {
    match kind {
        "commit" => Ok(WorkKind::FirestoreCommit),
        "event" => Ok(WorkKind::EventDispatch),
        "invocation" => Ok(WorkKind::FunctionInvocation),
        "textIndexBuild" => Ok(WorkKind::TextIndexBuild),
        _ => Err(invalid_data("unknown modeled work kind")),
    }
}

const fn kind_name(kind: WorkKind) -> &'static str {
    match kind {
        WorkKind::FirestoreCommit => "commit",
        WorkKind::EventDispatch => "event",
        WorkKind::FunctionInvocation => "invocation",
        WorkKind::TextIndexBuild => "textIndexBuild",
        _ => "unsupported",
    }
}

fn invalid_data(message: &str) -> anyhow::Error {
    anyhow::anyhow!(message.to_owned())
}
