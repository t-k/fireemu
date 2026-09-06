//! Quint Connect driver for optimistic transaction conflict retries around a conditional lock.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{
    FirestoreError, FirestoreState, TransactionId, Write, WriteOp,
};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;
use quint_connect::{switch, Config, Driver, Result, State, Step};
use serde::Deserialize;

/// Actions exercised through the production transaction boundary.
pub const MODELED_ACTIONS: [&str; 7] = [
    "ReadUnlocked",
    "Commit",
    "AbortStale",
    "Retry",
    "RejectLocked",
    "RunProtectedAction",
    "Release",
];

/// Reproducible seeds used by generated conformance campaigns.
pub const GENERATED_TRACE_SEEDS: [&str; 4] = ["0x1", "0x2", "0x3", "0x4"];

const CLIENTS: [&str; 2] = ["c1", "c2"];

/// Production-derived lock state plus bounded protocol observations.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransactionConditionalLockState {
    /// Protocol phase for each bounded client.
    pub phase: BTreeMap<String, String>,
    /// Value read from the real lock document.
    pub locked: bool,
    /// Values returned by real transaction reads for each attempt.
    pub observations: BTreeMap<String, Vec<bool>>,
    /// Clients that reached the protected side effect.
    pub acted: BTreeSet<String>,
}

/// Test-only perturbation after reading the projection boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionFault {
    /// Change only one client phase.
    Phase,
    /// Change only the real lock projection.
    Locked,
    /// Change only one observation list.
    Observations,
    /// Change only the protected-action set.
    Acted,
}

impl ProjectionFault {
    /// Returns the serialized field affected by this fault.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::Phase => "phase",
            Self::Locked => "locked",
            Self::Observations => "observations",
            Self::Acted => "acted",
        }
    }
}

/// Stateful adapter around one real `FirestoreState`.
pub struct TransactionConditionalLockDriver {
    store: FirestoreState,
    phase: BTreeMap<String, String>,
    observations: BTreeMap<String, Vec<bool>>,
    acted: BTreeSet<String>,
    transactions: BTreeMap<String, TransactionId>,
    projection_fault: Option<ProjectionFault>,
    action_recorder: Option<Arc<Mutex<BTreeSet<String>>>>,
}

impl Default for TransactionConditionalLockDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionConditionalLockDriver {
    /// Builds a fresh bounded conditional-lock driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: FirestoreState::new(),
            phase: client_map("Ready"),
            observations: CLIENTS
                .into_iter()
                .map(|client| (client.to_owned(), Vec::new()))
                .collect(),
            acted: BTreeSet::new(),
            transactions: BTreeMap::new(),
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

    /// Changes the projection-only fault without mutating state.
    pub fn set_projection_fault(&mut self, fault: ProjectionFault) {
        self.projection_fault = Some(fault);
    }

    /// Recreates the production store and bounded protocol state.
    pub fn init(&mut self) -> Result {
        self.store = FirestoreState::new();
        self.phase = client_map("Ready");
        self.observations = CLIENTS
            .into_iter()
            .map(|client| (client.to_owned(), Vec::new()))
            .collect();
        self.acted.clear();
        self.transactions.clear();
        Ok(())
    }

    /// Begins a real read-write transaction and observes the unlocked document.
    pub fn read_unlocked(&mut self, client: &str) -> Result {
        self.require_phase(client, "Ready")?;
        if self.locked()? {
            return Err(invalid_data(
                "the bounded read requires an unlocked document",
            ));
        }
        let transaction = self
            .store
            .begin_transaction(false, LogicalInstant::UNIX_EPOCH)
            .map_err(|error| firestore_error(&error))?;
        let observed = self
            .store
            .get_in_transaction(&transaction, &lock_path())
            .map_err(|error| firestore_error(&error))?
            .map_or(Ok(false), |document| lock_value(&document))?;
        if observed {
            return Err(invalid_data(
                "the initial transaction observed a locked document",
            ));
        }
        self.transactions.insert(client.to_owned(), transaction);
        self.observations
            .get_mut(client)
            .ok_or_else(|| invalid_data("unknown bounded client"))?
            .push(observed);
        self.set_phase(client, "Read")?;
        self.record_action("ReadUnlocked")
    }

    /// Commits the first stale snapshot through the real transaction API.
    pub fn commit(&mut self, client: &str) -> Result {
        self.require_phase(client, "Read")?;
        if self
            .observations
            .values()
            .any(|observations| observations.as_slice() != [false])
        {
            return Err(invalid_data("both clients must read the unlocked snapshot"));
        }
        if self.locked()? {
            return Err(invalid_data(
                "the winning commit requires an unlocked document",
            ));
        }
        let transaction = self.transaction(client)?.clone();
        match self.store.commit(
            &[set_lock_write(true)],
            Some(&transaction),
            LogicalInstant::UNIX_EPOCH,
        ) {
            Ok(_) => self.set_phase(client, "Committed")?,
            // Held back by the other client's read lock (the adapter waits for the release);
            // the commit completes when that client's commit is aborted as the deadlock victim.
            Err(FirestoreError::Aborted(_)) if self.store.transaction_is_active(&transaction) => {
                self.set_phase(client, "Held")?;
            }
            Err(error) => return Err(firestore_error(&error)),
        }
        self.record_action("Commit")
    }

    /// Confirms the other stale transaction is rejected as retryable `ABORTED`.
    pub fn abort_stale(&mut self, client: &str) -> Result {
        self.require_phase(client, "Read")?;
        let held: Vec<String> = CLIENTS
            .into_iter()
            .filter(|other| {
                *other != client && self.phase.get(*other).map(String::as_str) == Some("Held")
            })
            .map(str::to_owned)
            .collect();
        if !self.locked()? && held.is_empty() {
            return Err(invalid_data(
                "a stale abort requires the committed lock or a held-back commit",
            ));
        }
        let transaction = self.transaction(client)?.clone();
        match self.store.commit(
            &[set_lock_write(true)],
            Some(&transaction),
            LogicalInstant::UNIX_EPOCH,
        ) {
            Err(FirestoreError::Aborted(_)) => {}
            Err(error) => {
                return Err(invalid_data(&format!(
                    "stale production commit returned the wrong error: {error}"
                )));
            }
            Ok(_) => return Err(invalid_data("stale production transaction committed")),
        }
        self.set_phase(client, "Aborted")?;
        // The victim released its lock: a held-back commit goes through now, as the adapter's
        // wait loop retries it in the daemon.
        for other in held {
            let held_transaction = self.transaction(&other)?.clone();
            self.store
                .commit(
                    &[set_lock_write(true)],
                    Some(&held_transaction),
                    LogicalInstant::UNIX_EPOCH,
                )
                .map_err(|error| firestore_error(&error))?;
            self.set_phase(&other, "Committed")?;
        }
        self.record_action("AbortStale")
    }

    /// Starts a real retry lineage and reads the winner's committed lock.
    pub fn retry(&mut self, client: &str) -> Result {
        self.require_phase(client, "Aborted")?;
        let previous = self.transaction(client)?.clone();
        let retry = self
            .store
            .retry_transaction(&previous, LogicalInstant::UNIX_EPOCH)
            .map_err(|error| firestore_error(&error))?;
        let observed = self
            .store
            .get_in_transaction(&retry, &lock_path())
            .map_err(|error| firestore_error(&error))?
            .map_or(Ok(false), |document| lock_value(&document))?;
        self.transactions.insert(client.to_owned(), retry);
        self.observations
            .get_mut(client)
            .ok_or_else(|| invalid_data("unknown bounded client"))?
            .push(observed);
        self.set_phase(client, "Retried")?;
        self.record_action("Retry")
    }

    /// Rejects the application operation after its retry observes `locked=true`.
    pub fn reject_locked(&mut self, client: &str) -> Result {
        self.require_phase(client, "Retried")?;
        if self.observations.get(client).map(Vec::as_slice) != Some(&[false, true]) {
            return Err(invalid_data("the retry did not observe the committed lock"));
        }
        let transaction = self.transaction(client)?.clone();
        self.store
            .rollback(&transaction)
            .map_err(|error| firestore_error(&error))?;
        self.set_phase(client, "Rejected")?;
        self.record_action("RejectLocked")
    }

    /// Records the bounded protected action for the winning transaction.
    pub fn run_protected_action(&mut self, client: &str) -> Result {
        self.require_phase(client, "Committed")?;
        if !self.acted.insert(client.to_owned()) {
            return Err(invalid_data("the protected action already ran"));
        }
        self.record_action("RunProtectedAction")
    }

    /// Releases the real lock only after every losing client has rejected its retry.
    pub fn release(&mut self, client: &str) -> Result {
        self.require_phase(client, "Committed")?;
        if !self.acted.contains(client) {
            return Err(invalid_data("the protected action has not completed"));
        }
        if CLIENTS
            .into_iter()
            .filter(|other| *other != client)
            .any(|other| self.phase.get(other).map(String::as_str) != Some("Rejected"))
        {
            return Err(invalid_data("the losing retry has not rejected the lock"));
        }
        self.store
            .commit(&[set_lock_write(false)], None, LogicalInstant::UNIX_EPOCH)
            .map_err(|error| firestore_error(&error))?;
        self.set_phase(client, "Done")?;
        self.record_action("Release")
    }

    /// Projects the real lock document and bounded protocol observations.
    pub fn project(&self) -> Result<TransactionConditionalLockState> {
        let mut projected = TransactionConditionalLockState {
            phase: self.phase.clone(),
            locked: self.locked()?,
            observations: self.observations.clone(),
            acted: self.acted.clone(),
        };
        match self.projection_fault {
            None => {}
            Some(ProjectionFault::Phase) => {
                projected
                    .phase
                    .insert("c1".to_owned(), "Faulted".to_owned());
            }
            Some(ProjectionFault::Locked) => projected.locked = !projected.locked,
            Some(ProjectionFault::Observations) => {
                projected
                    .observations
                    .entry("c1".to_owned())
                    .or_default()
                    .push(true);
            }
            Some(ProjectionFault::Acted) => {
                projected.acted.insert("c1".to_owned());
            }
        }
        Ok(projected)
    }

    fn locked(&self) -> Result<bool> {
        self.store.get(&lock_path()).map_or(Ok(false), lock_value)
    }

    fn transaction(&self, client: &str) -> Result<&TransactionId> {
        self.transactions
            .get(client)
            .ok_or_else(|| invalid_data("client has no active transaction"))
    }

    fn require_phase(&self, client: &str, expected: &str) -> Result {
        if self.phase.get(client).map(String::as_str) == Some(expected) {
            Ok(())
        } else {
            Err(invalid_data("action is disabled in the client phase"))
        }
    }

    fn set_phase(&mut self, client: &str, phase: &str) -> Result {
        let value = self
            .phase
            .get_mut(client)
            .ok_or_else(|| invalid_data("unknown bounded client"))?;
        phase.clone_into(value);
        Ok(())
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

impl State<TransactionConditionalLockDriver> for TransactionConditionalLockState {
    fn from_driver(driver: &TransactionConditionalLockDriver) -> Result<Self> {
        driver.project()
    }
}

impl Driver for TransactionConditionalLockDriver {
    type State = TransactionConditionalLockState;

    fn config() -> Config {
        Config {
            state: &["TransactionConditionalLockScenarios::TransactionConditionalLock::observable"],
            nondet: &[
                "TransactionConditionalLockScenarios::TransactionConditionalLock::actionTaken",
            ],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        switch!(step {
            init => self.init()?,
            ReadUnlocked(client: String) => self.read_unlocked(&client)?,
            Commit(client: String) => self.commit(&client)?,
            AbortStale(client: String) => self.abort_stale(&client)?,
            Retry(client: String) => self.retry(&client)?,
            RejectLocked(client: String) => self.reject_locked(&client)?,
            RunProtectedAction(client: String) => self.run_protected_action(&client)?,
            Release(client: String) => self.release(&client)?,
        })
    }
}

/// Driver configured for generated traces.
pub struct TransactionConditionalLockConnectDriver {
    inner: TransactionConditionalLockDriver,
}

impl Default for TransactionConditionalLockConnectDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionConditionalLockConnectDriver {
    /// Builds a fresh generated-trace driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: TransactionConditionalLockDriver::new(),
        }
    }
}

impl State<TransactionConditionalLockConnectDriver> for TransactionConditionalLockState {
    fn from_driver(driver: &TransactionConditionalLockConnectDriver) -> Result<Self> {
        driver.inner.project()
    }
}

impl Driver for TransactionConditionalLockConnectDriver {
    type State = TransactionConditionalLockState;

    fn config() -> Config {
        Config {
            state: &["TransactionConditionalLockConnect::TransactionConditionalLock::observable"],
            nondet: &["TransactionConditionalLockConnect::TransactionConditionalLock::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        self.inner.step(step)
    }
}

fn client_map(value: &str) -> BTreeMap<String, String> {
    CLIENTS
        .into_iter()
        .map(|client| (client.to_owned(), value.to_owned()))
        .collect()
}

fn lock_path() -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("quint-connect").expect("fixed project id is valid"),
        &DatabaseId::default_database(),
        "locks/conditional",
    )
    .expect("bounded lock path is valid")
}

fn set_lock_write(locked: bool) -> Write {
    Write {
        op: WriteOp::Set {
            path: lock_path(),
            fields: BTreeMap::from([("locked".to_owned(), Value::Boolean(locked))]),
            update_mask: None,
        },
        precondition: None,
        transforms: Vec::new(),
    }
}

fn lock_value(document: &fireemu_core_firestore::store::Document) -> Result<bool> {
    match document.fields.get("locked") {
        Some(Value::Boolean(value)) => Ok(*value),
        _ => Err(invalid_data(
            "production lock document has no boolean locked field",
        )),
    }
}

fn firestore_error(error: &FirestoreError) -> anyhow::Error {
    invalid_data(&format!("production Firestore operation failed: {error}"))
}

fn invalid_data(message: &str) -> anyhow::Error {
    anyhow::anyhow!(message.to_owned())
}
