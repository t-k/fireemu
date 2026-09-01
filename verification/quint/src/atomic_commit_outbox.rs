//! Quint Connect driver for atomic Firestore writes and their committed change batch.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{FirestoreState, Precondition, Write, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;
use quint_connect::{switch, Config, Driver, Result, State, Step};
use serde::Deserialize;

/// Actions exercised through the atomic commit boundary.
pub const MODELED_ACTIONS: [&str; 6] = [
    "Begin",
    "StageWrite",
    "StageOutbox",
    "DetectConflict",
    "Commit",
    "Abort",
];

/// Reproducible seeds used by generated conformance campaigns.
pub const GENERATED_TRACE_SEEDS: [&str; 4] = ["0x1", "0x2", "0x3", "0x4"];

const DOCS: [&str; 2] = ["d1", "d2"];
const MAX_VERSION: u64 = 2;

/// Production-derived documents and committed changes plus the harness transaction phase.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AtomicCommitOutboxState {
    /// Real document versions, with zero representing absence.
    pub documents: BTreeMap<String, u64>,
    /// Document identities from the real successful commit change batch.
    pub outbox: BTreeSet<String>,
    /// Harness phase around the synchronous production commit call.
    pub transaction_state: String,
}

/// Test-only perturbation after reading the projection boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionFault {
    /// Change only one document version.
    Documents,
    /// Change only the committed change set.
    Outbox,
    /// Change only the harness phase.
    TransactionState,
}

impl ProjectionFault {
    /// Returns the serialized field affected by this fault.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::Documents => "documents",
            Self::Outbox => "outbox",
            Self::TransactionState => "transactionState",
        }
    }
}

/// Stateful adapter around one real `FirestoreState`.
pub struct AtomicCommitOutboxDriver {
    store: FirestoreState,
    phase: String,
    staged: BTreeSet<String>,
    staged_events: BTreeSet<String>,
    conflict: bool,
    committed_changes: BTreeSet<String>,
    projection_fault: Option<ProjectionFault>,
    action_recorder: Option<Arc<Mutex<BTreeSet<String>>>>,
}

impl Default for AtomicCommitOutboxDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicCommitOutboxDriver {
    /// Builds a fresh bounded commit driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: FirestoreState::new(),
            phase: "Idle".to_owned(),
            staged: BTreeSet::new(),
            staged_events: BTreeSet::new(),
            conflict: false,
            committed_changes: BTreeSet::new(),
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

    /// Recreates the production store and harness staging state.
    pub fn init(&mut self) -> Result {
        self.store = FirestoreState::new();
        "Idle".clone_into(&mut self.phase);
        self.staged.clear();
        self.staged_events.clear();
        self.conflict = false;
        self.committed_changes.clear();
        Ok(())
    }

    /// Opens harness staging without modifying production state.
    pub fn begin(&mut self) -> Result {
        self.require_phase("Idle")?;
        "Staging".clone_into(&mut self.phase);
        self.staged.clear();
        self.staged_events.clear();
        self.conflict = false;
        self.record_action("Begin")
    }

    /// Stages one symbolic write for the later real commit.
    pub fn stage_write(&mut self, doc: &str) -> Result {
        self.require_phase("Staging")?;
        self.require_doc(doc)?;
        if self.staged.contains(doc) {
            return Err(invalid_data("document write is already staged"));
        }
        let current = self
            .store
            .get(&document_path(doc))
            .map_or(0, |document| document.version.value());
        if current >= MAX_VERSION {
            return Err(invalid_data("bounded document version is exhausted"));
        }
        self.staged.insert(doc.to_owned());
        self.record_action("StageWrite")
    }

    /// Stages the matching logical event; this remains harness state until commit.
    pub fn stage_outbox(&mut self, doc: &str) -> Result {
        self.require_phase("Staging")?;
        self.require_doc(doc)?;
        if !self.staged.contains(doc) {
            return Err(invalid_data("outbox entry requires a staged write"));
        }
        self.staged_events.insert(doc.to_owned());
        self.record_action("StageOutbox")
    }

    /// Marks the harness transaction as conflicted before exercising real atomic rejection.
    pub fn detect_conflict(&mut self) -> Result {
        self.require_phase("Staging")?;
        self.conflict = true;
        self.record_action("DetectConflict")
    }

    /// Executes all staged writes through one real production commit.
    pub fn commit(&mut self) -> Result {
        self.require_phase("Staging")?;
        if self.conflict || self.staged.is_empty() || self.staged_events != self.staged {
            return Err(invalid_data("commit guard is not satisfied"));
        }
        let writes = self
            .staged
            .iter()
            .map(|doc| set_write(doc, None))
            .collect::<Vec<_>>();
        let result = self
            .store
            .commit(&writes, None, LogicalInstant::UNIX_EPOCH)
            .map_err(|error| invalid_data(&format!("production commit failed: {error}")))?;
        self.committed_changes = result
            .changes
            .iter()
            .map(|change| bounded_doc_name(&change.path))
            .collect::<Result<BTreeSet<_>>>()?;
        "Committed".clone_into(&mut self.phase);
        self.record_action("Commit")
    }

    /// Exercises a real multi-write precondition failure and verifies atomic rejection.
    pub fn abort(&mut self) -> Result {
        self.require_phase("Staging")?;
        if !self.conflict {
            return Err(invalid_data("abort requires a detected conflict"));
        }
        let before = self.production_documents();
        let mut writes = self
            .staged
            .iter()
            .map(|doc| set_write(doc, None))
            .collect::<Vec<_>>();
        if let Some(failing_doc) = self.staged.iter().next() {
            // The prior staged write creates this document in the commit's working copy, so
            // a later `Exists(false)` fails only after earlier writes have been evaluated.
            writes.push(set_write(failing_doc, Some(Precondition::Exists(false))));
        } else {
            writes.push(set_write("d1", Some(Precondition::Exists(true))));
        }
        if self
            .store
            .commit(&writes, None, LogicalInstant::UNIX_EPOCH)
            .is_ok()
        {
            return Err(invalid_data(
                "conflicted production batch unexpectedly committed",
            ));
        }
        if self.production_documents() != before {
            return Err(invalid_data("rejected production batch changed documents"));
        }
        "Aborted".clone_into(&mut self.phase);
        self.record_action("Abort")
    }

    /// Projects real documents and commit changes, plus the declared harness phase.
    pub fn project(&self) -> Result<AtomicCommitOutboxState> {
        let mut projected = AtomicCommitOutboxState {
            documents: self.production_documents(),
            outbox: self.committed_changes.clone(),
            transaction_state: self.phase.clone(),
        };
        match self.projection_fault {
            None => {}
            Some(ProjectionFault::Documents) => {
                projected.documents.insert("d1".to_owned(), MAX_VERSION);
            }
            Some(ProjectionFault::Outbox) => {
                projected.outbox.insert("d1".to_owned());
            }
            Some(ProjectionFault::TransactionState) => {
                "Faulted".clone_into(&mut projected.transaction_state);
            }
        }
        Ok(projected)
    }

    fn production_documents(&self) -> BTreeMap<String, u64> {
        DOCS.into_iter()
            .map(|doc| {
                let version = self
                    .store
                    .get(&document_path(doc))
                    .map_or(0, |document| document.version.value());
                (doc.to_owned(), version)
            })
            .collect()
    }

    fn require_phase(&self, expected: &str) -> Result {
        if self.phase == expected {
            Ok(())
        } else {
            Err(invalid_data("action is disabled in the current phase"))
        }
    }

    fn require_doc(&self, doc: &str) -> Result {
        if DOCS.contains(&doc) {
            Ok(())
        } else {
            Err(invalid_data("unknown bounded document"))
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

impl State<AtomicCommitOutboxDriver> for AtomicCommitOutboxState {
    fn from_driver(driver: &AtomicCommitOutboxDriver) -> Result<Self> {
        driver.project()
    }
}

impl Driver for AtomicCommitOutboxDriver {
    type State = AtomicCommitOutboxState;

    fn config() -> Config {
        Config {
            state: &["AtomicCommitOutboxScenarios::AtomicCommitOutbox::observable"],
            nondet: &["AtomicCommitOutboxScenarios::AtomicCommitOutbox::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        switch!(step {
            init => self.init()?,
            Begin => self.begin()?,
            StageWrite(doc: String) => self.stage_write(&doc)?,
            StageOutbox(doc: String) => self.stage_outbox(&doc)?,
            DetectConflict => self.detect_conflict()?,
            Commit => self.commit()?,
            Abort => self.abort()?,
        })
    }
}

/// Driver configured for generated traces.
pub struct AtomicCommitOutboxConnectDriver {
    inner: AtomicCommitOutboxDriver,
}

impl Default for AtomicCommitOutboxConnectDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicCommitOutboxConnectDriver {
    /// Builds a fresh generated-trace driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: AtomicCommitOutboxDriver::new(),
        }
    }
}

impl State<AtomicCommitOutboxConnectDriver> for AtomicCommitOutboxState {
    fn from_driver(driver: &AtomicCommitOutboxConnectDriver) -> Result<Self> {
        driver.inner.project()
    }
}

impl Driver for AtomicCommitOutboxConnectDriver {
    type State = AtomicCommitOutboxState;

    fn config() -> Config {
        Config {
            state: &["AtomicCommitOutboxConnect::AtomicCommitOutbox::observable"],
            nondet: &["AtomicCommitOutboxConnect::AtomicCommitOutbox::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        self.inner.step(step)
    }
}

fn document_path(doc: &str) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("quint-connect").expect("fixed project id is valid"),
        &DatabaseId::default_database(),
        &format!("docs/{doc}"),
    )
    .expect("bounded document path is valid")
}

fn set_write(doc: &str, precondition: Option<Precondition>) -> Write {
    Write {
        op: WriteOp::Set {
            path: document_path(doc),
            fields: BTreeMap::from([("value".to_owned(), Value::String(doc.to_owned()))]),
            update_mask: None,
        },
        precondition,
        transforms: Vec::new(),
    }
}

fn bounded_doc_name(path: &DocumentPath) -> Result<String> {
    path.relative()
        .strip_prefix("docs/")
        .filter(|doc| DOCS.contains(doc))
        .map(str::to_owned)
        .ok_or_else(|| invalid_data("production change escaped the bounded document set"))
}

fn invalid_data(message: &str) -> anyhow::Error {
    anyhow::anyhow!(message.to_owned())
}
