//! Quint Connect driver for atomic Firestore writes and their committed change batch.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{
    CatchUpPolicy, EventBatchReservation, FunctionsConfig, FunctionsRuntime, OverlapPolicy,
    SourceEventAdmissionError,
};
use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::{
    Actor, AtomicChangeSink, CommitEvent, CommitPublication, LocalBackend,
};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{FirestoreState, Precondition, Write, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::admission::EventAdmissionError;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::SessionId;
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use quint_connect::{switch, Config, Driver, Result, State, Step};
use serde::Deserialize;

/// Actions exercised through the atomic commit boundary.
pub const MODELED_ACTIONS: [&str; 9] = [
    "Begin",
    "StageWrite",
    "StageOutbox",
    "Reserve",
    "Cancel",
    "Reset",
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
    /// Real Functions deliveries owned by an unpublished source mutation.
    pub reserved_events: u64,
    /// Real Functions deliveries published into the runtime outbox.
    pub published_events: u64,
    /// Real Functions session generation owning the reservation and outbox.
    pub event_generation: u64,
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
    /// Change only the reserved Functions delivery count.
    ReservedEvents,
    /// Change only the published Functions delivery count.
    PublishedEvents,
    /// Change only the Functions generation.
    EventGeneration,
}

impl ProjectionFault {
    /// Returns the serialized field affected by this fault.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::Documents => "documents",
            Self::Outbox => "outbox",
            Self::TransactionState => "transactionState",
            Self::ReservedEvents => "reservedEvents",
            Self::PublishedEvents => "publishedEvents",
            Self::EventGeneration => "eventGeneration",
        }
    }
}

/// Stateful driver around the real Firestore adapter and Functions admission boundary.
pub struct AtomicCommitOutboxDriver {
    backend: Arc<LocalBackend>,
    published_changes: Arc<Mutex<BTreeSet<String>>>,
    runtime: Arc<FunctionsRuntime>,
    runtime_executor: tokio::runtime::Runtime,
    base_event_generation: u64,
    phase: String,
    staged: BTreeSet<String>,
    staged_events: BTreeSet<String>,
    conflict: bool,
    committed_changes: BTreeSet<String>,
    reservation: Option<EventBatchReservation>,
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
        let runtime_executor = tokio::runtime::Runtime::new()
            .expect("Quint Connect can create a private Functions executor");
        let runtime = build_functions_runtime(&runtime_executor);
        let (backend, published_changes) = build_firestore_backend(&runtime);
        Self {
            backend,
            published_changes,
            runtime,
            runtime_executor,
            base_event_generation: 0,
            phase: "Idle".to_owned(),
            staged: BTreeSet::new(),
            staged_events: BTreeSet::new(),
            conflict: false,
            committed_changes: BTreeSet::new(),
            reservation: None,
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
        self.reservation.take();
        self.runtime.reset();
        self.base_event_generation = self
            .runtime
            .source_event_accounting()
            .ok_or_else(|| invalid_data("Functions source accounting is unavailable"))?
            .epoch
            .value();
        (self.backend, self.published_changes) = build_firestore_backend(&self.runtime);
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
        self.reservation.take();
        self.record_action("Begin")
    }

    /// Stages one symbolic write for the later real commit.
    pub fn stage_write(&mut self, doc: &str) -> Result {
        self.require_phase("Staging")?;
        Self::require_doc(doc)?;
        if self.staged.contains(doc) {
            return Err(invalid_data("document write is already staged"));
        }
        let current = self
            .firestore_state()
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
        Self::require_doc(doc)?;
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

    /// Reserves the exact real Functions fan-out for the staged prospective commit.
    pub fn reserve(&mut self) -> Result {
        self.require_phase("Staging")?;
        if self.staged.is_empty() || self.staged_events != self.staged || self.conflict {
            return Err(invalid_data("reservation guard is not satisfied"));
        }
        if self.reservation.is_some() {
            return Err(invalid_data("commit already owns an event reservation"));
        }
        let preview = self.preview_commit()?;
        self.reservation = Some(
            self.runtime
                .reserve_commit_events(&preview)
                .map_err(|error| {
                    invalid_data(&format!("production admission failed: {error:?}"))
                })?,
        );
        self.record_action("Reserve")
    }

    /// Cancels the owned batch before the source state changes.
    pub fn cancel(&mut self) -> Result {
        self.require_phase("Staging")?;
        if self.reservation.take().is_none() {
            return Err(invalid_data("cancel requires an event reservation"));
        }
        "Aborted".clone_into(&mut self.phase);
        self.record_action("Cancel")
    }

    /// Advances the real Functions generation while cancelling stale staged ownership.
    pub fn reset(&mut self) -> Result {
        self.require_phase("Staging")?;
        self.runtime.reset();
        self.reservation.take();
        self.staged.clear();
        self.staged_events.clear();
        self.conflict = false;
        "Idle".clone_into(&mut self.phase);
        self.record_action("Reset")
    }

    /// Executes all staged writes through one real production commit.
    pub fn commit(&mut self) -> Result {
        self.require_phase("Staging")?;
        if self.conflict
            || self.staged.is_empty()
            || self.staged_events != self.staged
            || self.reservation.is_none()
        {
            return Err(invalid_data("commit guard is not satisfied"));
        }
        let writes = self
            .staged
            .iter()
            .map(|doc| set_write(doc, None))
            .collect::<Vec<_>>();
        // Reserve/Cancel are independently connected lifecycle actions. The adapter commit
        // acquires and publishes its own batch while holding the database critical section.
        self.reservation.take();
        self.backend
            .commit(&commit_request(&writes))
            .map_err(|error| invalid_data(&format!("adapter commit failed: {error}")))?;
        let published_changes = self
            .published_changes
            .lock()
            .map_err(|_| invalid_data("published change projection is unavailable"))?;
        self.committed_changes.clone_from(&published_changes);
        "Committed".clone_into(&mut self.phase);
        self.record_action("Commit")
    }

    /// Exercises a real multi-write precondition failure and verifies atomic rejection.
    pub fn abort(&mut self) -> Result {
        self.require_phase("Staging")?;
        if !self.conflict {
            return Err(invalid_data("abort requires a detected conflict"));
        }
        if self.reservation.is_some() {
            return Err(invalid_data(
                "a conflicted commit cannot retain a reservation",
            ));
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
        if self.backend.commit(&commit_request(&writes)).is_ok() {
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
            reserved_events: 0,
            published_events: 0,
            event_generation: 0,
        };
        let accounting = self
            .runtime
            .source_event_accounting()
            .ok_or_else(|| invalid_data("Functions source accounting is unavailable"))?;
        projected.reserved_events = u64::try_from(accounting.reserved_records)
            .map_err(|_| invalid_data("reserved event count exceeds the projection"))?;
        projected.published_events = u64::try_from(accounting.published_records)
            .map_err(|_| invalid_data("published event count exceeds the projection"))?;
        projected.event_generation = accounting
            .epoch
            .value()
            .checked_sub(self.base_event_generation)
            .ok_or_else(|| invalid_data("Functions generation moved before the trace base"))?;
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
            Some(ProjectionFault::ReservedEvents) => projected.reserved_events += 1,
            Some(ProjectionFault::PublishedEvents) => projected.published_events += 1,
            Some(ProjectionFault::EventGeneration) => projected.event_generation += 1,
        }
        Ok(projected)
    }

    fn production_documents(&self) -> BTreeMap<String, u64> {
        let store = self.firestore_state();
        DOCS.into_iter()
            .map(|doc| {
                let version = store
                    .get(&document_path(doc))
                    .map_or(0, |document| document.version.value());
                (doc.to_owned(), version)
            })
            .collect()
    }

    fn preview_commit(&self) -> Result<CommitEvent> {
        let mut preview = self.firestore_state();
        let writes = self
            .staged
            .iter()
            .map(|doc| set_write(doc, None))
            .collect::<Vec<_>>();
        let result = preview
            .commit(&writes, None, LogicalInstant::UNIX_EPOCH)
            .map_err(|error| invalid_data(&format!("production preview failed: {error}")))?;
        Ok(CommitEvent {
            actor: Actor::system(),
            project: "quint-connect".to_owned(),
            database: DatabaseId::DEFAULT.to_owned(),
            version: result.version.value(),
            commit_time: Some(result.commit_time),
            changes: result.changes,
        })
    }

    fn firestore_state(&self) -> FirestoreState {
        self.backend
            .snapshot_databases()
            .remove(&("quint-connect".to_owned(), DatabaseId::DEFAULT.to_owned()))
            .unwrap_or_default()
    }

    /// Saturates the real runtime, then proves the real adapter refuses before source publish.
    pub fn verify_real_capacity_refusal(&mut self) -> Result {
        self.init()?;
        self.begin()?;
        self.stage_write("d1")?;
        self.stage_outbox("d1")?;
        let preview = self.preview_commit()?;
        let mut reservations = Vec::new();
        loop {
            match self.runtime.reserve_commit_events(&preview) {
                Ok(reservation) => reservations.push(reservation),
                Err(SourceEventAdmissionError::Capacity) => break,
                Err(error) => {
                    return Err(invalid_data(&format!(
                        "unexpected production admission failure: {error:?}"
                    )))
                }
            }
            if reservations.len() > 5_000 {
                return Err(invalid_data("real Functions capacity was not reached"));
            }
        }
        let before = self.production_documents();
        let writes = vec![set_write("d1", None)];
        let error = self
            .backend
            .commit(&commit_request(&writes))
            .expect_err("the saturated runtime must reject the adapter commit");
        if error.code() != tonic::Code::ResourceExhausted {
            return Err(invalid_data("capacity refusal used the wrong gRPC status"));
        }
        if self.production_documents() != before {
            return Err(invalid_data("capacity refusal published source documents"));
        }
        let accounting = self
            .runtime
            .source_event_accounting()
            .ok_or_else(|| invalid_data("Functions source accounting is unavailable"))?;
        if accounting.published_records != 0 {
            return Err(invalid_data("capacity refusal published logical events"));
        }
        drop(reservations);
        if self
            .runtime
            .source_event_accounting()
            .is_none_or(|accounting| accounting.reserved_records != 0)
        {
            return Err(invalid_data("capacity reservations were not refunded"));
        }
        Ok(())
    }

    fn require_phase(&self, expected: &str) -> Result {
        if self.phase == expected {
            Ok(())
        } else {
            Err(invalid_data("action is disabled in the current phase"))
        }
    }

    fn require_doc(doc: &str) -> Result {
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
            Reserve => self.reserve()?,
            Cancel => self.cancel()?,
            Reset => self.reset()?,
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
        &format!("items/{doc}"),
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

fn commit_request(writes: &[Write]) -> pb::CommitRequest {
    pb::CommitRequest {
        database: "projects/quint-connect/databases/(default)".to_owned(),
        writes: writes.iter().map(encode_set_write).collect(),
        transaction: Vec::new(),
        ..Default::default()
    }
}

fn encode_set_write(write: &Write) -> pb::Write {
    let WriteOp::Set { path, fields, .. } = &write.op else {
        unreachable!("the bounded driver only creates set writes")
    };
    pb::Write {
        operation: Some(pb::write::Operation::Update(pb::Document {
            name: path.resource_name(),
            fields: fields
                .iter()
                .map(|(key, value)| {
                    let Value::String(value) = value else {
                        unreachable!("the bounded driver only creates string fields")
                    };
                    (
                        key.clone(),
                        pb::Value {
                            value_type: Some(pb::value::ValueType::StringValue(value.clone())),
                        },
                    )
                })
                .collect(),
            create_time: None,
            update_time: None,
        })),
        current_document: write.precondition.as_ref().map(|precondition| {
            let Precondition::Exists(exists) = precondition else {
                unreachable!("the bounded driver only creates existence preconditions")
            };
            pb::Precondition {
                condition_type: Some(pb::precondition::ConditionType::Exists(*exists)),
            }
        }),
        update_mask: None,
        update_transforms: Vec::new(),
    }
}

fn bounded_doc_name(path: &DocumentPath) -> std::result::Result<String, EventAdmissionError> {
    path.relative()
        .strip_prefix("items/")
        .filter(|doc| DOCS.contains(doc))
        .map(str::to_owned)
        .ok_or_else(|| {
            EventAdmissionError::InvalidEvent(
                "production change escaped the bounded document set".to_owned(),
            )
        })
}

fn build_functions_runtime(executor: &tokio::runtime::Runtime) -> Arc<FunctionsRuntime> {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/fireemu-adapter-functions/tests/fake_runner.py");
    let spawn = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_string_lossy().into_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(20),
    };
    let runner = executor
        .block_on(Runner::spawn_spec(&spawn))
        .expect("Quint Connect fake Functions runner starts");
    let manifest = parse_manifest(
        runner
            .hello()
            .manifest
            .as_ref()
            .expect("fake Functions runner declares its manifest"),
    )
    .expect("fake Functions manifest is valid");
    let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
    FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            project: "quint-connect".to_owned(),
            default_bucket: "quint-connect.appspot.com".to_owned(),
            location: "nam5".to_owned(),
            session: SessionId::new(1),
            max_running: 4,
            debug_mode: false,
            retry_attempts: 1,
            max_catch_up_runs: 16,
            runner_secret: "quint-connect".to_owned(),
            overlap: OverlapPolicy::Allow,
            catch_up: CatchUpPolicy::All,
            functions_host: None,
        },
        clock,
        Arc::new(runner),
        None,
    )
}

struct RuntimePublication {
    reservation: Option<EventBatchReservation>,
    docs: BTreeSet<String>,
    published_changes: Arc<Mutex<BTreeSet<String>>>,
}

impl CommitPublication for RuntimePublication {
    fn publish(mut self: Box<Self>) {
        if let Ok(mut published) = self.published_changes.lock() {
            *published = std::mem::take(&mut self.docs);
        }
        if let Some(reservation) = self.reservation.take() {
            reservation.publish();
        }
    }
}

struct RuntimeChangeSink {
    runtime: Arc<FunctionsRuntime>,
    published_changes: Arc<Mutex<BTreeSet<String>>>,
}

impl AtomicChangeSink for RuntimeChangeSink {
    fn reserve(
        &self,
        event: &CommitEvent,
    ) -> std::result::Result<Box<dyn CommitPublication>, EventAdmissionError> {
        let docs = event
            .changes
            .iter()
            .map(|change| bounded_doc_name(&change.path))
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        self.runtime
            .reserve_commit_events(event)
            .map(|reservation| {
                Box::new(RuntimePublication {
                    reservation: Some(reservation),
                    docs,
                    published_changes: self.published_changes.clone(),
                }) as Box<dyn CommitPublication>
            })
            .map_err(|error| match error {
                SourceEventAdmissionError::Capacity => {
                    EventAdmissionError::Capacity("Functions event capacity exhausted".to_owned())
                }
                SourceEventAdmissionError::Unavailable => EventAdmissionError::Unavailable(
                    "Functions event admission unavailable".to_owned(),
                ),
                SourceEventAdmissionError::InvalidEvent => {
                    EventAdmissionError::InvalidEvent("invalid Functions event".to_owned())
                }
            })
    }
}

fn build_firestore_backend(
    runtime: &Arc<FunctionsRuntime>,
) -> (Arc<LocalBackend>, Arc<Mutex<BTreeSet<String>>>) {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Conservative,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
    let backend = Arc::new(LocalBackend::new(gateway, clock, 1));
    let published_changes = Arc::new(Mutex::new(BTreeSet::new()));
    backend.set_atomic_change_sink(Arc::new(RuntimeChangeSink {
        runtime: runtime.clone(),
        published_changes: published_changes.clone(),
    }));
    (backend, published_changes)
}

impl Drop for AtomicCommitOutboxDriver {
    fn drop(&mut self) {
        self.runtime.begin_shutdown();
        self.runtime.runner().kill_now();
        let _ = &self.runtime_executor;
    }
}

fn invalid_data(message: &str) -> anyhow::Error {
    anyhow::anyhow!(message.to_owned())
}
