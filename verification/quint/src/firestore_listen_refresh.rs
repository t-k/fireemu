//! Quint Connect driver for incremental Firestore Listen refreshes.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{Arc, Mutex};

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{
    Direction, FieldOp, FilterExpr, OrderClause, Query, QueryScope,
};
use fireemu_core_firestore::store::{FirestoreState, Write, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{CollectionId, DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;
use quint_connect::{switch, Config, Driver, Result, State, Step};
use serde::Deserialize;

/// Actions exercised by deterministic and generated conformance traces.
pub const MODELED_ACTIONS: [&str; 6] = [
    "QueueContiguous",
    "QueueGap",
    "QueueReset",
    "MarkUnsafe",
    "SetFiftyTargets",
    "Refresh",
];

/// Reproducible seeds used by generated conformance campaigns.
pub const GENERATED_TRACE_SEEDS: [&str; 4] = ["0x1", "0x2", "0x3", "0x4"];

const SINGLE_TARGET: u64 = 1;
const MANY_TARGETS: u64 = 50;

/// Production-derived observation compared with the Quint model after every action.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct FirestoreListenRefreshState {
    /// Database generation that owns the current target state.
    pub generation: u64,
    /// Last snapshot version installed in the target state.
    pub last_version: u64,
    /// Highest queued commit version.
    pub through_version: u64,
    /// `Idle`, `Delta`, or `Full` refresh classification.
    pub refresh_mode: String,
    /// Deduplicated paths accumulated from contiguous notifications.
    pub changed_paths: BTreeSet<String>,
    /// Whether the target query has only row-local membership semantics.
    pub safe_query: bool,
    /// Number of equivalent targets refreshed by the bounded scenario.
    pub target_count: u64,
    /// Changed documents presented to the production incremental query API.
    pub examined_count: u64,
    /// Whether incremental and full-query projections agree on the changed subset.
    pub projection_equivalent: bool,
    /// Whether the last refresh called the production incremental query API.
    pub incremental_used: bool,
    /// Whether target state is current for the active generation.
    pub target_current: bool,
    /// Whether a generation reset still requires a full replay.
    pub reset_pending: bool,
    /// Documents replayed after a generation reset across all targets.
    pub replay_count: u64,
    /// Stable refresh classification for conformance diagnostics.
    pub last_reason: String,
}

/// Test-only perturbation of one comparison field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionFault {
    /// Perturb the database generation.
    Generation,
    /// Perturb the installed snapshot version.
    LastVersion,
    /// Perturb the queued through-version.
    ThroughVersion,
    /// Perturb the refresh mode.
    RefreshMode,
    /// Perturb the changed-path set.
    ChangedPaths,
    /// Perturb query safety.
    SafeQuery,
    /// Perturb target count.
    TargetCount,
    /// Perturb examined-document count.
    ExaminedCount,
    /// Perturb full-versus-incremental equivalence.
    ProjectionEquivalent,
    /// Perturb whether incremental execution was used.
    IncrementalUsed,
    /// Perturb target currency.
    TargetCurrent,
    /// Perturb pending reset state.
    ResetPending,
    /// Perturb reset replay count.
    ReplayCount,
    /// Perturb the refresh reason.
    LastReason,
}

impl ProjectionFault {
    /// Serialized field changed by this fault.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::Generation => "generation",
            Self::LastVersion => "lastVersion",
            Self::ThroughVersion => "throughVersion",
            Self::RefreshMode => "refreshMode",
            Self::ChangedPaths => "changedPaths",
            Self::SafeQuery => "safeQuery",
            Self::TargetCount => "targetCount",
            Self::ExaminedCount => "examinedCount",
            Self::ProjectionEquivalent => "projectionEquivalent",
            Self::IncrementalUsed => "incrementalUsed",
            Self::TargetCurrent => "targetCurrent",
            Self::ResetPending => "resetPending",
            Self::ReplayCount => "replayCount",
            Self::LastReason => "lastReason",
        }
    }
}

/// Stateful adapter that projects refresh planning and real query execution.
pub struct FirestoreListenRefreshDriver {
    store: FirestoreState,
    query: Query,
    state: FirestoreListenRefreshState,
    projection_fault: Option<ProjectionFault>,
    action_recorder: Option<Arc<Mutex<BTreeSet<String>>>>,
}

impl Default for FirestoreListenRefreshDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl FirestoreListenRefreshDriver {
    /// Builds an uninitialized bounded refresh driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: FirestoreState::new(),
            query: safe_query(),
            state: initial_state(),
            projection_fault: None,
            action_recorder: None,
        }
    }

    /// Records each successfully dispatched modeled action.
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

    /// Changes the projection-only fault without changing production state.
    pub fn set_projection_fault(&mut self, fault: ProjectionFault) {
        self.projection_fault = Some(fault);
    }

    /// Recreates the bounded production database at commit version one.
    pub fn init(&mut self) -> Result {
        self.store = FirestoreState::new();
        self.query = safe_query();
        self.store
            .commit(
                &[
                    set("items/a", true, 1),
                    set("items/b", false, 2),
                    set("other/a", true, 3),
                ],
                None,
                LogicalInstant::UNIX_EPOCH,
            )
            .map_err(|error| {
                invalid_data(&format!("cannot initialize Firestore state: {error}"))
            })?;
        self.state = initial_state();
        Ok(())
    }

    /// Queues one exactly contiguous commit and unions its changed path.
    pub fn queue_contiguous(&mut self, path: &str) -> Result {
        validate_path(path)?;
        self.state.through_version = self.state.through_version.saturating_add(1);
        if self.state.refresh_mode != "Full" && self.state.safe_query {
            "Delta".clone_into(&mut self.state.refresh_mode);
        } else {
            "Full".clone_into(&mut self.state.refresh_mode);
        }
        self.state.changed_paths.insert(path.to_owned());
        self.state.incremental_used = false;
        "contiguous".clone_into(&mut self.state.last_reason);
        self.record_action("QueueContiguous")
    }

    /// Queues a notification after a missing version and forces a full refresh.
    pub fn queue_gap(&mut self) -> Result {
        self.state.through_version = self.state.through_version.saturating_add(2);
        "Full".clone_into(&mut self.state.refresh_mode);
        self.state.changed_paths.insert("items/a".to_owned());
        self.state.incremental_used = false;
        "gap".clone_into(&mut self.state.last_reason);
        self.record_action("QueueGap")
    }

    /// Records a reset notification and forces a full refresh.
    pub fn queue_reset(&mut self) -> Result {
        self.state.generation = self.state.generation.saturating_add(1);
        "Full".clone_into(&mut self.state.refresh_mode);
        self.state.changed_paths.clear();
        self.state.incremental_used = false;
        self.state.target_current = false;
        self.state.reset_pending = true;
        self.state.replay_count = 0;
        "reset".clone_into(&mut self.state.last_reason);
        self.record_action("QueueReset")
    }

    /// Installs a limit, whose global page boundary is unsafe for delta refresh.
    pub fn mark_unsafe(&mut self) -> Result {
        self.query.limit = Some(1);
        self.state.safe_query = false;
        "Full".clone_into(&mut self.state.refresh_mode);
        self.state.incremental_used = false;
        "unsafe".clone_into(&mut self.state.last_reason);
        self.record_action("MarkUnsafe")
    }

    /// Expands the bounded workload to fifty identical targets.
    pub fn set_fifty_targets(&mut self) -> Result {
        self.state.target_count = MANY_TARGETS;
        self.state.incremental_used = false;
        "targets".clone_into(&mut self.state.last_reason);
        self.record_action("SetFiftyTargets")
    }

    /// Refreshes through the queued boundary, using the production incremental query API only
    /// for exact, safe deltas.
    pub fn refresh(&mut self) -> Result {
        if self.state.refresh_mode == "Idle" {
            return Err(invalid_data("refresh requires queued work"));
        }

        let use_incremental = self.state.refresh_mode == "Delta" && self.state.safe_query;
        let mut examined = 0_u64;
        let mut replayed = 0_u64;
        let equivalent = if use_incremental {
            let changed_documents = self
                .state
                .changed_paths
                .iter()
                .filter_map(|relative| self.store.get(&path(relative)))
                .collect::<Vec<_>>();
            let changed_path_set = changed_documents
                .iter()
                .map(|document| document.path.clone())
                .collect::<BTreeSet<_>>();
            let expected = self
                .store
                .run_query(&self.query, None)
                .map_err(|error| invalid_data(&format!("full query failed: {error}")))?
                .into_iter()
                .filter(|document| changed_path_set.contains(&document.path))
                .collect::<Vec<_>>();
            let mut all_equal = true;
            for _ in 0..self.state.target_count {
                let actual = self
                    .store
                    .run_incremental_query(&self.query, changed_documents.iter().copied())
                    .map_err(|error| invalid_data(&format!("incremental query failed: {error}")))?
                    .ok_or_else(|| {
                        invalid_data("safe query unexpectedly refused delta execution")
                    })?;
                examined = examined
                    .saturating_add(u64::try_from(changed_documents.len()).unwrap_or(u64::MAX));
                all_equal &= actual == expected;
            }
            all_equal
        } else {
            for _ in 0..self.state.target_count {
                let result = self
                    .store
                    .run_query(&self.query, None)
                    .map_err(|error| invalid_data(&format!("fallback query failed: {error}")))?;
                if self.state.reset_pending {
                    replayed =
                        replayed.saturating_add(u64::try_from(result.len()).unwrap_or(u64::MAX));
                }
            }
            true
        };

        self.state.last_version = self.state.through_version;
        "Idle".clone_into(&mut self.state.refresh_mode);
        self.state.changed_paths.clear();
        self.state.examined_count = examined;
        self.state.projection_equivalent = equivalent;
        self.state.incremental_used = use_incremental;
        self.state.target_current = true;
        self.state.reset_pending = false;
        self.state.replay_count = replayed;
        if use_incremental { "delta" } else { "full" }.clone_into(&mut self.state.last_reason);
        self.record_action("Refresh")
    }

    /// Projects the refresh state, including independently faultable fields.
    pub fn project(&self) -> Result<FirestoreListenRefreshState> {
        let mut projected = self.state.clone();
        match self.projection_fault {
            None => {}
            Some(ProjectionFault::Generation) => {
                projected.generation = projected.generation.saturating_add(1);
            }
            Some(ProjectionFault::LastVersion) => {
                projected.last_version = projected.last_version.saturating_add(1);
            }
            Some(ProjectionFault::ThroughVersion) => {
                projected.through_version = projected.through_version.saturating_add(1);
            }
            Some(ProjectionFault::RefreshMode) => {
                "Fault".clone_into(&mut projected.refresh_mode);
            }
            Some(ProjectionFault::ChangedPaths) => {
                if !projected.changed_paths.remove("items/a") {
                    projected.changed_paths.insert("items/a".to_owned());
                }
            }
            Some(ProjectionFault::SafeQuery) => projected.safe_query = !projected.safe_query,
            Some(ProjectionFault::TargetCount) => {
                projected.target_count = projected.target_count.saturating_add(1);
            }
            Some(ProjectionFault::ExaminedCount) => {
                projected.examined_count = projected.examined_count.saturating_add(1);
            }
            Some(ProjectionFault::ProjectionEquivalent) => {
                projected.projection_equivalent = !projected.projection_equivalent;
            }
            Some(ProjectionFault::IncrementalUsed) => {
                projected.incremental_used = !projected.incremental_used;
            }
            Some(ProjectionFault::TargetCurrent) => {
                projected.target_current = !projected.target_current;
            }
            Some(ProjectionFault::ResetPending) => {
                projected.reset_pending = !projected.reset_pending;
            }
            Some(ProjectionFault::ReplayCount) => {
                projected.replay_count = projected.replay_count.saturating_add(1);
            }
            Some(ProjectionFault::LastReason) => {
                "fault".clone_into(&mut projected.last_reason);
            }
        }
        Ok(projected)
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

impl State<FirestoreListenRefreshDriver> for FirestoreListenRefreshState {
    fn from_driver(driver: &FirestoreListenRefreshDriver) -> Result<Self> {
        driver.project()
    }
}

impl Driver for FirestoreListenRefreshDriver {
    type State = FirestoreListenRefreshState;

    fn config() -> Config {
        Config {
            state: &["FirestoreListenRefreshScenarios::FirestoreListenRefresh::observable"],
            nondet: &["FirestoreListenRefreshScenarios::FirestoreListenRefresh::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        switch!(step {
            init => self.init()?,
            QueueContiguous(path: String) => self.queue_contiguous(&path)?,
            QueueGap => self.queue_gap()?,
            QueueReset => self.queue_reset()?,
            MarkUnsafe => self.mark_unsafe()?,
            SetFiftyTargets => self.set_fifty_targets()?,
            Refresh => self.refresh()?,
        })
    }
}

/// Driver configured for generated traces.
pub struct FirestoreListenRefreshConnectDriver {
    inner: FirestoreListenRefreshDriver,
}

impl Default for FirestoreListenRefreshConnectDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl FirestoreListenRefreshConnectDriver {
    /// Builds a fresh generated-trace driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: FirestoreListenRefreshDriver::new(),
        }
    }
}

impl State<FirestoreListenRefreshConnectDriver> for FirestoreListenRefreshState {
    fn from_driver(driver: &FirestoreListenRefreshConnectDriver) -> Result<Self> {
        driver.inner.project()
    }
}

impl Driver for FirestoreListenRefreshConnectDriver {
    type State = FirestoreListenRefreshState;

    fn config() -> Config {
        Config {
            state: &["FirestoreListenRefreshConnect::FirestoreListenRefresh::observable"],
            nondet: &["FirestoreListenRefreshConnect::FirestoreListenRefresh::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        self.inner.step(step)
    }
}

fn initial_state() -> FirestoreListenRefreshState {
    FirestoreListenRefreshState {
        generation: 1,
        last_version: 1,
        through_version: 1,
        refresh_mode: "Idle".to_owned(),
        changed_paths: BTreeSet::new(),
        safe_query: true,
        target_count: SINGLE_TARGET,
        examined_count: 0,
        projection_equivalent: true,
        incremental_used: false,
        target_current: true,
        reset_pending: false,
        replay_count: 0,
        last_reason: "init".to_owned(),
    }
}

fn safe_query() -> Query {
    let mut query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("items").expect("fixed collection is valid"),
    ));
    query.filter = Some(FilterExpr::Field {
        field: FieldPath::parse("active").expect("fixed field path is valid"),
        op: FieldOp::Equal,
        value: Value::Boolean(true),
    });
    query.order_by = vec![OrderClause {
        field: FieldPath::parse("rank").expect("fixed field path is valid"),
        direction: Direction::Ascending,
    }];
    query.projection = Some(vec![
        FieldPath::parse("active").expect("fixed field path is valid"),
        FieldPath::parse("rank").expect("fixed field path is valid"),
    ]);
    query
}

fn set(relative: &str, active: bool, rank: i64) -> Write {
    Write {
        op: WriteOp::Set {
            path: path(relative),
            fields: BTreeMap::from([
                ("active".to_owned(), Value::Boolean(active)),
                ("rank".to_owned(), Value::Integer(rank)),
            ]),
            update_mask: None,
        },
        precondition: None,
        transforms: Vec::new(),
    }
}

fn path(relative: &str) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-listen").expect("fixed project is valid"),
        &DatabaseId::default_database(),
        relative,
    )
    .expect("fixed document path is valid")
}

fn validate_path(relative: &str) -> Result {
    if matches!(relative, "items/a" | "items/b" | "other/a") {
        Ok(())
    } else {
        Err(invalid_data("path is outside the bounded authority"))
    }
}

fn invalid_data(message: &str) -> anyhow::Error {
    anyhow::Error::new(io::Error::new(io::ErrorKind::InvalidData, message))
}
