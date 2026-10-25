//! Long-running operations of the Admin API (`projects/{p}/databases/{d}/operations`).
//!
//! Each Admin method that production answers with a `google.longrunning.Operation` records one
//! here: its first answer (`initial`), what `operations.get` answers afterwards (`current`),
//! and whether it can still be cancelled. The shapes follow production, including its quirks:
//! a database create or update is already done when it is answered, a database delete is
//! answered unfinished and never reports `done`, and `operations.get` of a delete answers under
//! a shorter name than the one the delete returned.

// Native build integration uses the transport's tonic status throughout the admitted callback.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use tonic::Status;

use serde_json::{json, Value};

use crate::rest::{RestResponse, RestState};

/// How many operations are kept per database; the oldest are forgotten first.
pub const OPERATIONS_RETAINED_PER_DATABASE: usize = 128;

/// What produced an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    /// `databases.create`.
    CreateDatabase,
    /// `databases.patch`.
    UpdateDatabase,
    /// `databases.delete`.
    DeleteDatabase,
    /// `collectionGroups.indexes.create`: its answer follows the index it builds.
    CreateIndex,
    /// A Native text index build, bound to one catalog generation.
    CreateTextIndex,
    /// Export, import or bulk delete: finished by the time it is first polled.
    Managed,
    /// `collectionGroups.fields.patch`: its answer follows the patch it applies.
    Field,
}

impl OperationKind {
    /// Whether the operation creates, updates or deletes the database itself.
    #[must_use]
    pub const fn is_database_operation(self) -> bool {
        matches!(
            self,
            Self::CreateDatabase | Self::UpdateDatabase | Self::DeleteDatabase
        )
    }
}

/// Scheduling and generation linkage only; definitions live in the shared text catalog.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NativeTextBuild {
    pub index: String,
    pub generation: u64,
}

/// One recorded operation.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredOperation {
    /// The id `operations.get` answers under.
    pub id: String,
    /// Another id the operation was first answered under, if production uses two.
    pub alias: Option<String>,
    /// What produced it.
    pub kind: OperationKind,
    /// The first answer.
    pub initial: Value,
    /// What `operations.get` and `operations.list` answer (for an index operation, what they
    /// answered last; the route derives the live answer from the index).
    pub current: Value,
    /// The index an index operation builds.
    pub index: Option<String>,
    pub(crate) native_text: Option<NativeTextBuild>,
}

/// The operations of every database of one backend.
#[derive(Debug, Default)]
pub struct OperationStore {
    by_database: Mutex<BTreeMap<(String, String), VecDeque<StoredOperation>>>,
    /// Ids an `operations.delete` removed: production answers them differently from ids it
    /// never issued.
    deleted: Mutex<Vec<DeletedOperation>>,
    ordinal: std::sync::atomic::AtomicU64,
}

/// Deletion ownership is retained even after its bounded wire view is removed.
#[derive(Debug, Clone, PartialEq)]
struct DeletedOperation {
    project: String,
    database: String,
    id: String,
    native_text: bool,
}

/// A pure Native projection, or an exact transient queue preimage for CONTROL rollback.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TextOperationSnapshot {
    exact: bool,
    queues: BTreeMap<(String, String), Vec<(usize, StoredOperation)>>,
    deleted: Vec<(usize, DeletedOperation)>,
}

impl TextOperationSnapshot {
    pub(crate) fn retained_bytes(&self) -> u64 {
        self.queues
            .iter()
            .fold(0_u64, |total, ((p, d), queue)| {
                queue.iter().fold(
                    total
                        .saturating_add(p.len() as u64)
                        .saturating_add(d.len() as u64),
                    |total, (_, op)| {
                        total
                            .saturating_add(op.id.len() as u64)
                            .saturating_add(op.alias.as_ref().map_or(0, String::len) as u64)
                            .saturating_add(op.initial.to_string().len() as u64)
                            .saturating_add(op.current.to_string().len() as u64)
                            .saturating_add(op.index.as_ref().map_or(0, String::len) as u64)
                            .saturating_add(
                                op.native_text
                                    .as_ref()
                                    .map_or(0, |target| target.index.len())
                                    as u64,
                            )
                            .saturating_add(std::mem::size_of::<StoredOperation>() as u64)
                    },
                )
            })
            .saturating_add(self.deleted.iter().fold(0_u64, |total, (_, deleted)| {
                total
                    .saturating_add(deleted.project.len() as u64)
                    .saturating_add(deleted.database.len() as u64)
                    .saturating_add(deleted.id.len() as u64)
                    .saturating_add(std::mem::size_of::<DeletedOperation>() as u64)
            }))
    }
}

fn opaque_id(seed: &[u8], length: usize) -> String {
    let mut out = String::new();
    let mut counter = 0_u32;
    while out.len() < length {
        let mut digest = fireemu_core_types::hash::Sha256::new();
        digest.update(b"fireemu:admin-operation:");
        digest.update(seed);
        digest.update(&counter.to_be_bytes());
        out.push_str(
            fireemu_core_types::hash::base64_url_safe(&digest.finalize()).trim_end_matches('='),
        );
        counter += 1;
    }
    out.truncate(length);
    out
}

impl OperationStore {
    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<(String, String), VecDeque<StoredOperation>>> {
        self.by_database
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn capture_text(
        &self,
        owned: impl Fn(&str) -> bool,
        exact: bool,
    ) -> Result<TextOperationSnapshot, Status> {
        let queues = self
            .by_database
            .lock()
            .map_err(|_| Status::internal("operation store is poisoned"))?;
        let deleted = self
            .deleted
            .lock()
            .map_err(|_| Status::internal("operation deletion store is poisoned"))?;
        Ok(TextOperationSnapshot {
            exact,
            queues: queues
                .iter()
                .filter(|((p, _), _)| owned(p))
                .filter_map(|(key, queue)| {
                    let records = queue
                        .iter()
                        .enumerate()
                        .filter(|(_, op)| exact || op.native_text.is_some())
                        .map(|(slot, op)| (slot, op.clone()))
                        .collect::<Vec<_>>();
                    (exact || !records.is_empty()).then(|| (key.clone(), records))
                })
                .collect(),
            deleted: deleted
                .iter()
                .enumerate()
                .filter(|(_, marker)| owned(&marker.project) && (exact || marker.native_text))
                .map(|(slot, marker)| (slot, marker.clone()))
                .collect(),
        })
    }

    pub(crate) fn validate_text(
        &self,
        owned: impl Fn(&str) -> bool,
        captured: &TextOperationSnapshot,
    ) -> Result<(), Status> {
        self.replace_text(owned, captured, None::<fn()>)
    }

    /// Prepares the entire replacement before publishing either catalog or operation state.
    /// Explicit CONTROL restore may rewind Native terminal views; ordinary observations cannot.
    pub(crate) fn replace_text(
        &self,
        owned: impl Fn(&str) -> bool,
        captured: &TextOperationSnapshot,
        publish: Option<impl FnOnce()>,
    ) -> Result<(), Status> {
        let mut queues = self
            .by_database
            .lock()
            .map_err(|_| Status::internal("operation store is poisoned"))?;
        let mut deleted = self
            .deleted
            .lock()
            .map_err(|_| Status::internal("operation deletion store is poisoned"))?;
        let mut trial = queues.clone();
        if captured.exact {
            trial.retain(|(p, _), _| !owned(p));
        } else {
            for ((p, _), queue) in &mut trial {
                if owned(p) {
                    queue.retain(|op| op.native_text.is_none());
                }
            }
        }
        for (key, records) in &captured.queues {
            if !owned(&key.0) {
                continue;
            }
            let queue = trial.entry(key.clone()).or_default();
            if queue.len().saturating_add(records.len()) > OPERATIONS_RETAINED_PER_DATABASE {
                return Err(Status::failed_precondition(
                    "CONTROL text restore exceeds operation retention capacity",
                ));
            }
            for (slot, op) in records {
                queue.insert((*slot).min(queue.len()), op.clone());
            }
        }
        let mut markers = deleted.clone();
        markers
            .retain(|marker| !owned(&marker.project) || (!captured.exact && !marker.native_text));
        for (slot, marker) in &captured.deleted {
            if owned(&marker.project) {
                markers.insert((*slot).min(markers.len()), marker.clone());
            }
        }
        if let Some(publish) = publish {
            // No fallible work remains: the failing hook must be internally atomic.
            publish();
            *queues = trial;
            *deleted = markers;
        }
        Ok(())
    }

    /// Whether any operation of `project`/`database` is kept (a deleted database's are).
    #[must_use]
    pub fn has_database(&self, project: &str, database: &str) -> bool {
        self.lock()
            .contains_key(&(project.to_owned(), database.to_owned()))
    }

    /// Records an operation of `kind`, rendering its answers from `metadata` and `response`.
    pub fn record(
        &self,
        project: &str,
        database: &str,
        kind: OperationKind,
        metadata: &Value,
        response: Option<Value>,
    ) -> StoredOperation {
        let ordinal = self
            .ordinal
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let seed = format!("{project}/{database}/{kind:?}/{ordinal}");
        let prefix = format!("projects/{project}/databases/{database}/operations/");
        let (id, alias, initial, current) = match kind {
            // An index operation is recorded through `record_index`; this arm only keeps the
            // match total.
            OperationKind::CreateDatabase
            | OperationKind::UpdateDatabase
            | OperationKind::CreateIndex
            | OperationKind::CreateTextIndex
            | OperationKind::Managed
            | OperationKind::Field => {
                let id = opaque_id(
                    seed.as_bytes(),
                    if kind == OperationKind::CreateDatabase {
                        62
                    } else {
                        24
                    },
                );
                let answer = json!({
                    "name": format!("{prefix}{id}"),
                    "metadata": metadata,
                    "done": true,
                    "response": response.unwrap_or(Value::Null),
                });
                (id, None, answer.clone(), answer)
            }
            OperationKind::DeleteDatabase => {
                let id = opaque_id(seed.as_bytes(), 24);
                let long = format!("{id}{}", opaque_id(format!("{seed}/long").as_bytes(), 18));
                let type_url = response
                    .as_ref()
                    .and_then(|r| r.get("@type"))
                    .cloned()
                    .unwrap_or(Value::Null);
                let initial = json!({
                    "name": format!("{prefix}{long}"),
                    "metadata": metadata,
                    "response": response.unwrap_or(Value::Null),
                });
                let current = json!({
                    "name": format!("{prefix}{id}"),
                    "metadata": metadata,
                    "response": {"@type": type_url},
                });
                (id, Some(long), initial, current)
            }
        };
        let stored = StoredOperation {
            id,
            alias,
            kind,
            initial,
            current,
            index: None,
            native_text: None,
        };
        self.push(project, database, stored.clone());
        stored
    }

    fn push(&self, project: &str, database: &str, stored: StoredOperation) {
        let mut all = self.lock();
        let queue = all
            .entry((project.to_owned(), database.to_owned()))
            .or_default();
        queue.push_back(stored);
        while queue.len() > OPERATIONS_RETAINED_PER_DATABASE {
            queue.pop_front();
        }
    }

    /// A fresh operation id, for an operation whose answer is rendered by its caller.
    pub fn reserve(&self, project: &str, database: &str) -> String {
        let ordinal = self
            .ordinal
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        opaque_id(
            format!("{project}/{database}/reserved/{ordinal}").as_bytes(),
            88,
        )
    }

    /// Records an operation whose first answer and later answer its caller rendered.
    pub fn record_views(
        &self,
        project: &str,
        database: &str,
        id: &str,
        initial: Value,
        current: Value,
    ) {
        self.push(
            project,
            database,
            StoredOperation {
                id: id.to_owned(),
                alias: None,
                kind: OperationKind::Managed,
                initial,
                current,
                index: None,
                native_text: None,
            },
        );
    }

    /// Records the operation that applies a field patch.
    pub fn record_field(&self, project: &str, database: &str, id: &str, initial: Value) {
        self.push(
            project,
            database,
            StoredOperation {
                id: id.to_owned(),
                alias: None,
                kind: OperationKind::Field,
                current: initial.clone(),
                initial,
                index: None,
                native_text: None,
            },
        );
    }

    /// Records the operation that builds index `index`.
    pub fn record_index(
        &self,
        project: &str,
        database: &str,
        id: &str,
        index: &str,
        initial: Value,
    ) {
        self.push(
            project,
            database,
            StoredOperation {
                id: id.to_owned(),
                alias: None,
                kind: OperationKind::CreateIndex,
                current: initial.clone(),
                initial,
                index: Some(index.to_owned()),
                native_text: None,
            },
        );
    }

    pub(crate) fn record_text(
        &self,
        project: &str,
        database: &str,
        id: &str,
        target: NativeTextBuild,
        initial: Value,
    ) {
        self.push(
            project,
            database,
            StoredOperation {
                id: id.to_owned(),
                alias: None,
                kind: OperationKind::CreateTextIndex,
                current: initial.clone(),
                initial,
                index: None,
                native_text: Some(target),
            },
        );
    }

    pub(crate) fn text_observation_current(
        &self,
        project: &str,
        database: &str,
        targets: &[(&str, &NativeTextBuild)],
    ) -> bool {
        text_targets_current(
            self.lock().get(&(project.to_owned(), database.to_owned())),
            targets,
        )
    }

    /// Publish prepared catalog work and retained views only after validating every link.
    /// Missing/deleted/evicted views remain absent; explicit CONTROL is the only audit rewind.
    pub(crate) fn finish_text(
        &self,
        project: &str,
        database: &str,
        completions: &[(String, NativeTextBuild, Value)],
        observed_targets: Option<&[(&str, &NativeTextBuild)]>,
        publish: impl FnOnce(),
    ) -> Result<(), Status> {
        if completions.is_empty() {
            return Ok(());
        }
        let mut all = self.lock();
        let queue = all.get_mut(&(project.to_owned(), database.to_owned()));
        if observed_targets.is_some_and(|targets| !text_targets_current(queue.as_deref(), targets))
        {
            return Ok(());
        }
        if let Some(queue) = queue {
            let mut prepared = queue.clone();
            for (id, expected, terminal) in completions {
                let Some(operation) = prepared.iter_mut().find(|op| op.id == *id) else {
                    continue;
                };
                if operation.native_text.as_ref() != Some(expected) {
                    return Err(Status::unimplemented(
                        "FS_TEXT_ADMIN_UNVERIFIED: incoherent Native operation generation",
                    ));
                }
                if is_done(&operation.current) {
                    return Err(Status::unimplemented("FS_TEXT_ADMIN_UNVERIFIED: partial catalog restore retained a terminal operation"));
                }
                operation.current = terminal.clone();
            }
            // All source work and every retained identity are validated before publication.
            publish();
            *queue = prepared;
        } else {
            publish();
        }
        Ok(())
    }

    /// The operation `id` (or its alias) names in a database.
    pub fn get(&self, project: &str, database: &str, id: &str) -> Option<StoredOperation> {
        self.lock()
            .get(&(project.to_owned(), database.to_owned()))?
            .iter()
            .find(|op| op.id == id || op.alias.as_deref() == Some(id))
            .cloned()
    }

    /// Every operation of a database, oldest first.
    pub fn list(&self, project: &str, database: &str) -> Vec<StoredOperation> {
        self.lock()
            .get(&(project.to_owned(), database.to_owned()))
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Removes an operation; returns whether it existed.
    pub fn remove(&self, project: &str, database: &str, id: &str) -> bool {
        let mut all = self.lock();
        let Some(queue) = all.get_mut(&(project.to_owned(), database.to_owned())) else {
            return false;
        };
        let native_text = queue
            .iter()
            .find(|op| op.id == id || op.alias.as_deref() == Some(id))
            .is_some_and(|op| op.native_text.is_some());
        let before = queue.len();
        queue.retain(|op| op.id != id && op.alias.as_deref() != Some(id));
        let removed = queue.len() != before;
        drop(all);
        if removed {
            self.deleted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(DeletedOperation {
                    project: project.to_owned(),
                    database: database.to_owned(),
                    id: id.to_owned(),
                    native_text,
                });
        }
        removed
    }

    fn was_deleted(&self, project: &str, database: &str, id: &str) -> bool {
        self.deleted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|marker| {
                marker.project == project && marker.database == database && marker.id == id
            })
    }

    /// Forgets the operations of the projects `owned` selects (a session reset).
    pub fn reset(&self, owned: impl Fn(&str) -> bool) {
        self.lock().retain(|(project, _), _| !owned(project));
        self.deleted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|marker| !owned(&marker.project));
    }
}

fn text_targets_current(
    queue: Option<&VecDeque<StoredOperation>>,
    targets: &[(&str, &NativeTextBuild)],
) -> bool {
    targets.iter().all(|(id, target)| {
        queue
            .and_then(|queue| queue.iter().find(|op| op.id == *id))
            .is_some_and(|op| op.native_text.as_ref() == Some(*target) && !is_done(&op.current))
    })
}

/// A fresh operation id in the backend's store.
pub(crate) fn reserve_id(state: &RestState, project: &str, database: &str) -> String {
    state.local.admin().operations().reserve(project, database)
}

/// Records an index operation in the backend's store.
pub(crate) fn record_index(
    state: &RestState,
    project: &str,
    database: &str,
    id: &str,
    index: &str,
    initial: Value,
) {
    let barrier = state.local.barrier();
    let _admission = barrier.admit();
    state
        .local
        .admin()
        .operations()
        .record_index(project, database, id, index, initial);
}

/// What `operations.get` answers for `op` now.
fn current(state: &RestState, project: &str, database: &str, op: &StoredOperation) -> Value {
    current_counted(state, project, database, op, &mut |group| {
        super::managed::group_document_count(state, project, database, group)
    })
}

/// [`current`], counting a collection group's documents with `count` (a list counts every
/// group from one snapshot instead of copying the database once per operation).
fn current_counted(
    state: &RestState,
    project: &str,
    database: &str,
    op: &StoredOperation,
    count: &mut dyn FnMut(&str) -> u64,
) -> Value {
    if op.kind == OperationKind::Field {
        return state
            .local
            .admin()
            .fields()
            .by_operation(&op.id)
            .map_or_else(
                || op.current.clone(),
                |patch| state.field_operation_json_counted(&patch, &op.initial, count),
            );
    }
    let Some(index_id) = &op.index else {
        return op.current.clone();
    };
    let registry = state.local.admin().indexes();
    match registry.get(project, database, index_id) {
        Some(index) => {
            let name = format!(
                "projects/{project}/databases/{database}/operations/{}",
                op.id
            );
            let documents = count(index.definition.collection_group.as_str());
            // The build finished after it started: production reports two instants.
            let end = fireemu_core_types::time::LogicalInstant::from_nanos(
                index.start_time.as_nanos() + 1_000_000,
            );
            super::index_rest::operation_json(
                project,
                database,
                &name,
                &index,
                registry.state(&index, state.local.admin_now()),
                (documents, end),
            )
        }
        None => op.current.clone(),
    }
}

/// Records an operation in the backend's store.
pub(crate) fn record(
    state: &RestState,
    project: &str,
    database: &str,
    kind: OperationKind,
    metadata: &Value,
    response: Option<Value>,
) -> StoredOperation {
    let barrier = state.local.barrier();
    let _admission = barrier.admit();
    state
        .local
        .admin()
        .operations()
        .record(project, database, kind, metadata, response)
}

fn ok(body: Value) -> RestResponse {
    RestResponse { status: 200, body }
}

fn is_done(operation: &Value) -> bool {
    operation.get("done") == Some(&Value::Bool(true))
}

/// The `filter` of `operations.list`: `done=true` or `done=false` (`None` when there is
/// none). A bare term is what production refuses as a global comparison.
fn parse_filter(params: &BTreeMap<String, Vec<String>>) -> Result<Option<bool>, RestResponse> {
    let Some(filter) = params.get("filter").and_then(|v| v.last()) else {
        return Ok(None);
    };
    let filter = filter.trim();
    if filter.is_empty() {
        return Ok(None);
    }
    let refuse = |why: &str| {
        super::rest::error(
            tonic::Code::InvalidArgument,
            &format!("Error evaluating filter: {why}"),
            None,
        )
    };
    let Some((field, value)) = filter.split_once('=') else {
        return Err(refuse(&format!(
            "Filtering does not support GLOBAL comparator {filter}."
        )));
    };
    match (field.trim(), value.trim()) {
        ("done", "true") => Ok(Some(true)),
        ("done", "false") => Ok(Some(false)),
        _ => Err(refuse(&format!("Unsupported filter {filter}."))),
    }
}

/// `operations.list`, with its `filter`.
fn list(
    state: &RestState,
    project: &str,
    database: &str,
    params: &BTreeMap<String, Vec<String>>,
) -> RestResponse {
    let store = state.local.admin().operations();
    if !super::rest::database_exists(state, project, database)
        && !store.has_database(project, database)
    {
        return super::rest::missing_database(project, database);
    }
    let filter = match parse_filter(params) {
        Ok(filter) => filter,
        Err(response) => return response,
    };
    // Production lists a database's document and index work, not the operations
    // that created, updated or deleted the database itself.
    let mut counts: Option<BTreeMap<String, u64>> = None;
    let mut operations: Vec<Value> = store
        .list(project, database)
        .iter()
        .filter(|op| !op.kind.is_database_operation())
        .map(|op| {
            current_counted(state, project, database, op, &mut |group| {
                counts
                    .get_or_insert_with(|| {
                        super::managed::group_document_counts(state, project, database)
                    })
                    .get(group)
                    .copied()
                    .unwrap_or(0)
            })
        })
        .collect();
    let prefix = format!("projects/{project}/databases/{database}/operations/");
    operations.extend(
        state
            .local
            .field_operations(project)
            .into_iter()
            .filter(|op| op.name.starts_with(&prefix))
            .map(|op| crate::rest::admin_fields::operation_json(&op)),
    );
    operations.retain(|op| filter.is_none_or(|done| is_done(op) == done));
    if operations.is_empty() {
        ok(json!({}))
    } else {
        ok(json!({ "operations": operations }))
    }
}

/// Prepares ordinary operation rendering before admission, then revalidates the retained
/// identity. CONTROL may rewind an operation while preparation waits for its source snapshot.
fn delete(state: &RestState, project: &str, database: &str, id: &str) -> RestResponse {
    let store = state.local.admin().operations();
    let barrier = state.local.barrier();
    let name = format!("projects/{project}/databases/{database}/operations/{id}");
    loop {
        let seen = barrier.epoch();
        let observed = store.get(project, database, id);
        let field = state.local.field_operation(project, &name);
        // Field and ordinary index rendering may admit their own database snapshot.
        // Never retain the publication guard across those callbacks.
        let running = observed.as_ref().map_or_else(
            || {
                field
                    .as_ref()
                    .is_some_and(|op| !is_done(&crate::rest::admin_fields::operation_json(op)))
            },
            |op| !is_done(&current(state, project, database, op)),
        );
        let admission = barrier.admit();
        if admission.epoch() != seen
            || store.get(project, database, id) != observed
            || state.local.field_operation(project, &name) != field
        {
            continue;
        }
        if running {
            return super::rest::error(
                tonic::Code::FailedPrecondition,
                "Precondition check failed.",
                None,
            );
        }
        return if store.remove(project, database, id) || field.is_some() {
            ok(json!({}))
        } else {
            super::rest::error(tonic::Code::NotFound, "Operation does not exist", None)
        };
    }
}

/// `operations.list`, `operations.get`, `operations.delete` and `operations.cancel`.
pub(crate) fn route(
    state: &RestState,
    project: &str,
    database: &str,
    method: &str,
    rest: &[&str],
    action: Option<&str>,
    params: &BTreeMap<String, Vec<String>>,
) -> RestResponse {
    let store = state.local.admin().operations();
    // Review S9: a DELETE observes its operation as a GET does, so a build past its deadline
    // completes before the done check instead of waiting for a read.
    if matches!(method, "GET" | "DELETE") {
        // Resolve locally retained identities before admission. An absent view is a404;
        // an ordinary or terminal operation reads its audit without touching catalog work.
        let observed = match rest {
            [] => store.list(project, database),
            [id] => store.get(project, database, id).into_iter().collect(),
            _ => Vec::new(),
        };
        let targets = observed
            .iter()
            .filter(|op| !is_done(&op.current))
            .filter_map(|op| {
                op.native_text
                    .as_ref()
                    .map(|target| (op.id.as_str(), target))
            })
            .collect::<Vec<_>>();
        if !targets.is_empty() {
            if let Err(status) = state.local.advance_native_text_builds(
                project,
                database,
                super::index_rest::NativeTextSelection {
                    operation_targets: Some(&targets),
                    direct: rest.len() == 1,
                    ..Default::default()
                },
            ) {
                return crate::rest::error_response(&status);
            }
        }
    }
    let field_operation = |id: &str| {
        let name = format!("projects/{project}/databases/{database}/operations/{id}");
        state.local.field_operation(project, &name)
    };
    match (method, rest, action) {
        ("GET", [], None) => list(state, project, database, params),
        ("GET", [id], None) => match store.get(project, database, id) {
            Some(op) => ok(current(state, project, database, &op)),
            None => match field_operation(id) {
                Some(op) => ok(crate::rest::admin_fields::operation_json(&op)),
                None if store.was_deleted(project, database, id) => super::rest::error(
                    tonic::Code::NotFound,
                    "Requested entity was not found.",
                    None,
                ),
                None => super::rest::error(tonic::Code::NotFound, "Operation does not exist", None),
            },
        },
        ("DELETE", [id], None) => delete(state, project, database, id),
        ("POST", [id], Some("cancel")) => {
            if store
                .get(project, database, id)
                .is_some_and(|op| op.native_text.is_some())
            {
                return crate::rest::error_response(&Status::unimplemented(
                    "FS_TEXT_ADMIN_UNVERIFIED: text build cancellation",
                ));
            }
            if store
                .get(project, database, id)
                .is_some_and(|op| op.kind == OperationKind::CreateIndex)
            {
                // Running or finished, production refuses to cancel an index build.
                super::rest::error(
                    tonic::Code::InvalidArgument,
                    "CancelOperation is not supported for operation type BUILD_INDEX.",
                    None,
                )
            } else if store.get(project, database, id).is_some() || field_operation(id).is_some() {
                // Every operation this runtime records has already finished.
                super::rest::error(
                    tonic::Code::FailedPrecondition,
                    "Precondition check failed.",
                    None,
                )
            } else {
                super::rest::error(tonic::Code::NotFound, "Operation does not exist", None)
            }
        }
        _ => crate::rest::not_found_text(),
    }
}

#[cfg(test)]
mod text_snapshot_properties {
    use super::*;
    use proptest::prelude::*;

    fn append(store: &OperationStore, project: &str, id: &str, native: bool) {
        let value = json!({"name":id,"done":true});
        if native {
            store.record_text(
                project,
                "db",
                id,
                NativeTextBuild {
                    index: id.into(),
                    generation: 1,
                },
                value,
            );
        } else {
            store.record_views(project, "db", id, value.clone(), value);
        }
    }

    #[test]
    fn native_completion_rechecks_all_retained_identities_before_publication() {
        let store = OperationStore::default();
        append(&store, "p", "first", true);
        append(&store, "p", "second", true);
        let before = store.capture_text(|_| true, true).unwrap();
        for terminal in [false, true] {
            if terminal {
                let mut all = store.lock();
                all.get_mut(&("p".into(), "db".into())).unwrap()[1].current = json!({"done":true});
            } else {
                let mut all = store.lock();
                for op in all.get_mut(&("p".into(), "db".into())).unwrap() {
                    op.current = json!({});
                }
            }
            let snapshot = store.capture_text(|_| true, true).unwrap();
            let published = std::cell::Cell::new(false);
            let completions = vec![
                (
                    "first".into(),
                    NativeTextBuild {
                        index: "first".into(),
                        generation: 1,
                    },
                    json!({"done":true}),
                ),
                (
                    "second".into(),
                    NativeTextBuild {
                        index: "second".into(),
                        generation: if terminal { 1 } else { 2 },
                    },
                    json!({"done":true}),
                ),
            ];
            assert!(store
                .finish_text("p", "db", &completions, None, || published.set(true))
                .is_err());
            assert!(!published.get());
            assert_eq!(store.capture_text(|_| true, true).unwrap(), snapshot);
        }
        store.replace_text(|_| true, &before, Some(|| {})).unwrap();
    }

    #[test]
    fn native_completion_does_not_publish_an_observers_lost_retained_selection() {
        for loss in ["evicted", "deleted", "terminal", "generation"] {
            let store = OperationStore::default();
            append(&store, "p", "first", true);
            append(&store, "p", "second", true);
            {
                let mut all = store.lock();
                for op in all.get_mut(&("p".into(), "db".into())).unwrap() {
                    op.current = json!({});
                }
            }
            let completions: Vec<(String, NativeTextBuild, Value)> = vec![
                (
                    "first".into(),
                    NativeTextBuild {
                        index: "first".into(),
                        generation: 1,
                    },
                    json!({"done":true}),
                ),
                (
                    "second".into(),
                    NativeTextBuild {
                        index: "second".into(),
                        generation: 1,
                    },
                    json!({"done":true}),
                ),
            ];
            match loss {
                "deleted" => {
                    assert!(store.remove("p", "db", "second"));
                }
                "evicted" => {
                    for i in 0..128 {
                        append(&store, "p", &format!("later-{i}"), false);
                    }
                }
                _ => {
                    let mut all = store.lock();
                    let op = &mut all.get_mut(&("p".into(), "db".into())).unwrap()[1];
                    if loss == "terminal" {
                        op.current = json!({"done":true});
                    } else {
                        op.native_text.as_mut().unwrap().generation = 2;
                    }
                }
            }
            let before = store.capture_text(|_| true, true).unwrap();
            let published = std::cell::Cell::new(false);
            let targets = completions
                .iter()
                .map(|(id, target, _)| (id.as_str(), target))
                .collect::<Vec<_>>();
            store
                .finish_text("p", "db", &completions, Some(&targets), || {
                    published.set(true);
                })
                .unwrap();
            assert!(
                !published.get(),
                "an operation observer cannot publish after {loss} changes its retained selection"
            );
            assert_eq!(store.capture_text(|_| true, true).unwrap(), before);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn native_projection_is_bounded_isolated_idempotent_and_exactly_compensated(
            before in prop::collection::vec(any::<bool>(),0..130),
            after in prop::collection::vec((any::<bool>(),any::<bool>()),0..150),
        ) {
            let store=OperationStore::default();
            for (i,native) in before.into_iter().enumerate() {append(&store,"p",&format!("captured-{i}"),native);}
            let captured=store.capture_text(|p|p=="p",false).unwrap();
            for (i,(native,remove)) in after.into_iter().enumerate() {
                let id=format!("live-{i}");
                append(&store,"p",&id,native);
                append(&store,"outside",&id,!native);
                if remove {store.remove("p","db",&id);store.remove("outside","db",&id);}
            }
            let preimage=store.capture_text(|_|true,true).unwrap();
            let own_preimage=store.capture_text(|p|p=="p",true).unwrap();
            let unrelated=store.list("p","db").into_iter().filter(|op|op.native_text.is_none()).collect::<Vec<_>>();
            let outside=store.capture_text(|p|p=="outside",true).unwrap();
            let captured_count=captured.queues.values().map(Vec::len).sum::<usize>();
            let outcome=store.replace_text(|p|p=="p",&captured,Some(||{}));
            if captured_count+unrelated.len()>OPERATIONS_RETAINED_PER_DATABASE {
                prop_assert!(outcome.is_err());
                prop_assert_eq!(store.capture_text(|_|true,true).unwrap(),preimage);
            } else {
                prop_assert!(outcome.is_ok());
                let restored=store.capture_text(|_|true,true).unwrap();
                prop_assert!(store.list("p","db").len()<=OPERATIONS_RETAINED_PER_DATABASE);
                prop_assert_eq!(store.list("p","db").into_iter().filter(|op|op.native_text.is_none()).collect::<Vec<_>>(),unrelated);
                let actual_outside=store.capture_text(|p|p=="outside",true).unwrap();
                prop_assert_eq!(actual_outside.queues,outside.queues);
                prop_assert_eq!(actual_outside.deleted.into_iter().map(|(_,marker)|marker).collect::<Vec<_>>(),outside.deleted.into_iter().map(|(_,marker)|marker).collect::<Vec<_>>());
                store.replace_text(|p|p=="p",&captured,Some(||{})).unwrap();
                prop_assert_eq!(store.capture_text(|_|true,true).unwrap(),restored);
                store.replace_text(|p|p=="p",&own_preimage,Some(||{})).unwrap();
                prop_assert_eq!(store.capture_text(|_|true,true).unwrap(),preimage);
            }
        }
    }
}
