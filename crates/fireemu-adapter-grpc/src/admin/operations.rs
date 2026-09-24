//! Long-running operations of the Admin API (`projects/{p}/databases/{d}/operations`).
//!
//! Each Admin method that production answers with a `google.longrunning.Operation` records one
//! here: its first answer (`initial`), what `operations.get` answers afterwards (`current`),
//! and whether it can still be cancelled. The shapes follow production, including its quirks:
//! a database create or update is already done when it is answered, a database delete is
//! answered unfinished and never reports `done`, and `operations.get` of a delete answers under
//! a shorter name than the one the delete returned.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

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
    /// Export, import or bulk delete: finished by the time it is first polled.
    Managed,
    /// `collectionGroups.fields.patch`: its answer follows the patch it applies.
    Field,
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
}

/// The operations of every database of one backend.
#[derive(Debug, Default)]
pub struct OperationStore {
    by_database: Mutex<BTreeMap<(String, String), VecDeque<StoredOperation>>>,
    /// Ids an `operations.delete` removed: production answers them differently from ids it
    /// never issued.
    deleted: Mutex<Vec<(String, String, String)>>,
    ordinal: std::sync::atomic::AtomicU64,
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
            },
        );
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
        let before = queue.len();
        queue.retain(|op| op.id != id && op.alias.as_deref() != Some(id));
        let removed = queue.len() != before;
        drop(all);
        if removed {
            self.deleted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((project.to_owned(), database.to_owned(), id.to_owned()));
        }
        removed
    }

    fn was_deleted(&self, project: &str, database: &str, id: &str) -> bool {
        self.deleted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|(p, d, i)| p == project && d == database && i == id)
    }

    /// Forgets the operations of the projects `owned` selects (a session reset).
    pub fn reset(&self, owned: impl Fn(&str) -> bool) {
        self.lock().retain(|(project, _), _| !owned(project));
        self.deleted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(project, _, _)| !owned(project));
    }
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
    state
        .local
        .admin()
        .operations()
        .record_index(project, database, id, index, initial);
}

/// What `operations.get` answers for `op` now.
fn current(state: &RestState, project: &str, database: &str, op: &StoredOperation) -> Value {
    if op.kind == OperationKind::Field {
        return state
            .local
            .admin()
            .fields()
            .by_operation(&op.id)
            .map_or_else(
                || op.current.clone(),
                |patch| state.field_operation_json(&patch, &op.initial),
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
            let documents = super::managed::group_document_count(
                state,
                project,
                database,
                index.definition.collection_group.as_str(),
            );
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
    state
        .local
        .admin()
        .operations()
        .record(project, database, kind, metadata, response)
}

fn ok(body: Value) -> RestResponse {
    RestResponse { status: 200, body }
}

/// `operations.list`, `operations.get`, `operations.delete` and `operations.cancel`.
pub(crate) fn route(
    state: &RestState,
    project: &str,
    database: &str,
    method: &str,
    rest: &[&str],
    action: Option<&str>,
    _params: &BTreeMap<String, Vec<String>>,
) -> RestResponse {
    let store = state.local.admin().operations();
    let field_operation = |id: &str| {
        let name = format!("projects/{project}/databases/{database}/operations/{id}");
        state.local.field_operation(project, &name)
    };
    match (method, rest, action) {
        ("GET", [], None) => {
            let mut operations: Vec<Value> = store
                .list(project, database)
                .iter()
                .map(|op| current(state, project, database, op))
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
            if operations.is_empty() {
                ok(json!({}))
            } else {
                ok(json!({ "operations": operations }))
            }
        }
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
        ("DELETE", [id], None) => {
            if store.remove(project, database, id) || field_operation(id).is_some() {
                ok(json!({}))
            } else {
                super::rest::error(tonic::Code::NotFound, "Operation does not exist", None)
            }
        }
        ("POST", [id], Some("cancel")) => {
            if store.get(project, database, id).is_some() || field_operation(id).is_some() {
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
