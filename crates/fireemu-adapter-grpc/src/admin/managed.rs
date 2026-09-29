//! `databases.exportDocuments`, `databases.importDocuments` and `databases.bulkDeleteDocuments`.
//!
//! Export and import read and write Cloud Storage objects through [`ManagedStorage`], which the
//! daemon implements over its Storage emulator (this crate has no Storage dependency). Each
//! answers production's long-running operation: unfinished when first answered, finished on the
//! first poll with production's progress counters.

use std::collections::BTreeMap;
use std::sync::Arc;

use fireemu_core_firestore::value::Value;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Map, Value as Json};

use super::rest::error;
use crate::encode::encode_instant;
use crate::rest::json::timestamp_to_json;
use crate::rest::{RestResponse, RestState};

/// One document an export holds or an import brings.
#[derive(Debug, Clone, PartialEq)]
pub struct ManagedDocument {
    /// Alternating collection and document ids.
    pub path: Vec<(String, String)>,
    /// Fields.
    pub fields: BTreeMap<String, Value>,
}

/// What an export writes.
#[derive(Debug, Clone)]
pub struct ExportJob {
    /// The project whose database is exported.
    pub project: String,
    /// The database.
    pub database: String,
    /// The bucket of the output prefix.
    pub bucket: String,
    /// The object prefix (no leading or trailing slash).
    pub prefix: String,
    /// Requested collection ids.
    pub collection_ids: Vec<String>,
    /// Requested namespace ids.
    pub namespace_ids: Vec<String>,
    /// When the export started and finished.
    pub window: (LogicalInstant, LogicalInstant),
    /// The documents, in path order.
    pub documents: Vec<ManagedDocument>,
}

/// What an export wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportOutcome {
    /// Documents written.
    pub documents: u64,
    /// Entity bytes written.
    pub bytes: u64,
}

/// What an import reads.
#[derive(Debug, Clone)]
pub struct ImportJob {
    /// The project importing (it may read only a bucket it uses).
    pub project: String,
    /// The bucket of the input prefix.
    pub bucket: String,
    /// The object prefix.
    pub prefix: String,
    /// Requested collection ids.
    pub collection_ids: Vec<String>,
    /// Requested namespace ids.
    pub namespace_ids: Vec<String>,
}

/// One document an import read, with where the export took it from.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportedDocument {
    /// The document.
    pub document: ManagedDocument,
    /// The project the export named.
    pub project: String,
    /// The database the export named.
    pub database: String,
}

/// What an import read.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportOutcome {
    /// The documents.
    pub documents: Vec<ImportedDocument>,
    /// Entity bytes read.
    pub bytes: u64,
}

/// Why an import cannot start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportRefusal {
    /// The overall metadata object does not exist (its full `/<bucket>/<name>` path).
    MissingMetadata(String),
    /// The export holds none of the requested collection or namespace ids.
    KindsUnavailable,
    /// The export cannot be read.
    Malformed(String),
}

/// Cloud Storage as managed export and import see it.
pub trait ManagedStorage: Send + Sync {
    /// Whether the bucket exists.
    fn bucket_exists(&self, project: &str, bucket: &str) -> bool;
    /// Writes an export.
    ///
    /// # Errors
    ///
    /// Why the objects could not be written.
    fn export(&self, job: &ExportJob) -> Result<ExportOutcome, String>;
    /// Reads an export.
    ///
    /// # Errors
    ///
    /// Why the export cannot be imported.
    fn import(&self, job: &ImportJob) -> Result<ImportOutcome, ImportRefusal>;
}

/// The daemon's managed storage, when it serves one.
pub type SharedManagedStorage = Arc<dyn ManagedStorage>;

/// When a local operation finished: a moment after it started, as production reports two
/// distinct instants for work that takes it seconds.
fn finished(start: LogicalInstant) -> LogicalInstant {
    LogicalInstant::from_nanos(start.as_nanos() + 1_000_000)
}

fn instant(at: LogicalInstant) -> Json {
    json!(timestamp_to_json(&encode_instant(at)))
}

fn progress(value: u64, estimated: bool) -> Json {
    if value == 0 {
        return json!({});
    }
    if estimated {
        json!({"estimatedWork": value.to_string(), "completedWork": value.to_string()})
    } else {
        json!({"completedWork": value.to_string()})
    }
}

/// `gs://<bucket>[/<object prefix>]`, as production validates it.
fn parse_gcs(uri: &str) -> Option<(String, String)> {
    let rest = uri.strip_prefix("gs://")?;
    let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
    if bucket.is_empty() {
        return None;
    }
    Some((bucket.to_owned(), prefix.trim_end_matches('/').to_owned()))
}

const GCS_FORMAT: &str = "Google Cloud Storage resource path must be in format: gs://<bucket-name> or: gs://<bucket-name>/<object-name>";

fn strings(body: &Json, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(Json::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Json::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn metadata(type_name: &str, start: LogicalInstant, fields: &[(&str, Json)]) -> Map<String, Json> {
    let mut out = Map::new();
    out.insert(
        "@type".into(),
        json!(format!(
            "type.googleapis.com/google.firestore.admin.v1.{type_name}"
        )),
    );
    out.insert("startTime".into(), instant(start));
    for (key, value) in fields {
        out.insert((*key).to_owned(), value.clone());
    }
    out
}

fn filters(collection_ids: &[String], namespace_ids: &[String]) -> Vec<(&'static str, Json)> {
    let mut out = Vec::new();
    if !collection_ids.is_empty() {
        out.push(("collectionIds", json!(collection_ids)));
    }
    if !namespace_ids.is_empty() {
        out.push(("namespaceIds", json!(namespace_ids)));
    }
    out
}

/// The first document of a database in key order, as production names it (`/items/a`), if
/// it holds any.
pub(crate) fn first_document_key(
    state: &RestState,
    project: &str,
    database: &str,
) -> Result<Option<String>, RestResponse> {
    let mut keys: Vec<String> = documents_of(state, project, database)?
        .iter()
        .map(|d| {
            let mut key = String::new();
            for (collection, id) in &d.path {
                key.push('/');
                key.push_str(collection);
                key.push('/');
                key.push_str(id);
            }
            key
        })
        .collect();
    keys.sort();
    Ok(keys.into_iter().next())
}

fn documents_of(
    state: &RestState,
    project: &str,
    database: &str,
) -> Result<Vec<ManagedDocument>, RestResponse> {
    let parent = crate::decode::parse_parent(&format!(
        "projects/{project}/databases/{database}/documents"
    ))
    .map_err(|e| crate::rest::error_response(&tonic::Status::invalid_argument(e.to_string())))?;
    let handle = state
        .local
        .database_handle(&parent)
        .map_err(|s| crate::rest::error_response(&s))?;
    let documents = handle
        .read(fireemu_core_firestore::store::FirestoreState::documents)
        .unwrap_or_default();
    Ok(documents
        .into_iter()
        .map(|d| ManagedDocument {
            path: d
                .path
                .pairs()
                .iter()
                .map(|(c, id)| (c.as_str().to_owned(), id.as_str().to_owned()))
                .collect(),
            fields: d.fields,
        })
        .collect())
}

/// How many documents of a database belong to one collection group (an index build's and a
/// field change's progress counter).
/// The document count of every collection group of a database, from one snapshot.
pub(crate) fn group_document_counts(
    state: &RestState,
    project: &str,
    database: &str,
) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for document in documents_of(state, project, database).unwrap_or_default() {
        if let Some((collection, _)) = document.path.last() {
            *counts.entry(collection.clone()).or_insert(0) += 1;
        }
    }
    counts
}

pub(crate) fn group_document_count(
    state: &RestState,
    project: &str,
    database: &str,
    group: &str,
) -> u64 {
    documents_of(state, project, database)
        .map(|all| {
            all.iter()
                .filter(|d| {
                    d.path
                        .last()
                        .is_some_and(|(collection, _)| collection == group)
                })
                .count() as u64
        })
        .unwrap_or(0)
}

/// `databases/{d}:exportDocuments`.
pub(crate) fn export(
    state: &RestState,
    project: &str,
    database: &str,
    body: &Json,
) -> RestResponse {
    let Some(uri) = body
        .get("outputUriPrefix")
        .and_then(Json::as_str)
        .filter(|u| !u.is_empty())
    else {
        return error(
            tonic::Code::InvalidArgument,
            "Missing required field: output_uri_prefix",
            None,
        );
    };
    let Some((bucket, prefix)) = parse_gcs(uri) else {
        return error(tonic::Code::InvalidArgument, GCS_FORMAT, None);
    };
    let Some(storage) = state.local.admin().managed_storage() else {
        return error(
            tonic::Code::NotFound,
            &format!("Google Cloud Storage bucket does not exist: {bucket}"),
            None,
        );
    };
    if !storage.bucket_exists(project, &bucket) {
        return error(
            tonic::Code::NotFound,
            &format!("Google Cloud Storage bucket does not exist: {bucket}"),
            None,
        );
    }
    let collection_ids = strings(body, "collectionIds");
    let namespace_ids = strings(body, "namespaceIds");
    let documents = match documents_of(state, project, database) {
        Ok(documents) => documents,
        Err(response) => return response,
    };
    let start = state.local.admin_now();
    let job = ExportJob {
        project: project.to_owned(),
        database: database.to_owned(),
        bucket,
        prefix,
        collection_ids: collection_ids.clone(),
        namespace_ids: namespace_ids.clone(),
        window: (start, finished(start)),
        documents,
    };
    let outcome = match storage.export(&job) {
        Ok(outcome) => outcome,
        Err(message) => return error(tonic::Code::Internal, &message, None),
    };
    let mut fields = filters(&collection_ids, &namespace_ids);
    fields.push(("outputUriPrefix", json!(uri)));
    let mut initial_metadata = metadata(
        "ExportDocumentsMetadata",
        start,
        &[("operationState", json!("PROCESSING"))],
    );
    for (k, v) in &fields {
        initial_metadata.insert((*k).to_owned(), v.clone());
    }
    let mut done_metadata = metadata(
        "ExportDocumentsMetadata",
        start,
        &[
            ("endTime", instant(finished(start))),
            ("operationState", json!("SUCCESSFUL")),
            ("progressDocuments", progress(outcome.documents, false)),
            ("progressBytes", progress(outcome.bytes, false)),
        ],
    );
    for (k, v) in &fields {
        done_metadata.insert((*k).to_owned(), v.clone());
    }
    finish(
        state,
        project,
        database,
        &Json::Object(initial_metadata),
        &Json::Object(done_metadata),
        &json!({"@type": "type.googleapis.com/google.firestore.admin.v1.ExportDocumentsResponse", "outputUriPrefix": uri}),
    )
}

/// Records an operation answered unfinished and finished on its first poll.
fn finish(
    state: &RestState,
    project: &str,
    database: &str,
    initial_metadata: &Json,
    done_metadata: &Json,
    response: &Json,
) -> RestResponse {
    let id = super::operations::reserve_id(state, project, database);
    let name = format!("projects/{project}/databases/{database}/operations/{id}");
    let initial = json!({"name": name, "metadata": initial_metadata});
    let current =
        json!({"name": name, "metadata": done_metadata, "done": true, "response": response});
    state
        .local
        .admin()
        .operations()
        .record_views(project, database, &id, initial.clone(), current);
    RestResponse {
        status: 200,
        body: initial,
    }
}

/// `databases/{d}:importDocuments`.
pub(crate) fn import(
    state: &RestState,
    project: &str,
    database: &str,
    body: &Json,
) -> RestResponse {
    let Some(uri) = body
        .get("inputUriPrefix")
        .and_then(Json::as_str)
        .filter(|u| !u.is_empty())
    else {
        return error(
            tonic::Code::InvalidArgument,
            "Missing required field: input_uri_prefix",
            None,
        );
    };
    let Some((bucket, prefix)) = parse_gcs(uri) else {
        return error(tonic::Code::InvalidArgument, GCS_FORMAT, None);
    };
    let collection_ids = strings(body, "collectionIds");
    let namespace_ids = strings(body, "namespaceIds");
    let Some(storage) = state.local.admin().managed_storage() else {
        return error(
            tonic::Code::NotFound,
            &format!("Google Cloud Storage bucket does not exist: {bucket}"),
            None,
        );
    };
    let job = ImportJob {
        project: project.to_owned(),
        bucket,
        prefix,
        collection_ids: collection_ids.clone(),
        namespace_ids: namespace_ids.clone(),
    };
    // One import holds a whole export in memory: only a few run at once.
    let Some(_running) = ImportSlot::take() else {
        return error(
            tonic::Code::ResourceExhausted,
            &format!(
                "fireemu runs at most {MAX_CONCURRENT_IMPORTS} imports at once; retry when one finishes."
            ),
            None,
        );
    };
    let outcome = match storage.import(&job) {
        Ok(outcome) => outcome,
        Err(ImportRefusal::MissingMetadata(path)) => {
            return error(
                tonic::Code::NotFound,
                &format!("Google Cloud Storage file does not exist: {path}"),
                None,
            )
        }
        Err(ImportRefusal::KindsUnavailable) => {
            return error(
                tonic::Code::InvalidArgument,
                "The requested kinds/namespaces are not available",
                None,
            )
        }
        Err(ImportRefusal::Malformed(message)) => {
            return error(tonic::Code::InvalidArgument, &message, None)
        }
    };
    let start = state.local.admin_now();
    if let Err(response) = apply_import(state, project, database, &outcome.documents) {
        return response;
    }
    let count = outcome.documents.len() as u64;
    let mut fields = filters(&collection_ids, &namespace_ids);
    fields.push(("inputUriPrefix", json!(uri)));
    let mut initial_metadata = metadata(
        "ImportDocumentsMetadata",
        start,
        &[("operationState", json!("PROCESSING"))],
    );
    for (k, v) in &fields {
        initial_metadata.insert((*k).to_owned(), v.clone());
    }
    let mut done_metadata = metadata(
        "ImportDocumentsMetadata",
        start,
        &[
            ("endTime", instant(finished(start))),
            ("operationState", json!("SUCCESSFUL")),
            ("progressDocuments", progress(count, true)),
            ("progressBytes", progress(outcome.bytes, true)),
        ],
    );
    for (k, v) in &fields {
        done_metadata.insert((*k).to_owned(), v.clone());
    }
    finish(
        state,
        project,
        database,
        &Json::Object(initial_metadata),
        &Json::Object(done_metadata),
        &json!({"@type": "type.googleapis.com/google.protobuf.Empty"}),
    )
}

/// Moves a reference into the target database when it named the exported database, as
/// production does on import.
fn retarget(value: Value, from: (&str, &str), to: (&str, &str)) -> Value {
    match value {
        Value::Reference(name) => {
            let source = format!("projects/{}/databases/{}/documents", from.0, from.1);
            match name.strip_prefix(&source) {
                Some(rest) => Value::Reference(format!(
                    "projects/{}/databases/{}/documents{rest}",
                    to.0, to.1
                )),
                None => Value::Reference(name),
            }
        }
        Value::Map(fields) => Value::Map(
            fields
                .into_iter()
                .map(|(k, v)| (k, retarget(v, from, to)))
                .collect(),
        ),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(|v| retarget(v, from, to)).collect())
        }
        other => other,
    }
}

/// The most managed imports that run at once.
const MAX_CONCURRENT_IMPORTS: usize = 2;

static IMPORTS_RUNNING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A running import's slot, released when it is dropped.
struct ImportSlot;

impl ImportSlot {
    fn take() -> Option<Self> {
        IMPORTS_RUNNING
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |running| (running < MAX_CONCURRENT_IMPORTS).then_some(running + 1),
            )
            .ok()
            .map(|_| Self)
    }
}

impl Drop for ImportSlot {
    fn drop(&mut self) {
        IMPORTS_RUNNING.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Whether every collection and document id an export names is one path segment: an id that
/// carried a `/` would write the document somewhere else than the export says.
fn ids_are_segments(documents: &[ImportedDocument]) -> bool {
    documents.iter().all(|d| {
        d.document
            .path
            .iter()
            .all(|(collection, id)| is_segment(collection) && is_segment(id))
    })
}

fn is_segment(id: &str) -> bool {
    !id.is_empty() && !id.contains('/')
}

/// Writes the imported documents into the target database (overwriting, as production does),
/// in commits of at most 500 writes.
fn apply_import(
    state: &RestState,
    project: &str,
    database: &str,
    documents: &[ImportedDocument],
) -> Result<(), RestResponse> {
    use fireemu_proto_firestore::google::firestore::v1 as pb;
    if !ids_are_segments(documents) {
        return Err(error(
            tonic::Code::InvalidArgument,
            "The export names a document whose id is not a single path segment.",
            None,
        ));
    }
    let root = format!("projects/{project}/databases/{database}/documents");
    let writes: Vec<pb::Write> = documents
        .iter()
        .map(|imported| {
            let mut name = root.clone();
            for (collection, id) in &imported.document.path {
                name.push('/');
                name.push_str(collection);
                name.push('/');
                name.push_str(id);
            }
            let fields = imported
                .document
                .fields
                .iter()
                .map(|(k, v)| {
                    let moved = retarget(
                        v.clone(),
                        (&imported.project, &imported.database),
                        (project, database),
                    );
                    (k.clone(), crate::encode::encode_value(&moved))
                })
                .collect();
            pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name,
                    fields,
                    create_time: None,
                    update_time: None,
                })),
                ..pb::Write::default()
            }
        })
        .collect();
    for chunk in writes.chunks(500) {
        state
            .local
            .commit(&pb::CommitRequest {
                database: format!("projects/{project}/databases/{database}"),
                writes: chunk.to_vec(),
                transaction: Vec::new(),
                request_options: None,
            })
            .map_err(|status| crate::rest::error_response(&status))?;
    }
    Ok(())
}

/// `databases/{d}:bulkDeleteDocuments`.
pub(crate) fn bulk_delete(
    state: &RestState,
    project: &str,
    database: &str,
    body: &Json,
) -> RestResponse {
    let collection_ids = strings(body, "collectionIds");
    let namespace_ids = strings(body, "namespaceIds");
    if collection_ids.is_empty() && namespace_ids.is_empty() {
        return error(
            tonic::Code::InvalidArgument,
            "Empty entity filter. To delete all entities, Use database deletion instead.",
            None,
        );
    }
    let documents = match documents_of(state, project, database) {
        Ok(documents) => documents,
        Err(response) => return response,
    };
    let start = state.local.admin_now();
    // Production takes the snapshot the delete works from at the next whole minute.
    let minute = 60_000_000_000_i128;
    let snapshot = LogicalInstant::from_nanos((start.as_nanos() / minute + 1) * minute);
    let doomed_documents: Vec<&ManagedDocument> = documents
        .iter()
        .filter(|d| {
            namespace_ids.is_empty()
                && d.path
                    .last()
                    .is_some_and(|(collection, _)| collection_ids.contains(collection))
        })
        .collect();
    let bytes: u64 = doomed_documents.iter().map(|d| stored_size(d)).sum();
    let doomed: Vec<String> = doomed_documents
        .iter()
        .map(|d| {
            let mut name = format!("projects/{project}/databases/{database}/documents");
            for (collection, id) in &d.path {
                name.push('/');
                name.push_str(collection);
                name.push('/');
                name.push_str(id);
            }
            name
        })
        .collect();
    {
        use fireemu_proto_firestore::google::firestore::v1 as pb;
        for chunk in doomed.chunks(500) {
            let writes = chunk
                .iter()
                .map(|name| pb::Write {
                    operation: Some(pb::write::Operation::Delete(name.clone())),
                    ..pb::Write::default()
                })
                .collect();
            if let Err(status) = state.local.commit(&pb::CommitRequest {
                database: format!("projects/{project}/databases/{database}"),
                writes,
                transaction: Vec::new(),
                request_options: None,
            }) {
                return crate::rest::error_response(&status);
            }
        }
    }
    let fields = filters(&collection_ids, &namespace_ids);
    let mut initial_metadata = metadata(
        "BulkDeleteDocumentsMetadata",
        start,
        &[("operationState", json!("PROCESSING"))],
    );
    let mut done_metadata = metadata(
        "BulkDeleteDocumentsMetadata",
        start,
        &[
            ("endTime", instant(finished(start))),
            ("operationState", json!("SUCCESSFUL")),
            ("progressDocuments", progress(doomed.len() as u64, false)),
            ("progressBytes", progress(bytes, false)),
        ],
    );
    for (k, v) in &fields {
        initial_metadata.insert((*k).to_owned(), v.clone());
        done_metadata.insert((*k).to_owned(), v.clone());
    }
    initial_metadata.insert("snapshotTime".into(), instant(snapshot));
    done_metadata.insert("snapshotTime".into(), instant(snapshot));
    finish(
        state,
        project,
        database,
        &Json::Object(initial_metadata),
        &Json::Object(done_metadata),
        &json!({"@type": "type.googleapis.com/google.firestore.admin.v1.BulkDeleteDocumentsResponse"}),
    )
}

/// The stored size of a document (name + fields + 32), which production's bulk delete reports
/// as the bytes it removed.
fn stored_size(document: &ManagedDocument) -> u64 {
    let name: u64 = document
        .path
        .iter()
        .map(|(collection, id)| collection.len() as u64 + 1 + id.len() as u64 + 1)
        .sum::<u64>()
        + 16;
    let fields: u64 = document
        .fields
        .iter()
        .map(|(key, value)| {
            key.len() as u64
                + 1
                + fireemu_core_firestore::size::field_value_size(value).unwrap_or(0)
        })
        .sum();
    name + fields + 32
}

#[cfg(test)]
mod import_tests {
    use super::*;

    #[test]
    fn only_a_few_imports_run_at_once() {
        let slots: Vec<ImportSlot> = (0..MAX_CONCURRENT_IMPORTS)
            .map(|_| ImportSlot::take().unwrap())
            .collect();
        assert!(ImportSlot::take().is_none());
        drop(slots);
        assert!(ImportSlot::take().is_some());
    }

    #[test]
    fn an_id_carrying_a_slash_is_not_a_document_of_the_export() {
        let document = |id: &str| ImportedDocument {
            document: ManagedDocument {
                path: vec![("items".to_owned(), id.to_owned())],
                fields: std::collections::BTreeMap::new(),
            },
            project: "p".to_owned(),
            database: "d".to_owned(),
        };
        assert!(ids_are_segments(&[document("a")]));
        assert!(!ids_are_segments(&[document("a/other/b")]));
        assert!(!ids_are_segments(&[document("")]));
    }
}
