//! Control-plane helpers for the binary: index file loading and the capability manifest.

use ftd_core_firestore::field_path::FieldPath;
use ftd_core_firestore::index::{
    IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet,
};
use ftd_core_types::ids::CollectionId;
use serde_json::{json, Value};

/// Loads `firestore.indexes.json` (composite indexes and single-field exemptions).
pub fn load_indexes(path: &str) -> Result<IndexSet, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let json: Value = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    let mut set = IndexSet::default();
    for idx in json
        .get("indexes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let collection = idx
            .get("collectionGroup")
            .and_then(Value::as_str)
            .ok_or("index without collectionGroup")?;
        let scope = match idx
            .get("queryScope")
            .and_then(Value::as_str)
            .unwrap_or("COLLECTION")
        {
            "COLLECTION" => IndexQueryScope::Collection,
            "COLLECTION_GROUP" => IndexQueryScope::CollectionGroup,
            other => return Err(format!("unsupported queryScope {other}")),
        };
        let mut fields = Vec::new();
        for f in idx
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let path = f
                .get("fieldPath")
                .and_then(Value::as_str)
                .ok_or("index field without fieldPath")?;
            let mode = match (
                f.get("order").and_then(Value::as_str),
                f.get("arrayConfig").and_then(Value::as_str),
            ) {
                (Some("ASCENDING"), _) => IndexFieldMode::Ascending,
                (Some("DESCENDING"), _) => IndexFieldMode::Descending,
                (_, Some("CONTAINS")) => IndexFieldMode::Contains,
                _ => return Err(format!("index field {path}: order or arrayConfig required")),
            };
            fields.push(IndexField {
                path: FieldPath::parse(path).map_err(|e| e.to_string())?,
                mode,
            });
        }
        set.add_composite(IndexDefinition {
            collection_group: CollectionId::try_new(collection).map_err(|e| e.to_string())?,
            query_scope: scope,
            fields,
        });
    }
    for ov in json
        .get("fieldOverrides")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let collection = ov
            .get("collectionGroup")
            .and_then(Value::as_str)
            .ok_or("fieldOverride without collectionGroup")?;
        let path = ov
            .get("fieldPath")
            .and_then(Value::as_str)
            .ok_or("fieldOverride without fieldPath")?;
        let disabled = ov
            .get("indexes")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
        if disabled {
            for scope in [
                IndexQueryScope::Collection,
                IndexQueryScope::CollectionGroup,
            ] {
                set.add_exemption(&ftd_core_firestore::index::SingleFieldExemption {
                    collection_group: CollectionId::try_new(collection)
                        .map_err(|e| e.to_string())?,
                    field: FieldPath::parse(path).map_err(|e| e.to_string())?,
                    query_scope: scope,
                });
            }
        }
    }
    Ok(set)
}

/// Capability manifest (`GET /v1/capabilities`, spec 4).
#[must_use]
pub fn capabilities_manifest() -> Value {
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "capabilities": {
            "CTL-1": {"status": "partial", "implemented": ["clock:set", "clock:advance", "clock:advanceTo", "sessions/{s}/reset", "rules load/replace/drop", "health", "capabilities", "limits"], "unimplemented": ["snapshots", "awaitIdle", "faultPlan", "multiple sessions"]},
            "FS-GW-1": {"status": "implemented", "precision": "conservative"},
            "FS-LIM-1": {"status": "partial", "implemented": ["FS-LIMIT-DOCUMENT-BYTES", "FS-LIMIT-NESTED-MAP-ARRAY-DEPTH", "FS-LIMIT-FIELD-TRANSFORMS-PER-DOCUMENT", "FS-LIMIT-COLLECTION-ID", "FS-LIMIT-DOCUMENT-ID", "FS-LIMIT-TRANSACTION-TOTAL-TIME", "FS-LIMIT-TRANSACTION-IDLE-TIME"]},
            "FS-RPC-1": {"status": "implemented", "implemented": ["GetDocument", "ListDocuments", "CreateDocument", "UpdateDocument", "DeleteDocument", "BatchGetDocuments", "BeginTransaction", "Commit", "Rollback", "RunQuery", "RunAggregationQuery", "ListCollectionIds", "BatchWrite", "Write", "Listen", "verify writes"], "unimplemented": ["PartitionQuery", "ExecutePipeline", "read_time consistency", "ListCollectionIds page tokens"]},
            "FS-REST-1": {"status": "implemented", "notes": ["served on the Firestore port next to gRPC", "readTime selectors and findNearest are refused explicitly"]},
            "FS-WEB-1": {"status": "implemented", "notes": ["WebChannel v8 transport of the browser web SDK (Listen / Write) on the Firestore port; no resume history (targets are RESET on resume)"]},
            "FS-QRY-1": {"status": "implemented", "notes": ["orderBy on missing fields excludes documents", "range filters are type-restricted"]},
            "FS-TXN-1": {"status": "implemented", "precision": "boundary-conformance", "notes": ["serializable: read sets and executed queries are re-validated at commit"]},
            "FS-LSN-1": {"status": "partial", "implemented": ["query and document targets", "live diffs after every commit", "once", "resume as RESET"], "unimplemented": ["resume history", "existence filters", "back-pressure by target"]},
            "FS-PIPE-RPC-1": {"status": "unimplemented"},
            "FS-TEXT-VAL-1": {"status": "unimplemented"},
            "AUTH-CORE-1": {"status": "implemented", "implemented": ["accounts:signUp (email, anonymous)", "accounts:signInWithPassword", "accounts:signInWithCustomToken", "accounts:lookup", "accounts:update", "securetoken token (JSON and form)", "Admin: projects/{p}/accounts create/lookup/update/delete/batchGet"], "unimplemented": ["federated providers", "email actions (oob codes)", "phone sign-in"]},
            "AUTH-TOKEN-1": {"status": "partial", "implemented": ["unsigned-emulator"], "unimplemented": ["session-rsa"]},
            "AUTH-MFA-TOTP-1": {"status": "implemented", "precision": "boundary-conformance", "notes": ["window and enrollment TTL are local policies"]},
            "AUTH-RULES-1": {"status": "implemented", "notes": ["request.auth from verified ID tokens on every Firestore surface; Bearer owner bypasses"]},
            "AUTH-MFA-SMS-0": {"status": "unsupported"},
            "RULES-LINT-1": {"status": "implemented"},
            "RULES-BUDGET-1": {"status": "partial", "implemented": ["expressions 1000", "call depth 20"], "unimplemented": ["document access budgets"]},
            "RULES-1": {"status": "partial", "precision": "conservative", "implemented": ["get / create / update / delete against the returned snapshot or the staged commit", "list / aggregation / Listen queries proven from equality and array-contains constraints (RULES-QUERY-CONSTRAINTS)", "collection groups need a recursive wildcard rule"], "unimplemented": ["get()/exists()/getAfter()", "regular expressions", "timestamp/duration/latlng/math/hashing namespaces", "inequality and request.query in proofs"]},
            "ST-OBJ-1": {"status": "implemented", "implemented": ["Firebase Storage protocol (/v0/b, X-Goog-Upload resumable, download tokens)", "JSON API (/storage/v1, /upload/storage/v1, /download/storage/v1, emulator-style /b paths, Content-Range resumable, rewriteTo)", "generation / metageneration preconditions", "prefix / delimiter listing", "MD5 / CRC32C"], "unimplemented": ["object versioning / archived generations", "ACLs and signed URLs", "compose", "notifications", "Storage triggers (FN-EVT-1)"]},
            "STORAGE-RULES-1": {"status": "partial", "implemented": ["service firebase.storage: get / list / create / update / delete with request.resource and resource", "Firebase protocol goes through the rules; the JSON API is a privileged surface"], "unimplemented": ["firestore.get() / firestore.exists()", "string.matches() (regular expressions)"]},
            "FN-HTTP-1": {"status": "unimplemented"},
            "FN-EVT-1": {"status": "unimplemented"},
            "FN-SCH-1": {"status": "unimplemented"}
        }
    })
}
