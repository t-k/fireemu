//! Control-plane helpers for the binary: index file loading and the capability manifest.

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet,
};
use fireemu_core_types::ids::CollectionId;
use serde_json::{json, Value};

/// Loads `firestore.text-indexes.json` when `firestore.textIndexDefinitionFile` is set:
/// every entry must validate (FS-TEXT-VAL-1) and the edition must be Enterprise.
pub fn load_text_indexes(
    cfg: &crate::config::RuntimeConfig,
) -> Result<fireemu_core_firestore::text_index::TextIndexCatalog, String> {
    let mut set = fireemu_core_firestore::text_index::TextIndexCatalog::default();
    let Some(path) = &cfg.text_index_file else {
        return Ok(set);
    };
    if cfg.edition != fireemu_core_types::edition::FirestoreEdition::Enterprise {
        return Err(format!(
            "{path}: text indexes need firestore.edition = enterprise"
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let json: Value = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    if json.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
        return Err(format!("{path}: schemaVersion 1 is required"));
    }
    let entries = json
        .get("indexes")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{path}: indexes must be an array"))?;
    for (i, e) in entries.iter().enumerate() {
        let (project, database, def) = fireemu_adapter_http::control::parse_text_index(e)
            .map_err(|m| format!("{path}: indexes[{i}]: {m}"))?;
        let id = def.id.clone();
        let warnings = set
            .add(&project, &database, def)
            .map_err(|e| format!("{path}: indexes[{i}]: {e}"))?;
        for w in warnings {
            eprintln!("[firestore] text index {id}: {w}");
        }
    }
    Ok(set)
}

/// Loads `firestore.indexes.json` (composite indexes and single-field exemptions).
pub fn load_indexes(path: &str) -> Result<IndexSet, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    parse_indexes(path, &text)
}

/// Parses one `firestore.indexes.json` generation already read by a reload supervisor.
pub fn parse_indexes(path: &str, text: &str) -> Result<IndexSet, String> {
    let json: Value = serde_json::from_str(text).map_err(|e| format!("{path}: {e}"))?;
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
                set.add_exemption(&fireemu_core_firestore::index::SingleFieldExemption {
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

/// The capability manifest data (spec 4). It is a data file rather than a `json!` literal so
/// that `tools/compat-check` can read exactly what the binary publishes without linking or
/// starting it, and so that the manifest cannot drift from the compatibility contract in
/// `spec/compatibility/contract.json`.
const CAPABILITIES_JSON: &str = include_str!("capabilities.json");

/// The one value the manifest text cannot state literally, because the budget it describes is
/// owned by the control API.
const SNAPSHOT_BUDGET_PLACEHOLDER: &str = "{MAX_SNAPSHOTS_PER_SESSION}";

/// The capability entries, with the placeholders of [`CAPABILITIES_JSON`] resolved.
///
/// # Panics
///
/// If the embedded manifest is not a JSON object. `crates/fireemu/tests/capabilities.rs` reads
/// the manifest from a running daemon, so a malformed file fails the test suite as well.
#[must_use]
pub fn capability_entries() -> Value {
    let text = CAPABILITIES_JSON.replace(
        SNAPSHOT_BUDGET_PLACEHOLDER,
        &fireemu_adapter_http::control::MAX_SNAPSHOTS_PER_SESSION.to_string(),
    );
    let entries: Value =
        serde_json::from_str(&text).expect("crates/fireemu/src/capabilities.json is valid JSON");
    assert!(
        entries.is_object(),
        "crates/fireemu/src/capabilities.json is a JSON object of capability entries"
    );
    entries
}

/// Capability manifest (`GET /v1/capabilities`, spec 4).
///
/// `profile` is the compatibility profile the run is executing under: every capability below
/// is described as it behaves in that profile, so a client reading the manifest knows which
/// of the two behaviours it is being told about.
#[must_use]
pub fn capabilities_manifest(profile: crate::config::CompatibilityProfile) -> Value {
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "profile": profile.as_str(),
        "capabilities": capability_entries(),
    })
}
