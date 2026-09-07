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
    for key in ["indexes", "fieldOverrides"] {
        if json
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|items| items.len() > 200)
        {
            return Err(format!("{path}: {key} exceeds the 200 configuration limit for the supported billing-disabled plan"));
        }
    }
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
        if fields.len() > 100 {
            return Err(format!(
                "{path}: FS-LIMIT-FIELDS-PER-COMPOSITE-INDEX: maximum 100 fields"
            ));
        }
        if fields
            .iter()
            .filter(|field| field.mode == IndexFieldMode::Contains)
            .count()
            > 1
        {
            return Err(format!(
                "{path}: a composite index may contain only one array field"
            ));
        }
        set.add_composite(IndexDefinition {
            collection_group: CollectionId::try_new(collection).map_err(|e| e.to_string())?,
            query_scope: scope,
            fields,
        });
    }
    parse_field_overrides(&json, &mut set)?;
    Ok(set)
}

fn parse_field_overrides(json: &Value, set: &mut IndexSet) -> Result<(), String> {
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
        if let Some(indexes) = ov.get("indexes").and_then(Value::as_array) {
            let mut modes = Vec::new();
            for index in indexes {
                let scope = match index
                    .get("queryScope")
                    .and_then(Value::as_str)
                    .unwrap_or("COLLECTION")
                {
                    "COLLECTION" => IndexQueryScope::Collection,
                    "COLLECTION_GROUP" => IndexQueryScope::CollectionGroup,
                    scope => return Err(format!("unsupported queryScope {scope}")),
                };
                let mode = match (
                    index.get("order").and_then(Value::as_str),
                    index.get("arrayConfig").and_then(Value::as_str),
                ) {
                    (Some("ASCENDING"), None) => IndexFieldMode::Ascending,
                    (Some("DESCENDING"), None) => IndexFieldMode::Descending,
                    (None, Some("CONTAINS")) => IndexFieldMode::Contains,
                    _ => {
                        return Err(format!(
                            "field override {path}: one order or arrayConfig required"
                        ))
                    }
                };
                if !modes.contains(&(scope, mode)) {
                    modes.push((scope, mode));
                }
            }
            let collection = CollectionId::try_new(collection).map_err(|e| e.to_string())?;
            if path == "*" {
                set.set_default_single_field_indexes(&collection, modes);
                continue;
            }
            let field = FieldPath::parse(path).map_err(|e| e.to_string())?;
            set.set_single_field_indexes(&collection, &field, modes);
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_configuration_limits_are_inclusive() {
        let index =
            json!({"collectionGroup":"tasks", "fields":[{"fieldPath":"a", "order":"ASCENDING"}]});
        for count in [200, 201] {
            let config = json!({"indexes": vec![index.clone(); count]});
            assert_eq!(
                parse_indexes("test", &config.to_string()).is_ok(),
                count == 200
            );
            let config = json!({"fieldOverrides": vec![json!({"collectionGroup":"tasks", "fieldPath":"a", "indexes":[]}); count]});
            assert_eq!(
                parse_indexes("test", &config.to_string()).is_ok(),
                count == 200
            );
        }
        for count in [100, 101] {
            let fields = (0..count)
                .map(|i| json!({"fieldPath":format!("f{i}"),"order":"ASCENDING"}))
                .collect::<Vec<_>>();
            let config = json!({"indexes":[{"collectionGroup":"tasks","fields":fields}]});
            assert_eq!(
                parse_indexes("test", &config.to_string()).is_ok(),
                count == 100
            );
        }
    }

    #[test]
    fn field_override_preserves_enabled_modes_and_rejects_conflicting_modes() {
        let config = json!({"fieldOverrides":[{"collectionGroup":"tasks", "fieldPath":"*", "indexes":[]}, {"collectionGroup":"tasks", "fieldPath":"map.x", "indexes":[{"order":"DESCENDING", "queryScope":"COLLECTION_GROUP"}]}]});
        let indexes = parse_indexes("test", &config.to_string()).unwrap();
        let collection = CollectionId::try_new("tasks").unwrap();
        assert!(indexes
            .single_field_modes(&collection, &FieldPath::parse("map.y").unwrap())
            .is_empty());
        assert_eq!(
            indexes.single_field_modes(&collection, &FieldPath::parse("map.x").unwrap()),
            vec![(IndexQueryScope::CollectionGroup, IndexFieldMode::Descending)]
        );
        let config = json!({"fieldOverrides":[{"collectionGroup":"tasks", "fieldPath":"a", "indexes":[{"order":"ASCENDING", "arrayConfig":"CONTAINS"}]}]});
        assert!(parse_indexes("test", &config.to_string()).is_err());
    }
}
