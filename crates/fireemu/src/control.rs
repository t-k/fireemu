//! Control-plane helpers for the binary: index file loading and the capability manifest.

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet,
};
use fireemu_core_firestore::ttl::TtlCatalog;
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
                f.get("vectorConfig"),
            ) {
                (Some("ASCENDING"), None, None) => IndexFieldMode::Ascending,
                (Some("DESCENDING"), None, None) => IndexFieldMode::Descending,
                (None, Some("CONTAINS"), None) => IndexFieldMode::Contains,
                (None, None, Some(config)) => {
                    let dimension = config
                        .get("dimension")
                        .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
                        .and_then(|value| u32::try_from(value).ok())
                        .filter(|dimension| (1..=2048).contains(dimension))
                        .ok_or_else(|| format!("index field {path}: vectorConfig.dimension must be an integer from 1 through 2048"))?;
                    if !config.get("flat").is_some_and(Value::is_object) {
                        return Err(format!("index field {path}: vectorConfig.flat is required"));
                    }
                    IndexFieldMode::Vector { dimension }
                }
                _ => return Err(format!("index field {path}: exactly one order, arrayConfig, or vectorConfig is required")),
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

/// Reads the time-to-live policies a `firestore.indexes.json` declares, as `firebase deploy`
/// creates them: a field override with `ttl: true` becomes a policy on that field of that
/// collection group. `ttl: false` and an absent `ttl` declare none (deploy leaves an
/// existing policy alone in the second case, and a fresh emulator has none). The result is
/// the policy state `fields.patch` sets, checked by the same catalog: one TTL field per
/// collection group, not `__name__`, not the `*` wildcard, at most
/// [`MAX_TTL_FIELDS_PER_DATABASE`](fireemu_core_firestore::ttl::MAX_TTL_FIELDS_PER_DATABASE).
pub fn parse_ttl_policies(path: &str, text: &str) -> Result<TtlCatalog, String> {
    let json: Value = serde_json::from_str(text).map_err(|e| format!("{path}: {e}"))?;
    let mut catalog = TtlCatalog::new();
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
        let field = ov
            .get("fieldPath")
            .and_then(Value::as_str)
            .ok_or("fieldOverride without fieldPath")?;
        if !override_ttl(ov, field)? {
            continue;
        }
        if field == "*" {
            return Err(format!(
                "{path}: the wildcard field cannot carry a TTL policy (collection group {collection})"
            ));
        }
        catalog
            .enable(
                CollectionId::try_new(collection).map_err(|e| e.to_string())?,
                FieldPath::parse(field).map_err(|e| e.to_string())?,
            )
            .map_err(|e| format!("{path}: fieldOverride {collection}.{field}: {e}"))?;
    }
    Ok(catalog)
}

/// Loads `firestore.indexes.json` as a whole: the query-planning indexes and the time-to-live
/// policies the same file declares, from one read of the file.
pub fn load_index_file(path: &str) -> Result<(IndexSet, TtlCatalog), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    parse_index_file(path, &text)
}

/// Parses one generation of `firestore.indexes.json`, both halves or neither: a file whose
/// indexes are valid but whose TTL declaration is not is refused as a whole.
pub fn parse_index_file(path: &str, text: &str) -> Result<(IndexSet, TtlCatalog), String> {
    Ok((parse_indexes(path, text)?, parse_ttl_policies(path, text)?))
}

/// A field override's `ttl`. `firebase deploy` refuses one that is not a boolean.
fn override_ttl(ov: &Value, field: &str) -> Result<bool, String> {
    match ov.get("ttl") {
        None => Ok(false),
        Some(Value::Bool(ttl)) => Ok(*ttl),
        Some(_) => Err(format!("field override {field}: ttl must be a boolean")),
    }
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
        override_ttl(ov, path)?;
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
                    index.get("vectorConfig"),
                ) {
                    (Some("ASCENDING"), None, None) => IndexFieldMode::Ascending,
                    (Some("DESCENDING"), None, None) => IndexFieldMode::Descending,
                    (None, Some("CONTAINS"), None) => IndexFieldMode::Contains,
                    (None, None, Some(config)) => {
                        let dimension = config
                            .get("dimension")
                            .and_then(|value| {
                                value.as_u64().or_else(|| value.as_str()?.parse().ok())
                            })
                            .and_then(|value| u32::try_from(value).ok())
                            .filter(|dimension| (1..=2048).contains(dimension))
                            .ok_or_else(|| {
                                format!(
                                    "field override {path}: vectorConfig.dimension must be an integer from 1 through 2048"
                                )
                            })?;
                        if !config.get("flat").is_some_and(Value::is_object) {
                            return Err(format!(
                                "field override {path}: vectorConfig.flat is required"
                            ));
                        }
                        IndexFieldMode::Vector { dimension }
                    }
                    _ => {
                        return Err(format!(
                            "field override {path}: exactly one order, arrayConfig, or vectorConfig is required"
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
    fn parses_vector_index_configuration() {
        let config = json!({
            "indexes": [{
                "collectionGroup": "items",
                "fields": [{"fieldPath": "category", "order": "ASCENDING"},
                           {"fieldPath": "embedding", "vectorConfig": {"dimension": 2, "flat": {}}}]
            }]
        });
        let indexes = parse_indexes("test", &config.to_string()).unwrap();
        assert_eq!(
            indexes.composites()[0].fields[1].mode,
            IndexFieldMode::Vector { dimension: 2 }
        );
    }

    #[test]
    fn rejects_malformed_vector_index_configuration() {
        for vector_config in [
            json!({"dimension": 0, "flat": {}}),
            json!({"dimension": 2049, "flat": {}}),
            json!({"dimension": 2}),
            json!({"dimension": "not-a-number", "flat": {}}),
        ] {
            let config = json!({
                "indexes": [{
                    "collectionGroup": "items",
                    "fields": [{"fieldPath": "embedding", "vectorConfig": vector_config}]
                }]
            });
            assert!(parse_indexes("test", &config.to_string()).is_err());
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

    fn ttl_fields(config: &Value) -> Result<Vec<(String, String)>, String> {
        parse_ttl_policies("test", &config.to_string()).map(|catalog| {
            catalog
                .iter()
                .map(|(collection, policy)| {
                    (collection.as_str().to_owned(), policy.field.canonical())
                })
                .collect()
        })
    }

    #[test]
    fn a_field_override_with_ttl_true_becomes_a_policy_like_fields_patch_sets() {
        let config = json!({"fieldOverrides":[
            {"collectionGroup":"sessions", "fieldPath":"expireAt", "ttl":true, "indexes":[]},
            {"collectionGroup":"logs", "fieldPath":"meta.until", "ttl":true, "indexes":[{"order":"ASCENDING", "queryScope":"COLLECTION"}]},
        ]});
        assert_eq!(
            ttl_fields(&config).unwrap(),
            vec![
                ("logs".to_owned(), "meta.until".to_owned()),
                ("sessions".to_owned(), "expireAt".to_owned()),
            ]
        );
        let catalog = parse_ttl_policies("test", &config.to_string()).unwrap();
        let policy = catalog
            .policy(&CollectionId::try_new("sessions").unwrap())
            .unwrap();
        assert_eq!(policy.state, fireemu_core_firestore::ttl::TtlState::Active);
        assert_eq!(policy.expiration_offset, None);
        // The index half of the same override is read as before.
        let indexes = parse_indexes("test", &config.to_string()).unwrap();
        assert_eq!(
            indexes.single_field_modes(
                &CollectionId::try_new("logs").unwrap(),
                &FieldPath::parse("meta.until").unwrap()
            ),
            vec![(IndexQueryScope::Collection, IndexFieldMode::Ascending)]
        );
    }

    #[test]
    fn ttl_false_or_absent_declares_no_policy() {
        for ttl in [Some(false), None] {
            let mut item =
                json!({"collectionGroup":"sessions", "fieldPath":"expireAt", "indexes":[]});
            if let Some(ttl) = ttl {
                item["ttl"] = json!(ttl);
            }
            let config = json!({"fieldOverrides":[item]});
            assert!(ttl_fields(&config).unwrap().is_empty(), "{ttl:?}");
        }
        assert!(ttl_fields(&json!({})).unwrap().is_empty());
    }

    #[test]
    fn a_ttl_that_is_not_a_boolean_is_refused_by_both_readers() {
        for ttl in [json!("true"), json!(1), json!(null), json!({})] {
            let config = json!({"fieldOverrides":[{"collectionGroup":"c", "fieldPath":"f", "ttl":ttl, "indexes":[]}]});
            assert!(ttl_fields(&config).is_err(), "{ttl}");
            assert!(parse_indexes("test", &config.to_string()).is_err(), "{ttl}");
        }
    }

    #[test]
    fn a_ttl_that_no_admin_patch_could_set_is_refused() {
        for field in ["*", "__name__"] {
            let config = json!({"fieldOverrides":[{"collectionGroup":"c", "fieldPath":field, "ttl":true, "indexes":[]}]});
            assert!(ttl_fields(&config).is_err(), "{field}");
        }
        let two_fields = json!({"fieldOverrides":[
            {"collectionGroup":"c", "fieldPath":"a", "ttl":true, "indexes":[]},
            {"collectionGroup":"c", "fieldPath":"b", "ttl":true, "indexes":[]},
        ]});
        let error = ttl_fields(&two_fields).unwrap_err();
        assert!(
            error.contains('c') && error.contains("at most one TTL field"),
            "{error}"
        );
        let repeated = json!({"fieldOverrides":[
            {"collectionGroup":"c", "fieldPath":"a", "ttl":true, "indexes":[]},
            {"collectionGroup":"c", "fieldPath":"a", "ttl":true, "indexes":[]},
        ]});
        assert_eq!(ttl_fields(&repeated).unwrap().len(), 1);
    }

    #[test]
    fn the_ttl_policy_count_is_bounded_like_the_catalog() {
        let overrides = |count: usize| {
            (0..count)
                .map(|i| json!({"collectionGroup":format!("c{i}"), "fieldPath":"t", "ttl":true, "indexes":[]}))
                .collect::<Vec<_>>()
        };
        let limit = fireemu_core_firestore::ttl::MAX_TTL_FIELDS_PER_DATABASE;
        assert_eq!(
            ttl_fields(&json!({"fieldOverrides": overrides(limit)}))
                .unwrap()
                .len(),
            limit
        );
        assert!(ttl_fields(&json!({"fieldOverrides": overrides(limit + 1)})).is_err());
    }

    #[test]
    fn parses_vector_field_override_configuration() {
        let config = json!({
            "fieldOverrides": [{
                "collectionGroup": "items",
                "fieldPath": "embedding",
                "indexes": [{
                    "queryScope": "COLLECTION",
                    "vectorConfig": {"dimension": 3, "flat": {}}
                }]
            }]
        });

        let indexes = parse_indexes("test", &config.to_string()).unwrap();
        let collection = CollectionId::try_new("items").unwrap();
        assert_eq!(
            indexes.single_field_modes(&collection, &FieldPath::parse("embedding").unwrap()),
            vec![(
                IndexQueryScope::Collection,
                IndexFieldMode::Vector { dimension: 3 }
            )]
        );
    }

    #[test]
    fn parsed_vector_indexes_drive_nearest_planning_and_filtered_queries_need_composites() {
        use fireemu_core_firestore::index::{
            decide, IndexDecision, IndexValidationPolicy, PlanningContext,
        };
        use fireemu_core_firestore::query::{
            DistanceMeasure, FieldOp, FilterExpr, Query, QueryScope,
        };
        use fireemu_core_firestore::value::Value;
        use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};

        let config = json!({
            "fieldOverrides": [{
                "collectionGroup": "items",
                "fieldPath": "embedding",
                "indexes": [{"vectorConfig": {"dimension": 2, "flat": {}}}]
            }]
        });
        let indexes = parse_indexes("test", &config.to_string()).unwrap();
        let context = PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        };
        let nearest = || {
            Query::new(QueryScope::collection(
                None,
                CollectionId::try_new("items").unwrap(),
            ))
            .with_find_nearest(fireemu_core_firestore::query::FindNearest {
                vector_field: FieldPath::parse("embedding").unwrap(),
                query_vector: vec![0.0, 1.0],
                distance_measure: DistanceMeasure::Cosine,
                limit: 5,
                distance_result_field: None,
                distance_threshold: None,
            })
        };

        assert!(matches!(
            decide(&nearest().canonicalize().unwrap(), &indexes, &context),
            IndexDecision::UseIndex { .. }
        ));

        let filtered = nearest().with_filter(FilterExpr::Field {
            field: FieldPath::parse("category").unwrap(),
            op: FieldOp::Equal,
            value: Value::String("book".to_owned()),
        });
        assert!(matches!(
            decide(&filtered.canonicalize().unwrap(), &indexes, &context),
            IndexDecision::MissingRequired { .. }
        ));
    }
}
