//! Control-plane helpers for the binary: index file loading and the capability manifest.

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet,
};
use fireemu_core_firestore::ttl::TtlCatalog;
use fireemu_core_types::ids::CollectionId;
use serde_json::{json, Value};

/// Loads canonical definitions and supported native text definitions from the ordinary
/// index files. Search definitions remain outside ordinary query planning.
pub fn load_text_indexes(
    cfg: &crate::config::RuntimeConfig,
) -> Result<fireemu_core_firestore::text_index::TextIndexCatalog, String> {
    let mut catalog = fireemu_core_firestore::text_index::TextIndexCatalog::default();
    if let Some(path) = &cfg.text_index_file {
        if cfg.edition != fireemu_core_types::edition::FirestoreEdition::Enterprise {
            return Err(format!(
                "{path}: text indexes need firestore.edition = enterprise"
            ));
        }
        let text = std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
        let body: Value =
            serde_json::from_str(&text).map_err(|error| format!("{path}: {error}"))?;
        if body.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
            return Err(format!("{path}: schemaVersion 1 is required"));
        }
        let entries = body
            .get("indexes")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{path}: indexes must be an array"))?;
        for (position, entry) in entries.iter().enumerate() {
            add_text_definition(&mut catalog, path, position, entry)?;
        }
    }
    if cfg.edition == fireemu_core_types::edition::FirestoreEdition::Enterprise {
        let files = cfg
            .index_file
            .iter()
            .map(|path| (fireemu_core_types::ids::DatabaseId::DEFAULT, path))
            .chain(
                cfg.firestore_databases
                    .iter()
                    .filter(|(database, _)| {
                        database.as_str() != fireemu_core_types::ids::DatabaseId::DEFAULT
                    })
                    .filter_map(|(database, files)| {
                        files.indexes.as_ref().map(|path| (database.as_str(), path))
                    }),
            );
        for (database, path) in files {
            let text = std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
            // Preserve the existing file validation and keep search out of the ordinary planner.
            parse_indexes_with_notes(path, &text, cfg.index_file_checks())?;
            for note in add_file_text_indexes(
                &mut catalog,
                &cfg.auth_project,
                database,
                path,
                &text,
                cfg.production_exact,
            )? {
                eprintln!("[firestore] {note}");
            }
        }
    }
    Ok(catalog)
}

/// The id prefix of the text indexes an ordinary index file defines (`file-text-<entry>`).
const FILE_TEXT_PREFIX: &str = "file-text-";

/// Adds the text indexes of one `firestore.indexes.json` generation to `database` of
/// `project`, as `file-text-<entry>` READY definitions, and returns the notes for the entries
/// it skipped. The file already passed [`parse_indexes_with_notes`], so every entry here is one
/// `firebase deploy` accepts. In the default profile an entry local search cannot serve (an
/// empty or repeated `indexSpecs`, a field that is also a `geoSpec`, more text indexes than the
/// catalog holds) is skipped with a note instead of failing the start (review S1); under
/// `productionExact` it fails as before. A `*_UNSPECIFIED` enum is its default (proto3), and a
/// JSON `null` is an absent key.
pub fn add_file_text_indexes(
    catalog: &mut fireemu_core_firestore::text_index::TextIndexCatalog,
    project: &str,
    database: &str,
    path: &str,
    text: &str,
    production_exact: bool,
) -> Result<Vec<String>, String> {
    let body: Value = serde_json::from_str(text).map_err(|error| format!("{path}: {error}"))?;
    let mut notes = Vec::new();
    for (position, index) in body
        .get("indexes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let fields = index
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|field| text_field_entry(field, production_exact))
            .collect::<Vec<_>>();
        if fields.is_empty() {
            continue;
        }
        let collection = ["collectionGroup", "collectionId"]
            .into_iter()
            .filter_map(|key| index.get(key).and_then(Value::as_str))
            .find(|value| !value.is_empty())
            .ok_or_else(|| format!("{path}: missing collectionGroup"))?;
        let scope = index
            .get("queryScope")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("COLLECTION");
        let options = index
            .get("searchIndexOptions")
            .filter(|options| !options.is_null())
            .cloned()
            .unwrap_or_else(|| json!({}));
        let entry = json!({"index": {
            "name":format!("projects/{project}/databases/{database}/collectionGroups/{collection}/indexes/{FILE_TEXT_PREFIX}{position}"),
            "queryScope":scope,
            "apiScope":index.get("apiScope").and_then(Value::as_str).unwrap_or("ANY_API"),
            "fields":fields,
            "searchIndexOptions":options,
        },"xFirebaseTestd":{"state":"READY","buildPolicy":"synchronous","languageOverride":"disabled"}});
        match add_text_definition(catalog, path, position, &entry) {
            Ok(()) => {}
            Err(error) if production_exact => return Err(error),
            Err(error) => notes.push(format!(
                "{error}; this search index is skipped: local text search cannot serve it"
            )),
        }
    }
    Ok(notes)
}

/// One field of an index-file entry as a text-index field (`fieldPath` and `searchConfig`
/// holding only its `textSpec`), or `None` when it has no `textSpec` object. In the default
/// profile the `*_UNSPECIFIED` enums become their defaults and a `geoSpec` beside the
/// `textSpec` stays in place, so the entry is skipped rather than half-loaded.
fn text_field_entry(field: &Value, production_exact: bool) -> Option<Value> {
    let config = field.get("searchConfig")?;
    let text_spec = config.get("textSpec").filter(|spec| spec.is_object())?;
    let mut text_spec = text_spec.clone();
    if !production_exact {
        for spec in text_spec
            .get_mut("indexSpecs")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            if let Some(spec) = spec.as_object_mut() {
                spec.retain(|key, value| {
                    !matches!(
                        (key.as_str(), value.as_str()),
                        ("indexType", Some("TEXT_INDEX_TYPE_UNSPECIFIED"))
                            | ("matchType", Some("TEXT_MATCH_TYPE_UNSPECIFIED"))
                    )
                });
            }
        }
    }
    let mut search = json!({ "textSpec": text_spec });
    if let Some(geo) = config.get("geoSpec").filter(|geo| !geo.is_null()) {
        search["geoSpec"] = geo.clone();
    }
    Some(json!({"fieldPath": field.get("fieldPath")?, "searchConfig": search}))
}

/// Replaces the `file-text-*` definitions of `database` of `project` with the ones a reloaded
/// index file defines (review S10). It changes nothing and answers `Ok(false)` when they are
/// the same, and keeps the last good definitions when the new generation is refused. The
/// definitions the control API or the Admin API added stay.
pub fn replace_file_text_indexes(
    catalog: &mut fireemu_core_firestore::text_index::TextIndexCatalog,
    project: &str,
    database: &str,
    path: &str,
    text: &str,
    production_exact: bool,
) -> Result<(bool, Vec<String>), String> {
    let from_file = |catalog: &fireemu_core_firestore::text_index::TextIndexCatalog| {
        catalog
            .entries()
            .filter(|(p, d, definition)| {
                *p == project && *d == database && definition.id.starts_with(FILE_TEXT_PREFIX)
            })
            .map(|(_, _, definition)| definition.clone())
            .collect::<Vec<_>>()
    };
    let current = from_file(catalog);
    let mut trial = catalog.clone();
    for definition in &current {
        trial.remove(project, database, &definition.id);
    }
    let mut fresh = fireemu_core_firestore::text_index::TextIndexCatalog::default();
    let notes = add_file_text_indexes(&mut fresh, project, database, path, text, production_exact)?;
    let loaded = from_file(&fresh);
    if loaded == current {
        return Ok((false, notes));
    }
    for definition in loaded {
        let id = definition.id.clone();
        trial
            .add(project, database, definition)
            .map_err(|error| format!("{path}: text index {id}: {error}"))?;
    }
    *catalog = trial;
    Ok((true, notes))
}

fn add_text_definition(
    catalog: &mut fireemu_core_firestore::text_index::TextIndexCatalog,
    path: &str,
    position: usize,
    entry: &Value,
) -> Result<(), String> {
    let (project, database, definition) = fireemu_adapter_http::control::parse_text_index(entry)
        .map_err(|message| format!("{path}: indexes[{position}]: {message}"))?;
    let id = definition.id.clone();
    let warnings = catalog
        .add(&project, &database, definition)
        .map_err(|error| format!("{path}: indexes[{position}]: {error}"))?;
    for warning in warnings {
        eprintln!("[firestore] text index {id}: {warning}");
    }
    Ok(())
}

/// The Firestore gateway's missing-index reports, served by `/v1/firestore/missingIndexes`.
pub struct MissingIndexReports {
    /// Whether this run reports at all: the strict profile with `firestore.missingIndexes` set
    /// to `"report"`, and Firestore selected.
    pub enabled: bool,
}

impl fireemu_adapter_http::control::MissingIndexHook for MissingIndexReports {
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn reports(&self) -> Vec<fireemu_adapter_http::control::MissingIndexEntry> {
        fireemu_adapter_grpc::gateway::missing_index_reports()
            .into_iter()
            .map(|r| fireemu_adapter_http::control::MissingIndexEntry {
                database: r.database,
                fragment: r.fragment,
                message: r.message,
            })
            .collect()
    }

    fn dropped(&self, project: Option<&str>) -> usize {
        fireemu_adapter_grpc::gateway::missing_index_dropped(project)
    }

    fn clear(&self, project: Option<&str>) -> usize {
        fireemu_adapter_grpc::gateway::clear_missing_index_reports(project)
    }
}

/// Which refusals of `firebase deploy` an index file is checked against when it loads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexFileChecks {
    /// What the official emulator needs: the caps and the entry grammar. The official emulator
    /// never reads the index file, so the `emulator` profile adds nothing to them.
    Emulator,
    /// Also what `firebase deploy` refuses before or while it creates the indexes (the `strict`
    /// profile): a composite index with a single field, an entry without `fields`, a field
    /// override without `indexes`.
    Deploy,
}

/// The `IndexField` modes, of which a field has exactly one.
const INDEX_FIELD_MODES: [&str; 4] = ["order", "arrayConfig", "searchConfig", "vectorConfig"];

/// Checks a `searchConfig` the way firebase-tools `validateIndex` does (each `textSpec` entry
/// names a known `indexType` and `matchType`, `geoJsonIndexingDisabled` is a boolean), and the
/// object shapes of the Admin API `IndexField.SearchConfig` message. Under strict, each level
/// also holds only the keys that message defines: `upgradeOldSpec` sends `searchConfig`
/// verbatim, and the Admin REST API refuses an unknown field name.
fn check_search_config(path: &str, config: &Value, checks: IndexFileChecks) -> Result<(), String> {
    let refuse = |what: &str| Err(format!("index field {path}: searchConfig{what}"));
    let closed = |object: &serde_json::Map<String, Value>, at: &str, known: &[&str]| match object
        .keys()
        .find(|key| !known.contains(&key.as_str()))
    {
        Some(key) if checks == IndexFileChecks::Deploy => Err(format!(
            "index field {path}: {at} has an unknown key {key:?}"
        )),
        _ => Ok(()),
    };
    let Some(object) = config.as_object() else {
        return refuse(" must be an object");
    };
    closed(object, "searchConfig", &["textSpec", "geoSpec"])?;
    match config.get("textSpec") {
        None | Some(Value::Null) => {}
        Some(Value::Object(text)) => {
            let Some(specs) = text.get("indexSpecs").and_then(Value::as_array) else {
                return refuse(".textSpec.indexSpecs must be an array");
            };
            closed(text, "searchConfig.textSpec", &["indexSpecs"])?;
            for (at, spec) in specs.iter().enumerate() {
                if !matches!(
                    spec.get("indexType").and_then(Value::as_str),
                    Some("TOKENIZED" | "TEXT_INDEX_TYPE_UNSPECIFIED")
                ) {
                    return refuse(".textSpec.indexSpecs[].indexType must be TOKENIZED or TEXT_INDEX_TYPE_UNSPECIFIED");
                }
                if !matches!(
                    spec.get("matchType").and_then(Value::as_str),
                    Some("MATCH_GLOBALLY" | "TEXT_MATCH_TYPE_UNSPECIFIED")
                ) {
                    return refuse(".textSpec.indexSpecs[].matchType must be MATCH_GLOBALLY or TEXT_MATCH_TYPE_UNSPECIFIED");
                }
                if let Some(spec) = spec.as_object() {
                    closed(
                        spec,
                        &format!("searchConfig.textSpec.indexSpecs[{at}]"),
                        &["indexType", "matchType"],
                    )?;
                }
            }
        }
        Some(_) => return refuse(".textSpec must be an object"),
    }
    match config.get("geoSpec") {
        None | Some(Value::Null) => {}
        Some(Value::Object(geo)) => {
            if geo
                .get("geoJsonIndexingDisabled")
                .is_some_and(|disabled| !disabled.is_boolean())
            {
                return refuse(".geoSpec.geoJsonIndexingDisabled must be a boolean");
            }
            closed(geo, "searchConfig.geoSpec", &["geoJsonIndexingDisabled"])?;
        }
        Some(_) => return refuse(".geoSpec must be an object"),
    }
    Ok(())
}

/// One field of a composite index entry, in the current or the older (`mode`) format. A search
/// field (`searchConfig`) is checked and answers `None` to the ordinary planner.
/// Supported text definitions are loaded separately by `load_text_indexes`; geo search is not executed.
fn parse_index_field(f: &Value, checks: IndexFileChecks) -> Result<Option<IndexField>, String> {
    let path = f
        .get("fieldPath")
        .and_then(Value::as_str)
        .ok_or("index field without fieldPath")?;
    if let Some(config) = f.get("searchConfig").filter(|config| !config.is_null()) {
        let modes = INDEX_FIELD_MODES
            .iter()
            .filter(|mode| f.get(**mode).is_some_and(|value| !value.is_null()))
            .count();
        if modes != 1 {
            return Err(one_index_field_mode(path));
        }
        check_search_config(path, config, checks)?;
        FieldPath::parse(path).map_err(|e| e.to_string())?;
        return Ok(None);
    }
    // The v1beta1 `mode` stands for `order` or `arrayConfig` when the field has neither
    // (`upgradeOldSpec`).
    let legacy = |wanted: &str| {
        f.get("order").is_none()
            && f.get("arrayConfig").is_none()
            && f.get("vectorConfig").is_none()
            && f.get("mode").and_then(Value::as_str) == Some(wanted)
    };
    let mode = match (
        f.get("order")
            .and_then(Value::as_str)
            .or_else(|| legacy("ASCENDING").then_some("ASCENDING"))
            .or_else(|| legacy("DESCENDING").then_some("DESCENDING")),
        f.get("arrayConfig")
            .and_then(Value::as_str)
            .or_else(|| legacy("ARRAY_CONTAINS").then_some("CONTAINS")),
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
        _ => return Err(one_index_field_mode(path)),
    };
    Ok(Some(IndexField {
        path: FieldPath::parse(path).map_err(|e| e.to_string())?,
        mode,
    }))
}

fn one_index_field_mode(path: &str) -> String {
    format!(
        "index field {path}: exactly one order, arrayConfig, searchConfig, or vectorConfig is required"
    )
}

/// [`parse_indexes_with_notes`] without the notes.
#[cfg(test)]
pub fn parse_indexes(path: &str, text: &str, checks: IndexFileChecks) -> Result<IndexSet, String> {
    parse_indexes_with_notes(path, text, checks).map(|(set, _)| set)
}

/// Parses one `firestore.indexes.json` generation already read by a reload supervisor, with
/// the notes the file deserves when it loads: a search index (`searchConfig`) is checked and
/// left out of the query-planning set, and one note says how many were.
pub fn parse_indexes_with_notes(
    path: &str,
    text: &str,
    checks: IndexFileChecks,
) -> Result<(IndexSet, Vec<String>), String> {
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
    let mut search_indexes = 0usize;
    for (entry, idx) in json
        .get("indexes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        // `firebase deploy` upgrades the file before it validates it (firebase-tools 15.28.2,
        // `upgradeOldSpec`): `collectionId` of the v1beta1 format stands for a missing or empty
        // `collectionGroup`, and a missing or empty `queryScope` is `COLLECTION`. Neither is
        // refused.
        let collection = ["collectionGroup", "collectionId"]
            .into_iter()
            .filter_map(|key| idx.get(key).and_then(Value::as_str))
            .find(|name| !name.is_empty())
            .ok_or("index without collectionGroup")?;
        let scope = match idx
            .get("queryScope")
            .and_then(Value::as_str)
            .filter(|scope| !scope.is_empty())
            .unwrap_or("COLLECTION")
        {
            "COLLECTION" => IndexQueryScope::Collection,
            "COLLECTION_GROUP" => IndexQueryScope::CollectionGroup,
            other => return Err(format!("unsupported queryScope {other}")),
        };
        // `firebase deploy` refuses an entry without `fields` (`validateIndex`), which is what
        // a misspelled key looks like.
        if checks == IndexFileChecks::Deploy && !idx.get("fields").is_some_and(Value::is_array) {
            return Err(format!(
                "{path}: indexes[{entry}] (collection group {collection}): Must contain \"fields\" (an array of index fields)"
            ));
        }
        let fields = idx
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|field| parse_index_field(field, checks))
            .collect::<Result<Vec<_>, _>>()?;
        // A search index serves only search queries, so it never satisfies or changes an
        // ordinary query's index requirement. The 200-entry cap above still counts it.
        let Some(fields) = fields.into_iter().collect::<Option<Vec<_>>>() else {
            CollectionId::try_new(collection).map_err(|e| e.to_string())?;
            search_indexes += 1;
            continue;
        };
        let definition = IndexDefinition {
            collection_group: CollectionId::try_new(collection).map_err(|e| e.to_string())?,
            query_scope: scope,
            fields,
        };
        definition
            .check_capacity()
            .map_err(|e| format!("{path}: {e}"))?;
        if checks == IndexFileChecks::Deploy {
            definition.check_necessary().map_err(|e| {
                format!("{path}: indexes[{entry}] (collection group {collection}): {e}")
            })?;
        }
        set.add_composite(definition);
    }
    parse_field_overrides(path, &json, &mut set, checks)?;
    let notes = match search_indexes {
        0 => Vec::new(),
        count => vec![format!(
            "{path}: {count} search {} (searchConfig) loaded outside ordinary query planning: supported Enterprise text definitions are available to local lexical search; geo search remains unsupported",
            if count == 1 { "index" } else { "indexes" }
        )],
    };
    Ok((set, notes))
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
        let problem =
            |e: &dyn std::fmt::Display| format!("{path}: fieldOverride {collection}.{field}: {e}");
        catalog
            .enable(
                CollectionId::try_new(collection).map_err(|e| problem(&e))?,
                FieldPath::parse(field).map_err(|e| problem(&e))?,
            )
            .map_err(|e| problem(&e))?;
    }
    Ok(catalog)
}

/// Loads `firestore.indexes.json` as a whole at start: the query-planning indexes and the
/// time-to-live policies the same file declares, from one read of the file. The file's notes
/// are printed here.
pub fn load_index_file(
    path: &str,
    checks: IndexFileChecks,
) -> Result<(IndexSet, TtlCatalog), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let (indexes, ttl_policies, notes) = parse_index_file(path, &text, checks)?;
    for note in notes {
        eprintln!("note: {note}");
    }
    Ok((indexes, ttl_policies))
}

/// Parses one generation of `firestore.indexes.json`, both halves or neither: a file whose
/// indexes are valid but whose TTL declaration is not is refused as a whole. The notes are the
/// caller's to print once the generation is in force.
pub fn parse_index_file(
    path: &str,
    text: &str,
    checks: IndexFileChecks,
) -> Result<(IndexSet, TtlCatalog, Vec<String>), String> {
    let (indexes, notes) = parse_indexes_with_notes(path, text, checks)?;
    Ok((indexes, parse_ttl_policies(path, text)?, notes))
}

/// A field override's `ttl`. `firebase deploy` refuses one that is not a boolean.
fn override_ttl(ov: &Value, field: &str) -> Result<bool, String> {
    match ov.get("ttl") {
        None => Ok(false),
        Some(Value::Bool(ttl)) => Ok(*ttl),
        Some(_) => Err(format!("field override {field}: ttl must be a boolean")),
    }
}

fn parse_field_overrides(
    file: &str,
    json: &Value,
    set: &mut IndexSet,
    checks: IndexFileChecks,
) -> Result<(), String> {
    for (entry, ov) in json
        .get("fieldOverrides")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
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
        // `firebase deploy` refuses an override without `indexes` (`validateField`), also when
        // it only sets a TTL policy: that needs `\"indexes\": []`.
        if checks == IndexFileChecks::Deploy && !ov.get("indexes").is_some_and(Value::is_array) {
            return Err(format!(
                "{file}: fieldOverrides[{entry}] ({collection}.{path}): Must contain \"indexes\" (an array, empty for a TTL-only override)"
            ));
        }
        if let Some(indexes) = ov.get("indexes").and_then(Value::as_array) {
            let mut modes = Vec::new();
            for index in indexes {
                // `firebase deploy` asserts exactly one of `arrayConfig` and `order` on every
                // override index (`validateField`), so one with only `vectorConfig` is refused;
                // a single vector field is a composite index.
                if checks == IndexFileChecks::Deploy
                    && index.get("arrayConfig").is_none() == index.get("order").is_none()
                {
                    return Err(format!(
                        "{file}: fieldOverrides[{entry}] ({collection}.{path}): Must contain exactly one of \"arrayConfig,order\" in each of its indexes"
                    ));
                }
                let scope = match index
                    .get("queryScope")
                    .and_then(Value::as_str)
                    .unwrap_or("COLLECTION")
                {
                    "COLLECTION" => IndexQueryScope::Collection,
                    "COLLECTION_GROUP" => IndexQueryScope::CollectionGroup,
                    scope => return Err(format!("unsupported queryScope {scope}")),
                };
                // A search index is a composite index. `firebase deploy` drops a `searchConfig`
                // here when `order` or `arrayConfig` is present and refuses the override
                // otherwise; fireemu refuses it in both cases.
                if index
                    .get("searchConfig")
                    .is_some_and(|config| !config.is_null())
                {
                    return Err(format!(
                        "field override {path}: searchConfig is only accepted in a composite index (indexes[].fields), not in a field override"
                    ));
                }
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
/// of the two behaviours it is being told about. `productionExact` says whether the
/// development defaults were replaced by production's behaviour; `developmentDefaults` lists the effective values and their sources.
#[must_use]
pub fn capabilities_manifest(
    profile: crate::config::CompatibilityProfile,
    production_exact: bool,
    development_defaults: &[Value],
) -> Value {
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "profile": profile.as_str(),
        "productionExact": production_exact,
        "developmentDefaults": development_defaults,
        "capabilities": capability_entries(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn configured_text_indexes_reach_the_database_scoped_execution_catalog() {
        let path =
            std::env::temp_dir().join(format!("fireemu-text-catalog-{}.json", std::process::id()));
        let input = serde_json::json!({"indexes":[{"collectionGroup":"products","queryScope":"COLLECTION","fields":[{"fieldPath":"title","searchConfig":{"textSpec":{"indexSpecs":[{"indexType":"TOKENIZED","matchType":"MATCH_GLOBALLY"}]}}}]}]});
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, input.to_string().as_bytes()).unwrap();
        drop(file);
        let cfg = crate::config::RuntimeConfig {
            auth_project: "demo-app".to_owned(),
            edition: fireemu_core_types::edition::FirestoreEdition::Enterprise,
            index_file: Some(path.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let loaded = super::load_text_indexes(&cfg);
        std::fs::remove_file(&path).unwrap();
        let loaded = loaded.unwrap();
        assert_eq!(loaded.len(), 1);
        let definition = loaded.get("demo-app", "(default)", "file-text-0").unwrap();
        assert_eq!(definition.collection_id.as_str(), "products");
        assert_eq!(
            definition.state,
            fireemu_core_firestore::text_index::TextIndexState::Ready
        );
        assert_eq!(
            definition.language_override,
            fireemu_core_firestore::text_index::LanguageOverridePolicy::Disabled
        );
    }
    use super::*;

    /// The route reads the gateway's list, what it dropped past its bound, and clears both.
    #[test]
    fn missing_index_reports_are_the_gateways_with_what_it_dropped() {
        use fireemu_adapter_http::control::MissingIndexHook as _;
        use fireemu_core_firestore::index::IndexValidationPolicy;
        use fireemu_core_firestore::query::{FieldOp, FilterExpr, Query, QueryScope};
        use fireemu_core_firestore::value::Value as FsValue;
        use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};

        let gateway = fireemu_adapter_grpc::gateway::Gateway {
            enforce_limits: true,
            ctx: fireemu_core_firestore::index::PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::ProductionReport,
            },
            indexes: IndexSet::default(),
        };
        let field = |path: &str, op, value| FilterExpr::Field {
            field: FieldPath::parse(path).unwrap(),
            op,
            value,
        };
        let accepted = gateway
            .validate_query(
                &Query::new(QueryScope::collection(
                    None,
                    CollectionId::try_new("tasks").unwrap(),
                ))
                .with_filter(FilterExpr::And(vec![
                    field("done", FieldOp::Equal, FsValue::Boolean(false)),
                    field("priority", FieldOp::GreaterThan, FsValue::Integer(1)),
                ])),
            )
            .unwrap();
        for n in 0..1000 {
            let database = format!("projects/demo-wire/databases/db-{n}");
            assert!(gateway.report_missing_index(&database, &accepted).is_some());
        }
        let overflow = "projects/demo-over/databases/(default)";
        assert!(gateway.report_missing_index(overflow, &accepted).is_some());
        assert_eq!(gateway.report_missing_index(overflow, &accepted), None);

        let hook = MissingIndexReports { enabled: true };
        assert!(hook.enabled());
        assert!(!MissingIndexReports { enabled: false }.enabled());
        let reports = hook.reports();
        assert_eq!(reports.len(), 1000);
        assert_eq!(reports[7].database, "projects/demo-wire/databases/db-7");
        assert!(reports[7]
            .fragment
            .contains("\"collectionGroup\": \"tasks\""));
        assert!(reports[7].message.contains("The query requires an index"));
        assert_eq!(hook.dropped(Some("demo-over")), 2);
        assert_eq!(hook.dropped(Some("demo-wire")), 0);
        assert_eq!(hook.dropped(None), 2);
        assert_eq!(hook.clear(Some("demo-over")), 0);
        assert_eq!(hook.dropped(None), 0);
        assert_eq!(hook.clear(Some("demo-wire")), 1000);
        assert!(hook.reports().is_empty());
    }

    #[test]
    fn capabilities_include_explicit_and_derived_development_defaults() {
        let cfg = crate::config::RuntimeConfig::from_json(&json!({
            "schemaVersion": 1,
            "productionExact": true,
            "auth": {"allowUnsignedIdTokens": true, "idpSigners": {}}
        }))
        .unwrap();
        let manifest =
            capabilities_manifest(cfg.profile, cfg.production_exact, &cfg.development_defaults);
        assert_eq!(manifest["profile"], "strict");
        assert_eq!(manifest["productionExact"], true);
        assert_eq!(
            manifest["developmentDefaults"][1],
            json!({"key":"auth.allowUnsignedIdTokens", "value":"true", "source":"explicit"})
        );
        assert_eq!(
            manifest["developmentDefaults"][2],
            json!({"key":"auth.idpAssertions", "value":"signed", "source":"derived from auth.idpSigners"})
        );
    }

    #[test]
    fn index_configuration_limits_are_inclusive() {
        let index =
            json!({"collectionGroup":"tasks", "fields":[{"fieldPath":"a", "order":"ASCENDING"}]});
        for count in [200, 201] {
            let config = json!({"indexes": vec![index.clone(); count]});
            assert_eq!(
                parse_indexes("test", &config.to_string(), IndexFileChecks::Emulator).is_ok(),
                count == 200
            );
            let config = json!({"fieldOverrides": vec![json!({"collectionGroup":"tasks", "fieldPath":"a", "indexes":[]}); count]});
            assert_eq!(
                parse_indexes("test", &config.to_string(), IndexFileChecks::Emulator).is_ok(),
                count == 200
            );
        }
        for count in [100, 101] {
            let fields = (0..count)
                .map(|i| json!({"fieldPath":format!("f{i}"),"order":"ASCENDING"}))
                .collect::<Vec<_>>();
            let config = json!({"indexes":[{"collectionGroup":"tasks","fields":fields}]});
            assert_eq!(
                parse_indexes("test", &config.to_string(), IndexFileChecks::Emulator).is_ok(),
                count == 100
            );
        }
    }

    fn deploy(config: &Value) -> Result<IndexSet, String> {
        parse_indexes(
            "firestore.indexes.json",
            &config.to_string(),
            IndexFileChecks::Deploy,
        )
    }

    fn entry(fields: &Value) -> Value {
        json!({"collectionGroup": "g", "queryScope": "COLLECTION", "fields": fields})
    }

    fn asc(path: &str) -> Value {
        json!({"fieldPath": path, "order": "ASCENDING"})
    }

    /// `conformance/fs-config-lifecycle-production.json` `fs-config/index/lifecycle/composite/steps/single-field`:
    /// production answers 400 "this index is not necessary, configure using single field index controls".
    #[test]
    fn a_single_field_composite_is_refused_like_the_deploy_refuses_it() {
        for scope in ["COLLECTION", "COLLECTION_GROUP"] {
            for field in [
                asc("n"),
                json!({"fieldPath": "n", "order": "DESCENDING"}),
                json!({"fieldPath": "tags", "arrayConfig": "CONTAINS"}),
            ] {
                let config = json!({"indexes": [
                    entry(&json!([asc("a"), asc("b")])),
                    {"collectionGroup": "g", "queryScope": scope, "fields": [field]},
                ]});
                let error = deploy(&config).unwrap_err();
                assert!(
                    error.contains("indexes[1]")
                        && error.contains("collection group g")
                        && error.contains(
                            "this index is not necessary, configure using single field index controls"
                        ),
                    "{error}"
                );
                // The emulator profile adds no refusal: the official emulator never reads the file.
                assert!(parse_indexes("f", &config.to_string(), IndexFileChecks::Emulator).is_ok());
            }
        }
    }

    /// Production deployed `(n ASC, __name__ DESC)`, `(__name__ DESC)` and a single-field
    /// vector index (`conformance/fs-query-index.indexes.json`), so they are not "necessary"
    /// refusals.
    #[test]
    fn the_recorded_one_field_shapes_stay_accepted() {
        let config = json!({"indexes": [
            entry(&json!([asc("n"), {"fieldPath": "__name__", "order": "DESCENDING"}])),
            entry(&json!([{"fieldPath": "__name__", "order": "DESCENDING"}])),
            entry(&json!([{"fieldPath": "emb", "vectorConfig": {"dimension": 3, "flat": {}}}])),
            entry(&json!([asc("a"), asc("b")])),
        ]});
        assert_eq!(deploy(&config).unwrap().composites().len(), 4);
    }

    /// `firebase deploy` fills in a missing `queryScope` with `COLLECTION` before it validates
    /// (firebase-tools 15.28.2, `upgradeOldSpec`), so a file without one deploys.
    #[test]
    fn a_missing_query_scope_is_collection_as_the_deploy_reads_it() {
        let config = json!({"indexes": [
            {"collectionGroup": "g", "fields": [asc("a"), asc("b")]}
        ]});
        let set = deploy(&config).unwrap();
        assert_eq!(set.composites()[0].query_scope, IndexQueryScope::Collection);
    }

    /// firebase-tools `validateIndex` asserts that an entry has `fields`.
    #[test]
    fn an_entry_without_fields_is_refused() {
        for entry in [
            json!({"collectionGroup": "g", "queryScope": "COLLECTION", "feilds": [asc("a"), asc("b")]}),
            json!({"collectionGroup": "g", "queryScope": "COLLECTION"}),
            json!({"collectionGroup": "g", "queryScope": "COLLECTION", "fields": null}),
            json!({"collectionGroup": "g", "queryScope": "COLLECTION", "fields": {}}),
        ] {
            let config = json!({"indexes": [entry_ok(), entry]});
            let error = deploy(&config).unwrap_err();
            assert!(
                error.contains("indexes[1]") && error.contains("fields"),
                "{error}"
            );
            assert!(
                parse_indexes("f", &config.to_string(), IndexFileChecks::Emulator).is_ok(),
                "the emulator profile keeps loading it"
            );
        }
    }

    fn entry_ok() -> Value {
        entry(&json!([asc("a"), asc("b")]))
    }

    /// firebase-tools `validateField` asserts that a field override has `indexes`.
    #[test]
    fn a_field_override_without_indexes_is_refused() {
        for overrides in [
            json!([{"collectionGroup": "g", "fieldPath": "t", "ttl": true}]),
            json!([{"collectionGroup": "g", "fieldPath": "t", "indxes": []}]),
            json!([{"collectionGroup": "g", "fieldPath": "t", "indexes": null}]),
        ] {
            let config = json!({"indexes": [], "fieldOverrides": overrides});
            let error = deploy(&config).unwrap_err();
            assert!(
                error.contains("fieldOverrides[0]") && error.contains("indexes"),
                "{error}"
            );
            assert!(parse_indexes("f", &config.to_string(), IndexFileChecks::Emulator).is_ok());
        }
        let config = json!({"indexes": [], "fieldOverrides": [
            {"collectionGroup": "g", "fieldPath": "t", "ttl": true, "indexes": []}
        ]});
        assert!(deploy(&config).is_ok());
    }

    #[test]
    fn the_caps_apply_under_both_checks() {
        let fields = (0..101).map(|i| asc(&format!("f{i}"))).collect::<Vec<_>>();
        let two_arrays = json!([
            {"fieldPath": "a", "arrayConfig": "CONTAINS"},
            {"fieldPath": "b", "arrayConfig": "CONTAINS"}
        ]);
        for checks in [IndexFileChecks::Emulator, IndexFileChecks::Deploy] {
            for fields in [json!(fields), two_arrays.clone()] {
                let config = json!({"indexes": [entry(&fields)]});
                assert!(parse_indexes("f", &config.to_string(), checks).is_err());
            }
        }
    }

    /// firebase-tools `upgradeOldSpec` reads the v1beta1 file format before it validates:
    /// `collectionId` for `collectionGroup`, `mode` for `order` / `arrayConfig`, and an empty
    /// `queryScope` as `COLLECTION`. The deploy accepts such a file, so neither check refuses it.
    #[test]
    fn the_legacy_file_format_loads_as_the_deploy_reads_it() {
        let config = json!({"indexes": [
            {"collectionId": "legacy", "queryScope": "",
             "fields": [{"fieldPath": "a", "mode": "ASCENDING"}, {"fieldPath": "b", "mode": "DESCENDING"}]},
            {"collectionGroup": "tags", "queryScope": "COLLECTION_GROUP",
             "fields": [{"fieldPath": "t", "mode": "ARRAY_CONTAINS"}, {"fieldPath": "b", "order": "ASCENDING"}]},
            {"collectionGroup": "both", "collectionId": "ignored",
             "fields": [{"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "b", "order": "ASCENDING"}]},
        ]});
        for checks in [IndexFileChecks::Emulator, IndexFileChecks::Deploy] {
            let set = parse_indexes("f", &config.to_string(), checks).unwrap();
            let composites = set.composites();
            assert_eq!(composites[0].collection_group.as_str(), "legacy");
            assert_eq!(composites[0].query_scope, IndexQueryScope::Collection);
            assert_eq!(
                composites[0]
                    .fields
                    .iter()
                    .map(|f| f.mode)
                    .collect::<Vec<_>>(),
                [IndexFieldMode::Ascending, IndexFieldMode::Descending]
            );
            assert_eq!(composites[1].fields[0].mode, IndexFieldMode::Contains);
            assert_eq!(composites[2].collection_group.as_str(), "both");
        }
        // A `mode` the deploy cannot turn into an order is still refused.
        let config = json!({"indexes": [{"collectionGroup": "g", "fields": [
            {"fieldPath": "a", "mode": "SIDEWAYS"}, {"fieldPath": "b", "order": "ASCENDING"}]}]});
        assert!(deploy(&config).is_err());
        // Without either key there is no collection group.
        let config = json!({"indexes": [{"fields": [asc("a"), asc("b")]}]});
        assert!(deploy(&config).is_err());
    }

    /// firebase-tools `validateField` asserts exactly one of `arrayConfig` and `order` on every
    /// override index, so a vector-only override is refused by the deploy (a single vector field
    /// is declared as a composite index, which production deployed).
    #[test]
    fn strict_refuses_a_vector_only_override_index() {
        let config = json!({"indexes": [], "fieldOverrides": [{
            "collectionGroup": "items", "fieldPath": "embedding",
            "indexes": [{"queryScope": "COLLECTION", "vectorConfig": {"dimension": 3, "flat": {}}}]
        }]});
        let error = deploy(&config).unwrap_err();
        assert!(
            error.contains("fieldOverrides[0]")
                && error.contains("items.embedding")
                && error.contains("exactly one of"),
            "{error}"
        );
        assert!(parse_indexes("f", &config.to_string(), IndexFileChecks::Emulator).is_ok());
        let config = json!({"indexes": [], "fieldOverrides": [{
            "collectionGroup": "items", "fieldPath": "n",
            "indexes": [{"order": "ASCENDING"}, {"arrayConfig": "CONTAINS", "queryScope": "COLLECTION_GROUP"}]
        }]});
        assert!(deploy(&config).is_ok());
    }

    fn scratch_file(name: &str, text: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "fireemu-control-{name}-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, text).unwrap();
        path
    }

    /// The reading path the daemon uses (`load_index_file`, `parse_index_file`) carries the
    /// choice of checks, and refuses the file as a whole.
    #[test]
    fn loading_a_file_applies_the_checks_it_is_given() {
        let bad = json!({"indexes": [entry_ok(), {"collectionGroup": "g", "queryScope": "COLLECTION", "fields": [asc("n")]}]})
            .to_string();
        let path = scratch_file("load", &bad);
        let name = path.display().to_string();
        let loaded = load_index_file(&name, IndexFileChecks::Deploy);
        let lenient = load_index_file(&name, IndexFileChecks::Emulator);
        std::fs::remove_file(&path).unwrap();
        let error = loaded.unwrap_err();
        assert!(
            error.contains("indexes[1]") && error.contains(&name),
            "{error}"
        );
        assert_eq!(lenient.unwrap().0.composites().len(), 2);
        // Both halves or neither: a bad index half refuses a file whose TTL half is fine.
        let ttl = json!({"indexes": [{"collectionGroup": "g", "fields": []}], "fieldOverrides": [
            {"collectionGroup": "s", "fieldPath": "t", "ttl": true, "indexes": []}]})
        .to_string();
        assert!(parse_index_file("f", &ttl, IndexFileChecks::Deploy).is_err());
        let (set, catalog, _) = parse_index_file("f", &ttl, IndexFileChecks::Emulator).unwrap();
        assert_eq!(set.composites().len(), 1);
        assert_eq!(catalog.iter().count(), 1);
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
        let indexes =
            parse_indexes("test", &config.to_string(), IndexFileChecks::Emulator).unwrap();
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
            assert!(parse_indexes("test", &config.to_string(), IndexFileChecks::Emulator).is_err());
        }
    }

    #[test]
    fn field_override_preserves_enabled_modes_and_rejects_conflicting_modes() {
        let config = json!({"fieldOverrides":[{"collectionGroup":"tasks", "fieldPath":"*", "indexes":[]}, {"collectionGroup":"tasks", "fieldPath":"map.x", "indexes":[{"order":"DESCENDING", "queryScope":"COLLECTION_GROUP"}]}]});
        let indexes =
            parse_indexes("test", &config.to_string(), IndexFileChecks::Emulator).unwrap();
        let collection = CollectionId::try_new("tasks").unwrap();
        assert!(indexes
            .single_field_modes(&collection, &FieldPath::parse("map.y").unwrap())
            .is_empty());
        assert_eq!(
            indexes.single_field_modes(&collection, &FieldPath::parse("map.x").unwrap()),
            vec![(IndexQueryScope::CollectionGroup, IndexFieldMode::Descending)]
        );
        let config = json!({"fieldOverrides":[{"collectionGroup":"tasks", "fieldPath":"a", "indexes":[{"order":"ASCENDING", "arrayConfig":"CONTAINS"}]}]});
        assert!(parse_indexes("test", &config.to_string(), IndexFileChecks::Emulator).is_err());
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
        let indexes =
            parse_indexes("test", &config.to_string(), IndexFileChecks::Emulator).unwrap();
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
            assert!(
                parse_indexes("test", &config.to_string(), IndexFileChecks::Emulator).is_err(),
                "{ttl}"
            );
        }
    }

    #[test]
    fn a_ttl_that_no_admin_patch_could_set_is_refused() {
        for field in ["*", "__name__"] {
            let config = json!({"fieldOverrides":[{"collectionGroup":"c", "fieldPath":field, "ttl":true, "indexes":[]}]});
            let error = ttl_fields(&config).unwrap_err();
            assert!(error.starts_with("test: "), "{field}: {error}");
            if field == "*" {
                assert!(
                    error.contains("wildcard field cannot carry a TTL policy"),
                    "{error}"
                );
            }
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

        let indexes =
            parse_indexes("test", &config.to_string(), IndexFileChecks::Emulator).unwrap();
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
        let indexes =
            parse_indexes("test", &config.to_string(), IndexFileChecks::Emulator).unwrap();
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

    fn search(path: &str) -> Value {
        json!({"fieldPath": path, "searchConfig": {"textSpec": {"indexSpecs": [
            {"indexType": "TOKENIZED", "matchType": "MATCH_GLOBALLY"}]}}})
    }

    fn both_checks() -> [IndexFileChecks; 2] {
        [IndexFileChecks::Emulator, IndexFileChecks::Deploy]
    }

    /// A production `firestore.indexes.json` with a search index (`searchConfig`, Enterprise
    /// full-text and geo search) loads under both profiles. The search index never takes part in
    /// query planning: the set is the one of the same file without it, and one note says so.
    #[test]
    fn search_indexes_load_without_taking_part_in_planning() {
        let ordinary = entry(&json!([asc("a"), asc("b")]));
        let with_search = json!({"indexes": [
            {"collectionGroup": "posts", "queryScope": "COLLECTION_GROUP", "fields": [search("body")]},
            ordinary,
            {"collectionGroup": "posts", "queryScope": "COLLECTION", "fields": [asc("a"), search("body")]}
        ]});
        let without = json!({"indexes": [ordinary]});
        for checks in both_checks() {
            let (set, notes) =
                parse_indexes_with_notes("f.json", &with_search.to_string(), checks).unwrap();
            assert_eq!(
                set,
                parse_indexes("f.json", &without.to_string(), checks).unwrap()
            );
            assert_eq!(notes.len(), 1, "{notes:?}");
            assert!(
                notes[0].contains("f.json")
                    && notes[0].contains("2 search indexes")
                    && notes[0].contains("searchConfig"),
                "{}",
                notes[0]
            );
            let (_, notes) =
                parse_indexes_with_notes("f.json", &without.to_string(), checks).unwrap();
            assert!(notes.is_empty(), "{notes:?}");
        }
        let one = json!({"indexes": [entry(&json!([search("body")]))]});
        let (set, notes) =
            parse_indexes_with_notes("f.json", &one.to_string(), IndexFileChecks::Deploy).unwrap();
        assert!(set.composites().is_empty());
        assert!(notes[0].contains("1 search index "), "{}", notes[0]);
    }

    /// firebase-tools `validateIndex` accepts a `searchConfig` without `textSpec`, a `geoSpec`
    /// with a boolean `geoJsonIndexingDisabled`, the `*_UNSPECIFIED` enum values and an empty
    /// `indexSpecs`.
    #[test]
    fn search_config_shapes_the_deploy_accepts_load() {
        for config in [
            json!({}),
            json!({"geoSpec": {}}),
            json!({"geoSpec": {"geoJsonIndexingDisabled": true}}),
            json!({"textSpec": null, "geoSpec": null}),
            json!({"textSpec": {"indexSpecs": []}}),
            json!({"textSpec": {"indexSpecs": [
                {"indexType": "TEXT_INDEX_TYPE_UNSPECIFIED", "matchType": "TEXT_MATCH_TYPE_UNSPECIFIED"},
                {"indexType": "TOKENIZED", "matchType": "MATCH_GLOBALLY"}]},
                "geoSpec": {"geoJsonIndexingDisabled": false}}),
        ] {
            let file = json!({"indexes": [entry(&json!([{"fieldPath": "body", "searchConfig": config}]))]});
            for checks in both_checks() {
                assert!(
                    parse_indexes("f", &file.to_string(), checks).is_ok(),
                    "{config} {checks:?}"
                );
            }
        }
    }

    /// The `searchConfig` checks of firebase-tools `validateIndex`, plus the object shapes the
    /// Admin API `IndexField.SearchConfig` message requires, refuse the file and name the field.
    #[test]
    fn malformed_search_config_is_refused_naming_the_field() {
        for (config, says) in [
            (json!("TOKENIZED"), "searchConfig must be an object"),
            (json!([]), "searchConfig must be an object"),
            (json!({"textSpec": {}}), "textSpec.indexSpecs"),
            (json!({"textSpec": "x"}), "textSpec must be an object"),
            (
                json!({"textSpec": {"indexSpecs": {}}}),
                "textSpec.indexSpecs",
            ),
            (
                json!({"textSpec": {"indexSpecs": [{"matchType": "MATCH_GLOBALLY"}]}}),
                "indexType",
            ),
            (
                json!({"textSpec": {"indexSpecs": [{"indexType": "NGRAM", "matchType": "MATCH_GLOBALLY"}]}}),
                "indexType",
            ),
            (
                json!({"textSpec": {"indexSpecs": [{"indexType": "TOKENIZED"}]}}),
                "matchType",
            ),
            (
                json!({"textSpec": {"indexSpecs": [{"indexType": "TOKENIZED", "matchType": "PREFIX"}]}}),
                "matchType",
            ),
            (
                json!({"textSpec": {"indexSpecs": ["TOKENIZED"]}}),
                "indexType",
            ),
            (
                json!({"geoSpec": {"geoJsonIndexingDisabled": "yes"}}),
                "geoJsonIndexingDisabled must be a boolean",
            ),
            (
                json!({"geoSpec": {"geoJsonIndexingDisabled": null}}),
                "geoJsonIndexingDisabled must be a boolean",
            ),
            (json!({"geoSpec": 5}), "geoSpec must be an object"),
        ] {
            let file = json!({"indexes": [entry(&json!([asc("a"), {"fieldPath": "body", "searchConfig": config}]))]});
            for checks in both_checks() {
                let error = parse_indexes("f", &file.to_string(), checks).unwrap_err();
                assert!(
                    error.contains("index field body") && error.contains(says),
                    "{config} {checks:?}: {error}"
                );
            }
        }
    }

    /// `IndexField` is a oneof: a field with `searchConfig` and another mode is refused under both
    /// profiles. `firebase deploy` does not refuse it: `upgradeOldSpec` keeps one mode per field
    /// (`order`, then `arrayConfig`, `vectorConfig`, `searchConfig`) before `validateIndex` runs,
    /// so deploy drops the others. fireemu keeps the oneof refusal, as it does for `order` with
    /// `arrayConfig` (issue `index-field-mode-precedence-differs-from-deploy.md`). The v1beta1
    /// `mode` comes last in that order, so `searchConfig` wins over it.
    #[test]
    fn search_config_beside_another_mode_is_refused() {
        for other in [
            json!({"order": "ASCENDING"}),
            json!({"arrayConfig": "CONTAINS"}),
            json!({"vectorConfig": {"dimension": 2, "flat": {}}}),
        ] {
            let mut field = search("body");
            for (key, value) in other.as_object().unwrap() {
                field[key] = value.clone();
            }
            let file = json!({"indexes": [entry(&json!([asc("a"), field]))]});
            for checks in both_checks() {
                let error = parse_indexes("f", &file.to_string(), checks).unwrap_err();
                assert!(
                    error.contains(
                        "index field body: exactly one order, arrayConfig, searchConfig, or vectorConfig is required"
                    ),
                    "{other} {checks:?}: {error}"
                );
            }
        }
        let mut legacy = search("body");
        legacy["mode"] = json!("ASCENDING");
        let file = json!({"indexes": [entry(&json!([asc("a"), legacy]))]});
        let (set, notes) =
            parse_indexes_with_notes("f", &file.to_string(), IndexFileChecks::Deploy).unwrap();
        assert!(set.composites().is_empty() && notes.len() == 1);
    }

    /// A search index is a composite index, so `searchConfig` in a field override is refused
    /// under both profiles, with a message that says where it belongs. Without `order` or
    /// `arrayConfig` deploy refuses the override too (`validateField`); with one of them deploy
    /// accepts it and drops `searchConfig` (`patchField` sends neither), which fireemu does not
    /// follow (issue `index-field-mode-precedence-differs-from-deploy.md`).
    #[test]
    fn a_search_config_field_override_is_refused_under_both_profiles() {
        let file = json!({"indexes": [], "fieldOverrides": [{
            "collectionGroup": "posts", "fieldPath": "body",
            "indexes": [{"queryScope": "COLLECTION", "searchConfig": {}}]
        }]});
        let error = parse_indexes("f", &file.to_string(), IndexFileChecks::Emulator).unwrap_err();
        assert!(
            error.contains("field override body")
                && error.contains("searchConfig")
                && error.contains("composite index"),
            "{error}"
        );
        let error = deploy(&file).unwrap_err();
        assert!(error.contains("exactly one of"), "{error}");
    }

    /// `upgradeOldSpec` copies `searchConfig` verbatim into `indexes.create`, and the Admin REST
    /// API refuses an unknown JSON field name with 400 ("Unknown name"), so strict refuses an
    /// unknown key at every level of a `searchConfig`. The emulator profile loads it.
    #[test]
    fn unknown_search_config_keys_are_refused_under_strict_only() {
        for (config, at) in [
            (
                json!({"textSpec": {"indexSpecs": []}, "foo": 1}),
                "searchConfig",
            ),
            (
                json!({"textSpec": {"indexSpecs": [], "foo": 1}}),
                "searchConfig.textSpec",
            ),
            (
                json!({"textSpec": {"indexSpecs": [{"indexType": "TOKENIZED", "matchType": "MATCH_GLOBALLY", "foo": 1}]}}),
                "searchConfig.textSpec.indexSpecs[0]",
            ),
            (
                json!({"geoSpec": {"geoJsonIndexingDisabled": true, "foo": 1}}),
                "searchConfig.geoSpec",
            ),
        ] {
            let file = json!({"indexes": [entry(&json!([{"fieldPath": "body", "searchConfig": config}]))]});
            let error = deploy(&file).unwrap_err();
            assert!(
                error.contains(&format!(
                    "index field body: {at} has an unknown key \"foo\""
                )),
                "{config}: {error}"
            );
            assert!(
                parse_indexes("f", &file.to_string(), IndexFileChecks::Emulator).is_ok(),
                "{config}"
            );
        }
    }

    /// The note is the file's, not the daemon's: every load of a file with a search index
    /// (the start, each hot reload, each database that names the file) carries it again.
    #[test]
    fn the_search_note_comes_with_each_load_of_the_file() {
        let file = json!({"indexes": [entry(&json!([search("body")]))]}).to_string();
        let first = parse_index_file("f", &file, IndexFileChecks::Deploy)
            .unwrap()
            .2;
        let second = parse_index_file("f", &file, IndexFileChecks::Deploy)
            .unwrap()
            .2;
        assert_eq!(first.len(), 1);
        assert_eq!(first, second);
        let plain = json!({"indexes": [entry_ok()]}).to_string();
        assert!(parse_index_file("f", &plain, IndexFileChecks::Deploy)
            .unwrap()
            .2
            .is_empty());
    }

    /// The skipped search index still needs a collection group production can hold.
    #[test]
    fn a_search_index_with_an_invalid_collection_group_is_refused() {
        for group in ["a/b", "__x__"] {
            let file = json!({"indexes": [{"collectionGroup": group, "queryScope": "COLLECTION_GROUP", "fields": [search("body")]}]});
            for checks in both_checks() {
                assert!(
                    parse_indexes("f", &file.to_string(), checks).is_err(),
                    "{group} {checks:?}"
                );
            }
        }
    }

    use fireemu_core_firestore::text_index::{TextIndexCatalog, TextIndexType, TextMatchType};

    /// Loads one index-file generation's text definitions into a fresh catalog.
    fn file_text(
        file: &Value,
        production_exact: bool,
    ) -> Result<(TextIndexCatalog, Vec<String>), String> {
        let mut catalog = TextIndexCatalog::default();
        let notes = add_file_text_indexes(
            &mut catalog,
            "demo-app",
            "(default)",
            "f.json",
            &file.to_string(),
            production_exact,
        )?;
        Ok((catalog, notes))
    }

    fn text_field(config: Value) -> Value {
        let mut field = json!({"fieldPath": "body"});
        field["searchConfig"] = config;
        field
    }

    /// Review S1: the `*_UNSPECIFIED` enums `firebase deploy` accepts are the defaults, so the
    /// index loads as a `TOKENIZED` / `MATCH_GLOBALLY` text index in the default profile.
    #[test]
    fn file_text_indexes_read_unspecified_enums_as_defaults() {
        let file = json!({"indexes": [entry(&json!([text_field(json!({"textSpec": {"indexSpecs": [
            {"indexType": "TEXT_INDEX_TYPE_UNSPECIFIED", "matchType": "TEXT_MATCH_TYPE_UNSPECIFIED"}]}}))]))]});
        let (catalog, notes) = file_text(&file, false).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        let definition = catalog.get("demo-app", "(default)", "file-text-0").unwrap();
        assert_eq!(definition.fields[0].index_type, TextIndexType::Tokenized);
        assert_eq!(
            definition.fields[0].match_type,
            TextMatchType::MatchGlobally
        );
    }

    /// The entry's scope and search options reach the definition.
    #[test]
    fn file_text_indexes_keep_the_scope_and_search_options() {
        let mut index = json!({"collectionGroup": "posts", "queryScope": "COLLECTION_GROUP", "fields": [search("body")]});
        index["searchIndexOptions"] =
            json!({"textLanguage": "en", "textLanguageOverrideFieldPath": "lang"});
        let (catalog, _) = file_text(&json!({"indexes": [index]}), false).unwrap();
        let definition = catalog.get("demo-app", "(default)", "file-text-0").unwrap();
        assert_eq!(definition.query_scope, IndexQueryScope::CollectionGroup);
        assert_eq!(
            definition.language_override,
            fireemu_core_firestore::text_index::LanguageOverridePolicy::ExplicitField(
                FieldPath::parse("lang").unwrap()
            )
        );
    }

    /// Review S1: shapes the deploy accepts but local search cannot serve are skipped with a
    /// note in the default profile; productionExact keeps refusing them at start.
    #[test]
    fn unsupported_file_text_shapes_are_skipped_by_default_and_refused_under_production_exact() {
        for config in [
            json!({"textSpec": {"indexSpecs": []}}),
            json!({"textSpec": {"indexSpecs": [
                {"indexType": "TOKENIZED", "matchType": "MATCH_GLOBALLY"},
                {"indexType": "TOKENIZED", "matchType": "MATCH_GLOBALLY"}]}}),
            json!({"textSpec": {"indexSpecs": [{"indexType": "TOKENIZED", "matchType": "MATCH_GLOBALLY"}]},
                "geoSpec": {"geoJsonIndexingDisabled": false}}),
        ] {
            let file = json!({"indexes": [entry(&json!([text_field(config.clone())])), entry(&json!([search("title")]))]});
            assert!(parse_indexes("f.json", &file.to_string(), IndexFileChecks::Deploy).is_ok());
            let (catalog, notes) = file_text(&file, false).unwrap();
            assert!(
                catalog
                    .get("demo-app", "(default)", "file-text-0")
                    .is_none(),
                "{config}"
            );
            assert!(
                catalog
                    .get("demo-app", "(default)", "file-text-1")
                    .is_some(),
                "{config}"
            );
            assert_eq!(notes.len(), 1, "{config}: {notes:?}");
            assert!(
                notes[0].contains("indexes[0]") && notes[0].contains("skipped"),
                "{}",
                notes[0]
            );
            let error = file_text(&file, true).unwrap_err();
            assert!(error.contains("indexes[0]"), "{error}");
        }
    }

    /// Review S1: a `null` `textSpec` (and a `null` mode beside `searchConfig`) is no text
    /// index, and the null mode never makes a text field unreadable.
    #[test]
    fn null_text_spec_and_null_modes_are_absent() {
        let file = json!({"indexes": [
            entry(&json!([text_field(json!({"textSpec": null, "geoSpec": {}}))])),
            entry(&json!([{"fieldPath": "body", "order": null, "searchConfig": {"textSpec": {"indexSpecs": [
                {"indexType": "TOKENIZED", "matchType": "MATCH_GLOBALLY"}]}}}])),
        ]});
        assert!(parse_indexes("f.json", &file.to_string(), IndexFileChecks::Deploy).is_ok());
        for production_exact in [false, true] {
            let (catalog, notes) = file_text(&file, production_exact).unwrap();
            assert!(notes.is_empty(), "{notes:?}");
            assert!(catalog
                .get("demo-app", "(default)", "file-text-0")
                .is_none());
            assert!(catalog
                .get("demo-app", "(default)", "file-text-1")
                .is_some());
        }
    }

    /// Review S10: a reload replaces the file's text definitions of that database, keeps the
    /// ones the control API added, and reports whether anything changed.
    #[test]
    fn reloading_the_index_file_replaces_only_its_text_indexes() {
        let mut catalog = TextIndexCatalog::default();
        let first =
            json!({"indexes": [entry(&json!([search("title")])), entry(&json!([search("body")]))]});
        add_file_text_indexes(
            &mut catalog,
            "demo-app",
            "(default)",
            "f.json",
            &first.to_string(),
            false,
        )
        .unwrap();
        let mut control = catalog
            .get("demo-app", "(default)", "file-text-0")
            .unwrap()
            .clone();
        control.id = "control".into();
        catalog.add("demo-app", "(default)", control).unwrap();
        let other = catalog
            .get("demo-app", "(default)", "file-text-1")
            .unwrap()
            .clone();
        catalog.add("demo-app", "named", other).unwrap();
        let second = json!({"indexes": [entry(&json!([search("summary")]))]});
        assert_eq!(
            replace_file_text_indexes(
                &mut catalog,
                "demo-app",
                "(default)",
                "f.json",
                &second.to_string(),
                false
            ),
            Ok((true, Vec::new()))
        );
        let fields = |id: &str| {
            catalog
                .get("demo-app", "(default)", id)
                .map(|d| d.fields[0].path.canonical())
        };
        assert_eq!(fields("file-text-0").as_deref(), Some("summary"));
        assert_eq!(fields("file-text-1"), None);
        assert_eq!(fields("control").as_deref(), Some("title"));
        assert!(catalog.get("demo-app", "named", "file-text-1").is_some());
        let before = catalog.clone();
        assert_eq!(
            replace_file_text_indexes(
                &mut catalog,
                "demo-app",
                "(default)",
                "f.json",
                &second.to_string(),
                false
            ),
            Ok((false, Vec::new()))
        );
        assert_eq!(catalog, before);
        let refused = json!({"indexes": [entry(&json!([text_field(json!({"textSpec": {"indexSpecs": []}}))]))]});
        assert!(replace_file_text_indexes(
            &mut catalog,
            "demo-app",
            "(default)",
            "f.json",
            &refused.to_string(),
            true
        )
        .is_err());
        assert_eq!(
            catalog, before,
            "a refused reload keeps the last good definitions"
        );
    }

    fn search_spec() -> impl proptest::strategy::Strategy<Value = Value> {
        use proptest::prelude::*;
        let spec = (
            proptest::sample::select(vec!["TOKENIZED", "TEXT_INDEX_TYPE_UNSPECIFIED"]),
            proptest::sample::select(vec!["MATCH_GLOBALLY", "TEXT_MATCH_TYPE_UNSPECIFIED"]),
        )
            .prop_map(|(index_type, match_type)| json!({"indexType": index_type, "matchType": match_type}));
        (
            proptest::option::of(proptest::option::of(proptest::collection::vec(spec, 0..3))),
            proptest::option::of(proptest::option::of(proptest::bool::ANY)),
            proptest::bool::ANY,
        )
            .prop_map(|(text, geo, null_order)| {
                let mut config = json!({});
                match text {
                    Some(Some(specs)) => config["textSpec"] = json!({"indexSpecs": specs}),
                    Some(None) => config["textSpec"] = Value::Null,
                    None => {}
                }
                match geo {
                    Some(Some(disabled)) => {
                        config["geoSpec"] = json!({"geoJsonIndexingDisabled": disabled});
                    }
                    Some(None) => config["geoSpec"] = json!({}),
                    None => {}
                }
                let mut field = text_field(config);
                if null_order {
                    field["order"] = Value::Null;
                }
                field
            })
    }

    proptest::proptest! {
        /// Review S1: in the default profile, loading the text indexes never fails where the
        /// deploy checks accept the file.
        #[test]
        fn file_text_indexes_never_fail_where_deploy_checks_accept(
            fields in proptest::collection::vec(search_spec(), 1..3),
            options in proptest::option::of(proptest::sample::select(vec![
                json!({}), json!({"textLanguage": "en"}), json!({"textLanguageOverrideFieldPath": "language"}),
            ])),
        ) {
            let mut index = entry(&Value::Array(fields));
            if let Some(options) = options {
                index["searchIndexOptions"] = options;
            }
            let file = json!({"indexes": [index]});
            for checks in both_checks() {
                if parse_indexes("f.json", &file.to_string(), checks).is_ok() {
                    proptest::prop_assert!(file_text(&file, false).is_ok(), "{} {:?}", file, checks);
                }
            }
        }
    }

    fn mode_value(key: &str) -> Value {
        match key {
            "order" => json!("DESCENDING"),
            "arrayConfig" => json!("CONTAINS"),
            "searchConfig" => json!({"textSpec": {"indexSpecs": [
                {"indexType": "TOKENIZED", "matchType": "MATCH_GLOBALLY"}]}}),
            _ => json!({"dimension": 4, "flat": {}}),
        }
    }

    const MODE_KEYS: [&str; 4] = ["order", "arrayConfig", "searchConfig", "vectorConfig"];

    proptest::proptest! {
        /// Any combination of the four `IndexField` modes other than exactly one is refused, in
        /// a composite index and under both profiles; exactly one loads.
        #[test]
        fn index_field_modes_are_a_oneof(present in proptest::collection::vec(proptest::bool::ANY, 4)) {
            let mut field = json!({"fieldPath": "b"});
            for (key, on) in MODE_KEYS.iter().zip(&present) {
                if *on {
                    field[*key] = mode_value(key);
                }
            }
            let file = json!({"indexes": [entry(&json!([asc("a"), field]))]});
            let exactly_one = present.iter().filter(|on| **on).count() == 1;
            for checks in both_checks() {
                let parsed = parse_indexes("f", &file.to_string(), checks);
                proptest::prop_assert_eq!(parsed.is_ok(), exactly_one, "{} {:?}: {:?}", field, checks, parsed);
            }
        }

        /// A text spec loads exactly when every entry names an `indexType` and a `matchType` of
        /// the firebase-tools enums.
        #[test]
        fn text_specs_load_exactly_when_their_enums_are_known(
            specs in proptest::collection::vec((
                proptest::option::of(proptest::sample::select(vec!["TOKENIZED", "TEXT_INDEX_TYPE_UNSPECIFIED", "NGRAM", ""])),
                proptest::option::of(proptest::sample::select(vec!["MATCH_GLOBALLY", "TEXT_MATCH_TYPE_UNSPECIFIED", "PREFIX", ""])),
            ), 0..4)
        ) {
            let known = specs.iter().all(|(index_type, match_type)| {
                matches!(index_type, Some("TOKENIZED" | "TEXT_INDEX_TYPE_UNSPECIFIED"))
                    && matches!(match_type, Some("MATCH_GLOBALLY" | "TEXT_MATCH_TYPE_UNSPECIFIED"))
            });
            let specs = specs.iter().map(|(index_type, match_type)| {
                let mut spec = json!({});
                if let Some(index_type) = index_type { spec["indexType"] = json!(index_type); }
                if let Some(match_type) = match_type { spec["matchType"] = json!(match_type); }
                spec
            }).collect::<Vec<_>>();
            let field = json!({"fieldPath": "body", "searchConfig": {"textSpec": {"indexSpecs": specs}}});
            let file = json!({"indexes": [entry(&json!([field]))]});
            for checks in both_checks() {
                proptest::prop_assert_eq!(parse_indexes("f", &file.to_string(), checks).is_ok(), known);
            }
        }

        /// An extra key at any level of a well-formed `searchConfig` is refused under strict
        /// unless it is one the Admin API message defines, and always loads under emulator.
        #[test]
        fn search_config_keys_are_closed_under_strict(
            level in 0usize..4,
            key in proptest::sample::select(vec!["foo", "textSpec", "geoSpec", "indexSpecs", "indexType", "matchType", "geoJsonIndexingDisabled", "TextSpec"]),
        ) {
            let mut config = json!({
                "textSpec": {"indexSpecs": [{"indexType": "TOKENIZED", "matchType": "MATCH_GLOBALLY"}]},
                "geoSpec": {"geoJsonIndexingDisabled": false},
            });
            let (target, known): (&mut Value, &[&str]) = match level {
                0 => (&mut config, &["textSpec", "geoSpec"]),
                1 => (&mut config["textSpec"], &["indexSpecs"]),
                2 => (&mut config["textSpec"]["indexSpecs"][0], &["indexType", "matchType"]),
                _ => (&mut config["geoSpec"], &["geoJsonIndexingDisabled"]),
            };
            if known.contains(&key) {
                return Ok(());
            }
            target[key] = json!(1);
            let file = json!({"indexes": [entry(&json!([{"fieldPath": "body", "searchConfig": config}]))]});
            proptest::prop_assert!(deploy(&file).is_err());
            proptest::prop_assert!(parse_indexes("f", &file.to_string(), IndexFileChecks::Emulator).is_ok());
        }

        /// Differential: inserting search indexes anywhere in a file changes neither the planning
        /// set nor whether the file loads, and the note counts them.
        #[test]
        fn search_indexes_never_change_the_planning_set(
            ordinary in proptest::collection::vec((0u8..3, 0u8..3, proptest::bool::ANY), 0..5),
            searches in proptest::collection::vec((0usize..6, proptest::bool::ANY), 0..4),
        ) {
            let fields = ["a", "b", "c"];
            let ordinary = ordinary.iter().map(|(first, second, group)| json!({
                "collectionGroup": "posts",
                "queryScope": if *group { "COLLECTION_GROUP" } else { "COLLECTION" },
                "fields": [asc(fields[usize::from(*first)]), {"fieldPath": fields[usize::from(*second)], "order": "DESCENDING"}],
            })).collect::<Vec<_>>();
            let mut mixed = ordinary.clone();
            for (at, with_order) in &searches {
                let fields = if *with_order { json!([asc("a"), search("body")]) } else { json!([search("body")]) };
                mixed.insert((*at).min(mixed.len()), json!({"collectionGroup": "posts", "queryScope": "COLLECTION_GROUP", "fields": fields}));
            }
            for checks in both_checks() {
                let plain = parse_indexes("f", &json!({"indexes": ordinary}).to_string(), checks);
                let with = parse_indexes_with_notes("f", &json!({"indexes": mixed}).to_string(), checks);
                proptest::prop_assert_eq!(plain.is_ok(), with.is_ok());
                if let (Ok(plain), Ok((with, notes))) = (plain, with) {
                    proptest::prop_assert_eq!(plain, with);
                    proptest::prop_assert_eq!(notes.len(), usize::from(!searches.is_empty()));
                }
            }
        }
    }
}
