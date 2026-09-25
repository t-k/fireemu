//! Exact, versioned denominator for the production-compatibility program.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::Report;

/// Versioned exact target ledger checked by the compatibility gate.
pub const DENOMINATOR_PATH: &str =
    "spec/compatibility/denominators/ip-fs-standard-2026-09-14.v1.json";

const GOAL: &str = "IP-FS-PRODUCTION-COMPATIBILITY";
const VERSION: &str = "ip-fs-standard-2026-09-14.v1";
const SOURCE_PATH: &str = "spec/compatibility/upstream/2026-09-09-retry/discovery.json";
const EVIDENCE_STATES: [&str; 5] = [
    "waiting-oracle",
    "local-verified",
    "oracle-compared",
    "repaired",
    "compat-verified",
];
const SCOPES: [&str; 3] = ["target", "enterprise-only", "outside-goal"];
const FEATURE_GROUPS: [&str; 18] = [
    "AUTH-ACCOUNT",
    "AUTH-CREDENTIAL",
    "AUTH-ACTION",
    "AUTH-MFA",
    "AUTH-FEDERATION",
    "AUTH-TENANT",
    "AUTH-BLOCKING",
    "AUTH-CONFIG",
    "AUTH-CROSS-CUTTING",
    "FS-DATA-WRITE",
    "FS-QUERY-INDEX",
    "FS-TRANSACTION",
    "FS-RULES",
    "FS-LISTEN-SDK",
    "FS-CONFIG-LIFECYCLE",
    "FS-CROSS-CUTTING",
    "FS-ENTERPRISE-EXCLUDED",
    "FS-DATASTORE-EXCLUDED",
];

/// Validates the exact pinned source set and refuses unsupported evidence promotions.
#[must_use]
pub fn check(root: &Path) -> Report {
    let mut report = Report::default();
    let Some(denominator) = read_json(root, DENOMINATOR_PATH, &mut report.problems) else {
        return report;
    };
    validate(root, &denominator, &mut report.problems);
    report
}

fn read_json(root: &Path, relative: &str, problems: &mut Vec<String>) -> Option<Value> {
    let path = match repository_file(root, relative) {
        Ok(path) => path,
        Err(error) => {
            problems.push(format!("PC-01: {relative}: {error}"));
            return None;
        }
    };
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            problems.push(format!("PC-01: {relative}: {error}"));
            return None;
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(value) => Some(value),
        Err(error) => {
            problems.push(format!("PC-01: {relative}: {error}"));
            None
        }
    }
}

fn repository_file(root: &Path, relative: &str) -> Result<PathBuf, String> {
    if !safe_relative(relative) {
        return Err("unsafe relative path".to_owned());
    }
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("cannot resolve repository root: {error}"))?;
    let mut candidate = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(component) = component else {
            return Err("unsafe relative path".to_owned());
        };
        candidate.push(component);
        let metadata = fs::symlink_metadata(&candidate)
            .map_err(|error| format!("cannot inspect repository file: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("symlink repository inputs are not accepted".to_owned());
        }
    }
    let canonical = candidate
        .canonicalize()
        .map_err(|error| format!("cannot resolve repository file: {error}"))?;
    if !canonical.starts_with(&canonical_root) || !canonical.is_file() {
        return Err("repository input must be a regular file within the root".to_owned());
    }
    Ok(canonical)
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn rows<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn fail(problems: &mut Vec<String>, rule: &str, context: &str, detail: &str) {
    problems.push(format!("{rule}: {context}: {detail}"));
}

fn object_keys(
    value: &Value,
    required: &[&str],
    optional: &[&str],
    context: &str,
    problems: &mut Vec<String>,
) {
    let Some(object) = value.as_object() else {
        fail(problems, "PC-01", context, "expected an object");
        return;
    };
    for key in required {
        if !object.contains_key(*key) {
            fail(problems, "PC-01", context, &format!("missing {key}"));
        }
    }
    for key in object.keys() {
        if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            fail(problems, "PC-01", context, &format!("unknown field {key}"));
        }
    }
}

fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path).is_relative()
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn canonical_id(definition: &str, kind: &str, transport: &str, locator: &str) -> String {
    format!("{definition}:{kind}:{transport}:{locator}")
}

fn enterprise_only(locator: &str) -> bool {
    locator.starts_with("firestore.projects.databases.documents.executePipeline")
        || locator.starts_with("firestore.projects.databases.changeStreams.")
        || locator.starts_with("firestore.projects.databases.userCreds.")
        || locator.starts_with("schemas/ExecutePipeline")
        || locator.starts_with("schemas/Pipeline")
        || locator.starts_with("schemas/StructuredPipeline")
        || locator.starts_with("schemas/GoogleFirestoreAdminV1ChangeStream")
        || locator.starts_with("schemas/GoogleFirestoreAdminV1ListChangeStreams")
        || locator.starts_with("schemas/GoogleFirestoreAdminV1UserCreds")
        || locator.starts_with("schemas/GoogleFirestoreAdminV1ListUserCreds")
        || locator.starts_with("schemas/GoogleFirestoreAdminV1DisableUserCredsRequest")
        || locator.starts_with("schemas/GoogleFirestoreAdminV1EnableUserCredsRequest")
        || locator.starts_with("schemas/GoogleFirestoreAdminV1Search")
        || matches!(
            locator,
            "schemas/Value/properties/pipelineValue"
                | "schemas/GoogleFirestoreAdminV1Index/properties/searchIndexOptions"
                | "schemas/GoogleFirestoreAdminV1IndexField/properties/searchConfig"
                | "schemas/GoogleFirestoreAdminV1Database/properties/databaseEdition/enum/ENTERPRISE"
                | "schemas/GoogleFirestoreAdminV1Index/properties/apiScope/enum/MONGODB_COMPATIBLE_API"
        )
        || locator.starts_with(
            "schemas/GoogleFirestoreAdminV1Database/properties/mongodbCompatibleDataAccessMode",
        )
}

fn datastore_only(locator: &str) -> bool {
    matches!(
        locator,
        "schemas/GoogleFirestoreAdminV1Database/properties/type/enum/DATASTORE_MODE"
            | "schemas/GoogleFirestoreAdminV1Index/properties/apiScope/enum/DATASTORE_MODE_API"
    )
}

fn validate(root: &Path, denominator: &Value, problems: &mut Vec<String>) {
    validate_header(denominator, problems);

    let source_path = text(denominator, "sourceSnapshot");
    if source_path != SOURCE_PATH {
        fail(
            problems,
            "PC-01",
            "sourceSnapshot",
            "sourceSnapshot must match the immutable denominator version",
        );
        return;
    }
    if !safe_relative(source_path) {
        fail(problems, "PC-01", "sourceSnapshot", "unsafe relative path");
        return;
    }
    let source_sha256 = text(denominator, "sourceSnapshotSha256");
    if source_sha256.len() != 64
        || !source_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        fail(
            problems,
            "PC-01",
            "sourceSnapshotSha256",
            "source snapshot SHA-256 must be lowercase hexadecimal",
        );
    }
    let Some(source) = read_json(root, source_path, problems) else {
        return;
    };
    let source_definitions = definition_index(&source, "source snapshot", problems);
    for definition in rows(denominator, "definitions") {
        object_keys(
            definition,
            &["id", "revision", "sha256"],
            &[],
            "denominator definition",
            problems,
        );
    }
    let denominator_definitions = definition_index(denominator, "denominator", problems);
    if source_definitions.len() != denominator_definitions.len()
        || source_definitions.iter().any(|(id, source_definition)| {
            denominator_definitions.get(id).is_none_or(|definition| {
                text(source_definition, "revision") != text(definition, "revision")
                    || text(source_definition, "sha256") != text(definition, "sha256")
            })
        })
    {
        fail(
            problems,
            "PC-02",
            "definitions",
            "definition IDs, revisions and source hashes must match the pinned snapshot",
        );
    }

    let expected = expected_targets(&source, problems);
    let actual = validate_targets(root, denominator, problems);
    if expected != actual {
        let missing = expected.difference(&actual).count();
        let extra = actual.difference(&expected).count();
        fail(
            problems,
            "PC-03",
            "target set",
            &format!("must exactly equal pinned source surfaces; missing {missing}, extra {extra}"),
        );
    }
    validate_predecessor(root, denominator, &actual, problems);
}

fn validate_header(denominator: &Value, problems: &mut Vec<String>) {
    object_keys(
        denominator,
        &[
            "schemaVersion",
            "goal",
            "denominatorVersion",
            "sourceSnapshot",
            "sourceSnapshotSha256",
            "parentDenominator",
            "definitions",
            "targets",
        ],
        &[],
        "production denominator",
        problems,
    );
    if denominator.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
        fail(
            problems,
            "PC-01",
            "production denominator",
            "schemaVersion must be 1",
        );
    }
    if text(denominator, "goal") != GOAL {
        fail(problems, "PC-01", "production denominator", "wrong goal");
    }
    if text(denominator, "denominatorVersion") != VERSION {
        fail(
            problems,
            "PC-01",
            "production denominator",
            "denominatorVersion must match the immutable versioned filename",
        );
    }
    if !denominator
        .get("parentDenominator")
        .is_some_and(|value| value.is_null() || value.is_string())
    {
        fail(
            problems,
            "PC-01",
            "production denominator",
            "parentDenominator must be null or an immutable predecessor reference",
        );
    }
    if !denominator
        .get("parentDenominator")
        .is_some_and(Value::is_null)
    {
        fail(
            problems,
            "PC-06",
            "parentDenominator",
            "initial denominator must not name a predecessor",
        );
    }
}

fn validate_predecessor(
    root: &Path,
    denominator: &Value,
    current_targets: &BTreeSet<String>,
    problems: &mut Vec<String>,
) {
    let Some(reference) = denominator.get("parentDenominator").and_then(Value::as_str) else {
        return;
    };
    if reference == DENOMINATOR_PATH {
        fail(
            problems,
            "PC-06",
            reference,
            "denominator cannot name itself as predecessor",
        );
        return;
    }
    let Some(previous) = read_json(root, reference, problems) else {
        return;
    };
    if previous.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || text(&previous, "goal") != GOAL
        || text(&previous, "denominatorVersion").is_empty()
        || text(&previous, "denominatorVersion") == text(denominator, "denominatorVersion")
    {
        fail(
            problems,
            "PC-06",
            reference,
            "predecessor needs the same goal and a distinct nonempty version",
        );
    }
    let previous_targets: BTreeSet<_> = rows(&previous, "targets")
        .iter()
        .filter_map(|target| target.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    if previous_targets.len() != rows(&previous, "targets").len()
        || !previous_targets.is_subset(current_targets)
    {
        fail(
            problems,
            "PC-06",
            reference,
            "predecessor target set must be a unique subset of the current target set",
        );
    }
}

fn definition_index<'a>(
    value: &'a Value,
    context: &str,
    problems: &mut Vec<String>,
) -> BTreeMap<&'a str, &'a Value> {
    let mut result = BTreeMap::new();
    for definition in rows(value, "definitions") {
        let id = text(definition, "id");
        if id.is_empty() || result.insert(id, definition).is_some() {
            fail(
                problems,
                "PC-02",
                context,
                "duplicate or empty definition ID",
            );
        }
        if text(definition, "revision").is_empty()
            || text(definition, "sha256").len() != 64
            || !text(definition, "sha256")
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            fail(problems, "PC-02", id, "invalid source revision or SHA-256");
        }
    }
    result
}

fn expected_targets(source: &Value, problems: &mut Vec<String>) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for definition in rows(source, "definitions") {
        let definition_id = text(definition, "id");
        for surface in rows(definition, "surfaces") {
            let id = canonical_id(
                definition_id,
                text(surface, "kind"),
                text(surface, "transport"),
                text(surface, "locator"),
            );
            if !result.insert(id.clone()) {
                fail(problems, "PC-03", &id, "duplicate source surface");
            }
        }
    }
    result
}

fn validate_targets(
    root: &Path,
    denominator: &Value,
    problems: &mut Vec<String>,
) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for target in rows(denominator, "targets") {
        let id = text(target, "id");
        object_keys(
            target,
            &[
                "id",
                "definition",
                "locator",
                "kind",
                "transport",
                "featureGroup",
                "scope",
                "scopeReason",
                "evidenceState",
                "receiptRefs",
            ],
            &[],
            id,
            problems,
        );
        let expected_id = canonical_id(
            text(target, "definition"),
            text(target, "kind"),
            text(target, "transport"),
            text(target, "locator"),
        );
        if id != expected_id || !result.insert(expected_id) {
            fail(problems, "PC-03", id, "noncanonical or duplicate target ID");
        }
        validate_target_scope(target, id, problems);
        validate_target_evidence(root, target, id, problems);
    }
    result
}

fn validate_target_scope(target: &Value, id: &str, problems: &mut Vec<String>) {
    let scope = text(target, "scope");
    let feature = text(target, "featureGroup");
    if !SCOPES.contains(&scope) {
        fail(problems, "PC-04", id, "unknown scope");
    }
    if !FEATURE_GROUPS.contains(&feature) {
        fail(problems, "PC-04", id, "unknown featureGroup");
    }
    if text(target, "scopeReason").is_empty() {
        fail(problems, "PC-04", id, "scopeReason must be nonempty");
    }
    let recognized_enterprise =
        text(target, "definition") == "firestore-v1" && enterprise_only(text(target, "locator"));
    let recognized_datastore =
        text(target, "definition") == "firestore-v1" && datastore_only(text(target, "locator"));
    if (scope == "enterprise-only") != recognized_enterprise
        || (scope == "enterprise-only") != (feature == "FS-ENTERPRISE-EXCLUDED")
        || (scope == "outside-goal") != recognized_datastore
        || (scope == "outside-goal") != (feature == "FS-DATASTORE-EXCLUDED")
    {
        fail(
            problems,
            "PC-04",
            id,
            "Enterprise-only and Datastore-only surfaces must use their explicit scope and feature group together",
        );
    }
}

fn validate_target_evidence(root: &Path, target: &Value, id: &str, problems: &mut Vec<String>) {
    let state = text(target, "evidenceState");
    if !EVIDENCE_STATES.contains(&state) {
        fail(problems, "PC-05", id, "unknown evidenceState");
    }
    let Some(receipts) = target.get("receiptRefs").and_then(Value::as_array) else {
        fail(problems, "PC-05", id, "receiptRefs must be an array");
        return;
    };
    if state != "waiting-oracle" {
        fail(
            problems,
            "PC-05",
            id,
            "schema 1 cannot accept evidence promotion; a later receipt schema must verify source, artifact, configuration, case and comparator bindings",
        );
    }
    if !receipts.is_empty() {
        fail(
            problems,
            "PC-05",
            id,
            "schema 1 receiptRefs must remain empty until a bound receipt schema exists",
        );
    }
    for receipt in receipts {
        let Some(path) = receipt.as_str().filter(|path| safe_relative(path)) else {
            fail(
                problems,
                "PC-05",
                id,
                "receipt path must be safe and nonempty",
            );
            continue;
        };
        if let Err(error) = repository_file(root, path) {
            fail(
                problems,
                "PC-05",
                id,
                &format!("invalid receipt {path}: {error}"),
            );
        }
    }
}
