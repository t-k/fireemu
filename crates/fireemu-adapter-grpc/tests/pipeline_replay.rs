//! Replays the FS-ENT-ORACLE pipeline corpus (every REST step of the O-1, O-2 and O-3 programs,
//! `conformance/fs-ent-pipeline-requests.json`) against the in-process REST surface under both
//! profiles and compares each answer with the production recording
//! (`conformance/fs-ent-pipeline-production.json`): the status, the result documents as a
//! multiset (order and framing are not compared) and the whole error body. Every difference is
//! named in the allowlist below with its reason, and each listed row must still differ, so the
//! list cannot hide a row that has started to match.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::json_syntax::KeyOrder;
use fireemu_adapter_grpc::rest::{RestRequest, RestState};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const DOCS: &str = "projects/demo-app/databases/(default)/documents";

/// Rows that differ from production, with the reason, the same under both profiles: functions and
/// stages outside the finite local subset (PX1b-d and later slices), which fireemu refuses with
/// UNIMPLEMENTED where production answers, and the result order without a sort.
const KNOWN_DIFFERENCES: &[(&str, &str)] = &[
    (
        "fs-ent-pipeline/px1/select#and-false-null",
        "and is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#and-false-x",
        "and is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#and-null-true",
        "and is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#and-true-i",
        "and is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#and-true-x",
        "and is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#array-contains-all-arr-empty",
        "array_contains* is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#array-contains-all-arr-list",
        "array_contains* is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#array-contains-all-x-list",
        "array_contains* is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#array-contains-any-arr-empty",
        "array_contains* is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#array-contains-any-arr-list",
        "array_contains* is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#array-contains-any-i-list",
        "array_contains* is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#array-contains-arr-1",
        "array_contains* is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#array-contains-arr-1-0",
        "array_contains* is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#array-contains-arr-null",
        "array_contains* is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#array-contains-arr-x",
        "array_contains* is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#array-contains-i-1",
        "array_contains* is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#array-contains-x-1",
        "array_contains* is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#equal-any-i-empty",
        "equal_any is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#equal-any-i-field",
        "equal_any is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#equal-any-i-list",
        "equal_any is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#equal-any-i-s",
        "equal_any is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#equal-any-n-null",
        "equal_any is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#equal-any-nan-nan",
        "equal_any is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#equal-any-x-list",
        "equal_any is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#exists-i",
        "exists is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#exists-n",
        "exists is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#exists-x",
        "exists is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#is-absent-n",
        "is_absent is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#is-absent-x",
        "is_absent is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#is-error-less-than-i-s",
        "is_error is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#is-error-sqrt-s",
        "is_error is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#is-error-x",
        "is_error is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#is-type-d5-float64",
        "is_type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#is-type-i-bogus",
        "is_type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#is-type-i-int64",
        "is_type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#is-type-i-number",
        "is_type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#is-type-n-null",
        "is_type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#is-type-x-null",
        "is_type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#nor-false-false",
        "nor is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#not-b",
        "not is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#not-equal-any-i-list",
        "not_equal_any is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#not-equal-any-n-list",
        "not_equal_any is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#not-equal-any-x-list",
        "not_equal_any is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#not-equal-x",
        "not is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#not-i",
        "not is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#not-n",
        "not is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#not-x",
        "not is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#or-false-i",
        "or is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#or-false-x",
        "or is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#or-null-true",
        "or is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#or-true-x",
        "or is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#type-arr",
        "type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#type-b",
        "type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#type-d5",
        "type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#type-i",
        "type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#type-m",
        "type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#type-n",
        "type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#type-nan",
        "type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#type-r",
        "type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#type-s",
        "type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#type-ts",
        "type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#type-x",
        "type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#xor-b-b",
        "xor is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#xor-b-x",
        "xor is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/select#xor-null-true",
        "xor is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/static-refusals#select-and-1-true",
        "and is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/static-refusals#select-array-contains-1-1",
        "array_contains* is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/static-refusals#select-equal-any-1-1",
        "equal_any is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/static-refusals#select-is-type-bogus",
        "is_type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/static-refusals#select-sqrt-a",
        "sqrt is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/static-refusals#where-and-1-true",
        "and is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/static-refusals#where-array-contains-1-1",
        "array_contains* is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/static-refusals#where-equal-any-1-1",
        "equal_any is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/static-refusals#where-is-type-bogus",
        "is_type is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/static-refusals#where-sqrt-a",
        "sqrt is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/where#is-error-less-than-i-s",
        "is_error is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/where#not-equal-x",
        "not is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/where#sqrt-s-positive",
        "sqrt is outside the subset",
    ),
    (
        "fs-ent-pipeline/results/metadata#add-fields",
        "add_fields is outside the subset",
    ),
    (
        "fs-ent-pipeline/results/metadata#distinct",
        "distinct is outside the subset",
    ),
    (
        "fs-ent-pipeline/results/metadata#limit",
        "without a sort production returns another order than document names, so limit keeps other documents (PX2)",
    ),
    (
        "fs-ent-pipeline/results/metadata#remove-fields",
        "remove_fields is outside the subset",
    ),
    (
        "fs-ent-pipeline/o4/stages#select-empty-then-unknown-function",
        "fireemu cannot tell a function that does not exist from one it does not run: strict refuses it as unobserved, the emulator profile answers the empty select's text first",
    ),
];

/// A fixture with the key order of its objects as written.
fn read_ordered(name: &str) -> (Value, KeyOrder) {
    let path = format!("{}/../../conformance/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    fireemu_adapter_grpc::rest::json_syntax::parse_with_key_order(&text).unwrap()
}

fn read(name: &str) -> Value {
    let path = format!("{}/../../conformance/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}")))
        .unwrap()
}

fn state(strict: bool) -> RestState {
    let gateway = Gateway {
        enforce_limits: strict,
        ctx: PlanningContext {
            edition: FirestoreEdition::Enterprise,
            api_mode: FirestoreApiMode::Native,
            policy: if strict {
                IndexValidationPolicy::Production
            } else {
                IndexValidationPolicy::Emulator
            },
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    RestState {
        local: Arc::new(LocalBackend::new(gateway.clone(), clock, 7)),
        gateway: Arc::new(gateway),
        rules: None,
        app_check: None,
        control_token: None,
    }
}

fn call(s: &RestState, method: &str, path: &str, body: &Value) -> (u16, Value) {
    call_ordered(s, method, path, body, &KeyOrder::default())
}

/// A request whose body keeps the key order it was written in.
fn call_ordered(
    s: &RestState,
    method: &str,
    path: &str,
    body: &Value,
    key_order: &KeyOrder,
) -> (u16, Value) {
    let r = s.handle(&RestRequest {
        method: method.to_owned(),
        path: format!("/v1/{path}"),
        query: String::new(),
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        remote_peer: false,
        browser_metadata: false,
        app_check: Vec::new(),
        body: body.clone(),
        batch_field_order: Vec::new(),
        key_order: key_order.clone(),
    });
    (r.status, r.body)
}

/// `{docs}` placeholders filled with this surface's documents path.
fn fill(value: &Value) -> Value {
    serde_json::from_str(&value.to_string().replace("{docs}", DOCS)).unwrap()
}

/// A documents path of any project and database written as `{docs}`.
fn relative(name: &str) -> String {
    match name.find("/documents") {
        Some(at) if name.starts_with("projects/") => format!("{{docs}}{}", &name[at + 10..]),
        _ => name.to_owned(),
    }
}

/// A timestamp without trailing zero fractions.
fn timestamp(text: &str) -> String {
    match text.strip_suffix('Z').and_then(|t| t.split_once('.')) {
        Some((whole, fraction)) => {
            let fraction = fraction.trim_end_matches('0');
            if fraction.is_empty() {
                format!("{whole}Z")
            } else {
                format!("{whole}.{fraction}Z")
            }
        }
        None => text.to_owned(),
    }
}

/// A double as its bits (the sign of zero kept, every NaN one value).
fn double(value: &Value) -> Value {
    let d = match value {
        Value::String(text) => match text.as_str() {
            "NaN" => f64::NAN,
            "Infinity" => f64::INFINITY,
            "-Infinity" => f64::NEG_INFINITY,
            other => other.parse().unwrap(),
        },
        other => other.as_f64().unwrap(),
    };
    json!(if d.is_nan() {
        "NaN".to_owned()
    } else {
        format!("{:#x}", d.to_bits())
    })
}

/// An error message in a comparable form. A missing-separator refusal names the document parent
/// and the index where the separator is missing, which is that name's length: the recorded
/// name carries the placeholder project ID while production counted the real one, so the
/// name is written relative to its documents root and the index is left out (fireemu's index
/// is pinned against its own name in the local tests).
fn message(text: &str) -> String {
    let parent = text
        .strip_prefix("Document parent name \"")
        .and_then(|rest| rest.split_once("\" lacks \"/\" at index "))
        .filter(|(_, index)| {
            index
                .strip_suffix('.')
                .is_some_and(|n| n.parse::<usize>().is_ok())
        });
    match parent {
        Some((name, _)) => format!(
            "Document parent name \"{}\" lacks \"/\" at index <n>.",
            relative(name)
        ),
        None => text.to_owned(),
    }
}

/// A Firestore value or document in a comparable form.
fn normalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, inner) in map {
                let inner = match key.as_str() {
                    "doubleValue" | "latitude" | "longitude" => double(inner),
                    "referenceValue" | "name" => json!(relative(inner.as_str().unwrap())),
                    "timestampValue" => json!(timestamp(inner.as_str().unwrap())),
                    "createTime" | "updateTime" => json!("<t>"),
                    "message" if inner.is_string() => json!(message(inner.as_str().unwrap())),
                    _ => normalize(inner),
                };
                out.insert(key.clone(), inner);
            }
            // An empty map or array may leave its member out.
            if let Some(Value::Object(fields)) = out.get("mapValue") {
                if fields.is_empty() {
                    out.insert("mapValue".to_owned(), json!({"fields": {}}));
                }
            }
            if let Some(Value::Object(values)) = out.get("arrayValue") {
                if values.is_empty() {
                    out.insert("arrayValue".to_owned(), json!({"values": []}));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(normalize).collect()),
        other => other.clone(),
    }
}

/// The comparable answer of an executePipeline step: the status, and the result documents as
/// a sorted list or the error body.
fn answer(status: u16, body: &Value) -> Value {
    if status != 200 {
        return json!({"status": status, "body": normalize(body)});
    }
    let mut results: Vec<String> = body
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|element| element["results"].as_array().cloned().unwrap_or_default())
        .map(|result| normalize(&result).to_string())
        .collect();
    results.sort();
    json!({"status": 200, "results": results})
}

// Exact measured compatibility debt, not a production-parity approval.
struct O5Difference {
    row: String,
    category: String,
    reason: String,
    production: Value,
    strict: Value,
    emulator: Option<Value>,
}

fn take_debt_string(object: &mut serde_json::Map<String, Value>, key: &str) -> String {
    match object.remove(key) {
        Some(Value::String(value)) => value,
        _ => panic!("required O5 debt string: {key}"),
    }
}

fn parse_o5_differences(text: &str) -> Vec<O5Difference> {
    let (value, order) =
        fireemu_adapter_grpc::rest::json_syntax::parse_with_key_order(text.as_bytes())
            .expect("O5 debt JSON parses");
    value
        .as_array()
        .expect("O5 debt array root")
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let mut object = row.as_object().expect("O5 debt object entry").clone();
            let pointer = format!("/{index}");
            let keys = order.keys(&pointer).expect("O5 debt wire keys");
            assert_eq!(
                keys.len(),
                object.len(),
                "duplicate O5 debt member: {index}"
            );
            assert_eq!(
                keys.iter().collect::<HashSet<_>>().len(),
                keys.len(),
                "duplicate O5 debt wire key: {index}"
            );
            assert!(
                keys.iter().all(|key| object.contains_key(key)),
                "O5 debt key mismatch: {index}"
            );
            let row = take_debt_string(&mut object, "row");
            let category = take_debt_string(&mut object, "category");
            let reason = take_debt_string(&mut object, "reason");
            let production = object
                .remove("production")
                .expect("required production answer");
            let strict = object.remove("strict").expect("required strict answer");
            let emulator = object.remove("emulator").filter(|value| !value.is_null());
            assert!(object.is_empty(), "unknown O5 debt member: {row}");
            O5Difference {
                row,
                category,
                reason,
                production,
                strict,
                emulator,
            }
        })
        .collect()
}

#[test]
fn o5_debt_schema_rejects_missing_unknown_duplicate_and_wrong_types() {
    let valid = json!([{"row":"x","category":"x","reason":"x","production":{},"strict":{}}]);
    assert!(parse_o5_differences(&valid.to_string())[0]
        .emulator
        .is_none());
    let mut with_null = valid.clone();
    with_null[0]["emulator"] = Value::Null;
    assert!(parse_o5_differences(&with_null.to_string())[0]
        .emulator
        .is_none());
    let mut with_answer = valid.clone();
    with_answer[0]["emulator"] = json!({"status":400});
    assert_eq!(
        parse_o5_differences(&with_answer.to_string())[0].emulator,
        Some(json!({"status":400}))
    );
    let mut invalid = vec![json!({}).to_string(), json!([0]).to_string()];
    for key in ["row", "category", "reason", "production", "strict"] {
        let mut missing = valid.clone();
        missing[0].as_object_mut().unwrap().remove(key);
        invalid.push(missing.to_string());
    }
    for key in ["row", "category", "reason"] {
        let mut wrong = valid.clone();
        wrong[0][key] = json!(42);
        invalid.push(wrong.to_string());
    }
    let mut unknown = valid;
    unknown[0]["other"] = Value::Null;
    invalid.push(unknown.to_string());
    invalid.push(
        r#"[{"row":"x","row":"y","category":"x","reason":"x","production":{},"strict":{}}]"#
            .to_owned(),
    );
    for text in invalid {
        assert!(
            std::panic::catch_unwind(|| parse_o5_differences(&text)).is_err(),
            "invalid schema accepted: {text}"
        );
    }
}

fn o5_differences() -> BTreeMap<String, O5Difference> {
    let rows = parse_o5_differences(include_str!("pipeline_o5_known_differences.json"));
    assert_eq!(rows.len(), 272, "finite O5 debt inventory");
    assert_eq!(
        rows.iter().filter(|row| row.emulator.is_some()).count(),
        199,
        "finite emulator debt inventory"
    );
    assert_eq!(KNOWN_DIFFERENCES.len(), 83, "original debt inventory");
    let mut table = BTreeMap::new();
    let mut unknown = 0;
    for row in rows {
        assert!(
            row.row.starts_with("fs-ent-pipeline/o5/"),
            "foreign debt: {}",
            row.row
        );
        assert!(
            !KNOWN_DIFFERENCES.iter().any(|(known, _)| *known == row.row),
            "old debt replaced: {}",
            row.row
        );
        assert!(!row.reason.trim().is_empty(), "missing reason: {}", row.row);
        assert!(
            matches!(
                row.category.as_str(),
                "unsupported-subset"
                    | "validation-order-or-subset"
                    | "arity-wording"
                    | "environment-reference-comparison"
                    | "missing-error-info"
                    | "self-name-projection-gap"
                    | "unsupported-current-document"
                    | "unknown-production-outcome"
            ),
            "unknown category: {}",
            row.row
        );
        assert_eq!(row.strict["status"], 501, "strict debt: {}", row.row);
        assert_eq!(
            row.strict["body"][0]["error"]["status"], "UNIMPLEMENTED",
            "strict debt: {}",
            row.row
        );
        if row.production["status"] == 500 {
            unknown += 1;
            assert_eq!(
                row.row,
                "fs-ent-pipeline/o5/appendix#proposed-select-duplicate-quoted-path"
            );
            assert_eq!(row.category, "unknown-production-outcome");
            assert_eq!(row.production["body"][0]["error"]["status"], "INTERNAL");
        }
        assert!(
            table.insert(row.row.clone(), row).is_none(),
            "duplicate O5 debt row"
        );
    }
    assert_eq!(
        unknown, 1,
        "one merged unknown production row, not two raw captures"
    );
    table
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_pipeline_corpus_replays_as_production_answered() {
    let (requests, order) = read_ordered("fs-ent-pipeline-requests.json");
    let production = read("fs-ent-pipeline-production.json");
    // A stopped run's private fixture (`fixture.partial.json`) is never replayed as production:
    // it holds programs finished by one recording, without the second recording's rows.
    assert!(production.get("partial").is_none(), "a partial fixture");
    assert!(
        production["programs"]
            .as_object()
            .is_some_and(|programs| programs.values().all(|p| p.get("recordings").is_none())),
        "a partial fixture"
    );
    let debts = o5_differences();
    let mut failures = Vec::new();
    for strict in [true, false] {
        let s = state(strict);
        let mut differing = Vec::new();
        let mut compared = 0;
        let mut seen = HashSet::new();
        for (p, program) in requests["programs"].as_array().unwrap().iter().enumerate() {
            let id = program["id"].as_str().unwrap();
            for seed in program["seed"].as_array().unwrap() {
                let (status, body) = call(
                    &s,
                    "PATCH",
                    &format!("{DOCS}/{}", seed[0].as_str().unwrap()),
                    &json!({"fields": fill(&seed[1])}),
                );
                assert_eq!(status, 200, "{id} seed: {body}");
            }
            let recorded = &production["programs"][id]["steps"];
            for (n, step) in program["steps"].as_array().unwrap().iter().enumerate() {
                let step_id = step["id"].as_str().unwrap();
                let row = format!("{id}#{step_id}");
                let rpc = step["rpc"].as_str().unwrap();
                let (status, body) = if rpc == "get" {
                    let parent = step["parent"].as_str().unwrap();
                    call(&s, "GET", &format!("{DOCS}/{parent}"), &Value::Null)
                } else {
                    call_ordered(
                        &s,
                        "POST",
                        &format!("{DOCS}:{rpc}"),
                        &fill(&step["body"]),
                        &order.rebased(&format!("/programs/{p}/steps/{n}/body"), ""),
                    )
                };
                let expected = &recorded[step_id];
                assert!(!expected.is_null(), "{row} has no production row");
                let matches = if rpc == "commit" {
                    u64::from(status) == expected["status"].as_u64().unwrap()
                } else if rpc == "get" {
                    // A document read: the status and the normalized document.
                    json!({"status": status, "body": normalize(&body)})
                        == json!({"status": expected["status"], "body": normalize(&expected["body"])})
                } else {
                    answer(status, &body)
                        == answer(
                            u16::try_from(expected["status"].as_u64().unwrap()).unwrap(),
                            &expected["body"],
                        )
                };
                compared += 1;
                seen.insert(row.clone());
                let got = answer(status, &body);
                let want = answer(
                    u16::try_from(expected["status"].as_u64().unwrap()).unwrap(),
                    &expected["body"],
                );
                if let Some(debt) = debts.get(&row) {
                    if debt.production != want {
                        failures.push(format!(
                            "strict={strict} {row}: production binding changed: {want}"
                        ));
                    }
                    let pinned = if strict {
                        Some(&debt.strict)
                    } else {
                        debt.emulator.as_ref()
                    };
                    if let Some(pinned) = pinned {
                        if got != *pinned {
                            failures.push(format!(
                                "strict={strict} {row}: pinned local debt answer changed: {got}"
                            ));
                        }
                        if matches || got == want {
                            failures.push(format!(
                                "strict={strict} {row}: stale debt now matches production"
                            ));
                        }
                    } else if !matches {
                        failures.push(format!(
                            "strict={strict} {row}: unlisted profile differs: {got}"
                        ));
                    }
                }
                if !matches {
                    differing.push((
                        row,
                        answer(status, &body),
                        answer(
                            u16::try_from(expected["status"].as_u64().unwrap_or(0)).unwrap(),
                            &expected["body"],
                        ),
                    ));
                }
            }
        }
        assert!(compared > 200, "{compared}");
        let known = |row: &str| KNOWN_DIFFERENCES.iter().any(|(known, _)| row == *known);
        let unexpected: Vec<_> = differing
            .iter()
            .filter(|(row, _, _)| {
                !known(row)
                    && !debts
                        .get(row)
                        .is_some_and(|debt| strict || debt.emulator.is_some())
            })
            .collect();
        for row in debts.keys().filter(|row| !seen.contains(*row)) {
            failures.push(format!(
                "strict={strict}: debt row absent from corpus: {row}"
            ));
        }
        let mut stale = Vec::new();
        let mut changed_known = Vec::new();
        for (known, reason) in KNOWN_DIFFERENCES {
            let Some((_, got, _)) = differing.iter().find(|(row, _, _)| row == known) else {
                stale.push(json!({"row": known, "reason": reason}));
                continue;
            };
            let pinned = if *known == "fs-ent-pipeline/results/metadata#limit" {
                got["status"] == 200 && got["results"].as_array().map(Vec::len) == Some(2)
            } else if *known == "fs-ent-pipeline/o4/stages#select-empty-then-unknown-function"
                && !strict
            {
                got["status"] == 400
                    && got["body"][0]["error"]["message"]
                        == "The 'select(...)' stage requires at least one field."
            } else {
                got["status"] == 501 && got["body"][0]["error"]["status"] == "UNIMPLEMENTED"
            };
            if !pinned {
                changed_known.push(json!({"row": known, "reason": reason, "local": got}));
            }
        }
        if !unexpected.is_empty() || !stale.is_empty() || !changed_known.is_empty() {
            failures.push(format!(
                "strict={strict}: unexpected={}, stale={}, changedKnown={}",
                unexpected.len(),
                stale.len(),
                changed_known.len()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
