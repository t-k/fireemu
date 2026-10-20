//! Replays the FS-ENT-ORACLE pipeline corpus (every REST step of the O-1 and O-2 programs,
//! `conformance/fs-ent-pipeline-requests.json`) against the in-process REST surface under both
//! profiles and compares each answer with the production recording
//! (`conformance/fs-ent-pipeline-production.json`): the status, the result documents as a
//! multiset (order and framing are not compared) and the whole error body. Every difference is
//! named in the allowlist below with its reason, and each listed row must still differ, so the
//! list cannot hide a row that has started to match.

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
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
    ("fs-ent-pipeline/px1/select#and-false-null", "and is outside the subset"),
    ("fs-ent-pipeline/px1/select#and-false-x", "and is outside the subset"),
    ("fs-ent-pipeline/px1/select#and-null-true", "and is outside the subset"),
    ("fs-ent-pipeline/px1/select#and-true-i", "and is outside the subset"),
    ("fs-ent-pipeline/px1/select#and-true-x", "and is outside the subset"),
    ("fs-ent-pipeline/px1/select#array-contains-all-arr-empty", "array_contains* is outside the subset"),
    ("fs-ent-pipeline/px1/select#array-contains-all-arr-list", "array_contains* is outside the subset"),
    ("fs-ent-pipeline/px1/select#array-contains-all-x-list", "array_contains* is outside the subset"),
    ("fs-ent-pipeline/px1/select#array-contains-any-arr-empty", "array_contains* is outside the subset"),
    ("fs-ent-pipeline/px1/select#array-contains-any-arr-list", "array_contains* is outside the subset"),
    ("fs-ent-pipeline/px1/select#array-contains-any-i-list", "array_contains* is outside the subset"),
    ("fs-ent-pipeline/px1/select#array-contains-arr-1", "array_contains* is outside the subset"),
    ("fs-ent-pipeline/px1/select#array-contains-arr-1-0", "array_contains* is outside the subset"),
    ("fs-ent-pipeline/px1/select#array-contains-arr-null", "array_contains* is outside the subset"),
    ("fs-ent-pipeline/px1/select#array-contains-arr-x", "array_contains* is outside the subset"),
    ("fs-ent-pipeline/px1/select#array-contains-i-1", "array_contains* is outside the subset"),
    ("fs-ent-pipeline/px1/select#array-contains-x-1", "array_contains* is outside the subset"),
    ("fs-ent-pipeline/px1/select#equal-any-i-empty", "equal_any is outside the subset"),
    ("fs-ent-pipeline/px1/select#equal-any-i-field", "equal_any is outside the subset"),
    ("fs-ent-pipeline/px1/select#equal-any-i-list", "equal_any is outside the subset"),
    ("fs-ent-pipeline/px1/select#equal-any-i-s", "equal_any is outside the subset"),
    ("fs-ent-pipeline/px1/select#equal-any-n-null", "equal_any is outside the subset"),
    ("fs-ent-pipeline/px1/select#equal-any-nan-nan", "equal_any is outside the subset"),
    ("fs-ent-pipeline/px1/select#equal-any-x-list", "equal_any is outside the subset"),
    ("fs-ent-pipeline/px1/select#exists-i", "exists is outside the subset"),
    ("fs-ent-pipeline/px1/select#exists-n", "exists is outside the subset"),
    ("fs-ent-pipeline/px1/select#exists-x", "exists is outside the subset"),
    ("fs-ent-pipeline/px1/select#is-absent-n", "is_absent is outside the subset"),
    ("fs-ent-pipeline/px1/select#is-absent-x", "is_absent is outside the subset"),
    ("fs-ent-pipeline/px1/select#is-error-less-than-i-s", "is_error is outside the subset"),
    ("fs-ent-pipeline/px1/select#is-error-sqrt-s", "is_error is outside the subset"),
    ("fs-ent-pipeline/px1/select#is-error-x", "is_error is outside the subset"),
    ("fs-ent-pipeline/px1/select#is-type-d5-float64", "is_type is outside the subset"),
    ("fs-ent-pipeline/px1/select#is-type-i-bogus", "is_type is outside the subset"),
    ("fs-ent-pipeline/px1/select#is-type-i-int64", "is_type is outside the subset"),
    ("fs-ent-pipeline/px1/select#is-type-i-number", "is_type is outside the subset"),
    ("fs-ent-pipeline/px1/select#is-type-n-null", "is_type is outside the subset"),
    ("fs-ent-pipeline/px1/select#is-type-x-null", "is_type is outside the subset"),
    ("fs-ent-pipeline/px1/select#nor-false-false", "nor is outside the subset"),
    ("fs-ent-pipeline/px1/select#not-b", "not is outside the subset"),
    ("fs-ent-pipeline/px1/select#not-equal-any-i-list", "not_equal_any is outside the subset"),
    ("fs-ent-pipeline/px1/select#not-equal-any-n-list", "not_equal_any is outside the subset"),
    ("fs-ent-pipeline/px1/select#not-equal-any-x-list", "not_equal_any is outside the subset"),
    ("fs-ent-pipeline/px1/select#not-equal-x", "not is outside the subset"),
    ("fs-ent-pipeline/px1/select#not-i", "not is outside the subset"),
    ("fs-ent-pipeline/px1/select#not-n", "not is outside the subset"),
    ("fs-ent-pipeline/px1/select#not-x", "not is outside the subset"),
    ("fs-ent-pipeline/px1/select#or-false-i", "or is outside the subset"),
    ("fs-ent-pipeline/px1/select#or-false-x", "or is outside the subset"),
    ("fs-ent-pipeline/px1/select#or-null-true", "or is outside the subset"),
    ("fs-ent-pipeline/px1/select#or-true-x", "or is outside the subset"),
    ("fs-ent-pipeline/px1/select#type-arr", "type is outside the subset"),
    ("fs-ent-pipeline/px1/select#type-b", "type is outside the subset"),
    ("fs-ent-pipeline/px1/select#type-d5", "type is outside the subset"),
    ("fs-ent-pipeline/px1/select#type-i", "type is outside the subset"),
    ("fs-ent-pipeline/px1/select#type-m", "type is outside the subset"),
    ("fs-ent-pipeline/px1/select#type-n", "type is outside the subset"),
    ("fs-ent-pipeline/px1/select#type-nan", "type is outside the subset"),
    ("fs-ent-pipeline/px1/select#type-r", "type is outside the subset"),
    ("fs-ent-pipeline/px1/select#type-s", "type is outside the subset"),
    ("fs-ent-pipeline/px1/select#type-ts", "type is outside the subset"),
    ("fs-ent-pipeline/px1/select#type-x", "type is outside the subset"),
    ("fs-ent-pipeline/px1/select#xor-b-b", "xor is outside the subset"),
    ("fs-ent-pipeline/px1/select#xor-b-x", "xor is outside the subset"),
    ("fs-ent-pipeline/px1/select#xor-null-true", "xor is outside the subset"),
    ("fs-ent-pipeline/px1/static-refusals#select-and-1-true", "and is outside the subset"),
    ("fs-ent-pipeline/px1/static-refusals#select-array-contains-1-1", "array_contains* is outside the subset"),
    ("fs-ent-pipeline/px1/static-refusals#select-equal-any-1-1", "equal_any is outside the subset"),
    ("fs-ent-pipeline/px1/static-refusals#select-is-type-bogus", "is_type is outside the subset"),
    ("fs-ent-pipeline/px1/static-refusals#select-sqrt-a", "sqrt is outside the subset"),
    ("fs-ent-pipeline/px1/static-refusals#where-and-1-true", "and is outside the subset"),
    ("fs-ent-pipeline/px1/static-refusals#where-array-contains-1-1", "array_contains* is outside the subset"),
    ("fs-ent-pipeline/px1/static-refusals#where-equal-any-1-1", "equal_any is outside the subset"),
    ("fs-ent-pipeline/px1/static-refusals#where-is-type-bogus", "is_type is outside the subset"),
    ("fs-ent-pipeline/px1/static-refusals#where-sqrt-a", "sqrt is outside the subset"),
    ("fs-ent-pipeline/px1/where#is-error-less-than-i-s", "is_error is outside the subset"),
    ("fs-ent-pipeline/px1/where#not-equal-x", "not is outside the subset"),
    ("fs-ent-pipeline/px1/where#sqrt-s-positive", "sqrt is outside the subset"),
    ("fs-ent-pipeline/results/metadata#add-fields", "add_fields is outside the subset"),
    ("fs-ent-pipeline/results/metadata#distinct", "distinct is outside the subset"),
    ("fs-ent-pipeline/results/metadata#limit", "without a sort production returns another order than document names, so limit keeps other documents (PX2)"),
    ("fs-ent-pipeline/results/metadata#remove-fields", "remove_fields is outside the subset"),
];

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

/// A Firestore value or document in a comparable form.
fn normalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, inner) in map {
                let inner = match key.as_str() {
                    "doubleValue" => double(inner),
                    "referenceValue" | "name" => json!(relative(inner.as_str().unwrap())),
                    "timestampValue" => json!(timestamp(inner.as_str().unwrap())),
                    "createTime" | "updateTime" => json!("<t>"),
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

#[test]
#[allow(clippy::too_many_lines)]
fn the_pipeline_corpus_replays_as_production_answered() {
    let requests = read("fs-ent-pipeline-requests.json");
    let production = read("fs-ent-pipeline-production.json");
    for strict in [true, false] {
        let s = state(strict);
        let mut differing = Vec::new();
        let mut compared = 0;
        for program in requests["programs"].as_array().unwrap() {
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
            for step in program["steps"].as_array().unwrap() {
                let step_id = step["id"].as_str().unwrap();
                let row = format!("{id}#{step_id}");
                let rpc = step["rpc"].as_str().unwrap();
                let (status, body) =
                    call(&s, "POST", &format!("{DOCS}:{rpc}"), &fill(&step["body"]));
                let expected = &recorded[step_id];
                assert!(!expected.is_null(), "{row} has no production row");
                let matches = if rpc == "commit" {
                    u64::from(status) == expected["status"].as_u64().unwrap()
                } else {
                    answer(status, &body)
                        == answer(
                            u16::try_from(expected["status"].as_u64().unwrap()).unwrap(),
                            &expected["body"],
                        )
                };
                compared += 1;
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
        let unexpected: Vec<_> = differing.iter().filter(|(row, _, _)| !known(row)).collect();
        assert!(
            unexpected.is_empty(),
            "strict={strict}: rows that differ from production:\n{}",
            unexpected
                .iter()
                .map(|(row, got, want)| format!("{row}\n  fireemu:    {got}\n  production: {want}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        // Each allowlist entry still differs, and fireemu answers it as pinned: the result
        // order row with two of the three documents, every other row with UNIMPLEMENTED.
        for (known, reason) in KNOWN_DIFFERENCES {
            let Some((_, got, _)) = differing.iter().find(|(row, _, _)| row == known) else {
                panic!("strict={strict}: {known} ({reason}) matches production now; remove it");
            };
            if *known == "fs-ent-pipeline/results/metadata#limit" {
                assert_eq!(got["status"], 200, "{known}: {got}");
                assert_eq!(
                    got["results"].as_array().map(Vec::len),
                    Some(2),
                    "{known}: {got}"
                );
            } else {
                assert_eq!(got["status"], 501, "strict={strict} {known}: {got}");
                assert_eq!(
                    got["body"][0]["error"]["status"], "UNIMPLEMENTED",
                    "strict={strict} {known}: {got}"
                );
            }
        }
    }
}
