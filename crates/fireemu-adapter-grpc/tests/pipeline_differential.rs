//! The differential corpus of the pipeline subset (coordinator ruling of 2026-10-20 for round 3 of the `PX1d` review):
//! fixed pipelines with the official emulator's answers (conformance/fs-ent-pipeline-differential.json,
//! recorded on loopback by conformance/src/fs-ent-pipeline/differential.mjs), run through the
//! in-process REST surface under both profiles, each body with the key order it was recorded in.
//! - The emulator profile accepts and refuses each row as the official emulator does, except
//!   the rows of `EMULATOR_STATUS_DIFFERENCES`.
//! - Under strict every answer is UNIMPLEMENTED, a result the official emulator gave, or a
//!   refusal whose request has the shape of a request production refused with the same text
//!   (the project, database and separator index aside; coordinator ruling of 2026-10-21, the
//!   shape-match rule). The table of recorded shapes is built here from the committed fixtures.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::pipeline_shape;
use fireemu_adapter_grpc::rest::json_syntax::{self, KeyOrder};
use fireemu_adapter_grpc::rest::{RestRequest, RestState};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const DOCS: &str = "projects/demo-app/databases/(default)/documents";

/// Rows the emulator profile accepts or refuses unlike the official emulator, with why.
const EMULATOR_STATUS_DIFFERENCES: &[(&str, &str)] = &[
    (
        "sweep-20261021-822",
        "select of __name__ as itself: the official emulator returns the document name, fireemu refuses the alias (results without the name are not supported)",
    ),
    (
        "sweep-42-2470",
        "select of __name__ as itself: the official emulator returns the document name, fireemu refuses the alias (results without the name are not supported)",
    ),
    (
        "r3 O12 aggregate{c: count(n) opts} by {}",
        "aggregate is a stage fireemu does not run; the local subset refuses it with UNIMPLEMENTED",
    ),
    (
        "N17 aggregate{c: count(n)} by {g: top}",
        "aggregate is a stage fireemu does not run; the local subset refuses it with UNIMPLEMENTED",
    ),
    (
        "o5/function-names#fn-current_document",
        "current_document is a function fireemu does not run; the local subset refuses it with UNIMPLEMENTED",
    ),
];

/// A fixture with the key order of its objects as written.
fn read_ordered(name: &str) -> (Value, KeyOrder) {
    let path = format!("{}/../../conformance/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    json_syntax::parse_with_key_order(&text).unwrap()
}

/// The shapes of the requests production refused, with their normalized texts.
fn recorded_refusals() -> BTreeMap<String, Vec<String>> {
    let (requests, order) = read_ordered("fs-ent-pipeline-requests.json");
    let production = read("fs-ent-pipeline-production.json");
    let mut table: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (p, program) in requests["programs"].as_array().unwrap().iter().enumerate() {
        let id = program["id"].as_str().unwrap();
        for (n, step) in program["steps"].as_array().unwrap().iter().enumerate() {
            let answer = &production["programs"][id]["steps"][step["id"].as_str().unwrap()];
            if step["rpc"] != "executePipeline" || answer["status"] != 400 {
                continue;
            }
            let element = answer["body"].as_array().map_or(&answer["body"], |a| &a[0]);
            let shape = pipeline_shape::shape_of_json(
                &step["body"],
                &order.rebased(&format!("/programs/{p}/steps/{n}/body"), ""),
            )
            .unwrap_or_else(|| panic!("{id} {}: no shape", step["id"]));
            table
                .entry(shape)
                .or_default()
                .push(pipeline_shape::normalized_text(
                    element["error"]["message"].as_str().unwrap(),
                ));
        }
    }
    table
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

fn call(state: &RestState, method: &str, path: &str, body: &Value) -> (u16, Value) {
    call_ordered(state, method, path, body, &KeyOrder::default())
}

/// A request whose body keeps the key order it was written in.
fn call_ordered(
    state: &RestState,
    method: &str,
    path: &str,
    body: &Value,
    key_order: &KeyOrder,
) -> (u16, Value) {
    let response = state.handle(&RestRequest {
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
    (response.status, response.body)
}

/// A comparable answer: the status and the error message, or the results without their name and
/// times (an empty map or array, and a whole double, written either way).
fn answer(status: u16, body: &Value) -> Value {
    fn strip(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (key, inner) in map {
                    if matches!(key.as_str(), "name" | "createTime" | "updateTime") {
                        continue;
                    }
                    // A double written as `1` (the recorder's JSON) or `1.0`.
                    if key == "doubleValue" && inner.is_number() {
                        out.insert(key.clone(), json!(inner.as_f64()));
                        continue;
                    }
                    out.insert(key.clone(), strip(inner));
                }
                for (member, empty) in [
                    ("mapValue", json!({"fields": {}})),
                    ("arrayValue", json!({"values": []})),
                ] {
                    if out
                        .get(member)
                        .is_some_and(|v| v.as_object().is_some_and(serde_json::Map::is_empty))
                    {
                        out.insert(member.to_owned(), empty);
                    }
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(items.iter().map(strip).collect()),
            other => other.clone(),
        }
    }
    if status != 200 {
        let element = body.as_array().and_then(|a| a.first()).unwrap_or(body);
        return json!({"status": status, "message": element["error"]["message"]});
    }
    let results: Vec<Value> = body
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|e| e["results"].as_array().cloned().unwrap_or_default())
        .collect();
    json!({"status": 200, "results": strip(&Value::Array(results))})
}

fn official(row: &Value) -> Value {
    let o = &row["official"];
    if o["status"] == 200 {
        json!({"status": 200, "results": answer(200, &json!([{"results": o["results"]}]))["results"]})
    } else {
        json!({"status": o["status"], "message": o["message"]})
    }
}

#[test]
fn the_differential_corpus_holds_both_profiles_to_their_rules() {
    let (corpus, order) = read_ordered("fs-ent-pipeline-differential.json");
    let rows = corpus["rows"].as_array().unwrap();
    assert!(rows.len() > 400, "{}", rows.len());
    let recorded = recorded_refusals();
    for (row, _) in EMULATOR_STATUS_DIFFERENCES {
        assert!(
            rows.iter().any(|r| r["id"] == *row),
            "{row}: not in the corpus"
        );
    }
    let known: BTreeMap<&str, &str> = EMULATOR_STATUS_DIFFERENCES.iter().copied().collect();
    let mut wrong = Vec::new();
    let mut strict_refusals = 0;
    for strict in [true, false] {
        let s = state(strict);
        let (status, body) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/c/d"),
            &json!({"fields": corpus["seed"]["fields"]}),
        );
        assert_eq!(status, 200, "{body}");
        for (at, row) in rows.iter().enumerate() {
            let id = row["id"].as_str().unwrap();
            let request = json!({"structuredPipeline": {"pipeline": {"stages": row["stages"]}}});
            let request_order = order.rebased(
                &format!("/rows/{at}/stages"),
                "/structuredPipeline/pipeline/stages",
            );
            let (status, body) = call_ordered(
                &s,
                "POST",
                &format!("{DOCS}:executePipeline"),
                &request,
                &request_order,
            );
            let got = answer(status, &body);
            let want = official(row);
            if strict {
                match status {
                    501 => {}
                    200 if got == want => {}
                    400 => {
                        strict_refusals += 1;
                        let shape = pipeline_shape::shape_of_json(&request, &request_order);
                        let text =
                            pipeline_shape::normalized_text(got["message"].as_str().unwrap());
                        let traced = shape
                            .as_ref()
                            .and_then(|shape| recorded.get(shape))
                            .is_some_and(|texts| texts.contains(&text));
                        if !traced {
                            wrong.push(format!(
                                "strict {id}: {got} is no production refusal of this shape (official {want})"
                            ));
                        }
                    }
                    _ => wrong.push(format!("strict {id}: {got} / official {want}")),
                }
            } else {
                let differs = (status == 200) != (want["status"] == 200);
                if differs != known.contains_key(id) {
                    wrong.push(format!("emulator {id}: {got} / official {want}"));
                }
            }
        }
    }
    // The corpus holds recorded shapes, so strict answers some refusals.
    assert!(strict_refusals >= 10, "{strict_refusals}");
    assert!(
        wrong.is_empty(),
        "{} rows:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Repeated requests get one answer (`PX1d` round 4, M4): the review's rows `H1`-`H9` each hold two
/// parts that fail on their own, where an answer that followed the decoded map's iteration
/// order would change from request to request. Strict answers each with UNIMPLEMENTED, and the
/// emulator profile answers each as the official emulator did or with UNIMPLEMENTED, every time.
#[test]
fn repeated_requests_get_one_answer_under_both_profiles() {
    let corpus = read("fs-ent-pipeline-differential.json");
    let rows: Vec<&Value> = corpus["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["id"].as_str().unwrap().starts_with("r4 H"))
        .collect();
    assert_eq!(rows.len(), 9);
    for strict in [true, false] {
        let s = state(strict);
        let (status, body) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/c/d"),
            &json!({"fields": corpus["seed"]["fields"]}),
        );
        assert_eq!(status, 200, "{body}");
        for row in &rows {
            let id = row["id"].as_str().unwrap();
            let request = json!({"structuredPipeline": {"pipeline": {"stages": row["stages"]}}});
            let answers: Vec<Value> = (0..25)
                .map(|_| {
                    let (status, body) =
                        call(&s, "POST", &format!("{DOCS}:executePipeline"), &request);
                    answer(status, &body)
                })
                .collect();
            assert!(
                answers.iter().all(|a| *a == answers[0]),
                "strict={strict} {id}: {answers:?}"
            );
            if strict {
                assert_eq!(answers[0]["status"], 501, "{id}: {}", answers[0]);
            } else if answers[0]["status"] != 501 {
                // (An unknown function is UNIMPLEMENTED under the emulator profile.)
                assert_eq!(answers[0], official(row), "{id}");
            }
        }
    }
}

/// The review's round-5 and round-6 rows (`r6 `, `r6 review ` and `r7 ` ids, the round-6
/// review's `m3-*` and `g777-*/EG` rows among them) answer the official emulator's
/// text under the emulator profile: a literal `map(...)` key's type before any row (on an empty
/// collection too) and before a repeated key, a negative count after an empty map, a literal
/// holding a field before a `map(...)` key that is no literal or a reserved alias, a failing
/// constant reference without rows, the reference and collection-name texts.
#[test]
fn the_round_five_rows_answer_the_official_texts_under_the_emulator_profile() {
    let (corpus, order) = read_ordered("fs-ent-pipeline-differential.json");
    let s = state(false);
    let (status, body) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/c/d"),
        &json!({"fields": corpus["seed"]["fields"]}),
    );
    assert_eq!(status, 200, "{body}");
    let mut checked = 0;
    for (at, row) in corpus["rows"].as_array().unwrap().iter().enumerate() {
        let id = row["id"].as_str().unwrap();
        if !id.starts_with("r6 ") && !id.starts_with("r7 ") {
            continue;
        }
        let request = json!({"structuredPipeline": {"pipeline": {"stages": row["stages"]}}});
        let (status, body) = call_ordered(
            &s,
            "POST",
            &format!("{DOCS}:executePipeline"),
            &request,
            &order.rebased(
                &format!("/rows/{at}/stages"),
                "/structuredPipeline/pipeline/stages",
            ),
        );
        assert_eq!(answer(status, &body), official(row), "{}", row["id"]);
        checked += 1;
    }
    assert_eq!(checked, 43);
}
