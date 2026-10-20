//! The differential corpus of the pipeline subset (coordinator ruling of 2026-10-20 for round 3 of the `PX1d` review):
//! fixed pipelines with the official emulator's answers (conformance/fs-ent-pipeline-differential.json,
//! recorded on loopback by conformance/src/fs-ent-pipeline/differential.mjs), run through the
//! in-process REST surface under both profiles.
//! - The emulator profile accepts and refuses each row as the official emulator does, except
//!   the rows of `EMULATOR_STATUS_DIFFERENCES`.
//! - Under strict every answer is UNIMPLEMENTED, or equals the official answer and the answer
//!   of the production row of conformance/fs-ent-pipeline-production.json it traces to
//!   (`TRACES`): the same status, and for a refusal the same text (the project, database and
//!   separator index aside). Where production and the official emulator differ, the row cannot
//!   be traced, so strict must refuse it.

use std::collections::BTreeMap;
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

/// Rows strict answers with a production text or result, the production row each traces to, and
/// how: `exact` (the row sends the recorded request, the collection aside), or
/// `composition:<kinds>` joined by `+`, each kind one of `COMPOSITION_KINDS`. A row that needs
/// any other step from a recorded request is an inference, which strict answers with
/// UNIMPLEMENTED until production answers it.
/// The composition kinds the reviews accepted (round 4 of the `PX1d` review, M1):
/// - `field-name`: another field or alias name of the same shape and runtime type;
/// - `value-of-recorded-kind`: another value of a kind production answered at that place (another
///   vector of doubles, another integer of the same sign, another empty array spelling);
/// - `constant-for-field`: a constant in place of a field of the recorded runtime type, or the
///   reverse;
/// - `function-name`: another function whose refused argument production answered with a text
///   that names no function;
/// - `passable-stage-before`: a valid `where`, `select`, `limit`, `offset` or `add_fields` stage before the
///   recorded one, or another valid value in such a stage, where a recorded row shows the check
///   running past that stage;
/// - `later-stage-added` / `later-stage-dropped`: a valid stage after the recorded one added or
///   removed;
/// - `unrun-argument`: another argument of a stage production refused for its argument count,
///   which production does not evaluate.
const COMPOSITION_KINDS: &[&str] = &[
    "field-name",
    "value-of-recorded-kind",
    "constant-for-field",
    "function-name",
    "passable-stage-before",
    "later-stage-added",
    "later-stage-dropped",
    "unrun-argument",
];

const TRACES: &[(&str, &str, &str)] = &[
    (
        "sweep-2026-12",
        "fs-ent-pipeline/o4/stages#add-fields-empty-map",
        "exact",
    ),
    (
        "sweep-2026-22",
        "fs-ent-pipeline/o4/stages#offset-string",
        "exact",
    ),
    (
        "sweep-2026-25",
        "fs-ent-pipeline/o4/stages#limit-negative",
        "exact",
    ),
    (
        "sweep-2026-150",
        "fs-ent-pipeline/o4/stages#limit-negative",
        "composition:passable-stage-before",
    ),
    (
        "sweep-2026-83",
        "fs-ent-pipeline/px0/aliases#reserved",
        "composition:field-name",
    ),
    (
        "sweep-2026-121",
        "fs-ent-pipeline/o4/stages#select-empty-map",
        "exact",
    ),
    (
        "sweep-2026-21",
        "fs-ent-pipeline/o3/comparisons#where-constant-string",
        "composition:constant-for-field+later-stage-dropped",
    ),
    (
        "sweep-2026-34",
        "fs-ent-pipeline/o4/conditions#where-integer",
        "composition:value-of-recorded-kind+later-stage-dropped",
    ),
    (
        "sweep-2026-73",
        "fs-ent-pipeline/o4/conditions#where-reference",
        "composition:value-of-recorded-kind+later-stage-dropped",
    ),
    (
        "sweep-2026-128",
        "fs-ent-pipeline/o3/literals#empty-array",
        "composition:value-of-recorded-kind",
    ),
    (
        "r3 Q2 select{v: document_id(parent(__name__))} alone",
        "fs-ent-pipeline/px1/select#document-id-parent-name",
        "exact",
    ),
    (
        "r3 Q3 select{v: document_id(parent(parent(__name__)))} then limit(\"x\")",
        "fs-ent-pipeline/o4/stages#limit-string",
        "composition:passable-stage-before",
    ),
    (
        "r3 Q4 select{v: map(\"k\", i, \"k\", n)} then limit(\"x\") (dup only with present fields)",
        "fs-ent-pipeline/o4/stages#limit-string",
        "composition:passable-stage-before",
    ),
    (
        "r3 Q6 select{v: map(\"k\", 1, \"k\", 2)} alone",
        "fs-ent-pipeline/o3/functions#map-repeated-key",
        "composition:constant-for-field",
    ),
    (
        "r3 Q7 select{v: document_id(i)} then limit(\"x\") (field arg)",
        "fs-ent-pipeline/o4/stages#limit-string",
        "composition:passable-stage-before",
    ),
    (
        "r3 Q8 select{v: equal(i, 1)} then limit(\"x\") (no failing call)",
        "fs-ent-pipeline/o4/stages#limit-string",
        "composition:passable-stage-before",
    ),
    (
        "r3 Q13 select{v: equal(vec[1.0], 1.5)} then limit(\"x\") (strict-unobserved compare)",
        "fs-ent-pipeline/o4/stages#limit-string",
        "composition:passable-stage-before",
    ),
    (
        "r3 Q20 select{v: collection_id(__name__)} then limit(\"x\")",
        "fs-ent-pipeline/o4/stages#limit-string",
        "composition:passable-stage-before",
    ),
    (
        "r3 T2 wide+deep array chains, leaf field i, then limit(\"x\")",
        "fs-ent-pipeline/o4/stages#limit-string",
        "composition:passable-stage-before",
    ),
    (
        "r3 V1 vec [1.0]",
        "fs-ent-pipeline/o4/literals#vector",
        "composition:value-of-recorded-kind",
    ),
    (
        "r3 S6 select{\"\": vec[1.0]}",
        "fs-ent-pipeline/o3/aliases#empty",
        "composition:value-of-recorded-kind",
    ),
    (
        "P28 document_id(ref c) literal index",
        "fs-ent-pipeline/o4/functions#collection-id-collection",
        "composition:function-name",
    ),
    (
        "P33 aggregate{c: count(n)} after where(true)",
        "fs-ent-pipeline/results/metadata#aggregate",
        "composition:passable-stage-before+unrun-argument",
    ),
    (
        "P35 alias quoted あ x500",
        "fs-ent-pipeline/o4/aliases#multibyte-1500",
        "composition:field-name",
    ),
    (
        "P36 alias `a`.あ x499 + a (1500 bytes joined?)",
        "fs-ent-pipeline/o4/aliases#multibyte-dotted-1499",
        "composition:field-name",
    ),
    (
        "N1 limit(\"x\") [recorded limit-string]",
        "fs-ent-pipeline/o4/stages#limit-string",
        "exact",
    ),
    (
        "N2 offset(\"x\") [recorded offset-string]",
        "fs-ent-pipeline/o4/stages#offset-string",
        "exact",
    ),
    (
        "N5 limit(-1) [recorded]",
        "fs-ent-pipeline/o4/stages#limit-negative",
        "exact",
    ),
    (
        "N13 select{} then limit(5)",
        "fs-ent-pipeline/o4/stages#select-empty-map",
        "composition:later-stage-added",
    ),
    (
        "N24 add_fields{a: top} then distinct{}",
        "fs-ent-pipeline/o4/stages#distinct-empty-map",
        "composition:passable-stage-before",
    ),
    (
        "N28 select{a: top} then add_fields{}",
        "fs-ent-pipeline/o4/stages#add-fields-empty-map",
        "composition:passable-stage-before",
    ),
    (
        "N31 where(true) then select{}",
        "fs-ent-pipeline/o4/stages#select-empty-map",
        "composition:passable-stage-before",
    ),
    (
        "N32 add_fields{a: top} then limit(-1)",
        "fs-ent-pipeline/o4/stages#limit-negative",
        "composition:passable-stage-before",
    ),
    (
        "N37 vector doubles",
        "fs-ent-pipeline/o4/literals#vector",
        "composition:value-of-recorded-kind",
    ),
    (
        "N40 vector 0.0 (the corpus JSON keeps no -0.0 sign)",
        "fs-ent-pipeline/o4/literals#vector",
        "composition:value-of-recorded-kind",
    ),
    (
        "N42 document_id(\"s\") [recorded STRING]",
        "fs-ent-pipeline/o3/functions#document-id-string",
        "composition:constant-for-field",
    ),
    (
        "N43 document_id(1) [recorded LONG]",
        "fs-ent-pipeline/o4/functions#document-id-integer",
        "composition:constant-for-field",
    ),
    (
        "N44 parent(true) [recorded BOOLEAN]",
        "fs-ent-pipeline/o4/functions#parent-boolean",
        "composition:constant-for-field",
    ),
    (
        "N45 collection_id({}) [recorded MAP]",
        "fs-ent-pipeline/o4/functions#collection-id-map",
        "composition:constant-for-field",
    ),
    (
        "N48 document_id(field i) (runtime LONG)",
        "fs-ent-pipeline/o4/functions#document-id-integer",
        "exact",
    ),
    (
        "N49 document_id(field top) (runtime STRING)",
        "fs-ent-pipeline/o3/functions#document-id-string",
        "composition:field-name",
    ),
    (
        "N51 map(field dbl, i) (runtime DOUBLE key)",
        "fs-ent-pipeline/o4/functions#map-key-string-field",
        "composition:field-name",
    ),
    (
        "N52 map(1, i) [recorded LONG key]",
        "fs-ent-pipeline/o3/functions#map-integer-key",
        "exact",
    ),
    (
        "N53 map(true, i) [recorded BOOLEAN key]",
        "fs-ent-pipeline/o4/functions#map-key-boolean",
        "exact",
    ),
    (
        "N57 {\"\": 1} single empty key [recorded]",
        "fs-ent-pipeline/o4/literals#key-empty",
        "exact",
    ),
    (
        "N59 where(vector doubles) [recorded where-vector]",
        "fs-ent-pipeline/o4/conditions#where-vector",
        "composition:value-of-recorded-kind+later-stage-dropped",
    ),
    (
        "N63 add_fields{a: top} then select{} [recorded add-fields-then-select-empty]",
        "fs-ent-pipeline/o4/stages#add-fields-then-select-empty",
        "exact",
    ),
    (
        "N64 select{} then add_fields{\"\": top} [recorded]",
        "fs-ent-pipeline/o4/stages#select-empty-then-add-fields-empty-alias",
        "exact",
    ),
    (
        "N65 aggregate{\"\": count(n)} by {} [recorded]",
        "fs-ent-pipeline/o4/stages#aggregate-empty-accumulator-alias",
        "exact",
    ),
    (
        "N66 aggregate{\"\": count()} by {}",
        "fs-ent-pipeline/o4/stages#aggregate-empty-accumulator-alias",
        "composition:unrun-argument",
    ),
    (
        "N70 aggregate one-arg {c: sum(n)} [arity]",
        "fs-ent-pipeline/o4/stages#aggregate-one-field",
        "composition:unrun-argument",
    ),
    (
        "N71 add_fields{a: top} then aggregate one-arg {c: nope_fn()}",
        "fs-ent-pipeline/o4/stages#aggregate-one-unknown-function",
        "composition:passable-stage-before",
    ),
    (
        "N77 add_fields{a: document_id(i)} then select{} (runtime type)",
        "fs-ent-pipeline/o4/stages#add-fields-then-select-empty",
        "composition:passable-stage-before",
    ),
    (
        "select {\"\": i} alone",
        "fs-ent-pipeline/o3/aliases#empty",
        "composition:field-name",
    ),
    (
        "select {} then limit(\"x\")",
        "fs-ent-pipeline/o4/stages#select-empty-then-limit-string",
        "exact",
    ),
    (
        "limit 1 then a one-argument aggregate",
        "fs-ent-pipeline/o4/stages#aggregate-one-after-limit",
        "composition:unrun-argument",
    ),
    (
        "select {v: [i]} alone",
        "fs-ent-pipeline/o4/literals#array-of-two-fields",
        "composition:value-of-recorded-kind",
    ),
    (
        "add_fields {t: top} then limit(\"x\")",
        "fs-ent-pipeline/o4/stages#limit-string",
        "composition:passable-stage-before",
    ),
    (
        "vector of doubles",
        "fs-ent-pipeline/o4/literals#vector",
        "exact",
    ),
    (
        "map holding a vector of doubles",
        "fs-ent-pipeline/o4/literals#map-holding-vector",
        "composition:value-of-recorded-kind",
    ),
    (
        "{__x__: 1}",
        "fs-ent-pipeline/o4/literals#key-reserved",
        "exact",
    ),
    (
        "select {v: [document_id(__name__)]}",
        "fs-ent-pipeline/o4/literals#array-of-function",
        "exact",
    ),
    (
        "add_fields {a: map(\"k\", 1)} then select {}",
        "fs-ent-pipeline/o4/stages#add-fields-then-select-empty",
        "composition:passable-stage-before",
    ),
    (
        "add_fields {t: document_id(__name__)} then select {}",
        "fs-ent-pipeline/o4/stages#add-fields-then-select-empty",
        "composition:passable-stage-before",
    ),
    (
        "a one-argument aggregate of an unknown function",
        "fs-ent-pipeline/o4/stages#aggregate-one-unknown-function",
        "exact",
    ),
    (
        "map(\"k\", i, \"k\", i)",
        "fs-ent-pipeline/o3/functions#map-repeated-key",
        "composition:field-name",
    ),
    (
        "map(i, i)",
        "fs-ent-pipeline/o4/functions#map-key-string-field",
        "composition:field-name",
    ),
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

fn call(state: &RestState, method: &str, path: &str, body: &Value) -> (u16, Value) {
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

/// Whether a strict answer is the production row's: the same status, and for a refusal the same
/// text once the recorded project and database and the separator index are put aside.
fn same_as_production(got: &Value, production: &Value) -> bool {
    let text = |message: &str| {
        let message = message.replace(
            "projects/demo-fs-query-index/databases/entpipe1",
            "projects/demo-app/databases/(default)",
        );
        match message.find(" at index ") {
            Some(at) => message[..at].to_owned(),
            None => message,
        }
    };
    let status = production["status"].as_u64().unwrap_or_default();
    if got["status"] != status {
        return false;
    }
    if status == 200 {
        return true;
    }
    let element = production["body"]
        .as_array()
        .and_then(|a| a.first())
        .unwrap_or(&production["body"]);
    match (
        got["message"].as_str(),
        element["error"]["message"].as_str(),
    ) {
        (Some(a), Some(b)) => text(a) == text(b),
        _ => false,
    }
}

/// A pipeline's stages without their options and with the collection stage's argument put aside
/// (the corpus and the recorded programs read different collections).
fn comparable_stages(stages: &Value) -> Value {
    let mut stages = stages.clone();
    for stage in stages.as_array_mut().into_iter().flatten() {
        let stage = stage.as_object_mut().unwrap();
        stage.remove("options");
        if stage["name"] == "collection" {
            stage.insert("args".to_owned(), json!([]));
        }
    }
    stages
}

fn official(row: &Value) -> Value {
    let o = &row["official"];
    if o["status"] == 200 {
        json!({"status": 200, "results": answer(200, &json!([{"results": o["results"]}]))["results"]})
    } else {
        json!({"status": o["status"], "message": o["message"]})
    }
}

/// Each trace names a recorded production row and a corpus row, and its tag holds: an `exact`
/// row sends the recorded request, and a composition names only accepted kinds.
fn check_traces(rows: &[Value], recorded: &BTreeMap<String, Value>) {
    let requests: BTreeMap<String, Value> = read("fs-ent-pipeline-requests.json")["programs"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|p| {
            let program = p["id"].as_str().unwrap().to_owned();
            p["steps"].as_array().unwrap().iter().map(move |step| {
                (
                    format!("{program}#{}", step["id"].as_str().unwrap()),
                    step["body"]["structuredPipeline"]["pipeline"]["stages"].clone(),
                )
            })
        })
        .collect();
    for (row, trace, how) in TRACES {
        assert!(
            recorded.contains_key(*trace),
            "{row}: no production row {trace}"
        );
        let Some(corpus_row) = rows.iter().find(|r| r["id"] == *row) else {
            panic!("{row}: not in the corpus");
        };
        if *how == "exact" {
            assert_eq!(
                comparable_stages(&corpus_row["stages"]),
                comparable_stages(&requests[*trace]),
                "{row}: tagged exact but sends another request than {trace}"
            );
        } else {
            let kinds = how
                .strip_prefix("composition:")
                .unwrap_or_else(|| panic!("{row}: {how} is neither exact nor a composition"));
            for kind in kinds.split('+') {
                assert!(
                    COMPOSITION_KINDS.contains(&kind),
                    "{row}: {kind} is not an accepted composition kind"
                );
            }
            assert_ne!(
                comparable_stages(&corpus_row["stages"]),
                comparable_stages(&requests[*trace]),
                "{row}: sends {trace}'s request; tag it exact"
            );
        }
    }
}

#[test]
fn the_differential_corpus_holds_both_profiles_to_their_rules() {
    let corpus = read("fs-ent-pipeline-differential.json");
    let rows = corpus["rows"].as_array().unwrap();
    assert!(rows.len() > 400, "{}", rows.len());
    let production = read("fs-ent-pipeline-production.json");
    let recorded: BTreeMap<String, Value> = production["programs"]
        .as_object()
        .unwrap()
        .iter()
        .flat_map(|(program, p)| {
            p["steps"]
                .as_object()
                .unwrap()
                .iter()
                .map(move |(step, row)| (format!("{program}#{step}"), row.clone()))
        })
        .collect();
    check_traces(rows, &recorded);
    for (row, _) in EMULATOR_STATUS_DIFFERENCES {
        assert!(
            rows.iter().any(|r| r["id"] == *row),
            "{row}: not in the corpus"
        );
    }
    let traces: BTreeMap<&str, &str> = TRACES
        .iter()
        .map(|(row, trace, _)| (*row, *trace))
        .collect();
    let known: BTreeMap<&str, &str> = EMULATOR_STATUS_DIFFERENCES.iter().copied().collect();
    let mut wrong = Vec::new();
    for strict in [true, false] {
        let s = state(strict);
        let (status, body) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/c/d"),
            &json!({"fields": corpus["seed"]["fields"]}),
        );
        assert_eq!(status, 200, "{body}");
        for row in rows {
            let id = row["id"].as_str().unwrap();
            let request = json!({"structuredPipeline": {"pipeline": {"stages": row["stages"]}}});
            let (status, body) = call(&s, "POST", &format!("{DOCS}:executePipeline"), &request);
            let got = answer(status, &body);
            let want = official(row);
            if strict {
                if status == 501 {
                    if traces.contains_key(id) {
                        wrong.push(format!(
                            "strict {id}: traced but UNIMPLEMENTED; remove the trace"
                        ));
                    }
                } else if !traces.contains_key(id) {
                    wrong.push(format!(
                        "strict {id}: {got} has no production trace (official {want})"
                    ));
                } else if got != want {
                    wrong.push(format!(
                        "strict {id}: {got} differs from the official {want}"
                    ));
                } else if !same_as_production(&got, &recorded[traces[id]]) {
                    wrong.push(format!(
                        "strict {id}: {got} differs from production {} ({})",
                        recorded[traces[id]], traces[id]
                    ));
                }
            } else {
                let differs = (status == 200) != (want["status"] == 200);
                if differs != known.contains_key(id) {
                    wrong.push(format!("emulator {id}: {got} / official {want}"));
                }
            }
        }
    }
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
