//! Under the strict profile, `executePipeline` answers only texts a production recording holds
//! (FS-ENT-ORACLE O-1 to O-4) and refuses the rest as UNIMPLEMENTED; the emulator profile keeps
//! the official emulator's answers. Each case names the shape and both answers.
#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

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
const EMPTY_SELECT: &str = "The 'select(...)' stage requires at least one field.";
const AGGREGATE_ARITY: &str = "Stage 'aggregate(accumulators: Map[FieldPath, Expr], groups: Map[FieldPath, Expr])' takes [2..2] argument(s), received 1.";

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

fn field(name: &str) -> Value {
    json!({ "fieldReferenceValue": name })
}
fn func(name: &str, args: Vec<Value>) -> Value {
    json!({ "functionValue": { "name": name, "args": args } })
}
fn stage(name: &str, args: Vec<Value>) -> Value {
    json!({ "name": name, "args": args })
}
fn map(entries: Vec<(&str, Value)>) -> Value {
    let fields: serde_json::Map<String, Value> = entries
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
    json!({ "mapValue": { "fields": fields } })
}
fn select(value: Value) -> Value {
    stage("select", vec![map(vec![("v", value)])])
}
fn int(n: i64) -> Value {
    json!({ "integerValue": n.to_string() })
}
fn string(s: &str) -> Value {
    json!({ "stringValue": s })
}
fn vector(elements: Vec<Value>) -> Value {
    map(vec![
        ("__type__", string("__vector__")),
        ("value", json!({ "arrayValue": { "values": elements } })),
    ])
}

/// What a pipeline over the one-document collection `c` answers: the status and, for an error,
/// its message.
fn answer(state: &RestState, stages: &[Value]) -> (u16, String) {
    let mut all = vec![stage("collection", vec![json!({ "referenceValue": "/c" })])];
    all.extend(stages.iter().cloned());
    let body = json!({ "structuredPipeline": { "pipeline": { "stages": all } } });
    let (status, body) = call(state, "POST", &format!("{DOCS}:executePipeline"), &body);
    let text = if status == 200 {
        String::new()
    } else {
        body[0]["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    };
    (status, text)
}

fn seeded(strict: bool) -> RestState {
    let state = state(strict);
    let (status, body) = call(
        &state,
        "PATCH",
        &format!("{DOCS}/c/d"),
        &json!({ "fields": { "i": int(1), "n": int(1), "top": string("t") } }),
    );
    assert_eq!(status, 200, "{body}");
    state
}

/// One shape: its stages, the strict answer (`None` is UNIMPLEMENTED) and the emulator answer.
struct Case {
    label: &'static str,
    stages: Vec<Value>,
    strict: Option<(u16, &'static str)>,
    emulator: (u16, &'static str),
}

fn check(cases: Vec<Case>) {
    let (strict, emulator) = (seeded(true), seeded(false));
    let mut wrong = Vec::new();
    for case in cases {
        let got = answer(&strict, &case.stages);
        let ok = match case.strict {
            None => got.0 == 501,
            Some((status, text)) => got == (status, text.to_owned()),
        };
        if !ok {
            wrong.push(format!(
                "strict {}: got {got:?}, want {:?}",
                case.label, case.strict
            ));
        }
        let got = answer(&emulator, &case.stages);
        if got != (case.emulator.0, case.emulator.1.to_owned()) {
            wrong.push(format!(
                "emulator {}: got {got:?}, want {:?}",
                case.label, case.emulator
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn strict_lets_no_deferred_or_later_check_answer_past_an_unvalidated_part() {
    let empty = || stage("select", vec![map(vec![])]);
    let add_unknown = || {
        stage(
            "add_fields",
            vec![map(vec![("a", func("nope_fn", vec![]))])],
        )
    };
    check(vec![
        // Production recorded the unknown function before the empty select (O-4); fireemu
        // cannot tell it from a function it does not run, so strict refuses it.
        Case {
            label: "select {} then where(nope_fn(n))",
            stages: vec![
                empty(),
                stage("where", vec![func("nope_fn", vec![field("n")])]),
            ],
            strict: None,
            emulator: (400, EMPTY_SELECT),
        },
        Case {
            label: "select {} then where(sqrt(\"a\"))",
            stages: vec![
                empty(),
                stage("where", vec![func("sqrt", vec![string("a")])]),
            ],
            strict: None,
            emulator: (400, EMPTY_SELECT),
        },
        Case {
            label: "add_fields {a: nope_fn()} then select {}",
            stages: vec![add_unknown(), empty()],
            strict: None,
            emulator: (400, EMPTY_SELECT),
        },
        Case {
            label: "add_fields {a: nope_fn()} then limit(\"x\")",
            stages: vec![add_unknown(), stage("limit", vec![string("x")])],
            strict: None,
            emulator: (
                400,
                "Expected limit to be INTEGER_VALUE, but was STRING_VALUE.",
            ),
        },
        Case {
            label: "add_fields {a: nope_fn()} then a one-argument aggregate",
            stages: vec![
                add_unknown(),
                stage(
                    "aggregate",
                    vec![map(vec![("c", func("count", vec![field("n")]))])],
                ),
            ],
            strict: None,
            emulator: (400, AGGREGATE_ARITY),
        },
        Case {
            label: "sort then limit(\"x\")",
            stages: vec![
                stage("sort", vec![func("ascending", vec![field("i")])]),
                stage("limit", vec![string("x")]),
            ],
            strict: None,
            emulator: (
                400,
                "Expected limit to be INTEGER_VALUE, but was STRING_VALUE.",
            ),
        },
        Case {
            label: "add_fields {t: top} then where(nope_fn()) then select {}",
            stages: vec![
                stage("add_fields", vec![map(vec![("t", field("top"))])]),
                stage("where", vec![func("nope_fn", vec![])]),
                empty(),
            ],
            strict: None,
            emulator: (400, EMPTY_SELECT),
        },
        Case {
            label: "add_fields {t: [field]} then select {}",
            stages: vec![
                stage(
                    "add_fields",
                    vec![map(vec![(
                        "t",
                        json!({ "arrayValue": { "values": [field("i")] } }),
                    )])],
                ),
                empty(),
            ],
            strict: None,
            emulator: (400, EMPTY_SELECT),
        },
        Case {
            label: "aggregate {c: sum(n)} by {} then select {}",
            stages: vec![
                stage(
                    "aggregate",
                    vec![map(vec![("c", func("sum", vec![field("n")]))]), map(vec![])],
                ),
                empty(),
            ],
            strict: None,
            emulator: (400, EMPTY_SELECT),
        },
        // Recorded orders stay answered under strict (O-4 `o4/stages#*`).
        Case {
            label: "select {} then limit(\"x\")",
            stages: vec![empty(), stage("limit", vec![string("x")])],
            strict: Some((
                400,
                "Expected limit to be INTEGER_VALUE, but was STRING_VALUE.",
            )),
            emulator: (
                400,
                "Expected limit to be INTEGER_VALUE, but was STRING_VALUE.",
            ),
        },
        Case {
            label: "add_fields {t: top} then select {}",
            stages: vec![
                stage("add_fields", vec![map(vec![("t", field("top"))])]),
                empty(),
            ],
            strict: Some((400, EMPTY_SELECT)),
            emulator: (400, EMPTY_SELECT),
        },
        Case {
            label: "add_fields {t: document_id(__name__)} then select {}",
            stages: vec![
                stage(
                    "add_fields",
                    vec![map(vec![(
                        "t",
                        func("document_id", vec![field("__name__")]),
                    )])],
                ),
                empty(),
            ],
            strict: Some((400, EMPTY_SELECT)),
            emulator: (400, EMPTY_SELECT),
        },
        Case {
            label: "select {} then add_fields {\"\": top}",
            stages: vec![
                empty(),
                stage("add_fields", vec![map(vec![("", field("top"))])]),
            ],
            strict: Some((400, "Invalid empty property path string.")),
            emulator: (400, "Invalid empty property path string."),
        },
        Case {
            label: "aggregate {c: count(n)} by {} then select {}",
            stages: vec![
                stage(
                    "aggregate",
                    vec![
                        map(vec![("c", func("count", vec![field("n")]))]),
                        map(vec![]),
                    ],
                ),
                empty(),
            ],
            strict: Some((400, EMPTY_SELECT)),
            emulator: (400, EMPTY_SELECT),
        },
        Case {
            label: "aggregate {\"\": count()} by {}",
            stages: vec![stage(
                "aggregate",
                vec![map(vec![("", func("count", vec![]))]), map(vec![])],
            )],
            strict: Some((400, "Invalid empty property path string.")),
            emulator: (400, "Invalid empty property path string."),
        },
        Case {
            label: "add_fields {a: nope_fn()} only",
            stages: vec![add_unknown()],
            strict: None,
            emulator: (501, "pipeline stage \"add_fields\" is unsupported locally"),
        },
        Case {
            label: "a one-argument aggregate of an unknown function",
            stages: vec![stage(
                "aggregate",
                vec![map(vec![("c", func("nope_fn", vec![]))])],
            )],
            strict: Some((400, AGGREGATE_ARITY)),
            emulator: (400, AGGREGATE_ARITY),
        },
    ]);
}

#[test]
fn strict_answers_only_the_argument_types_production_recorded() {
    let doc_id = |arg: Value| select(func("document_id", vec![arg]));
    let wrong = |function: &str, got: &str| -> String {
        format!("The function {function}(...) requires `Reference` but got `{got}`.")
    };
    let mut cases = Vec::new();
    // Recorded: STRING (O-3), LONG, MAP and BOOLEAN (O-4).
    for (label, arg, got) in [
        ("document_id(\"s\")", string("s"), "STRING"),
        ("document_id(1)", int(1), "LONG"),
        ("document_id({a: 1})", map(vec![("a", int(1))]), "MAP"),
        (
            "document_id(true)",
            json!({ "booleanValue": true }),
            "BOOLEAN",
        ),
    ] {
        let text: &'static str = Box::leak(wrong("document_id", got).into_boxed_str());
        cases.push(Case {
            label,
            stages: vec![doc_id(arg)],
            strict: Some((400, text)),
            emulator: (400, text),
        });
    }
    // Unrecorded: every other type.
    for (label, arg, got) in [
        ("document_id(1.5)", json!({ "doubleValue": 1.5 }), "DOUBLE"),
        (
            "document_id(geo)",
            json!({ "geoPointValue": { "latitude": 1, "longitude": 1 } }),
            "GEO_POINT",
        ),
        (
            "document_id(ts)",
            json!({ "timestampValue": "2020-01-01T00:00:00Z" }),
            "TIMESTAMP",
        ),
        (
            "document_id(bytes)",
            json!({ "bytesValue": "AA==" }),
            "BYTES",
        ),
        (
            "document_id([1])",
            json!({ "arrayValue": { "values": [int(1)] } }),
            "ARRAY",
        ),
        (
            "document_id(vector)",
            vector(vec![json!({ "doubleValue": 1.0 })]),
            "VECTOR",
        ),
    ] {
        let text: &'static str = Box::leak(wrong("document_id", got).into_boxed_str());
        cases.push(Case {
            label,
            stages: vec![doc_id(arg)],
            strict: None,
            emulator: (400, text),
        });
    }
    cases.push(Case {
        label: "parent(1.5)",
        stages: vec![select(func("parent", vec![json!({ "doubleValue": 1.5 })]))],
        strict: None,
        emulator: (
            400,
            "The function parent(...) requires `Reference` but got `DOUBLE`.",
        ),
    });
    // map() keys: LONG and BOOLEAN recorded (O-3, O-4).
    for (label, key, strict) in [
        ("map(1, i)", int(1), Some("LONG")),
        (
            "map(true, i)",
            json!({ "booleanValue": true }),
            Some("BOOLEAN"),
        ),
        ("map(1.5, i)", json!({ "doubleValue": 1.5 }), None),
        ("map(null, i)", json!({ "nullValue": null }), None),
        (
            "map(ts, i)",
            json!({ "timestampValue": "2020-01-01T00:00:00Z" }),
            None,
        ),
    ] {
        let given = match &key {
            k if k.get("integerValue").is_some() => "LONG",
            k if k.get("booleanValue").is_some() => "BOOLEAN",
            k if k.get("doubleValue").is_some() => "DOUBLE",
            k if k.get("nullValue").is_some() => "NULL",
            _ => "TIMESTAMP",
        };
        let text: &'static str = Box::leak(
            format!("map key must be of type STRING, given type is {given}").into_boxed_str(),
        );
        cases.push(Case {
            label,
            stages: vec![select(func("map", vec![key, field("i")]))],
            strict: strict.map(|_| (400, text)),
            emulator: (400, text),
        });
    }
    check(cases);
}

#[test]
fn strict_answers_only_the_limit_and_offset_arguments_production_recorded() {
    let limit = |arg: Value| vec![stage("limit", vec![arg])];
    let offset = |arg: Value| vec![stage("offset", vec![arg])];
    check(vec![
        Case {
            label: "limit(\"x\")",
            stages: limit(string("x")),
            strict: Some((
                400,
                "Expected limit to be INTEGER_VALUE, but was STRING_VALUE.",
            )),
            emulator: (
                400,
                "Expected limit to be INTEGER_VALUE, but was STRING_VALUE.",
            ),
        },
        Case {
            label: "offset(\"x\")",
            stages: offset(string("x")),
            strict: Some((
                400,
                "Expected offset to be INTEGER_VALUE, but was STRING_VALUE.",
            )),
            emulator: (
                400,
                "Expected offset to be INTEGER_VALUE, but was STRING_VALUE.",
            ),
        },
        Case {
            label: "limit(-1)",
            stages: limit(int(-1)),
            strict: Some((400, "The 'limit(...)' cannot have a negative value: -1")),
            emulator: (400, "The 'limit(...)' cannot have a negative value: -1"),
        },
        Case {
            label: "offset(-1)",
            stages: offset(int(-1)),
            strict: None,
            emulator: (400, "The 'offset(...)' cannot have a negative value: -1"),
        },
        Case {
            label: "limit(true)",
            stages: limit(json!({ "booleanValue": true })),
            strict: None,
            emulator: (
                400,
                "Expected limit to be INTEGER_VALUE, but was BOOLEAN_VALUE.",
            ),
        },
        Case {
            label: "limit(1.5)",
            stages: limit(json!({ "doubleValue": 1.5 })),
            strict: None,
            emulator: (
                400,
                "Expected limit to be INTEGER_VALUE, but was DOUBLE_VALUE.",
            ),
        },
        Case {
            label: "limit(null)",
            stages: limit(json!({ "nullValue": null })),
            strict: None,
            emulator: (
                400,
                "Expected limit to be INTEGER_VALUE, but was NULL_VALUE.",
            ),
        },
        Case {
            label: "limit({})",
            stages: limit(map(vec![])),
            strict: None,
            emulator: (
                400,
                "Expected limit to be INTEGER_VALUE, but was MAP_VALUE.",
            ),
        },
        Case {
            label: "offset(true)",
            stages: offset(json!({ "booleanValue": true })),
            strict: None,
            emulator: (
                400,
                "Expected offset to be INTEGER_VALUE, but was BOOLEAN_VALUE.",
            ),
        },
        // After an unrun stage, the same rule (O-4 `o4/stages#select-empty-then-limit-string`).
        Case {
            label: "add_fields {t: top} then limit(true)",
            stages: vec![
                stage("add_fields", vec![map(vec![("t", field("top"))])]),
                stage("limit", vec![json!({ "booleanValue": true })]),
            ],
            strict: None,
            emulator: (
                400,
                "Expected limit to be INTEGER_VALUE, but was BOOLEAN_VALUE.",
            ),
        },
        Case {
            label: "add_fields {t: top} then limit(\"x\")",
            stages: vec![
                stage("add_fields", vec![map(vec![("t", field("top"))])]),
                stage("limit", vec![string("x")]),
            ],
            strict: Some((
                400,
                "Expected limit to be INTEGER_VALUE, but was STRING_VALUE.",
            )),
            emulator: (
                400,
                "Expected limit to be INTEGER_VALUE, but was STRING_VALUE.",
            ),
        },
    ]);
}

#[test]
fn strict_answers_only_the_vector_and_key_shapes_production_recorded() {
    let double = |d: f64| json!({ "doubleValue": d });
    // The official emulator 1.22.0's vector checks, in its order: a missing value, a value that
    // is no array, another key, no element, an element that is no double, NaN
    // (docs.local probe px1e-official-1/2).
    let missing = "Vector map is missing key 'value'.";
    let not_array = "Vector value type must be an array.";
    let extraneous = "Vector value map has extraneous entries.";
    let doubles = "Vector must only contain values of type 'double'";
    check(vec![
        Case {
            label: "vector of doubles",
            stages: vec![select(vector(vec![double(1.0), double(2.0)]))],
            strict: Some((200, "")),
            emulator: (200, ""),
        },
        Case {
            label: "map holding a vector of doubles",
            stages: vec![select(map(vec![("a", vector(vec![double(1.0)]))]))],
            strict: Some((200, "")),
            emulator: (200, ""),
        },
        Case {
            label: "vector of integers",
            stages: vec![select(vector(vec![int(1)]))],
            strict: None,
            emulator: (400, doubles),
        },
        Case {
            label: "vector of a double and an integer",
            stages: vec![select(vector(vec![double(1.0), int(2)]))],
            strict: None,
            emulator: (400, doubles),
        },
        Case {
            label: "vector without value",
            stages: vec![select(map(vec![("__type__", string("__vector__"))]))],
            strict: None,
            emulator: (400, missing),
        },
        Case {
            label: "vector with an extra key",
            stages: vec![select(map(vec![
                ("__type__", string("__vector__")),
                (
                    "value",
                    json!({ "arrayValue": { "values": [double(1.0)] } }),
                ),
                ("x", int(1)),
            ]))],
            strict: None,
            emulator: (400, extraneous),
        },
        Case {
            label: "vector whose value is no array",
            stages: vec![select(map(vec![
                ("__type__", string("__vector__")),
                ("value", string("x")),
            ]))],
            strict: None,
            emulator: (400, not_array),
        },
        Case {
            label: "array holding a vector of integers",
            stages: vec![select(
                json!({ "arrayValue": { "values": [vector(vec![int(1)])] } }),
            )],
            strict: None,
            emulator: (400, doubles),
        },
        Case {
            label: "where on a vector of integers",
            stages: vec![stage("where", vec![vector(vec![int(1)])])],
            strict: None,
            emulator: (400, doubles),
        },
        Case {
            label: "where on a vector of doubles",
            stages: vec![stage("where", vec![vector(vec![double(1.0)])])],
            strict: Some((200, "")),
            emulator: (200, ""),
        },
        Case {
            label: "empty vector",
            stages: vec![select(vector(vec![]))],
            strict: None,
            emulator: (400, "Cannot have a zero length vector."),
        },
        Case {
            label: "vector of NaN",
            stages: vec![select(vector(vec![json!({ "doubleValue": "NaN" })]))],
            strict: None,
            emulator: (400, "Vectors cannot contain NaN values."),
        },
        Case {
            label: "vector without value and with another key",
            stages: vec![select(map(vec![
                ("__type__", string("__vector__")),
                ("x", int(1)),
            ]))],
            strict: None,
            emulator: (400, missing),
        },
        Case {
            label: "vector of integers with another key",
            stages: vec![select(map(vec![
                ("__type__", string("__vector__")),
                ("value", json!({ "arrayValue": { "values": [int(1)] } })),
                ("x", int(1)),
            ]))],
            strict: None,
            emulator: (400, extraneous),
        },
        Case {
            label: "empty vector with another key",
            stages: vec![select(map(vec![
                ("__type__", string("__vector__")),
                ("value", json!({ "arrayValue": {} })),
                ("x", int(1)),
            ]))],
            strict: None,
            emulator: (400, extraneous),
        },
        Case {
            label: "vector whose value is null",
            stages: vec![select(map(vec![
                ("__type__", string("__vector__")),
                ("value", json!({ "nullValue": null })),
            ]))],
            strict: None,
            emulator: (400, not_array),
        },
        // The vector check comes before the key and expression checks of the literal.
        Case {
            label: "{\"\": 1, a: vector of integers}",
            stages: vec![select(map(vec![("", int(1)), ("a", vector(vec![int(1)]))]))],
            strict: None,
            emulator: (400, doubles),
        },
        Case {
            label: "{a: vector of integers, b: field}",
            stages: vec![select(map(vec![
                ("a", vector(vec![int(1)])),
                ("b", field("i")),
            ]))],
            strict: None,
            emulator: (400, doubles),
        },
        Case {
            label: "equal(vector of integers, 1)",
            stages: vec![select(func("equal", vec![vector(vec![int(1)]), int(1)]))],
            strict: None,
            emulator: (400, doubles),
        },
        Case {
            label: "[vector without value, vector of integers]",
            stages: vec![select(json!({ "arrayValue": { "values": [
                map(vec![("__type__", string("__vector__"))]),
                vector(vec![int(1)]),
            ] } }))],
            strict: None,
            emulator: (400, missing),
        },
        // One refusable key is recorded (O-4 `o4/literals#key-empty`, `#key-reserved`); which
        // of several production names is not, nor `__name__`.
        Case {
            label: "{\"\": 1}",
            stages: vec![select(map(vec![("", int(1))]))],
            strict: Some((400, "Property names cannot be empty.")),
            emulator: (400, "Property names cannot be empty."),
        },
        Case {
            label: "{__x__: 1}",
            stages: vec![select(map(vec![("__x__", int(1))]))],
            strict: Some((400, "field name '__x__' is reserved.")),
            emulator: (400, "field name '__x__' is reserved."),
        },
        Case {
            label: "{\"\": 1, __x__: 1}",
            stages: vec![select(map(vec![("", int(1)), ("__x__", int(1))]))],
            strict: None,
            emulator: (400, "Property names cannot be empty."),
        },
        Case {
            label: "{__b__: 1, __a__: 1}",
            stages: vec![select(map(vec![("__b__", int(1)), ("__a__", int(1))]))],
            strict: None,
            emulator: (400, "field name '__a__' is reserved."),
        },
        Case {
            label: "{a: {__x__: 1}, __y__: 1}",
            stages: vec![select(map(vec![
                ("a", map(vec![("__x__", int(1))])),
                ("__y__", int(1)),
            ]))],
            strict: None,
            emulator: (400, "field name '__y__' is reserved."),
        },
        Case {
            label: "{__name__: 1}",
            stages: vec![select(map(vec![("__name__", int(1))]))],
            strict: None,
            emulator: (400, "field name '__name__' is reserved."),
        },
        Case {
            label: "{a: {__name__: 1}}",
            stages: vec![select(map(vec![("a", map(vec![("__name__", int(1))]))]))],
            strict: None,
            emulator: (400, "field name '__name__' is reserved."),
        },
    ]);
}

#[test]
fn strict_refuses_fireemus_own_texts_for_the_functions_it_runs() {
    check(vec![
        Case {
            label: "equal()",
            stages: vec![select(func("equal", vec![]))],
            strict: None,
            emulator: (
                400,
                "function \"equal\" takes 2 argument(s), got 0 argument(s)",
            ),
        },
        Case {
            label: "document_id()",
            stages: vec![select(func("document_id", vec![]))],
            strict: None,
            emulator: (
                400,
                "function \"document_id\" takes 1 argument(s), got 0 argument(s)",
            ),
        },
        Case {
            label: "map(\"k\")",
            stages: vec![select(func("map", vec![string("k")]))],
            strict: None,
            emulator: (
                400,
                "function \"map\" takes key and value pairs, got 1 argument(s)",
            ),
        },
        Case {
            label: "where(equal(i))",
            stages: vec![stage("where", vec![func("equal", vec![field("i")])])],
            strict: None,
            emulator: (400, "equal requires exactly two arguments and no options"),
        },
        Case {
            label: "select {} then where(equal())",
            stages: vec![
                stage("select", vec![map(vec![])]),
                stage("where", vec![func("equal", vec![])]),
            ],
            strict: None,
            // The official emulator answers the argument count first; the emulator profile
            // answers the empty select (a text difference, both refuse).
            emulator: (400, EMPTY_SELECT),
        },
        // The official emulator ignores function options; production has not answered them.
        Case {
            label: "document_id with options",
            stages: vec![select(json!({ "functionValue": {
                "name": "document_id",
                "args": [field("__name__")],
                "options": { "x": int(1) },
            } }))],
            strict: None,
            emulator: (200, ""),
        },
        Case {
            label: "where(equal(i, 1)) with options",
            stages: vec![stage(
                "where",
                vec![json!({ "functionValue": {
                "name": "equal",
                "args": [field("i"), int(1)],
                "options": { "x": int(1) },
            } })],
            )],
            strict: None,
            emulator: (200, ""),
        },
        Case {
            label: "map(\"k\", i) with a field option",
            stages: vec![select(json!({ "functionValue": {
                "name": "map",
                "args": [string("k"), field("i")],
                "options": { "x": field("i") },
            } }))],
            strict: None,
            emulator: (200, ""),
        },
        // Recorded texts of the functions it runs stay answered.
        Case {
            label: "map(\"k\", i, \"k\", i)",
            stages: vec![select(func(
                "map",
                vec![string("k"), field("i"), string("k"), field("n")],
            ))],
            strict: Some((400, "map(...) constructor given duplicate key: k")),
            emulator: (400, "map(...) constructor given duplicate key: k"),
        },
        Case {
            label: "map(i, i)",
            stages: vec![select(func("map", vec![field("i"), field("i")]))],
            strict: Some((400, "map keys must be constants/literals")),
            emulator: (400, "map keys must be constants/literals"),
        },
    ]);
}

#[test]
fn strict_lets_no_deferred_or_later_check_answer_past_a_constant_that_fails() {
    // Production's order between an argument-type refusal and an empty map or a later stage's
    // check is unrecorded, so under strict a function call that fails on its constants (fields
    // read as absent) refuses the pipeline as unobserved; the emulator profile keeps its order.
    let empty = || stage("select", vec![map(vec![])]);
    let double = json!({ "doubleValue": 1.5 });
    check(vec![
        Case {
            label: "N76 add_fields {a: map(1.5, i)} then select {}",
            stages: vec![
                stage(
                    "add_fields",
                    vec![map(vec![(
                        "a",
                        func("map", vec![double.clone(), field("i")]),
                    )])],
                ),
                empty(),
            ],
            strict: None,
            emulator: (400, EMPTY_SELECT),
        },
        Case {
            label: "N78 select {v: document_id(1.5)} then limit(\"x\")",
            stages: vec![
                select(func("document_id", vec![double.clone()])),
                stage("limit", vec![string("x")]),
            ],
            strict: None,
            emulator: (
                400,
                "Expected limit to be INTEGER_VALUE, but was STRING_VALUE.",
            ),
        },
        Case {
            label: "N15 add_fields {a: document_id(1)} then select {}",
            stages: vec![
                stage(
                    "add_fields",
                    vec![map(vec![("a", func("document_id", vec![int(1)]))])],
                ),
                empty(),
            ],
            strict: None,
            emulator: (400, EMPTY_SELECT),
        },
        Case {
            label: "N14 where(equal(document_id(1), \"x\")) then select {}",
            stages: vec![
                stage(
                    "where",
                    vec![func(
                        "equal",
                        vec![func("document_id", vec![int(1)]), string("x")],
                    )],
                ),
                empty(),
            ],
            strict: None,
            emulator: (400, EMPTY_SELECT),
        },
        Case {
            label: "N79 where(equal(i, map(1.5, i))) then select {}",
            stages: vec![
                stage(
                    "where",
                    vec![func(
                        "equal",
                        vec![field("i"), func("map", vec![double.clone(), field("i")])],
                    )],
                ),
                empty(),
            ],
            strict: None,
            emulator: (400, EMPTY_SELECT),
        },
        Case {
            label: "N68 aggregate {c: count(n)} by {\"\": document_id(1)}",
            stages: vec![stage(
                "aggregate",
                vec![
                    map(vec![("c", func("count", vec![field("n")]))]),
                    map(vec![("", func("document_id", vec![int(1)]))]),
                ],
            )],
            strict: None,
            emulator: (400, "Invalid empty property path string."),
        },
        // A failing call inside an array literal, beside the literal's own recorded refusal.
        Case {
            label: "select {v: [document_id(1)]}",
            stages: vec![select(json!({ "arrayValue": { "values": [
                func("document_id", vec![int(1)]),
            ] } }))],
            strict: None,
            emulator: (400, "Value type is not supported: FUNCTION_VALUE"),
        },
        Case {
            label: "select {v: [document_id(__name__)]}",
            stages: vec![select(json!({ "arrayValue": { "values": [
                func("document_id", vec![field("__name__")]),
            ] } }))],
            strict: Some((400, "Value type is not supported: FUNCTION_VALUE")),
            emulator: (400, "Value type is not supported: FUNCTION_VALUE"),
        },
        // A type that depends on the data: the plan-time empty map still wins (N77).
        Case {
            label: "N77 add_fields {a: document_id(i)} then select {}",
            stages: vec![
                stage(
                    "add_fields",
                    vec![map(vec![("a", func("document_id", vec![field("i")]))])],
                ),
                empty(),
            ],
            strict: Some((400, EMPTY_SELECT)),
            emulator: (400, EMPTY_SELECT),
        },
        // A constant that evaluates fine does not change the answer.
        Case {
            label: "add_fields {a: map(\"k\", 1)} then select {}",
            stages: vec![
                stage(
                    "add_fields",
                    vec![map(vec![("a", func("map", vec![string("k"), int(1)]))])],
                ),
                empty(),
            ],
            strict: Some((400, EMPTY_SELECT)),
            emulator: (400, EMPTY_SELECT),
        },
        // Alone, a failing constant is answered at evaluation as recorded (O-4
        // `functions#document-id-integer` with a field; a constant is a composition).
        Case {
            label: "select {v: document_id(1)} alone",
            stages: vec![select(func("document_id", vec![int(1)]))],
            strict: Some((
                400,
                "The function document_id(...) requires `Reference` but got `LONG`.",
            )),
            emulator: (
                400,
                "The function document_id(...) requires `Reference` but got `LONG`.",
            ),
        },
    ]);
}

#[test]
fn strict_answers_a_refusal_only_when_no_other_part_is_unobserved() {
    // Coordinator ruling (px-coordinator-rulings.md, PX1d r3): under strict an INVALID_ARGUMENT
    // answer needs every stage, value, literal and call of the pipeline to pass strict's own
    // checks, unless a recorded row shows that error winning over that kind of part.
    let empty = || stage("select", vec![map(vec![])]);
    let empty_alias = "Invalid empty property path string.";
    let limit_text = "Expected limit to be INTEGER_VALUE, but was STRING_VALUE.";
    let literal_text = "Value type is not supported: FIELD_REFERENCE_VALUE";
    check(vec![
        Case {
            label: "select {\"\": i} then where(nope_fn())",
            stages: vec![
                stage("select", vec![map(vec![("", field("i"))])]),
                stage("where", vec![func("nope_fn", vec![])]),
            ],
            strict: None,
            emulator: (400, empty_alias),
        },
        Case {
            label: "limit(\"x\") then where(equal(i, 1))",
            stages: vec![
                stage("limit", vec![string("x")]),
                stage("where", vec![func("equal", vec![field("i"), int(1)])]),
            ],
            strict: None,
            emulator: (400, limit_text),
        },
        Case {
            label: "select {v: [i]} then sort",
            stages: vec![
                select(json!({ "arrayValue": { "values": [field("i")] } })),
                stage("sort", vec![func("ascending", vec![field("i")])]),
            ],
            strict: None,
            emulator: (400, literal_text),
        },
        Case {
            label: "where(equal(i, [i])) then select {v: nope_fn()}",
            stages: vec![
                stage(
                    "where",
                    vec![func(
                        "equal",
                        vec![
                            field("i"),
                            json!({ "arrayValue": { "values": [field("i")] } }),
                        ],
                    )],
                ),
                select(func("nope_fn", vec![])),
            ],
            strict: None,
            emulator: (400, literal_text),
        },
        Case {
            label: "limit(\"x\") then add_fields {a: nope_fn()}",
            stages: vec![
                stage("limit", vec![string("x")]),
                stage(
                    "add_fields",
                    vec![map(vec![("a", func("nope_fn", vec![]))])],
                ),
            ],
            strict: None,
            emulator: (400, limit_text),
        },
        Case {
            label: "a one-argument aggregate then sort",
            stages: vec![
                stage(
                    "aggregate",
                    vec![map(vec![("c", func("count", vec![field("n")]))])],
                ),
                stage("sort", vec![func("ascending", vec![field("i")])]),
            ],
            strict: None,
            emulator: (400, AGGREGATE_ARITY),
        },
        Case {
            label: "select {\"\": i} then limit(true)",
            stages: vec![
                stage("select", vec![map(vec![("", field("i"))])]),
                stage("limit", vec![json!({ "booleanValue": true })]),
            ],
            strict: None,
            emulator: (400, empty_alias),
        },
        // Stages out of the subset's order or repeated, beside a recorded refusal.
        Case {
            label: "select {\"\": i} then where(equal(i, 1))",
            stages: vec![
                stage("select", vec![map(vec![("", field("i"))])]),
                stage("where", vec![func("equal", vec![field("i"), int(1)])]),
            ],
            strict: None,
            emulator: (400, empty_alias),
        },
        Case {
            label: "where(equal(i, [i])) twice",
            stages: vec![
                stage(
                    "where",
                    vec![func(
                        "equal",
                        vec![
                            field("i"),
                            json!({ "arrayValue": { "values": [field("i")] } }),
                        ],
                    )],
                ),
                stage("where", vec![func("equal", vec![field("i"), int(1)])]),
            ],
            strict: None,
            emulator: (400, literal_text),
        },
        Case {
            label: "select {\"\": i} then limit 1 twice",
            stages: vec![
                stage("select", vec![map(vec![("", field("i"))])]),
                stage("limit", vec![int(1)]),
                stage("limit", vec![int(1)]),
            ],
            strict: None,
            emulator: (400, empty_alias),
        },
        Case {
            label: "select {\"\": i} then limit 1 then offset 1",
            stages: vec![
                stage("select", vec![map(vec![("", field("i"))])]),
                stage("limit", vec![int(1)]),
                stage("offset", vec![int(1)]),
            ],
            strict: None,
            emulator: (400, empty_alias),
        },
        Case {
            label: "select {\"\": i} then offset 1 then limit 1",
            stages: vec![
                stage("select", vec![map(vec![("", field("i"))])]),
                stage("offset", vec![int(1)]),
                stage("limit", vec![int(1)]),
            ],
            strict: Some((400, empty_alias)),
            emulator: (400, empty_alias),
        },
        Case {
            label: "a one-argument aggregate of a failing constant",
            stages: vec![stage(
                "aggregate",
                vec![map(vec![("c", func("document_id", vec![int(1)]))])],
            )],
            strict: Some((400, AGGREGATE_ARITY)),
            emulator: (400, AGGREGATE_ARITY),
        },
        // Recorded orders stay answered (O-1 `results/metadata#aggregate`, O-4 `o4/stages#*`).
        Case {
            label: "select {\"\": i} alone",
            stages: vec![stage("select", vec![map(vec![("", field("i"))])])],
            strict: Some((400, empty_alias)),
            emulator: (400, empty_alias),
        },
        Case {
            label: "select {} then limit(\"x\")",
            stages: vec![empty(), stage("limit", vec![string("x")])],
            strict: Some((400, limit_text)),
            emulator: (400, limit_text),
        },
        Case {
            label: "limit 1 then a one-argument aggregate",
            stages: vec![
                stage("limit", vec![int(1)]),
                stage("aggregate", vec![map(vec![("c", func("count", vec![]))])]),
            ],
            strict: Some((400, AGGREGATE_ARITY)),
            emulator: (400, AGGREGATE_ARITY),
        },
        Case {
            label: "add_fields {t: top} then select {}",
            stages: vec![
                stage("add_fields", vec![map(vec![("t", field("top"))])]),
                empty(),
            ],
            strict: Some((400, EMPTY_SELECT)),
            emulator: (400, EMPTY_SELECT),
        },
        Case {
            label: "select {} then add_fields {\"\": top}",
            stages: vec![
                empty(),
                stage("add_fields", vec![map(vec![("", field("top"))])]),
            ],
            strict: Some((400, empty_alias)),
            emulator: (400, empty_alias),
        },
        Case {
            label: "select {v: [i]} alone",
            stages: vec![select(json!({ "arrayValue": { "values": [field("i")] } }))],
            strict: Some((400, literal_text)),
            emulator: (400, literal_text),
        },
    ]);
}

#[test]
fn strict_refuses_the_stage_registry_texts_and_unrecorded_empty_constructions() {
    let with_options = json!({
        "name": "select",
        "args": [map(vec![("v", field("i"))])],
        "options": { "x": int(1) },
    });
    check(vec![
        Case {
            label: "limit()",
            stages: vec![stage("limit", vec![])],
            strict: None,
            emulator: (400, "stage \"limit\" takes 1 argument(s), got 0"),
        },
        Case {
            label: "offset(1, 2)",
            stages: vec![stage("offset", vec![int(1), int(2)])],
            strict: None,
            emulator: (400, "stage \"offset\" takes 1 argument(s), got 2"),
        },
        Case {
            label: "where(true, true)",
            stages: vec![stage(
                "where",
                vec![
                    json!({ "booleanValue": true }),
                    json!({ "booleanValue": true }),
                ],
            )],
            strict: None,
            emulator: (400, "stage \"where\" takes 1 argument(s), got 2"),
        },
        Case {
            label: "select with a stage option",
            stages: vec![with_options],
            strict: None,
            emulator: (400, "stage \"select\": option \"x\": no such option"),
        },
        Case {
            label: "array()",
            stages: vec![select(func("array", vec![]))],
            strict: None,
            emulator: (200, ""),
        },
        Case {
            label: "map()",
            stages: vec![select(func("map", vec![]))],
            strict: None,
            emulator: (200, ""),
        },
        Case {
            label: "array(i)",
            stages: vec![select(func("array", vec![field("i")]))],
            strict: Some((200, "")),
            emulator: (200, ""),
        },
        Case {
            label: "vector of -0.0",
            stages: vec![select(vector(vec![json!({ "doubleValue": -0.0 })]))],
            strict: None,
            emulator: (200, ""),
        },
    ]);
}
