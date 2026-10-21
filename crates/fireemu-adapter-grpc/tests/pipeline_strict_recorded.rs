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
        key_order: fireemu_adapter_grpc::rest::json_syntax::KeyOrder::default(),
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
            strict: None,
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
            // A refusal after an aggregate stage is outside the recorded composition.
            strict: None,
            emulator: (400, EMPTY_SELECT),
        },
        Case {
            label: "aggregate {\"\": count()} by {}",
            stages: vec![stage(
                "aggregate",
                vec![map(vec![("", func("count", vec![]))]), map(vec![])],
            )],
            strict: None,
            emulator: (400, "Invalid empty property path string."),
        },
        Case {
            // PX1d r4 S3: the official emulator accepts an ordering written as a map, where
            // fireemu's stage registry would refuse its shape.
            label: "sort with an {expression, direction} map",
            stages: vec![stage(
                "sort",
                vec![map(vec![
                    ("expression", field("i")),
                    ("direction", json!({"stringValue": "ascending"})),
                ])],
            )],
            strict: None,
            emulator: (501, "pipeline stage \"sort\" is unsupported locally"),
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
    // Production refused each function of a field per runtime type, since the text names it:
    // document_id of a string (O-3) and an integer (O-4), collection_id of a string (O-3) and a
    // map (O-4), parent of a string (O-3) and a boolean (O-4). A constant where production read
    // a field is another shape, so strict answers none of these (ruling of 2026-10-21).
    let call_of = |function: &str, arg: Value| select(func(function, vec![arg]));
    for (function, field_name, got) in [
        ("document_id", "top", "STRING"),
        ("document_id", "i", "LONG"),
        ("collection_id", "top", "STRING"),
        ("parent", "top", "STRING"),
    ] {
        let label: &'static str = Box::leak(format!("{function}(field {got})").into_boxed_str());
        let text: &'static str = Box::leak(wrong(function, got).into_boxed_str());
        cases.push(Case {
            label,
            stages: vec![call_of(function, field(field_name))],
            strict: Some((400, text)),
            emulator: (400, text),
        });
    }
    for (function, arg, got) in [
        ("document_id", string("s"), "STRING"),
        ("document_id", int(1), "LONG"),
        ("document_id", map(vec![("a", int(1))]), "MAP"),
        ("document_id", json!({ "booleanValue": true }), "BOOLEAN"),
        ("collection_id", string("s"), "STRING"),
        ("collection_id", map(vec![("a", int(1))]), "MAP"),
        ("collection_id", int(1), "LONG"),
        ("parent", string("s"), "STRING"),
        ("parent", json!({ "booleanValue": true }), "BOOLEAN"),
        ("parent", int(1), "LONG"),
    ] {
        let label: &'static str = Box::leak(format!("{function}({got})").into_boxed_str());
        let text: &'static str = Box::leak(wrong(function, got).into_boxed_str());
        cases.push(Case {
            label,
            stages: vec![call_of(function, arg)],
            strict: None,
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
            strict: None,
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
            // The official emulator 1.22.0 names the reserved key first, in either order.
            emulator: (400, "field name '__x__' is reserved."),
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
            emulator: (400, "'map' function must have an even number of arguments"),
        },
        Case {
            label: "where(equal(i))",
            stages: vec![stage("where", vec![func("equal", vec![field("i")])])],
            strict: None,
            emulator: (400, "equal requires exactly two arguments"),
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
            // A literal key's type is checked before any row, and before the empty map
            // (the official emulator 1.22.0).
            emulator: (400, "map key must be of type STRING, given type is DOUBLE"),
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
            strict: None,
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
            strict: None,
            emulator: (400, EMPTY_SELECT),
        },
        // Alone, a failing constant is answered at evaluation as recorded (O-4
        // `functions#document-id-integer` with a field; a constant is a composition).
        Case {
            label: "select {v: document_id(1)} alone",
            stages: vec![select(func("document_id", vec![int(1)]))],
            strict: None,
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
            // Production recorded no offset of 1, so the pipeline holds an unobserved value.
            strict: None,
            emulator: (400, empty_alias),
        },
        Case {
            label: "a one-argument aggregate of a failing constant",
            stages: vec![stage(
                "aggregate",
                vec![map(vec![("c", func("document_id", vec![int(1)]))])],
            )],
            strict: None,
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
            strict: None,
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

#[test]
fn type_keys_references_and_the_official_order_of_literal_checks() {
    let double = |d: f64| json!({ "doubleValue": d });
    let reference = |path: &str| json!({ "referenceValue": format!("{DOCS}/{path}") });
    let typed = |value: Value| map(vec![("__type__", value)]);
    let vec_int = || vector(vec![int(1)]);
    let doubles = "Vector must only contain values of type 'double'";
    let mut cases = Vec::new();
    // A `__type__` that is no string (r3 review M1): the official text, 501 under strict.
    for (label, value, kind) in [
        ("{__type__: 1}", int(1), "LONG"),
        (
            "{__type__: true}",
            json!({ "booleanValue": true }),
            "BOOLEAN",
        ),
        ("{__type__: null}", json!({ "nullValue": null }), "NULL"),
        ("{__type__: 1.5}", double(1.5), "DOUBLE"),
        ("{__type__: {a: 1}}", map(vec![("a", int(1))]), "MAP"),
        (
            "{__type__: [1]}",
            json!({ "arrayValue": { "values": [int(1)] } }),
            "ARRAY",
        ),
    ] {
        let text: &'static str =
            Box::leak(format!("Field __type__ must be a string; founds {kind}.").into_boxed_str());
        cases.push(Case {
            label,
            stages: vec![select(typed(value))],
            strict: None,
            emulator: (400, text),
        });
    }
    cases.extend([
        Case {
            label: "{__type__: \"x\"} stays answered",
            stages: vec![select(typed(string("x")))],
            strict: Some((200, "")),
            emulator: (200, ""),
        },
        Case {
            label: "{a: {__type__: 1}}",
            stages: vec![select(map(vec![("a", typed(int(1)))]))],
            strict: None,
            emulator: (400, "Field __type__ must be a string; founds LONG."),
        },
        Case {
            label: "where({__type__: 1})",
            stages: vec![stage("where", vec![typed(int(1))])],
            strict: None,
            emulator: (400, "Field __type__ must be a string; founds LONG."),
        },
        Case {
            label: "equal(i, {__type__: 1})",
            stages: vec![select(func("equal", vec![field("i"), typed(int(1))]))],
            strict: None,
            emulator: (400, "Field __type__ must be a string; founds LONG."),
        },
        Case {
            label: "{__type__: 1, b: field} names the field",
            stages: vec![select(map(vec![("__type__", int(1)), ("b", field("i"))]))],
            strict: None,
            emulator: (400, "Value type is not supported: FIELD_REFERENCE_VALUE"),
        },
        // The official order (r3 review S1).
        Case {
            label: "equal(vector of integers): the argument count first",
            stages: vec![select(func("equal", vec![vec_int()]))],
            strict: None,
            emulator: (400, "function \"equal\" takes 2 argument(s), got 1 argument(s)"),
        },
        Case {
            label: "{__x__: field, a: vector of integers}: the reserved key first",
            stages: vec![select(map(vec![("__x__", field("i")), ("a", vec_int())]))],
            strict: None,
            emulator: (400, "field name '__x__' is reserved."),
        },
        Case {
            label: "select {a..b: field, c: vector of integers}: the alias first",
            stages: vec![stage("select", vec![map(vec![("a..b", field("i")), ("c", vec_int())])])],
            strict: None,
            emulator: (400, "Invalid property path \"a..b\". Unquoted property paths must match regex ([a-zA-Z_][a-zA-Z_0-9]*), and quoted property paths must match regex (`(?:[^`\\\\]|(?:\\\\.))+`)"),
        },
        Case {
            label: "a vector map holding a field names the field",
            stages: vec![select(map(vec![("__type__", string("__vector__")), ("value", field("i"))]))],
            strict: None,
            emulator: (400, "Value type is not supported: FIELD_REFERENCE_VALUE"),
        },
        Case {
            label: "add_fields {a: vector of integers} then select {}",
            stages: vec![stage("add_fields", vec![map(vec![("a", vec_int())])]), stage("select", vec![map(vec![])])],
            strict: None,
            emulator: (400, doubles),
        },
        Case {
            label: "vector of Infinity",
            stages: vec![select(vector(vec![json!({ "doubleValue": "Infinity" })]))],
            strict: None,
            emulator: (200, ""),
        },
        // An alias error beside a value strict refuses (r3 review M2).
        Case {
            label: "select {\"\": nope_fn()}",
            stages: vec![stage("select", vec![map(vec![("", func("nope_fn", vec![]))])])],
            strict: None,
            emulator: (400, "Invalid empty property path string."),
        },
        Case {
            label: "select {\"\": {__name__: 1}}",
            stages: vec![stage("select", vec![map(vec![("", map(vec![("__name__", int(1))]))])])],
            strict: None,
            emulator: (400, "Invalid empty property path string."),
        },
        // Reference literals that name no document.
        Case {
            label: "select {v: ref c}",
            stages: vec![select(reference("c"))],
            strict: None,
            emulator: (400, "Document parent name \"projects/demo-app/databases/(default)/documents/c\" lacks \"/\" at index 49."),
        },
        Case {
            label: "select {v: ref c//d}",
            stages: vec![select(reference("c//d"))],
            strict: None,
            emulator: (400, "Document parent name \"projects/demo-app/databases/(default)/documents/c//d\" lacks a resource id at index 50."),
        },
        Case {
            label: "select {v: ref garbage}",
            stages: vec![select(json!({ "referenceValue": "garbage" }))],
            strict: None,
            emulator: (400, "Document parent name \"garbage\" lacks \"projects\" at index 0."),
        },
        Case {
            label: "select {v: ref c/d}",
            stages: vec![select(reference("c/d"))],
            strict: Some((200, "")),
            emulator: (200, ""),
        },
        // The official checks of stages fireemu does not run.
        Case {
            label: "add_fields {__x__: top}",
            stages: vec![stage("add_fields", vec![map(vec![("__x__", field("top"))])])],
            strict: None,
            emulator: (400, "Stage 'add_fields': field name '__x__' is reserved."),
        },
        Case {
            label: "aggregate {v: count()} by {v: top}",
            stages: vec![stage(
                "aggregate",
                vec![map(vec![("v", func("count", vec![]))]), map(vec![("v", field("top"))])],
            )],
            strict: None,
            emulator: (400, "The 'aggregate(...)' stage cannot have overlapping field names: [v]"),
        },
        // Two refusals whose order production has not answered.
        Case {
            label: "select {\"\": 1, \"a..b\": 1}",
            stages: vec![stage("select", vec![map(vec![("", int(1)), ("a..b", int(1))])])],
            strict: None,
            emulator: (400, "Invalid empty property path string."),
        },
        Case {
            label: "add_fields {} then limit(-1)",
            stages: vec![stage("add_fields", vec![map(vec![])]), stage("limit", vec![int(-1)])],
            strict: None,
            // The official emulator answers the empty map before a negative count.
            emulator: (400, "The 'add_fields(...)' stage requires at least one field."),
        },
        Case {
            label: "map(n): the argument count first",
            stages: vec![stage("where", vec![func("map", vec![field("n")])])],
            strict: None,
            emulator: (400, "'map' function must have an even number of arguments"),
        },
    ]);
    check(cases);
}

#[test]
fn the_round_four_checks_hold_in_every_position() {
    let reference = |path: &str| json!({ "referenceValue": format!("{DOCS}/{path}") });
    let typed = |value: Value| map(vec![("__type__", value)]);
    let vec_int = || vector(vec![int(1)]);
    let list = |values: Vec<Value>| json!({ "arrayValue": { "values": values } });
    let field_text = "Value type is not supported: FIELD_REFERENCE_VALUE";
    let function_text = "Value type is not supported: FUNCTION_VALUE";
    let doubles = "Vector must only contain values of type 'double'";
    let key_call = || func("map", vec![field("i"), int(1)]);
    let mut cases = Vec::new();
    for (label, value, kind) in [
        (
            "{__type__: ts}",
            json!({ "timestampValue": "2020-01-01T00:00:00Z" }),
            "TIMESTAMP",
        ),
        (
            "{__type__: bytes}",
            json!({ "bytesValue": "AA==" }),
            "BYTES",
        ),
        ("{__type__: ref}", reference("c/d"), "ENTITY_REF"),
        (
            "{__type__: geo}",
            json!({ "geoPointValue": { "latitude": 1, "longitude": 1 } }),
            "GEO_POINT",
        ),
    ] {
        let text: &'static str =
            Box::leak(format!("Field __type__ must be a string; founds {kind}.").into_boxed_str());
        cases.push(Case {
            label,
            stages: vec![select(typed(value))],
            strict: None,
            emulator: (400, text),
        });
    }
    cases.extend([
        // Entries in order: a field first, a vector first, nested arrays and maps.
        Case { label: "[i, vector of integers]", stages: vec![select(list(vec![field("i"), vec_int()]))], strict: None, emulator: (400, field_text) },
        Case { label: "[[vector of integers, i]]", stages: vec![select(list(vec![list(vec![vec_int(), field("i")])]))], strict: None, emulator: (400, doubles) },
        Case { label: "{a: [vector of integers, i]}", stages: vec![select(map(vec![("a", list(vec![vec_int(), field("i")]))]))], strict: None, emulator: (400, doubles) },
        // References.
        Case { label: "ref to the documents root", stages: vec![select(json!({ "referenceValue": DOCS }))], strict: None, emulator: (200, "") },
        Case { label: "ref to a non-ASCII document", stages: vec![select(reference("あ/d"))], strict: None, emulator: (200, "") },
        Case {
            label: "document_id(ref garbage)",
            stages: vec![select(func("document_id", vec![json!({ "referenceValue": "garbage" })]))],
            strict: None,
            emulator: (400, "Document parent name \"garbage\" lacks \"projects\" at index 0."),
        },
        Case {
            label: "equal(i, ref c)",
            stages: vec![select(func("equal", vec![field("i"), reference("c")]))],
            strict: None,
            emulator: (400, "Document parent name \"projects/demo-app/databases/(default)/documents/c\" lacks \"/\" at index 49."),
        },
        // Two value refusals in one stage.
        Case {
            label: "select {a: [i], b: [n]}",
            stages: vec![stage("select", vec![map(vec![("a", list(vec![field("i")])), ("b", list(vec![field("n")]))])])],
            strict: None,
            emulator: (400, field_text),
        },
        // An aggregate without accumulators is an empty map, a second refusal here.
        Case {
            label: "aggregate {} by {} then select {__x__: i}",
            stages: vec![
                stage("aggregate", vec![map(vec![]), map(vec![])]),
                stage("select", vec![map(vec![("__x__", field("i"))])]),
            ],
            strict: None,
            emulator: (400, "Stage 'select': field name '__x__' is reserved."),
        },
        // One refusal after an unrun stage.
        Case {
            label: "add_fields {t: top} then select {__x__: i}",
            stages: vec![stage("add_fields", vec![map(vec![("t", field("top"))])]), stage("select", vec![map(vec![("__x__", field("i"))])])],
            strict: None,
            emulator: (400, "Stage 'select': field name '__x__' is reserved."),
        },
        // A function's own refusal inside a literal holding it, at any depth.
        Case { label: "[map(i, 1)]", stages: vec![select(list(vec![key_call()]))], strict: None, emulator: (400, function_text) },
        Case { label: "[[map(i, 1)]]", stages: vec![select(list(vec![list(vec![key_call()])]))], strict: None, emulator: (400, function_text) },
        Case { label: "{a: {b: map(i, 1)}}", stages: vec![select(map(vec![("a", map(vec![("b", key_call())]))]))], strict: None, emulator: (400, function_text) },
        // A part strict refuses inside a function's arguments or a literal's entries.
        Case {
            label: "equal(map(i, 1), nope_fn())",
            stages: vec![select(func("equal", vec![key_call(), func("nope_fn", vec![])]))],
            strict: None,
            // The official emulator names the nonexistent function first; fireemu refuses an
            // unknown function as unsupported (the known class).
            emulator: (501, "function \"nope_fn\" is unsupported locally"),
        },
        Case {
            label: "{a: [i], b: nope_fn()}",
            stages: vec![select(map(vec![("a", list(vec![field("i")])), ("b", func("nope_fn", vec![]))]))],
            strict: None,
            emulator: (400, field_text),
        },
        // Alias checks of a stage fireemu does not run: syntax, then reserved, then length.
        Case {
            label: "distinct {__name__: 1, 1500 bytes: 1}",
            stages: vec![stage("distinct", vec![map(vec![("__name__", int(1)), (&*Box::leak("a".repeat(1500).into_boxed_str()), int(1))])])],
            strict: None,
            emulator: (400, "Stage 'distinct': field name '__name__' is reserved and can not be overwritten."),
        },
        Case {
            label: "add_fields {\"\": top, __x__: top}",
            stages: vec![stage("add_fields", vec![map(vec![("", field("top")), ("__x__", field("top"))])])],
            strict: None,
            emulator: (400, "Invalid empty property path string."),
        },
        Case {
            label: "add_fields {__name__: __name__} is no overwrite",
            stages: vec![stage("add_fields", vec![map(vec![("__name__", field("__name__"))])])],
            strict: None,
            emulator: (501, "pipeline stage \"add_fields\" is unsupported locally"),
        },
        Case {
            label: "add_fields {__x__: __name__}",
            stages: vec![stage("add_fields", vec![map(vec![("__x__", field("__name__"))])])],
            strict: None,
            emulator: (400, "Stage 'add_fields': field name '__x__' is reserved."),
        },
    ]);
    check(cases);
}

#[test]
fn strict_answers_a_refusal_only_in_the_stage_production_recorded_it() {
    let list = |values: Vec<Value>| json!({ "arrayValue": { "values": values } });
    let empty = || stage("select", vec![map(vec![])]);
    let invalid_path = "Invalid property path \"a..b\". Unquoted property paths must match regex ([a-zA-Z_][a-zA-Z_0-9]*), and quoted property paths must match regex (`(?:[^`\\\\]|(?:\\\\.))+`)";
    check(vec![
        Case {
            label: "where(equal(i, [i]))",
            stages: vec![stage(
                "where",
                vec![func("equal", vec![field("i"), list(vec![field("i")])])],
            )],
            strict: None,
            emulator: (400, "Value type is not supported: FIELD_REFERENCE_VALUE"),
        },
        Case {
            label: "where(equal(i, [i])) then select {\"\": i}",
            stages: vec![
                stage(
                    "where",
                    vec![func("equal", vec![field("i"), list(vec![field("i")])])],
                ),
                stage("select", vec![map(vec![("", field("i"))])]),
            ],
            strict: None,
            emulator: (400, "Value type is not supported: FIELD_REFERENCE_VALUE"),
        },
        Case {
            label: "select {} then limit(-1)",
            stages: vec![empty(), stage("limit", vec![int(-1)])],
            strict: None,
            // The official emulator answers the empty map first.
            emulator: (400, EMPTY_SELECT),
        },
        Case {
            label: "select {} then add_fields {a..b: top}",
            stages: vec![
                empty(),
                stage("add_fields", vec![map(vec![("a..b", field("top"))])]),
            ],
            strict: None,
            emulator: (400, invalid_path),
        },
        Case {
            label: "select {v: equal(map(i, 1), [i])}",
            stages: vec![select(func(
                "equal",
                vec![
                    func("map", vec![field("i"), int(1)]),
                    list(vec![field("i")]),
                ],
            ))],
            strict: None,
            // The official emulator answers the literal holding a field first.
            emulator: (400, "Value type is not supported: FIELD_REFERENCE_VALUE"),
        },
        Case {
            label: "aggregate {a..b: count()} by {}",
            stages: vec![stage(
                "aggregate",
                vec![map(vec![("a..b", func("count", vec![]))]), map(vec![])],
            )],
            strict: None,
            emulator: (400, invalid_path),
        },
        // Recorded in this stage: answered.
        Case {
            label: "add_fields {a..b: top}",
            stages: vec![stage("add_fields", vec![map(vec![("a..b", field("top"))])])],
            strict: Some((400, invalid_path)),
            emulator: (400, invalid_path),
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
    ]);
}

/// A `map(...)` key of a literal that is not a string is refused before any row is read, as the
/// official emulator refuses it on an empty collection (`PX1d` r5 review M3): `map(1, i)`,
/// `map(true, i)`, `map(1, 2)`. Strict answers the shapes production refused (O-3
/// `functions#map-integer-key`, O-4 `#map-key-boolean`, both of a field value) and nothing else.
#[test]
fn a_map_key_type_is_refused_before_any_row() {
    let long = "map key must be of type STRING, given type is LONG";
    let boolean = "map key must be of type STRING, given type is BOOLEAN";
    for strict in [true, false] {
        // No document: the collection is empty.
        let state = state(strict);
        for (key, value, text, recorded) in [
            (int(1), field("i"), long, true),
            (json!({ "booleanValue": true }), field("i"), boolean, true),
            (int(1), int(2), long, false),
            (
                json!({ "doubleValue": 1.5 }),
                field("i"),
                "map key must be of type STRING, given type is DOUBLE",
                false,
            ),
            (
                json!({ "nullValue": null }),
                field("i"),
                "map key must be of type STRING, given type is NULL",
                false,
            ),
        ] {
            let got = answer(
                &state,
                &[select(func("map", vec![key.clone(), value.clone()]))],
            );
            if strict && !recorded {
                assert_eq!(got.0, 501, "{key} {value}: {got:?}");
            } else {
                assert_eq!(got, (400, text.to_owned()), "strict={strict} {key} {value}");
            }
        }
        // The key type is answered before a repeated key, whatever the order.
        let got = answer(
            &state,
            &[select(func(
                "map",
                vec![
                    string("k"),
                    field("i"),
                    string("k"),
                    field("i"),
                    int(1),
                    field("i"),
                ],
            ))],
        );
        if !strict {
            assert_eq!(got, (400, long.to_owned()));
        }
    }
}

/// A call of constants that fails is refused before any row (`PX1d` r6 review M1, ruling (d)):
/// on an empty collection and after a `where` that keeps no row, strict answers the recorded
/// text for a recorded shape and 501 otherwise, never 200; the emulator profile answers the
/// official text.
#[test]
fn a_failing_constant_call_is_refused_without_rows() {
    let collection = format!("{DOCS}/c");
    let lacks = format!(
        "Document parent name \"{collection}\" lacks \"/\" at index {}.",
        collection.len()
    );
    let reference = json!({ "referenceValue": collection });
    let none = stage("where", vec![func("equal", vec![field("i"), int(99)])]);
    for strict in [true, false] {
        let empty = state(strict);
        let seeded = seeded(strict);
        for (label, value, text, recorded) in [
            (
                "collection_id(collection)",
                func("collection_id", vec![reference.clone()]),
                lacks.as_str(),
                true,
            ),
            (
                "parent(collection)",
                func("parent", vec![reference.clone()]),
                lacks.as_str(),
                true,
            ),
            (
                "document_id(collection)",
                func("document_id", vec![reference.clone()]),
                lacks.as_str(),
                false,
            ),
            (
                "map({}, 2)",
                func("map", vec![map(vec![]), int(2)]),
                "map key must be of type STRING, given type is MAP",
                false,
            ),
        ] {
            for (place, got) in [
                ("empty", answer(&empty, &[select(value.clone())])),
                (
                    "filtered",
                    answer(&seeded, &[none.clone(), select(value.clone())]),
                ),
            ] {
                assert_ne!(got.0, 200, "strict={strict} {label} {place}");
                if strict && !recorded {
                    assert_eq!(got.0, 501, "{label} {place}: {got:?}");
                } else if !(strict && place == "filtered") {
                    assert_eq!(
                        got,
                        (400, text.to_owned()),
                        "strict={strict} {label} {place}"
                    );
                }
            }
        }
    }
}

/// Check order across values and stages under the emulator profile (the official emulator
/// 1.22.0, `PX1d` r6 review S2): an empty literal key after a later value's literal holding a
/// field; a reserved alias or a `map(...)` key type after a later stage's argument type.
#[test]
fn later_checks_answer_before_an_empty_key_a_reserved_alias_or_a_map_key_type() {
    let field_text = "Value type is not supported: FIELD_REFERENCE_VALUE";
    let limit_text = "Expected limit to be INTEGER_VALUE, but was STRING_VALUE.";
    let state = seeded(false);
    let select_map = |entries: Vec<(&str, Value)>| stage("select", vec![map(entries)]);
    let list = |values: Vec<Value>| json!({ "arrayValue": { "values": values } });
    for (label, stages, text) in [
        (
            "empty key in aa, field literal in zz",
            vec![select_map(vec![
                ("aa", map(vec![("", string("1"))])),
                ("zz", list(vec![field("i")])),
            ])],
            field_text,
        ),
        (
            "reserved alias then limit(\"x\")",
            vec![
                select_map(vec![("__x__", field("i"))]),
                stage("limit", vec![string("x")]),
            ],
            limit_text,
        ),
        (
            "map key type then limit(\"x\")",
            vec![
                select(func("map", vec![int(1), field("i")])),
                stage("limit", vec![string("x")]),
            ],
            limit_text,
        ),
    ] {
        assert_eq!(answer(&state, &stages), (400, text.to_owned()), "{label}");
    }
}
