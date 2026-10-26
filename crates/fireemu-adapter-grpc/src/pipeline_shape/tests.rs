use proptest::prelude::*;
use serde_json::json;

use super::*;

fn body(stages: &Value) -> Value {
    json!({"structuredPipeline": {"pipeline": {"stages": stages}}})
}

/// A body's shape read from its text, with the text's key order.
fn shape_of_text(text: &str) -> Option<String> {
    let (value, order) = json_syntax::parse_with_key_order(text.as_bytes()).unwrap();
    shape_of_json(&value, &order)
}

fn collection() -> Value {
    json!({"name": "collection", "args": [{"referenceValue": "/c"}]})
}

fn invalid(message: &str) -> Status {
    Status::invalid_argument(message)
}

const EMPTY_ALIAS: &str = "Invalid empty property path string.";
const DB: &str = "projects/demo-app/databases/(default)";

#[test]
fn every_recorded_refusal_has_a_shape() {
    let (requests, order) = json_syntax::parse_with_key_order(REQUESTS.as_bytes()).unwrap();
    let production: Value = serde_json::from_str(PRODUCTION).unwrap();
    let table = recorded();
    let mut original = 0;
    let mut o5 = 0;
    let mut o6 = 0;
    let mut o7 = 0;
    let mut o8a = 0;
    let mut o8b = 0;
    let mut o8c = 0;
    let mut raw = 0;
    let mut eligible = 0;
    let mut excluded_500 = 0;
    for (p, program) in requests["programs"].as_array().unwrap().iter().enumerate() {
        let id = program["id"].as_str().unwrap();
        for (s, step) in program["steps"].as_array().unwrap().iter().enumerate() {
            if step["rpc"] != "executePipeline" {
                continue;
            }
            let step_id = step["id"].as_str().unwrap();
            let row = format!("{id}#{step_id}");
            let answer = &production["programs"][id]["steps"][step_id];
            if answer["status"] == 500 {
                excluded_500 += 1;
                assert!(
                    row == "fs-ent-pipeline/o5/appendix#proposed-select-duplicate-quoted-path"
                        || row.starts_with("fs-ent-pipeline/o8a/dupquote-main#")
                        || row == "fs-ent-pipeline/o8c/collections-main#array-reverse-none",
                    "{row}"
                );
                assert_eq!(answer["body"][0]["error"]["status"], "INTERNAL", "{row}");
                let message = answer["body"][0]["error"]["message"].as_str().unwrap();
                assert!(
                    !table
                        .values()
                        .any(|texts| texts.contains(&normalized_text(message))),
                    "HTTP500 entered refusal table: {row}"
                );
                continue;
            }
            if answer["status"] != 400 {
                continue;
            }
            // A body sent as written (O-8A malformed bodies) has no shape: it is not a request
            // the gate matches, only a row the replay compares.
            if step.get("rawBody").is_some() {
                raw += 1;
                continue;
            }
            if id.starts_with("fs-ent-pipeline/o5/") {
                o5 += 1;
            } else if id.starts_with("fs-ent-pipeline/o6/") {
                o6 += 1;
            } else if id.starts_with("fs-ent-pipeline/o7/") {
                o7 += 1;
            } else if id.starts_with("fs-ent-pipeline/o8a/") {
                o8a += 1;
            } else if id.starts_with("fs-ent-pipeline/o8b/") {
                o8b += 1;
            } else if id.starts_with("fs-ent-pipeline/o8c/") {
                o8c += 1;
            } else {
                original += 1;
            }
            let element = answer["body"]
                .as_array()
                .and_then(|a| a.first())
                .unwrap_or(&answer["body"]);
            if element["error"]["status"] != "INVALID_ARGUMENT" {
                continue;
            }
            let Some(message) = element["error"]["message"].as_str() else {
                continue;
            };
            eligible += 1;
            let body_order = order.rebased(&format!("/programs/{p}/steps/{s}/body"), "");
            let shape = shape_of_json(&step["body"], &body_order)
                .unwrap_or_else(|| panic!("recorded refusal has no shape: {row}"));
            assert!(
                table
                    .get(&shape)
                    .is_some_and(|texts| texts.contains(&normalized_text(message))),
                "recorded shape/text missing: {row}"
            );
        }
    }
    assert_eq!(
        (original, o5, o6, o7, o8a, o8b, o8c, raw),
        (98, 291, 21, 54, 3, 80, 84, 18)
    );
    let refused = original + o5 + o6 + o7 + o8a + o8b + o8c;
    assert_eq!(refused, 631);
    assert_eq!(eligible, 631);
    assert_eq!(excluded_500, 7);
    let texts: usize = table.values().map(HashSet::len).sum();
    // Rows of one shape and one text share an entry.
    assert!(texts <= refused && texts > 80, "{texts}");
    assert!(table.values().flatten().any(|t| t == EMPTY_ALIAS));
}

#[test]
fn the_gate_answers_a_recorded_shape_with_its_recorded_text_only() {
    // O-3 `o3/aliases#empty`: select {"": top}.
    let recorded = shape_of_text(
        r#"{"structuredPipeline": {"pipeline": {"stages": [{"name": "collection", "args": [{"referenceValue": "/x"}]}, {"name": "select", "args": [{"mapValue": {"fields": {"": {"fieldReferenceValue": "other"}}}}]}]}}}"#,
    );
    let gate = RefusalGate::Recorded(recorded.clone(), DB.to_owned());
    assert_eq!(
        gate.answer(invalid(EMPTY_ALIAS)).code(),
        tonic::Code::InvalidArgument
    );
    // Another text for the same shape is not production's.
    let other = gate.answer(invalid("Invalid property path \"\"."));
    assert_eq!(other.code(), tonic::Code::Unimplemented);
    assert!(
        other.message().starts_with("Invalid property path"),
        "{}",
        other.message()
    );
    // Other codes pass, and the emulator profile answers everything.
    assert_eq!(
        gate.answer(Status::not_found("x")).code(),
        tonic::Code::NotFound
    );
    assert_eq!(
        RefusalGate::Open.answer(invalid("x")).code(),
        tonic::Code::InvalidArgument
    );
    // A function where production had a field, another alias, or no shape: no answer.
    for shape in [
        shape_of_text(
            r#"{"structuredPipeline": {"pipeline": {"stages": [{"name": "collection", "args": [{"referenceValue": "/x"}]}, {"name": "select", "args": [{"mapValue": {"fields": {"": {"functionValue": {"name": "document_id", "args": [{"fieldReferenceValue": "__name__"}]}}}}}]}]}}}"#,
        ),
        shape_of_text(
            r#"{"structuredPipeline": {"pipeline": {"stages": [{"name": "collection", "args": [{"referenceValue": "/x"}]}, {"name": "select", "args": [{"mapValue": {"fields": {"a": {"fieldReferenceValue": "other"}}}}]}]}}}"#,
        ),
        None,
    ] {
        let status =
            RefusalGate::Recorded(shape.clone(), DB.to_owned()).answer(invalid(EMPTY_ALIAS));
        assert_eq!(status.code(), tonic::Code::Unimplemented, "{shape:?}");
    }
}

#[test]
fn a_text_may_name_the_request_database_only() {
    // O-4 `o4/functions#collection-id-collection`: select {v: collection_id(<collection ref>)}.
    let shape = shape_of_text(
        r#"{"structuredPipeline": {"pipeline": {"stages": [{"name": "collection", "args": [{"referenceValue": "/x"}]}, {"name": "select", "args": [{"mapValue": {"fields": {"v": {"functionValue": {"name": "collection_id", "args": [{"referenceValue": "r"}]}}}}}]}]}}}"#,
    );
    let gate = RefusalGate::Recorded(shape, DB.to_owned());
    let lacks = |name: &str| {
        invalid(&format!(
            "Document parent name \"{name}\" lacks \"/\" at index {}.",
            name.len()
        ))
    };
    assert_eq!(
        gate.answer(lacks(&format!("{DB}/documents/c"))).code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        gate.answer(lacks("projects/x/databases/y/documents/c"))
            .code(),
        tonic::Code::Unimplemented
    );
    // The whole database id: not a prefix of a longer one (r8 review S1).
    for other in [
        "projects/demo-app/databases/(default)x/documents/c",
        "projects/demo-app/databases/(default)-x/documents/c",
    ] {
        assert_eq!(
            gate.answer(lacks(other)).code(),
            tonic::Code::Unimplemented,
            "{other}"
        );
    }
    let named = RefusalGate::Recorded(
        shape_of_text(
            r#"{"structuredPipeline": {"pipeline": {"stages": [{"name": "collection", "args": [{"referenceValue": "/x"}]}, {"name": "select", "args": [{"mapValue": {"fields": {"v": {"functionValue": {"name": "collection_id", "args": [{"referenceValue": "r"}]}}}}}]}]}}}"#,
        ),
        "projects/p/databases/db".to_owned(),
    );
    assert_eq!(
        named
            .answer(lacks("projects/p/databases/db/documents/c"))
            .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        named
            .answer(lacks("projects/p/databases/db2/documents/c"))
            .code(),
        tonic::Code::Unimplemented
    );
    assert_eq!(
        own_database("a projects/p/databases/db2/x", "projects/p/databases/db"),
        "a projects/p/databases/db2/x"
    );
}

#[test]
fn wire_order_is_part_of_the_shape_and_grpc_has_none() {
    let overlap = |first: &str, second: &str| {
        shape_of_text(&format!(
            r#"{{"structuredPipeline": {{"pipeline": {{"stages": [{{"name": "collection", "args": [{{"referenceValue": "/al"}}]}}, {{"name": "select", "args": [{{"mapValue": {{"fields": {{"{first}": {{"fieldReferenceValue": "top"}}, "{second}": {{"fieldReferenceValue": "top"}}}}}}}}]}}]}}}}}}"#
        ))
        .unwrap()
    };
    let recorded = overlap("m", "m.r");
    assert!(
        recorded.contains("{name:field,\"m.r\":field,}"),
        "{recorded}"
    );
    assert!(recorded_refusals(REQUESTS, PRODUCTION).contains_key(&recorded));
    assert_ne!(overlap("m.r", "m"), recorded);
    // A body read without its order (a value built in memory) has no shape for that map.
    let unordered: Value = serde_json::from_str(
        r#"{"structuredPipeline": {"pipeline": {"stages": [{"name": "select", "args": [{"mapValue": {"fields": {"m": {"fieldReferenceValue": "top"}, "m.r": {"fieldReferenceValue": "top"}}}}]}]}}}"#
    )
    .unwrap();
    assert_eq!(shape_of_json(&unordered, &KeyOrder::default()), None);
    let request =
        crate::rest::pipeline_json::request_from_json("projects/p/databases/(default)", &unordered)
            .unwrap();
    assert_eq!(shape_of_request(&request), None);
}

#[test]
fn a_plain_field_name_is_replaced_and_every_other_key_kept() {
    let select = |key: &str| {
        let stages = json!([collection(), {"name": "select", "args": [{"mapValue": {"fields": {key: {"fieldReferenceValue": "i"}}}}]}]);
        shape_of_json(&body(&stages), &KeyOrder::default()).unwrap()
    };
    assert_eq!(select("v"), select("id"));
    assert_eq!(select("_a1"), select("v"));
    // Only a name both starting and ending with `__` (four bytes or more) is reserved.
    for plain in ["__lead", "trail__", "__", "___"] {
        assert_eq!(select(plain), select("v"), "{plain}");
    }
    assert_eq!(select(&"a".repeat(PLAIN_NAME_BYTES)), select("v"));
    for kept in [
        "",
        "a.b",
        "a..b",
        "1a",
        "`q`",
        "__x__",
        "__name__",
        "a-b",
        "あ",
        &"a".repeat(PLAIN_NAME_BYTES + 1),
    ] {
        assert_ne!(select(kept), select("v"), "{kept}");
        assert!(select(kept).contains(&quoted(kept)), "{kept}");
    }
    // A field path of plain names is replaced; `__name__` and any other path are kept.
    let field = |path: &str| {
        let stages = json!([collection(), {"name": "select", "args": [{"mapValue": {"fields": {"v": {"fieldReferenceValue": path}}}}]}]);
        shape_of_json(&body(&stages), &KeyOrder::default()).unwrap()
    };
    assert_eq!(field("i"), field("profile.score"));
    for kept in ["__name__", "a..b", "`a b`", "1a", "a.__x__", ""] {
        assert_ne!(field(kept), field("i"), "{kept}");
        assert!(field(kept).contains(&quoted(kept)), "{kept}");
    }
    // Empty options are no options.
    let bare = json!([collection(), {"name": "limit", "args": [{"integerValue": "1"}]}]);
    let empty =
        json!([collection(), {"name": "limit", "args": [{"integerValue": "1"}], "options": {}}]);
    assert_eq!(
        shape_of_json(&body(&bare), &KeyOrder::default()),
        shape_of_json(&body(&empty), &KeyOrder::default())
    );
    let with_options = json!({"structuredPipeline": {"pipeline": {"stages": bare}, "options": {}}});
    assert_eq!(
        shape_of_json(&with_options, &KeyOrder::default()),
        shape_of_json(&body(&bare), &KeyOrder::default())
    );
    // Option names stay as written.
    let options = |key: &str| {
        let stages = json!([collection(), {"name": "limit", "args": [{"integerValue": "1"}], "options": {key: {"integerValue": "1"}}}]);
        shape_of_json(&body(&stages), &KeyOrder::default()).unwrap()
    };
    assert_ne!(options("x"), options("y"));
}

#[test]
fn rest_and_grpc_shapes_agree_where_no_map_needs_an_order() {
    let (requests, order) = json_syntax::parse_with_key_order(REQUESTS.as_bytes()).unwrap();
    let mut compared = 0;
    for (p, program) in requests["programs"].as_array().unwrap().iter().enumerate() {
        for (s, step) in program["steps"].as_array().unwrap().iter().enumerate() {
            if step["rpc"] != "executePipeline" {
                continue;
            }
            let body = &step["body"];
            let Ok(request) = crate::rest::pipeline_json::request_from_json(
                "projects/p/databases/(default)",
                body,
            ) else {
                continue;
            };
            let json = shape_of_json(
                body,
                &order.rebased(&format!("/programs/{p}/steps/{s}/body"), ""),
            );
            let grpc = shape_of_request(&request);
            if grpc.is_some() {
                assert_eq!(json, grpc, "{}", step["id"]);
                compared += 1;
            } else {
                assert!(json.is_some(), "{}", step["id"]);
            }
        }
    }
    assert!(compared > 300, "{compared}");
}

#[test]
fn every_part_of_a_body_enters_its_shape() {
    let shape = |stages: Value| shape_of_json(&body(&stages), &KeyOrder::default()).unwrap();
    let select = |value: Value| json!([collection(), {"name": "select", "args": [{"mapValue": {"fields": {"v": value}}}]}]);
    // Parts the protocol defines, read alike over REST and gRPC.
    for value in [
        json!({"variableReferenceValue": "x"}),
        json!({"pipelineValue": {"stages": [{"name": "limit", "args": [{"integerValue": "1"}]}]}}),
        json!({"functionValue": {"name": "f", "args": [], "options": {"o": {"integerValue": "1"}}}}),
    ] {
        let stages = select(value.clone());
        let request = crate::rest::pipeline_json::request_from_json(
            "projects/p/databases/(default)",
            &body(&stages),
        )
        .unwrap();
        assert_eq!(Some(shape(stages)), shape_of_request(&request), "{value}");
    }
    assert_ne!(
        shape(select(json!({"variableReferenceValue": "x"}))),
        shape(select(json!({"fieldReferenceValue": "x"})))
    );
    // A part outside the protocol is kept as written.
    let extra = |key: &str| shape(select(json!({"pipelineValue": {"stages": [], key: 1}})));
    assert_ne!(extra("a"), extra("b"));
    assert_ne!(
        shape(select(json!({"pipelineValue": {"stages": []}}))),
        extra("a")
    );
    assert_ne!(
        shape(select(json!({"booleanValue": true, "nullValue": null}))),
        shape(select(json!({"booleanValue": true, "integerValue": "1"})))
    );
    // An empty options map of a function is no options; a non-empty one is kept.
    let function = |options: Value| {
        shape(select(
            json!({"functionValue": {"name": "f", "args": [], "options": options}}),
        ))
    };
    assert_eq!(
        function(json!({})),
        shape(select(json!({"functionValue": {"name": "f", "args": []}})))
    );
    assert_ne!(
        function(json!({"o": {"integerValue": "1"}})),
        function(json!({}))
    );
}

#[test]
fn a_map_that_lost_an_entry_has_no_shape() {
    // The transcoder drops a null entry, so the body's map can hold fewer keys than its text.
    let (mut value, order) = json_syntax::parse_with_key_order(
        br#"{"structuredPipeline": {"pipeline": {"stages": [{"name": "collection", "args": [{"referenceValue": "/c"}]}, {"name": "select", "args": [{"mapValue": {"fields": {"a": {"fieldReferenceValue": "i"}, "b": {"fieldReferenceValue": "i"}, "c": {"fieldReferenceValue": "i"}}}}]}]}}}"#,
    )
    .unwrap();
    assert!(shape_of_json(&value, &order).is_some());
    value["structuredPipeline"]["pipeline"]["stages"][1]["args"][0]["mapValue"]["fields"]
        .as_object_mut()
        .unwrap()
        .remove("c");
    assert_eq!(shape_of_json(&value, &order), None);
    // An order that names only some of the map's keys is not its order either.
    let (_, partial) = json_syntax::parse_with_key_order(
        br#"{"structuredPipeline": {"pipeline": {"stages": [{}, {"args": [{"mapValue": {"fields": {"b": 1, "a": 2}}}]}]}}}"#,
    )
    .unwrap();
    value["structuredPipeline"]["pipeline"]["stages"][1]["args"][0]["mapValue"]["fields"]["c"] =
        json!({"fieldReferenceValue": "i"});
    assert_eq!(shape_of_json(&value, &partial), None);
}

#[test]
fn only_invalid_argument_rows_enter_the_table() {
    let requests = r#"{"programs": [{"id": "p", "steps": [
        {"id": "a", "rpc": "executePipeline", "body": {"structuredPipeline": {"pipeline": {"stages": [{"name": "limit", "args": [{"stringValue": "x"}]}]}}}},
        {"id": "b", "rpc": "executePipeline", "body": {"structuredPipeline": {"pipeline": {"stages": [{"name": "offset", "args": [{"stringValue": "x"}]}]}}}},
        {"id": "c", "rpc": "executePipeline", "body": {"structuredPipeline": {"pipeline": {"stages": [{"name": "limit", "args": [{"stringValue": "x"}]}]}}}},
        {"id": "d", "rpc": "executePipeline", "body": {"structuredPipeline": {"pipeline": {"stages": [{"name": "offset", "args": [{"stringValue": "x"}]}]}}}}
    ]}]}"#;
    let production = r#"{"programs": {"p": {"steps": {
        "a": {"status": 400, "body": [{"error": {"code": 400, "message": "A", "status": "INVALID_ARGUMENT"}}]},
        "b": {"status": 400, "body": [{"error": {"code": 400, "message": "B", "status": "FAILED_PRECONDITION"}}]},
        "c": {"status": 500, "body": [{"error": {"code": 500, "message": "HTTP500 is not refusal evidence", "status": "INVALID_ARGUMENT"}}]},
        "d": {"status": 500, "body": [{"error": {"code": 500, "message": "An internal error occurred.", "status": "INTERNAL"}}]}
    }}}}"#;
    let table = recorded_refusals(requests, production);
    assert_eq!(table.len(), 1);
    assert!(table.values().flatten().all(|text| text == "A"));
}

#[test]
fn an_unknown_member_changes_the_shape() {
    let shape = |stage: Value| {
        shape_of_json(&body(&json!([collection(), stage])), &KeyOrder::default()).unwrap()
    };
    let limit = json!({"name": "limit", "args": [{"integerValue": "1"}]});
    let mut stage_member = limit.clone();
    stage_member["bogus"] = json!(1);
    assert_ne!(shape(stage_member.clone()), shape(limit.clone()));
    let mut other_member = limit.clone();
    other_member["other"] = json!(1);
    assert_ne!(shape(stage_member), shape(other_member));
    let value = |v: Value| shape(json!({"name": "limit", "args": [v]}));
    assert_ne!(
        value(json!({"bogusValue": 1})),
        value(json!({"integerValue": "1"}))
    );
    assert_ne!(
        value(json!({"bogusValue": 1})),
        value(json!({"otherValue": 1}))
    );
    assert_ne!(
        value(json!({"integerValue": "1", "stringValue": "x"})),
        value(json!({"integerValue": "1"}))
    );
}

#[test]
fn normalized_text_puts_aside_the_project_database_and_index() {
    assert_eq!(
        normalized_text(
            "Document parent name \"projects/demo-x/databases/entpipe1/documents/c\" lacks \"/\" at index 60."
        ),
        "Document parent name \"projects/~/databases/~/documents/c\" lacks \"/\" at index ~."
    );
    assert_eq!(
        normalized_text(
            "Document parent name \"projects/demo-app/databases/(default)/documents/c\" lacks \"/\" at index 55."
        ),
        "Document parent name \"projects/~/databases/~/documents/c\" lacks \"/\" at index ~."
    );
    assert_eq!(normalized_text("plain text"), "plain text");
    // The database name ends at a slash, a quote or a space.
    assert_eq!(
        normalized_text("\"projects/p/databases/d\" and projects/p/databases/e here"),
        "\"projects/~/databases/~\" and projects/~/databases/~ here"
    );
    assert_eq!(normalized_text("projects/only"), "projects/only");
}

fn kind_value(kind: u8, n: i64) -> Value {
    match kind % 6 {
        0 => json!({"integerValue": n.to_string()}),
        1 => json!({"stringValue": format!("s{n}")}),
        2 => json!({"doubleValue": f64::from(i32::try_from(n).unwrap()) / 2.0}),
        3 => json!({"booleanValue": n % 2 == 0}),
        4 => json!({"fieldReferenceValue": format!("f{}", n.unsigned_abs())}),
        _ => json!({"arrayValue": {"values": [{"integerValue": n.to_string()}]}}),
    }
}

proptest! {
    /// Field names and values of the same kind leave the shape as it was; another key or kind
    /// changes it.
    #[test]
    fn only_field_names_and_same_kind_values_are_replaced(
        kinds in proptest::collection::vec(any::<u8>(), 1..4),
        a in -5i64..5,
        b in -5i64..5,
    ) {
        let fields = |n: i64, key: &str| {
            let map: serde_json::Map<String, Value> = kinds
                .iter()
                .enumerate()
                .map(|(i, k)| (if i == 0 { key.to_owned() } else { format!("k{i}") }, kind_value(*k, n)))
                .collect();
            Value::Object(map)
        };
        let text = |n: i64, key: &str| {
            let stages = json!([collection(), {"name": "select", "args": [{"mapValue": {"fields": fields(n, key)}}]}]);
            // The written order is the map's iteration order (sorted keys).
            serde_json::to_string(&body(&stages)).unwrap()
        };
        let first = shape_of_text(&text(a, "x"));
        prop_assert!(first.is_some());
        prop_assert_eq!(&first, &shape_of_text(&text(b, "x")));
        // A plain name is replaced; a dotted one is kept.
        prop_assert_eq!(&first, &shape_of_text(&text(a, "y")));
        prop_assert_ne!(&first, &shape_of_text(&text(a, "x.y")));
        let other_kind = json!([collection(), {"name": "select", "args": [{"mapValue": {"fields": {"x": kind_value(kinds[0].wrapping_add(1), a)}}}]}]);
        let same_kind = json!([collection(), {"name": "select", "args": [{"mapValue": {"fields": {"x": kind_value(kinds[0], b)}}}]}]);
        prop_assert_ne!(
            shape_of_text(&serde_json::to_string(&body(&other_kind)).unwrap()),
            shape_of_text(&serde_json::to_string(&body(&same_kind)).unwrap())
        );
    }
}

/// A database id ends at `/`, `"`, whitespace or the end of the text, and only the whole id
/// stands for the request's database; a text without `/databases/` names none.
#[test]
fn own_database_matches_whole_database_ids_only() {
    let db = "projects/p/databases/db";
    for (message, want) in [
        (
            "at projects/p/databases/db/documents/c",
            "at \u{1}database\u{1}/documents/c",
        ),
        (
            "name \"projects/p/databases/db\" lacks",
            "name \"\u{1}database\u{1}\" lacks",
        ),
        (
            "name projects/p/databases/db lacks",
            "name \u{1}database\u{1} lacks",
        ),
        ("end projects/p/databases/db", "end \u{1}database\u{1}"),
        (
            "other projects/p/databases/db2/documents",
            "other projects/p/databases/db2/documents",
        ),
        (
            "other projects/p/databases/db\tx",
            "other \u{1}database\u{1}\tx",
        ),
        ("no database projects/p", "no database projects/p"),
    ] {
        assert_eq!(own_database(message, db), want, "{message}");
    }
    assert_eq!(own_database("projects/p", ""), "projects/p");
}
