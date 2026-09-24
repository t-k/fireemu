//! Firestore REST surface at the handler level: documents, queries, transactions, errors and
//! rules (the JSON mapping is exercised end-to-end by tools/sdk-smoke/lite.mjs).

use std::collections::BTreeMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::{RestRequest, RestState};
use fireemu_adapter_grpc::rules::RulesEnforcer;
use fireemu_core_auth::jwt::{base64url_encode, TokenAcceptance};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet, IndexValidationPolicy,
    PlanningContext,
};
use fireemu_core_firestore::size::document_size;
use fireemu_core_firestore::value::Value as CoreValue;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::CollectionId;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const DOCS: &str = "/v1/projects/demo-app/databases/(default)/documents";

/// Production answers an error of a streaming REST method inside a one-element array; other
/// methods answer the bare envelope.
fn stream_error(body: &Value) -> &Value {
    body.as_array()
        .and_then(|elements| elements.first())
        .unwrap_or(body)
}

fn state(rules: Option<&str>) -> RestState {
    state_with(rules, TokenAcceptance::Verified)
}

fn state_with(rules: Option<&str>, acceptance: TokenAcceptance) -> RestState {
    state_with_clock(rules, acceptance).0
}

/// A REST surface under one compatibility profile: `strict` enforces the Standard limits with
/// production's index policy and verified tokens, `emulator` observes the limits with the
/// official emulator's index policy and mock tokens.
fn state_with_profile(strict: bool) -> RestState {
    let gateway = Gateway {
        enforce_limits: strict,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: if strict {
                IndexValidationPolicy::Production
            } else {
                IndexValidationPolicy::Emulator
            },
        },
        indexes: IndexSet::default(),
    };
    state_with_gateway(gateway, None, TokenAcceptance::Verified).0
}

fn state_with_clock(
    rules: Option<&str>,
    acceptance: TokenAcceptance,
) -> (RestState, Arc<Mutex<VirtualClock>>) {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    state_with_gateway(gateway, rules, acceptance)
}

fn state_with_gateway(
    gateway: Gateway,
    rules: Option<&str>,
    acceptance: TokenAcceptance,
) -> (RestState, Arc<Mutex<VirtualClock>>) {
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let local = Arc::new(LocalBackend::new(gateway.clone(), clock.clone(), 7));
    let rules = rules.map(|src| {
        let auth = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(3),
            TotpPolicy::default(),
        )));
        let loaded = Arc::new(RulesetSlot::new(LoadedRules::from_source(src).unwrap()));
        Arc::new(RulesEnforcer::new(loaded, auth, clock.clone()).with_token_acceptance(acceptance))
    });
    let state = RestState {
        local,
        gateway: Arc::new(gateway),
        rules,
        app_check: None,
        control_token: None,
    };
    (state, clock)
}

fn call(s: &RestState, method: &str, path_and_query: &str, body: Value) -> (u16, Value) {
    call_as(s, method, path_and_query, body, Some("Bearer owner"))
}

fn call_as(
    s: &RestState,
    method: &str,
    path_and_query: &str,
    body: Value,
    authorization: Option<&str>,
) -> (u16, Value) {
    let (path, query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, ""), |(p, q)| (p, q));
    let r = s.handle(&RestRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        authorization: authorization.map(str::to_owned),
        app_check: Vec::new(),
        body,
        origin: None,
        browser_metadata: false,
    });
    (r.status, r.body)
}

/// PCT-1. `%` followed by anything but two hexadecimal digits is not an escape. The
/// hand-rolled decoders went through `u8::from_str_radix`, which accepts a leading sign, so
/// `%+f` became U+000F: in a query value it silently changed the document ID, and in a path
/// segment it slipped past the refusal a malformed escape is supposed to get.
#[test]
fn percent_escapes_in_the_rest_surface_take_two_hexadecimal_digits_or_none() {
    let s = state(None);
    let (status, created) = call(
        &s,
        "POST",
        &format!("{DOCS}/users?documentId=doc%+fid"),
        json!({"fields": {"name": {"stringValue": "Percent"}}}),
    );
    assert_eq!(status, 200, "{created}");
    // A query value keeps its form-encoded reading of `+`, unchanged by this: what the
    // escape rule fixes is the `%`, which is now literal instead of U+000F.
    assert_eq!(
        created["name"],
        "projects/demo-app/databases/(default)/documents/users/doc% fid"
    );
    // A path segment reads `+` literally, so the document is fetched with both characters
    // escaped.
    let (status, got) = call(&s, "GET", &format!("{DOCS}/users/doc%25%20fid"), json!({}));
    assert_eq!(status, 200, "{got}");
    assert_eq!(got["fields"]["name"]["stringValue"], "Percent");

    // The same sequence in a path segment is a malformed escape, and the path decoder
    // refuses it rather than inventing a control character.
    let (status, refused) = call(&s, "GET", &format!("{DOCS}/users/doc%+fid"), json!({}));
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "malformed percent escape in path"
    );

    // A well-formed escape still decodes, and one that hides a separator is still refused.
    let (status, created) = call(
        &s,
        "POST",
        &format!("{DOCS}/users?documentId=with%20space"),
        json!({"fields": {}}),
    );
    assert_eq!(status, 200, "{created}");
    let (status, got) = call(&s, "GET", &format!("{DOCS}/users/with%20space"), json!({}));
    assert_eq!(status, 200, "{got}");
    assert_eq!(
        got["name"],
        "projects/demo-app/databases/(default)/documents/users/with space"
    );
    let (status, refused) = call(&s, "GET", &format!("{DOCS}/users/a%2Fb"), json!({}));
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "encoded '/' in a path segment");
}

#[test]
fn encoded_slash_in_a_create_collection_id_uses_the_observed_production_error() {
    let s = state(None);
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}/bad%2Finside?documentId=x"),
        json!({"fields": {"v": {"integerValue": "1"}}}),
    );
    assert_eq!(status, 400);
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
    assert_eq!(
        body["error"]["message"],
        "Collection id \"bad/inside\" is invalid because it contains \"/\"."
    );
}

#[test]
fn update_mask_path_errors_use_the_observed_production_messages() {
    let s = state(None);
    let cases = [
        (
            "a..b".to_owned(),
            r#"Invalid property path "a..b". Unquoted property paths must match regex ([a-zA-Z_][a-zA-Z_0-9]*), and quoted property paths must match regex (`(?:[^`\\]|(?:\\.))+`)"#.to_owned(),
        ),
        (
            "f".repeat(1500),
            "property path is longer than 1500 bytes.".to_owned(),
        ),
        (
            format!("{}.{}", "a".repeat(750), "b".repeat(750)),
            "property path is longer than 1500 bytes.".to_owned(),
        ),
    ];
    for (mask, expected) in cases {
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:commit"),
            json!({"writes": [{"update": {"name": "projects/demo-app/databases/(default)/documents/masks/x", "fields": {"v": {"integerValue": "1"}}}, "updateMask": {"fieldPaths": [mask]}}]}),
        );
        assert_eq!(status, 400);
        assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
        assert_eq!(body["error"]["message"], expected);
    }
}

#[test]
fn document_crud_over_rest() {
    let s = state(None);
    let (status, created) = call(
        &s,
        "POST",
        &format!("{DOCS}/users?documentId=alice"),
        json!({"fields": {"name": {"stringValue": "Alice"}, "age": {"integerValue": "30"}, "tags": {"arrayValue": {"values": [{"stringValue": "a"}]}}}}),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(
        created["name"],
        format!("projects/demo-app/databases/(default)/documents/users/alice")
    );
    assert_eq!(created["fields"]["age"]["integerValue"], "30");
    assert!(created["createTime"].as_str().unwrap().ends_with('Z'));

    let (status, _) = call(
        &s,
        "POST",
        &format!("{DOCS}/users?documentId=alice"),
        json!({"fields": {}}),
    );
    assert_eq!(
        status, 409,
        "create on an existing document is ALREADY_EXISTS"
    );

    let (status, got) = call(
        &s,
        "GET",
        &format!("{DOCS}/users/alice?mask.fieldPaths=name"),
        json!({}),
    );
    assert_eq!(status, 200);
    assert_eq!(got["fields"]["name"]["stringValue"], "Alice");
    assert!(got["fields"].get("age").is_none());

    let (status, patched) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/users/alice?updateMask.fieldPaths=age&currentDocument.exists=true"),
        json!({"fields": {"age": {"integerValue": 31}}}),
    );
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["fields"]["age"]["integerValue"], "31");
    assert_eq!(
        patched["fields"]["name"]["stringValue"], "Alice",
        "mask keeps other fields"
    );

    let (status, err) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/users/nobody?currentDocument.exists=true"),
        json!({"fields": {}}),
    );
    assert_eq!(status, 404, "{err}");
    assert_eq!(err["error"]["status"], "NOT_FOUND");
    assert_eq!(
        err["error"]["message"],
        "Document \"projects/demo-app/databases/(default)/documents/users/nobody\" not found."
    );

    let (status, listed) = call(&s, "GET", &format!("{DOCS}/users"), json!({}));
    assert_eq!(status, 200);
    assert_eq!(listed["documents"].as_array().map(Vec::len), Some(1));

    let (status, _) = call(&s, "DELETE", &format!("{DOCS}/users/alice"), json!({}));
    assert_eq!(status, 200);
    let (status, _) = call(&s, "GET", &format!("{DOCS}/users/alice"), json!({}));
    assert_eq!(status, 404);
    // An odd number of segments names a (sub)collection: listing it is valid and empty.
    let (status, listed) = call(
        &s,
        "GET",
        "/v1/projects/demo-app/databases/(default)/documents/users/x/y",
        json!({}),
    );
    assert_eq!(status, 200, "{listed}");
    // Proto3 JSON leaves an empty list out: the body is `{}`.
    assert_eq!(listed, json!({}), "an empty listing has no documents key");
    // A method the surface has no route for is a plain-text 404, as the official
    // emulator's HTTP adapter answers it (conformance/src/firestore-probe, errors/rest-shapes).
    let (status, err) = call(
        &s,
        "PUT",
        "/v1/projects/demo-app/databases/(default)/documents/users/x",
        json!({}),
    );
    assert_eq!(status, 404, "{err}");
    assert_eq!(err[fireemu_adapter_grpc::rest::TEXT_KEY], "Not Found\n");
}

#[test]
fn rest_round_trips_all_standard_value_types_and_preserves_refused_writes() {
    let s = state(None);
    let fields = json!({
        "null": {"nullValue": null},
        "bool": {"booleanValue": true},
        "int": {"integerValue": "-42"},
        "double": {"doubleValue": 1.5},
        "nan": {"doubleValue": "NaN"},
        "timestamp": {"timestampValue": "2020-03-04T05:06:07.008Z"},
        "bytes": {"bytesValue": "AAEC/w=="},
        "reference": {"referenceValue": "projects/demo-app/databases/(default)/documents/types/all"},
        "geo": {"geoPointValue": {"latitude": 35.68, "longitude": 139.76}},
        "array": {"arrayValue": {"values": [{"integerValue": "1"}, {"nullValue": null}]}},
        "map": {"mapValue": {"fields": {"nested": {"booleanValue": false}}}},
    });
    let (status, created) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/types/all"),
        json!({"fields": fields.clone()}),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["fields"], fields);
    assert_eq!(created["fields"]["null"]["nullValue"], Value::Null);
    assert_eq!(created["fields"]["nan"]["doubleValue"], "NaN");
    assert_eq!(created["fields"]["bytes"]["bytesValue"], "AAEC/w==");
    assert_eq!(
        created["fields"]["array"]["arrayValue"]["values"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let (status, masked) = call(
        &s,
        "GET",
        &format!("{DOCS}/types/all?mask.fieldPaths=null&mask.fieldPaths=map.nested&mask.fieldPaths=missing"),
        Value::Null,
    );
    assert_eq!(status, 200, "{masked}");
    assert_eq!(masked["fields"]["null"]["nullValue"], Value::Null);
    assert_eq!(
        masked["fields"]["map"]["mapValue"]["fields"]["nested"]["booleanValue"],
        false
    );
    assert!(masked["fields"].get("missing").is_none());
    assert!(masked["fields"].get("int").is_none());

    let (status, body) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/types/all?currentDocument.exists=false"),
        json!({"fields": {"int": {"integerValue": "0"}}}),
    );
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"]["status"], "ALREADY_EXISTS");
    let (status, after_refusal) = call(&s, "GET", &format!("{DOCS}/types/all"), Value::Null);
    assert_eq!(status, 200, "{after_refusal}");
    assert_eq!(after_refusal["fields"], fields);
}

#[test]
fn rest_document_size_and_nesting_boundaries_refuse_without_publishing() {
    let s = state(None);
    let nested = |levels: usize| {
        (0..levels).fold(
            json!({"integerValue": "1"}),
            |value, _| json!({"mapValue": {"fields": {"nested": value}}}),
        )
    };
    let project = fireemu_core_types::ids::ProjectId::try_new("demo-app").unwrap();
    let database = fireemu_core_types::ids::DatabaseId::try_new("(default)").unwrap();
    let path =
        fireemu_core_firestore::path::DocumentPath::parse(&project, &database, "limits/exact")
            .unwrap();
    let empty = BTreeMap::from([
        ("a".to_owned(), CoreValue::String(String::new())),
        ("b".to_owned(), CoreValue::String(String::new())),
    ]);
    let base = document_size(&path, &empty).unwrap().total;
    let exact_payload = usize::try_from(1_048_576 - base).unwrap();
    let first_len = exact_payload / 2;
    let second_len = exact_payload - first_len;
    let exact_core = BTreeMap::from([
        ("a".to_owned(), CoreValue::String("x".repeat(first_len))),
        ("b".to_owned(), CoreValue::String("x".repeat(second_len))),
    ]);
    assert_eq!(document_size(&path, &exact_core).unwrap().total, 1_048_576);
    let exact_fields = json!({
        "a": {"stringValue": "x".repeat(first_len)},
        "b": {"stringValue": "x".repeat(second_len)},
    });
    let (status, accepted_size) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/limits/exact"),
        json!({"fields": exact_fields}),
    );
    assert_eq!(status, 200, "{accepted_size}");

    let over_fields = json!({
        "a": {"stringValue": "x".repeat(first_len)},
        "b": {"stringValue": "x".repeat(second_len + 1)},
    });
    let (status, body) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/limits/overx"),
        json!({"fields": over_fields}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
    assert_eq!(
        body["error"]["message"],
        "Document 'projects/demo-app/databases/(default)/documents/limits/overx' cannot be written because its size (1,048,577 bytes) exceeds the maximum allowed size of 1,048,576 bytes."
    );

    let (status, body) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/limits/oversized-field"),
        json!({"fields": {"blob": {"stringValue": "x".repeat(1_048_488)}}}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["error"]["message"],
        "The value of property \"blob\" is longer than 1048487 bytes."
    );

    let (status, exact) = call(&s, "GET", &format!("{DOCS}/limits/exact"), Value::Null);
    assert_eq!(status, 200, "{exact}");
    assert_eq!(
        exact["fields"]["a"]["stringValue"].as_str().unwrap().len(),
        first_len
    );
    let (status, missing) = call(&s, "GET", &format!("{DOCS}/limits/overx"), Value::Null);
    assert_eq!(status, 404, "{missing}");

    let (status, body) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/limits/too-deep"),
        json!({"fields": {"nested": nested(21)}}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
    assert_eq!(
        body["error"]["message"],
        "Property nested contains an invalid nested entity."
    );
    let (status, missing) = call(&s, "GET", &format!("{DOCS}/limits/too-deep"), Value::Null);
    assert_eq!(status, 404, "{missing}");

    let (status, accepted) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/limits/deep"),
        json!({"fields": {"value": nested(20)}}),
    );
    assert_eq!(status, 200, "{accepted}");
}

#[test]
fn rest_nested_limit_diagnostics_keep_the_property_and_route_context() {
    let s = state(None);
    let nested = |levels: usize| {
        (0..levels).fold(
            json!({"integerValue": "1"}),
            |value, _| json!({"mapValue": {"fields": {"nested": value}}}),
        )
    };

    let (status, body) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/limits/other-depth"),
        json!({"fields": {"other": nested(21)}}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["error"]["message"],
        "Property other contains an invalid nested entity."
    );

    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}/limits?documentId=post-depth"),
        json!({"fields": {"nested": nested(21)}}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["error"]["message"],
        "Property nested contains an invalid nested entity."
    );

    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({
            "writes": [{
                "update": {
                    "name": "projects/demo-app/databases/(default)/documents/limits/commit-depth",
                    "fields": {"nested": nested(21)}
                }
            }]
        }),
    );
    assert_eq!(status, 400, "{body}");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("FS-LIMIT-NESTED-MAP-ARRAY-DEPTH"));
}

#[test]
fn rest_collection_create_oversize_reports_the_explicit_document_resource() {
    let s = state(None);
    let project = fireemu_core_types::ids::ProjectId::try_new("demo-app").unwrap();
    let database = fireemu_core_types::ids::DatabaseId::try_new("(default)").unwrap();
    let path =
        fireemu_core_firestore::path::DocumentPath::parse(&project, &database, "limits/post-size")
            .unwrap();
    let base = document_size(
        &path,
        &BTreeMap::from([
            ("a".to_owned(), CoreValue::String(String::new())),
            ("b".to_owned(), CoreValue::String(String::new())),
        ]),
    )
    .unwrap()
    .total;
    let payload = usize::try_from(1_048_577 - base).unwrap();
    let first_len = payload / 2;
    let second_len = payload - first_len;
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}/limits?documentId=post-size"),
        json!({"fields": {
            "a": {"stringValue": "x".repeat(first_len)},
            "b": {"stringValue": "x".repeat(second_len)}
        }}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["error"]["message"],
        "Document 'projects/demo-app/databases/(default)/documents/limits/post-size' cannot be written because its size (1,048,577 bytes) exceeds the maximum allowed size of 1,048,576 bytes."
    );
    let (status, missing) = call(&s, "GET", &format!("{DOCS}/limits/post-size"), Value::Null);
    assert_eq!(status, 404, "{missing}");
}

#[test]
fn rest_oversized_nested_values_report_canonical_paths_without_publishing() {
    let s = state(None);
    let oversized = "x".repeat(1_048_488);
    for (document_id, key, expected_path) in [
        ("dotted-key", "with.dot", "items.`with.dot`"),
        ("quoted-key", "with\"quote", "items.`with\"quote`"),
    ] {
        let (status, body) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/limits/{document_id}"),
            json!({
                "fields": {
                    "items": {"arrayValue": {"values": [{
                        "mapValue": {"fields": {
                            key: {"stringValue": oversized}
                        }}
                    }]}}
                }
            }),
        );
        assert_eq!(status, 400, "{body}");
        assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
        assert_eq!(
            body["error"]["message"],
            format!("The value of property \"{expected_path}\" is longer than 1048487 bytes.")
        );

        let (status, missing) = call(
            &s,
            "GET",
            &format!("{DOCS}/limits/{document_id}"),
            Value::Null,
        );
        assert_eq!(status, 404, "{missing}");
    }
}

#[test]
fn batch_write_rest_preserves_slots_and_omits_success_status_defaults() {
    let s = state(None);
    let middle = "projects/demo-app/databases/(default)/documents/batch/1";
    let (status, _) = call(
        &s,
        "POST",
        &format!("{DOCS}/batch?documentId=1"),
        json!({"fields": {"existing": {"integerValue": "7"}}}),
    );
    assert_eq!(status, 200);

    let first = "projects/demo-app/databases/(default)/documents/batch/0";
    let last = "projects/demo-app/databases/(default)/documents/batch/2";
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchWrite"),
        json!({
            "writes": [
                {"update": {"name": first, "fields": {
                    "zero": {"integerValue": "0"},
                    "empty": {"stringValue": ""},
                    "map": {"mapValue": {"fields": {}}}
                }}},
                {"update": {"name": middle, "fields": {"existing": {"integerValue": "8"}}},
                 "currentDocument": {"exists": false}},
                {"update": {"name": last, "fields": {"value": {"integerValue": "9"}}}}
            ]
        }),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["status"],
        json!([
            {},
            {"code": 6, "message": format!("Document already exists: {middle}")},
            {}
        ]),
        "{body}"
    );
    assert_eq!(body["writeResults"].as_array().unwrap().len(), 3);
    assert_eq!(body["writeResults"][1], json!({}));

    let (status, first_document) = call(&s, "GET", &format!("{DOCS}/batch/0"), json!({}));
    assert_eq!(status, 200, "{first_document}");
    assert_eq!(first_document["fields"]["zero"]["integerValue"], "0");
    assert_eq!(first_document["fields"]["empty"]["stringValue"], "");
    assert_eq!(first_document["fields"]["map"]["mapValue"], json!({}));
    let (status, middle_document) = call(&s, "GET", &format!("{DOCS}/batch/1"), json!({}));
    assert_eq!(status, 200, "{middle_document}");
    assert_eq!(middle_document["fields"]["existing"]["integerValue"], "7");
    let (status, last_document) = call(&s, "GET", &format!("{DOCS}/batch/2"), json!({}));
    assert_eq!(status, 200, "{last_document}");
    assert_eq!(last_document["fields"]["value"]["integerValue"], "9");
}

#[test]
fn batch_write_rest_unknown_transaction_rejects_before_writes() {
    let s = state(None);
    let created = "projects/demo-app/databases/(default)/documents/guard/would-be-created";
    let (status, _) = call(
        &s,
        "POST",
        &format!("{DOCS}/guard?documentId=1"),
        json!({"fields": {"a": {"integerValue": "3"}}}),
    );
    assert_eq!(status, 200);
    let (status, before) = call(&s, "GET", &format!("{DOCS}/guard/1"), json!({}));
    assert_eq!(status, 200, "{before}");

    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchWrite"),
        json!({
            "writes": [{"update": {"name": created, "fields": {"a": {"integerValue": "4"}}}}],
            "transaction": "AA=="
        }),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body,
        json!({
            "error": {
                "code": 400,
                "message": "Invalid JSON payload received. Unknown name \"transaction\": Cannot find field.",
                "status": "INVALID_ARGUMENT",
                "details": [{
                    "@type": "type.googleapis.com/google.rpc.BadRequest",
                    "fieldViolations": [{
                        "description": "Invalid JSON payload received. Unknown name \"transaction\": Cannot find field."
                    }]
                }]
            }
        }),
        "{body}"
    );
    let (status, after) = call(&s, "GET", &format!("{DOCS}/guard/1"), json!({}));
    assert_eq!(status, 200, "{after}");
    assert_eq!(after, before);
    let (status, _) = call(
        &s,
        "GET",
        &format!("{DOCS}/guard/would-be-created"),
        json!({}),
    );
    assert_eq!(status, 404);
}

#[test]
fn batch_write_rest_rejects_non_array_writes_without_mutation() {
    let s = state(None);
    let target = "projects/demo-app/databases/(default)/documents/batch-shape/target";

    {
        let writes = json!({"not": "an array"});
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:batchWrite"),
            json!({"writes": writes}),
        );
        assert_eq!(status, 400, "{body}");
        assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");
    }

    let (status, body) = call(&s, "GET", &format!("/v1/{target}"), Value::Null);
    assert_eq!(
        status, 404,
        "malformed batch requests must not mutate state: {body}"
    );
}

#[test]
fn batch_write_rest_rejects_invalid_middle_operation_before_any_write() {
    let s = state(None);
    let first = "projects/demo-app/databases/(default)/documents/batch-atomic/first";
    let last = "projects/demo-app/databases/(default)/documents/batch-atomic/last";
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchWrite"),
        json!({
            "writes": [
                {"update": {"name": first, "fields": {"v": {"integerValue": "1"}}}},
                {"currentDocument": {"exists": false}},
                {"update": {"name": last, "fields": {"v": {"integerValue": "2"}}}}
            ]
        }),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");
    for name in [first, last] {
        let (status, body) = call(&s, "GET", &format!("/v1/{name}"), Value::Null);
        assert_eq!(status, 404, "invalid batch mutated {name}: {body}");
    }
}

#[test]
fn batch_write_rest_rejects_invalid_field_names_before_any_write() {
    for field in ["", "__bad__"] {
        let s = state(None);
        let first = "projects/demo-app/databases/(default)/documents/batch-fields/first";
        let middle = "projects/demo-app/databases/(default)/documents/batch-fields/middle";
        let last = "projects/demo-app/databases/(default)/documents/batch-fields/last";
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:batchWrite"),
            json!({"writes": [
                {"update": {"name": first, "fields": {"v": {"integerValue": "1"}}}},
                {"update": {"name": middle, "fields": {field: {"integerValue": "2"}}}},
                {"update": {"name": last, "fields": {"v": {"integerValue": "3"}}}}
            ]}),
        );
        assert_eq!(status, 400, "field {field:?}: {body}");
        assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");
        for name in [first, middle, last] {
            let (status, body) = call(&s, "GET", &format!("/v1/{name}"), Value::Null);
            assert_eq!(status, 404, "field {field:?} mutated {name}: {body}");
        }
    }
}

#[test]
fn batch_write_rest_rejects_reserved_nested_map_keys_before_any_write() {
    let s = state(None);
    let first = "projects/demo-app/databases/(default)/documents/batch-nested/first";
    let middle = "projects/demo-app/databases/(default)/documents/batch-nested/middle";
    let last = "projects/demo-app/databases/(default)/documents/batch-nested/last";
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchWrite"),
        json!({"writes": [
            {"update": {"name": first, "fields": {"v": {"integerValue": "1"}}}},
            {"update": {"name": middle, "fields": {"nested": {"mapValue": {"fields": {"__bad__": {"integerValue": "2"}}}}}}},
            {"update": {"name": last, "fields": {"v": {"integerValue": "3"}}}}
        ]}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");
    for name in [first, middle, last] {
        let (status, body) = call(&s, "GET", &format!("/v1/{name}"), Value::Null);
        assert_eq!(status, 404, "invalid nested field mutated {name}: {body}");
    }
}

#[test]
fn batch_write_rest_reports_the_saved_production_integer_error_without_mutation() {
    let s = state(None);
    let names = ["first", "middle", "last"]
        .map(|id| format!("projects/demo-app/databases/(default)/documents/batch-integer/{id}"));
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchWrite"),
        json!({"writes": [
            {"update": {"name": names[0], "fields": {"v": {"integerValue": "1"}}}},
            {"update": {"name": names[1], "fields": {"v": {"integerValue": "not-a-number"}}}},
            {"update": {"name": names[2], "fields": {"v": {"integerValue": "3"}}}}
        ]}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
    assert_eq!(
        body["error"]["message"],
        "Invalid value at 'writes[1].update.fields[0].value.integer_value' (TYPE_INT64), \"not-a-number\""
    );
    for name in names {
        let (status, _) = call(&s, "GET", &format!("/v1/{name}"), Value::Null);
        assert_eq!(status, 404, "invalid middle value must prevent every write");
    }
}

#[test]
fn batch_write_rest_reports_saved_production_value_decode_errors() {
    let cases = [
        (
            json!({"timestampValue": "yesterday"}),
            "Invalid value at 'writes[1].update.fields[0].value.timestamp_value' (type.googleapis.com/google.protobuf.Timestamp), Field 'timestampValue', Illegal timestamp format; timestamps must end with 'Z' or have a valid timezone offset.",
        ),
        (
            json!({"arrayValue": {"values": "not-an-array"}}),
            "Invalid value at 'writes[1].update.fields[0].value.array_value.values' (type.googleapis.com/google.firestore.v1.Value), \"not-an-array\"",
        ),
        (
            json!({"fooValue": "ignored"}),
            "Invalid JSON payload received. Unknown name \"fooValue\" at 'writes[1].update.fields[0].value': Cannot find field.",
        ),
    ];
    for (invalid, expected) in cases {
        let s = state(None);
        let names = ["first", "middle", "last"]
            .map(|id| format!("projects/demo-app/databases/(default)/documents/batch-decode/{id}"));
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:batchWrite"),
            json!({"writes": [
                {"update": {"name": names[0], "fields": {"v": {"integerValue": "1"}}}},
                {"update": {"name": names[1], "fields": {"v": invalid}}},
                {"update": {"name": names[2], "fields": {"v": {"integerValue": "3"}}}}
            ]}),
        );
        assert_eq!(status, 400, "{body}");
        assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
        assert_eq!(body["error"]["message"], expected);
        for name in names {
            let (status, _) = call(&s, "GET", &format!("/v1/{name}"), Value::Null);
            assert_eq!(status, 404, "invalid middle value must prevent every write");
        }
    }
}

#[test]
fn batch_write_rest_does_not_reuse_the_observed_timezone_error_for_an_invalid_date() {
    let s = state(None);
    let name = "projects/demo-app/databases/(default)/documents/batch-decode/invalid-date";
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchWrite"),
        json!({"writes": [{"update": {"name": name, "fields": {
            "v": {"timestampValue": "2020-13-45T00:00:00Z"}
        }}}]}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
    assert!(!body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("timestamps must end with 'Z' or have a valid timezone offset."));
    let (read_status, _) = call(&s, "GET", &format!("/v1/{name}"), Value::Null);
    assert_eq!(read_status, 404);
}

#[test]
fn batch_write_rest_rejects_malformed_nested_repeated_values_without_mutation() {
    let s = state(None);
    let target = "projects/demo-app/databases/(default)/documents/batch-shape/nested";
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchWrite"),
        json!({
            "writes": [{
                "update": {
                    "name": target,
                    "fields": {
                        "values": {"arrayValue": {"values": "not-an-array"}}
                    }
                }
            }]
        }),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");

    let (status, after) = call(&s, "GET", &format!("/v1/{target}"), Value::Null);
    assert_eq!(
        status, 404,
        "malformed nested values must not mutate state: {after}"
    );
}

#[test]
fn batch_write_rest_rejects_write_without_operation_before_dispatch() {
    let s = state(None);
    let target = "projects/demo-app/databases/(default)/documents/batch-shape/target";
    let (status, created) = call(
        &s,
        "POST",
        &format!("{DOCS}/batch-shape?documentId=target"),
        json!({"fields": {"v": {"integerValue": "0"}}}),
    );
    assert_eq!(status, 200, "{created}");

    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchWrite"),
        json!({
            "writes": [
                {},
                {"update": {"name": target, "fields": {"v": {"integerValue": "1"}}}}
            ]
        }),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");

    let (status, after) = call(&s, "GET", &format!("/v1/{target}"), Value::Null);
    assert_eq!(
        status, 200,
        "a malformed request must not dispatch its suffix: {after}"
    );
    assert_eq!(after["fields"]["v"]["integerValue"], "0", "{after}");
}

#[test]
fn batch_write_rest_rejects_empty_oneof_between_valid_writes() {
    let s = state(None);
    let first = "projects/demo-app/databases/(default)/documents/batch-shape/first";
    let last = "projects/demo-app/databases/(default)/documents/batch-shape/last";
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchWrite"),
        json!({
            "writes": [
                {"update": {"name": first, "fields": {"v": {"integerValue": "1"}}}},
                {},
                {"update": {"name": last, "fields": {"v": {"integerValue": "2"}}}}
            ]
        }),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");

    for path in ["batch-shape/first", "batch-shape/last"] {
        let (status, document) = call(&s, "GET", &format!("{DOCS}/{path}"), Value::Null);
        assert_eq!(status, 404, "{document}");
    }
}

#[test]
fn batch_write_rest_rejects_multiple_non_null_operations_before_dispatch() {
    let s = state(None);
    let target = "projects/demo-app/databases/(default)/documents/batch-shape/multiple";
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchWrite"),
        json!({
            "writes": [
                {"update": {"name": target, "fields": {"v": {"integerValue": "1"}}}, "delete": target}
            ]
        }),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");

    let (status, after) = call(
        &s,
        "GET",
        &format!("{DOCS}/batch-shape/multiple"),
        Value::Null,
    );
    assert_eq!(status, 404, "multiple operations mutated state: {after}");
}

#[test]
fn commit_rest_rejects_empty_oneof_write_before_mutation() {
    let s = state(None);
    let target = "projects/demo-app/databases/(default)/documents/commit-shape/target";
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({
            "writes": [
                {},
                {"update": {"name": target, "fields": {"v": {"integerValue": "1"}}}}
            ]
        }),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");

    let (status, after) = call(
        &s,
        "GET",
        &format!("{DOCS}/commit-shape/target"),
        Value::Null,
    );
    assert_eq!(status, 404, "an invalid commit mutated state: {after}");
}

#[test]
fn batch_write_rest_treats_null_oneof_members_as_unset() {
    let null_members = ["update", "delete", "verify", "transform"];
    for (index, member) in null_members.iter().enumerate() {
        let s = state(None);
        let target = format!("projects/demo-app/databases/(default)/documents/null-oneof/{index}");
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:batchWrite"),
            json!({"writes": [{*member: null}]}),
        );
        assert_eq!(
            status, 400,
            "null-only {member} is an unset operation: {body}"
        );
        assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");
        let target_path = format!("/v1/{target}");
        let (status, after) = call(&s, "GET", &target_path, Value::Null);
        assert_eq!(status, 404, "null-only {member} mutated state: {after}");

        let valid = json!({
            "update": {"name": target, "fields": {"v": {"integerValue": "1"}}}
        });
        let payload = if *member == "update" {
            let (status, _) = call(
                &s,
                "POST",
                &format!("{DOCS}/null-oneof?documentId={index}"),
                json!({"fields": {"v": {"integerValue": "0"}}}),
            );
            assert_eq!(status, 200);
            json!({"update": null, "delete": target})
        } else {
            let mut value = valid.as_object().unwrap().clone();
            value.insert((*member).to_owned(), Value::Null);
            Value::Object(value)
        };
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:batchWrite"),
            json!({"writes": [payload]}),
        );
        assert_eq!(status, 200, "null-plus-valid {member} failed: {body}");
        let (status, after) = call(&s, "GET", &target_path, Value::Null);
        if *member == "update" {
            assert_eq!(
                status, 404,
                "null update was treated as an operation: {after}"
            );
        } else {
            assert_eq!(status, 200, "valid update was not dispatched: {after}");
            assert_eq!(after["fields"]["v"]["integerValue"], "1");
        }
    }
}

#[test]
fn batch_write_rest_rejects_malformed_labels_without_mutation() {
    let s = state(None);
    let target = "projects/demo-app/databases/(default)/documents/batch-labels/target";
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchWrite"),
        json!({
            "labels": "not-an-object",
            "writes": [{"update": {"name": target, "fields": {"v": {"integerValue": "1"}}}}]
        }),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");

    let (status, after) = call(
        &s,
        "GET",
        &format!("{DOCS}/batch-labels/target"),
        Value::Null,
    );
    assert_eq!(
        status, 404,
        "malformed labels must not publish writes: {after}"
    );
}

#[test]
fn batch_write_rest_separates_validation_failure_from_failed_precondition() {
    let s = state(None);
    for (failure_index, failure) in [
        (
            0,
            json!({
                "update": {
                    "name": "not a document name",
                    "fields": {"v": {"integerValue": "0"}}
                }
            }),
        ),
        (
            1,
            json!({
                "update": {
                    "name": "projects/demo-app/databases/(default)/documents/rest-batch-1/1",
                    "fields": {"v": {"integerValue": "8"}}
                },
                "currentDocument": {"exists": false}
            }),
        ),
    ] {
        let collection = format!("rest-batch-{failure_index}");
        let wire_docs = DOCS.trim_start_matches("/v1/");
        let middle = format!("{wire_docs}/{collection}/1");
        let middle_path = format!("{DOCS}/{collection}/1");
        let (status, _) = call(
            &s,
            "POST",
            &format!("{DOCS}/{collection}?documentId=1"),
            json!({"fields": {"v": {"integerValue": "7"}}}),
        );
        assert_eq!(status, 200);

        let first = format!("{wire_docs}/{collection}/0");
        let last = format!("{wire_docs}/{collection}/2");
        let first_path = format!("{DOCS}/{collection}/0");
        let last_path = format!("{DOCS}/{collection}/2");
        let mut writes = vec![
            json!({"update": {"name": first, "fields": {"v": {"integerValue": "1"}}}}),
            json!({"update": {"name": middle, "fields": {"v": {"integerValue": "8"}}}}),
            json!({"update": {"name": last, "fields": {"v": {"integerValue": "3"}}}}),
        ];
        writes[failure_index] = failure;
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:batchWrite"),
            json!({"writes": writes}),
        );
        if failure_index == 0 {
            assert_eq!(status, 400, "{body}");
            assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");
        } else {
            assert_eq!(status, 200, "{body}");
            assert_eq!(body["status"].as_array().map(Vec::len), Some(3), "{body}");
            assert_ne!(body["status"][failure_index]["code"], Value::Null, "{body}");
            assert_eq!(
                body["writeResults"].as_array().map(Vec::len),
                Some(3),
                "{body}"
            );
        }

        for (index, path) in [(0, first_path), (1, middle_path), (2, last_path)] {
            let (status, document) = call(&s, "GET", &path, Value::Null);
            if failure_index == 0 && index != 1 {
                assert_eq!(status, 404, "{document}");
            } else {
                assert_eq!(status, 200, "{document}");
                let expected = if failure_index == 0 {
                    "7".to_owned()
                } else if index == 0 {
                    "1".to_owned()
                } else if index == 1 && failure_index == 1 {
                    "7".to_owned()
                } else if index == 1 {
                    "8".to_owned()
                } else {
                    "3".to_owned()
                };
                assert_eq!(document["fields"]["v"]["integerValue"], expected);
            }
        }
    }
}

#[test]
fn batch_write_rest_reports_lock_contention_per_item_and_recovers_after_rollback() {
    let s = state(None);
    let locked = "projects/demo-app/databases/(default)/documents/rest-batch-contention/locked";
    let prefix = "projects/demo-app/databases/(default)/documents/rest-batch-contention/prefix";
    let suffix = "projects/demo-app/databases/(default)/documents/rest-batch-contention/suffix";

    let (status, seeded) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/rest-batch-contention/locked"),
        json!({"fields": {"v": {"integerValue": "1"}}}),
    );
    assert_eq!(status, 200, "{seeded}");

    let (status, begun) = call(
        &s,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readWrite": {}}}),
    );
    assert_eq!(status, 200, "{begun}");
    let transaction = begun["transaction"].as_str().unwrap().to_owned();
    let (status, held) = call(
        &s,
        "GET",
        &format!("{DOCS}/rest-batch-contention/locked?transaction={transaction}"),
        Value::Null,
    );
    assert_eq!(status, 200, "{held}");

    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchWrite"),
        json!({
            "writes": [
                {"update": {"name": prefix, "fields": {"v": {"integerValue": "2"}}}},
                {"update": {"name": locked, "fields": {"v": {"integerValue": "3"}}}},
                {"update": {"name": suffix, "fields": {"v": {"integerValue": "4"}}}}
            ]
        }),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"].as_array().map(Vec::len), Some(3), "{body}");
    assert_eq!(
        body["writeResults"].as_array().map(Vec::len),
        Some(3),
        "{body}"
    );
    assert_eq!(body["status"][0], json!({}));
    assert_eq!(body["status"][1]["code"], 10);
    assert_eq!(
        body["status"][1]["message"],
        "Too much contention on these documents. Please try again."
    );
    assert_eq!(body["writeResults"][1], json!({}));
    assert_eq!(body["status"][2], json!({}));
    assert!(body["writeResults"][0]["updateTime"].is_string());
    assert!(body["writeResults"][2]["updateTime"].is_string());

    for (path, expected) in [
        ("rest-batch-contention/prefix", "2"),
        ("rest-batch-contention/locked", "1"),
        ("rest-batch-contention/suffix", "4"),
    ] {
        let (status, document) = call(&s, "GET", &format!("{DOCS}/{path}"), Value::Null);
        assert_eq!(status, 200, "{document}");
        assert_eq!(document["fields"]["v"]["integerValue"], expected);
    }

    let (status, rolled_back) = call(
        &s,
        "POST",
        &format!("{DOCS}:rollback"),
        json!({"transaction": transaction}),
    );
    assert_eq!(status, 200, "{rolled_back}");
    let (status, recovered) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/rest-batch-contention/locked"),
        json!({"fields": {"v": {"integerValue": "5"}}}),
    );
    assert_eq!(status, 200, "{recovered}");
    assert_eq!(recovered["fields"]["v"]["integerValue"], "5");
}

/// Production's refusal of a `BatchWrite` that names one document twice
/// (`conformance/firestore-production-matrix.json`, `writes/batch-write` step
/// `non-atomic-batch`, 2026-09-07 live corpus: HTTP 400 `INVALID_ARGUMENT`, no status array,
/// readbacks proving nothing landed).
const BATCH_WRITE_REPEATED_DOCUMENT: &str =
    "the same document cannot be written more than once in a single request";

/// FS-WRITE-002. A REST `:batchWrite` that writes one document twice is refused as a whole
/// request with production's exact wording under both profiles: no `status` array, no
/// `writeResults`, and neither the repeated document nor its distinct siblings change. A
/// batch of distinct documents keeps its per-item results.
#[test]
fn batch_write_rest_refuses_a_repeated_document_as_a_whole_with_production_wording() {
    for strict in [true, false] {
        let s = state_with_profile(strict);
        let existing = "projects/demo-app/databases/(default)/documents/batch-repeat/existing";
        let sibling = "projects/demo-app/databases/(default)/documents/batch-repeat/sibling";
        let suffix = "projects/demo-app/databases/(default)/documents/batch-repeat/suffix";
        let (status, seeded) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/batch-repeat/existing"),
            json!({"fields": {"v": {"integerValue": "0"}}}),
        );
        assert_eq!(status, 200, "{seeded}");
        let before_time = seeded["updateTime"].as_str().unwrap().to_owned();

        // The repeated document sits between distinct siblings and its second occurrence is a
        // different operation (delete after update), as in the production observation.
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:batchWrite"),
            json!({
                "writes": [
                    {"update": {"name": sibling, "fields": {"v": {"integerValue": "1"}}}},
                    {"update": {"name": existing, "fields": {"v": {"integerValue": "1"}}}},
                    {"delete": existing},
                    {"update": {"name": suffix, "fields": {"v": {"integerValue": "2"}}}}
                ]
            }),
        );
        assert_eq!(status, 400, "strict={strict} {body}");
        assert_eq!(body["error"]["code"], 400, "strict={strict} {body}");
        assert_eq!(
            body["error"]["status"], "INVALID_ARGUMENT",
            "strict={strict} {body}"
        );
        assert_eq!(
            body["error"]["message"], BATCH_WRITE_REPEATED_DOCUMENT,
            "strict={strict} {body}"
        );
        assert!(body.get("status").is_none(), "strict={strict} {body}");
        assert!(body.get("writeResults").is_none(), "strict={strict} {body}");

        for absent in [sibling, suffix] {
            let (status, missing) = call(&s, "GET", &format!("/v1/{absent}"), Value::Null);
            assert_eq!(status, 404, "strict={strict} {missing}");
        }
        let (status, unchanged) = call(&s, "GET", &format!("/v1/{existing}"), Value::Null);
        assert_eq!(status, 200, "strict={strict} {unchanged}");
        assert_eq!(unchanged["fields"]["v"]["integerValue"], "0");
        assert_eq!(unchanged["updateTime"], before_time, "strict={strict}");

        // Distinct documents: every write is its own commit with its own result.
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:batchWrite"),
            json!({
                "writes": [
                    {"update": {"name": format!("{}/batch-repeat/a", &DOCS[4..]), "fields": {"v": {"integerValue": "1"}}}},
                    {"update": {"name": format!("{}/batch-repeat/b", &DOCS[4..]), "fields": {"v": {"integerValue": "2"}}}}
                ]
            }),
        );
        assert_eq!(status, 200, "strict={strict} {body}");
        assert_eq!(body["status"], json!([{}, {}]), "strict={strict} {body}");
        assert!(body["writeResults"][0]["updateTime"].is_string());
        assert!(body["writeResults"][1]["updateTime"].is_string());
    }
}

#[test]
fn partition_ranges_reconstruct_the_same_snapshot_without_boundary_duplicates() {
    let s = state(None);
    let mut read_time = String::new();
    // Twelve documents, and four more the partition sampler picks so the group splits.
    let project = fireemu_core_types::ids::ProjectId::try_new("demo-app").unwrap();
    let database = fireemu_core_types::ids::DatabaseId::try_new("(default)").unwrap();
    let name = |index: usize| format!("owners/{}/items/i{index:02}", ["a", "a-", "b"][index % 3]);
    let sampled = (12..)
        .map(name)
        .filter(|relative| {
            fireemu_adapter_grpc::partition::is_sample(
                &fireemu_core_firestore::path::DocumentPath::parse(&project, &database, relative)
                    .unwrap(),
            )
        })
        .take(4);
    let documents: Vec<String> = (0..12).map(name).chain(sampled).collect();
    for (index, relative) in documents.iter().enumerate() {
        let (status, document) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/{relative}"),
            json!({"fields": {"value": {"integerValue": index.to_string()}}}),
        );
        assert_eq!(status, 200, "{document}");
        read_time = document["updateTime"].as_str().unwrap().to_owned();
    }
    // The explicit `__name__` order the SDKs send: a partition cursor positions against the
    // explicit order only.
    let query = json!({
        "from": [{"collectionId": "items", "allDescendants": true}],
        "orderBy": [{"field": {"fieldPath": "__name__"}, "direction": "ASCENDING"}],
    });
    let mut token = String::new();
    let mut cuts = Vec::new();
    loop {
        let (status, page) = call(
            &s,
            "POST",
            &format!("{DOCS}:partitionQuery"),
            json!({"structuredQuery": query, "partitionCount": "4", "pageSize": 2, "pageToken": token, "readTime": read_time}),
        );
        assert_eq!(status, 200, "{page}");
        let points = page["partitions"].as_array().cloned().unwrap_or_default();
        assert!(points.len() <= 2);
        cuts.extend(points.iter().cloned());
        token = page["nextPageToken"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if token.is_empty() {
            break;
        }
        assert!(cuts.len() < 4);
    }
    assert_eq!(cuts.len(), 4);
    cuts.sort_by(|left, right| {
        left["values"][0]["referenceValue"]
            .as_str()
            .unwrap()
            .split('/')
            .cmp(
                right["values"][0]["referenceValue"]
                    .as_str()
                    .unwrap()
                    .split('/'),
            )
    });
    let names = |rows: &Value| {
        rows.as_array()
            .unwrap()
            .iter()
            .filter_map(|row| row["document"]["name"].as_str().map(str::to_owned))
            .collect::<Vec<_>>()
    };
    let (status, all) = call(
        &s,
        "POST",
        &format!("{DOCS}:runQuery"),
        json!({"structuredQuery": query, "readTime": read_time}),
    );
    assert_eq!(status, 200, "{all}");
    let expected = names(&all);
    assert_eq!(expected.len(), documents.len());
    let mut actual = Vec::new();
    for index in 0..=cuts.len() {
        let mut range = query.clone();
        if index > 0 {
            range["startAt"] = cuts[index - 1].clone();
        }
        if index < cuts.len() {
            range["endAt"] = cuts[index].clone();
        }
        let (status, rows) = call(
            &s,
            "POST",
            &format!("{DOCS}:runQuery"),
            json!({"structuredQuery": range, "readTime": read_time}),
        );
        assert_eq!(status, 200, "{rows}");
        actual.extend(names(&rows));
    }
    assert_eq!(actual, expected);
}

#[test]
#[allow(clippy::too_many_lines)]
fn commit_query_aggregation_and_transactions_over_rest() {
    let s = state(None);
    let (status, committed) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [
            {"update": {"name": format!("projects/demo-app/databases/(default)/documents/n/1"), "fields": {"v": {"integerValue": "1"}, "t": {"stringValue": "x"}}}},
            {"update": {"name": format!("projects/demo-app/databases/(default)/documents/n/2"), "fields": {"v": {"integerValue": "2"}, "t": {"stringValue": "y"}}}},
            {"update": {"name": format!("projects/demo-app/databases/(default)/documents/n/3"), "fields": {"t": {"stringValue": "missing-v"}}}},
            {"transform": {"document": format!("projects/demo-app/databases/(default)/documents/n/1"), "fieldTransforms": [{"fieldPath": "v", "increment": {"integerValue": "10"}}, {"fieldPath": "at", "setToServerValue": "REQUEST_TIME"}]}}
        ]}),
    );
    assert_eq!(status, 200, "{committed}");
    assert_eq!(committed["writeResults"].as_array().map(Vec::len), Some(4));
    assert_eq!(
        committed["writeResults"][3]["transformResults"][0]["integerValue"],
        "11"
    );
    assert!(committed["commitTime"].as_str().is_some());

    let (status, rows) = call(
        &s,
        "POST",
        &format!("{DOCS}:runQuery"),
        json!({"structuredQuery": {
            "from": [{"collectionId": "n"}],
            "where": {"fieldFilter": {"field": {"fieldPath": "v"}, "op": "GREATER_THAN", "value": {"integerValue": "1"}}},
            "orderBy": [{"field": {"fieldPath": "v"}, "direction": "DESCENDING"}],
            "limit": 5
        }}),
    );
    assert_eq!(status, 200, "{rows}");
    let names: Vec<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["document"]["name"].as_str())
        .collect();
    assert_eq!(names.len(), 2);
    assert!(
        names[0].ends_with("/n/1"),
        "11 sorts before 2 descending: {names:?}"
    );
    assert!(rows[0]["readTime"].as_str().is_some());

    let (status, agg) = call(
        &s,
        "POST",
        &format!("{DOCS}:runAggregationQuery"),
        json!({"structuredAggregationQuery": {
            "structuredQuery": {"from": [{"collectionId": "n"}]},
            "aggregations": [{"alias": "count", "count": {}}, {"alias": "total", "sum": {"field": {"fieldPath": "v"}}}]
        }}),
    );
    assert_eq!(status, 200, "{agg}");
    assert_eq!(
        agg[0]["result"]["aggregateFields"]["count"]["integerValue"],
        "2"
    );
    assert_eq!(
        agg[0]["result"]["aggregateFields"]["total"]["integerValue"],
        "13"
    );
    let (status, count_only) = call(
        &s,
        "POST",
        &format!("{DOCS}:runAggregationQuery"),
        json!({"structuredAggregationQuery": {
            "structuredQuery": {"from": [{"collectionId": "n"}]},
            "aggregations": [{"alias": "count", "count": {}}]
        }}),
    );
    assert_eq!(status, 200, "{count_only}");
    assert_eq!(
        count_only[0]["result"]["aggregateFields"]["count"]["integerValue"],
        "3"
    );

    let (status, begun) = call(
        &s,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readWrite": {}}}),
    );
    assert_eq!(status, 200);
    let txn = begun["transaction"].as_str().unwrap().to_owned();
    let (status, got) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchGet"),
        json!({"documents": [format!("projects/demo-app/databases/(default)/documents/n/1"), format!("projects/demo-app/databases/(default)/documents/n/none")], "transaction": txn}),
    );
    assert_eq!(status, 200, "{got}");
    assert!(got[0]["found"].is_object());
    assert!(got[1]["missing"].as_str().unwrap().ends_with("/n/none"));
    // Production (PESSIMISTIC): the documents the transaction read are locked, so the
    // out-of-band write is refused with production's wording (this backend waits zero
    // seconds for a release), and the transaction commits.
    let (status, contended) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{"update": {"name": format!("projects/demo-app/databases/(default)/documents/n/1"), "fields": {"v": {"integerValue": "99"}}}}]}),
    );
    assert_eq!(status, 409, "{contended}");
    assert_eq!(contended["error"]["status"], "ABORTED");
    assert_eq!(
        contended["error"]["message"],
        "Too much contention on these documents. Please try again."
    );
    let (status, committed) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"transaction": txn, "writes": [{"delete": format!("projects/demo-app/databases/(default)/documents/n/2")}]}),
    );
    assert_eq!(status, 200, "{committed}");
    let (status, _) = call(&s, "GET", &format!("{DOCS}/n/2"), json!({}));
    assert_eq!(status, 404);
    let (status, released) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{"update": {"name": format!("projects/demo-app/databases/(default)/documents/n/1"), "fields": {"v": {"integerValue": "99"}}}}]}),
    );
    assert_eq!(status, 200, "{released}");

    let (status, ids) = call(&s, "POST", &format!("{DOCS}:listCollectionIds"), json!({}));
    assert_eq!(status, 200);
    assert_eq!(ids["collectionIds"], json!(["n"]));

    let (status, err) = call(
        &s,
        "POST",
        &format!("{DOCS}:runQuery"),
        json!({"structuredQuery": {"from": [{"collectionId": "n"}], "where": {"fieldFilter": {"field": {"fieldPath": "v"}, "op": "BOGUS", "value": {"integerValue": "1"}}}}}),
    );
    assert_eq!(status, 400, "{err}");
}

#[test]
#[allow(clippy::too_many_lines)]
fn rest_aggregation_refused_commit_preserves_state_and_new_transaction_route() {
    let s = state(None);
    let document = |id: &str, fields: Value| {
        let (status, body) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/agg/{id}"),
            json!({"fields": fields}),
        );
        assert_eq!(status, 200, "{body}");
    };
    document("a", json!({"x": {"integerValue": "10"}}));
    document("b", json!({"x": {"integerValue": "20"}}));
    document("c", json!({"x": {"doubleValue": 0.5}}));
    document("d", json!({"other": {"stringValue": "missing"}}));

    let (status, before) = call(&s, "GET", &format!("{DOCS}/agg/a"), json!({}));
    assert_eq!(status, 200, "{before}");
    let (status, before_missing_field) = call(&s, "GET", &format!("{DOCS}/agg/d"), json!({}));
    assert_eq!(status, 200, "{before_missing_field}");
    let (status, aggregate) = call(
        &s,
        "POST",
        &format!("{DOCS}:runAggregationQuery"),
        json!({
            "structuredAggregationQuery": {
                "structuredQuery": {"from": [{"collectionId": "agg"}]},
                "aggregations": [
                    {"alias": "count", "count": {}},
                    {"alias": "sum", "sum": {"field": {"fieldPath": "x"}}},
                    {"alias": "avg", "avg": {"field": {"fieldPath": "x"}}}
                ]
            }
        }),
    );
    assert_eq!(status, 200, "{aggregate}");
    assert_eq!(
        aggregate[0]["result"]["aggregateFields"]["count"]["integerValue"],
        "3"
    );
    assert_eq!(
        aggregate[0]["result"]["aggregateFields"]["sum"]["doubleValue"],
        30.5
    );
    assert_eq!(
        aggregate[0]["result"]["aggregateFields"]["avg"]["doubleValue"],
        10.166_666_666_666_666
    );

    // The failed precondition is checked before any write is applied. This mirrors the
    // saved production aggregation receipt's refused-commit and unchanged-state cases.
    let (status, refused) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({
            "writes": [
                {"update": {"name": "projects/demo-app/databases/(default)/documents/agg/a", "fields": {"x": {"integerValue": "99"}}}},
                {"update": {"name": "projects/demo-app/databases/(default)/documents/agg/d", "fields": {}}, "currentDocument": {"exists": false}}
            ]
        }),
    );
    assert_eq!(status, 409, "{refused}");
    assert_eq!(refused["error"]["status"], "ALREADY_EXISTS");
    let (status, after) = call(&s, "GET", &format!("{DOCS}/agg/a"), json!({}));
    assert_eq!(status, 200, "{after}");
    assert_eq!(
        after, before,
        "a refused commit must preserve fields and timestamps"
    );
    let (status, after_missing_field) = call(&s, "GET", &format!("{DOCS}/agg/d"), json!({}));
    assert_eq!(status, 200, "{after_missing_field}");
    assert_eq!(
        after_missing_field, before_missing_field,
        "d refused commit must preserve fields and timestamps"
    );

    let (status, aggregate_after) = call(
        &s,
        "POST",
        &format!("{DOCS}:runAggregationQuery"),
        json!({
            "structuredAggregationQuery": {
                "structuredQuery": {"from": [{"collectionId": "agg"}]},
                "aggregations": [{"alias": "sum", "sum": {"field": {"fieldPath": "x"}}}]
            }
        }),
    );
    assert_eq!(status, 200, "{aggregate_after}");
    assert_eq!(
        aggregate_after[0]["result"]["aggregateFields"]["sum"]["doubleValue"],
        30.5
    );

    let (status, transaction_aggregate) = call(
        &s,
        "POST",
        &format!("{DOCS}:runAggregationQuery"),
        json!({
            "structuredAggregationQuery": {
                "structuredQuery": {"from": [{"collectionId": "agg"}]},
                "aggregations": [{"alias": "count", "count": {}}]
            },
            "newTransaction": {"readWrite": {}}
        }),
    );
    assert_eq!(status, 200, "{transaction_aggregate}");
    assert_eq!(transaction_aggregate.as_array().map(Vec::len), Some(1));
    assert_eq!(
        transaction_aggregate[0]["result"]["aggregateFields"]["count"]["integerValue"],
        "4"
    );
    let transaction = transaction_aggregate[0]["transaction"]
        .as_str()
        .expect("REST aggregation announces new transaction")
        .to_owned();
    assert!(!transaction.is_empty());
    let (status, committed) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"transaction": transaction, "writes": []}),
    );
    assert_eq!(status, 200, "{committed}");
    let (status, reused_transaction) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"transaction": transaction, "writes": []}),
    );
    assert_eq!(status, 409, "{reused_transaction}");
    assert_eq!(reused_transaction["error"]["status"], "ABORTED");
}

#[test]
fn rest_find_nearest_without_a_source_is_rejected_before_kindless_scan() {
    let s = state(None);
    let vector = json!({
        "mapValue": {"fields": {
            "__type__": {"stringValue": "__vector__"},
            "value": {"arrayValue": {"values": [{"doubleValue": 0.0}, {"doubleValue": 1.0}]}}
        }}
    });
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:runQuery"),
        json!({"structuredQuery": {
            "findNearest": {
                "vectorField": {"fieldPath": "embedding"},
                "queryVector": vector,
                "distanceMeasure": "COSINE",
                "limit": 1
            }
        }}),
    );
    assert_eq!(status, 501, "{body}");
    assert!(stream_error(&body)["error"]["message"]
        .as_str()
        .unwrap()
        .contains("collection source"));
}

#[test]
fn rest_run_query_supports_standard_find_nearest() {
    let s = state(None);
    let mut indexes = IndexSet::default();
    indexes.add_composite(IndexDefinition {
        collection_group: CollectionId::try_new("items").unwrap(),
        query_scope: IndexQueryScope::Collection,
        fields: vec![IndexField {
            path: FieldPath::parse("embedding").unwrap(),
            mode: IndexFieldMode::Vector { dimension: 2 },
        }],
    });
    s.local
        .replace_project_database_indexes("demo-app", "(default)", indexes);
    let vector = |values: &[f64]| {
        json!({
            "mapValue": {"fields": {
                "__type__": {"stringValue": "__vector__"},
                "value": {"arrayValue": {"values": values.iter().map(|v| json!({"doubleValue": v})).collect::<Vec<_>>()}}
            }}
        })
    };
    for (id, embedding) in [("near", [1.0, 0.0]), ("far", [-1.0, 0.0])] {
        let (status, body) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/items/{id}"),
            json!({"fields": {"embedding": vector(&embedding)}}),
        );
        assert_eq!(status, 200, "{body}");
    }
    let (status, rows) = call(
        &s,
        "POST",
        &format!("{DOCS}:runQuery"),
        json!({"structuredQuery": {
            "from": [{"collectionId": "items"}],
            "findNearest": {
                "vectorField": {"fieldPath": "embedding"},
                "queryVector": vector(&[1.0, 0.0]),
                "distanceMeasure": "EUCLIDEAN",
                "limit": 1,
                "distanceResultField": "distance"
            }
        }}),
    );
    assert_eq!(status, 200, "{rows}");
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0]["document"]["name"]
        .as_str()
        .unwrap()
        .ends_with("/items/near"));
    assert_eq!(
        rows[0]["document"]["fields"]["distance"]["doubleValue"],
        0.0
    );
}

#[test]
fn rest_requests_are_authorized_like_grpc() {
    let s = state(Some(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /open/{id} { allow read, write: if true; } match /closed/{id} { allow read, write: if false; } } }",
    ));
    let (status, _) = call_as(
        &s,
        "PATCH",
        &format!("{DOCS}/open/a"),
        json!({"fields": {"v": {"integerValue": "1"}}}),
        None,
    );
    assert_eq!(status, 200);
    let (status, err) = call_as(
        &s,
        "PATCH",
        &format!("{DOCS}/closed/a"),
        json!({"fields": {}}),
        None,
    );
    assert_eq!(status, 403, "{err}");
    assert_eq!(err["error"]["status"], "PERMISSION_DENIED");
    let (status, _) = call_as(
        &s,
        "PATCH",
        &format!("{DOCS}/closed/a"),
        json!({"fields": {}}),
        Some("Bearer owner"),
    );
    assert_eq!(status, 200, "owner bypasses rules");
    let (status, err) = call_as(
        &s,
        "GET",
        &format!("{DOCS}/closed/a"),
        json!({}),
        Some("Bearer not-a-token"),
    );
    assert_eq!(status, 401, "{err}");
    let (status, _) = call_as(
        &s,
        "POST",
        &format!("{DOCS}:runQuery"),
        json!({"structuredQuery": {"from": [{"collectionId": "closed"}]}}),
        None,
    );
    assert_eq!(status, 403);
}

#[test]
fn rest_consistency_selectors_are_mutually_exclusive() {
    let s = state(None);
    let (status, err) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchGet"),
        json!({"documents": [], "transaction": "AAAA", "readTime": "2026-08-29T12:00:00Z"}),
    );
    assert_eq!(status, 400, "{err}");
    let (status, err) = call(
        &s,
        "POST",
        &format!("{DOCS}:runQuery"),
        json!({"structuredQuery": {"from": [{"collectionId": "n"}]}, "newTransaction": {}, "readTime": "2026-08-29T12:00:00Z"}),
    );
    assert_eq!(status, 400, "{err}");
}

/// The REST surface resolves its caller through the same [`RulesEnforcer`] as gRPC, so the
/// compatibility profile has to reach it too. `createMockUserToken`'s defaults again:
/// `iat: 0`, `exp: 3600`, a subject the Auth store has never heard of.
const OWNER_RULES: &str = "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /owned/{uid} { allow read, write: if request.auth != null && request.auth.uid == uid; } } }";

fn mock_user_token(sub: &str, project: &str) -> String {
    let header = base64url_encode(br#"{"alg":"none","type":"JWT"}"#);
    let payload = base64url_encode(
        format!(
            r#"{{"iss":"https://securetoken.google.com/{project}","aud":"{project}","iat":0,"exp":3600,"auth_time":0,"sub":"{sub}","user_id":"{sub}"}}"#
        )
        .as_bytes(),
    );
    format!("{header}.{payload}.")
}

#[test]
fn the_profile_decides_whether_rest_admits_a_mock_token() {
    let write = json!({"fields": {"v": {"integerValue": "1"}}});
    let bearer = format!("Bearer {}", mock_user_token("alice", "demo-app"));

    let firebase = state_with(Some(OWNER_RULES), TokenAcceptance::EmulatorMock);
    let (status, body) = call_as(
        &firebase,
        "PATCH",
        &format!("{DOCS}/owned/alice"),
        write.clone(),
        Some(&bearer),
    );
    assert_eq!(status, 200, "{body}");
    // Still an identity: another subject's document is denied by the rule, not by the token.
    let (status, _) = call_as(
        &firebase,
        "PATCH",
        &format!("{DOCS}/owned/bob"),
        write.clone(),
        Some(&bearer),
    );
    assert_eq!(status, 403);

    let strict = state_with(Some(OWNER_RULES), TokenAcceptance::Verified);
    let (status, body) = call_as(
        &strict,
        "PATCH",
        &format!("{DOCS}/owned/alice"),
        write,
        Some(&bearer),
    );
    assert_eq!(status, 401, "{body}");
}

#[test]
fn rest_binds_unknown_mock_tokens_to_the_requested_project() {
    let write = json!({"fields": {"v": {"integerValue": "1"}}});
    let bearer = format!("Bearer {}", mock_user_token("alice", "demo-app-w0"));
    let worker_docs = "/v1/projects/demo-app-w0/databases/(default)/documents";

    let firebase = state_with(Some(OWNER_RULES), TokenAcceptance::EmulatorMock);
    let (status, body) = call_as(
        &firebase,
        "PATCH",
        &format!("{worker_docs}/owned/alice"),
        write.clone(),
        Some(&bearer),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = call_as(
        &firebase,
        "PATCH",
        &format!("{DOCS}/owned/alice"),
        write.clone(),
        Some(&bearer),
    );
    assert_eq!(status, 401, "{body}");

    let strict = state_with(Some(OWNER_RULES), TokenAcceptance::Verified);
    let (status, body) = call_as(
        &strict,
        "PATCH",
        &format!("{worker_docs}/owned/alice"),
        write,
        Some(&bearer),
    );
    assert_eq!(status, 401, "{body}");
}

const EMULATOR: &str = "/emulator/v1/projects/demo-app";

fn put_rules(s: &RestState, source: &str) -> (u16, Value) {
    call_as(
        s,
        "PUT",
        &format!("{EMULATOR}:securityRules"),
        json!({"rules": {"files": [{"name": "firestore.rules", "content": source}]}}),
        None,
    )
}

#[test]
fn the_emulator_security_rules_route_replaces_the_ruleset_and_reports_the_compiler() {
    let s = state(Some("rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /{document=**} { allow read, write: if false; }\n  }\n}\n"));
    // The ruleset that is loaded denies everything, with no credential in play.
    let (status, _) = call_as(&s, "GET", &format!("{DOCS}/notes/a"), json!({}), None);
    assert_eq!(status, 403);

    let (status, body) = put_rules(
        &s,
        "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /notes/{id} { allow read: if id != 'secret'; }\n  }\n}\n",
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({}),
        "the official success shape (an empty issue list is left out)"
    );

    let (status, _) = call_as(&s, "GET", &format!("{DOCS}/notes/a"), json!({}), None);
    assert_eq!(status, 404, "allowed, and the document does not exist");
    let (status, _) = call_as(&s, "GET", &format!("{DOCS}/notes/secret"), json!({}), None);
    assert_eq!(status, 403);

    // A source that does not compile is refused, and the previous ruleset stays in force.
    let (status, body) = put_rules(
        &s,
        "service cloud.firestore { match /a/{b} { allow read: if (; } }",
    );
    assert_eq!(status, 400, "{body}");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.starts_with("Error compiling rules:\nL"),
        "{message}"
    );
    let (status, _) = call_as(&s, "GET", &format!("{DOCS}/notes/a"), json!({}), None);
    assert_eq!(status, 404, "the failed load did not open the session up");

    // Only PUT, and only with one file.
    let (status, _) = call_as(
        &s,
        "GET",
        &format!("{EMULATOR}:securityRules"),
        json!({}),
        None,
    );
    assert_eq!(status, 400);
    let (status, _) = call_as(
        &s,
        "PUT",
        &format!("{EMULATOR}:securityRules"),
        json!({"rules": {"files": []}}),
        None,
    );
    assert_eq!(status, 400);
}

#[test]
fn security_rules_publication_waits_for_exclusive_snapshot_work() {
    const DENY: &str = "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if false; } } }";
    const ALLOW: &str = "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if true; } } }";

    let state = Arc::new(state(Some(DENY)));
    let barrier = state.local.barrier();
    let exclusive = barrier.exclusive();
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let worker_state = state.clone();
    let worker = std::thread::spawn(move || {
        started_tx.send(()).expect("signal publication start");
        let result = put_rules(&worker_state, ALLOW);
        finished_tx.send(result).expect("signal publication finish");
    });

    started_rx.recv().expect("publication worker started");
    assert!(
        finished_rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "rules publication must wait while snapshot work owns the exclusive barrier"
    );
    drop(exclusive);
    let (status, body) = finished_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("publication resumes after snapshot work");
    assert_eq!(status, 200, "{body}");
    worker.join().expect("publication worker exits");
}

#[test]
fn the_rule_coverage_route_reports_every_expression_by_its_source_position() {
    let source = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /notes/{id} {\n      allow get: if id != 'secret';\n      allow create: if request.resource.data.n > 0;\n    }\n  }\n}\n";
    let s = state(Some(source));
    for id in ["a", "secret", "a"] {
        call_as(&s, "GET", &format!("{DOCS}/notes/{id}"), json!({}), None);
    }

    let (status, body) = call_as(
        &s,
        "GET",
        &format!("{EMULATOR}:ruleCoverage"),
        json!({}),
        None,
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["rules"]["files"][0]["name"], "firestore.rules");
    assert_eq!(body["rules"]["files"][0]["content"], source);

    let report = body["report"].as_array().expect("a report").clone();
    let condition_at = source.find("id != 'secret'").unwrap();
    let condition = report
        .iter()
        .find(|n| n["sourcePosition"]["currentOffset"] == json!(condition_at))
        .expect("the get condition is a root of the report");
    assert_eq!(condition["sourcePosition"]["line"], 5);
    assert_eq!(
        condition["sourcePosition"]["endOffset"],
        json!(condition_at + "id != 'secret'".len())
    );
    assert_eq!(
        condition["values"],
        json!([
            {"value": {"boolValue": true}, "count": 2},
            {"value": {"boolValue": false}, "count": 1},
        ])
    );
    // `id` is a child, and it took each document id it was asked about.
    assert_eq!(
        condition["children"][0]["values"],
        json!([
            {"value": {"stringValue": "a"}, "count": 2},
            {"value": {"stringValue": "secret"}, "count": 1},
        ])
    );
    // The create condition was never reached: children, no values.
    let create_at = source.find("request.resource.data.n > 0").unwrap();
    let create = report
        .iter()
        .find(|n| n["sourcePosition"]["currentOffset"] == json!(create_at))
        .expect("an unevaluated condition is still in the report");
    assert!(create.get("values").is_none(), "{create}");
    assert!(create["children"].is_array());

    // The HTML report is the same document in a page.
    let (status, body) = call_as(
        &s,
        "GET",
        &format!("{EMULATOR}:ruleCoverage.html"),
        json!({}),
        None,
    );
    assert_eq!(status, 200);
    let html = body[fireemu_adapter_grpc::rest::coverage::HTML_KEY]
        .as_str()
        .expect("an HTML body");
    assert!(html.starts_with("<!DOCTYPE html>"), "{html}");
    assert!(html.contains("Firestore Rule Coverage Report"));
    assert!(html.contains("coverage-expr"));

    // Loading a new ruleset drops the positions that described the old one.
    put_rules(&s, "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /notes/{id} { allow read: if true; }\n  }\n}\n");
    let (_, body) = call_as(
        &s,
        "GET",
        &format!("{EMULATOR}:ruleCoverage"),
        json!({}),
        None,
    );
    for node in body["report"].as_array().cloned().unwrap_or_default() {
        assert!(node.get("values").is_none(), "{node}");
    }
}

#[test]
fn rule_coverage_html_preserves_json_without_allowing_script_termination() {
    let payload = "</ScRiPt><script>alert(1)</script><!--&>\u{2028}\u{2029}";
    let source = format!(
        "rules_version = '2'; service cloud.firestore {{ match /databases/{{db}}/documents {{ match /notes/{{id}} {{ allow get: if id != 'secret'; allow create: if request.resource.data.value != 'blocked'; }} }} }} // {payload}"
    );
    let s = state(Some(&source));
    call_as(&s, "GET", &format!("{DOCS}/notes/a"), json!({}), None);
    let (created, response) = call_as(
        &s,
        "POST",
        &format!("{DOCS}/notes?documentId=payload"),
        json!({"fields": {"value": {"stringValue": payload}}}),
        None,
    );
    assert_eq!(created, 200, "{response}");
    let (_, expected) = call_as(
        &s,
        "GET",
        &format!("{EMULATOR}:ruleCoverage"),
        json!({}),
        None,
    );

    let (status, response) = call_as(
        &s,
        "GET",
        &format!("{EMULATOR}:ruleCoverage.html"),
        json!({}),
        None,
    );
    assert_eq!(status, 200, "{response}");
    let html = response[fireemu_adapter_grpc::rest::coverage::HTML_KEY]
        .as_str()
        .expect("an HTML body");
    assert_eq!(
        html.to_ascii_lowercase().matches("</script").count(),
        1,
        "only the template may close the JSON element"
    );
    let embedded = html
        .split("type=\"application/json\">")
        .nth(1)
        .expect("embedded JSON")
        .split("</script>")
        .next()
        .expect("JSON script content");
    for forbidden in ['<', '>', '&', '\u{2028}', '\u{2029}'] {
        assert!(
            !embedded.contains(forbidden),
            "raw HTML-sensitive character: {forbidden:?}"
        );
    }
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(embedded).expect("valid embedded JSON"),
        expected
    );
}

/// Production Firestore's REST wire, recorded in `conformance/firestore-production-matrix.json`:
/// no `done` marker on the last query element, offsets reported in a leading result-less
/// element, no `nextPageToken` on the last page, and batch results with found documents in
/// name order ahead of the missing ones.
#[test]
fn rest_wire_follows_production_not_the_official_emulator() {
    let s = state(None);
    let (status, _) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": (1..=3).map(|n| json!({"update": {"name": format!("projects/demo-app/databases/(default)/documents/q/{n}"), "fields": {"v": {"integerValue": n.to_string()}}}})).collect::<Vec<_>>()}),
    );
    assert_eq!(status, 200);

    let (status, rows) = call(
        &s,
        "POST",
        &format!("{DOCS}:runQuery"),
        json!({"structuredQuery": {"from": [{"collectionId": "q"}], "orderBy": [{"field": {"fieldPath": "v"}}]}}),
    );
    assert_eq!(status, 200, "{rows}");
    assert_eq!(rows.as_array().unwrap().len(), 3);
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .all(|r| r.get("done").is_none()),
        "production sends no done marker over REST: {rows}"
    );

    let (status, rows) = call(
        &s,
        "POST",
        &format!("{DOCS}:runQuery"),
        json!({"structuredQuery": {"from": [{"collectionId": "q"}], "orderBy": [{"field": {"fieldPath": "v"}}], "offset": 2}}),
    );
    assert_eq!(status, 200, "{rows}");
    assert_eq!(rows[0]["skippedResults"], 2, "{rows}");
    assert!(rows[0].get("document").is_none(), "{rows}");
    assert!(rows[0]["readTime"].is_string());
    assert_eq!(rows[1]["document"]["fields"]["v"]["integerValue"], "3");
    assert!(rows[1].get("skippedResults").is_none());
    assert_eq!(rows.as_array().unwrap().len(), 2);

    let (status, rows) = call(
        &s,
        "POST",
        &format!("{DOCS}:runQuery"),
        json!({"structuredQuery": {"from": [{"collectionId": "q"}], "offset": 10}}),
    );
    assert_eq!(status, 200, "{rows}");
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["skippedResults"], 3, "{rows}");
    assert!(rows[0].get("done").is_none());

    let (status, agg) = call(
        &s,
        "POST",
        &format!("{DOCS}:runAggregationQuery"),
        json!({"structuredAggregationQuery": {"structuredQuery": {"from": [{"collectionId": "q"}]}, "aggregations": [{"alias": "count", "count": {}}]}}),
    );
    assert_eq!(status, 200, "{agg}");
    assert!(agg[0].get("done").is_none(), "{agg}");
}

/// Production issues no `nextPageToken` on the last page (full or not) and answers a batch
/// get with found documents in name order ahead of the missing ones.
#[test]
fn rest_listing_and_batch_get_follow_production() {
    let s = state(None);
    let (status, _) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": (1..=3).map(|n| json!({"update": {"name": format!("projects/demo-app/databases/(default)/documents/q/{n}"), "fields": {"v": {"integerValue": n.to_string()}}}})).collect::<Vec<_>>()}),
    );
    assert_eq!(status, 200);
    let (status, page) = call(&s, "GET", &format!("{DOCS}/q?pageSize=3"), json!({}));
    assert_eq!(status, 200, "{page}");
    assert_eq!(page["documents"].as_array().unwrap().len(), 3);
    assert!(
        page.get("nextPageToken").is_none(),
        "a full last page carries no token: {page}"
    );
    let (status, page) = call(&s, "GET", &format!("{DOCS}/q?pageSize=2"), json!({}));
    assert_eq!(status, 200, "{page}");
    let token = page["nextPageToken"]
        .as_str()
        .expect("more documents follow")
        .to_owned();
    let (status, last) = call(
        &s,
        "GET",
        &format!("{DOCS}/q?pageSize=2&pageToken={token}"),
        json!({}),
    );
    assert_eq!(status, 200, "{last}");
    assert_eq!(last["documents"].as_array().unwrap().len(), 1);
    assert!(last.get("nextPageToken").is_none(), "{last}");

    let (status, ids) = call(
        &s,
        "POST",
        &format!("{DOCS}:listCollectionIds"),
        json!({"pageSize": 1}),
    );
    assert_eq!(status, 200, "{ids}");
    assert_eq!(ids["collectionIds"], json!(["q"]));
    assert!(ids.get("nextPageToken").is_none(), "{ids}");

    let (status, batch) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchGet"),
        json!({"documents": [
            "projects/demo-app/databases/(default)/documents/q/3",
            "projects/demo-app/databases/(default)/documents/q/none",
            "projects/demo-app/databases/(default)/documents/q/1"
        ]}),
    );
    assert_eq!(status, 200, "{batch}");
    let order: Vec<String> = batch
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            r["found"]["name"]
                .as_str()
                .or_else(|| r["missing"].as_str())
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(order, ["1", "3", "none"], "{batch}");
}

#[test]
#[allow(clippy::result_large_err)]
fn malformed_batch_get_documents_is_rejected_without_starting_a_transaction() {
    let s = state(None);
    let parent = fireemu_adapter_grpc::decode::parse_parent(&DOCS[4..]).unwrap();
    let before = s
        .local
        .database_handle(&parent)
        .unwrap()
        .with(|db| Ok(db.transaction_bookkeeping_stats().active))
        .unwrap();

    for documents in [
        json!("projects/demo-app/databases/(default)/documents/q/1"),
        json!(["projects/demo-app/databases/(default)/documents/q/1", 7]),
    ] {
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:batchGet"),
            json!({"documents": documents, "newTransaction": {"readWrite": {}}}),
        );
        assert_eq!(status, 400, "{body}");
        assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");
    }

    let after = s
        .local
        .database_handle(&parent)
        .unwrap()
        .with(|db| Ok(db.transaction_bookkeeping_stats().active))
        .unwrap();
    assert_eq!(
        after, before,
        "shape validation must precede transaction creation"
    );
}

#[test]
#[allow(clippy::result_large_err)]
fn malformed_structured_query_lists_are_rejected_and_valid_arrays_remain_usable() {
    let s = state(None);
    let parent = fireemu_adapter_grpc::decode::parse_parent(&DOCS[4..]).unwrap();
    let active_before = s
        .local
        .database_handle(&parent)
        .unwrap()
        .with(|db| Ok(db.transaction_bookkeeping_stats().active))
        .unwrap();
    for query in [
        json!({"from": "q"}),
        json!({"orderBy": {}}),
        json!({"from": [null]}),
        json!({"orderBy": [1]}),
        json!({"from": [{"collectionId": 1}]}),
        // (`"true"` is a boolean to production's transcoder, so it is not refused here.)
        json!({"from": [{"allDescendants": 1}]}),
        json!({"orderBy": [{"direction": 3}]}),
        json!({"select": "not an object"}),
        json!({"select": {"fields": "not an array"}}),
        json!({"where": {"compositeFilter": {"op": "AND", "filters": "not an array"}}}),
        json!({"startAt": "not an object"}),
        json!({"startAt": {"values": "not an array"}}),
        json!({"startAt": {"before": "not a boolean"}}),
        json!({"endAt": {"values": [null]}}),
    ] {
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:runQuery"),
            json!({"structuredQuery": query, "newTransaction": {"readWrite": {}}}),
        );
        assert_eq!(status, 400, "{body}");
        assert_eq!(
            stream_error(&body)["error"]["status"],
            "INVALID_ARGUMENT",
            "{body}"
        );
    }
    let active_after = s
        .local
        .database_handle(&parent)
        .unwrap()
        .with(|db| Ok(db.transaction_bookkeeping_stats().active))
        .unwrap();
    assert_eq!(active_after, active_before);

    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:runQuery"),
        json!({"structuredQuery": {"from": [{"collectionId": "q"}], "orderBy": []}}),
    );
    assert_eq!(status, 200, "{body}");
}

#[test]
#[allow(clippy::result_large_err)]
fn begin_transaction_rejects_unknown_transaction_option_without_creating_state() {
    let s = state(None);
    let parent = fireemu_adapter_grpc::decode::parse_parent(&DOCS[4..]).unwrap();
    let active_before = s
        .local
        .database_handle(&parent)
        .unwrap()
        .with(|db| Ok(db.transaction_bookkeeping_stats().active))
        .unwrap();

    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readWrite": {"unknown": true}}}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");

    let active_after = s
        .local
        .database_handle(&parent)
        .unwrap()
        .with(|db| Ok(db.transaction_bookkeeping_stats().active))
        .unwrap();
    assert_eq!(
        active_after, active_before,
        "invalid options must not create a transaction"
    );
}

#[test]
#[allow(clippy::result_large_err)]
fn begin_transaction_rejects_unknown_body_without_creating_state() {
    let s = state(None);
    let parent = fireemu_adapter_grpc::decode::parse_parent(&DOCS[4..]).unwrap();
    let active_before = s
        .local
        .database_handle(&parent)
        .unwrap()
        .with(|db| Ok(db.transaction_bookkeeping_stats().active))
        .unwrap();

    for body in [json!({"unexpected": true}), json!([]), Value::Null] {
        let (status, response) = call(&s, "POST", &format!("{DOCS}:beginTransaction"), body);
        assert_eq!(status, 400, "{response}");
        assert_eq!(
            response["error"]["status"], "INVALID_ARGUMENT",
            "{response}"
        );
    }

    let active_after = s
        .local
        .database_handle(&parent)
        .unwrap()
        .with(|db| Ok(db.transaction_bookkeeping_stats().active))
        .unwrap();
    assert_eq!(active_after, active_before);
}

#[test]
fn transaction_option_null_oneof_members_are_unset() {
    let s = state(None);
    for options in [
        json!({"readWrite": {}}),
        json!({"readOnly": null, "readWrite": {}}),
    ] {
        let (status, response) = call(
            &s,
            "POST",
            &format!("{DOCS}:beginTransaction"),
            json!({"options": options}),
        );
        assert_eq!(status, 200, "{response}");
        let token = response["transaction"].as_str().unwrap();
        let (status, rollback) = call(
            &s,
            "POST",
            &format!("{DOCS}:rollback"),
            json!({"transaction": token}),
        );
        assert_eq!(status, 200, "{rollback}");
    }
}

#[test]
fn transaction_option_accepts_concurrency_mode_enum() {
    let s = state(None);
    for mode in ["CONCURRENCY_MODE_UNSPECIFIED", "OPTIMISTIC", "PESSIMISTIC"] {
        let (status, response) = call(
            &s,
            "POST",
            &format!("{DOCS}:beginTransaction"),
            json!({"options": {"readWrite": {"concurrencyMode": mode}}}),
        );
        assert_eq!(status, 200, "{response}");
        let token = response["transaction"].as_str().unwrap();
        let (status, rollback) = call(
            &s,
            "POST",
            &format!("{DOCS}:rollback"),
            json!({"transaction": token}),
        );
        assert_eq!(status, 200, "{rollback}");
    }
}

/// The same refusal for a `bytesValue` inside a written document. Production names the
/// write, the document, the map entry and the proto value field:
/// `Invalid value at 'writes[0].update.fields[0].value.bytes_value' (TYPE_BYTES), Base64
/// decoding failed for "!!!"` (conformance/firestore-production-matrix.json,
/// errors/rest-shapes, `write-bad-base64`, recorded against production 2026-09-07; the
/// probe writes a single field `a`).
#[test]
fn malformed_bytes_value_is_refused_in_productions_wording() {
    let s = state(None);
    let (status, response) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{
            "update": {
                "name": format!("{DOCS}/err/x"),
                "fields": {"a": {"bytesValue": "!!!"}}
            }
        }]}),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(
        response["error"]["status"], "INVALID_ARGUMENT",
        "{response}"
    );
    assert_eq!(
        response["error"]["message"],
        concat!(
            "Invalid value at 'writes[0].update.fields[0].value.bytes_value' (TYPE_BYTES), ",
            "Base64 decoding failed for \"!!!\""
        ),
        "{response}"
    );
}

/// The write index is the position in the request, not a constant.
#[test]
fn a_malformed_bytes_value_names_the_write_it_came_from() {
    let s = state(None);
    let good = json!({
        "update": {"name": format!("{DOCS}/err/first"), "fields": {"a": {"integerValue": "1"}}}
    });
    let bad = json!({
        "update": {"name": format!("{DOCS}/err/second"), "fields": {"a": {"bytesValue": "!!!"}}}
    });
    let (status, response) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [good, bad]}),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(
        response["error"]["message"],
        concat!(
            "Invalid value at 'writes[1].update.fields[0].value.bytes_value' (TYPE_BYTES), ",
            "Base64 decoding failed for \"!!!\""
        ),
        "{response}"
    );
}

/// Production has not been recorded on a nested value, so these paths continue the recorded
/// form with the proto spelling of the nested messages. They are an inference, and this test
/// is where a production observation would land.
#[test]
fn a_nested_malformed_bytes_value_continues_the_recorded_path_form() {
    let s = state(None);
    for (field, expected) in [
        (
            json!({"arrayValue": {"values": [{"integerValue": "1"}, {"bytesValue": "!!!"}]}}),
            "writes[0].update.fields[0].value.array_value.values[1].bytes_value",
        ),
        (
            json!({"mapValue": {"fields": {"inner": {"bytesValue": "!!!"}}}}),
            "writes[0].update.fields[0].value.map_value.fields[0].value.bytes_value",
        ),
    ] {
        let (status, response) = call(
            &s,
            "POST",
            &format!("{DOCS}:commit"),
            json!({"writes": [{
                "update": {"name": format!("{DOCS}/err/x"), "fields": {"a": field}}
            }]}),
        );
        assert_eq!(status, 400, "{response}");
        assert_eq!(
            response["error"]["message"],
            format!(
                "Invalid value at '{expected}' (TYPE_BYTES), Base64 decoding failed for \"!!!\""
            ),
            "{response}"
        );
    }
}

/// A document written through the REST document routes rather than a commit. The request
/// message names the document `document`, which production has not been recorded on.
#[test]
fn a_malformed_bytes_value_in_a_patched_document_names_the_document_field() {
    let s = state(None);
    let (status, response) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/err/x"),
        json!({"fields": {"a": {"bytesValue": "!!!"}}}),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(
        response["error"]["message"],
        concat!(
            "Invalid value at 'document.fields[0].value.bytes_value' (TYPE_BYTES), ",
            "Base64 decoding failed for \"!!!\""
        ),
        "{response}"
    );
}

/// A transform carries values too. Unrecorded, so the path continues the same proto form.
#[test]
fn a_malformed_bytes_value_in_a_transform_names_the_transform() {
    let s = state(None);
    let (status, response) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{
            "transform": {
                "document": format!("{DOCS}/err/x"),
                "fieldTransforms": [{
                    "fieldPath": "a",
                    "appendMissingElements": {"values": [{"bytesValue": "!!!"}]}
                }]
            }
        }]}),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(
        response["error"]["message"],
        concat!(
            "Invalid value at 'writes[0].transform.field_transforms[0]",
            ".append_missing_elements.values[0].bytes_value' (TYPE_BYTES), ",
            "Base64 decoding failed for \"!!!\""
        ),
        "{response}"
    );
}

/// A known difference from production, pinned so it is not mistaken for correct. The map
/// entry index is the position among the parsed `fields`, and this parser holds them sorted
/// by key, while production indexes the entries in the order the request spelled them. The
/// two agree for the single-field document production was recorded on, and disagree here:
/// production would name `fields[1]` for `a`, which is written second.
#[test]
fn the_map_entry_index_follows_this_parsers_field_order() {
    let s = state(None);
    let (status, response) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{
            "update": {
                "name": format!("{DOCS}/err/x"),
                "fields": {"z": {"integerValue": "1"}, "a": {"bytesValue": "!!!"}}
            }
        }]}),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(
        response["error"]["message"],
        concat!(
            "Invalid value at 'writes[0].update.fields[0].value.bytes_value' (TYPE_BYTES), ",
            "Base64 decoding failed for \"!!!\""
        ),
        "{response}"
    );
}

/// Production refuses an undecodable `bytes` field by naming the request field, its proto
/// type and the offending value, rather than with a bare decoder message:
/// `Invalid value at 'transaction' (TYPE_BYTES), Base64 decoding failed for "not base64!"`
/// (conformance/firestore-production-matrix.json, transactions/lifecycle,
/// `commit-with-malformed-transaction`, recorded against production 2026-09-07).
#[test]
fn malformed_transaction_token_is_refused_in_productions_wording() {
    let s = state(None);
    let expected = concat!(
        "Invalid value at 'transaction' (TYPE_BYTES), ",
        "Base64 decoding failed for \"not base64!\""
    );
    for (path, body) in [
        (
            format!("{DOCS}:commit"),
            json!({"writes": [], "transaction": "not base64!"}),
        ),
        (
            format!("{DOCS}:rollback"),
            json!({"transaction": "not base64!"}),
        ),
        (
            format!("{DOCS}:runQuery"),
            json!({"structuredQuery": {"from": [{"collectionId": "tx"}]}, "transaction": "not base64!"}),
        ),
        (
            format!("{DOCS}:batchGet"),
            json!({"documents": [format!("{DOCS}/tx/third")], "transaction": "not base64!"}),
        ),
    ] {
        let (status, response) = call(&s, "POST", &path, body);
        assert_eq!(status, 400, "{path}: {response}");
        assert_eq!(
            stream_error(&response)["error"]["status"],
            "INVALID_ARGUMENT",
            "{path}"
        );
        assert_eq!(
            stream_error(&response)["error"]["message"],
            expected,
            "{path}"
        );
    }
}

/// The same field carried as a query parameter on the two read routes that accept one.
#[test]
fn malformed_transaction_query_parameter_is_refused_in_productions_wording() {
    let s = state(None);
    let expected = concat!(
        "Invalid value at 'transaction' (TYPE_BYTES), ",
        "Base64 decoding failed for \"not base64!\""
    );
    for path in [
        format!("{DOCS}/tx/third?transaction=not%20base64!"),
        format!("{DOCS}/tx?transaction=not%20base64!"),
    ] {
        let (status, response) = call(&s, "GET", &path, Value::Null);
        assert_eq!(status, 400, "{path}: {response}");
        assert_eq!(response["error"]["status"], "INVALID_ARGUMENT", "{path}");
        assert_eq!(response["error"]["message"], expected, "{path}");
    }
}

/// `retryTransaction` is the sibling `bytes` field of the same request family. Production has
/// not been observed on it, so the wording is the observed `transaction` shape with the proto
/// field path this parser is given; the path segment naming follows production's own observed
/// use of proto field names (`writes[0].update.fields[0].value.bytes_value` in the same
/// recorded matrix, errors/rest-shapes).
#[test]
fn malformed_retry_transaction_token_is_refused_in_productions_wording() {
    let s = state(None);
    for (path, body, field) in [
        (
            format!("{DOCS}:beginTransaction"),
            json!({"options": {"readWrite": {"retryTransaction": "not base64!"}}}),
            "options.read_write.retry_transaction",
        ),
        (
            format!("{DOCS}:batchGet"),
            json!({
                "documents": [format!("{DOCS}/tx/third")],
                "newTransaction": {"readWrite": {"retryTransaction": "not base64!"}}
            }),
            "new_transaction.read_write.retry_transaction",
        ),
    ] {
        let expected = format!(
            "Invalid value at '{field}' (TYPE_BYTES), Base64 decoding failed for \"not base64!\""
        );
        let (status, response) = call(&s, "POST", &path, body);
        assert_eq!(status, 400, "{path}: {response}");
        assert_eq!(response["error"]["status"], "INVALID_ARGUMENT", "{path}");
        assert_eq!(response["error"]["message"], expected, "{path}");
    }
}

#[test]
fn begin_transaction_accepts_request_options_with_request_tags() {
    let s = state(None);
    let (status, response) = call(
        &s,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"requestOptions": {"requestTags": ["transaction-test"]}}),
    );
    assert_eq!(status, 200, "{response}");
    let token = response["transaction"].as_str().unwrap();
    let (status, rollback) = call(
        &s,
        "POST",
        &format!("{DOCS}:rollback"),
        json!({"transaction": token}),
    );
    assert_eq!(status, 200, "{rollback}");
}

#[test]
fn rest_protojson_null_fields_and_numeric_order_direction_follow_unset_rules() {
    let s = state(None);
    for query in [
        json!({"from": null, "orderBy": null}),
        // A kindless query may order by `__name__` ascending only.
        json!({"from": [{"collectionId": null, "allDescendants": null}], "orderBy": [{"field": {"fieldPath": "__name__"}, "direction": null}]}),
        json!({"from": [{"collectionId": "c"}], "orderBy": [{"field": {"fieldPath": "v"}, "direction": 1}]}),
        json!({"from": [{"collectionId": "c"}], "orderBy": [{"field": {"fieldPath": "v"}, "direction": 2}]}),
        json!({"from": [{"collectionId": "c"}], "orderBy": [{"field": {"fieldPath": "v"}, "direction": 0}], "where": null, "findNearest": null}),
    ] {
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:runQuery"),
            json!({"structuredQuery": query}),
        );
        assert_eq!(status, 200, "{body}");
    }

    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchWrite"),
        json!({"writes": null, "labels": null}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, json!({}));

    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchGet"),
        json!({"documents": null}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, json!([]));
}

#[test]
fn rest_top_level_null_consistency_selectors_are_unset() {
    let s = state(None);
    let name = "projects/demo-app/databases/(default)/documents/null-selectors/doc";
    let (status, _) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/null-selectors/doc"),
        json!({"fields": {"v": {"integerValue": "1"}}}),
    );
    assert_eq!(status, 200);

    for action in ["batchGet", "runQuery"] {
        let (status, omitted) = call(
            &s,
            "POST",
            &format!("{DOCS}:{action}"),
            if action == "batchGet" {
                json!({"documents": [name]})
            } else {
                json!({"structuredQuery": {"from": [{"collectionId": "null-selectors"}]}})
            },
        );
        assert_eq!(status, 200, "{action} omitted: {omitted}");
        let (status, null) = call(
            &s,
            "POST",
            &format!("{DOCS}:{action}"),
            if action == "batchGet" {
                json!({"documents": [name], "transaction": null, "newTransaction": null, "readTime": null})
            } else {
                json!({"structuredQuery": {"from": [{"collectionId": "null-selectors"}]}, "transaction": null, "newTransaction": null, "readTime": null})
            },
        );
        assert_eq!(status, 200, "{action} null: {null}");
        assert_eq!(null, omitted, "{action} null selectors differ");
    }

    let aggregation = json!({
        "structuredAggregationQuery": {
            "structuredQuery": {"from": [{"collectionId": "null-selectors"}]},
            "aggregations": [{"alias": "count", "count": {}}]
        }
    });
    let (status, omitted) = call(
        &s,
        "POST",
        &format!("{DOCS}:runAggregationQuery"),
        aggregation.clone(),
    );
    assert_eq!(status, 200, "aggregation omitted: {omitted}");
    let (status, null) = call(
        &s,
        "POST",
        &format!("{DOCS}:runAggregationQuery"),
        json!({
            "structuredAggregationQuery": aggregation["structuredAggregationQuery"],
            "transaction": null,
            "newTransaction": null,
            "readTime": null
        }),
    );
    assert_eq!(status, 200, "aggregation null: {null}");
    assert_eq!(null, omitted, "aggregation null selectors differ");

    let (status, omitted) = call(&s, "POST", &format!("{DOCS}:listCollectionIds"), json!({}));
    assert_eq!(status, 200, "{omitted}");
    let (status, null) = call(
        &s,
        "POST",
        &format!("{DOCS}:listCollectionIds"),
        json!({"readTime": null}),
    );
    assert_eq!(status, 200, "{null}");
    assert_eq!(null, omitted);

    for payload in [
        json!({"documents": [name], "transaction": 1}),
        json!({"documents": [name], "newTransaction": "invalid"}),
        json!({"documents": [name], "readTime": 1}),
    ] {
        let (status, body) = call(&s, "POST", &format!("{DOCS}:batchGet"), payload);
        assert_eq!(status, 400, "{body}");
    }
    for payload in [json!({"readTime": 1}), json!({"readTime": "invalid"})] {
        let (status, body) = call(&s, "POST", &format!("{DOCS}:listCollectionIds"), payload);
        assert_eq!(status, 400, "{body}");
    }
}

#[test]
fn rest_accepts_an_empty_document_mask_object() {
    let s = state(None);
    let (status, created) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/masked/doc"),
        json!({"fields": {"kept": {"stringValue": "value"}}}),
    );
    assert_eq!(status, 200, "{created}");

    let (status, response) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchGet"),
        json!({
            "documents": ["projects/demo-app/databases/(default)/documents/masked/doc"],
            "mask": {}
        }),
    );
    assert_eq!(status, 200, "{response}");
    assert_eq!(
        response[0]["found"]["name"],
        "projects/demo-app/databases/(default)/documents/masked/doc"
    );
    assert!(response[0]["found"].get("fields").is_none());
}

#[test]
fn production_update_mask_rejects_a_1500_byte_path_but_accepts_1499() {
    let s = state_with_profile(true);
    let a = "a".repeat(750);
    for (label, field, fields, expected_status) in [
        (
            "nested1499",
            format!("{a}.{}", "b".repeat(748)),
            BTreeMap::from([(
                a.clone(),
                json!({"mapValue": {"fields": BTreeMap::from([("b".repeat(748), json!({"integerValue": "1"}))])}}),
            )]),
            200,
        ),
        (
            "nested1500",
            format!("{a}.{}", "b".repeat(749)),
            BTreeMap::from([(
                a.clone(),
                json!({"mapValue": {"fields": BTreeMap::from([("b".repeat(749), json!({"integerValue": "1"}))])}}),
            )]),
            400,
        ),
        (
            "simple1500",
            "a".repeat(1_500),
            BTreeMap::from([("a".repeat(1_500), json!({"integerValue": "1"}))]),
            400,
        ),
    ] {
        let name = format!("projects/demo-app/databases/(default)/documents/maskbytes/{label}");
        let (status, response) = call(
            &s,
            "POST",
            &format!("{DOCS}:batchWrite"),
            json!({"writes": [{"update": {"name": name, "fields": fields}, "updateMask": {"fieldPaths": [field]}, "currentDocument": {"exists": false}}]}),
        );
        assert_eq!(status, expected_status, "{label}: {response}");
        let (read_status, _) = call(&s, "GET", &format!("{DOCS}/maskbytes/{label}"), json!({}));
        assert_eq!(
            read_status,
            if expected_status == 200 { 200 } else { 404 },
            "{label}"
        );
    }
}

#[test]
fn rest_rejects_non_object_and_unknown_document_masks() {
    let s = state(None);
    let name = "projects/demo-app/databases/(default)/documents/masked/strict";
    let (status, created) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/masked/strict"),
        json!({"fields": {"kept": {"stringValue": "value"}}}),
    );
    assert_eq!(status, 200, "{created}");

    for mask in [
        json!([]),
        json!("invalid"),
        json!(true),
        json!({"fieldPath": []}),
    ] {
        let (status, _) = call(
            &s,
            "POST",
            &format!("{DOCS}:batchGet"),
            json!({"documents": [name], "mask": mask}),
        );
        assert_eq!(status, 400, "mask={mask}");
    }

    let (status, null_mask) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchGet"),
        json!({"documents": [name], "mask": null}),
    );
    assert_eq!(status, 200, "{null_mask}");
    assert_eq!(
        null_mask[0]["found"]["fields"]["kept"]["stringValue"], "value",
        "a null message field is equivalent to an omitted mask"
    );

    for update_mask in [
        json!([]),
        json!("invalid"),
        json!(true),
        json!({"fieldPath": []}),
    ] {
        let (status, _) = call(
            &s,
            "POST",
            &format!("{DOCS}:commit"),
            json!({
                "writes": [{
                    "update": {"name": name, "fields": {"kept": {"stringValue": "changed"}}},
                    "updateMask": update_mask
                }]
            }),
        );
        assert_eq!(status, 400, "updateMask={update_mask}");
    }

    let (status, null_update_mask) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({
            "writes": [{
                "update": {"name": name, "fields": {"kept": {"stringValue": "changed"}}},
                "updateMask": null,
                "currentDocument": null
            }]
        }),
    );
    assert_eq!(status, 200, "{null_update_mask}");

    let (status, changed) = call(&s, "GET", &format!("{DOCS}/masked/strict"), json!({}));
    assert_eq!(status, 200, "{changed}");
    assert_eq!(changed["fields"]["kept"]["stringValue"], "changed");

    let (status, empty_mask_write) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({
            "writes": [{
                "update": {"name": name, "fields": {"kept": {"stringValue": "changed"}}},
                "updateMask": {}
            }]
        }),
    );
    assert_eq!(status, 200, "{empty_mask_write}");
    let (status, after_empty_mask) = call(&s, "GET", &format!("{DOCS}/masked/strict"), json!({}));
    assert_eq!(status, 200, "{after_empty_mask}");
    assert_eq!(after_empty_mask["fields"]["kept"]["stringValue"], "changed");
}

#[test]
fn rest_list_rejects_invalid_page_size_and_show_missing_encodings() {
    let s = state(None);
    let (status, created) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/listed/doc"),
        json!({"fields": {"value": {"integerValue": "1"}}}),
    );
    assert_eq!(status, 200, "{created}");

    for page_size in ["invalid", "-1", "2147483648"] {
        let (status, _) = call(
            &s,
            "GET",
            &format!("{DOCS}/listed?pageSize={page_size}"),
            json!({}),
        );
        assert_eq!(status, 400, "pageSize={page_size}");
    }

    // The front end reads booleans loosely (`1`, `TRUE`, `yes`) and refuses anything else
    // (FS-DATA-WRITE-LIST show-missing rows).
    for show_missing in ["maybe", ""] {
        let (status, _) = call(
            &s,
            "GET",
            &format!("{DOCS}/listed?showMissing={show_missing}"),
            json!({}),
        );
        assert_eq!(status, 400, "showMissing={show_missing:?}");
    }

    let (status, baseline) = call(&s, "GET", &format!("{DOCS}/listed"), json!({}));
    assert_eq!(status, 200, "{baseline}");
    for query in [
        "pageSize=0",
        "pageSize=1",
        "pageSize=2147483647",
        "showMissing=false",
        "showMissing=false&orderBy=__name__",
        "showMissing=true&orderBy=",
        "showMissing=1",
        "showMissing=TRUE",
    ] {
        let (status, body) = call(&s, "GET", &format!("{DOCS}/listed?{query}"), json!({}));
        assert_eq!(status, 200, "{query}: {body}");
    }
    let (status, after) = call(&s, "GET", &format!("{DOCS}/listed"), json!({}));
    assert_eq!(status, 200, "{after}");
    assert_eq!(
        after, baseline,
        "refused requests must not change listed data"
    );
}

/// A repeated scalar parameter takes its last value, as production's front end does
/// (FS-DATA-WRITE-LIST paging#page-size-twice); the value is then checked as usual.
#[test]
fn rest_list_takes_the_last_value_of_a_repeated_scalar_parameter() {
    let s = state(None);
    let (status, created) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/duplicates/doc"),
        json!({"fields": {"value": {"integerValue": "1"}}}),
    );
    assert_eq!(status, 200, "{created}");

    for query in [
        "pageSize=1&pageSize=invalid",
        "showMissing=true&orderBy=&orderBy=__name__",
        "readTime=one&readTime=two",
    ] {
        let (status, _) = call(&s, "GET", &format!("{DOCS}/duplicates?{query}"), json!({}));
        assert_eq!(status, 400, "{query}");
    }
    for query in [
        "pageSize=invalid&pageSize=1",
        "showMissing=false&showMissing=TRUE",
        "orderBy=&orderBy=__name__",
    ] {
        let (status, body) = call(&s, "GET", &format!("{DOCS}/duplicates?{query}"), json!({}));
        assert_eq!(status, 200, "{query}: {body}");
    }

    let (status, valid) = call(&s, "GET", &format!("{DOCS}/duplicates"), json!({}));
    assert_eq!(status, 200, "{valid}");
    assert_eq!(valid["documents"].as_array().map(Vec::len), Some(1));
}

#[test]
fn rest_list_refuses_a_malformed_last_page_token_without_fault_or_state_change() {
    use fireemu_core_session::fault::{
        FaultAction, FaultMatch, FaultPlan, FaultRegistry, FaultRule,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (s, clock) = state_with_clock(None, TokenAcceptance::Verified);
    for id in ["a", "b"] {
        let (status, created) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/token/{id}"),
            json!({"fields": {"value": {"stringValue": id}}}),
        );
        assert_eq!(status, 200, "{created}");
    }
    let (status, baseline) = call(&s, "GET", &format!("{DOCS}/token"), json!({}));
    assert_eq!(status, 200, "{baseline}");
    let (status, first_page) = call(&s, "GET", &format!("{DOCS}/token?pageSize=1"), json!({}));
    assert_eq!(status, 200, "{first_page}");
    let token = first_page["nextPageToken"].as_str().unwrap().to_owned();

    let fault_callbacks = Arc::new(AtomicUsize::new(0));
    let callback_counter = Arc::clone(&fault_callbacks);
    s.local.set_clock_observer(Arc::new(move || {
        callback_counter.fetch_add(1, Ordering::SeqCst);
    }));
    let registry = Arc::new(FaultRegistry::new());
    registry.default_state().lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "firestore.read".into(),
                nth: None,
                function: None,
                event_type: None,
            },
            action: FaultAction::Delay { seconds: 90 },
        }],
    });
    s.local.set_faults(registry);
    let clock_before = clock.lock().unwrap().now_for_test();
    let (status, _) = call(
        &s,
        "GET",
        &format!("{DOCS}/token?pageSize=1&pageToken=a&pageToken=b"),
        json!({}),
    );
    assert_eq!(status, 400);
    assert_eq!(clock.lock().unwrap().now_for_test(), clock_before);
    assert_eq!(fault_callbacks.load(Ordering::SeqCst), 0);

    s.local.set_faults(Arc::new(FaultRegistry::new()));
    let (status, single_page) = call(
        &s,
        "GET",
        &format!("{DOCS}/token?pageSize=1&pageToken={token}"),
        json!({}),
    );
    assert_eq!(status, 200, "{single_page}");
    assert_eq!(single_page["documents"].as_array().map(Vec::len), Some(1));
    let (status, after) = call(&s, "GET", &format!("{DOCS}/token"), json!({}));
    assert_eq!(status, 200, "{after}");
    assert_eq!(after["documents"], baseline["documents"]);
}

#[test]
#[allow(clippy::too_many_lines)]
fn rest_list_collection_ids_validates_body_and_honors_read_time() {
    let (s, clock) = state_with_clock(None, TokenAcceptance::Verified);
    let (status, first) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/first/doc"),
        json!({"fields": {"value": {"integerValue": "1"}}}),
    );
    assert_eq!(status, 200, "{first}");
    let read_time = first["updateTime"].as_str().unwrap().to_owned();

    clock
        .lock()
        .unwrap()
        .advance(fireemu_core_types::time::LogicalDuration::from_seconds(1))
        .unwrap();
    let (status, second) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/second/doc"),
        json!({"fields": {"value": {"integerValue": "2"}}}),
    );
    assert_eq!(status, 200, "{second}");
    clock
        .lock()
        .unwrap()
        .advance(fireemu_core_types::time::LogicalDuration::from_seconds(1))
        .unwrap();
    let (status, descendant) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/missing-parent/sub/children/doc"),
        json!({"fields": {"value": {"integerValue": "3"}}}),
    );
    assert_eq!(status, 200, "{descendant}");
    let descendant_time = descendant["updateTime"].as_str().unwrap().to_owned();
    let (status, _) = call(&s, "DELETE", &format!("{DOCS}/second/doc"), json!({}));
    assert_eq!(status, 200);
    let (status, after_delete) = call(&s, "POST", &format!("{DOCS}:listCollectionIds"), json!({}));
    assert_eq!(status, 200, "{after_delete}");
    assert_eq!(
        after_delete["collectionIds"],
        json!(["first", "missing-parent"])
    );
    let (status, before_delete) = call(
        &s,
        "POST",
        &format!("{DOCS}:listCollectionIds"),
        json!({"readTime": descendant_time}),
    );
    assert_eq!(status, 200, "{before_delete}");
    assert_eq!(
        before_delete["collectionIds"],
        json!(["first", "missing-parent", "second"])
    );
    let (status, recreated) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/second/new"),
        json!({"fields": {"value": {"integerValue": "4"}}}),
    );
    assert_eq!(status, 200, "{recreated}");

    let (status, latest) = call(&s, "POST", &format!("{DOCS}:listCollectionIds"), json!({}));
    assert_eq!(status, 200, "{latest}");
    assert_eq!(
        latest["collectionIds"],
        json!(["first", "missing-parent", "second"])
    );
    let (status, first_page) = call(
        &s,
        "POST",
        &format!("{DOCS}:listCollectionIds"),
        json!({"pageSize": 1}),
    );
    assert_eq!(status, 200, "{first_page}");
    let token = first_page["nextPageToken"].as_str().unwrap().to_owned();
    let (status, second_page) = call(
        &s,
        "POST",
        &format!("{DOCS}:listCollectionIds"),
        json!({"pageSize": 1, "pageToken": token}),
    );
    assert_eq!(status, 200, "{second_page}");
    assert_eq!(second_page["collectionIds"], json!(["missing-parent"]));
    let (status, historical) = call(
        &s,
        "POST",
        &format!("{DOCS}:listCollectionIds"),
        json!({"readTime": read_time}),
    );
    assert_eq!(status, 200, "{historical}");
    assert_eq!(historical["collectionIds"], json!(["first"]));
    // A token is a cursor of collection ids, continued at another read time as production
    // continues it (FS-DATA-WRITE-LIST read-time#collection-ids-paged-at-write-1-next-without-
    // read-time).
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:listCollectionIds"),
        json!({"pageSize": 1, "pageToken": token, "readTime": read_time}),
    );
    assert_eq!((status, &body), (200, &json!({})));

    for body in [
        json!({"unknown": true}),
        json!({"pageSize": []}),
        json!({"pageToken": 1}),
        json!({"pageToken": "eg=="}),
        json!({"readTime": "not-a-timestamp"}),
        json!({"requestOptions": []}),
        json!({"requestOptions": {"unknown": true}}),
        json!({"requestOptions": {"requestTags": [1]}}),
    ] {
        let (status, _) = call(&s, "POST", &format!("{DOCS}:listCollectionIds"), body);
        assert_eq!(status, 400);
    }
    let (status, after) = call(&s, "POST", &format!("{DOCS}:listCollectionIds"), json!({}));
    assert_eq!(status, 200, "{after}");
    assert_eq!(after, latest);
}

#[test]
fn rest_negative_page_size_refusal_does_not_move_clock_or_change_state() {
    use fireemu_core_session::fault::{
        FaultAction, FaultMatch, FaultPlan, FaultRegistry, FaultRule,
    };

    for page_size in ["invalid", "-1", "2147483648"] {
        let (s, clock) = state_with_clock(None, TokenAcceptance::Verified);
        let (status, created) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/negative/doc"),
            json!({"fields": {"value": {"integerValue": "1"}}}),
        );
        assert_eq!(status, 200, "{created}");
        let (status, before) = call(&s, "GET", &format!("{DOCS}/negative"), json!({}));
        assert_eq!(status, 200, "{before}");

        let registry = Arc::new(FaultRegistry::new());
        registry.default_state().lock().unwrap().install(FaultPlan {
            seed: 1,
            rules: vec![FaultRule {
                matches: FaultMatch {
                    operation: "firestore.read".into(),
                    nth: None,
                    function: None,
                    event_type: None,
                },
                action: FaultAction::Delay { seconds: 90 },
            }],
        });
        s.local.set_faults(registry);
        let clock_before = clock.lock().unwrap().now_for_test();
        let (status, _) = call(
            &s,
            "GET",
            &format!("{DOCS}/negative?pageSize={page_size}"),
            json!({}),
        );
        assert_eq!(status, 400, "pageSize={page_size}");
        assert_eq!(clock.lock().unwrap().now_for_test(), clock_before);

        s.local.set_faults(Arc::new(FaultRegistry::new()));
        let (status, after) = call(&s, "GET", &format!("{DOCS}/negative"), json!({}));
        assert_eq!(status, 200, "{after}");
        assert_eq!(after["documents"], before["documents"]);
    }
}

#[test]
fn rest_list_rejects_show_missing_with_order_by() {
    let s = state(None);
    let (status, created) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/ordered/doc"),
        json!({"fields": {"value": {"integerValue": "1"}}}),
    );
    assert_eq!(status, 200, "{created}");

    let (status, _) = call(
        &s,
        "GET",
        &format!("{DOCS}/ordered?showMissing=true&orderBy=__name__"),
        json!({}),
    );
    assert_eq!(status, 400);

    let (status, body) = call(
        &s,
        "GET",
        &format!("{DOCS}/ordered?showMissing=true"),
        json!({}),
    );
    assert_eq!(status, 200, "{body}");
}

/// Validation answers where production and the official emulator disagree: fireemu follows
/// production (conformance/firestore-production-matrix.json, `errors/rest-shapes`,
/// `transactions`, `read-time`).
#[test]
fn rest_validation_codes_follow_production() {
    let s = state(None);
    let (status, _) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/q/1"),
        json!({"fields": {"tags": {"arrayValue": {"values": [{"stringValue": "a"}]}}}}),
    );
    assert_eq!(status, 200);

    // Two array-contains clauses: INVALID_ARGUMENT in production's words, not the official
    // emulator's FAILED_PRECONDITION.
    let contains = |v: &str| json!({"fieldFilter": {"field": {"fieldPath": "tags"}, "op": "ARRAY_CONTAINS", "value": {"stringValue": v}}});
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:runQuery"),
        json!({"structuredQuery": {"from": [{"collectionId": "q"}], "where": {"compositeFilter": {"op": "AND", "filters": [contains("a"), contains("b")]}}}}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        stream_error(&body)["error"]["status"],
        "INVALID_ARGUMENT",
        "{body}"
    );
    assert_eq!(
        stream_error(&body)["error"]["message"],
        "A maximum of 1 'ARRAY_CONTAINS' filter is allowed per disjunction.",
        "{body}"
    );

    // A read_time before the database was created is INVALID_ARGUMENT.
    let (status, body) = call(
        &s,
        "GET",
        &format!("{DOCS}/q/1?readTime=2020-01-01T00:00:00Z"),
        Value::Null,
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        stream_error(&body)["error"]["status"],
        "INVALID_ARGUMENT",
        "{body}"
    );
    assert_eq!(
        stream_error(&body)["error"]["message"],
        "The requested 'read_time' cannot be before database creation time.",
        "{body}"
    );

    // A database id production never creates is a database that does not exist.
    let (status, body) = call(
        &s,
        "GET",
        "/v1/projects/demo-app/databases/Upper/documents/q/1",
        Value::Null,
    );
    assert_eq!(status, 404, "{body}");
    assert_eq!(
        stream_error(&body)["error"]["status"],
        "NOT_FOUND",
        "{body}"
    );
    assert_eq!(
        stream_error(&body)["error"]["message"],
        missing_database_message("Upper"),
        "{body}"
    );

    // A read-only transaction cannot be committed, even without writes.
    let (status, begun) = call(
        &s,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readOnly": {}}}),
    );
    assert_eq!(status, 200, "{begun}");
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"transaction": begun["transaction"], "writes": []}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        stream_error(&body)["error"]["status"],
        "INVALID_ARGUMENT",
        "{body}"
    );
    assert!(
        stream_error(&body)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no longer valid"),
        "{body}"
    );
}

/// A query without a collection selector, or with an empty collection id, scans every document
/// under the parent, as production and the official emulator both do; more field transforms
/// than production accepts on one document are refused in every profile.
#[test]
fn rest_kindless_queries_and_transform_budget_follow_production() {
    let s = state(None);
    for (collection, id) in [("a", "1"), ("b", "2")] {
        let (status, _) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/{collection}/{id}"),
            json!({"fields": {"v": {"stringValue": id}}}),
        );
        assert_eq!(status, 200);
    }
    for query in [
        json!({"structuredQuery": {}}),
        json!({"structuredQuery": {"from": [{"collectionId": ""}]}}),
        json!({"structuredQuery": {"from": [{"collectionId": "", "allDescendants": true}]}}),
    ] {
        let (status, rows) = call(&s, "POST", &format!("{DOCS}:runQuery"), query.clone());
        assert_eq!(status, 200, "{query}: {rows}");
        let names: Vec<&str> = rows
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| row["document"]["name"].as_str())
            .collect();
        assert_eq!(
            names,
            [
                "projects/demo-app/databases/(default)/documents/a/1",
                "projects/demo-app/databases/(default)/documents/b/2",
            ],
            "{query}: {rows}"
        );
    }

    let transforms = |n: usize| {
        (0..n)
            .map(|i| json!({"fieldPath": format!("f{i}"), "increment": {"integerValue": "1"}}))
            .collect::<Vec<_>>()
    };
    let write = |n: usize| json!({"writes": [{"update": {"name": "projects/demo-app/databases/(default)/documents/t/1", "fields": {}}, "updateTransforms": transforms(n)}]});
    let (status, body) = call(&s, "POST", &format!("{DOCS}:commit"), write(500));
    assert_eq!(status, 200, "{body}");
    let (status, body) = call(&s, "POST", &format!("{DOCS}:commit"), write(501));
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");
    assert_eq!(
        body["error"]["message"], "cannot have more than 500 field transforms on a single document",
        "{body}"
    );
}

#[test]
fn an_idle_rest_transaction_expires_and_releases_its_document_lock() {
    let (s, clock) = state_with_clock(None, TokenAcceptance::Verified);
    let document = "projects/demo-app/databases/(default)/documents/expiry/doc";
    let (status, seeded) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/expiry/doc"),
        json!({"fields": {"v": {"integerValue": "1"}}}),
    );
    assert_eq!(status, 200, "{seeded}");

    let (status, begun) = call(
        &s,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readWrite": {}}}),
    );
    assert_eq!(status, 200, "{begun}");
    let transaction = begun["transaction"].as_str().unwrap().to_owned();
    let (status, held) = call(
        &s,
        "GET",
        &format!("{DOCS}/expiry/doc?transaction={transaction}"),
        Value::Null,
    );
    assert_eq!(status, 200, "{held}");

    let _ = clock
        .lock()
        .unwrap()
        .advance(fireemu_core_types::time::LogicalDuration::from_seconds(61));
    let (status, expired) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({
            "transaction": transaction,
            "writes": [{"update": {"name": document, "fields": {"v": {"integerValue": "2"}}}}]
        }),
    );
    assert_eq!(status, 409, "{expired}");
    assert_eq!(expired["error"]["status"], "ABORTED");
    let (status, after_expiry) = call(&s, "GET", &format!("{DOCS}/expiry/doc"), Value::Null);
    assert_eq!(status, 200, "{after_expiry}");
    assert_eq!(after_expiry["fields"]["v"]["integerValue"], "1");

    let (status, released) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/expiry/doc"),
        json!({"fields": {"v": {"integerValue": "3"}}}),
    );
    assert_eq!(status, 200, "{released}");
    let (status, after) = call(&s, "GET", &format!("{DOCS}/expiry/doc"), Value::Null);
    assert_eq!(status, 200, "{after}");
    assert_eq!(after["fields"]["v"]["integerValue"], "3");
}

/// Over REST the contended writer blocks its (blocking-pool) thread until the transaction
/// finishes, then goes through.
#[test]
fn a_contended_rest_commit_waits_for_the_transaction_to_finish() {
    contended_rest_commit_waits(false);
}

#[test]
fn a_phantom_rest_write_succeeds_after_the_query_transaction_finishes() {
    contended_rest_commit_waits(true);
}

#[test]
#[allow(clippy::too_many_lines)]
fn rest_retry_transaction_starts_fresh_transaction_and_replay_is_refused() {
    let s = state(None);
    let locked = "projects/demo-app/databases/(default)/documents/retry-contention/locked";
    let (status, seeded) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/retry-contention/locked"),
        json!({"fields": {"v": {"integerValue": "1"}}}),
    );
    assert_eq!(status, 200, "{seeded}");

    let begin = || {
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:beginTransaction"),
            json!({"options": {"readWrite": {}}}),
        );
        assert_eq!(status, 200, "{body}");
        body["transaction"].as_str().unwrap().to_owned()
    };
    let first = begin();
    let second = begin();
    for transaction in [&first, &second] {
        let (status, body) = call(
            &s,
            "GET",
            &format!("{DOCS}/retry-contention/locked?transaction={transaction}"),
            Value::Null,
        );
        assert_eq!(status, 200, "{body}");
    }

    let (status, first_error) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({
            "transaction": first,
            "writes": [{"update": {"name": locked, "fields": {"v": {"integerValue": "2"}}}}]
        }),
    );
    assert_eq!(status, 409, "{first_error}");
    assert_eq!(first_error["error"]["status"], "ABORTED");
    let (status, after_first_abort) = call(
        &s,
        "GET",
        &format!("{DOCS}/retry-contention/locked"),
        Value::Null,
    );
    assert_eq!(status, 200, "{after_first_abort}");
    assert_eq!(after_first_abort["fields"]["v"]["integerValue"], "1");

    let (status, second_error) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({
            "transaction": second,
            "writes": [{"update": {"name": locked, "fields": {"v": {"integerValue": "3"}}}}]
        }),
    );
    assert_eq!(status, 409, "{second_error}");
    assert_eq!(second_error["error"]["status"], "ABORTED");
    let (status, after_second_abort) = call(
        &s,
        "GET",
        &format!("{DOCS}/retry-contention/locked"),
        Value::Null,
    );
    assert_eq!(status, 200, "{after_second_abort}");
    assert_eq!(after_second_abort["fields"]["v"]["integerValue"], "1");

    let (status, retried) = call(
        &s,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readWrite": {"retryTransaction": second}}}),
    );
    assert_eq!(status, 200, "{retried}");
    let fresh = retried["transaction"].as_str().unwrap();
    assert!(!fresh.is_empty());
    assert_ne!(fresh, second);

    let (status, replay) = call(
        &s,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readWrite": {"retryTransaction": second}}}),
    );
    assert_eq!(status, 400, "{replay}");
    assert_eq!(replay["error"]["status"], "INVALID_ARGUMENT");

    let (status, first_rolled_back) = call(
        &s,
        "POST",
        &format!("{DOCS}:rollback"),
        json!({"transaction": first}),
    );
    assert_eq!(status, 200, "{first_rolled_back}");

    let (status, fresh_read) = call(
        &s,
        "GET",
        &format!("{DOCS}/retry-contention/locked?transaction={fresh}"),
        Value::Null,
    );
    assert_eq!(status, 200, "{fresh_read}");
    assert_eq!(fresh_read["fields"]["v"]["integerValue"], "1");

    let (status, fresh_commit) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({
            "transaction": fresh,
            "writes": [{"update": {"name": locked, "fields": {"v": {"integerValue": "4"}}}}]
        }),
    );
    assert_eq!(status, 200, "{fresh_commit}");
    assert_eq!(
        fresh_commit["writeResults"].as_array().map(Vec::len),
        Some(1)
    );

    let (status, after_fresh_commit) = call(
        &s,
        "GET",
        &format!("{DOCS}/retry-contention/locked"),
        Value::Null,
    );
    assert_eq!(status, 200, "{after_fresh_commit}");
    assert_eq!(after_fresh_commit["fields"]["v"]["integerValue"], "4");
}

fn contended_rest_commit_waits(query_lock: bool) {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let local = Arc::new(
        LocalBackend::new(gateway.clone(), clock, 7).with_contention_wait(Duration::from_secs(10)),
    );
    let s = RestState {
        local,
        gateway: Arc::new(gateway),
        rules: None,
        app_check: None,
        control_token: None,
    };
    let (status, begun) = call(
        &s,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readWrite": {}}}),
    );
    assert_eq!(status, 200, "{begun}");
    let txn = begun["transaction"].clone();
    let (status, _) = if query_lock {
        call(
            &s,
            "POST",
            &format!("{DOCS}:runQuery"),
            json!({"transaction": txn, "structuredQuery": {"from": [{"collectionId": "blocked"}]}}),
        )
    } else {
        call(
            &s,
            "GET",
            &format!("{DOCS}/blocked/doc?transaction={}", txn.as_str().unwrap()),
            Value::Null,
        )
    };
    assert_eq!(status, if query_lock { 200 } else { 404 });
    let started = std::time::Instant::now();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(200));
            let (status, body) = call(
                &s,
                "POST",
                &format!("{DOCS}:commit"),
                json!({"transaction": txn, "writes": [{"update": {"name": "projects/demo-app/databases/(default)/documents/blocked/doc", "fields": {"v": {"integerValue": "1"}}}}]}),
            );
            assert_eq!(status, 200, "{body}");
        });
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:commit"),
            json!({"writes": [{"update": {"name": "projects/demo-app/databases/(default)/documents/blocked/doc", "fields": {"v": {"integerValue": "2"}}}}]}),
        );
        assert_eq!(status, 200, "{body}");
    });
    assert!(started.elapsed() < Duration::from_secs(5));
    let (_, doc) = call(&s, "GET", &format!("{DOCS}/blocked/doc"), Value::Null);
    assert_eq!(doc["fields"]["v"]["integerValue"], "2", "{doc}");
}

/// A read at the commit time a commit just reported is served, even when the commit time was
/// aligned past a clock that did not move (production serves it; the official emulator's REST
/// adapter misparses `?readTime=`).
#[test]
fn a_read_at_the_latest_commit_time_is_served() {
    let s = state(None);
    let (status, first) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/rt/a"),
        json!({"fields": {"v": {"integerValue": "1"}}}),
    );
    assert_eq!(status, 200, "{first}");
    let (status, second) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{"update": {"name": "projects/demo-app/databases/(default)/documents/rt/a", "fields": {"v": {"integerValue": "2"}}}}]}),
    );
    assert_eq!(status, 200, "{second}");
    let commit_time = second["commitTime"].as_str().unwrap();
    assert_ne!(commit_time, first["updateTime"].as_str().unwrap());
    let (status, at_second) = call(
        &s,
        "GET",
        &format!("{DOCS}/rt/a?readTime={commit_time}"),
        Value::Null,
    );
    assert_eq!(status, 200, "{at_second}");
    assert_eq!(at_second["fields"]["v"]["integerValue"], "2");
    let (status, at_first) = call(
        &s,
        "GET",
        &format!(
            "{DOCS}/rt/a?readTime={}",
            first["updateTime"].as_str().unwrap()
        ),
        Value::Null,
    );
    assert_eq!(status, 200, "{at_first}");
    assert_eq!(at_first["fields"]["v"]["integerValue"], "1");
    // Past the latest commit is still the future.
    let (status, body) = call(
        &s,
        "GET",
        &format!("{DOCS}/rt/a?readTime=2030-01-01T00:00:00Z"),
        Value::Null,
    );
    assert_eq!(status, 400, "{body}");
}

/// The REST connection task runs a request on a blocking-pool thread with waits disabled:
/// a contended write comes back at once, flagged, and the task waits for a release without
/// holding the pool slot; a release wakes that wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rest_request_does_not_wait_for_locks_on_the_blocking_pool_thread() {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let local = Arc::new(
        LocalBackend::new(gateway.clone(), clock, 7).with_contention_wait(Duration::from_secs(30)),
    );
    let s = Arc::new(RestState {
        local: local.clone(),
        gateway: Arc::new(gateway),
        rules: None,
        app_check: None,
        control_token: None,
    });
    let (status, begun) = call(
        &s,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readWrite": {}}}),
    );
    assert_eq!(status, 200, "{begun}");
    let txn = begun["transaction"].as_str().unwrap().to_owned();
    let (status, _) = call(
        &s,
        "GET",
        &format!("{DOCS}/pool/doc?transaction={txn}"),
        Value::Null,
    );
    assert_eq!(status, 404);

    let seen = local.release_count();
    let started = std::time::Instant::now();
    let attempt = Arc::clone(&s);
    let ((status, body), contended) = tokio::task::spawn_blocking(move || {
        LocalBackend::without_waiting(|| {
            call(
                &attempt,
                "POST",
                &format!("{DOCS}:commit"),
                json!({"writes": [{"update": {"name": "projects/demo-app/databases/(default)/documents/pool/doc", "fields": {"v": {"integerValue": "1"}}}}]}),
            )
        })
    })
    .await
    .unwrap();
    assert!(contended);
    assert_eq!(status, 409, "{body}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the pool thread did not wait out the contention"
    );

    // The task-side wait wakes when the holder finishes.
    let releaser = Arc::clone(&s);
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (status, _) = call(
            &releaser,
            "POST",
            &format!("{DOCS}:rollback"),
            json!({"transaction": txn}),
        );
        assert_eq!(status, 200);
    });
    let wait_started = std::time::Instant::now();
    let wait_deadline = wait_started + Duration::from_secs(10);
    let woke = local.await_any_release(seen, wait_deadline).await;
    assert!(woke);
    assert!(wait_started.elapsed() >= Duration::from_millis(100));
    assert!(wait_started.elapsed() < Duration::from_secs(10));
    assert!(started.elapsed() < Duration::from_secs(5));
    release.await.unwrap();
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{"update": {"name": "projects/demo-app/databases/(default)/documents/pool/doc", "fields": {"v": {"integerValue": "1"}}}}]}),
    );
    assert_eq!(status, 200, "{body}");

    let no_release_started = std::time::Instant::now();
    let no_release = local
        .await_any_release(
            local.release_count(),
            std::time::Instant::now() + Duration::from_millis(100),
        )
        .await;
    assert!(!no_release);
    assert!(no_release_started.elapsed() >= Duration::from_millis(80));
}

/// Saved production bc38f392: this runQuery validation error uses a stream envelope.
#[test]
fn negative_limit_query_error_is_a_single_array_element() {
    let s = state(None);
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:runQuery"),
        json!({"structuredQuery":{"from":[{"collectionId":"broad"}],"limit":-1}}),
    );
    assert_eq!(status, 400);
    assert_eq!(body.as_array().map(Vec::len), Some(1));
    assert_eq!(body[0]["error"]["status"], "INVALID_ARGUMENT");
    for limit in [0, 1] {
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:runQuery"),
            json!({"structuredQuery":{"from":[{"collectionId":"broad"}],"limit":limit}}),
        );
        assert_eq!(status, 200, "{body}");
    }
}

fn explain_body(aggregation: bool, analyze: bool) -> Value {
    let query = json!({"from": [{"collectionId": "items"}], "offset": 2});
    if aggregation {
        json!({"structuredAggregationQuery": {"structuredQuery": query, "aggregations": [{"alias": "count", "count": {}}]}, "explainOptions": {"analyze": analyze}})
    } else {
        json!({"structuredQuery": query, "explainOptions": {"analyze": analyze}})
    }
}

fn explain_method(aggregation: bool) -> &'static str {
    if aggregation {
        "runAggregationQuery"
    } else {
        "runQuery"
    }
}

#[test]
fn explain_rest_plan_and_analyze_return_only_requested_data_and_one_metrics_object() {
    let s = state(None);
    for index in 0..5 {
        assert_eq!(
            call(
                &s,
                "PATCH",
                &format!("{DOCS}/items/{index}"),
                json!({"fields": {}})
            )
            .0,
            200
        );
    }
    for aggregation in [false, true] {
        for analyze in [false, true] {
            let (status, body) = call(
                &s,
                "POST",
                &format!("{DOCS}:{}", explain_method(aggregation)),
                explain_body(aggregation, analyze),
            );
            assert_eq!(status, 200, "{body}");
            let rows = body.as_array().unwrap();
            let metrics: Vec<_> = rows
                .iter()
                .filter_map(|row| row.get("explainMetrics"))
                .collect();
            assert_eq!(metrics.len(), 1, "{body}");
            if analyze {
                assert!(rows.iter().all(|row| row["readTime"].is_string()), "{body}");
                assert_eq!(
                    metrics[0]["executionStats"]["resultsReturned"],
                    if aggregation { "1" } else { "3" }
                );
            } else {
                assert_eq!(rows.len(), 1);
                assert!(metrics[0].get("executionStats").is_none());
                for row in rows {
                    assert!(row.get("document").is_none());
                    assert!(row.get("result").is_none());
                    assert!(row.get("readTime").is_none(), "{body}");
                }
            }
        }
    }
}

#[test]
fn explain_rest_plan_only_new_and_existing_transactions_can_be_rolled_back() {
    let s = state(None);
    for aggregation in [false, true] {
        for options in [json!({"readOnly": {}}), json!({"readWrite": {}})] {
            let mut request = explain_body(aggregation, false);
            request["newTransaction"] = options;
            let path = format!("{DOCS}:{}", explain_method(aggregation));
            let (status, body) = call(&s, "POST", &path, request);
            assert_eq!(status, 200, "{body}");
            let token = body[0]["transaction"].as_str().unwrap();
            if !aggregation {
                assert_eq!(body.as_array().unwrap().len(), 2);
                assert_eq!(body[0], json!({"transaction": token}));
                assert_eq!(
                    body[1],
                    json!({"explainMetrics": {"planSummary": {"indexesUsed": [{"properties": "(__name__ ASC)", "query_scope": "Collection"}]}}})
                );
            }
            let mut reuse = explain_body(aggregation, false);
            reuse["transaction"] = json!(token);
            let (status, body) = call(&s, "POST", &path, reuse);
            assert_eq!(status, 200, "{body}");
            assert!(body[0].get("transaction").is_none());
            assert_eq!(
                call(
                    &s,
                    "POST",
                    "/v1/projects/demo-app/databases/(default)/documents:rollback",
                    json!({"transaction": token})
                )
                .0,
                200
            );
        }
    }
}

#[test]
#[allow(clippy::result_large_err)]
fn explain_rest_authorization_denies_without_metrics_or_leaked_transactions() {
    for source in [
        "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if false; } } }",
        "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if request.auth != null; } } }",
    ] {
        let s = state(Some(source));
        for aggregation in [false, true] {
            for analyze in [false, true] {
                let mut request = explain_body(aggregation, analyze);
                request["newTransaction"] = json!({"readOnly": {}});
                let (status, body) = call_as(&s, "POST", &format!("{DOCS}:{}", explain_method(aggregation)), request, None);
                assert_eq!(status, 403, "{body}");
                // The array wraps every streaming-method error; for a Rules denial that comes
                // from an exploratory probe only (not closure evidence).
                assert_eq!(body[0]["error"]["status"], "PERMISSION_DENIED");
                assert!(!body.to_string().contains("explainMetrics"));
                assert!(s.local.latest_query_execution_stats().is_none());
            }
        }
        let parent = fireemu_adapter_grpc::decode::parse_parent(&DOCS[4..]).unwrap();
        assert_eq!(s.local.database_handle(&parent).unwrap().with(|db| Ok(db.transaction_bookkeeping_stats().active)).unwrap(), 0);
    }
}

#[test]
fn explain_rest_validates_queries_parents_and_consistency_selectors() {
    let s = state(None);
    for aggregation in [false, true] {
        for analyze in [false, true] {
            let path = format!("{DOCS}:{}", explain_method(aggregation));
            for field in ["transaction", "readTime"] {
                let mut request = explain_body(aggregation, analyze);
                request[field] = json!(if field == "transaction" {
                    "YmFk"
                } else {
                    "invalid"
                });
                let (status, body) = call(&s, "POST", &path, request);
                assert_eq!(status, 400, "{body}");
            }
            for request in [
                json!({"explainOptions": {"analyze": analyze}}),
                json!({"structuredQuery": [], "explainOptions": {"analyze": analyze}}),
            ] {
                let (status, body) = call(&s, "POST", &path, request);
                assert_eq!(status, 400, "{body}");
            }
            let (status, body) = call(
                &s,
                "POST",
                &format!("{DOCS}/items:{}", explain_method(aggregation)),
                explain_body(aggregation, analyze),
            );
            assert_eq!(status, 400, "{body}");
        }
    }
}

#[test]
fn explain_rest_empty_analyze_output_preserves_read_time() {
    let s = state(None);
    for aggregation in [false, true] {
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:{}", explain_method(aggregation)),
            explain_body(aggregation, true),
        );
        assert_eq!(status, 200, "{body}");
        let rows = body.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0]["readTime"].is_string(), "{body}");
        assert_eq!(
            rows[0]["explainMetrics"]["executionStats"]["resultsReturned"],
            if aggregation { json!("1") } else { Value::Null }
        );
    }
}

#[test]
fn explain_rest_name_scans_report_production_plan_billing_and_protojson_defaults() {
    let s = state(None);
    for index in 0..3 {
        assert_eq!(
            call(
                &s,
                "PATCH",
                &format!("{DOCS}/items/{index}"),
                json!({"fields": {}})
            )
            .0,
            200
        );
    }
    for aggregation in [false, true] {
        for (analyze, limit) in [(false, None), (true, None), (true, Some(0))] {
            let mut request = explain_body(aggregation, analyze);
            let query = if aggregation {
                &mut request["structuredAggregationQuery"]["structuredQuery"]
            } else {
                &mut request["structuredQuery"]
            };
            query["offset"] = json!(0);
            if let Some(limit) = limit {
                query["limit"] = json!(limit);
            }
            let (http_code, body) = call(
                &s,
                "POST",
                &format!("{DOCS}:{}", explain_method(aggregation)),
                request,
            );
            assert_eq!(http_code, 200, "{body}");
            let metrics = &body.as_array().unwrap().last().unwrap()["explainMetrics"];
            let empty = limit == Some(0);
            assert_eq!(
                metrics["planSummary"],
                if empty && !aggregation {
                    json!({})
                } else {
                    json!({"indexesUsed": [{"properties": "(__name__ ASC)", "query_scope": "Collection"}]})
                },
                "{body}"
            );
            if !analyze {
                assert!(metrics.get("executionStats").is_none());
                continue;
            }
            let stats = &metrics["executionStats"];
            assert_eq!(
                stats["readOperations"],
                if aggregation || empty { "1" } else { "3" }
            );
            if !aggregation && empty {
                assert!(stats.get("resultsReturned").is_none());
            } else {
                assert_eq!(
                    stats["resultsReturned"],
                    if aggregation { "1" } else { "3" }
                );
            }
            let duration = stats["executionDuration"].as_str().unwrap();
            assert!(duration.strip_suffix('s').unwrap().parse::<f64>().unwrap() >= 0.0);
            assert_eq!(
                stats["debugStats"],
                json!({
                    "index_entries_scanned": if empty { if aggregation { "1" } else { "0" } } else { "3" },
                    "documents_scanned": if aggregation || empty { "0" } else { "3" },
                    "billing_details": {
                        "index_entries_billable": if aggregation && !empty { "3" } else { "0" },
                        "documents_billable": if !aggregation && !empty { "3" } else { "0" },
                        "min_query_cost": if empty { "1" } else { "0" },
                        "small_ops": "0"
                    }
                })
            );
        }
    }
}

/// The message production answers on the data plane for a database that was never created.
/// Recorded from the oracle project in `conformance/firestore-production-matrix.json`
/// (`emulator/routes#named-database-document`), trailing space included.
fn missing_database_message(database: &str) -> String {
    format!(
        "The database {database} does not exist for project demo-app Please visit \
         https://console.cloud.google.com/datastore/setup?project=demo-app to add a Cloud \
         Datastore or Cloud Firestore database. "
    )
}

#[test]
fn every_data_plane_surface_refuses_a_database_that_was_never_created() {
    // Production refuses a request against a database `databases.create` was never called
    // for before it considers the document; fireemu materialized it on first touch.
    let s = state(None);
    let docs = "/v1/projects/demo-app/databases/never-created/documents";
    let document = "projects/demo-app/databases/never-created/documents/c/d";
    let expected = missing_database_message("never-created");
    let write = json!({"writes": [{"update": {"name": document, "fields": {}}}]});
    for (method, path, body) in [
        ("GET", format!("{docs}/c/d"), Value::Null),
        ("GET", format!("{docs}/c"), Value::Null),
        (
            "POST",
            format!("{docs}/c?documentId=x"),
            json!({"fields": {}}),
        ),
        ("PATCH", format!("{docs}/c/d"), json!({"fields": {}})),
        ("DELETE", format!("{docs}/c/d"), Value::Null),
        ("POST", format!("{docs}:commit"), write.clone()),
        ("POST", format!("{docs}:batchWrite"), write),
        (
            "POST",
            format!("{docs}:batchGet"),
            json!({"documents": [document]}),
        ),
        (
            "POST",
            format!("{docs}:runQuery"),
            json!({"structuredQuery": {"from": [{"collectionId": "c"}]}}),
        ),
        (
            "POST",
            format!("{docs}:runAggregationQuery"),
            json!({"structuredAggregationQuery": {
                "structuredQuery": {"from": [{"collectionId": "c"}]},
                "aggregations": [{"alias": "n", "count": {}}]
            }}),
        ),
        ("POST", format!("{docs}:beginTransaction"), json!({})),
        ("POST", format!("{docs}:listCollectionIds"), json!({})),
    ] {
        let (status, body) = call(&s, method, &path, body);
        assert_eq!(status, 404, "{method} {path}: {body}");
        // Production answers the streaming methods' errors inside a one-element array (recorded
        // for refusals in FS-QUERY-INDEX; a never-created database was seen so only in an
        // exploratory probe, which is not closure evidence).
        let body = if path.ends_with(":runQuery") || path.ends_with(":runAggregationQuery") {
            body[0].clone()
        } else {
            body
        };
        assert_eq!(
            body["error"]["status"], "NOT_FOUND",
            "{method} {path}: {body}"
        );
        assert_eq!(
            body["error"]["message"], expected,
            "{method} {path}: {body}"
        );
    }
}

#[test]
fn the_default_database_is_reachable_without_having_been_created() {
    // Every project has `(default)`: the refusal is for named databases only.
    let s = state(None);
    let (status, body) = call(&s, "GET", &format!("{DOCS}/c/d"), Value::Null);
    assert_eq!(status, 404, "{body}");
    assert_eq!(
        body["error"]["message"],
        "Document \"projects/demo-app/databases/(default)/documents/c/d\" not found.",
        "{body}"
    );
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}/c?documentId=d"),
        json!({"fields": {}}),
    );
    assert_eq!(status, 200, "{body}");
}

/// `PUT /emulator/v1/projects/{p}:securityRules` replaces the authorization policy of the
/// whole run, and this surface answers a CORS preflight for any loopback origin, so a page on
/// another loopback port could reach it. It is held to the same privileged-route policy as
/// every other such route: a browser request needs the run's control token. The Node shape
/// `@firebase/rules-unit-testing` sends carries no browser metadata and is unaffected.
#[test]
fn the_security_rules_route_needs_the_control_token_from_a_browser() {
    const DENY: &str = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /{document=**} { allow read, write: if false; }\n  }\n}\n";
    const ALLOW: &str = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /{document=**} { allow read, write: if true; }\n  }\n}\n";
    const TOKEN: &str = "rest-test-control-token";

    let put = |s: &RestState, origin: Option<&str>, browser: bool, authorization: Option<&str>| {
        let r = s.handle(&RestRequest {
            method: "PUT".to_owned(),
            path: format!("{EMULATOR}:securityRules"),
            query: String::new(),
            authorization: authorization.map(str::to_owned),
            origin: origin.map(str::to_owned),
            browser_metadata: browser,
            app_check: Vec::new(),
            body: json!({"rules": {"files": [{"name": "firestore.rules", "content": ALLOW}]}}),
        });
        (r.status, r.body)
    };

    for (label, origin, browser, authorization) in [
        (
            "loopback origin, no token",
            Some("http://localhost:5173"),
            true,
            None,
        ),
        (
            "loopback origin, wrong token",
            Some("http://localhost:5173"),
            true,
            Some("Bearer not-the-control-token"),
        ),
        ("browser metadata without an origin", None, true, None),
        (
            "foreign origin with the token",
            Some("https://evil.example"),
            true,
            Some("Bearer rest-test-control-token"),
        ),
    ] {
        let mut s = state(Some(DENY));
        s.control_token = Some(TOKEN.to_owned());
        let (status, body) = put(&s, origin, browser, authorization);
        assert_eq!(status, 403, "{label}: {body}");
    }

    // With the control token the same browser request is admitted.
    let mut s = state(Some(DENY));
    s.control_token = Some(TOKEN.to_owned());
    let (status, body) = put(
        &s,
        Some("http://localhost:5173"),
        true,
        Some("Bearer rest-test-control-token"),
    );
    assert_eq!(status, 200, "{body}");

    // A process-issued request keeps its unauthenticated access.
    let mut s = state(Some(DENY));
    s.control_token = Some(TOKEN.to_owned());
    let (status, body) = put(&s, None, false, None);
    assert_eq!(status, 200, "{body}");
}

/// `DELETE /emulator/v1/projects/{p}/databases/{db}/documents` is `clearFirestore()`: it drops
/// every document of the project. It is as privileged as replacing the ruleset and this
/// surface answers a CORS preflight for any loopback origin, so a page on another loopback
/// port could wipe a session's data. It takes the same admission as the rules route: a browser
/// request needs the control token, a process-issued one is unaffected.
#[test]
fn the_emulator_clear_route_needs_the_control_token_from_a_browser() {
    const TOKEN: &str = "rest-test-control-token";
    let clear =
        |s: &RestState, origin: Option<&str>, browser: bool, authorization: Option<&str>| {
            let r = s.handle(&RestRequest {
                method: "DELETE".to_owned(),
                path: format!("{EMULATOR}/databases/(default)/documents"),
                query: String::new(),
                authorization: authorization.map(str::to_owned),
                origin: origin.map(str::to_owned),
                browser_metadata: browser,
                app_check: Vec::new(),
                body: json!({}),
            });
            (r.status, r.body)
        };
    let seed = |s: &RestState| {
        let (status, _) = call(
            s,
            "POST",
            &format!("{DOCS}/things?documentId=kept"),
            json!({"fields": {"a": {"stringValue": "x"}}}),
        );
        assert_eq!(status, 200);
    };
    let present =
        |s: &RestState| call(s, "GET", &format!("{DOCS}/things/kept"), json!({})).0 == 200;

    for (label, origin, browser, authorization) in [
        (
            "loopback origin, no token",
            Some("http://localhost:5173"),
            true,
            None,
        ),
        (
            "loopback origin, wrong token",
            Some("http://localhost:5173"),
            true,
            Some("Bearer not-the-control-token"),
        ),
        ("browser metadata without an origin", None, true, None),
        (
            "foreign origin with the token",
            Some("https://evil.example"),
            true,
            Some("Bearer rest-test-control-token"),
        ),
    ] {
        let mut s = state(None);
        s.control_token = Some(TOKEN.to_owned());
        seed(&s);
        let (status, body) = clear(&s, origin, browser, authorization);
        assert_eq!(status, 403, "{label}: {body}");
        assert!(present(&s), "{label}: the refused clear must keep the data");
    }

    // A browser that presents the control token clears, and so does a process client.
    for (label, origin, browser, authorization) in [
        (
            "browser with the control token",
            Some("http://localhost:5173"),
            true,
            Some("Bearer rest-test-control-token"),
        ),
        ("process client", None, false, None),
    ] {
        let mut s = state(None);
        s.control_token = Some(TOKEN.to_owned());
        seed(&s);
        let (status, body) = clear(&s, origin, browser, authorization);
        assert_eq!(status, 200, "{label}: {body}");
        assert!(!present(&s), "{label}: the data must be gone");
    }
}

/// Production refuses every REST pipeline on a Standard-edition database inside the stream
/// array, with its `ErrorInfo` and `Help` details (observed 2026-09-24).
#[test]
fn rest_execute_pipeline_on_standard_is_refused_like_production() {
    let s = state(None);
    for body in [
        json!({}),
        json!({"structuredPipeline": {"pipeline": {"stages": [{"name": "collection", "args": [{"referenceValue": "/c"}]}]}}}),
    ] {
        let (status, body) = call(&s, "POST", &format!("{DOCS}:executePipeline"), body);
        assert_eq!(status, 400, "{body}");
        assert_eq!(
            body,
            json!([{"error": {
                "code": 400,
                "message": "Pipeline Operations are only available for Firestore databases in Enterprise edition.\n\nPlease switch to an Enterprise edition database to take advantage of such functionality.",
                "status": "FAILED_PRECONDITION",
                "details": [
                    {
                        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                        "reason": "PIPELINE_REQUIRES_ENTERPRISE_EDITION",
                        "domain": "firestore.googleapis.com",
                    },
                    {
                        "@type": "type.googleapis.com/google.rpc.Help",
                        "links": [{
                            "description": "Learn more about Firestore database editions",
                            "url": "https://cloud.google.com/firestore/docs/editions",
                        }],
                    },
                ],
            }}])
        );
    }
}

/// Production's REST templates for the query methods need a document below `documents`
/// (`documents/*/**`), so `documents/qn:runQuery` is a create in collection `qn:runQuery`, whose
/// body is a `Document` (FS-QUERY-INDEX request-shape/rest#parent-is-collection).
#[test]
fn rest_query_method_on_a_root_collection_routes_as_a_create_document() {
    let s = state(None);
    let expected = |method: &str| {
        json!({
            "error": {
                "code": 400,
                "message": format!("Invalid JSON payload received. Unknown name \"{method}\" at 'document': Cannot find field."),
                "status": "INVALID_ARGUMENT",
                "details": [{
                    "@type": "type.googleapis.com/google.rpc.BadRequest",
                    "fieldViolations": [{
                        "field": "document",
                        "description": format!("Invalid JSON payload received. Unknown name \"{method}\" at 'document': Cannot find field."),
                    }],
                }],
            }
        })
    };
    for (method, key) in [
        ("runQuery", "structuredQuery"),
        ("runAggregationQuery", "structuredAggregationQuery"),
        ("partitionQuery", "structuredQuery"),
    ] {
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}/qn:{method}"),
            json!({ key: {"from": [{"collectionId": "qn"}]} }),
        );
        assert_eq!((status, &body), (400, &expected(key)), "{method}");
    }
    // A create with only document keys goes through: the collection id carries the colon.
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}/qn:runQuery?documentId=d"),
        json!({"fields": {"v": {"integerValue": "1"}}}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["name"],
        "projects/demo-app/databases/(default)/documents/qn:runQuery/d"
    );
    // Below a document the method is the query method itself.
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}/qn/d:runQuery"),
        json!({"structuredQuery": {"from": [{"collectionId": "sub"}]}}),
    );
    assert_eq!(status, 200, "{body}");
}

/// An enum given by an unknown number reaches the query decoder over REST as over gRPC, which
/// refuses it in production's words (closure review F5).
#[test]
fn rest_unknown_enum_numbers_are_refused_as_the_decoder_refuses_them() {
    let s = state(None);
    let cases = [
        (
            json!({"from": [{"collectionId": "c"}], "where": {"unaryFilter": {"field": {"fieldPath": "a"}, "op": 99}}}),
            "Unknown UnaryFilter operator.",
        ),
        (
            json!({"from": [{"collectionId": "c"}], "where": {"compositeFilter": {"op": 9, "filters": [
                {"fieldFilter": {"field": {"fieldPath": "a"}, "op": "EQUAL", "value": {"integerValue": "1"}}},
                {"fieldFilter": {"field": {"fieldPath": "b"}, "op": "EQUAL", "value": {"integerValue": "1"}}}
            ]}}}),
            "Unsupported CompositeFilter operator.",
        ),
        (
            json!({"from": [{"collectionId": "c"}], "findNearest": {
                "vectorField": {"fieldPath": "e"}, "queryVector": {"mapValue": {"fields": {
                    "__type__": {"stringValue": "__vector__"},
                    "value": {"arrayValue": {"values": [{"doubleValue": 1.0}]}}}}},
                "distanceMeasure": 9, "limit": 1}}),
            "Unknown Distance Measure.",
        ),
    ];
    for (query, expected) in cases {
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:runQuery"),
            json!({"structuredQuery": query}),
        );
        assert_eq!(status, 400, "{body}");
        assert_eq!(body[0]["error"]["message"], expected, "{body}");
    }
}

/// `:executePipeline` is routed only on the database's documents resource, and a caller who is
/// not the owner is refused first, as over gRPC (closure review F6).
#[test]
fn rest_execute_pipeline_routes_one_resource_and_checks_the_owner_first() {
    let s = state(None);
    for path in [
        "qn:executePipeline",
        "qn/d:executePipeline",
        "a/b/c:executePipeline",
    ] {
        let (status, body) = call(&s, "POST", &format!("{DOCS}/{path}"), json!({}));
        assert_ne!(
            body[0]["error"]["status"], "FAILED_PRECONDITION",
            "{path}: {body}"
        );
        assert!(status == 404 || status == 400, "{path}: {status} {body}");
    }
    let s = state(Some(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /{document=**} { allow read, write: if true; } } }",
    ));
    let (status, body) = call_as(
        &s,
        "POST",
        &format!("{DOCS}:executePipeline"),
        json!({}),
        None,
    );
    assert_eq!(status, 403, "{body}");
    assert_eq!(body[0]["error"]["status"], "PERMISSION_DENIED");
}

/// A `__name__` filter on a collection name is refused with production's "lacks /" text
/// (filter-validation/paths-and-names#name-collection-reference); another malformed name gets
/// the text that names its own fault, not that one (closure review 11).
#[test]
fn rest_name_filter_references_are_refused_for_their_own_fault() {
    let s = state(None);
    let refusal = |reference: &str| {
        let (status, body) = call(
            &s,
            "POST",
            &format!("{DOCS}:runQuery"),
            json!({"structuredQuery": {"from": [{"collectionId": "qn"}], "where": {"fieldFilter": {
                "field": {"fieldPath": "__name__"}, "op": "EQUAL",
                "value": {"referenceValue": reference}}}}}),
        );
        assert_eq!(status, 400, "{body}");
        body[0]["error"]["message"].as_str().unwrap().to_owned()
    };
    let collection = "projects/demo-app/databases/(default)/documents/qn".to_owned();
    assert_eq!(
        refusal(&collection),
        format!(
            "Document parent name \"{collection}\" lacks \"/\" at index {}.",
            collection.len()
        )
    );
    let dotted = "projects/demo-app/databases/(default)/documents/qn/d/./x".to_owned();
    assert!(!refusal(&dotted).contains("lacks"), "{}", refusal(&dotted));
}

/// The refusals only production makes stay out of the emulator profile, which may add no
/// rejection (`spec/compatibility/contract.json`): the transcoder's and the Standard REST
/// pipeline route. Each is pinned on both profiles; the emulator side answers as it did before.
#[test]
fn production_only_refusals_differ_between_the_profiles() {
    let strict = state_with_profile(true);
    let emulator = state_with_profile(false);
    for s in [&strict, &emulator] {
        let (status, body) = call(
            s,
            "PATCH",
            &format!("{DOCS}/c/d"),
            json!({"fields": {"v": {"integerValue": "1"}}}),
        );
        assert_eq!(status, 200, "{body}");
    }
    let query = |s: &RestState, body: Value| call(s, "POST", &format!("{DOCS}:runQuery"), body);
    // The transcoder: an unknown field in the structured query.
    let body = json!({"structuredQuery": {"from": [{"collectionId": "c"}], "extra": 1}});
    let (status, refused) = query(&strict, body.clone());
    assert_eq!(status, 400);
    assert_eq!(
        refused[0]["error"]["message"],
        "Invalid JSON payload received. Unknown name \"extra\" at 'structured_query': Cannot find field."
    );
    let (status, answered) = query(&emulator, body);
    assert_eq!(status, 200, "{answered}");
    assert_eq!(answered.as_array().unwrap().len(), 1, "{answered}");
    assert!(answered[0]["document"]["name"]
        .as_str()
        .unwrap()
        .ends_with("/c/d"));
    // The REST pipeline route on a Standard database.
    let (status, _) = call(
        &strict,
        "POST",
        &format!("{DOCS}:executePipeline"),
        json!({}),
    );
    assert_eq!(status, 400);
    let (status, _) = call(
        &emulator,
        "POST",
        &format!("{DOCS}:executePipeline"),
        json!({}),
    );
    assert_eq!(status, 404);
}

/// A read time before the database was created is refused on both profiles: production does,
/// and fireemu did before FS-QUERY-INDEX (the emulator profile keeps every earlier refusal).
#[test]
fn a_read_time_before_database_creation_is_refused_on_both_profiles() {
    // Half an hour before the database was created (its clock start), inside the retention
    // hour.
    let early = json!({"structuredQuery": {"from": [{"collectionId": "c"}]},
        "readTime": "2026-08-29T11:31:00Z"});
    for strict in [true, false] {
        let s = state_with_profile(strict);
        let (status, refused) = call(&s, "POST", &format!("{DOCS}:runQuery"), early.clone());
        assert_eq!(status, 400, "strict={strict} {refused}");
        assert_eq!(
            refused[0]["error"]["message"],
            "The requested 'read_time' cannot be before database creation time.",
            "strict={strict}"
        );
    }
}

/// Both profiles with `qn/a` (v 1) and `qn/b` (v 2). The tests below pin requests fireemu
/// accepted before FS-QUERY-INDEX that production refuses: the strict profile refuses each in
/// production's words, the emulator profile still answers them (confirmation review
/// 2026-09-24, Must Fix 1 and 2).
fn seeded_profiles() -> (RestState, RestState) {
    let strict = state_with_profile(true);
    let emulator = state_with_profile(false);
    for s in [&strict, &emulator] {
        for (id, v) in [("a", 1), ("b", 2)] {
            let (status, body) = call(
                s,
                "PATCH",
                &format!("{DOCS}/qn/{id}"),
                json!({"fields": {"v": {"integerValue": v.to_string()}}}),
            );
            assert_eq!(status, 200, "{body}");
        }
    }
    (strict, emulator)
}

#[test]
fn the_emulator_profile_never_routes_a_query_method_to_a_create() {
    let (_, emulator) = seeded_profiles();
    // A query method on a root collection: production routes it to the create template and
    // refuses the query keys; the emulator profile keeps the query route, which refuses the
    // collection parent, and never creates a document.
    let (status, body) = call(
        &emulator,
        "POST",
        &format!("{DOCS}/qn:runQuery"),
        json!({"structuredQuery": {"from": [{"collectionId": "qn"}]}}),
    );
    assert_eq!(status, 400, "{body}");
    for method in ["runAggregationQuery", "partitionQuery"] {
        let (status, body) = call(
            &emulator,
            "POST",
            &format!("{DOCS}/qn:{method}"),
            json!({"structuredQuery": {"from": [{"collectionId": "qn"}]}}),
        );
        assert_eq!(status, 400, "{method}: {body}");
    }
    let (status, body) = call(
        &emulator,
        "GET",
        &format!("{DOCS}/qn:runQuery"),
        json!(null),
    );
    assert_eq!(status, 404, "{body}");
    let (status, listed) = call(
        &emulator,
        "POST",
        &format!("{DOCS}:listCollectionIds"),
        json!({}),
    );
    assert_eq!(status, 200, "{listed}");
    assert_eq!(listed["collectionIds"], json!(["qn"]), "{listed}");
}

#[test]
fn the_emulator_profile_keeps_the_earlier_aggregation_aliases() {
    let (strict, emulator) = seeded_profiles();
    let aggregate = |s: &RestState, aggregations: Value| {
        call(
            s,
            "POST",
            &format!("{DOCS}:runAggregationQuery"),
            json!({"structuredAggregationQuery": {
                "structuredQuery": {"from": [{"collectionId": "qn"}]},
                "aggregations": aggregations}}),
        )
    };
    // An alias equal to the name production gives the first unnamed aggregation.
    let colliding =
        json!([{"alias": "field_1", "count": {}}, {"sum": {"field": {"fieldPath": "v"}}}]);
    let (status, body) = aggregate(&strict, colliding.clone());
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        stream_error(&body)["error"]["message"],
        "Aggregation aliases contain duplicate alias: field_1."
    );
    let (status, body) = aggregate(&emulator, colliding);
    assert_eq!(status, 200, "{body}");
    let fields = &body[0]["result"]["aggregateFields"];
    assert_eq!(fields["field_1"]["integerValue"], "2", "{body}");
    assert_eq!(fields["field_2"]["integerValue"], "3", "{body}");
    // A reserved alias, and one longer than 1500 bytes.
    let long = "a".repeat(1501);
    for (alias, refusal) in [
        (
            "__x__".to_owned(),
            "The property.name \"__x__\" is reserved.".to_owned(),
        ),
        (
            long.clone(),
            "The property.name is longer than 1500 bytes.".to_owned(),
        ),
    ] {
        let aggregations = json!([{"alias": alias, "count": {}}]);
        let (status, body) = aggregate(&strict, aggregations.clone());
        assert_eq!(status, 400, "{body}");
        assert_eq!(stream_error(&body)["error"]["message"], refusal.as_str());
        let (status, body) = aggregate(&emulator, aggregations);
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            body[0]["result"]["aggregateFields"][alias.as_str()]["integerValue"],
            "2"
        );
    }
    // `count.upTo` in its wrapper message form, which fireemu read before (production's
    // answer is not observed; the strict transcoder admits the wrapper message too).
    // The emulator profile reads every wrapper form as before; the strict transcoder admits
    // the plain wrapper and judges the empty and nested ones itself.
    for (up_to, count, strict_too) in [
        (json!({"value": 1}), "1", true),
        (json!({}), "2", false),
        (json!({"value": {"value": 1}}), "1", false),
        (json!({"value": {}}), "2", false),
    ] {
        let wrapped = json!([{"alias": "c", "count": {"upTo": up_to}}]);
        let profiles: &[&RestState] = if strict_too {
            &[&strict, &emulator]
        } else {
            &[&emulator]
        };
        for s in profiles {
            let (status, body) = aggregate(s, wrapped.clone());
            assert_eq!(status, 200, "{up_to}: {body}");
            assert_eq!(
                body[0]["result"]["aggregateFields"]["c"]["integerValue"], count,
                "{up_to}"
            );
        }
    }
}

#[test]
fn the_emulator_profile_keeps_partition_projections_and_name_comparisons() {
    let (strict, emulator) = seeded_profiles();
    // A projection on a partitioned query.
    let partition = json!({"structuredQuery": {
        "from": [{"collectionId": "qp", "allDescendants": true}],
        "select": {"fields": [{"fieldPath": "v"}]},
        "orderBy": [{"field": {"fieldPath": "__name__"}, "direction": "ASCENDING"}]},
        "partitionCount": "2"});
    let (status, body) = call(
        &strict,
        "POST",
        &format!("{DOCS}:partitionQuery"),
        partition.clone(),
    );
    assert_eq!(
        (status, &body["error"]["message"]),
        (400, &json!("Property masks are not supported."))
    );
    // The emulator partitions it as it partitions the query without the projection: enough
    // documents for sampled cursors, the same cursors either way.
    let writes: Vec<Value> = (0..600)
        .map(|i| json!({"update": {"name": format!("projects/demo-app/databases/(default)/documents/qp/p{i:03}"), "fields": {"v": {"integerValue": "1"}}}}))
        .collect();
    let (status, body) = call(
        &emulator,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": writes}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, projected) = call(
        &emulator,
        "POST",
        &format!("{DOCS}:partitionQuery"),
        partition.clone(),
    );
    assert_eq!(status, 200, "{projected}");
    let mut unprojected = partition;
    unprojected["structuredQuery"]
        .as_object_mut()
        .unwrap()
        .remove("select");
    let (status, plain) = call(
        &emulator,
        "POST",
        &format!("{DOCS}:partitionQuery"),
        unprojected,
    );
    assert_eq!(status, 200, "{plain}");
    assert!(
        projected["partitions"]
            .as_array()
            .is_some_and(|p| !p.is_empty()),
        "{projected}"
    );
    assert_eq!(projected["partitions"], plain["partitions"]);

    // A `__name__` filter on a reference that is not a document.
    let collection = "projects/demo-app/databases/(default)/documents/qn";
    let by_name = json!({"structuredQuery": {"from": [{"collectionId": "qn"}],
        "where": {"fieldFilter": {"field": {"fieldPath": "__name__"}, "op": "GREATER_THAN",
            "value": {"referenceValue": collection}}}}});
    let (status, body) = call(
        &strict,
        "POST",
        &format!("{DOCS}:runQuery"),
        by_name.clone(),
    );
    assert_eq!(status, 400, "{body}");
    let (status, body) = call(&emulator, "POST", &format!("{DOCS}:runQuery"), by_name);
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body.as_array()
            .unwrap()
            .iter()
            .filter(|row| row.get("document").is_some())
            .count(),
        2,
        "{body}"
    );
}

fn vector_value(values: &[f64]) -> Value {
    json!({"mapValue": {"fields": {
        "__type__": {"stringValue": "__vector__"},
        "value": {"arrayValue": {"values": values.iter().map(|v| json!({"doubleValue": v})).collect::<Vec<_>>()}}
    }}})
}

/// Both profiles with `items/near` (1, 0), `items/mid` (1, 1) and `items/far` (-1, 0), and the
/// vector index the strict profile needs.
fn nearest_profiles() -> (RestState, RestState) {
    let strict = state_with_profile(true);
    let emulator = state_with_profile(false);
    let mut indexes = IndexSet::default();
    indexes.add_composite(IndexDefinition {
        collection_group: CollectionId::try_new("items").unwrap(),
        query_scope: IndexQueryScope::Collection,
        fields: vec![IndexField {
            path: FieldPath::parse("e").unwrap(),
            mode: IndexFieldMode::Vector { dimension: 2 },
        }],
    });
    strict
        .local
        .replace_project_database_indexes("demo-app", "(default)", indexes);
    for s in [&strict, &emulator] {
        for (id, e) in [
            ("near", [1.0, 0.0]),
            ("mid", [1.0, 1.0]),
            ("far", [-1.0, 0.0]),
        ] {
            let (status, body) = call(
                s,
                "PATCH",
                &format!("{DOCS}/items/{id}"),
                json!({"fields": {"e": vector_value(&e)}}),
            );
            assert_eq!(status, 200, "{body}");
        }
    }
    (strict, emulator)
}

/// A nearest-neighbour query on `items` from (1, 0), three results, with `extra` clauses.
fn nearest_query(measure: &str, extra: &Value) -> Value {
    let mut query = json!({"from": [{"collectionId": "items"}], "findNearest": {
        "vectorField": {"fieldPath": "e"}, "queryVector": vector_value(&[1.0, 0.0]),
        "distanceMeasure": measure, "limit": 3}});
    query
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    query
}

fn result_ids(rows: &Value) -> Vec<String> {
    rows.as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["document"]["name"].as_str())
        .map(|name| name.rsplit('/').next().unwrap().to_owned())
        .collect()
}

fn run_structured(s: &RestState, query: &Value) -> (u16, Value) {
    call(
        s,
        "POST",
        &format!("{DOCS}:runQuery"),
        json!({"structuredQuery": query}),
    )
}

fn count_of(s: &RestState, query: &Value) -> (u16, Value) {
    call(
        s,
        "POST",
        &format!("{DOCS}:runAggregationQuery"),
        json!({"structuredAggregationQuery": {
            "structuredQuery": query,
            "aggregations": [{"alias": "n", "count": {}}]}}),
    )
}

/// A query limit, offset or cursor beside `findNearest`: the strict profile refuses each in
/// production's words, the emulator profile applies them before the ranking as fireemu did
/// before (confirmation review 2026-09-24, Should Fix 2).
#[test]
fn the_emulator_profile_serves_nearest_neighbour_query_clauses() {
    let (strict, emulator) = nearest_profiles();
    for (extra, refusal, served) in [
        (
            json!({"limit": 2}),
            "A query limit cannot be used with FindNearest",
            // The first two by name (far, mid), then ranked.
            vec!["mid", "far"],
        ),
        (
            json!({"offset": 1}),
            "A query offset cannot be used with FindNearest",
            // All but the first by name (mid, near), then ranked.
            vec!["near", "mid"],
        ),
        (
            json!({"orderBy": [{"field": {"fieldPath": "__name__"}}],
                "startAt": {"values": [{"referenceValue": "projects/demo-app/databases/(default)/documents/items/mid"}], "before": true}}),
            "A cursor cannot be used with FindNearest",
            vec!["near", "mid"],
        ),
    ] {
        let (status, body) = run_structured(&strict, &nearest_query("EUCLIDEAN", &extra));
        assert_eq!(status, 400, "{body}");
        assert_eq!(stream_error(&body)["error"]["message"], refusal);
        let (status, body) = run_structured(&emulator, &nearest_query("EUCLIDEAN", &extra));
        assert_eq!(status, 200, "{extra}: {body}");
        assert_eq!(result_ids(&body), served, "{extra}: {body}");
    }
    // An aggregation over a nearest-neighbour query with a query limit.
    let limited = nearest_query("EUCLIDEAN", &json!({"limit": 2}));
    let (status, body) = count_of(&strict, &limited);
    assert_eq!(status, 400, "{body}");
    let (status, body) = count_of(&emulator, &limited);
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body[0]["result"]["aggregateFields"]["n"]["integerValue"],
        "2"
    );
}

/// A zero vector among the candidates of a cosine search: the strict profile refuses the
/// search as production does, the emulator profile leaves that candidate out, over runQuery
/// and runAggregationQuery (the flag reaches the store on both paths).
#[test]
fn the_emulator_profile_leaves_a_zero_vector_out_of_a_cosine_search() {
    let (strict, emulator) = nearest_profiles();
    for s in [&strict, &emulator] {
        let (status, body) = call(
            s,
            "PATCH",
            &format!("{DOCS}/items/zero"),
            json!({"fields": {"e": vector_value(&[0.0, 0.0])}}),
        );
        assert_eq!(status, 200, "{body}");
    }
    let cosine = nearest_query("COSINE", &json!({}));
    let (status, body) = run_structured(&strict, &cosine);
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        stream_error(&body)["error"]["message"],
        "Cannot compute cosine distance against a vector with a magnitude of zero."
    );
    let (status, body) = run_structured(&emulator, &cosine);
    assert_eq!(status, 200, "{body}");
    assert_eq!(result_ids(&body), ["near", "mid", "far"], "{body}");
    let (status, body) = count_of(&strict, &cosine);
    assert_eq!(status, 400, "{body}");
    let (status, body) = count_of(&emulator, &cosine);
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body[0]["result"]["aggregateFields"]["n"]["integerValue"],
        "3"
    );
}

/// Every refusal text that repeats client input repeats at most 1 KiB of it (the shared echo
/// bound, `spec/compatibility/contract.json`), on each profile that makes the refusal
/// (confirmation review 2026-09-24, Should Fix 6).
#[test]
fn refusal_texts_echo_at_most_one_kibibyte_of_client_input() {
    // Longer than the echo bound, shorter than the 1500-byte name limits checked first.
    let long = "x".repeat(1400);
    let reserved = format!("__{long}__");
    let collection = format!("projects/demo-app/databases/(default)/documents/{long}");
    let vector = json!({"mapValue": {"fields": {
        "__type__": {"stringValue": "__vector__"},
        "value": {"arrayValue": {"values": [{"doubleValue": 1.0}]}}}}});
    let inequalities: Vec<Value> = (0..20)
        .map(|i| {
            json!({"fieldFilter": {"field": {"fieldPath": format!("f{i}{}", "y".repeat(1400))},
                "op": "GREATER_THAN", "value": {"integerValue": "1"}}})
        })
        .collect();
    let cases = [
        (
            "collection id",
            json!({"from": [{"collectionId": reserved}]}),
            "Collection id \"__xxx",
            true,
        ),
        (
            "distance result field",
            json!({"from": [{"collectionId": "c"}], "findNearest": {
                "vectorField": {"fieldPath": "e"}, "queryVector": vector,
                "distanceMeasure": "EUCLIDEAN", "limit": 1, "distanceResultField": reserved}}),
            "The distanceResultField.property.name \"__xxx",
            true,
        ),
        (
            "inequality fields",
            json!({"from": [{"collectionId": "c"}],
                "where": {"compositeFilter": {"op": "AND", "filters": inequalities}}}),
            "The query contains 20 distinct inequality fields: [f0yyy",
            false,
        ),
        (
            "kindless filter",
            json!({"from": [{"allDescendants": true}], "where": {"fieldFilter": {
                "field": {"fieldPath": long}, "op": "EQUAL", "value": {"integerValue": "1"}}}}),
            "kind is required for filter: xxx",
            false,
        ),
        (
            "cursor reference",
            json!({"from": [{"collectionId": "c"}],
                "orderBy": [{"field": {"fieldPath": "__name__"}}],
                "startAt": {"values": [{"referenceValue": collection}]}}),
            "Document parent name \"projects/demo-app",
            false,
        ),
        (
            "duplicate order field",
            json!({"from": [{"collectionId": "c"}], "orderBy": [
                {"field": {"fieldPath": long}}, {"field": {"fieldPath": long}}]}),
            "order by clause cannot contain duplicate fields xxx",
            false,
        ),
    ];
    for strict in [true, false] {
        let s = state_with_profile(strict);
        for (what, query, prefix, both_profiles) in &cases {
            if !strict && !both_profiles {
                continue;
            }
            let (status, body) = call(
                &s,
                "POST",
                &format!("{DOCS}:runQuery"),
                json!({"structuredQuery": query}),
            );
            assert_eq!(status, 400, "{what} strict={strict}: {body}");
            let message = stream_error(&body)["error"]["message"]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(
                message.starts_with(prefix),
                "{what} strict={strict}: {}",
                &message[..message.len().min(200)]
            );
            assert!(
                message.len() < 1024 + 256,
                "{what} strict={strict}: {} bytes",
                message.len()
            );
            assert!(message.contains("..."), "{what} strict={strict}");
        }
    }
}
