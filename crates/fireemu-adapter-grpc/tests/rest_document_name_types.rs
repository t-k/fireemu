//! FS-WRITE-DOCUMENT-NAME-TYPE-044: malformed names must not become omitted names.
//! These are local regression tests, not recorded production observations.

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::json::{document_from_json, FieldPath};
use fireemu_adapter_grpc::rest::{RestRequest, RestResponse, RestState};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const DOCS: &str = "/v1/projects/demo-app/databases/(default)/documents";
const RESOURCE: &str = "projects/demo-app/databases/(default)/documents";

fn state(strict: bool) -> RestState {
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

fn call(state: &RestState, method: &str, path_and_query: &str, body: Value) -> RestResponse {
    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query, ""));
    state.handle(&RestRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        browser_metadata: false,
        app_check: Vec::new(),
        body,
    })
}

fn invalid_names() -> Vec<Value> {
    vec![
        json!(0),
        json!(42),
        json!(-1),
        json!(1.25),
        json!(true),
        json!(false),
        json!([]),
        json!(["projects/demo-app/databases/(default)/documents/items/a"]),
        json!({}),
        json!({"name": "projects/demo-app/databases/(default)/documents/items/a"}),
    ]
}

fn require_name_type_refusal(response: &RestResponse) {
    assert_eq!(response.status, 400, "{:?}", response.body);
    assert_eq!(response.body["error"]["status"], "INVALID_ARGUMENT");
    // This is the local diagnostic, not a claim of production wording parity.
    assert_eq!(
        response.body["error"]["message"],
        "document.name must be a string"
    );
}

fn require_absent(state: &RestState, relative: &str) {
    let response = call(state, "GET", &format!("{DOCS}/{relative}"), Value::Null);
    assert_eq!(response.status, 404, "{:?}", response.body);
    assert_eq!(response.body["error"]["status"], "NOT_FOUND");
}

fn create_write(relative: &str, n: i64) -> Value {
    json!({
        "update": {
            "name": format!("{RESOURCE}/{relative}"),
            "fields": {"v": {"integerValue": n.to_string()}}
        },
        "currentDocument": {"exists": false}
    })
}

#[test]
fn document_parser_rejects_non_string_names() {
    for name in invalid_names() {
        let value = json!({"name": name, "fields": {}});
        let error = document_from_json(&value, &FieldPath::root("document")).unwrap_err();
        assert_eq!(error.0, "document.name must be a string", "{value}");
    }
}

#[test]
fn document_parser_preserves_omitted_null_and_exact_string_names() {
    for value in [json!({}), json!({"name": null}), json!({"name": ""})] {
        let parsed = document_from_json(&value, &FieldPath::root("document")).unwrap();
        assert_eq!(parsed.name, "", "{value}");
    }
    // Parsing checks the scalar type; resource syntax belongs to the backend.
    // No trimming, numeric conversion, URL decoding or normalization is introduced.
    for name in [
        "projects/demo-app/databases/(default)/documents/items/a",
        "projects/demo-app/databases/(default)/documents/items/文書",
        "42",
        "false",
        " value with spaces ",
        "x%2Fy",
    ] {
        let parsed =
            document_from_json(&json!({"name": name}), &FieldPath::root("document")).unwrap();
        assert_eq!(parsed.name, name);
    }
}

#[test]
fn malformed_patch_name_does_not_overwrite_the_url_document() {
    for strict in [true, false] {
        let s = state(strict);
        let path = format!("{DOCS}/name-type/existing");
        let created = call(
            &s,
            "PATCH",
            &path,
            json!({"fields": {"v": {"integerValue": "7"}}}),
        );
        assert_eq!(created.status, 200, "{:?}", created.body);
        for name in invalid_names() {
            let response = call(
                &s,
                "PATCH",
                &path,
                json!({"name": name, "fields": {"v": {"integerValue": "9"}}}),
            );
            require_name_type_refusal(&response);
            let after = call(&s, "GET", &path, Value::Null);
            assert_eq!(after.status, 200);
            assert_eq!(
                after.body, created.body,
                "invalid PATCH changed the document"
            );
        }
    }
}

#[test]
fn malformed_patch_name_does_not_create_the_url_document() {
    for strict in [true, false] {
        let s = state(strict);
        for name in invalid_names() {
            let response = call(
                &s,
                "PATCH",
                &format!("{DOCS}/name-type/new"),
                json!({"name": name, "fields": {"v": {"integerValue": "9"}}}),
            );
            require_name_type_refusal(&response);
            require_absent(&s, "name-type/new");
        }
    }
}

#[test]
fn malformed_create_document_name_does_not_use_the_supplied_document_id() {
    for strict in [true, false] {
        let s = state(strict);
        for name in invalid_names() {
            let response = call(
                &s,
                "POST",
                &format!("{DOCS}/name-type?documentId=chosen"),
                json!({"name": name, "fields": {"v": {"integerValue": "9"}}}),
            );
            require_name_type_refusal(&response);
            require_absent(&s, "name-type/chosen");
        }
    }
}

#[test]
fn omitted_null_and_empty_patch_names_still_use_the_url_target() {
    for strict in [true, false] {
        for name_fields in [json!({}), json!({"name": null}), json!({"name": ""})] {
            let s = state(strict);
            let mut body = name_fields;
            body["fields"] = json!({"v": {"integerValue": "7"}});
            let response = call(&s, "PATCH", &format!("{DOCS}/name-type/valid"), body);
            assert_eq!(response.status, 200, "{:?}", response.body);
            assert_eq!(response.body["name"], format!("{RESOURCE}/name-type/valid"));
            assert_eq!(response.body["fields"]["v"]["integerValue"], "7");
        }
    }
}

#[test]
fn mismatching_string_name_is_not_erased_to_the_url_target() {
    for strict in [true, false] {
        let s = state(strict);
        let response = call(
            &s,
            "PATCH",
            &format!("{DOCS}/name-type/url"),
            json!({
                "name": format!("{RESOURCE}/name-type/body"),
                "fields": {"v": {"integerValue": "7"}}
            }),
        );
        assert_eq!(response.status, 400, "{:?}", response.body);
        assert_eq!(
            response.body["error"]["message"],
            "document.name does not match the URL"
        );
        require_absent(&s, "name-type/url");
        require_absent(&s, "name-type/body");
    }
}

#[test]
fn commit_name_type_error_does_not_publish_valid_neighbor_writes() {
    for strict in [true, false] {
        for name in invalid_names() {
            let s = state(strict);
            let response = call(
                &s,
                "POST",
                &format!("{DOCS}:commit"),
                json!({"writes": [
                    create_write("name-type/before", 1),
                    {"update": {"name": name, "fields": {}}},
                    create_write("name-type/after", 2)
                ]}),
            );
            require_name_type_refusal(&response);
            require_absent(&s, "name-type/before");
            require_absent(&s, "name-type/after");
        }
    }
}

#[test]
fn batchwrite_name_type_error_is_not_an_empty_name_row_error() {
    for strict in [true, false] {
        for name in invalid_names() {
            for at in 0..=2 {
                let s = state(strict);
                let mut writes = vec![
                    create_write("name-type/before", 1),
                    create_write("name-type/after", 2),
                ];
                writes.insert(at, json!({"update": {"name": name, "fields": {}}}));
                let response = call(
                    &s,
                    "POST",
                    &format!("{DOCS}:batchWrite"),
                    json!({"writes": writes}),
                );
                require_name_type_refusal(&response);
                require_absent(&s, "name-type/before");
                require_absent(&s, "name-type/after");
            }
        }
    }
}

#[test]
fn batchwrite_empty_operation_refuses_request_before_neighbors() {
    for strict in [true, false] {
        let s = state(strict);
        let response = call(
            &s,
            "POST",
            &format!("{DOCS}:batchWrite"),
            json!({"writes": [
                create_write("name-type/before", 1),
                {},
                create_write("name-type/after", 2)
            ]}),
        );
        assert_eq!(response.status, 400, "{:?}", response.body);
        assert_eq!(response.body["error"]["status"], "INVALID_ARGUMENT");
        for relative in ["name-type/before", "name-type/after"] {
            let got = call(&s, "GET", &format!("{DOCS}/{relative}"), Value::Null);
            assert_eq!(got.status, 404, "{:?}", got.body);
        }
    }
}
