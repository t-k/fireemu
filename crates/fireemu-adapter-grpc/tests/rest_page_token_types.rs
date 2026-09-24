//! FS-REST-PAGE-TOKEN-TYPE-041: JSON type handling before page-token validation.
//!
//! Handler-level tests against the actual `LocalBackend`, not an HTTP service or a
//! production oracle. Compile and run these in a complete fireemu checkout.

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::{RestRequest, RestResponse, RestState};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const DOCS: &str = "/v1/projects/demo-app/databases/(default)/documents";

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
        control_token: None,
        app_check: None,
    }
}

fn call(state: &RestState, method: &str, path: &str, body: Value) -> RestResponse {
    state.handle(&RestRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: String::new(),
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        browser_metadata: false,
        app_check: Vec::new(),
        body,
    })
}

fn partition_body() -> Value {
    json!({
        "structuredQuery": {
            "from": [{"collectionId": "items", "allDescendants": true}],
            "orderBy": [{"field": {"fieldPath": "__name__"}, "direction": "ASCENDING"}]
        },
        "partitionCount": "2",
        "pageSize": 1
    })
}

fn invalid_tokens() -> Vec<Value> {
    vec![
        json!(false),
        json!(true),
        json!(0),
        json!(42),
        json!(-1),
        json!(1.5),
        json!([]),
        json!(["opaque"]),
        json!({}),
        json!({"token": "opaque"}),
    ]
}

fn assert_type_error(response: &RestResponse) {
    assert_refused(response, "pageToken must be a string");
}

fn assert_refused(response: &RestResponse, message: &str) {
    assert_eq!(response.status, 400, "{}", response.body);
    assert_eq!(response.body["error"]["status"], "INVALID_ARGUMENT");
    assert_eq!(response.body["error"]["message"], message);
}

fn seed_collections(state: &RestState) {
    for collection in ["page_a", "page_b", "page_c"] {
        let response = call(
            state,
            "PATCH",
            &format!("{DOCS}/{collection}/one"),
            json!({"fields": {"value": {"integerValue": "1"}}}),
        );
        assert_eq!(response.status, 200, "{}", response.body);
    }
}

#[test]
fn partition_query_rejects_non_string_page_tokens_instead_of_restarting() {
    for strict in [true, false] {
        let state = state(strict);
        let path = format!("{DOCS}:partitionQuery");
        let control = call(&state, "POST", &path, partition_body());
        assert_eq!(control.status, 200, "{}", control.body);
        for token in invalid_tokens() {
            let mut body = partition_body();
            body["pageToken"] = token.clone();
            // Production's transcoder refuses a non-string page token before the method runs
            // (strict); the emulator profile keeps fireemu's own refusal.
            let response = call(&state, "POST", &path, body);
            if strict {
                assert_refused(
                    &response,
                    &format!("Invalid value at 'page_token' (TYPE_STRING), {token}"),
                );
            } else {
                assert_type_error(&response);
            }
        }
    }
}

#[test]
fn partition_query_retains_unset_null_and_empty_token_equivalence() {
    let state = state(true);
    let path = format!("{DOCS}:partitionQuery");
    let absent = call(&state, "POST", &path, partition_body());
    assert_eq!(absent.status, 200, "{}", absent.body);
    for token in [Value::Null, json!("")] {
        let mut body = partition_body();
        body["pageToken"] = token;
        let response = call(&state, "POST", &path, body);
        assert_eq!(response.status, absent.status);
        assert_eq!(response.body["partitions"], absent.body["partitions"]);
    }
}

#[test]
fn list_collection_ids_treats_null_as_an_unset_token() {
    for strict in [true, false] {
        let state = state(strict);
        seed_collections(&state);
        let path = format!("{DOCS}:listCollectionIds");
        let absent = call(&state, "POST", &path, json!({"pageSize": 1}));
        assert_eq!(absent.status, 200, "{}", absent.body);
        for token in [Value::Null, json!("")] {
            let response = call(
                &state,
                "POST",
                &path,
                json!({"pageSize": 1, "pageToken": token}),
            );
            assert_eq!(response.status, absent.status);
            // Opaque page tokens need not be byte-identical across separate calls.
            assert_eq!(response.body["collectionIds"], absent.body["collectionIds"]);
        }
    }
}

#[test]
fn list_collection_ids_still_rejects_non_string_non_null_tokens() {
    for strict in [true, false] {
        let state = state(strict);
        seed_collections(&state);
        let path = format!("{DOCS}:listCollectionIds");
        let before = call(&state, "POST", &path, json!({}));
        assert_eq!(before.status, 200, "{}", before.body);
        for token in invalid_tokens() {
            // Production's transcoder refuses a non-string page token before the method runs
            // (strict); the emulator profile keeps fireemu's own refusal.
            let response = call(&state, "POST", &path, json!({"pageToken": token}));
            if strict {
                assert_refused(
                    &response,
                    &format!("Invalid value at 'page_token' (TYPE_STRING), {token}"),
                );
            } else {
                assert_type_error(&response);
            }
        }
        let after = call(&state, "POST", &path, json!({}));
        assert_eq!(after.status, before.status);
        assert_eq!(after.body["collectionIds"], before.body["collectionIds"]);
    }
}

#[test]
fn list_collection_ids_preserves_real_page_tokens_without_restarting() {
    let state = state(true);
    seed_collections(&state);
    let path = format!("{DOCS}:listCollectionIds");
    let mut next: Option<String> = None;
    let mut seen = Vec::new();
    for page in 0..3 {
        let mut body = json!({"pageSize": 1});
        if let Some(token) = next.take() {
            body["pageToken"] = json!(token);
        }
        let response = call(&state, "POST", &path, body);
        assert_eq!(response.status, 200, "{}", response.body);
        let ids = response.body["collectionIds"].as_array().unwrap();
        assert_eq!(ids.len(), 1);
        seen.push(ids[0].as_str().unwrap().to_owned());
        next = response.body["nextPageToken"]
            .as_str()
            .filter(|token| !token.is_empty())
            .map(str::to_owned);
        assert_eq!(next.is_some(), page < 2, "{}", response.body);
    }
    seen.sort();
    assert_eq!(seen, ["page_a", "page_b", "page_c"]);
}
