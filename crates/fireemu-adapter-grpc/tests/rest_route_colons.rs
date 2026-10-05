//! A colon in a REST path is routing syntax only after the last slash: a custom method suffix, or
//! (when the method is unknown) a route that does not exist; elsewhere it belongs to the name.
//! Local regression tests, not recorded production observations.

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
        batch_field_order: Vec::new(),
    })
}

/// A document ID or a collection ID that carries a colon before the last slash is a name, not a
/// method: the document is created, read and found again.
#[test]
fn a_colon_before_the_last_slash_belongs_to_the_name() {
    for strict in [false, true] {
        let st = state(strict);
        let created = call(
            &st,
            "PATCH",
            &format!("{DOCS}/a:b/doc1"),
            json!({"fields": {"v": {"integerValue": "1"}}}),
        );
        assert_eq!(created.status, 200, "{:?}", created.body);
        let read = call(&st, "GET", &format!("{DOCS}/a:b/doc1"), Value::Null);
        assert_eq!(read.status, 200, "{:?}", read.body);
        assert_eq!(read.body["name"], format!("{RESOURCE}/a:b/doc1"));
        assert_eq!(read.body["fields"]["v"]["integerValue"], "1");
    }
}

/// A colon in the last segment that names no custom method is a route that does not exist: it is
/// never a collection whose ID contains the colon, and never a method the handler has not heard of.
#[test]
fn an_unknown_method_suffix_is_no_route() {
    for strict in [false, true] {
        let st = state(strict);
        for method in ["GET", "POST", "PATCH", "DELETE"] {
            let response = call(
                &st,
                method,
                &format!("{DOCS}/items:bogus"),
                json!({"fields": {}}),
            );
            assert_eq!(response.status, 404, "{method}: {:?}", response.body);
            assert_eq!(
                response.body,
                json!({"fireemuText": "Not Found\n"}),
                "{method}"
            );
        }
    }
}
