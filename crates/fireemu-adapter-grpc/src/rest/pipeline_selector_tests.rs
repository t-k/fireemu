//! `:executePipeline` transaction and read-time selectors over REST, against the answers
//! production gave on 2026-11-01 (collection, collection-group and documents inputs).

#![allow(clippy::needless_pass_by_value)] // test helpers take JSON literals

use std::sync::{Arc, Mutex};

use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;
use serde_json::{json, Value};

use super::{RestRequest, RestState};
use crate::gateway::Gateway;
use crate::local::LocalBackend;

const DOCS: &str = "/v1/projects/demo-app/databases/(default)/documents";
const GONE: &str = "The referenced transaction has expired or is no longer valid.";

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
    let local = Arc::new(LocalBackend::new(
        gateway.clone(),
        Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH))),
        7,
    ));
    RestState {
        local,
        gateway: Arc::new(gateway),
        rules: None,
        control_token: None,
        app_check: None,
    }
}

fn call(state: &RestState, method: &str, path: &str, body: Value) -> (u16, Value) {
    let response = state.handle(&RestRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: String::new(),
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        remote_peer: false,
        browser_metadata: false,
        app_check: Vec::new(),
        body,
        batch_field_order: Vec::new(),
        key_order: crate::rest::json_syntax::KeyOrder::default(),
    });
    (response.status, response.body)
}

fn write_v(state: &RestState, v: i64) -> String {
    let (status, document) = call(
        state,
        "PATCH",
        &format!("{DOCS}/selector/d1"),
        json!({"fields": {"v": {"integerValue": v.to_string()}}}),
    );
    assert_eq!(status, 200, "{document}");
    document["updateTime"].as_str().unwrap().to_owned()
}

fn source(kind: &str) -> Value {
    match kind {
        "collection" => json!({"name": "collection", "args": [{"referenceValue": "/selector"}]}),
        "group" => json!({"name": "collection_group", "args": [
            {"referenceValue": ""}, {"stringValue": "selector"}]}),
        "documents" => json!({"name": "documents", "args": [{"referenceValue": "/selector/d1"}]}),
        _ => unreachable!(),
    }
}

fn pipeline(kind: &str, extra: Value) -> Value {
    let mut body = json!({"structuredPipeline": {"pipeline": {"stages": [
        source(kind),
        {"name": "select", "args": [{"mapValue": {"fields": {"v": {"fieldReferenceValue": "v"}}}}]}
    ]}}});
    for (key, value) in extra.as_object().unwrap() {
        body[key] = value.clone();
    }
    body
}

fn execute(state: &RestState, body: Value) -> (u16, Value) {
    call(state, "POST", &format!("{DOCS}:executePipeline"), body)
}

fn begin(state: &RestState, options: Value) -> String {
    let (status, body) = call(
        state,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": options}),
    );
    assert_eq!(status, 200, "{body}");
    body["transaction"].as_str().unwrap().to_owned()
}

fn rollback(state: &RestState, token: &str) -> (u16, Value) {
    call(
        state,
        "POST",
        &format!("{DOCS}:rollback"),
        json!({"transaction": token}),
    )
}

fn stats(state: &RestState) -> fireemu_core_firestore::store::TransactionBookkeepingStats {
    state
        .local
        .database_handle(
            &crate::decode::parse_parent("projects/demo-app/databases/(default)/documents")
                .unwrap(),
        )
        .unwrap()
        .with(|state| Ok(state.transaction_bookkeeping_stats()))
        .unwrap()
}

fn only(body: &Value) -> (&Value, i64) {
    let elements = body.as_array().unwrap();
    assert_eq!(elements.len(), 1, "{body}");
    let results = elements[0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 1, "{body}");
    let v = results[0]["fields"]["v"]["integerValue"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    (&elements[0], v)
}

/// `rest-collection-read-time`: the value at that time, executed at that time, no token.
#[test]
fn collection_read_time_answers_the_old_snapshot() {
    for strict in [true, false] {
        let state = state(strict);
        let read_time = write_v(&state, 1);
        write_v(&state, 2);
        let (status, body) = execute(
            &state,
            pipeline("collection", json!({"readTime": read_time})),
        );
        assert_eq!(status, 200, "{body}");
        let (element, v) = only(&body);
        assert_eq!(v, 1);
        assert_eq!(element["executionTime"], json!(read_time));
        assert!(element.get("transaction").is_none());
        let (status, body) = execute(&state, pipeline("collection", json!({})));
        assert_eq!(status, 200);
        assert_eq!(only(&body).1, 2);
        assert_ne!(only(&body).0["executionTime"], json!(read_time));
    }
}

/// `rest-documents-new-default`: the first answer carries a transaction, which the next
/// request reuses (the same snapshot, no new token) and then rolls back.
#[test]
fn documents_new_default_token_is_reusable_and_rolls_back() {
    for strict in [true, false] {
        let state = state(strict);
        write_v(&state, 2);
        let (status, first) = execute(&state, pipeline("documents", json!({"newTransaction": {}})));
        assert_eq!(status, 200, "{first}");
        let (element, v) = only(&first);
        assert_eq!(v, 2);
        let token = element["transaction"].as_str().unwrap().to_owned();
        assert!(!token.is_empty());
        let (status, reused) =
            execute(&state, pipeline("documents", json!({"transaction": token})));
        assert_eq!(status, 200, "{reused}");
        let (again, v) = only(&reused);
        assert_eq!(v, 2);
        assert!(again.get("transaction").is_none());
        assert_eq!(again["executionTime"], element["executionTime"]);
        assert_eq!(rollback(&state, &token), (200, json!({})));
        assert_eq!(stats(&state).active, 0);
    }
}

/// `rest-group-existing-rw-auto`: the answer carries no token; the transaction is committed, so
/// a later query and a rollback of it answer 409 `ABORTED`.
#[test]
fn group_existing_read_write_auto_commit_closes_the_transaction() {
    for strict in [true, false] {
        let state = state(strict);
        write_v(&state, 2);
        let token = begin(&state, json!({"readWrite": {}}));
        let (status, body) = execute(
            &state,
            pipeline(
                "group",
                json!({"transaction": token, "autoCommitTransaction": true}),
            ),
        );
        assert_eq!(status, 200, "{body}");
        let (element, v) = only(&body);
        assert_eq!(v, 2);
        assert!(element.get("transaction").is_none());
        assert!(element["executionTime"].is_string());
        let gone = json!({"error": {"code": 409, "message": GONE, "status": "ABORTED"}});
        let (status, body) = execute(&state, pipeline("group", json!({"transaction": token})));
        assert_eq!((status, body), (409, json!([gone.clone()])));
        assert_eq!(rollback(&state, &token), (409, gone));
        assert_eq!(stats(&state).active, 0);
    }
}

#[test]
fn collection_new_read_write_auto_commit_returns_no_token() {
    for strict in [true, false] {
        let state = state(strict);
        write_v(&state, 2);
        let (status, body) = execute(
            &state,
            pipeline(
                "collection",
                json!({"newTransaction": {"readWrite": {}}, "autoCommitTransaction": true}),
            ),
        );
        assert_eq!(status, 200, "{body}");
        let (element, v) = only(&body);
        assert_eq!(v, 2);
        assert!(element.get("transaction").is_none());
        let after = stats(&state);
        assert_eq!((after.active, after.finished), (0, 1));
    }
}

#[test]
fn read_only_transaction_anchors_collection_and_group_reads() {
    for kind in ["collection", "group"] {
        let state = state(true);
        let read_time = write_v(&state, 1);
        let token = begin(&state, json!({"readOnly": {"readTime": read_time}}));
        write_v(&state, 2);
        let (status, body) = execute(&state, pipeline(kind, json!({"transaction": token})));
        assert_eq!(status, 200, "{body}");
        let (element, v) = only(&body);
        assert_eq!(v, 1);
        assert_eq!(element["executionTime"], json!(read_time));
        // The caller still owns the transaction.
        assert_eq!(rollback(&state, &token), (200, json!({})));
    }
}

#[test]
fn a_refused_pipeline_mints_nothing_and_a_failing_one_releases_only_its_own_token() {
    for kind in ["collection", "group", "documents"] {
        let state = state(true);
        write_v(&state, 1);
        // Compile before mint.
        let mut bad = pipeline(kind, json!({"newTransaction": {"readWrite": {}}}));
        bad["structuredPipeline"]["pipeline"]["stages"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "not_a_pipeline_stage", "args": [{"integerValue": "1"}]}));
        assert_ne!(execute(&state, bad).0, 200);
        let after = stats(&state);
        assert_eq!((after.active, after.finished), (0, 0), "{kind}");
        // An evaluation failure after the read: the new token is rolled back, nothing is
        // committed, and the caller's own token survives.
        let failing = |extra: Value| {
            let mut body = pipeline(kind, extra);
            body["structuredPipeline"]["pipeline"]["stages"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name": "select", "args": [{"mapValue": {"fields": {"bad": {
                    "functionValue": {"name": "array_length", "args": [{"fieldReferenceValue": "v"}]}}}}}]}));
            body
        };
        let (status, _) = execute(
            &state,
            failing(json!({"newTransaction": {"readWrite": {}}, "autoCommitTransaction": true})),
        );
        assert_ne!(status, 200, "{kind}");
        let after = stats(&state);
        assert_eq!((after.active, after.finished), (0, 1), "{kind}");
        let token = begin(&state, json!({"readWrite": {}}));
        let (status, _) = execute(
            &state,
            failing(json!({"transaction": token, "autoCommitTransaction": true})),
        );
        assert_ne!(status, 200, "{kind}");
        assert_eq!(stats(&state).active, 1, "{kind}");
        assert_eq!(rollback(&state, &token), (200, json!({})));
    }
}

#[test]
fn a_bad_token_is_not_read_as_the_latest_snapshot() {
    for strict in [true, false] {
        for kind in ["collection", "group", "documents"] {
            let state = state(strict);
            write_v(&state, 1);
            let (status, _) = execute(&state, pipeline(kind, json!({"transaction": "AQ=="})));
            assert_eq!(status, 400, "{strict}/{kind}");
            assert_eq!(stats(&state).active, 0);
        }
    }
}

#[test]
fn inputs_production_did_not_answer_with_a_selector_stay_refused() {
    let state = state(true);
    write_v(&state, 1);
    let union =
        json!({"name": "union", "args": [{"pipelineValue": {"stages": [source("collection")]}}]});
    for stages in [
        vec![json!({"name": "database"})],
        vec![source("collection"), union],
    ] {
        for extra in [
            json!({"newTransaction": {}}),
            json!({"readTime": "2026-01-01T00:00:00Z"}),
        ] {
            let mut body = pipeline("collection", extra);
            body["structuredPipeline"]["pipeline"]["stages"] = Value::Array(stages.clone());
            let (status, body) = execute(&state, body);
            assert_eq!(status, 501, "{body}");
            assert_eq!(
                body[0]["error"]["message"],
                json!("pipeline consistency is unsupported for this input")
            );
            let after = stats(&state);
            assert_eq!((after.active, after.finished), (0, 0));
        }
    }
}

#[test]
fn auto_commit_of_a_new_read_only_transaction_commits_it() {
    for kind in ["collection", "group", "documents"] {
        for options in [json!({}), json!({"readOnly": {}})] {
            let state = state(true);
            write_v(&state, 1);
            let (status, body) = execute(
                &state,
                pipeline(
                    kind,
                    json!({"newTransaction": options, "autoCommitTransaction": true}),
                ),
            );
            assert_eq!(status, 200, "{body}");
            let (element, v) = only(&body);
            assert_eq!(v, 1);
            assert!(element.get("transaction").is_none());
            let after = stats(&state);
            assert_eq!((after.active, after.finished), (0, 1));
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]
    /// A reference model of one selected REST pipeline: the token appears exactly when the
    /// transaction is new and not auto-committed, an auto-committed one is closed, and nothing
    /// stays open once the caller rolls its tokens back.
    #[test]
    fn selected_pipelines_follow_the_reference_model(
        kind in prop::sample::select(vec!["collection", "group", "documents"]),
        strict in any::<bool>(),
        mode in prop::sample::select(vec!["none", "default", "ro", "rw", "existing", "read_time"]),
        auto in any::<bool>(),
    ) {
        prop_assume!(!auto || !matches!(mode, "none" | "read_time"));
        let state = state(strict);
        let read_time = write_v(&state, 1);
        write_v(&state, 2);
        let mut existing = None;
        let extra = match mode {
            "none" => json!({}),
            "default" => json!({"newTransaction": {}}),
            "ro" => json!({"newTransaction": {"readOnly": {}}}),
            "rw" => json!({"newTransaction": {"readWrite": {}}}),
            "existing" => {
                let token = begin(&state, json!({"readWrite": {}}));
                existing = Some(token.clone());
                json!({"transaction": token})
            }
            "read_time" => json!({"readTime": read_time}),
            _ => unreachable!(),
        };
        let mut extra = extra;
        if auto {
            extra["autoCommitTransaction"] = json!(true);
        }
        let (status, body) = execute(&state, pipeline(kind, extra));
        prop_assert_eq!(status, 200, "{}", body);
        let (element, v) = only(&body);
        prop_assert_eq!(v, if mode == "read_time" { 1 } else { 2 });
        let announced = element.get("transaction").is_some();
        prop_assert_eq!(announced, matches!(mode, "default" | "ro" | "rw") && !auto);
        if announced {
            let token = element["transaction"].as_str().unwrap().to_owned();
            prop_assert_eq!(rollback(&state, &token), (200, json!({})));
        }
        if let Some(token) = existing {
            let closed = rollback(&state, &token).0 == 409;
            prop_assert_eq!(closed, auto);
        }
        prop_assert_eq!(stats(&state).active, 0);
    }
}
