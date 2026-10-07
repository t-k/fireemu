use std::sync::{Arc, Mutex};

use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

use super::{RestRequest, RestState};
use crate::gateway::Gateway;
use crate::local::LocalBackend;

const DOCS: &str = "/v1/projects/demo-app/databases/(default)/documents";

fn state() -> RestState {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
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
    let (path, query) = path.split_once('?').map_or((path, ""), |parts| parts);
    let response = state.handle(&RestRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        browser_metadata: false,
        app_check: Vec::new(),
        body,
        batch_field_order: Vec::new(),
    });
    (response.status, response.body)
}

#[test]
#[allow(clippy::too_many_lines)]
fn foreign_transaction_tokens_match_profile_over_rest() {
    for strict in [true, false] {
        let mut state = state();
        if !strict {
            let mut gateway = (*state.gateway).clone();
            gateway.ctx.policy = IndexValidationPolicy::Emulator;
            gateway.enforce_limits = false;
            state.local = Arc::new(LocalBackend::new(
                gateway.clone(),
                Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH))),
                7,
            ));
            state.gateway = Arc::new(gateway);
        }
        for (issuer_project, issuer_database, project, database, tampered) in [
            ("demo-app", "(default)", "demo-app", "other", None),
            ("demo-app", "(default)", "demo-other", "(default)", None),
            ("demo-app", "(default)", "demo-other", "other", None),
            ("demo-app", "(default)", "demo-app", "other", Some(8)),
            ("demo-app", "(default)", "demo-app", "other", Some(12)),
            ("demo-app", "(default)", "demo-app", "(default)", Some(23)),
            ("demo-app", "db-000518cc", "demo-app", "db-000cec18", None),
            ("db-000518cc", "(default)", "db-000cec18", "other", None),
        ]
        .into_iter()
        .chain((0..24).flat_map(|index| {
            ["(default)", "other"]
                .map(|database| ("demo-app", "(default)", "demo-app", database, Some(index)))
        })) {
            let issuer_docs =
                format!("/v1/projects/{issuer_project}/databases/{issuer_database}/documents");
            let issuer = crate::decode::parse_parent(&issuer_docs[4..]).unwrap();
            state.local.ensure_database(&issuer).unwrap();
            let docs = format!("/v1/projects/{project}/databases/{database}/documents");
            let parent = crate::decode::parse_parent(&docs[4..]).unwrap();
            state.local.ensure_database(&parent).unwrap();
            let (status, seeded) = call(&state, "PATCH", &format!("{docs}/guard/read"), json!({}));
            assert_eq!(status, 200, "{seeded}");
            let (status, begun) = call(
                &state,
                "POST",
                &format!("{issuer_docs}:beginTransaction"),
                json!({"options": {"readWrite": {}}}),
            );
            assert_eq!(status, 200, "{begun}");
            let original = begun["transaction"].as_str().unwrap();
            let mut bytes = super::json::base64_decode(original).unwrap();
            assert_eq!(bytes.len(), 24);
            if let Some(index) = tampered {
                bytes[index] ^= 1;
            }
            let transaction = super::json::base64_encode(&bytes);
            let query_transaction = transaction.replace('+', "%2B");
            let (http, code, message) = if tampered.is_some() {
                (400, "INVALID_ARGUMENT", "Invalid transaction.")
            } else if !strict {
                (
                    400,
                    "INVALID_ARGUMENT",
                    "transaction token does not belong to this database",
                )
            } else if project != issuer_project {
                (400, "INVALID_ARGUMENT", "Invalid transaction.")
            } else {
                (
                    409,
                    "ABORTED",
                    "The referenced transaction has expired or is no longer valid.",
                )
            };
            for method in [
                "GetDocument",
                "BatchGetDocuments",
                "Commit",
                "Rollback",
                "ListDocuments",
                "RunQuery",
                "RunAggregationQuery",
                "RetryBeginTransaction",
                "RetryBatchGetDocuments",
                "RetryRunQuery",
                "RetryRunAggregationQuery",
            ] {
                let (status, refused) = match method {
                    "GetDocument" => call(
                        &state,
                        "GET",
                        &format!("{docs}/guard/read?transaction={query_transaction}"),
                        Value::Null,
                    ),
                    "BatchGetDocuments" => call(
                        &state,
                        "POST",
                        &format!("{docs}:batchGet"),
                        json!({
                            "documents": [format!("{}/guard/read", &docs[4..])], "transaction": transaction
                        }),
                    ),
                    "Commit" => call(
                        &state,
                        "POST",
                        &format!("{docs}:commit"),
                        json!({
                            "transaction": transaction,
                            "writes": [{"update": {"name": format!("{}/guard/should-not-write", &docs[4..])}}]
                        }),
                    ),
                    "Rollback" => call(
                        &state,
                        "POST",
                        &format!("{docs}:rollback"),
                        json!({"transaction": transaction}),
                    ),
                    "ListDocuments" => call(
                        &state,
                        "GET",
                        &format!("{docs}/guard?transaction={query_transaction}"),
                        Value::Null,
                    ),
                    "RetryBeginTransaction" => call(
                        &state,
                        "POST",
                        &format!("{docs}:beginTransaction"),
                        json!({"options": {"readWrite": {"retryTransaction": transaction}}}),
                    ),
                    "RetryBatchGetDocuments" => call(
                        &state,
                        "POST",
                        &format!("{docs}:batchGet"),
                        json!({"documents": [format!("{}/guard/read", &docs[4..])],
                            "newTransaction": {"readWrite": {"retryTransaction": transaction}}}),
                    ),
                    _ => {
                        let aggregation = method.ends_with("AggregationQuery");
                        let action = if aggregation {
                            "runAggregationQuery"
                        } else {
                            "runQuery"
                        };
                        let query = json!({"from": [{"collectionId": "guard"}]});
                        let mut body = if aggregation {
                            json!({"structuredAggregationQuery": {"structuredQuery": query,
                                "aggregations": [{"alias": "count", "count": {}}]}})
                        } else {
                            json!({"structuredQuery": query})
                        };
                        if method.starts_with("Retry") {
                            body["newTransaction"] =
                                json!({"readWrite": {"retryTransaction": transaction}});
                        } else {
                            body["transaction"] = json!(transaction);
                        }
                        call(&state, "POST", &format!("{docs}:{action}"), body)
                    }
                };
                assert_eq!(
                    status, http,
                    "strict={strict} {project}/{database} {method}: {refused}"
                );
                let error = if matches!(
                    method,
                    "BatchGetDocuments"
                        | "RetryBatchGetDocuments"
                        | "RunQuery"
                        | "RetryRunQuery"
                        | "RunAggregationQuery"
                        | "RetryRunAggregationQuery"
                ) {
                    &refused[0]["error"]
                } else {
                    &refused["error"]
                };
                assert_eq!(error["code"], http);
                assert_eq!(error["status"], code);
                assert_eq!(error["message"], message);
            }
            let (status, absent) = call(
                &state,
                "GET",
                &format!("{docs}/guard/should-not-write"),
                Value::Null,
            );
            assert_eq!(
                status, 404,
                "foreign transaction refusal must not write: {absent}"
            );
            let (status, rolled_back) = call(
                &state,
                "POST",
                &format!("{issuer_docs}:rollback"),
                json!({"transaction": original}),
            );
            assert_eq!(
                status, 200,
                "issuing database must retain ownership: {rolled_back}"
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn imported_databases_can_issue_identical_transaction_ids_over_rest() {
    for strict in [true, false] {
        for new_transaction in [false, true] {
            let mut state = state();
            if !strict {
                let mut gateway = (*state.gateway).clone();
                gateway.ctx.policy = IndexValidationPolicy::Emulator;
                gateway.enforce_limits = false;
                state.local = Arc::new(LocalBackend::new(
                    gateway.clone(),
                    Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH))),
                    7,
                ));
                state.gateway = Arc::new(gateway);
            }
            let databases = [
                ("demo-app", "(default)"),
                ("demo-app", "other"),
                ("demo-other", "(default)"),
            ];
            let imported = databases.map(|(project, database)| {
                (
                    (project.to_owned(), database.to_owned()),
                    fireemu_core_firestore::store::FirestoreState::new(),
                )
            });
            state
                .local
                .restore_databases(imported.clone().into_iter().collect())
                .unwrap();
            let mut transactions = Vec::new();
            for (project, database) in databases {
                let docs = format!("/v1/projects/{project}/databases/{database}/documents");
                let (status, begun) = if new_transaction {
                    call(
                        &state,
                        "POST",
                        &format!("{docs}:batchGet"),
                        json!({
                            "documents": [format!("{}/guard/read", &docs[4..])], "newTransaction": {}
                        }),
                    )
                } else {
                    call(
                        &state,
                        "POST",
                        &format!("{docs}:beginTransaction"),
                        json!({}),
                    )
                };
                assert_eq!(
                    status, 200,
                    "strict={strict} newTransaction={new_transaction}: {begun}"
                );
                let begun = if new_transaction { &begun[0] } else { &begun };
                let transaction = begun["transaction"].as_str().unwrap().to_owned();
                let bytes = super::json::base64_decode(&transaction).unwrap();
                assert_eq!(&bytes[..8], &1_u64.to_be_bytes());
                transactions.push(transaction);
            }
            assert_ne!(transactions[0], transactions[1]);
            assert_ne!(transactions[1], transactions[2]);
            let docs = "/v1/projects/demo-app/databases/other/documents";
            for index in [0, 2] {
                let transaction = &transactions[index];
                let (http, code, message) = if !strict {
                    (
                        400,
                        "INVALID_ARGUMENT",
                        "transaction token does not belong to this database",
                    )
                } else if index == 0 {
                    (
                        409,
                        "ABORTED",
                        "The referenced transaction has expired or is no longer valid.",
                    )
                } else {
                    (400, "INVALID_ARGUMENT", "Invalid transaction.")
                };
                let (status, refused) = call(
                    &state,
                    "POST",
                    &format!("{docs}:commit"),
                    json!({"transaction": transaction, "writes": [{"update": {"name": format!("{}/guard/should-not-write", &docs[4..])}}]}),
                );
                assert_eq!(status, http, "{refused}");
                assert_eq!(refused["error"]["code"], http);
                assert_eq!(refused["error"]["status"], code);
                assert_eq!(refused["error"]["message"], message);
            }
            assert_eq!(
                call(
                    &state,
                    "GET",
                    &format!("{docs}/guard/should-not-write"),
                    Value::Null
                )
                .0,
                404
            );
            for ((project, database), transaction) in
                databases.into_iter().zip(&transactions).skip(1)
            {
                assert_eq!(
                    call(
                        &state,
                        "POST",
                        &format!("/v1/projects/{project}/databases/{database}/documents:rollback"),
                        json!({"transaction": transaction})
                    )
                    .0,
                    200
                );
            }
            let (status, refused) = call(
                &state,
                "POST",
                &format!("{docs}:commit"),
                json!({"transaction": transactions[0]}),
            );
            assert_eq!(
                status,
                if strict { 409 } else { 400 },
                "retiring B must preserve A: {refused}"
            );
            assert_eq!(
                refused["error"]["message"],
                if strict {
                    "The referenced transaction has expired or is no longer valid."
                } else {
                    "transaction token does not belong to this database"
                }
            );
            // Import replaces the states and restarts their database-local counters.
            state
                .local
                .restore_databases(imported.into_iter().collect())
                .unwrap();
            let (status, begun) = call(
                &state,
                "POST",
                &format!("{docs}:beginTransaction"),
                json!({}),
            );
            assert_eq!(status, 200, "{begun}");
            let bytes = super::json::base64_decode(begun["transaction"].as_str().unwrap()).unwrap();
            assert_eq!(&bytes[..8], &1_u64.to_be_bytes());
            let (status, refused) = call(
                &state,
                "POST",
                &format!("{docs}:commit"),
                json!({"transaction": transactions[0]}),
            );
            assert_eq!(status, 400, "{refused}");
            assert_eq!(
                refused["error"]["message"],
                if strict {
                    "Invalid transaction."
                } else {
                    "transaction token does not belong to this database"
                }
            );
            assert_eq!(
                call(
                    &state,
                    "POST",
                    &format!("{docs}:rollback"),
                    json!({"transaction": begun["transaction"]})
                )
                .0,
                200
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn failed_rest_commit_requires_rollback_before_exact_subsequent_poststate() {
    let state = state();
    let original = format!("{DOCS}/locked/doc");
    let valid_target = format!("{DOCS}/atomic/valid");
    let invalid_target = format!("{DOCS}/atomic/invalid");
    let original_fields = json!({"value": {"integerValue": "1"}});
    let (status, body) = call(
        &state,
        "PATCH",
        &original,
        json!({"fields": original_fields.clone()}),
    );
    assert_eq!(status, 200, "{body}");

    let (status, begun) = call(
        &state,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readWrite": {}}}),
    );
    assert_eq!(status, 200, "{begun}");
    let transaction = begun["transaction"]
        .as_str()
        .expect("transaction token")
        .to_owned();
    let (status, read) = call(
        &state,
        "GET",
        &format!("{original}?transaction={transaction}"),
        Value::Null,
    );
    assert_eq!(status, 200, "{read}");
    assert_eq!(read["fields"], original_fields);

    let oversized = "x".repeat(1_048_488);
    let (status, failed) = call(
        &state,
        "POST",
        &format!("{DOCS}:commit"),
        json!({
            "transaction": transaction,
            "writes": [
                {"update": {"name": "projects/demo-app/databases/(default)/documents/atomic/valid"}},
                {"update": {"name": "projects/demo-app/databases/(default)/documents/atomic/invalid", "fields": {"value": {"stringValue": oversized}}}}
            ]
        }),
    );
    assert_eq!(status, 400, "{failed}");
    assert_eq!(failed["error"]["status"], "INVALID_ARGUMENT");

    let (status, absent) = call(&state, "GET", &valid_target, Value::Null);
    assert_eq!(
        status, 404,
        "failed Commit must publish no valid write: {absent}"
    );
    let (status, absent) = call(&state, "GET", &invalid_target, Value::Null);
    assert_eq!(
        status, 404,
        "failed Commit must publish no invalid write: {absent}"
    );
    let (status, still_usable) = call(
        &state,
        "GET",
        &format!("{original}?transaction={transaction}"),
        Value::Null,
    );
    assert_eq!(
        status, 200,
        "failed Commit leaves transaction usable: {still_usable}"
    );
    assert_eq!(still_usable["fields"], original_fields);

    let control = format!("{DOCS}/atomic/control");
    let (status, control_commit) = call(
        &state,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{"update": {"name": "projects/demo-app/databases/(default)/documents/atomic/control"}}]}),
    );
    assert_eq!(status, 200, "{control_commit}");
    let (status, control_document) = call(&state, "GET", &control, Value::Null);
    assert_eq!(status, 200, "{control_document}");
    assert_eq!(
        control_document["name"],
        "projects/demo-app/databases/(default)/documents/atomic/control"
    );
    assert!(
        control_document.get("fields").is_none(),
        "an empty update writes the document without a fields member: {control_document}"
    );

    let (status, contended) = call(
        &state,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{"update": {"name": "projects/demo-app/databases/(default)/documents/locked/doc", "fields": {"value": {"integerValue": "9"}}}}]}),
    );
    assert_eq!(status, 409, "{contended}");
    assert_eq!(contended["error"]["status"], "ABORTED");

    let (status, rolled_back) = call(
        &state,
        "POST",
        &format!("{DOCS}:rollback"),
        json!({"transaction": transaction}),
    );
    assert_eq!(status, 200, "{rolled_back}");
    let (status, committed) = call(
        &state,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{"update": {"name": "projects/demo-app/databases/(default)/documents/locked/doc", "fields": {"value": {"integerValue": "2"}}}}]}),
    );
    assert_eq!(status, 200, "{committed}");
    let (status, poststate) = call(&state, "GET", &original, Value::Null);
    assert_eq!(status, 200, "{poststate}");
    assert_eq!(
        poststate["name"],
        "projects/demo-app/databases/(default)/documents/locked/doc"
    );
    assert_eq!(
        poststate["fields"],
        json!({"value": {"integerValue": "2"}}),
        "rollback must permit the exact subsequent write poststate"
    );
}
