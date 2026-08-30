//! Firestore REST surface at the handler level: documents, queries, transactions, errors and
//! rules (the JSON mapping is exercised end-to-end by tools/sdk-smoke/lite.mjs).

use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::{RestRequest, RestState};
use fireemu_adapter_grpc::rules::RulesEnforcer;
use fireemu_core_auth::jwt::{base64url_encode, TokenAcceptance};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_rules::runtime::LoadedRules;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const DOCS: &str = "/v1/projects/demo-app/databases/(default)/documents";

fn state(rules: Option<&str>) -> RestState {
    state_with(rules, TokenAcceptance::Verified)
}

fn state_with(rules: Option<&str>, acceptance: TokenAcceptance) -> RestState {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Conservative,
        },
        indexes: IndexSet::default(),
    };
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
        let loaded = Arc::new(RwLock::new(LoadedRules::from_source(src).unwrap()));
        Arc::new(RulesEnforcer::new(loaded, auth, clock).with_token_acceptance(acceptance))
    });
    RestState {
        local,
        gateway: Arc::new(gateway),
        rules,
        app_check: None,
    }
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
    });
    (r.status, r.body)
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
    assert_eq!(listed["documents"].as_array().map(Vec::len), Some(0));
    let (status, err) = call(
        &s,
        "PUT",
        "/v1/projects/demo-app/databases/(default)/documents/users/x",
        json!({}),
    );
    assert_eq!(status, 400, "{err}");
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
            {"transform": {"document": format!("projects/demo-app/databases/(default)/documents/n/1"), "fieldTransforms": [{"fieldPath": "v", "increment": {"integerValue": "10"}}, {"fieldPath": "at", "setToServerValue": "REQUEST_TIME"}]}}
        ]}),
    );
    assert_eq!(status, 200, "{committed}");
    assert_eq!(committed["writeResults"].as_array().map(Vec::len), Some(3));
    assert_eq!(
        committed["writeResults"][2]["transformResults"][0]["integerValue"],
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
    // Concurrent write, then the transaction's commit aborts.
    call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{"update": {"name": format!("projects/demo-app/databases/(default)/documents/n/1"), "fields": {"v": {"integerValue": "99"}}}}]}),
    );
    let (status, err) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"transaction": txn, "writes": [{"delete": format!("projects/demo-app/databases/(default)/documents/n/2")}]}),
    );
    assert_eq!(status, 409, "{err}");
    assert_eq!(err["error"]["status"], "ABORTED");

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
