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
    // Optimistic concurrency: an out-of-band write is not blocked by a reader.
    let (status, concurrent) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{"update": {"name": format!("projects/demo-app/databases/(default)/documents/n/1"), "fields": {"v": {"integerValue": "99"}}}}]}),
    );
    assert_eq!(status, 200, "{concurrent}");
    // The stale transaction aborts before its unrelated staged delete is published.
    let (status, aborted) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"transaction": txn, "writes": [{"delete": format!("projects/demo-app/databases/(default)/documents/n/2")}]}),
    );
    assert_eq!(status, 409, "{aborted}");
    assert_eq!(aborted["error"]["status"], "ABORTED");
    assert_eq!(
        aborted["error"]["message"],
        "Transaction was aborted due to a concurrent modification."
    );
    let (status, preserved) = call(&s, "GET", &format!("{DOCS}/n/2"), json!({}));
    assert_eq!(status, 200, "{preserved}");
    assert_eq!(preserved["fields"]["v"]["integerValue"], "2");

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
