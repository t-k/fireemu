//! Firestore REST surface at the handler level: documents, queries, transactions, errors and
//! rules (the JSON mapping is exercised end-to-end by tools/sdk-smoke/lite.mjs).

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
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
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
            policy: IndexValidationPolicy::Production,
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
        let loaded = Arc::new(RulesetSlot::new(LoadedRules::from_source(src).unwrap()));
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
fn partition_ranges_reconstruct_the_same_snapshot_without_boundary_duplicates() {
    let s = state(None);
    let mut read_time = String::new();
    for index in 0..12 {
        let (status, document) = call(
            &s,
            "PATCH",
            &format!(
                "{DOCS}/owners/{}/items/i{index:02}",
                ["a", "a-", "b"][index % 3]
            ),
            json!({"fields": {"value": {"integerValue": index.to_string()}}}),
        );
        assert_eq!(status, 200, "{document}");
        read_time = document["updateTime"].as_str().unwrap().to_owned();
    }
    let query = json!({"from": [{"collectionId": "items", "allDescendants": true}]});
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
        let points = page["partitions"].as_array().unwrap();
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
    assert_eq!(expected.len(), 12);
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
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");
    assert_eq!(
        body["error"]["message"],
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
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");
    assert_eq!(
        body["error"]["message"],
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
    assert_eq!(body["error"]["status"], "NOT_FOUND", "{body}");
    assert_eq!(
        body["error"]["message"], "The database Upper does not exist for project demo-app",
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
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT", "{body}");
    assert!(
        body["error"]["message"]
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
    let (status, body) = call(&s, "POST", &format!("{DOCS}:runQuery"), json!({"structuredQuery":{"from":[{"collectionId":"broad"}],"limit":-1}}));
    assert_eq!(status, 400);
    assert_eq!(body.as_array().map(Vec::len), Some(1));
    assert_eq!(body[0]["error"]["status"], "INVALID_ARGUMENT");
    for limit in [0, 1] {
        let (status, body) = call(&s, "POST", &format!("{DOCS}:runQuery"), json!({"structuredQuery":{"from":[{"collectionId":"broad"}],"limit":limit}}));
        assert_eq!(status, 200, "{body}");
    }
}
