//! Request planning is socket-free; actual listener delivery has a separate integration gate.
use fireemu_adapter_ui::{
    database::{prepare, DatabaseEndpoint},
    UiRequest,
};
use std::collections::BTreeMap;
use std::fmt::Write as _;

fn endpoint() -> DatabaseEndpoint {
    DatabaseEndpoint {
        address: "0.0.0.0:19000".parse().unwrap(),
        project: "demo-app".into(),
        configured_instances: BTreeMap::from([("named".into(), "demo-app".into())]),
    }
}
fn request(query: &str) -> UiRequest {
    UiRequest {
        method: "PUT".into(),
        query: query.into(),
        body: b" -0 ".to_vec(),
        ..UiRequest::default()
    }
}
fn plan(
    action: &str,
    query: &str,
) -> Result<fireemu_adapter_ui::database::DatabasePlan, fireemu_adapter_ui::UiResponse> {
    prepare(
        &endpoint(),
        &BTreeMap::from([("default".into(), "demo-app".into())]),
        action,
        &request(query),
    )
}
const SCOPE: &str = "session=default&project=demo-app&namespace=named&path=%2Fnotes%2F%E6%97%A5";
#[test]
fn raw_source_and_encoded_paths_are_preserved() {
    let prepared = plan("data", SCOPE).unwrap();
    assert_eq!(prepared.target, "/notes/%E6%97%A5.json?ns=named");
    assert_eq!(prepared.body, b" -0 ");
    assert!(prepared.administrator);
    assert_eq!(endpoint().loopback().to_string(), "127.0.0.1:19000");
}
#[test]
fn exact_session_project_and_supported_routes_are_required() {
    for query in [
        SCOPE.replace("default", "deleted"),
        SCOPE.replace("demo-app", "other"),
        format!("{SCOPE}&project=demo-app"),
    ] {
        assert!(plan("data", &query).is_err());
    }
    assert!(plan("unknown", SCOPE).is_err());
}
#[test]
fn credentials_targets_reserved_paths_and_duplicate_queries_are_refused() {
    for suffix in [
        "&auth=owner",
        "&access_token=owner",
        "&host=attacker",
        "&url=http://attacker",
        "&auth_variable_override=null",
        "&namespace=other",
        "&query=ns%3Dother",
        "&query=auth%3Downer",
        "&query=orderBy%3D1%26orderBy%3D2",
        "&query=callback%3Dalert",
        "&query=ns%253Dother",
    ] {
        assert!(
            plan("data", &format!("{SCOPE}{suffix}")).is_err(),
            "{suffix}"
        );
    }
    for path in [
        "%2F.settings%2Frules",
        "%2F.info",
        "%2F%2E%2E",
        "%2Fa%00b",
        "%2Fa%0Db",
        "%ZZ",
    ] {
        assert!(
            plan("data", &SCOPE.replace("%2Fnotes%2F%E6%97%A5", path)).is_err(),
            "{path}"
        );
    }
}
#[test]
fn probes_are_anonymous_and_rules_cannot_be_deleted() {
    assert!(!plan("request", SCOPE).unwrap().administrator);
    let mut req = request("session=default&project=demo-app&namespace=named");
    req.method = "DELETE".into();
    assert!(prepare(
        &endpoint(),
        &BTreeMap::from([("default".into(), "demo-app".into())]),
        "rules",
        &req
    )
    .is_err());
}
#[test]
fn ownership_uses_the_daemon_project_for_named_instances() {
    assert_eq!(endpoint().project_of("arbitrary-name"), "demo-app");
    assert_eq!(endpoint().project_of("other-default-rtdb"), "other");
}
#[test]
fn encoded_literal_percent_and_unicode_roundtrip_over_a_finite_property_domain() {
    for key in ["a", "日", "😀", "%2F", "+", "white space", "quote\"", "é"] {
        let mut query = SCOPE.replace("%2Fnotes%2F%E6%97%A5", "%2F");
        // Encode the input as a parameter; the planner must encode the data path exactly once.
        for byte in key.as_bytes() {
            let _ = write!(query, "%{byte:02X}");
        }
        let planned = plan("data", &query).unwrap();
        let encoded = planned
            .target
            .strip_prefix('/')
            .unwrap()
            .split(".json?")
            .next()
            .unwrap();
        assert_eq!(fireemu_adapter_ui::percent_decode(encoded), key);
    }
}

#[test]
fn body_and_operation_limits_are_enforced_before_sending() {
    let endpoint = endpoint();
    let sessions = BTreeMap::from([("default".into(), "demo-app".into())]);
    let mut req = request(SCOPE);
    req.body = vec![b'0'; fireemu_adapter_ui::MAX_JSON_BODY_BYTES + 1];
    assert_eq!(
        prepare(&endpoint, &sessions, "data", &req)
            .unwrap_err()
            .status,
        413
    );
    for method in [
        "HEAD",
        "OPTIONS",
        "CONNECT",
        "POST",
        "PUT\r\nHost: attacker",
    ] {
        req.body.clear();
        req.method = method.into();
        assert_eq!(
            prepare(&endpoint, &sessions, "data", &req)
                .unwrap_err()
                .status,
            405
        );
    }
}

#[test]
fn malformed_utf8_is_not_silently_replaced_with_another_key() {
    assert_eq!(
        plan("data", &SCOPE.replace("%E6%97%A5", "%FF"))
            .unwrap_err()
            .status,
        400
    );
}
