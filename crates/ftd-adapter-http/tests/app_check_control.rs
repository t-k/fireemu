//! The privileged App Check observation route (specification section 15; obligation
//! `AC-OBS-001`, management and observation scenarios 2 and 4).
//!
//! Debug-token management (scenario 1) is covered by `tests/app_check.rs`, which the AC0
//! milestone delivered; this file covers the read-only observation surface AC1 adds.

mod app_check_support;

use std::sync::{Arc, Mutex, RwLock};

use app_check_support as fixture;
use ftd_adapter_http::control::{handle_with, ControlState};
use ftd_adapter_http::identity_toolkit::RequestHeaders;
use ftd_core_app_check::admission::{AdmissionRequest, PrivilegedBypass};
use ftd_core_app_check::header::HeaderClassification;
use ftd_core_app_check::verify::BaselineMode;
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_types::edition::FirestoreEdition;
use ftd_core_types::time::LogicalInstant;
use serde_json::json;

const TOKEN: &str = "test-control-token";
const OBSERVATIONS: &str = "/v1/sessions/default/appCheck/observations";

fn state(app_check: Option<ftd_core_app_check::AppCheckGate>) -> ControlState {
    ControlState {
        clock: Arc::new(Mutex::new(ftd_core_session::clock::VirtualClock::new(
            LogicalInstant::from_unix_seconds(fixture::START),
        ))),
        require_demo_prefix: true,
        edition: FirestoreEdition::Standard,
        capabilities: json!({"schemaVersion": 1}),
        rules: Arc::new(RwLock::new(LoadedRules::default())),
        storage_rules: Arc::new(RwLock::new(LoadedRules::default())),
        reset_hooks: Vec::new(),
        functions: None,
        control_token: TOKEN.to_owned(),
        app_check,
        barrier: None,
        snapshot_hooks: Vec::new(),
        snapshots: Mutex::new(std::collections::BTreeMap::new()),
        faults: Some(Arc::new(ftd_core_session::fault::FaultRegistry::new())),
        text_indexes: Arc::new(Mutex::new(
            ftd_core_firestore::text_index::TextIndexCatalog::default(),
        )),
        default_project: "demo-app".to_owned(),
        tenancy: Arc::new(RwLock::new(ftd_core_session::tenancy::Tenancy::new(
            "demo-app",
        ))),
        sessions: Mutex::new(std::collections::BTreeMap::from([(
            "default".to_owned(),
            "demo-app".to_owned(),
        )])),
        project_hooks: None,
    }
}

fn control() -> RequestHeaders {
    RequestHeaders {
        authorization: Some(format!("Bearer {TOKEN}")),
        ..RequestHeaders::default()
    }
}

/// Records a handful of classified requests against the gate, as the adapters would.
fn record(
    gate: &ftd_core_app_check::AppCheckGate,
    app_check: &Arc<ftd_adapter_http::app_check::AppCheckState>,
) {
    let policy = ftd_core_app_check::admission::ServiceAdmission::new(
        gate.clone(),
        "firestore",
        BaselineMode::Unenforced,
    )
    .expect("a non-off mode has an admission");
    let valid = fixture::token(app_check, "demo-app", fixture::APP_ID);
    let at = LogicalInstant::from_unix_seconds(fixture::START);
    for (operation, header, bypass) in [
        (
            "Commit",
            HeaderClassification::Present(valid.clone()),
            PrivilegedBypass::None,
        ),
        (
            "Commit",
            HeaderClassification::Present(valid),
            PrivilegedBypass::None,
        ),
        (
            "GetDocument",
            HeaderClassification::Missing,
            PrivilegedBypass::None,
        ),
        (
            "RunQuery",
            HeaderClassification::Present("not-a-jwt".to_owned()),
            PrivilegedBypass::None,
        ),
        (
            "ListDocuments",
            HeaderClassification::Missing,
            PrivilegedBypass::FirestoreOwner,
        ),
    ] {
        let _ = policy.admit(&AdmissionRequest {
            project_id: "demo-app",
            transport: "grpc",
            operation,
            bypass,
            header: &header,
            now: at,
        });
    }
}

fn gate() -> (
    ftd_core_app_check::AppCheckGate,
    Arc<ftd_adapter_http::app_check::AppCheckState>,
) {
    let app_check = fixture::app_check_state(1, fixture::clock());
    (app_check.gate(), app_check)
}

// ------------------------------------------------------------------------------------------
// Scenario 2: read-only observations reject a missing or wrong control token
// ------------------------------------------------------------------------------------------

#[test]
fn read_only_observations_reject_a_missing_or_wrong_control_token() {
    let (gate, app_check) = gate();
    record(&gate, &app_check);
    let s = state(Some(gate));

    for (name, headers) in [
        ("no credential at all", RequestHeaders::default()),
        (
            "a wrong control token",
            RequestHeaders {
                authorization: Some("Bearer not-the-control-token".to_owned()),
                ..RequestHeaders::default()
            },
        ),
        (
            "a non-bearer credential",
            RequestHeaders {
                authorization: Some(TOKEN.to_owned()),
                ..RequestHeaders::default()
            },
        ),
    ] {
        // Every method, and with no Origin at all: unlike the rest of the control API this
        // route never trusts a command-line client on loopback.
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] {
            let r = handle_with(&s, method, OBSERVATIONS, &headers, &json!({}));
            assert_eq!(r.status, 403, "{method} with {name}: {}", r.body);
            assert!(
                r.body.to_string().contains("CONTROL_TOKEN_REQUIRED"),
                "{method} with {name}: {}",
                r.body
            );
            assert!(
                !r.body.to_string().contains("APP_CHECK_"),
                "an unauthenticated caller learns no failure reason: {}",
                r.body
            );
        }
    }

    let allowed = handle_with(&s, "GET", OBSERVATIONS, &control(), &json!({}));
    assert_eq!(allowed.status, 200, "{}", allowed.body);
}

#[test]
fn the_observation_route_is_read_only_and_names_its_session() {
    let (gate, app_check) = gate();
    record(&gate, &app_check);
    let s = state(Some(gate));
    let denied = handle_with(&s, "POST", OBSERVATIONS, &control(), &json!({}));
    assert_eq!(denied.status, 405, "{}", denied.body);

    let missing = handle_with(
        &s,
        "GET",
        "/v1/sessions/nope/appCheck/observations",
        &control(),
        &json!({}),
    );
    assert_eq!(missing.status, 404, "{}", missing.body);
}

#[test]
fn the_observation_route_is_absent_while_app_check_is_disabled() {
    let s = state(None);
    let r = handle_with(&s, "GET", OBSERVATIONS, &control(), &json!({}));
    assert_eq!(r.status, 404, "{}", r.body);
    assert!(
        r.body.to_string().contains("appCheck.enabled"),
        "{}",
        r.body
    );
}

// ------------------------------------------------------------------------------------------
// Counters and redaction
// ------------------------------------------------------------------------------------------

#[test]
fn observations_count_by_service_app_category_and_outcome() {
    let (gate, app_check) = gate();
    record(&gate, &app_check);
    let s = state(Some(gate));
    let r = handle_with(&s, "GET", OBSERVATIONS, &control(), &json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["session"], "default");
    assert_eq!(r.body["project"], "demo-app");

    let counters = r.body["counters"].as_array().expect("counters");
    let find = |app_id: &str, category: &str| -> u64 {
        counters
            .iter()
            .find(|c| c["appId"] == app_id && c["category"] == category)
            .and_then(|c| c["count"].as_u64())
            .unwrap_or(0)
    };
    assert_eq!(find(fixture::APP_ID, "valid"), 2);
    assert_eq!(find("unknown", "missing"), 1);
    assert_eq!(find("unknown", "invalid"), 1);
    assert_eq!(find("unknown", "bypass"), 1);
    assert!(
        counters.iter().all(|c| c["outcome"] == "admitted"),
        "unenforced admits everything: {counters:?}"
    );

    // The privileged view is exactly where the detailed reasons live.
    let observations = r.body["observations"].as_array().expect("observations");
    assert_eq!(observations.len(), 5);
    assert!(
        observations
            .iter()
            .any(|o| o["reason"] == "APP_CHECK_MALFORMED"),
        "{observations:?}"
    );
    assert!(observations.iter().all(|o| o["mode"] == "unenforced"));
}

/// Section 15: nothing the caller controls becomes a counter label, and no secret is exposed.
#[test]
fn unknown_token_input_does_not_create_an_unbounded_metrics_label() {
    let (gate, app_check) = gate();
    let policy = ftd_core_app_check::admission::ServiceAdmission::new(
        gate.clone(),
        "storage",
        BaselineMode::Enforced,
    )
    .expect("a non-off mode has an admission");
    let at = LogicalInstant::from_unix_seconds(fixture::START);
    let mut presented = Vec::new();
    for i in 0..32 {
        let token = format!("attacker-controlled-app-id-{i}");
        presented.push(token.clone());
        let _ = policy.admit(&AdmissionRequest {
            project_id: "demo-app",
            transport: "http",
            operation: "storage.upload",
            bypass: PrivilegedBypass::None,
            header: &HeaderClassification::Present(token),
            now: at,
        });
    }
    // One correctly signed token, so a verified label does exist alongside the bucket.
    let valid = fixture::token(&app_check, "demo-app", fixture::APP_ID);
    let _ = policy.admit(&AdmissionRequest {
        project_id: "demo-app",
        transport: "http",
        operation: "storage.upload",
        bypass: PrivilegedBypass::None,
        header: &HeaderClassification::Present(valid.clone()),
        now: at,
    });

    let s = state(Some(gate));
    let r = handle_with(&s, "GET", OBSERVATIONS, &control(), &json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    let counters = r.body["counters"].as_array().expect("counters");
    let labels: Vec<&str> = counters
        .iter()
        .filter_map(|c| c["appId"].as_str())
        .collect();
    assert_eq!(
        labels.len(),
        2,
        "32 unverified identities collapse into one bucket: {labels:?}"
    );
    assert!(labels.contains(&"unknown"));
    assert!(labels.contains(&fixture::APP_ID));

    let rendered = r.body.to_string();
    for token in presented {
        assert!(!rendered.contains(&token), "{token} leaked into {rendered}");
    }
    assert!(!rendered.contains(&valid), "no raw JWT is ever rendered");
    assert!(!rendered.contains("ftd_epoch"), "{rendered}");
}

/// The route is privileged and mutable-looking data must never be cached (section 15).
#[test]
fn the_observation_route_is_marked_no_store() {
    assert!(ftd_adapter_http::control::is_no_store_path(OBSERVATIONS));
    assert!(ftd_adapter_http::control::is_no_store_path(
        "/v1/sessions/other/appCheck/observations?x=1"
    ));
    assert!(!ftd_adapter_http::control::is_no_store_path(
        "/v1/sessions/default"
    ));
}
