//! Tests of the diagnostics bundle route: guard, format choice, denied rules and secret masking.

use fireemu_adapter_http::control::{handle, handle_with, ControlState};
use fireemu_adapter_http::identity_toolkit::RequestHeaders;
use fireemu_core_rules::runtime::RulesetSlot;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::FirestoreEdition;
use fireemu_core_types::time::LogicalInstant;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

fn state(counter: Arc<AtomicUsize>) -> ControlState {
    ControlState {
        clock: Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        require_demo_prefix: true,
        edition: FirestoreEdition::Standard,
        capabilities: json!({"schemaVersion": 1}).into(),
        rules: Arc::new(RulesetSlot::default()),
        storage_rules: Arc::new(fireemu_adapter_http::storage::StorageRulesRegistry::default()),
        reset_hooks: vec![Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })],
        functions: None,
        control_token: "test-token".to_owned(),
        app_check: None,
        firestore_listen_expiry: None,
        firestore_missing_indexes: None,
        require_control_token: false,
        barrier: None,
        snapshot_hooks: Vec::new(),
        snapshots: Mutex::new(std::collections::BTreeMap::new()),
        faults: Some(Arc::new(fireemu_core_session::fault::FaultRegistry::new())),
        text_indexes: Arc::new(Mutex::new(
            fireemu_core_firestore::text_index::TextIndexCatalog::default(),
        )),
        default_project: "demo-app".to_owned(),
        tenancy: Arc::new(RwLock::new(fireemu_core_session::tenancy::Tenancy::new(
            "demo-app",
        ))),
        sessions: Mutex::new(std::collections::BTreeMap::from([(
            "default".to_owned(),
            "demo-app".to_owned(),
        )])),
        project_hooks: None,
        resource_hooks: Vec::new(),
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn bundle_guards_and_denials_and_redacts_both_formats() {
    use fireemu_core_rules::coverage::RequestTrace;
    use fireemu_core_rules::eval::{evaluate_request_traced, Method, RequestContext, RulesService};
    use fireemu_core_rules::parse::parse_ruleset;

    let s = state(Arc::new(AtomicUsize::new(0)));
    let sentinel = ["confidential", "example", "value"].concat();
    let source = format!("rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow get: if id != 'Bearer {sentinel}'; }} }} }}");
    assert_eq!(
        handle(&s, "PUT", "/v1/rules", &json!({"source": source})).status,
        200
    );
    let ruleset = parse_ruleset(&source).unwrap();
    let ctx = RequestContext {
        service: RulesService::Firestore,
        method: Method::Get,
        path: format!("/databases/(default)/documents/notes/Bearer {sentinel}"),
        auth: None,
        resource: None,
        request_resource: None,
        time_unix_nanos: 1_788_004_860_i128 * 1_000_000_000,
        abstract_path: false,
        request_query: None,
    };
    let (_, coverage) = evaluate_request_traced(&ruleset, &ctx, None);
    let expressions = coverage.trace_entries();
    let expected = expressions
        .iter()
        .find(|e| {
            source
                .get(e.span.offset..e.end)
                .is_some_and(|excerpt| excerpt.contains(&sentinel))
        })
        .expect("the secret is present in a traced excerpt");
    let (line, column) = (expected.span.line, expected.span.column);
    let rules = s.rules.snapshot().unwrap();
    let mut diagnostics = rules.diagnostics.lock().unwrap();
    diagnostics.enable_request_traces_with_capacity(100);
    diagnostics.push(&coverage, |sequence| RequestTrace {
        sequence,
        method: "get",
        path: "notes/a".to_owned(),
        allowed: false,
        reason: "denied".to_owned(),
        uid: None,
        expressions,
    });
    drop(diagnostics);
    let path = "/v1/sessions/default/diagnostics/bundle";
    for authorization in [None, Some("Bearer wrong".to_owned())] {
        let headers = RequestHeaders {
            authorization,
            ..RequestHeaders::default()
        };
        assert_eq!(
            handle_with(&s, "GET", path, &headers, &json!({})).status,
            403
        );
    }
    let headers = RequestHeaders {
        authorization: Some(format!("Bearer {}", s.control_token)),
        ..RequestHeaders::default()
    };
    let result = handle_with(&s, "GET", path, &headers, &json!({}));
    assert_eq!(result.status, 200);
    assert_eq!(result.body["schemaVersion"], 1);
    let conditions = result.body["rules"]["denials"][0]["conditions"]
        .as_array()
        .unwrap();
    assert!(conditions.iter().any(|c| c["line"] == line
        && c["column"] == column
        && c["excerpt"].as_str() == Some("[redacted]")));
    assert!(!result.body.to_string().contains(&sentinel));
    assert!(result.body["redactions"].as_u64().unwrap() > 0);
    let html = handle_with(
        &s,
        "GET",
        &format!("{path}?format=html"),
        &headers,
        &json!({}),
    );
    assert_eq!(html.status, 200);
    assert!(html.body["html"]
        .as_str()
        .unwrap()
        .contains("<!doctype html>"));
    assert!(!html.body.to_string().contains(&sentinel));
    assert_eq!(
        handle_with(
            &s,
            "GET",
            &format!("{path}?format=bad"),
            &headers,
            &json!({})
        )
        .status,
        400
    );
    s.sessions
        .lock()
        .unwrap()
        .insert("other".to_owned(), "demo-other".to_owned());
    let other = handle_with(
        &s,
        "GET",
        "/v1/sessions/other/diagnostics/bundle",
        &headers,
        &json!({}),
    );
    assert_eq!(other.status, 400);
    assert!(other.body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("FAILED_PRECONDITION"));
}

#[test]
fn bundle_masks_recorded_rule_values() {
    use fireemu_core_rules::coverage::RequestTrace;
    use fireemu_core_rules::eval::{
        evaluate_request_traced, Decision, Method, RequestContext, RulesService,
    };
    use fireemu_core_rules::parse::parse_ruleset;
    use fireemu_core_rules::value::RulesValue;
    use std::collections::BTreeMap;

    let s = state(Arc::new(AtomicUsize::new(0)));
    let sentinel = ["private", "payload"].concat();
    let source = "rules_version = '2'; service cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow get: if resource.data.secret == 'other' || (resource.data.number == 42 && resource.data.enabled == true && resource.data.items == [] && resource.data.long == 'other'); } } }";
    assert_eq!(
        handle(&s, "PUT", "/v1/rules", &json!({"source": source})).status,
        200
    );
    let data = RulesValue::Map(BTreeMap::from([
        ("secret".into(), RulesValue::String(sentinel.clone())),
        ("number".into(), RulesValue::Int(42)),
        ("enabled".into(), RulesValue::Bool(true)),
        ("items".into(), RulesValue::List(vec![])),
        ("long".into(), RulesValue::String(sentinel.repeat(200))),
    ]));
    let ctx = RequestContext {
        service: RulesService::Firestore,
        method: Method::Get,
        path: "/databases/(default)/documents/notes/a".into(),
        auth: None,
        resource: Some(RulesValue::Map(BTreeMap::from([("data".into(), data)]))),
        request_resource: None,
        time_unix_nanos: 0,
        abstract_path: false,
        request_query: None,
    };
    let (report, coverage) = evaluate_request_traced(&parse_ruleset(source).unwrap(), &ctx, None);
    assert!(matches!(report.decision, Decision::Deny(_)));
    let rules = s.rules.snapshot().unwrap();
    let mut diagnostics = rules.diagnostics.lock().unwrap();
    diagnostics.enable_request_traces_with_capacity(100);
    diagnostics.push(&coverage, |sequence| RequestTrace {
        sequence,
        method: "get",
        path: "notes/a".into(),
        allowed: false,
        reason: "denied".into(),
        uid: None,
        expressions: coverage.trace_entries(),
    });
    drop(diagnostics);
    let headers = RequestHeaders {
        authorization: Some(format!("Bearer {}", s.control_token)),
        ..RequestHeaders::default()
    };
    for suffix in ["", "?format=html"] {
        let result = handle_with(
            &s,
            "GET",
            &format!("/v1/sessions/default/diagnostics/bundle{suffix}"),
            &headers,
            &json!({}),
        );
        assert_eq!(result.status, 200);
        let output = result.body.to_string();
        assert!(!output.contains(&sentinel));
        assert!(output.contains(&format!("string(len={})", sentinel.len())));
        assert!(output.contains("string(truncated)"));
        assert!(output.contains("composite(list)"));
        assert!(output.contains("Int(42)"));
        assert!(output.contains("Bool(true)"));
    }
}

struct BundleFunctions(serde_json::Value);

impl fireemu_adapter_http::control::FunctionsHook for BundleFunctions {
    fn on_clock_changed(&self) {}
    fn run_schedule(&self, _: &str) -> Result<(), fireemu_adapter_http::control::RunScheduleError> {
        Ok(())
    }
    fn is_idle(&self) -> bool {
        true
    }
    fn idle_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::new(tokio::sync::Notify::new())
    }
    fn status(&self) -> serde_json::Value {
        self.0.clone()
    }
    fn publish(
        &self,
        _: &str,
        _: &[serde_json::Value],
    ) -> Result<Vec<String>, fireemu_adapter_http::control::PublishMessagesError> {
        Ok(vec![])
    }
    fn project(&self) -> String {
        "demo-app".into()
    }
}

#[test]
fn bundle_reports_functions_causality_gaps() {
    for (evicted, reset_gaps, truncated, log_gaps, expected) in [
        (0, 0, false, false, false),
        (1, 0, false, false, true),
        (0, 1, false, false, true),
        (0, 0, true, false, true),
        (0, 0, false, true, true),
    ] {
        let mut s = state(Arc::new(AtomicUsize::new(0)));
        s.functions = Some(Arc::new(BundleFunctions(
            json!({"logGaps": log_gaps, "causality": {"evicted": evicted, "resetGaps": reset_gaps, "truncated": truncated}}),
        )));
        let headers = RequestHeaders {
            authorization: Some(format!("Bearer {}", s.control_token)),
            ..RequestHeaders::default()
        };
        let result = handle_with(
            &s,
            "GET",
            "/v1/sessions/default/diagnostics/bundle",
            &headers,
            &json!({}),
        );
        assert_eq!(result.status, 200);
        assert_eq!(result.body["functions"]["logGaps"], expected);
    }
}
