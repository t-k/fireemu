//! The daemon side of the Admin SDK App Check instrumentation: the verdict handler a runner
//! reaches over its private stdio pipe, the session admission barrier, project scoping and the
//! fail-closed paths.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use fireemu_adapter_functions::admin_app_check::{
    answer, parse_request, reply_frame, AdminAppCheckVerifier, BarrierVerifier, Reply,
    MAX_IN_FLIGHT,
};
use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{InvokeOutcome, Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
use fireemu_core_app_check::admin::{AdminPolicy, AdminRejection, AdminVerdict};
use fireemu_core_app_check::admission::AppCheckGate;
use fireemu_core_app_check::crypto::AppCheckSigner;
use fireemu_core_app_check::registry::{AppCheckRegistry, AppRegistration, ProjectEpoch};
use fireemu_core_functions::manifest::BlockingAuthEvent;
use fireemu_core_session::barrier::AdmissionBarrier;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::{DeterministicRng, SplitMix64};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const PROJECT: &str = "demo-app";
const APP_ID: &str = "1:1234567890:web:local-test-app";
const OTHER_APP_ID: &str = "1:9876543210:web:other-test-app";

fn keyed_tag(key: u64, input: &[u8]) -> [u8; 32] {
    let mut acc = SplitMix64::new(key).next_u64();
    for byte in input {
        acc = SplitMix64::new(acc ^ u64::from(*byte).wrapping_mul(0x9E37_79B9)).next_u64();
    }
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(
            &SplitMix64::new(acc ^ (i as u64).wrapping_mul(0x1234_5678))
                .next_u64()
                .to_be_bytes(),
        );
    }
    out
}

struct TestSigner(String);

impl AppCheckSigner for TestSigner {
    fn alg(&self) -> &'static str {
        "RS256"
    }
    fn kid(&self) -> &str {
        &self.0
    }
    fn sign(&self, input: &[u8]) -> Vec<u8> {
        keyed_tag(11, input).to_vec()
    }
    fn verify(&self, input: &[u8], signature: &[u8]) -> bool {
        signature == self.sign(input)
    }
    fn public_jwk_json(&self) -> String {
        format!(r#"{{"kty":"oct","kid":"{}"}}"#, self.0)
    }
}

fn gate() -> AppCheckGate {
    let mut registry = AppCheckRegistry::new(3600).unwrap();
    for (project, number, app) in [
        (PROJECT, "1234567890", APP_ID),
        ("demo-other", "9876543210", OTHER_APP_ID),
    ] {
        registry
            .register_app(AppRegistration {
                project_id: project.to_owned(),
                project_number: number.to_owned(),
                app_id: app.to_owned(),
                enabled: true,
                debug_token_digests: Vec::new(),
            })
            .unwrap();
    }
    registry.set_project_epoch(PROJECT, ProjectEpoch::new(0x0123_4567_89AB_CDEF));
    registry.set_project_epoch("demo-other", ProjectEpoch::new(0xFEDC_BA98_7654_3210));
    AppCheckGate::new(
        Arc::new(RwLock::new(registry)),
        Arc::new(TestSigner("fireemu-app-check-test".to_owned())),
    )
}

fn token(gate: &AppCheckGate, project: &str, app: &str) -> String {
    let registry = gate.registry().read().unwrap();
    let claims = registry.issue_claims(project, app, START).unwrap();
    fireemu_core_app_check::jwt::encode(&claims, gate.signer().as_ref())
}

fn verifier(gate: &AppCheckGate, barrier: &Arc<AdmissionBarrier>) -> Arc<BarrierVerifier> {
    Arc::new(BarrierVerifier::new(
        gate.clone(),
        barrier.clone(),
        PROJECT.to_owned(),
        Arc::new(|| Some(START)),
        AdminPolicy::STRICT,
    ))
}

fn spec() -> SpawnSpec {
    SpawnSpec {
        command: vec![
            "python3".to_owned(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_admin_runner.py").to_owned(),
        ],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(60),
    }
}

async fn ask(runner: &Runner, event: Value) -> Vec<Value> {
    let invocation = runner
        .invoke(
            json!({"invocationId": "ask", "function": "f", "trigger": "http", "event": event}),
            Duration::from_secs(30),
        )
        .await;
    match invocation.outcome {
        InvokeOutcome::Failed(text) => serde_json::from_str(&text).expect("verdict list"),
        other => panic!("unexpected outcome {other:?}"),
    }
}

fn request(id: &str, project: &str, token: &str) -> Value {
    json!({"requestId": id, "projectId": project, "token": token})
}

fn reason_of(verdict: &Value) -> Option<&str> {
    verdict["reason"].as_str()
}

#[test]
fn frame_parsing_accepts_only_bounded_well_formed_requests() {
    let ok = parse_request(
        &json!({"type": "appCheck:verify", "requestId": "r1", "projectId": "p", "token": "t"}),
    );
    let ok = ok.expect("well formed");
    assert_eq!(
        (
            ok.request_id.as_str(),
            ok.project_id.as_str(),
            ok.token.as_str()
        ),
        ("r1", "p", "t")
    );
    // A usable request id travels with the refusal so the runner can fail that call.
    for (frame, id) in [
        (json!({"requestId": "r2", "projectId": "p"}), Some("r2")),
        (
            json!({"requestId": "r3", "projectId": 7, "token": "t"}),
            Some("r3"),
        ),
        (
            json!({"requestId": "r4", "projectId": "p", "token": "x".repeat(16 * 1024 + 1)}),
            Some("r4"),
        ),
        (
            json!({"requestId": "r5", "projectId": "", "token": "t"}),
            Some("r5"),
        ),
        (
            json!({"requestId": "r6", "projectId": "p".repeat(257), "token": "t"}),
            Some("r6"),
        ),
        (
            json!({"requestId": "", "projectId": "p", "token": "t"}),
            None,
        ),
        (
            json!({"requestId": 5, "projectId": "p", "token": "t"}),
            None,
        ),
        (
            json!({"requestId": "i".repeat(129), "projectId": "p", "token": "t"}),
            None,
        ),
        (json!({}), None),
    ] {
        assert_eq!(
            parse_request(&frame).err().flatten().as_deref(),
            id,
            "{frame}"
        );
    }
}

#[test]
fn debug_output_names_the_request_and_the_verifier_but_never_the_token() {
    let request = parse_request(&json!({
        "requestId": "r-debug", "projectId": "p-debug", "token": "SECRET-TOKEN-VALUE"
    }))
    .unwrap();
    let shown = format!("{request:?}");
    assert!(
        shown.contains("r-debug") && shown.contains("p-debug"),
        "{shown}"
    );
    assert!(!shown.contains("SECRET-TOKEN-VALUE"), "{shown}");
    let gate = gate();
    let verifier = verifier(&gate, &Arc::new(AdmissionBarrier::new()));
    let shown = format!("{verifier:?}");
    assert!(
        shown.contains("BarrierVerifier") && shown.contains(PROJECT),
        "{shown}"
    );
    assert!(shown.contains("policy"), "{shown}");
}

#[test]
fn reply_frames_carry_the_wire_reason_and_nothing_else() {
    assert_eq!(
        reply_frame("r1", Reply::Verdict(AdminVerdict::Accept)),
        json!({"type": "appCheck:verdict", "requestId": "r1", "ok": true})
    );
    for rejection in AdminRejection::ALL {
        assert_eq!(
            reply_frame("r1", Reply::Verdict(AdminVerdict::Reject(rejection))),
            json!({"type": "appCheck:verdict", "requestId": "r1", "ok": false, "reason": rejection.wire()})
        );
    }
    assert_eq!(
        reply_frame("r1", Reply::Unavailable),
        json!({"type": "appCheck:verdict", "requestId": "r1", "ok": false, "reason": "unavailable"})
    );
}

#[test]
fn the_answer_is_unavailable_without_a_verifier_and_scoped_to_the_runners_project() {
    let gate = gate();
    let barrier = Arc::new(AdmissionBarrier::new());
    let verifier = verifier(&gate, &barrier);
    let own = token(&gate, PROJECT, APP_ID);
    let req =
        parse_request(&json!({"requestId": "r", "projectId": PROJECT, "token": own})).unwrap();
    assert!(matches!(answer(&req, None), Reply::Unavailable));
    assert!(matches!(
        answer(&req, Some(&*verifier)),
        Reply::Verdict(AdminVerdict::Accept)
    ));
    // Another project's name never reaches that project's registry state.
    let other = parse_request(&json!({"requestId": "r", "projectId": "demo-other", "token": token(&gate, "demo-other", OTHER_APP_ID)})).unwrap();
    assert!(matches!(
        answer(&other, Some(&*verifier)),
        Reply::Verdict(AdminVerdict::Reject(AdminRejection::NoMatchingKid))
    ));
}

#[test]
fn an_unreadable_clock_makes_the_answer_unavailable_never_an_acceptance() {
    let gate = gate();
    let barrier = Arc::new(AdmissionBarrier::new());
    for policy in [AdminPolicy::STRICT, AdminPolicy::OWNER_RULINGS] {
        let verifier = BarrierVerifier::new(
            gate.clone(),
            barrier.clone(),
            PROJECT.to_owned(),
            Arc::new(|| None),
            policy,
        );
        assert_eq!(
            verifier.verify(PROJECT, &token(&gate, PROJECT, APP_ID)),
            Reply::Unavailable
        );
    }
}

#[test]
fn a_verification_waits_out_a_reset_and_sees_the_state_after_it() {
    let gate = gate();
    let barrier = Arc::new(AdmissionBarrier::new());
    let verifier = verifier(&gate, &barrier);
    let own = token(&gate, PROJECT, APP_ID);
    assert_eq!(
        verifier.verify(PROJECT, &own),
        Reply::Verdict(AdminVerdict::Accept)
    );

    let exclusive = barrier.exclusive();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = {
        let verifier = verifier.clone();
        let own = own.clone();
        std::thread::spawn(move || tx.send(verifier.verify(PROJECT, &own)).unwrap())
    };
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "no verdict while the reset holds the barrier"
    );
    gate.set_epochs(&[(PROJECT.to_owned(), ProjectEpoch::new(42))]);
    drop(exclusive);
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(10))
            .expect("verdict after the reset"),
        Reply::Verdict(AdminVerdict::Reject(AdminRejection::NoMatchingKid))
    );
    worker.join().unwrap();
}

#[tokio::test]
async fn a_runner_gets_the_daemons_verdict_over_its_pipe() {
    let gate = gate();
    let barrier = Arc::new(AdmissionBarrier::new());
    let runner = Runner::spawn_spec_with(&spec(), Some(verifier(&gate, &barrier)))
        .await
        .unwrap();
    let valid = token(&gate, PROJECT, APP_ID);
    let mut forged = valid.clone();
    forged.push('A');
    let other_project = token(&gate, "demo-other", OTHER_APP_ID);
    let verdicts = ask(
        &runner,
        json!({"requests": [
            request("valid", PROJECT, &valid),
            request("forged", PROJECT, &forged),
            request("foreign", PROJECT, &other_project),
            request("elsewhere", "demo-other", &other_project),
            request("garbage", PROJECT, "not.a.jwt"),
        ]}),
    )
    .await;
    let by_id = |id: &str| {
        verdicts
            .iter()
            .find(|v| v["requestId"] == id)
            .unwrap_or_else(|| panic!("{id}: {verdicts:?}"))
    };
    assert_eq!(by_id("valid")["ok"], true);
    assert_eq!(reason_of(by_id("forged")), Some("invalid-signature"));
    assert_eq!(reason_of(by_id("foreign")), Some("claims"));
    assert_eq!(reason_of(by_id("elsewhere")), Some("no-matching-kid"));
    assert_eq!(reason_of(by_id("garbage")), Some("malformed"));
    // The pipe stays usable after verification traffic.
    let again = ask(
        &runner,
        json!({"requests": [request("again", PROJECT, &valid)]}),
    )
    .await;
    assert_eq!(again[0]["ok"], true);
    runner.shutdown().await;
}

#[tokio::test]
async fn without_a_verifier_every_request_is_unavailable_and_nothing_else_breaks() {
    let gate = gate();
    let runner = Runner::spawn_spec(&spec()).await.unwrap();
    let verdicts = ask(
        &runner,
        json!({"requests": [request("a", PROJECT, &token(&gate, PROJECT, APP_ID))]}),
    )
    .await;
    assert_eq!(verdicts[0]["ok"], false);
    assert_eq!(reason_of(&verdicts[0]), Some("unavailable"));
    runner.shutdown().await;
}

#[tokio::test]
async fn malformed_frames_are_answered_when_they_name_a_request_and_dropped_when_they_do_not() {
    let gate = gate();
    let barrier = Arc::new(AdmissionBarrier::new());
    let runner = Runner::spawn_spec_with(&spec(), Some(verifier(&gate, &barrier)))
        .await
        .unwrap();
    let valid = token(&gate, PROJECT, APP_ID);
    let verdicts = ask(
        &runner,
        json!({
            "raw": [
                {"type": "appCheck:verify", "requestId": "no-token", "projectId": PROJECT},
                {"type": "appCheck:verify", "projectId": PROJECT, "token": "x"},
                {"type": "appCheck:verify", "requestId": "huge", "projectId": PROJECT, "token": "x".repeat(16 * 1024 + 1)},
            ],
            "requests": [request("after", PROJECT, &valid)],
            "expect": 3,
        }),
    )
    .await;
    let ids: Vec<_> = verdicts
        .iter()
        .map(|v| v["requestId"].as_str().unwrap_or(""))
        .collect();
    assert!(
        ids.contains(&"no-token") && ids.contains(&"huge") && ids.contains(&"after"),
        "{verdicts:?}"
    );
    for v in &verdicts {
        match v["requestId"].as_str() {
            Some("no-token" | "huge") => assert_eq!(reason_of(v), Some("malformed")),
            Some("after") => assert_eq!(v["ok"], true),
            other => panic!("unexpected verdict for {other:?}"),
        }
    }
    runner.shutdown().await;
}

#[tokio::test]
async fn requests_over_the_in_flight_cap_are_refused_at_once_and_the_rest_wait_for_the_reset() {
    let gate = gate();
    let barrier = Arc::new(AdmissionBarrier::new());
    let runner = Arc::new(
        Runner::spawn_spec_with(&spec(), Some(verifier(&gate, &barrier)))
            .await
            .unwrap(),
    );
    let valid = token(&gate, PROJECT, APP_ID);
    let extra = 5;
    let requests: Vec<Value> = (0..MAX_IN_FLIGHT + extra)
        .map(|i| request(&format!("r{i}"), PROJECT, &valid))
        .collect();
    let exclusive = barrier.exclusive();
    let invoke = {
        let runner = runner.clone();
        tokio::spawn(
            async move { ask(&runner, json!({"requests": requests, "waitSeconds": 20})).await },
        )
    };
    tokio::time::sleep(Duration::from_millis(800)).await;
    drop(exclusive);
    let verdicts = invoke.await.unwrap();
    let unavailable = verdicts
        .iter()
        .filter(|v| reason_of(v) == Some("unavailable"))
        .count();
    let accepted = verdicts.iter().filter(|v| v["ok"] == true).count();
    assert_eq!(verdicts.len(), MAX_IN_FLIGHT + extra);
    assert_eq!(unavailable, extra);
    assert_eq!(accepted, MAX_IN_FLIGHT);
    runner.shutdown().await;
}

#[tokio::test]
async fn the_in_flight_count_returns_to_zero_after_every_burst() {
    let gate = gate();
    let barrier = Arc::new(AdmissionBarrier::new());
    let runner = Arc::new(
        Runner::spawn_spec_with(&spec(), Some(verifier(&gate, &barrier)))
            .await
            .unwrap(),
    );
    let valid = token(&gate, PROJECT, APP_ID);
    for burst in 0..3 {
        // A burst of exactly the cap, then one over the cap, then the cap again: nothing from
        // the earlier bursts (answered or refused) may still count.
        let requests: Vec<Value> = (0..MAX_IN_FLIGHT)
            .map(|i| request(&format!("b{burst}-{i}"), PROJECT, &valid))
            .collect();
        let verdicts = ask(&runner, json!({"requests": requests, "waitSeconds": 20})).await;
        let refused = verdicts
            .iter()
            .filter(|v| reason_of(v) == Some("unavailable"))
            .count();
        assert_eq!(
            refused, 0,
            "burst {burst}: a full cap of fresh requests is served"
        );
        assert_eq!(
            verdicts.iter().filter(|v| v["ok"] == true).count(),
            MAX_IN_FLIGHT
        );
    }
    // Refused requests do not leak a slot either.
    let exclusive = barrier.exclusive();
    let over: Vec<Value> = (0..MAX_IN_FLIGHT + 8)
        .map(|i| request(&format!("over-{i}"), PROJECT, &valid))
        .collect();
    let pending = {
        let runner = runner.clone();
        tokio::spawn(
            async move { ask(&runner, json!({"requests": over, "waitSeconds": 20})).await },
        )
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(exclusive);
    let verdicts = pending.await.unwrap();
    assert_eq!(
        verdicts
            .iter()
            .filter(|v| reason_of(v) == Some("unavailable"))
            .count(),
        8
    );
    let requests: Vec<Value> = (0..MAX_IN_FLIGHT)
        .map(|i| request(&format!("after-{i}"), PROJECT, &valid))
        .collect();
    let verdicts = ask(&runner, json!({"requests": requests, "waitSeconds": 20})).await;
    assert_eq!(
        verdicts.iter().filter(|v| v["ok"] == true).count(),
        MAX_IN_FLIGHT
    );
    runner.shutdown().await;
}

#[tokio::test]
async fn a_runner_that_stops_reading_is_retired_when_a_verdict_cannot_be_written() {
    let gate = gate();
    let barrier = Arc::new(AdmissionBarrier::new());
    let runner = Arc::new(
        Runner::spawn_spec_with(&spec(), Some(verifier(&gate, &barrier)))
            .await
            .unwrap(),
    );
    assert!(runner.is_alive());
    let valid = token(&gate, PROJECT, APP_ID);
    let invoke = {
        let runner = runner.clone();
        let event = json!({"requests": [request("closed", PROJECT, &valid)], "closeStdin": true, "expect": 0});
        tokio::spawn(async move {
            runner
                .invoke(
                    json!({"invocationId": "c", "function": "f", "trigger": "http", "event": event}),
                    Duration::from_secs(5),
                )
                .await
        })
    };
    // The runner closed its stdin and lives on for a few seconds: the failed verdict write is
    // what retires it, well before it exits by itself.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(2000);
    while runner.is_alive() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !runner.is_alive(),
        "the daemon retired the runner whose pipe it could not write"
    );
    let _ = invoke.await;
}

/// A verifier whose thread panics: the runner must get an unavailable answer, never an
/// acceptance, and the slot must be freed.
#[derive(Debug)]
struct Panicking;

impl AdminAppCheckVerifier for Panicking {
    fn verify(&self, _project_id: &str, _token: &str) -> Reply {
        panic!("the verifier thread panicked on purpose");
    }
}

#[tokio::test]
async fn a_panicking_verifier_is_unavailable_never_an_acceptance_and_frees_its_slot() {
    let gate = gate();
    let valid = token(&gate, PROJECT, APP_ID);
    let runner = Runner::spawn_spec_with(&spec(), Some(Arc::new(Panicking)))
        .await
        .unwrap();
    for round in 0..(MAX_IN_FLIGHT / 8 + 2) {
        let requests: Vec<Value> = (0..8)
            .map(|i| request(&format!("p{round}-{i}"), PROJECT, &valid))
            .collect();
        let verdicts = ask(&runner, json!({"requests": requests})).await;
        assert_eq!(verdicts.len(), 8);
        for verdict in &verdicts {
            assert_eq!(verdict["ok"], false, "{verdict}");
            assert_eq!(reason_of(verdict), Some("unavailable"), "{verdict}");
        }
    }
    runner.shutdown().await;
}

#[tokio::test]
async fn the_hello_carries_the_runners_admin_report() {
    let runner = Runner::spawn_spec(&spec()).await.unwrap();
    assert_eq!(
        runner.hello().admin_app_check,
        Some(json!({"instrumentation": "ok", "firebaseAdminVersion": "14.3.0"}))
    );
    runner.shutdown().await;
}

#[tokio::test]
async fn a_runner_killed_while_a_verification_waits_does_not_wedge_the_barrier() {
    let gate = gate();
    let barrier = Arc::new(AdmissionBarrier::new());
    let runner = Arc::new(
        Runner::spawn_spec_with(&spec(), Some(verifier(&gate, &barrier)))
            .await
            .unwrap(),
    );
    let valid = token(&gate, PROJECT, APP_ID);
    let exclusive = barrier.exclusive();
    let pending = {
        let runner = runner.clone();
        let event = json!({"requests": [request("k1", PROJECT, &valid)], "waitSeconds": 20});
        tokio::spawn(async move {
            runner
                .invoke(
                    json!({"invocationId": "k", "function": "f", "trigger": "http", "event": event}),
                    Duration::from_secs(30),
                )
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    runner.kill_now();
    drop(exclusive);
    let outcome = pending.await.unwrap().outcome;
    assert!(
        matches!(outcome, InvokeOutcome::RunnerGone(_)),
        "{outcome:?}"
    );
    // The shared side of the barrier is free again.
    let (tx, rx) = std::sync::mpsc::channel();
    let barrier2 = barrier.clone();
    std::thread::spawn(move || {
        let _admitted = barrier2.admit();
        tx.send(()).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("barrier admits again");
}

/// A runner the runtime respawns after it died. `installed` says whether the runtime was given
/// the verifier; the first runner always had it.
async fn respawned_runner_answers(installed: bool) -> Value {
    let gate = gate();
    let barrier = Arc::new(AdmissionBarrier::new());
    let verifier = verifier(&gate, &barrier);
    let runner = Arc::new(
        Runner::spawn_spec_with(&spec(), Some(verifier.clone()))
            .await
            .unwrap(),
    );
    let manifest = parse_manifest(&json!({"functions": [{
        "name": "beforeCreate", "generation": 2,
        "trigger": {"type": "blockingAuth", "eventType": "beforeCreate"}
    }]}))
    .unwrap();
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig::for_tests(1000, "s".into()),
        Arc::new(Mutex::new(VirtualClock::new(START))),
        runner.clone(),
        Some(spec()),
    );
    if installed {
        runtime.set_admin_app_check(verifier);
    }
    runner.kill_now();
    runtime
        .recover_blocking_auth_runner_for(BlockingAuthEvent::BeforeCreate, None)
        .await
        .expect("the runner is respawned");
    let fresh = runtime.runner();
    assert!(!Arc::ptr_eq(&fresh, &runner), "a new runner process");
    let valid = token(&gate, PROJECT, APP_ID);
    let verdicts = ask(
        &fresh,
        json!({"requests": [request("after", PROJECT, &valid)]}),
    )
    .await;
    runtime.shutdown().await;
    verdicts[0].clone()
}

#[tokio::test]
async fn a_respawned_runner_keeps_answering_verifications() {
    let verdict = respawned_runner_answers(true).await;
    assert_eq!(verdict["ok"], true, "{verdict}");
}

#[tokio::test]
async fn a_runtime_without_a_verifier_respawns_runners_that_cannot_verify() {
    let verdict = respawned_runner_answers(false).await;
    assert_eq!(verdict["ok"], false, "{verdict}");
    assert_eq!(reason_of(&verdict), Some("unavailable"));
}

mod frames {
    use super::*;
    use proptest::prelude::*;

    fn field() -> impl Strategy<Value = Value> {
        prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::from),
            any::<i64>().prop_map(Value::from),
            ".{0,40}".prop_map(Value::from),
            "[a-z0-9-]{1,130}".prop_map(Value::from),
            "[a-zA-Z0-9._-]{0,17000}".prop_map(Value::from),
            Just(json!([])),
            Just(json!({})),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Whatever a runner sends, parsing never panics, an accepted request is within every
        /// bound, and a refusal names a request id only when that id is itself usable.
        #[test]
        fn parsing_is_total_and_bounded(
            id in proptest::option::of(field()),
            project in proptest::option::of(field()),
            token in proptest::option::of(field()),
        ) {
            let mut frame = serde_json::Map::new();
            frame.insert("type".to_owned(), json!("appCheck:verify"));
            for (name, value) in [("requestId", id), ("projectId", project), ("token", token)] {
                if let Some(value) = value {
                    frame.insert(name.to_owned(), value);
                }
            }
            match parse_request(&Value::Object(frame)) {
                Ok(request) => {
                    prop_assert!(!request.request_id.is_empty() && request.request_id.len() <= 128);
                    prop_assert!(!request.project_id.is_empty() && request.project_id.len() <= 256);
                    prop_assert!(request.token.len() <= 16 * 1024);
                }
                Err(Some(id)) => prop_assert!(!id.is_empty() && id.len() <= 128),
                Err(None) => {}
            }
        }

        /// A verdict is always addressed to the request it answers and carries a reason exactly
        /// when it is a refusal.
        #[test]
        fn a_reply_names_its_request_and_a_reason_only_for_a_refusal(
            id in "[a-z0-9-]{1,128}",
            pick in 0usize..9,
        ) {
            let reply = match pick {
                0 => Reply::Verdict(AdminVerdict::Accept),
                1 => Reply::Unavailable,
                n => Reply::Verdict(AdminVerdict::Reject(AdminRejection::ALL[n - 2])),
            };
            let frame = reply_frame(&id, reply);
            prop_assert_eq!(frame["requestId"].as_str(), Some(id.as_str()));
            prop_assert_eq!(frame["type"].as_str(), Some("appCheck:verdict"));
            let ok = frame["ok"].as_bool().expect("ok is a boolean");
            prop_assert_eq!(ok, reply == Reply::Verdict(AdminVerdict::Accept));
            prop_assert_eq!(frame.get("reason").is_some(), !ok);
        }
    }
}
