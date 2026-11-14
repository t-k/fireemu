use super::{
    FunctionsConfig, FunctionsRuntime, SourceEventAdmissionError, TaskCompletion,
    MAX_ACTIVE_EVENT_BYTES,
};
use crate::manifest_json::parse_manifest;
use crate::runner::{Runner, SpawnSpec};
use fireemu_adapter_grpc::local::{Actor, CommitEvent};
use fireemu_core_auth::store::{UserEvent, UserEventKind};
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{CommitVersion, Document, DocumentChange};
use fireemu_core_functions::manifest::{TaskRateLimits, TaskRetryConfig, Trigger};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule, FaultState};
use fireemu_core_types::ids::{DatabaseId, EventId, ProjectId, SessionId};
use fireemu_core_types::time::LogicalInstant;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

async fn runtime() -> Arc<FunctionsRuntime> {
    let spec = SpawnSpec {
        command: vec![
            "python3".to_owned(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py").to_owned(),
        ],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(60),
    };
    let runner = Runner::spawn_spec(&spec).await.unwrap();
    let mut manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
    let template = manifest.get("echo").unwrap().clone();
    for name in ["taskA", "taskB"] {
        let mut queue = template.clone();
        queue.name = name.to_owned();
        queue.entry_point = name.to_owned();
        queue.trigger = Trigger::TaskQueue {
            retry: TaskRetryConfig::default(),
            rate_limits: TaskRateLimits::default(),
        };
        manifest.functions.push(queue);
    }
    FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            retry_attempts: 1,
            functions_host: Some("127.0.0.1:5001".to_owned()),
            ..FunctionsConfig::for_tests(1, "test-secret".to_owned())
        },
        Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        Arc::new(runner),
        Some(spec),
    )
}

#[tokio::test]
async fn remote_config_atomic_capacity_disabled_shutdown_and_metadata() {
    use fireemu_core_functions::manifest::FunctionGeneration;
    let base = runtime().await;
    let mut manifest = base.manifest.clone();
    let mut template = manifest.get("echo").unwrap().clone();
    template.trigger = Trigger::RemoteConfig;
    manifest.functions = [FunctionGeneration::First, FunctionGeneration::Second]
        .into_iter()
        .map(|generation| {
            let mut spec = template.clone();
            spec.generation = generation;
            spec.name = format!("config{generation:?}");
            spec
        })
        .collect();
    let runtime = FunctionsRuntime::with_codebases(
        vec![super::CodebaseSpec {
            function: None,
            name: "default".into(),
            manifest,
            runner: base.runner(),
            spawn: None,
            cleanup_dir: None,
        }],
        base.config.clone(),
        base.clock.clone(),
        super::FunctionsHttpProfile::Strict,
    )
    .unwrap();
    let body = json!({
        "data": {"versionNumber": 7, "updateTime": "2026-01-02T03:04:05Z"},
        "v1Context": {"eventId": "one", "timestamp": "2026-01-02T03:04:06Z", "eventType": "google.firebase.remoteconfig.update", "resource": {"service": "firebaseremoteconfig.googleapis.com", "name": "projects/demo-app"}},
        "v2Context": {"specversion": "1.0", "id": "two", "time": "2026-01-02T03:04:07Z", "type": "google.firebase.remoteconfig.remoteConfig.v1.updated", "source": "//firebaseremoteconfig.googleapis.com/projects/demo-app"}
    });
    let mut missing = body.clone();
    missing.as_object_mut().unwrap().remove("v1Context");
    assert_eq!(
        runtime.publish_remote_config(&missing),
        Err(SourceEventAdmissionError::InvalidEvent)
    );
    assert!(runtime.inner.lock().unwrap().payloads.is_empty());
    runtime.set_background_triggers(false);
    assert_eq!(runtime.publish_remote_config(&body), Ok(0));
    assert!(runtime.inner.lock().unwrap().payloads.is_empty());
    runtime.set_background_triggers(true);
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS - 1;
    assert_eq!(
        runtime.publish_remote_config(&body),
        Err(SourceEventAdmissionError::Capacity)
    );
    assert!(runtime.inner.lock().unwrap().payloads.is_empty());
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS - 2;
    assert_eq!(runtime.publish_remote_config(&body), Ok(2));
    {
        let inner = runtime.inner.lock().unwrap();
        assert_eq!(inner.payloads.len(), 2);
        for (id, queued) in &inner.payloads {
            let spec = runtime.manifest.get(&queued.function).unwrap();
            let frame = runtime
                .invoke_request_at(
                    *id,
                    spec,
                    2,
                    inner.epoch,
                    &queued.payload,
                    runtime.now(),
                    None,
                    runtime.now(),
                )
                .unwrap();
            let frame: serde_json::Value = serde_json::from_str(frame.get()).unwrap();
            assert_eq!(frame["event"], *queued.payload);
            assert!(frame["event"].get("traceparent").is_none());
            assert_eq!(frame["event"]["data"], body["data"]);
        }
    }
    runtime.inner.lock().unwrap().reserved_event_records = 0;
    runtime.begin_shutdown();
    assert_eq!(
        runtime.publish_remote_config(&body),
        Err(SourceEventAdmissionError::Unavailable)
    );
    runtime.shutdown().await;
    base.shutdown().await;
}

/// A runtime whose manifest holds exactly `functions` (name, trigger), sharing the base
/// runtime's runner and clock.
fn runtime_with(
    base: &Arc<FunctionsRuntime>,
    functions: &[(&str, Trigger)],
) -> Arc<FunctionsRuntime> {
    runtime_with_session(base, functions, base.config.session)
}

/// [`runtime_with`] in the given session (what a daemon start without `daemon.seed` draws).
fn runtime_with_session(
    base: &Arc<FunctionsRuntime>,
    functions: &[(&str, Trigger)],
    session: SessionId,
) -> Arc<FunctionsRuntime> {
    let mut manifest = base.manifest.clone();
    let template = manifest.get("echo").unwrap().clone();
    manifest.functions = functions
        .iter()
        .map(|(name, trigger)| {
            let mut spec = template.clone();
            spec.name = (*name).to_owned();
            spec.entry_point = (*name).to_owned();
            spec.trigger = trigger.clone();
            spec
        })
        .collect();
    FunctionsRuntime::with_codebases(
        vec![super::CodebaseSpec {
            function: None,
            name: "default".into(),
            manifest,
            runner: base.runner(),
            spawn: None,
            cleanup_dir: None,
        }],
        FunctionsConfig {
            session,
            ..base.config.clone()
        },
        base.clock.clone(),
        super::FunctionsHttpProfile::Strict,
    )
    .unwrap()
}

fn pubsub_on(topic: &str) -> Trigger {
    Trigger::PubSub {
        topic: topic.to_owned(),
    }
}

fn capacity_refusals(runtime: &FunctionsRuntime) -> u64 {
    runtime
        .inner
        .lock()
        .unwrap()
        .admission_refusals
        .get("capacity")
        .copied()
        .unwrap_or(0)
}

/// C1/C2: a control publish whose complete fan-out does not fit is refused whole: no
/// message id, nothing enqueued, the refusal counted; one slot more admits it.
#[tokio::test]
async fn control_publish_is_all_or_none_at_capacity() {
    let base = runtime().await;
    let runtime = runtime_with(&base, &[("a", pubsub_on("jobs")), ("b", pubsub_on("jobs"))]);
    let message = json!({"data": "YQ=="});
    // One message reaches two functions: it needs two free records.
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS - 1;
    let next_before = runtime.inner.lock().unwrap().next_event;
    assert_eq!(
        runtime.publish("jobs", std::slice::from_ref(&message)),
        Err(SourceEventAdmissionError::Capacity)
    );
    {
        let inner = runtime.inner.lock().unwrap();
        assert!(
            inner.payloads.is_empty(),
            "nothing is enqueued on a refusal"
        );
        assert_eq!(inner.next_event, next_before, "no id is consumed");
    }
    assert_eq!(capacity_refusals(&runtime), 1);
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS - 2;
    let ids = runtime
        .publish("jobs", std::slice::from_ref(&message))
        .unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(runtime.inner.lock().unwrap().payloads.len(), 2);
    // Two messages need four records: with three free the whole call is refused and the
    // first message is not delivered alone.
    {
        let mut inner = runtime.inner.lock().unwrap();
        inner.payloads.clear();
        inner.active_event_bytes = 0;
        inner.reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS - 3;
    }
    assert_eq!(
        runtime.publish("jobs", &[message.clone(), message.clone()]),
        Err(SourceEventAdmissionError::Capacity)
    );
    assert!(runtime.inner.lock().unwrap().payloads.is_empty());
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS - 4;
    assert_eq!(
        runtime
            .publish("jobs", &[message.clone(), message])
            .unwrap()
            .len(),
        2
    );
    assert_eq!(runtime.inner.lock().unwrap().payloads.len(), 4);
    runtime.inner.lock().unwrap().reserved_event_records = 0;
    runtime.shutdown().await;
    base.shutdown().await;
}

/// C5: with no subscriber, or with background triggers off, a full queue has nothing to
/// refuse and the ids are still issued.
#[tokio::test]
async fn control_publish_without_deliveries_never_refuses() {
    let base = runtime().await;
    let runtime = runtime_with(&base, &[("a", pubsub_on("jobs"))]);
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS;
    let message = json!({"data": "YQ=="});
    assert_eq!(
        runtime
            .publish("nobody", std::slice::from_ref(&message))
            .unwrap()
            .len(),
        1
    );
    runtime.set_background_triggers(false);
    assert_eq!(runtime.publish("jobs", &[message]).unwrap().len(), 1);
    assert_eq!(capacity_refusals(&runtime), 0);
    runtime.inner.lock().unwrap().reserved_event_records = 0;
    runtime.shutdown().await;
    base.shutdown().await;
}

/// C3: a duplicate fault multiplies the fan-out, and the copies are part of the
/// all-or-none reservation. After a refusal the same publish succeeds once capacity returns.
#[tokio::test]
async fn control_publish_reserves_duplicate_copies_with_the_fan_out() {
    use fireemu_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule};
    let base = runtime().await;
    let runtime = runtime_with(&base, &[("a", pubsub_on("jobs"))]);
    let faults = Arc::new(Mutex::new(
        fireemu_core_session::fault::FaultState::default(),
    ));
    faults.lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "functions.deliver".to_owned(),
                nth: None,
                function: Some("a".to_owned()),
                event_type: None,
            },
            action: FaultAction::Duplicate { count: 2 },
        }],
    });
    runtime.set_faults(faults);
    let message = json!({"data": "YQ=="});
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS - 2;
    assert_eq!(
        runtime.publish("jobs", std::slice::from_ref(&message)),
        Err(SourceEventAdmissionError::Capacity),
        "one message with two extra copies needs three records"
    );
    assert!(runtime.inner.lock().unwrap().payloads.is_empty());
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS - 3;
    runtime.publish("jobs", &[message]).unwrap();
    assert_eq!(runtime.inner.lock().unwrap().payloads.len(), 3);
    runtime.inner.lock().unwrap().reserved_event_records = 0;
    runtime.shutdown().await;
    base.shutdown().await;
}

/// A broker reservation that does not fit is counted as a capacity refusal, and the resource
/// report lists the count.
#[tokio::test]
async fn a_refused_broker_reservation_is_counted_in_the_resource_report() {
    use fireemu_core_types::resources::RootBudget;
    let base = runtime().await;
    let runtime = runtime_with(&base, &[("a", pubsub_on("jobs"))]);
    let message = json!({"data": "YQ==", "messageId": "m1"});
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS;
    assert!(matches!(
        runtime.reserve_pubsub_events("jobs", std::slice::from_ref(&message)),
        Err(SourceEventAdmissionError::Capacity)
    ));
    assert_eq!(capacity_refusals(&runtime), 1);
    let report = runtime.resources(RootBudget::DEFAULT).unwrap();
    assert!(
        report
            .refusals
            .iter()
            .any(|r| r.reason == "admission.capacity" && r.count == 1),
        "{:?}",
        report.refusals
    );
    runtime.inner.lock().unwrap().reserved_event_records = 0;
    runtime.shutdown().await;
    base.shutdown().await;
}

/// M1: the message id of a control publish, which the `CloudEvent` id reuses, is a function of
/// the session as well as of the counter: a restart into another session does not repeat the
/// previous run's first id, and one session replays its ids.
#[tokio::test]
async fn control_publish_ids_follow_the_session() {
    let base = runtime().await;
    let first_id = |session: u128| {
        let runtime =
            runtime_with_session(&base, &[("a", pubsub_on("jobs"))], SessionId::new(session));
        let ids = runtime
            .publish("jobs", &[json!({"data": "YQ=="}), json!({"data": "Yg=="})])
            .unwrap();
        let event_id = {
            let inner = runtime.inner.lock().unwrap();
            let id = inner.payloads.keys().next().unwrap();
            inner.payloads[id].payload["id"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        (ids, event_id, runtime)
    };
    let (one, one_event, r1) = first_id(1_234_567_890_123);
    let (again, again_event, r2) = first_id(1_234_567_890_123);
    let (other, other_event, r3) = first_id(9_876_543_210_987);
    assert_eq!(one, again, "one session replays its ids");
    assert_eq!(one_event, again_event);
    assert_ne!(one[0], other[0], "another session starts elsewhere");
    assert_ne!(
        one_event, other_event,
        "the CloudEvent id follows the message id"
    );
    assert_ne!(one[0], one[1]);
    for id in one.iter().chain(&other) {
        assert!(
            id.len() == 17 && id.bytes().all(|b| b.is_ascii_digit()),
            "{id}"
        );
    }
    for r in [r1, r2, r3] {
        r.shutdown().await;
    }
    base.shutdown().await;
}

/// The boundary of an event that can never be admitted: exactly the queue's records or
/// bytes still fits an empty queue, one more does not.
#[test]
fn an_event_fits_an_empty_queue_up_to_exactly_its_limits() {
    let fits = FunctionsRuntime::fits_an_empty_queue;
    assert!(fits(0, 0));
    assert!(fits(super::MAX_ACTIVE_EVENT_RECORDS, 0));
    assert!(fits(0, super::MAX_ACTIVE_EVENT_BYTES));
    assert!(fits(
        super::MAX_ACTIVE_EVENT_RECORDS,
        super::MAX_ACTIVE_EVENT_BYTES
    ));
    assert!(!fits(super::MAX_ACTIVE_EVENT_RECORDS + 1, 0));
    assert!(!fits(0, super::MAX_ACTIVE_EVENT_BYTES + 1));
}

/// The exact ids a control publish gets: the session's sequence, counted from the message
/// position, which wraps modulo `BROKER_SPAN` (and not at the end of a `u64`).
#[tokio::test]
async fn control_publish_ids_are_the_sessions_sequence() {
    use fireemu_core_types::pubsub_message_id::session_runtime_message_id as expected;
    let base = runtime().await;
    for session in [0_u128, 42, 5_000_000_000_042, u128::from(u64::MAX)] {
        let runtime =
            runtime_with_session(&base, &[("a", pubsub_on("jobs"))], SessionId::new(session));
        let ids = runtime
            .publish("jobs", &[json!({"data": "YQ=="}), json!({"data": "Yg=="})])
            .unwrap();
        assert_eq!(
            ids,
            vec![expected(session, 1), expected(session, 2)],
            "session {session}"
        );
        // The next publish continues after both message ids.
        let next = runtime.publish("jobs", &[json!({"data": "Yw=="})]).unwrap();
        assert!(!ids.contains(&next[0]));
        runtime.shutdown().await;
    }
    // The position wraps at the end of the span, and every id on the way is different.
    let span = fireemu_core_types::pubsub_message_id::BROKER_SPAN;
    let runtime = runtime_with(&base, &[("a", pubsub_on("jobs"))]);
    runtime.inner.lock().unwrap().message_position = span - 2;
    let session = runtime.config.session.value();
    let three = [
        json!({"data": "YQ=="}),
        json!({"data": "Yg=="}),
        json!({"data": "Yw=="}),
    ];
    let ids = runtime.publish("nobody", &three).unwrap();
    assert_eq!(
        ids,
        vec![
            expected(session, span - 1),
            expected(session, span),
            expected(session, span + 1)
        ]
    );
    assert_eq!(runtime.inner.lock().unwrap().message_position, 1);
    let next = runtime.publish("nobody", &three[..1]).unwrap();
    assert_eq!(next, vec![expected(session, 2)]);
    runtime.shutdown().await;
    base.shutdown().await;
}

/// The ids of messages published without a delivery (no subscriber, or triggers off) and
/// across the end of the `u64` event counter are all different: the position of a message
/// has one definition for generating and for storing.
#[tokio::test]
async fn control_publish_ids_stay_distinct_across_the_counter_boundary_on_every_path() {
    let base = runtime().await;
    for triggers_on in [true, false] {
        let runtime = runtime_with_session(&base, &[("a", pubsub_on("jobs"))], SessionId::new(42));
        runtime.set_background_triggers(triggers_on);
        runtime.inner.lock().unwrap().next_event = u64::MAX - 1;
        let mut ids = runtime
            .publish(
                "nobody",
                &[
                    json!({"data": "YQ=="}),
                    json!({"data": "Yg=="}),
                    json!({"data": "Yw=="}),
                ],
            )
            .unwrap();
        for _ in 0..3 {
            ids.extend(
                runtime
                    .publish("nobody", &[json!({"data": "ZA=="})])
                    .unwrap(),
            );
        }
        let distinct: std::collections::BTreeSet<&String> = ids.iter().collect();
        assert_eq!(
            distinct.len(),
            ids.len(),
            "triggers on: {triggers_on}: {ids:?}"
        );
        runtime.shutdown().await;
    }
    base.shutdown().await;
}

/// A refused publish takes no ids and leaves the message position where it was, so the next
/// publish that succeeds continues the session's sequence from there.
#[tokio::test]
async fn a_refused_control_publish_leaves_the_message_position_unchanged() {
    use fireemu_core_types::pubsub_message_id::{
        session_runtime_message_id as expected, BROKER_SPAN,
    };
    let base = runtime().await;
    let runtime = runtime_with(&base, &[("a", pubsub_on("jobs"))]);
    let session = runtime.config.session.value();
    let message = json!({"data": "YQ=="});
    let position = |runtime: &FunctionsRuntime| runtime.inner.lock().unwrap().message_position;
    runtime.inner.lock().unwrap().message_position = BROKER_SPAN - 1;
    // Capacity: the queue is full.
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS;
    assert_eq!(
        runtime.publish("jobs", std::slice::from_ref(&message)),
        Err(SourceEventAdmissionError::Capacity)
    );
    assert_eq!(position(&runtime), BROKER_SPAN - 1);
    runtime.inner.lock().unwrap().reserved_event_records = 0;
    // The next publish continues from the position, across the end of the span.
    let ids = runtime
        .publish("jobs", &[message.clone(), message.clone()])
        .unwrap();
    assert_eq!(
        ids,
        vec![
            expected(session, BROKER_SPAN),
            expected(session, BROKER_SPAN + 1)
        ]
    );
    assert_eq!(position(&runtime), 1);
    // Unavailable: the runtime is shutting down.
    runtime.begin_shutdown();
    assert_eq!(
        runtime.publish("nobody", std::slice::from_ref(&message)),
        Err(SourceEventAdmissionError::Unavailable)
    );
    assert_eq!(position(&runtime), 1);
    runtime.shutdown().await;
    base.shutdown().await;
}

/// Deliveries, publishes without subscribers, publishes with the triggers off and a reset,
/// mixed across the end of the span, give one unbroken sequence of different ids.
#[tokio::test]
async fn a_mixed_control_publish_sequence_across_the_span_boundary_is_one_sequence() {
    use fireemu_core_types::pubsub_message_id::{
        session_runtime_message_id as expected, BROKER_SPAN,
    };
    let base = runtime().await;
    let runtime = runtime_with(&base, &[("a", pubsub_on("jobs"))]);
    let session = runtime.config.session.value();
    let message = json!({"data": "YQ=="});
    runtime.inner.lock().unwrap().message_position = BROKER_SPAN - 3;
    let mut ids: Vec<String> = Vec::new();
    ids.extend(
        runtime
            .publish("jobs", std::slice::from_ref(&message))
            .unwrap(),
    );
    ids.extend(
        runtime
            .publish("nobody", &[message.clone(), message.clone()])
            .unwrap(),
    );
    runtime.set_background_triggers(false);
    ids.extend(
        runtime
            .publish("jobs", std::slice::from_ref(&message))
            .unwrap(),
    );
    runtime.set_background_triggers(true);
    // A reset starts a new session of events but not a new sequence of message ids.
    runtime.reset();
    ids.extend(
        runtime
            .publish("jobs", &[message.clone(), message.clone()])
            .unwrap(),
    );
    ids.extend(
        runtime
            .publish("nobody", std::slice::from_ref(&message))
            .unwrap(),
    );
    let wanted: Vec<String> = (1..=ids.len() as u64)
        .map(|n| expected(session, BROKER_SPAN - 3 + n))
        .collect();
    assert_eq!(ids, wanted);
    let distinct: std::collections::BTreeSet<&String> = ids.iter().collect();
    assert_eq!(distinct.len(), ids.len());
    assert_eq!(runtime.inner.lock().unwrap().message_position, 4);
    runtime.shutdown().await;
    base.shutdown().await;
}

/// M2: an Auth user event whose fan-out is larger than the whole queue can never be admitted.
/// It is dropped on the spot, counted and logged; it does not block the events behind it, the
/// runtime goes idle, and the held events before it are not lost.
#[tokio::test]
async fn an_auth_event_larger_than_the_queue_is_dropped_and_blocks_nothing() {
    use fireemu_core_functions::manifest::AuthEvent;
    let base = runtime().await;
    let runtime = runtime_with(
        &base,
        &[
            ("a", auth_on(AuthEvent::Created)),
            ("b", auth_on(AuthEvent::Created)),
            ("c", auth_on(AuthEvent::Deleted)),
        ],
    );
    let faults = Arc::new(Mutex::new(FaultState::default()));
    faults.lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "functions.deliver".to_owned(),
                nth: None,
                function: None,
                event_type: Some(AuthEvent::Created.event_type().to_owned()),
            },
            action: FaultAction::Duplicate { count: 3071 },
        }],
    });
    runtime.set_faults(faults);
    let dropped = |runtime: &FunctionsRuntime| {
        runtime
            .inner
            .lock()
            .unwrap()
            .admission_refusals
            .get("auth_event_dropped")
            .copied()
            .unwrap_or(0)
    };
    // 2 functions x 3072 copies = 6144 records against 4096: with nothing held ...
    runtime.on_user_event(&user_event(UserEventKind::Created, "big@example.com"));
    assert_eq!(
        auth_pending(&runtime),
        0,
        "it never waits for room it cannot get"
    );
    assert_eq!(dropped(&runtime), 1);
    assert!(runtime.is_idle(), "nothing is outstanding");
    // ... and with an older event held ahead of it.
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS;
    runtime.on_user_event(&user_event(UserEventKind::Deleted, "held@example.com"));
    runtime.on_user_event(&user_event(UserEventKind::Created, "big2@example.com"));
    assert_eq!(dropped(&runtime), 2);
    assert_eq!(auth_pending(&runtime), 1, "only the admissible event waits");
    runtime.inner.lock().unwrap().reserved_event_records = 0;
    runtime.admit_pending_auth();
    assert_eq!(auth_pending(&runtime), 0);
    assert_eq!(
        payload_subjects(&runtime),
        vec!["held@example.com".to_owned()]
    );
    runtime.shutdown().await;
    base.shutdown().await;
}

/// S1: a control publish whose fan-out cannot fit is refused while its drafts are planned,
/// not after the whole messages x subscribers x copies vector is built.
#[tokio::test]
async fn control_publish_refuses_overflow_before_expanding_the_remaining_targets() {
    let base = runtime().await;
    for (data, expected_visits) in [("YQ==".to_owned(), 2), ("A".repeat(64 * 1024), 1)] {
        let functions: Vec<(String, Trigger)> = (0..4)
            .map(|n| (format!("f{n}"), pubsub_on("jobs")))
            .collect();
        let functions: Vec<(&str, Trigger)> = functions
            .iter()
            .map(|(n, t)| (n.as_str(), t.clone()))
            .collect();
        let runtime = runtime_with(&base, &functions);
        let faults = Arc::new(Mutex::new(FaultState::default()));
        faults.lock().unwrap().install(FaultPlan {
            seed: 1,
            rules: vec![FaultRule {
                matches: FaultMatch {
                    operation: "functions.deliver".into(),
                    nth: None,
                    function: None,
                    event_type: None,
                },
                action: FaultAction::Duplicate {
                    count: if data.len() > 100 { 1023 } else { 3000 },
                },
            }],
        });
        runtime.set_faults(faults.clone());
        assert_eq!(
            runtime.publish("jobs", &[json!({"data": data})]),
            Err(SourceEventAdmissionError::Capacity)
        );
        assert!(runtime.inner.lock().unwrap().payloads.is_empty());
        assert_eq!(
            faults.lock().unwrap().counters()["functions.deliver"],
            expected_visits,
            "stop planning once the record or byte budget cannot fit"
        );
        runtime.shutdown().await;
    }
    base.shutdown().await;
}

/// A publish to a runtime that is shutting down is unavailable, also when it has nobody to
/// deliver to: the answer does not depend on the topic's subscribers or on the triggers.
#[tokio::test]
async fn control_publish_during_shutdown_is_unavailable_whatever_the_fan_out() {
    let base = runtime().await;
    let runtime = runtime_with(&base, &[("a", pubsub_on("jobs"))]);
    let message = json!({"data": "YQ=="});
    runtime.begin_shutdown();
    for topic in ["jobs", "nobody"] {
        assert_eq!(
            runtime.publish(topic, std::slice::from_ref(&message)),
            Err(SourceEventAdmissionError::Unavailable),
            "{topic}"
        );
    }
    runtime.set_background_triggers(false);
    assert_eq!(
        runtime.publish("jobs", &[message]),
        Err(SourceEventAdmissionError::Unavailable),
        "triggers off"
    );
    runtime.shutdown().await;
    base.shutdown().await;
}

/// Switching the triggers off between `on_user_event`'s first check and its lock must not
/// leave the event held (the flag is read again under the lock).
#[tokio::test]
async fn disabling_the_triggers_while_an_auth_event_waits_for_the_lock_holds_nothing() {
    use fireemu_core_functions::manifest::AuthEvent;
    let base = runtime().await;
    let runtime = runtime_with(&base, &[("created", auth_on(AuthEvent::Created))]);
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS;
    let event = user_event(UserEventKind::Created, "u@example.com");
    let guard = runtime.inner.lock().unwrap();
    let caller = {
        let runtime = Arc::clone(&runtime);
        std::thread::spawn(move || runtime.on_user_event(&event))
    };
    std::thread::sleep(Duration::from_millis(300));
    runtime
        .background_triggers
        .store(false, std::sync::atomic::Ordering::SeqCst);
    drop(guard);
    caller.join().unwrap();
    assert_eq!(auth_pending(&runtime), 0);
    runtime.inner.lock().unwrap().reserved_event_records = 0;
    runtime.shutdown().await;
    base.shutdown().await;
}

/// Dropping the held events when the triggers go off wakes `await-idle` waiters: a
/// runtime whose only outstanding work was a held event is idle now.
#[tokio::test]
async fn disabling_the_triggers_wakes_idle_waiters_when_it_drops_held_events() {
    use fireemu_core_functions::manifest::AuthEvent;
    let base = runtime().await;
    let runtime = runtime_with(&base, &[("created", auth_on(AuthEvent::Created))]);
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS;
    runtime.on_user_event(&user_event(UserEventKind::Created, "u@example.com"));
    assert_eq!(auth_pending(&runtime), 1);
    runtime.inner.lock().unwrap().reserved_event_records = 0;
    // Let the start-up wake-ups pass, so only the switch-off can wake the waiter.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let idle = runtime.idle_notify();
    let notified = idle.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    runtime.set_background_triggers(false);
    assert!(runtime.is_idle());
    tokio::time::timeout(Duration::from_secs(2), notified)
        .await
        .expect("the waiter is woken");
    runtime.shutdown().await;
    base.shutdown().await;
}

fn auth_on(event: fireemu_core_functions::manifest::AuthEvent) -> Trigger {
    Trigger::Auth { event }
}

/// One user lifecycle event for a freshly created user.
fn user_event(kind: UserEventKind, email: &str) -> UserEvent {
    use fireemu_core_auth::mfa::TotpPolicy;
    use fireemu_core_auth::store::{AuthStore, NewUser};
    use fireemu_core_types::determinism::SplitMix64;
    let mut store = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
    store
        .create_user(
            NewUser::email(email),
            LogicalInstant::from_unix_seconds(1_788_004_860),
        )
        .unwrap();
    let mut event = store.take_user_events().remove(0);
    event.kind = kind;
    event
}

fn auth_pending(runtime: &FunctionsRuntime) -> u64 {
    runtime.status()["authEventsPending"].as_u64().unwrap()
}

fn payload_subjects(runtime: &FunctionsRuntime) -> Vec<String> {
    let inner = runtime.inner.lock().unwrap();
    let mut ids: Vec<EventId> = inner.payloads.keys().copied().collect();
    ids.sort();
    ids.iter()
        .map(|id| {
            inner.payloads[id].payload["data"]["email"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

/// A1-A3: an Auth event the queue cannot take is held, not dropped. It is admitted when
/// capacity returns, oldest first, and an event that fits is admitted at once.
#[tokio::test]
async fn an_auth_event_at_capacity_is_held_and_admitted_oldest_first() {
    use fireemu_core_functions::manifest::AuthEvent;
    let base = runtime().await;
    let runtime = runtime_with(&base, &[("created", auth_on(AuthEvent::Created))]);
    let (first, second) = (
        user_event(UserEventKind::Created, "one@example.com"),
        user_event(UserEventKind::Created, "two@example.com"),
    );
    // A free slot: admitted at once, nothing held.
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS - 1;
    runtime.on_user_event(&first);
    assert_eq!(runtime.inner.lock().unwrap().payloads.len(), 1);
    assert_eq!(auth_pending(&runtime), 0);
    // No slot: both are held, visible, and the runtime is not idle.
    runtime.on_user_event(&second);
    runtime.on_user_event(&first);
    assert_eq!(runtime.inner.lock().unwrap().payloads.len(), 1);
    assert_eq!(auth_pending(&runtime), 2);
    assert_eq!(
        runtime
            .inner
            .lock()
            .unwrap()
            .admission_refusals
            .get("auth_event_deferred"),
        Some(&2),
        "each held event is counted once"
    );
    assert!(!runtime.is_idle(), "a held event is outstanding work");
    // One slot frees: only the oldest held event is admitted.
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS - 2;
    runtime.admit_pending_auth();
    assert_eq!(auth_pending(&runtime), 1);
    assert_eq!(
        payload_subjects(&runtime),
        vec!["one@example.com".to_owned(), "two@example.com".to_owned()]
    );
    runtime.inner.lock().unwrap().reserved_event_records = 0;
    runtime.admit_pending_auth();
    assert_eq!(auth_pending(&runtime), 0);
    assert_eq!(runtime.inner.lock().unwrap().payloads.len(), 3);
    runtime.shutdown().await;
    base.shutdown().await;
}

/// A4/A5/A9: a held event is admitted whole (every matching function and every duplicate
/// copy) or not at all, and its payload carries the id of the event it becomes.
#[tokio::test]
async fn a_held_auth_event_is_admitted_whole_and_with_the_id_it_gets() {
    use fireemu_core_functions::manifest::AuthEvent;
    use fireemu_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule, FaultState};
    let base = runtime().await;
    let runtime = runtime_with(
        &base,
        &[
            ("a", auth_on(AuthEvent::Created)),
            ("b", auth_on(AuthEvent::Created)),
        ],
    );
    let faults = Arc::new(Mutex::new(FaultState::default()));
    faults.lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "functions.deliver".to_owned(),
                nth: None,
                function: Some("a".to_owned()),
                event_type: None,
            },
            action: FaultAction::Duplicate { count: 1 },
        }],
    });
    runtime.set_faults(faults);
    // Function a delivers twice, b once: three records.
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS - 2;
    runtime.on_user_event(&user_event(UserEventKind::Created, "u@example.com"));
    assert!(
        runtime.inner.lock().unwrap().payloads.is_empty(),
        "two free records do not hold the three copies, and none is admitted alone"
    );
    assert_eq!(auth_pending(&runtime), 1);
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS - 3;
    runtime.admit_pending_auth();
    assert_eq!(auth_pending(&runtime), 0);
    {
        let inner = runtime.inner.lock().unwrap();
        assert_eq!(inner.payloads.len(), 3);
        let session = runtime.config.session.value();
        for (id, queued) in &inner.payloads {
            let expected_ordinal = match queued.function.as_str() {
                "a" => [1_u128, 2],
                _ => [3, 3],
            };
            // The copies of one delivery share the payload (and so its id), which is the
            // ordinal of the delivery's first copy.
            let expected =
                crate::events::event_id_uuid(&format!("{session}-{}", expected_ordinal[0]));
            assert_eq!(
                queued.payload["id"],
                expected,
                "{} copy {}",
                queued.function,
                id.value()
            );
        }
    }
    runtime.inner.lock().unwrap().reserved_event_records = 0;
    runtime.shutdown().await;
    base.shutdown().await;
}

/// A6: the hold is bounded. The event beyond the bound is dropped, and the drop is counted
/// (it shows in the resource report), never silent.
#[tokio::test]
async fn the_auth_hold_is_bounded_and_a_drop_beyond_it_is_counted() {
    use fireemu_core_functions::manifest::AuthEvent;
    let base = runtime().await;
    let runtime = runtime_with(&base, &[("created", auth_on(AuthEvent::Created))]);
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS;
    let event = user_event(UserEventKind::Created, "u@example.com");
    for _ in 0..super::MAX_PENDING_AUTH_EVENTS {
        runtime.on_user_event(&event);
    }
    assert_eq!(
        auth_pending(&runtime),
        super::MAX_PENDING_AUTH_EVENTS as u64
    );
    let dropped = |runtime: &FunctionsRuntime| {
        runtime
            .inner
            .lock()
            .unwrap()
            .admission_refusals
            .get("auth_event_dropped")
            .copied()
            .unwrap_or(0)
    };
    assert_eq!(dropped(&runtime), 0);
    runtime.on_user_event(&event);
    assert_eq!(dropped(&runtime), 1);
    assert_eq!(
        auth_pending(&runtime),
        super::MAX_PENDING_AUTH_EVENTS as u64
    );
    runtime.inner.lock().unwrap().reserved_event_records = 0;
    runtime.shutdown().await;
    base.shutdown().await;
}

/// A7: a reset discards held events with the rest of the session; disabled background
/// triggers hold nothing.
#[tokio::test]
async fn a_reset_discards_held_auth_events_and_disabled_triggers_hold_none() {
    use fireemu_core_functions::manifest::AuthEvent;
    let base = runtime().await;
    let runtime = runtime_with(&base, &[("created", auth_on(AuthEvent::Created))]);
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS;
    let event = user_event(UserEventKind::Created, "u@example.com");
    runtime.on_user_event(&event);
    assert_eq!(auth_pending(&runtime), 1);
    runtime.reset();
    assert_eq!(auth_pending(&runtime), 0);
    runtime.inner.lock().unwrap().reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS;
    runtime.on_user_event(&event);
    assert_eq!(auth_pending(&runtime), 1);
    runtime.set_background_triggers(false);
    assert_eq!(
        auth_pending(&runtime),
        0,
        "switching the triggers off drops what was held"
    );
    runtime.on_user_event(&event);
    assert_eq!(auth_pending(&runtime), 0, "dropped by contract, never held");
    runtime.inner.lock().unwrap().reserved_event_records = 0;
    runtime.shutdown().await;
    base.shutdown().await;
}

/// A8 (model-based): over any interleaving of user events and capacity changes, the held
/// Auth events and the admitted ones equal a reference queue: first in, first out, a head
/// that does not fit blocks the younger events, and an event is admitted whole.
#[tokio::test]
async fn held_auth_events_follow_a_fifo_reference_model() {
    use fireemu_core_functions::manifest::AuthEvent;
    use proptest::prelude::*;
    use proptest::test_runner::{Config, TestRunner};

    #[derive(Debug, Clone)]
    enum Op {
        Created,
        Deleted,
        SetFree(usize),
    }
    let base = runtime().await;
    // Created reaches two functions (two records), Deleted one.
    let runtime = runtime_with(
        &base,
        &[
            ("a", auth_on(AuthEvent::Created)),
            ("b", auth_on(AuthEvent::Created)),
            ("c", auth_on(AuthEvent::Deleted)),
        ],
    );
    let ops = proptest::collection::vec(
        prop_oneof![
            Just(Op::Created),
            Just(Op::Deleted),
            (0_usize..5).prop_map(Op::SetFree),
        ],
        1..40,
    );
    let mut runner = TestRunner::new(Config::with_cases(96));
    runner
        .run(&ops, |ops| {
            {
                let mut inner = runtime.inner.lock().unwrap();
                inner.payloads.clear();
                inner.active_event_bytes = 0;
                inner.pending_auth.clear();
                inner.reserved_event_records = super::MAX_ACTIVE_EVENT_RECORDS;
            }
            // Model: free records, the held queue (need, label), admitted labels in order.
            let mut free = 0_usize;
            let mut held: std::collections::VecDeque<(usize, String)> =
                std::collections::VecDeque::default();
            let mut admitted: Vec<String> = Vec::new();
            for (n, op) in ops.iter().enumerate() {
                let label = format!("u{n}@example.com");
                match op {
                    Op::Created | Op::Deleted => {
                        let need = if matches!(op, Op::Created) { 2 } else { 1 };
                        let kind = if matches!(op, Op::Created) {
                            UserEventKind::Created
                        } else {
                            UserEventKind::Deleted
                        };
                        runtime.on_user_event(&user_event(kind, &label));
                        if held.is_empty() && free >= need {
                            free -= need;
                            admitted.push(label);
                        } else {
                            held.push_back((need, label));
                        }
                    }
                    Op::SetFree(f) => {
                        let active = runtime.inner.lock().unwrap().payloads.len();
                        runtime.inner.lock().unwrap().reserved_event_records =
                            super::MAX_ACTIVE_EVENT_RECORDS - active - f;
                        free = *f;
                        runtime.admit_pending_auth();
                        while let Some((need, _)) = held.front() {
                            if free < *need {
                                break;
                            }
                            free -= *need;
                            admitted.push(held.pop_front().unwrap().1);
                        }
                    }
                }
                let inner = runtime.inner.lock().unwrap();
                prop_assert_eq!(inner.pending_auth.len(), held.len());
                // The admitted events, in id order, are the model's admitted labels; each
                // delivery (a record per function) carries its user.
                let mut ids: Vec<EventId> = inner.payloads.keys().copied().collect();
                ids.sort();
                let mut seen: Vec<String> = Vec::new();
                for id in ids {
                    let email = inner.payloads[&id].payload["data"]["email"]
                        .as_str()
                        .unwrap()
                        .to_owned();
                    if seen.last() != Some(&email) {
                        seen.push(email);
                    }
                }
                prop_assert_eq!(seen, admitted.clone());
            }
            Ok(())
        })
        .unwrap();
    runtime.inner.lock().unwrap().reserved_event_records = 0;
    runtime.shutdown().await;
    base.shutdown().await;
}

#[tokio::test]
async fn remote_config_refuses_overflow_before_expanding_the_remaining_targets() {
    use fireemu_core_functions::manifest::FunctionGeneration;
    let base = runtime().await;
    for (duplicates, description, expected_visits) in [
        (3000, "small".to_owned(), 2),
        (1023, "x".repeat(64 * 1024), 1),
    ] {
        let mut manifest = base.manifest.clone();
        let template = manifest.get("echo").unwrap().clone();
        manifest.functions = (0..4)
            .map(|index| {
                let mut spec = template.clone();
                spec.name = format!("config{index}");
                spec.generation = FunctionGeneration::Second;
                spec.trigger = Trigger::RemoteConfig;
                spec
            })
            .collect();
        let runtime = FunctionsRuntime::new(
            manifest,
            base.config.clone(),
            base.clock.clone(),
            base.runner(),
            None,
        );
        let faults = Arc::new(Mutex::new(FaultState::default()));
        faults.lock().unwrap().install(FaultPlan {
            seed: 1,
            rules: vec![FaultRule {
                matches: FaultMatch {
                    operation: "functions.deliver".into(),
                    nth: None,
                    function: None,
                    event_type: None,
                },
                action: FaultAction::Duplicate { count: duplicates },
            }],
        });
        runtime.set_faults(faults.clone());
        let body = json!({
            "data": {"versionNumber": 7, "updateTime": "2026-01-02T03:04:05Z", "description": description},
            "v2Context": {"specversion": "1.0", "id": "caller", "time": "2026-01-02T03:04:07Z", "type": "google.firebase.remoteconfig.remoteConfig.v1.updated", "source": "//firebaseremoteconfig.googleapis.com/projects/demo-app"}
        });
        assert_eq!(
            runtime.publish_remote_config(&body),
            Err(SourceEventAdmissionError::Capacity)
        );
        assert!(runtime.inner.lock().unwrap().payloads.is_empty());
        assert_eq!(faults.lock().unwrap().counters()["functions.deliver"], expected_visits,
                "stop planning once the existing record or byte budget cannot fit; do not expand the remaining functions");
        runtime.shutdown().await;
    }
    base.shutdown().await;
}

/// Records, at each source-event payload encoding on this thread, whether the runtime
/// lock and the Eventarc registry lock were held.
fn locks_held_while_encoding(runtime: &Arc<FunctionsRuntime>) -> Arc<Mutex<Vec<(bool, bool)>>> {
    use std::sync::TryLockError::WouldBlock;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (runtime, record) = (Arc::downgrade(runtime), Arc::clone(&seen));
    crate::events::PAYLOAD_ENCODING_PROBE.set(Some(Box::new(move || {
        let runtime = runtime.upgrade().unwrap();
        let inner = matches!(runtime.inner.try_lock(), Err(WouldBlock));
        let registry = matches!(runtime.eventarc_registry.try_lock(), Err(WouldBlock));
        record.lock().unwrap().push((inner, registry));
    })));
    seen
}

#[tokio::test]
async fn firestore_admission_encodes_document_data_outside_the_runtime_lock() {
    use fireemu_core_firestore::value::Value as FsValue;

    let runtime = runtime().await;
    runtime.runner().kill_now();
    let mut commit = created_commit();
    let mut change = commit.changes[0].clone();
    let after = Arc::make_mut(change.after.as_mut().unwrap());
    after
        .fields
        .insert("blob".to_owned(), FsValue::String("x".repeat(256 * 1024)));
    let mut before = after.clone();
    let created = change.clone();
    before
        .fields
        .insert("blob".to_owned(), FsValue::String("y".repeat(1024)));
    change.before = Some(Arc::new(before));
    // A create (no old document) and an update (both documents).
    for change in [created, change] {
        commit.changes = Arc::from([change]);
        let held = locks_held_while_encoding(&runtime);
        let reservation = runtime.reserve_commit_events(&commit);
        crate::events::PAYLOAD_ENCODING_PROBE.set(None);
        let reservation = reservation.unwrap();
        let deliveries = reservation.deliveries.as_deref().unwrap();
        assert!(!deliveries.is_empty());
        for delivery in deliveries {
            assert!(delivery.payload.raw_data.as_deref().unwrap().len() > 256 * 1024);
        }
        // One encoding for the one change, with the runtime lock free.
        assert_eq!(*held.lock().unwrap(), [(false, false)]);
    }
}

#[tokio::test]
async fn firestore_large_delete_batch_stops_encoding_at_the_event_budget() {
    use crate::events::FIRESTORE_DOCUMENT_ENCODINGS;
    use crate::http::FunctionsHttpProfile;
    use fireemu_core_firestore::value::Value as FsValue;
    use fireemu_core_functions::manifest::{DocumentEvent, FunctionGeneration};

    let base = runtime().await;
    base.runner().kill_now();
    let mut manifest = base.manifest.clone();
    let mut function = manifest.get("ok").unwrap().clone();
    function.generation = FunctionGeneration::Second;
    if let Trigger::Firestore { event, .. } = &mut function.trigger {
        *event = DocumentEvent::Deleted;
    }
    manifest.functions = vec![function];
    let runtime = FunctionsRuntime::with_codebases(
        vec![super::CodebaseSpec {
            function: None,
            name: "default".into(),
            manifest,
            runner: base.runner(),
            spawn: None,
            cleanup_dir: None,
        }],
        base.config.clone(),
        base.clock.clone(),
        FunctionsHttpProfile::Strict,
    )
    .unwrap();
    let mut commit = created_commit();
    let mut document = commit.changes[0].after.as_deref().unwrap().clone();
    document
        .fields
        .insert("blob".into(), FsValue::Bytes(vec![0; 900 * 1024]));
    commit.changes = (0..100)
        .map(|index| {
            let mut before = document.clone();
            before.path = DocumentPath::parse(
                &ProjectId::try_new("demo-app").unwrap(),
                &DatabaseId::try_new("(default)").unwrap(),
                &format!("items/delete{index}"),
            )
            .unwrap();
            DocumentChange {
                path: before.path.clone(),
                before: Some(Arc::new(before)),
                after: None,
            }
        })
        .collect::<Vec<_>>()
        .into();
    let before_id = runtime.inner.lock().unwrap().next_event;
    FIRESTORE_DOCUMENT_ENCODINGS.set(0);
    let held = locks_held_while_encoding(&runtime);
    let result = runtime.reserve_commit_events(&commit);
    crate::events::PAYLOAD_ENCODING_PROBE.set(None);
    assert!(matches!(result, Err(SourceEventAdmissionError::Capacity)));
    assert_eq!(FIRESTORE_DOCUMENT_ENCODINGS.get(), 55);
    assert_eq!(*held.lock().unwrap(), vec![(false, false); 55]);
    assert_eq!(runtime.inner.lock().unwrap().next_event, before_id);
    assert_eq!(runtime.inner.lock().unwrap().active_event_bytes, 0);
    runtime.shutdown().await;
    base.shutdown().await;
}

#[tokio::test]
async fn eventarc_admission_encodes_payloads_outside_both_locks() {
    const CHANNEL: &str = "projects/demo-app/locations/us-central1/channels/custom";
    let runtime = runtime().await;
    runtime.runner().kill_now();
    let event = crate::eventarc::PublishedEvent {
        event_type: "com.example.done".to_owned(),
        attributes: [("region".to_owned(), "eu".to_owned())].into(),
        event: json!({
            "specversion": "1.0",
            "id": "e-1",
            "source": "demo",
            "type": "com.example.done",
            "data": {"blob": "x".repeat(64 * 1024)},
        }),
        raw_data: Some(r#"{"z":1,"blob":"y","a":2}"#.to_owned()),
    };
    let held = locks_held_while_encoding(&runtime);
    let delivered =
        runtime.publish_registered_custom_events(CHANNEL, &[event.clone(), event.clone()]);
    crate::events::PAYLOAD_ENCODING_PROBE.set(None);
    assert_eq!(delivered, Ok(2));
    // One encoding per published event, with neither lock held.
    assert_eq!(*held.lock().unwrap(), [(false, false); 2]);
    // The admitted deliveries carry the published payload and raw data, charged exactly
    // what `enqueue` charges for them.
    let inner = runtime.inner.lock().unwrap();
    assert_eq!(inner.payloads.len(), 2);
    let mut charged = 0;
    for payload in inner.payloads.values() {
        assert_eq!(*payload.payload, event.event);
        assert_eq!(payload.raw_data.as_deref(), event.raw_data.as_deref());
        let expected = FunctionsRuntime::retained_event_bytes(
            &payload.function,
            &event.event_type,
            CHANNEL,
            &event.event,
        )
        .unwrap()
            + event.raw_data.as_deref().unwrap().len();
        assert_eq!(payload.retained_bytes, expected);
        charged += expected;
    }
    assert_eq!(inner.active_eventarc_bytes, charged);
    assert_eq!(inner.active_event_bytes, charged);
    assert_eq!(inner.active_eventarc_records, 2);
}

/// The admission bound of an RTDB invocation frame is exactly the longest frame a
/// delivery of that event can send: the latest representable timestamps, the largest
/// attempt, and in the strict profile a 2nd gen `traceparent`.
#[tokio::test]
async fn the_database_frame_bound_is_the_longest_frame_a_delivery_sends() {
    use super::{CodebaseSpec, FunctionsHttpProfile};
    use fireemu_core_types::ids::{Epoch, EventId};
    use fireemu_core_types::time::LogicalDuration;

    let base = runtime().await;
    let latest = LogicalInstant::parse_rfc3339("9999-12-31T23:59:59.999999999Z").unwrap();
    let event = json!({
        "specversion": "1.0", "id": "event-id", "type": "google.firebase.database.ref.v1.written",
        "data": {"data": "q\"é😀", "delta": {"k": 1.5, "n": null}},
    });
    let event_bytes = serde_json::to_vec(&event).unwrap().len();
    for profile in [FunctionsHttpProfile::Strict, FunctionsHttpProfile::Emulator] {
        let runtime = FunctionsRuntime::with_codebases(
            vec![CodebaseSpec {
                function: None,
                name: "default".to_owned(),
                manifest: base.manifest.clone(),
                runner: base.runner(),
                spawn: None,
                cleanup_dir: None,
            }],
            base.config.clone(),
            base.clock.clone(),
            profile,
        )
        .unwrap();
        for generation in [1, 2] {
            let spec = parse_manifest(&json!({"functions": [{
                    "name": "roomChanged", "entryPoint": "rooms.changed", "generation": generation,
                    "trigger": {"type": "database", "eventType": "google.firebase.database.ref.v1.written",
                                "instance": "*", "ref": "/rooms/{room}"},
                }]}))
                .unwrap()
                .functions
                .remove(0);
            let now = latest
                .checked_add(LogicalDuration::from_seconds(-i64::from(
                    spec.timeout_seconds,
                )))
                .unwrap();
            let request = runtime
                .invoke_request_at(
                    EventId::new(7),
                    &spec,
                    u32::MAX,
                    Epoch::initial(),
                    &event,
                    latest,
                    None,
                    now,
                )
                .unwrap();
            // Framed as `Runner::invoke_inner` frames it.
            let mut frame: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>> =
                serde_json::from_str(request.get()).unwrap();
            frame.insert(
                "type".to_owned(),
                serde_json::value::to_raw_value("invoke").unwrap(),
            );
            let frame = serde_json::value::to_raw_value(&frame).unwrap().get().len();
            let largest = event_bytes + (crate::protocol::MAX_FRAME_BYTES - frame);
            let case = format!("{profile:?} generation {generation}");
            assert!(
                runtime.database_invoke_frame_fits(&spec, largest, 7, Epoch::initial()),
                "{case}"
            );
            assert!(
                !runtime.database_invoke_frame_fits(&spec, largest + 1, 7, Epoch::initial()),
                "{case}"
            );
        }
    }
    base.shutdown().await;
}

#[tokio::test]
async fn strict_second_gen_deliveries_have_fresh_sampled_traceparents_including_retries() {
    use super::{CodebaseSpec, FunctionsHttpProfile};
    use fireemu_core_functions::manifest::FunctionGeneration;
    use fireemu_core_types::ids::{Epoch, EventId};

    let base = runtime().await;
    let mut spec = base.manifest.get("ok").unwrap().clone();
    spec.generation = FunctionGeneration::Second;
    let mut traces = std::collections::BTreeSet::new();
    let mut trace_ids = std::collections::BTreeSet::new();
    let mut parent_ids = std::collections::BTreeSet::new();
    for profile in [FunctionsHttpProfile::Strict, FunctionsHttpProfile::Emulator] {
        let runtime = FunctionsRuntime::with_codebases(
            vec![CodebaseSpec {
                function: None,
                name: "default".to_owned(),
                manifest: base.manifest.clone(),
                runner: base.runner(),
                spawn: None,
                cleanup_dir: None,
            }],
            base.config.clone(),
            base.clock.clone(),
            profile,
        )
        .unwrap();
        for trigger in [
            base.manifest.get("ok").unwrap().trigger.clone(),
            Trigger::Storage {
                event: fireemu_core_functions::manifest::ObjectEvent::Finalized,
                bucket: None,
            },
            Trigger::PubSub {
                topic: "jobs".to_owned(),
            },
            Trigger::Eventarc {
                event_type: "example.event".to_owned(),
                channel: "locations/us-central1/channels/custom".to_owned(),
                filters: std::collections::BTreeMap::default(),
            },
        ] {
            spec.trigger = trigger;
            let raw_data = matches!(spec.trigger, Trigger::Eventarc { .. })
                .then_some(r#"{"z":3,"a":{"last":true,"first":null}}"#);
            for generation in [FunctionGeneration::First, FunctionGeneration::Second] {
                spec.generation = generation;
                // FE v5/v7 retry frames have the same event id and different trace and parent ids.
                for (event_id, attempt) in [(1, 1), (1, 2), (2, 1), (2, 2)] {
                    let data = raw_data.map_or(json!({}), |raw| serde_json::from_str(raw).unwrap());
                    let event = json!({"id": format!("event-{event_id}"), "specversion": "1.0", "data": data});
                    let request = runtime
                        .invoke_request(
                            EventId::new(event_id),
                            &spec,
                            attempt,
                            Epoch::initial(),
                            &event,
                            runtime.now(),
                            raw_data,
                        )
                        .unwrap();
                    if let Some(raw_data) = raw_data {
                        assert!(request.get().contains(&format!("\"data\":{raw_data}")));
                    }
                    let request: serde_json::Value = serde_json::from_str(request.get()).unwrap();
                    let delivered = &request["event"];
                    if profile == FunctionsHttpProfile::Strict
                        && generation == FunctionGeneration::Second
                    {
                        let trace = delivered["traceparent"]
                            .as_str()
                            .expect("traceparent extension");
                        let parts: Vec<_> = trace.split('-').collect();
                        assert_eq!(parts.len(), 4);
                        assert_eq!(parts[0], "00");
                        assert_eq!(parts[3], "01");
                        for (part, length) in [(parts[1], 32), (parts[2], 16)] {
                            assert_eq!(part.len(), length);
                            assert!(part
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
                            assert!(part.bytes().any(|b| b != b'0'));
                        }
                        assert!(traces.insert(trace.to_owned()));
                        assert!(trace_ids.insert(parts[1].to_owned()));
                        assert!(parent_ids.insert(parts[2].to_owned()));
                        assert_eq!(delivered["id"], event["id"]);
                    } else {
                        assert_eq!(delivered, &event);
                    }
                    assert!(event.get("traceparent").is_none());
                }
            }
        }
    }
    base.shutdown().await;
}

proptest::proptest! {
    #[test]
    fn pubsub_topic_matching_respects_profile_generation_origin_and_exact_name(
        name in "[a-z][a-zA-Z0-9]{0,15}",
        region in proptest::sample::select(vec!["us-central1", "europe-west1"]),
        first_generation in proptest::bool::ANY,
        strict in proptest::bool::ANY,
        include_schedules in proptest::bool::ANY,
        exact_topic in proptest::bool::ANY,
        schedule in proptest::bool::ANY,
    ) {
        let topic = format!("firebase-schedule-{name}-{region}");
        let trigger = if schedule {
            json!({"type": "schedule", "schedule": "every 5 minutes"})
        } else {
            json!({"type": "pubsub", "topic": topic})
        };
        let manifest = parse_manifest(&json!({"functions": [{"name": name, "region": region, "generation": if first_generation { 1 } else { 2 }, "trigger": trigger}]})).unwrap();
        let candidate = if exact_topic { topic } else { format!("{topic}-other") };
        let profile = if strict { super::FunctionsHttpProfile::Strict } else { super::FunctionsHttpProfile::Emulator };
        proptest::prop_assert_eq!(
            super::matches_pubsub_topic(&manifest.functions[0], &candidate, profile, include_schedules),
            exact_topic && (!schedule || (strict && first_generation && include_schedules))
        );
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep the profile, payload and routing boundaries in one scenario.
async fn user_publishes_to_gen1_schedule_topics_keep_their_pubsub_message_and_fan_out() {
    use super::{CodebaseSpec, FunctionsHttpProfile};
    use fireemu_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule, FaultState};
    for profile in [FunctionsHttpProfile::Strict, FunctionsHttpProfile::Emulator] {
        let base = runtime().await;
        let manifest = parse_manifest(&json!({"functions": [
                {"name": "tick", "generation": 1, "trigger": {"type": "schedule", "schedule": "every 5 minutes"}},
                {"name": "other", "generation": 1, "trigger": {"type": "schedule", "schedule": "every 5 minutes"}},
                {"name": "second", "generation": 2, "trigger": {"type": "schedule", "schedule": "every 5 minutes"}},
                {"name": "observer", "trigger": {"type": "pubsub", "topic": "firebase-schedule-tick-us-central1"}}
            ]})).unwrap();
        let runtime = FunctionsRuntime::with_codebases(
            vec![CodebaseSpec {
                function: None,
                name: "default".into(),
                manifest,
                runner: base.runner(),
                spawn: None,
                cleanup_dir: None,
            }],
            base.config.clone(),
            base.clock.clone(),
            profile,
        )
        .unwrap();
        let message = json!({"messageId": "11700000000000001", "data": "dXNlciBtZXNzYWdl", "attributes": {"scheduled": "true", "custom": "kept"}, "orderingKey": "ordered"});
        runtime
            .reserve_pubsub_events(
                "firebase-schedule-tick-us-central1",
                std::slice::from_ref(&message),
            )
            .unwrap()
            .publish();
        let delivered: Vec<_> = runtime
            .inner
            .lock()
            .unwrap()
            .payloads
            .values()
            .map(|queued| (queued.function.clone(), queued.payload.clone()))
            .collect();
        let names: Vec<_> = delivered.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            if profile == FunctionsHttpProfile::Strict {
                vec!["tick", "observer"]
            } else {
                vec!["observer"]
            }
        );
        for (_, event) in &delivered {
            assert_eq!(event["id"], message["messageId"]);
            assert_eq!(event["data"]["message"]["data"], message["data"]);
            assert_eq!(
                event["data"]["message"]["attributes"],
                message["attributes"]
            );
            assert_eq!(
                event["data"]["message"]["orderingKey"],
                message["orderingKey"]
            );
            assert_eq!(
                event["type"],
                "google.cloud.pubsub.topic.v1.messagePublished"
            );
        }
        let before = runtime.status()["pending"].clone();
        for topic in [
            "firebase-schedule-other-us-central1-miss",
            "firebase-schedule-second-us-central1",
            "firebase-schedule-tick",
        ] {
            runtime
                .reserve_pubsub_events(topic, std::slice::from_ref(&message))
                .unwrap()
                .publish();
        }
        assert_eq!(runtime.status()["pending"], before);
        runtime
            .reserve_scheduler_pubsub_events(
                "firebase-schedule-tick-us-central1",
                std::slice::from_ref(&message),
            )
            .unwrap()
            .publish();
        let subscribers: Vec<_> = runtime
            .inner
            .lock()
            .unwrap()
            .payloads
            .values()
            .map(|queued| queued.function.clone())
            .collect();
        assert_eq!(
            subscribers.iter().filter(|name| *name == "tick").count(),
            usize::from(profile == FunctionsHttpProfile::Strict)
        );
        assert_eq!(
            subscribers
                .iter()
                .filter(|name| *name == "observer")
                .count(),
            2
        );

        let faults = Arc::new(Mutex::new(FaultState::default()));
        faults.lock().unwrap().install(FaultPlan {
            seed: 1,
            rules: vec![FaultRule {
                matches: FaultMatch {
                    operation: "functions.deliver".into(),
                    nth: None,
                    function: Some("other".into()),
                    event_type: Some("google.cloud.pubsub.topic.v1.messagePublished".into()),
                },
                action: FaultAction::Duplicate { count: 1 },
            }],
        });
        runtime.set_faults(faults);
        let ids = runtime
            .publish("firebase-schedule-other-us-central1", &[message])
            .unwrap();
        let delivered = runtime
            .inner
            .lock()
            .unwrap()
            .payloads
            .values()
            .filter(|queued| queued.function == "other")
            .map(|queued| queued.payload.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            delivered.len(),
            2 * usize::from(profile == FunctionsHttpProfile::Strict)
        );
        for event in &delivered {
            assert_eq!(event["id"], ids[0]);
        }
        runtime.shutdown().await;
        base.shutdown().await;
    }
}

#[tokio::test]
async fn a_pubsub_event_names_the_subscription_provisioned_for_its_function_by_profile() {
    use crate::events::{function_subscription_id, SubscriptionNaming};
    use fireemu_core_functions::manifest::FunctionGeneration;
    let runtime = runtime().await;
    let mut second_gen = runtime.manifest.get("echo").unwrap().clone();
    second_gen.name = "onMessageV2".to_owned();
    second_gen.region = "europe-west1".to_owned();
    second_gen.generation = FunctionGeneration::Second;
    second_gen.trigger = Trigger::PubSub {
        topic: "jobs".to_owned(),
    };
    let mut first_gen = second_gen.clone();
    first_gen.name = "onMessageV1".to_owned();
    first_gen.generation = FunctionGeneration::First;
    let message = json!({"data": "YQ=="});
    let time = LogicalInstant::from_unix_seconds(1_788_004_860);
    let named = |runtime: &FunctionsRuntime, spec: &_| {
        runtime.pubsub_payload(spec, "22254343790642112", "jobs", &message, time)["data"]
            ["subscription"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    // The strict profile: Eventarc's name for a 2nd gen function, the topic's for a 1st gen one,
    // each the id the provisioning derives from the same function.
    let strict = named(&runtime, &second_gen);
    assert_eq!(
        strict,
        format!(
            "projects/demo-app/subscriptions/{}",
            function_subscription_id(
                SubscriptionNaming::Eventarc,
                "demo-app",
                &second_gen,
                "jobs"
            )
        )
    );
    assert!(
        strict.contains("/eventarc-europe-west1-onmessagev2-"),
        "{strict}"
    );
    assert_eq!(
        named(&runtime, &first_gen),
        "projects/demo-app/subscriptions/emulator-sub-jobs"
    );
    // The emulator profile: the official emulator's name for both.
    let mut emulator = runtime.config.clone();
    emulator.subscription_naming = SubscriptionNaming::EmulatorTopic;
    let emulator_runtime = FunctionsRuntime::new(
        runtime.manifest.clone(),
        emulator,
        Arc::new(Mutex::new(VirtualClock::new(time))),
        runtime.runner(),
        None,
    );
    assert_eq!(
        named(&emulator_runtime, &second_gen),
        "projects/demo-app/subscriptions/emulator-sub-jobs"
    );
    assert_eq!(
        named(&emulator_runtime, &first_gen),
        "projects/demo-app/subscriptions/emulator-sub-jobs"
    );
}

#[tokio::test]
async fn the_event_names_its_writer_by_profile() {
    use crate::events::{AuthContextNaming, OFFICIAL_AUTH_ID};
    let runtime = runtime().await;
    // The default is production's naming (the strict profile).
    assert_eq!(
        runtime.auth_context_of("app_user", Some("alice")),
        ("api_key", Some("alice"))
    );
    assert_eq!(
        runtime.auth_context_of("service_account", Some("owner")),
        ("unknown", Some("owner"))
    );
    assert_eq!(runtime.auth_context_of("system", None), ("system", None));
    // The emulator profile's: the official emulator's constants for every writer.
    let mut config = runtime.config.clone();
    config.auth_context = AuthContextNaming::Official;
    let official = FunctionsRuntime::new(
        runtime.manifest.clone(),
        config,
        Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        runtime.runner(),
        None,
    );
    for (kind, id) in [
        ("app_user", Some("alice")),
        ("service_account", Some("owner")),
        ("system", None),
    ] {
        assert_eq!(
            official.auth_context_of(kind, id),
            ("unknown", Some(OFFICIAL_AUTH_ID)),
            "{kind}"
        );
    }
}

/// The delivered payload, not only the mapping function, names the writer by profile: a call
/// site that passed the commit's actor through raw would fail here (the live-daemon test of the
/// same behaviour is ignored by default).
#[tokio::test]
async fn the_reserved_payload_of_an_auth_context_event_names_its_writer_by_profile() {
    use crate::events::{AuthContextNaming, OFFICIAL_AUTH_ID};
    let base = runtime().await;
    let commit_by = |auth_type: &str, auth_id: Option<&str>| {
        let mut commit = created_commit();
        commit.actor = Actor {
            auth_type: auth_type.to_owned(),
            auth_id: auth_id.map(str::to_owned),
        };
        // The fake runner's `withAuth` function listens on `audited/{id}`.
        let path = DocumentPath::parse(
            &ProjectId::try_new("demo-app").unwrap(),
            &DatabaseId::try_new("(default)").unwrap(),
            "audited/reserved",
        )
        .unwrap();
        let mut change = commit.changes[0].clone();
        change.path = path.clone();
        if let Some(after) = change.after.as_mut() {
            Arc::make_mut(after).path = path;
        }
        commit.changes = Arc::from([change]);
        commit
    };
    let named = |runtime: &Arc<FunctionsRuntime>, commit: &CommitEvent| {
        let reservation = runtime.reserve_commit_events(commit).unwrap();
        let deliveries = reservation.deliveries.as_ref().unwrap();
        assert_eq!(deliveries.len(), 1, "only the withAuth function listens");
        let payload = &deliveries[0].payload.payload;
        (
            payload["authtype"].as_str().map(str::to_owned),
            payload["authid"].as_str().map(str::to_owned),
        )
    };
    let production = |kind: &str, id: Option<&str>| (Some(kind.to_owned()), id.map(str::to_owned));
    // Strict (the default): production's names.
    for (actor, expected) in [
        (
            ("app_user", Some("alice")),
            production("api_key", Some("alice")),
        ),
        (
            ("service_account", Some("owner")),
            production("unknown", Some("owner")),
        ),
        // An actor that carries an identity (an email) keeps it. Only the id is pinned: production
        // documents the type of a real service account as `service_account` (UNRECORDED, not modelled).
        (
            (
                "service_account",
                Some("ops@demo-project.iam.gserviceaccount.com"),
            ),
            production("unknown", Some("ops@demo-project.iam.gserviceaccount.com")),
        ),
        // Near miss: a principal production was not recorded with keeps its own name.
        (
            ("unauthenticated", None),
            (Some("unauthenticated".to_owned()), None),
        ),
    ] {
        assert_eq!(
            named(&base, &commit_by(actor.0, actor.1)),
            expected,
            "{actor:?}"
        );
    }
    // The emulator profile: the official emulator's constants for every writer.
    let mut config = base.config.clone();
    config.auth_context = AuthContextNaming::Official;
    let official = FunctionsRuntime::new(
        base.manifest.clone(),
        config,
        Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        base.runner(),
        None,
    );
    for actor in [
        ("app_user", Some("alice")),
        ("service_account", Some("owner")),
        ("unauthenticated", None),
    ] {
        assert_eq!(
            named(&official, &commit_by(actor.0, actor.1)),
            production("unknown", Some(OFFICIAL_AUTH_ID)),
            "{actor:?}"
        );
    }
}

#[tokio::test]
async fn queued_event_retries_after_restart_budget_window_expires() {
    let runtime = runtime().await;
    {
        let mut budget = runtime.codebases[0].restart_budget.lock().unwrap();
        budget.attempts = super::RUNNER_RESTART_ATTEMPTS;
        budget.window_started = Some(
            Instant::now()
                .checked_sub(
                    super::RUNNER_RESTART_WINDOW
                        .checked_sub(Duration::from_millis(200))
                        .unwrap(),
                )
                .unwrap(),
        );
    }
    runtime.runner().kill_now();
    tokio::spawn(runtime.clone().dispatch_loop());
    runtime.publish("jobs", &[json!({"data": "YQ=="})]).unwrap();
    runtime
        .await_idle(Duration::from_secs(3))
        .await
        .expect("the queued event resumes when the restart budget resets");
    assert!(runtime
        .history()
        .iter()
        .any(|record| record.function == "onJob" && record.outcome == "ok"));
    runtime.shutdown().await;
}

fn body(id: &str) -> serde_json::Value {
    json!({"task": {
        "name": format!("projects/demo-app/locations/us-central1/queues/taskA/tasks/{id}"),
        "httpRequest": {"url": "", "body": "eyJkYXRhIjp7fX0="}
    }})
}

fn lease(runtime: &FunctionsRuntime) -> crate::task_scheduler::Dispatch {
    let mut inner = runtime.inner.lock().unwrap();
    let (mut dispatches, _) = inner.task_scheduler.dispatch_ready(
        Instant::now() + Duration::from_secs(1),
        "demo-app",
        |_| Some("us-central1".to_owned()),
        1,
    );
    dispatches.remove(0)
}

pub(super) fn created_commit() -> CommitEvent {
    let now = LogicalInstant::from_unix_seconds(1_788_004_860);
    let path = DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::try_new("(default)").unwrap(),
        "items/reserved",
    )
    .unwrap();
    CommitEvent {
        actor: Actor::system(),
        project: "demo-app".to_owned(),
        database: "(default)".to_owned(),
        version: 1,
        commit_time: Some(now),
        changes: Arc::from([DocumentChange {
            path: path.clone(),
            before: None,
            after: Some(Arc::new(Document {
                path,
                fields: std::collections::BTreeMap::default(),
                create_time: now,
                update_time: now,
                version: CommitVersion::from_value(1),
            })),
        }]),
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn firestore_fanout_preserves_frames_and_exact_logical_admission_bytes() {
    use crate::events::{firestore_event, FIRESTORE_DOCUMENT_ENCODINGS};
    use crate::http::FunctionsHttpProfile;
    use fireemu_core_firestore::value::Value as FsValue;
    use fireemu_core_functions::manifest::DocumentEvent;

    for (triggers, profile, generation) in [1, 4, 16].into_iter().flat_map(|triggers| {
        [FunctionsHttpProfile::Strict, FunctionsHttpProfile::Emulator]
            .into_iter()
            .flat_map(move |profile| {
                [
                    fireemu_core_functions::manifest::FunctionGeneration::First,
                    fireemu_core_functions::manifest::FunctionGeneration::Second,
                ]
                .into_iter()
                .map(move |generation| (triggers, profile, generation))
            })
    }) {
        let base = runtime().await;
        base.runner().kill_now();
        let mut manifest = base.manifest.clone();
        let template = manifest.get("ok").unwrap().clone();
        manifest.functions = (0..triggers)
            .map(|index| {
                let mut spec = template.clone();
                spec.name = format!("fanout{index}");
                spec.generation = generation;
                if let Trigger::Firestore {
                    event,
                    with_auth_context,
                    ..
                } = &mut spec.trigger
                {
                    *event = if index % 2 == 0 {
                        DocumentEvent::Updated
                    } else {
                        DocumentEvent::Written
                    };
                    *with_auth_context = index % 2 == 0;
                }
                spec
            })
            .collect();
        let runtime = FunctionsRuntime::with_codebases(
            vec![super::CodebaseSpec {
                function: None,
                name: "default".into(),
                manifest,
                runner: base.runner(),
                spawn: None,
                cleanup_dir: None,
            }],
            base.config.clone(),
            base.clock.clone(),
            profile,
        )
        .unwrap();
        let faults = Arc::new(Mutex::new(FaultState::default()));
        faults.lock().unwrap().install(FaultPlan {
            seed: 1,
            rules: vec![FaultRule {
                matches: FaultMatch {
                    operation: "functions.deliver".to_owned(),
                    nth: None,
                    function: None,
                    event_type: None,
                },
                action: FaultAction::Duplicate { count: 1 },
            }],
        });
        runtime.set_faults(faults);
        let mut commit = created_commit();
        let mut change = commit.changes[0].clone();
        let after = Arc::make_mut(change.after.as_mut().unwrap());
        after
            .fields
            .insert("blob".to_owned(), FsValue::String("x".repeat(256 * 1024)));
        after
            .fields
            .insert("escaped".to_owned(), FsValue::String("é\n\"".to_owned()));
        let mut before = after.clone();
        before.fields.remove("blob");
        before
            .fields
            .insert("removed".to_owned(), FsValue::Boolean(true));
        change.before = Some(Arc::new(before));
        commit.changes = Arc::from([change]);
        FIRESTORE_DOCUMENT_ENCODINGS.set(0);
        let reservation = runtime.reserve_commit_events(&commit).unwrap();
        let encodings = FIRESTORE_DOCUMENT_ENCODINGS.get();
        let deliveries = reservation.deliveries.as_ref().unwrap();
        assert_eq!(deliveries.len(), triggers * 2);
        let mut expected_bytes = 0;
        for (index, delivery) in deliveries.iter().enumerate() {
            let spec = runtime.manifest.get(&delivery.payload.function).unwrap();
            let Trigger::Firestore {
                event,
                with_auth_context,
                ..
            } = spec.trigger
            else {
                unreachable!()
            };
            let seed = format!("{}-{}", runtime.config.session.value(), index / 2 * 2 + 1);
            let mut expected = firestore_event(
                &seed,
                &commit.project,
                &commit.database,
                &runtime.config.location,
                "items/reserved",
                event,
                commit.changes[0].before.as_deref(),
                commit.changes[0].after.as_deref(),
                commit.commit_time.unwrap(),
                with_auth_context.then(|| runtime.auth_context_of("system", None)),
            );
            if profile == FunctionsHttpProfile::Strict
                && generation == fireemu_core_functions::manifest::FunctionGeneration::Second
            {
                expected["datacontenttype"] = json!("application/protobuf");
                expected["data"] = crate::events::firestore_event_data_encoded(
                    commit.changes[0].before.as_deref(),
                    commit.changes[0].after.as_deref(),
                    true,
                );
            }
            expected["params"] = json!({"id": "reserved"});
            let expected_len = FunctionsRuntime::retained_event_bytes(
                &spec.name,
                expected["type"].as_str().unwrap(),
                "documents/items/reserved",
                &expected,
            )
            .unwrap();
            assert_eq!(delivery.payload.retained_bytes, expected_len);
            expected_bytes += expected_len;
            let actual = runtime
                .invoke_request(
                    delivery.event.event_id,
                    spec,
                    1,
                    delivery.event.epoch,
                    &delivery.payload.payload,
                    delivery.payload.admitted_at,
                    delivery.payload.raw_data.as_deref(),
                )
                .unwrap();
            let mut actual: serde_json::Value = serde_json::from_str(actual.get()).unwrap();
            actual["event"]
                .as_object_mut()
                .unwrap()
                .remove("traceparent");
            if expected["datacontenttype"] == "application/protobuf" {
                use base64::Engine as _;
                use prost::Message as _;
                let decode = |data: &serde_json::Value| {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(data.as_str().unwrap())
                        .unwrap();
                    crate::events::DocumentEventData::decode(bytes.as_slice()).unwrap()
                };
                // Protobuf maps have no wire order; compare the decoded documents and retain exact byte lengths above.
                assert_eq!(decode(&actual["event"]["data"]), decode(&expected["data"]));
                expected["data"] = actual["event"]["data"].clone();
            }
            assert_eq!(actual["event"], expected);
            assert_eq!(actual["invocationId"], format!("{}-1", index + 1));
            assert_eq!(actual["function"], spec.name);
        }
        let shared_data = deliveries[0].payload.raw_data.as_ref().unwrap();
        assert!(deliveries
            .iter()
            .all(|delivery| Arc::ptr_eq(shared_data, delivery.payload.raw_data.as_ref().unwrap())));
        assert!(deliveries
            .chunks_exact(2)
            .all(|pair| Arc::ptr_eq(&pair[0].payload.payload, &pair[1].payload.payload)));
        assert_eq!(reservation.retained_bytes, expected_bytes);
        eprintln!("fanout triggers={triggers} document_encodings={encodings}");
        drop(reservation);
        let before_id = runtime.inner.lock().unwrap().next_event;
        runtime.inner.lock().unwrap().active_event_bytes =
            MAX_ACTIVE_EVENT_BYTES - expected_bytes + 1;
        assert!(matches!(
            runtime.reserve_commit_events(&commit),
            Err(SourceEventAdmissionError::Capacity)
        ));
        assert_eq!(runtime.inner.lock().unwrap().next_event, before_id);
        runtime.inner.lock().unwrap().active_event_bytes = MAX_ACTIVE_EVENT_BYTES - expected_bytes;
        let exact = runtime.reserve_commit_events(&commit).unwrap();
        assert_eq!(exact.retained_bytes, expected_bytes);
        drop(exact);
        runtime.shutdown().await;
        base.shutdown().await;
        assert_eq!(
            encodings, 2,
            "encode each before/after document once across all triggers"
        );
    }
}

#[tokio::test]
async fn invocation_encoding_does_not_hold_the_global_queue_lock() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let runtime = runtime().await;
    let acquired = Arc::new(AtomicBool::new(false));
    let observed = acquired.clone();
    let weak = Arc::downgrade(&runtime);
    *runtime.dispatch_encoding_probe.lock().unwrap() = Some(Arc::new(move || {
        observed.store(
            weak.upgrade().unwrap().inner.try_lock().is_ok(),
            Ordering::SeqCst,
        );
    }));
    {
        let mut inner = runtime.inner.lock().unwrap();
        assert!(FunctionsRuntime::enqueue(
            &mut inner,
            runtime.config.session,
            super::EventSource::Firestore,
            "ok",
            "example.event",
            "documents/test",
            runtime.now(),
            &json!({"data": "x".repeat(1024 * 1024)}),
            None
        ));
    }
    runtime.dispatch_ready();
    let idle = runtime.await_idle(Duration::from_secs(10)).await;
    runtime.shutdown().await;
    assert!(idle.is_ok());
    assert!(
        acquired.load(Ordering::SeqCst),
        "encoding must let unrelated enqueue/completion acquire Inner"
    );
}

#[tokio::test]
async fn resetting_a_reserved_encoding_ticket_never_reaches_a_replacement_runner() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let runtime = runtime().await;
    let reset = Arc::new(AtomicBool::new(false));
    let observed = reset.clone();
    let weak = Arc::downgrade(&runtime);
    *runtime.dispatch_encoding_probe.lock().unwrap() = Some(Arc::new(move || {
        if !observed.swap(true, Ordering::SeqCst) {
            weak.upgrade().unwrap().reset();
        }
    }));
    {
        let mut inner = runtime.inner.lock().unwrap();
        assert!(FunctionsRuntime::enqueue(
            &mut inner,
            runtime.config.session,
            super::EventSource::Firestore,
            "ok",
            "example.event",
            "documents/test",
            runtime.now(),
            &json!({"data":{}}),
            None
        ));
    }
    let old_runner = runtime.runner().diagnostic_id();
    runtime.dispatch_ready();
    tokio::time::timeout(Duration::from_secs(10), async {
        while runtime.runner().diagnostic_id() == old_runner {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let idle = runtime.await_idle(Duration::from_secs(10)).await;
    let history = runtime.history();
    let logs = runtime.runner().logs_since(None);
    let running = runtime.status()["running"].as_u64().unwrap();
    runtime.shutdown().await;
    assert!(idle.is_ok());
    assert!(
        history.is_empty(),
        "old epoch completion must not append history"
    );
    assert!(logs
        .lines
        .iter()
        .all(|line| line.invocation_id() != Some("1-1")));
    assert_eq!(running, 0);
}

#[tokio::test]
async fn dispatch_ticket_encoding_preserves_wire_bytes_raw_numbers_and_captured_deadline() {
    use fireemu_core_functions::manifest::FunctionGeneration;
    use fireemu_core_types::ids::{Epoch, EventId};
    let runtime = runtime().await;
    let mut spec = runtime.manifest.get("ok").unwrap().clone();
    spec.generation = FunctionGeneration::First;
    let captured = runtime.now();
    for index in 1..=32 {
        let raw = format!(r#"{{"z":{index}.00,"a":{{"last":true,"first":null}}}}"#);
        let event =
            json!({"id":index,"data":serde_json::from_str::<serde_json::Value>(&raw).unwrap()});
        let before = runtime
            .invoke_request(
                EventId::new(index),
                &spec,
                2,
                Epoch::initial(),
                &event,
                captured,
                Some(&raw),
            )
            .unwrap();
        let after = runtime
            .invoke_request_at(
                EventId::new(index),
                &spec,
                2,
                Epoch::initial(),
                &event,
                captured,
                Some(&raw),
                captured,
            )
            .unwrap();
        assert_eq!(before.get(), after.get());
        assert!(after.get().contains(&raw));
    }
    runtime
        .clock
        .lock()
        .unwrap()
        .advance_to(
            captured
                .checked_add(fireemu_core_types::time::LogicalDuration::from_seconds(600))
                .unwrap(),
        )
        .unwrap();
    let request = runtime
        .invoke_request_at(
            EventId::new(1),
            &spec,
            1,
            Epoch::initial(),
            &json!({"data":{}}),
            captured,
            None,
            captured,
        )
        .unwrap();
    let decoded: serde_json::Value = serde_json::from_str(request.get()).unwrap();
    assert_eq!(
        decoded["deadline"],
        captured
            .checked_add(fireemu_core_types::time::LogicalDuration::from_seconds(
                i64::from(spec.timeout_seconds)
            ))
            .unwrap()
            .to_rfc3339()
            .unwrap()
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn a_missing_head_payload_does_not_block_the_next_event_of_the_same_function() {
    let runtime = runtime().await;
    let next_id = {
        let mut inner = runtime.inner.lock().unwrap();
        for _ in 0..2 {
            assert!(FunctionsRuntime::enqueue(
                &mut inner,
                runtime.config.session,
                super::EventSource::Firestore,
                "ok",
                "example.event",
                "documents/backlog",
                runtime.now(),
                &json!({"data": {}}),
                None,
            ));
        }
        let ids = inner
            .outbox
            .dispatchable()
            .map(|event| event.event_id)
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), 2);
        inner.payloads.remove(&ids[0]);
        ids[1]
    };
    runtime.dispatch_ready();
    let dispatched = runtime
        .inner
        .lock()
        .unwrap()
        .running
        .contains_key(&format!("{}-1", next_id.value()));
    runtime.shutdown().await;
    assert!(dispatched, "the next event in the same queue must dispatch");
}

#[tokio::test]
async fn serial_backlog_keeps_canonical_order_and_healthy_function_progress() {
    for count in [256, 1024, 4096] {
        let base = runtime().await;
        let mut config = base.config.clone();
        config.max_running = 2;
        let manifest = base.manifest.clone();
        let runtime =
            FunctionsRuntime::new(manifest, config, base.clock.clone(), base.runner(), None);
        {
            let mut inner = runtime.inner.lock().unwrap();
            for index in 0..count {
                assert!(FunctionsRuntime::enqueue(
                    &mut inner,
                    runtime.config.session,
                    super::EventSource::Firestore,
                    if index == count - 1 { "onJob" } else { "ok" },
                    "example.event",
                    "documents/backlog",
                    LogicalInstant::from_unix_seconds(i64::from(index % 2 == 0)),
                    &json!({"data": {}}),
                    None
                ));
            }
        }
        let expected = runtime
            .inner
            .lock()
            .unwrap()
            .outbox
            .dispatchable()
            .map(|event| event.event_id.value())
            .collect::<Vec<_>>();
        let mut dispatched = Vec::new();
        while dispatched.len() < count {
            runtime.dispatch_ready();
            let running = runtime
                .inner
                .lock()
                .unwrap()
                .running
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            if dispatched.is_empty() {
                assert_eq!(
                    running.len(),
                    2,
                    "a saturated function does not block a healthy one"
                );
            }
            let mut batch = running
                .iter()
                .map(|key| key.split_once('-').unwrap().0.parse::<u128>().unwrap())
                .collect::<Vec<_>>();
            batch.sort_by_key(|id| {
                expected
                    .iter()
                    .position(|candidate| candidate == id)
                    .unwrap()
            });
            dispatched.extend(batch);
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    let notified = runtime.idle.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if runtime.inner.lock().unwrap().running.is_empty() {
                        break;
                    }
                    notified.await;
                }
            })
            .await
            .expect("fake runner completes the selected deliveries");
        }
        let healthy = count as u128;
        let expected_serial = expected
            .into_iter()
            .filter(|id| *id != healthy)
            .collect::<Vec<_>>();
        assert_eq!(
            dispatched
                .iter()
                .copied()
                .filter(|id| *id != healthy)
                .collect::<Vec<_>>(),
            expected_serial
        );
        assert_eq!(dispatched.iter().filter(|id| **id == healthy).count(), 1);
        assert_eq!(dispatched[1], healthy);
        let visits = runtime.inner.lock().unwrap().dispatch_candidate_visits;
        eprintln!("backlog events={count} candidate_visits={visits}");
        runtime.shutdown().await;
        base.shutdown().await;
        assert!(
            visits <= 2 * count,
            "visit at most two candidates per delivery, got {visits}"
        );
    }
}

#[tokio::test]
async fn source_event_reservation_is_all_or_none_and_drop_refunds_capacity() {
    let runtime = runtime().await;
    let commit = created_commit();
    let reservation = runtime.reserve_commit_events(&commit).unwrap();
    assert_eq!(reservation.deliveries.as_ref().unwrap().len(), 2);
    let required_bytes = reservation.retained_bytes;
    drop(reservation);
    {
        let inner = runtime.inner.lock().unwrap();
        assert_eq!(inner.reserved_event_records, 0);
        assert_eq!(inner.reserved_event_bytes, 0);
        assert!(inner.payloads.is_empty());
    }

    let stale = runtime.reserve_commit_events(&commit).unwrap();
    {
        let mut inner = runtime.inner.lock().unwrap();
        inner.epoch = inner.epoch.next().unwrap();
        inner.reserved_event_records = 0;
        inner.reserved_event_bytes = 0;
    }
    let current = runtime.reserve_commit_events(&commit).unwrap();
    let current_records = current.deliveries.as_ref().unwrap().len();
    let current_bytes = current.retained_bytes;
    drop(stale);
    {
        let inner = runtime.inner.lock().unwrap();
        assert_eq!(inner.reserved_event_records, current_records);
        assert_eq!(inner.reserved_event_bytes, current_bytes);
    }
    drop(current);

    {
        let mut inner = runtime.inner.lock().unwrap();
        inner.active_event_bytes = MAX_ACTIVE_EVENT_BYTES - required_bytes + 1;
    }
    let before_id = runtime.inner.lock().unwrap().next_event;
    assert!(matches!(
        runtime.reserve_commit_events(&commit),
        Err(SourceEventAdmissionError::Capacity)
    ));
    {
        let inner = runtime.inner.lock().unwrap();
        assert_eq!(inner.next_event, before_id);
        assert_eq!(inner.reserved_event_records, 0);
        assert_eq!(inner.reserved_event_bytes, 0);
        assert!(inner.payloads.is_empty());
    }

    {
        let mut inner = runtime.inner.lock().unwrap();
        inner.active_event_bytes = MAX_ACTIVE_EVENT_BYTES - required_bytes;
    }
    runtime.reserve_commit_events(&commit).unwrap().publish();
    {
        let inner = runtime.inner.lock().unwrap();
        assert_eq!(inner.payloads.len(), 2);
        assert_eq!(inner.reserved_event_records, 0);
        assert_eq!(inner.reserved_event_bytes, 0);
        assert_eq!(inner.active_event_bytes, MAX_ACTIVE_EVENT_BYTES);
    }
    runtime.shutdown().await;
    assert!(matches!(
        runtime.reserve_commit_events(&commit),
        Err(SourceEventAdmissionError::Unavailable)
    ));
    let mut foreign_commit = commit.clone();
    foreign_commit.project = "other-project".to_owned();
    let foreign = runtime.reserve_commit_events(&foreign_commit).unwrap();
    assert!(foreign.deliveries.as_ref().unwrap().is_empty());
}

#[tokio::test]
async fn shutdown_waits_for_an_owned_source_reservation_to_publish_or_cancel() {
    async fn assert_handoff(publish: bool) {
        let runtime = runtime().await;
        let reservation = runtime.reserve_commit_events(&created_commit()).unwrap();
        runtime.begin_shutdown();
        assert!(matches!(
            runtime.reserve_commit_events(&created_commit()),
            Err(SourceEventAdmissionError::Unavailable)
        ));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let shutting_down = {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                entered_tx.send(()).unwrap();
                runtime.shutdown().await;
            })
        };
        entered_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!shutting_down.is_finished());

        if publish {
            reservation.publish();
        } else {
            drop(reservation);
        }
        tokio::time::timeout(Duration::from_secs(5), shutting_down)
            .await
            .expect("shutdown finishes after the source handoff")
            .expect("shutdown task remains healthy");
        let inner = runtime.inner.lock().unwrap();
        assert_eq!(inner.reserved_event_records, 0);
        assert_eq!(inner.payloads.len(), usize::from(publish) * 2);
    }

    assert_handoff(true).await;
    assert_handoff(false).await;
}

#[tokio::test]
async fn source_event_reservation_charges_duplicate_fault_fanout() {
    let runtime = runtime().await;
    let faults = Arc::new(Mutex::new(FaultState::default()));
    faults.lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "functions.deliver".to_owned(),
                nth: None,
                function: None,
                event_type: None,
            },
            action: FaultAction::Duplicate { count: 1 },
        }],
    });
    runtime.set_faults(faults);

    let reservation = runtime.reserve_commit_events(&created_commit()).unwrap();
    assert_eq!(reservation.deliveries.as_ref().unwrap().len(), 4);
    assert_eq!(runtime.inner.lock().unwrap().reserved_event_records, 4);
    drop(reservation);
    assert_eq!(runtime.inner.lock().unwrap().reserved_event_records, 0);
    runtime.shutdown().await;
}

async fn assert_cleanup_after(
    runtime: &Arc<FunctionsRuntime>,
    dispatch: crate::task_scheduler::Dispatch,
    panic: bool,
) {
    let retained_before = runtime
        .inner
        .lock()
        .unwrap()
        .task_scheduler
        .retained_bytes();
    let idle = runtime.idle_notify();
    let notified = idle.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    let weak = Arc::downgrade(runtime);
    let (ready, ready_rx) = tokio::sync::oneshot::channel();
    let attempt = tokio::spawn(async move {
        let _completion = TaskCompletion {
            runtime: weak,
            queue: dispatch.queue,
            id: dispatch.id,
            generation: dispatch.generation,
            failed: false,
        };
        let _ = ready.send(());
        assert!(!panic, "exercise task-completion unwind cleanup");
        std::future::pending::<()>().await;
    });
    ready_rx.await.unwrap();
    if panic {
        assert!(attempt.await.unwrap_err().is_panic());
    } else {
        attempt.abort();
        let _ = attempt.await;
    }
    tokio::time::timeout(Duration::from_millis(100), &mut notified)
        .await
        .expect("task cleanup wakes idle waiters");
    let inner = runtime.inner.lock().unwrap();
    assert_eq!(inner.task_scheduler.outstanding(), 0);
    assert_eq!(inner.task_scheduler.active(), 0);
    assert!(inner.task_scheduler.retained_bytes() < retained_before);
}

#[tokio::test]
async fn task_completion_releases_scheduler_state_on_cancellation_and_panic() {
    let runtime = runtime().await;
    runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &body("cancelled"))
        .unwrap();
    assert_cleanup_after(&runtime, lease(&runtime), false).await;
    runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &body("panicked"))
        .unwrap();
    assert_cleanup_after(&runtime, lease(&runtime), true).await;
    runtime.shutdown().await;
}

#[tokio::test]
async fn runtime_maps_queue_and_process_task_capacity_to_distinct_responses() {
    let runtime = runtime().await;
    for sequence in 0..crate::task_scheduler::MAX_PENDING_PER_QUEUE {
        runtime
            .enqueue_task(
                "demo-app",
                "us-central1",
                "taskA",
                &body(&format!("queued-{sequence}")),
            )
            .unwrap();
    }
    let queue_full = runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &body("queue-full"))
        .unwrap_err();
    assert_eq!(queue_full.status, 409);

    let active = lease(&runtime);
    let process_full = runtime
        .enqueue_task("demo-app", "us-central1", "taskB", &body("process-full"))
        .unwrap_err();
    assert_eq!(process_full.status, 429);
    assert_eq!(
        process_full.body,
        "the local task queue capacity is exhausted"
    );
    drop(TaskCompletion {
        runtime: Arc::downgrade(&runtime),
        queue: active.queue,
        id: active.id,
        generation: active.generation,
        failed: false,
    });
    runtime
        .enqueue_task("demo-app", "us-central1", "taskB", &body("process-full"))
        .expect("a count-refused name remains reusable after capacity is released");
    runtime.shutdown().await;
}

#[tokio::test]
async fn active_event_admission_is_bounded_and_retirement_refunds_its_bytes() {
    let runtime = runtime().await;
    let now = runtime.now();
    let payload = json!({"ok": true});
    {
        let mut inner = runtime.inner.lock().unwrap();
        for _ in 0..super::MAX_ACTIVE_EVENTARC_RECORDS {
            assert!(FunctionsRuntime::enqueue(
                &mut inner,
                SessionId::new(7),
                super::EventSource::Eventarc,
                "customEvent",
                "com.example.done",
                "projects/demo-app/locations/us-central1/channels/custom",
                now,
                &payload,
                None,
            ));
        }
        let retained = inner.active_event_bytes;
        assert!(!FunctionsRuntime::enqueue(
            &mut inner,
            SessionId::new(7),
            super::EventSource::Eventarc,
            "customEvent",
            "com.example.done",
            "projects/demo-app/locations/us-central1/channels/custom",
            now,
            &payload,
            None,
        ));
        assert!(FunctionsRuntime::enqueue(
            &mut inner,
            SessionId::new(7),
            super::EventSource::Firestore,
            "customEvent",
            "com.example.done",
            "documents/reserved-for-other-sources",
            now,
            &payload,
            None,
        ));
        FunctionsRuntime::remove_payload(&mut inner, super::EventId::new(1));
        assert!(inner.active_event_bytes < retained);
        assert!(FunctionsRuntime::enqueue(
            &mut inner,
            SessionId::new(7),
            super::EventSource::Eventarc,
            "customEvent",
            "com.example.done",
            "projects/demo-app/locations/us-central1/channels/custom",
            now,
            &payload,
            None,
        ));

        inner.active_event_bytes = super::MAX_ACTIVE_EVENT_BYTES - 1;
        assert!(FunctionsRuntime::can_admit_events(
            &inner,
            super::EventSource::Firestore,
            0,
            1
        ));
        assert!(!FunctionsRuntime::can_admit_events(
            &inner,
            super::EventSource::Firestore,
            0,
            2
        ));
        inner.active_event_bytes = 0;
        inner.active_eventarc_bytes = super::MAX_ACTIVE_EVENTARC_BYTES - 1;
        assert!(FunctionsRuntime::can_admit_events(
            &inner,
            super::EventSource::Eventarc,
            0,
            1
        ));
        assert!(!FunctionsRuntime::can_admit_events(
            &inner,
            super::EventSource::Eventarc,
            0,
            2
        ));
    }
    runtime.shutdown().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn reload_expires_never_settling_background_generations_except_in_debug_mode() {
    for debug_mode in [false, true] {
        let root = std::env::temp_dir().join(format!(
            "fireemu-drain-deadline-{}-{debug_mode}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let handler_source = r"
const fs = require('node:fs');
const path = require('node:path');
for (const [name, topic, timeout] of [['hang', 'jobs', 1], ['longHang', 'long-jobs', 4]]) {
  const fn = async event => {
    fs.writeFileSync(path.join(process.cwd(), '..', event.signal || name), 'started');
    await new Promise(() => {});
  };
  fn.run = fn;
  fn.__endpoint = { platform: 'gcfv2', concurrency: 2, timeoutSeconds: timeout,
    eventTrigger: { eventType: 'google.cloud.pubsub.topic.v1.messagePublished', eventFilters: { topic } } };
  exports[name] = fn;
}
";
        std::fs::create_dir_all(root.join("0")).unwrap();
        std::fs::write(root.join("0/package.json"), r#"{"main":"index.cjs"}"#).unwrap();
        std::fs::write(root.join("0/index.cjs"), handler_source).unwrap();
        let spawn = SpawnSpec {
            command: vec![
                "node".into(),
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../tools/runner-node/index.mjs"
                )
                .into(),
                "--source".into(),
                ".".into(),
            ],
            cwd: Some(root.join("0").display().to_string()),
            env: vec![("GCLOUD_PROJECT".into(), "demo-app".into())],
            hello_timeout: Duration::from_secs(10),
        };
        let first = Arc::new(Runner::spawn_spec(&spawn).await.unwrap());
        let manifest = parse_manifest(first.hello().manifest.as_ref().unwrap()).unwrap();
        let runtime = FunctionsRuntime::with_codebases(
            vec![super::CodebaseSpec {
                function: None,
                name: "default".into(),
                manifest: manifest.clone(),
                runner: first.clone(),
                spawn: None,
                cleanup_dir: Some(root.join("0")),
            }],
            FunctionsConfig {
                debug_mode,
                max_running: 3,
                retry_attempts: 1,
                ..FunctionsConfig::for_tests(1, "test-secret".into())
            },
            Arc::new(Mutex::new(VirtualClock::new(
                LogicalInstant::from_unix_seconds(0),
            ))),
            crate::http::FunctionsHttpProfile::Emulator,
        )
        .unwrap();
        std::fs::create_dir_all(root.join("0")).unwrap();
        let dispatcher = tokio::spawn(runtime.clone().dispatch_loop());
        let mut runners = vec![first];
        let mut waiters = Vec::new();
        let mut oldest_deadline = None;
        for revision in 0..2 {
            if revision == 0 {
                runtime
                    .publish("long-jobs", &[json!({"data": "YQ=="})])
                    .unwrap();
            }
            runtime.publish("jobs", &[json!({"data": "YQ=="})]).unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if root.join("hang").exists()
                        && (revision != 0 || root.join("longHang").exists())
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            // A separate unbounded waiter must receive the timeout verdict, not runner death.
            let runner = runners[revision].clone();
            waiters.push(tokio::spawn(async move {
                    runner
                        .invoke_unbounded(json!({"invocationId": format!("waiter-{revision}"), "function": "hang", "trigger": "pubsub", "event": {"signal": format!("waiter-{revision}")}}))
                        .await
                        .outcome
                }));
            tokio::time::timeout(Duration::from_secs(5), async {
                while !root.join(format!("waiter-{revision}")).exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            std::fs::remove_file(root.join("hang")).unwrap();
            if revision == 0 {
                std::fs::remove_file(root.join("longHang")).unwrap();
            }
            if revision == 0 {
                // Keep the original deadline so a publication-relative timeout cannot pass.
                oldest_deadline = {
                    let inner = runtime.inner.lock().unwrap();
                    inner
                        .running
                        .iter()
                        .find(|(_, function)| function.as_str() == "longHang")
                        .and_then(|(key, _)| inner.running_deadlines.get(key))
                        .copied()
                };
                tokio::time::sleep(Duration::from_millis(1250)).await;
            }
            let source = root.join((revision + 1).to_string());
            std::fs::create_dir_all(&source).unwrap();
            std::fs::write(source.join("package.json"), r#"{"main":"index.cjs"}"#).unwrap();
            std::fs::write(source.join("index.cjs"), handler_source).unwrap();
            let mut replacement_spawn = spawn.clone();
            replacement_spawn.cwd = Some(source.display().to_string());
            let replacement = Arc::new(Runner::spawn_spec(&replacement_spawn).await.unwrap());
            runtime
                .reload_codebase(super::CodebaseSpec {
                    function: None,
                    name: "default".into(),
                    manifest: manifest.clone(),
                    runner: replacement.clone(),
                    spawn: None,
                    cleanup_dir: Some(root.join((revision + 1).to_string())),
                })
                .unwrap();
            runners.push(replacement);
        }
        if debug_mode {
            tokio::time::sleep(Duration::from_millis(2400)).await;
            assert!(runners.iter().all(|runner| runner.is_alive()));
            assert_eq!(runtime.inner.lock().unwrap().running.len(), 3);
            assert!(waiters.iter().all(|waiter| !waiter.is_finished()));
        } else {
            tokio::time::timeout(Duration::from_secs(4), async {
                while runners[1].is_alive() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert!(
                runners[0].is_alive(),
                "the longer invocation must protect its generation"
            );
            tokio::time::timeout_at(
                oldest_deadline.unwrap() + Duration::from_millis(1500),
                async {
                    while runners[0].is_alive() {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                },
            )
            .await
            .unwrap();
            assert!(
                runners[..2].iter().all(|runner| !runner.is_alive()),
                "overdue draining generations must stop"
            );
            assert!(
                runtime.inner.lock().unwrap().running.is_empty(),
                "expired invocations release concurrency slots"
            );
            for waiter in waiters.drain(..) {
                assert_eq!(
                    waiter.await.unwrap(),
                    crate::runner::InvokeOutcome::TimedOut
                );
            }
            for revision in 0..2 {
                assert!(
                    !root.join(revision.to_string()).exists(),
                    "expired snapshots are removed"
                );
            }
            assert_eq!(
                runtime
                    .history()
                    .iter()
                    .filter(|record| record.outcome == "timeout")
                    .count(),
                3
            );
        }
        if !debug_mode {
            runtime.publish("jobs", &[json!({"data": "YQ=="})]).unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if runtime.inner.lock().unwrap().running.len() == 1 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("released slots admit the current generation");
        }
        runtime.shutdown().await;
        dispatcher.await.unwrap();
        for waiter in waiters {
            let _ = waiter.await;
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn reload_drains_selected_generations_and_shutdown_removes_their_snapshots() {
    let spawn = SpawnSpec {
        command: vec![
            "node".into(),
            "-e".into(),
            r"
const hello = JSON.stringify({ type: 'hello', runner: 'node', httpPort: 1 });
process.stdout.write(`${Buffer.byteLength(hello)}\n${hello}`);
process.stdin.resume();
process.stdin.on('data', () => process.exit(0));
"
            .into(),
        ],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(10),
    };
    let manifest = parse_manifest(
        &json!({"functions":[{"name":"echo","trigger":{"type":"http","callable":false}}]}),
    )
    .unwrap();
    let runner = Arc::new(Runner::spawn_spec(&spawn).await.unwrap());
    let runtime = FunctionsRuntime::new(
        manifest.clone(),
        FunctionsConfig::for_tests(1, "test-secret".into()),
        Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(0),
        ))),
        runner.clone(),
        None,
    );
    let target = runtime
        .http_target("demo-app", "us-central1", "echo")
        .unwrap();
    let (_, _, first) = runtime.admit_http_stream(&target, 4).unwrap();
    runtime
        .current_http_addr(&target, &first.key)
        .await
        .unwrap();
    let root = std::env::temp_dir().join(format!("fireemu-drain-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let mut runners = vec![runner];
    let mut cleanups = Vec::new();
    let mut admissions = vec![first];
    for revision in 1..=2 {
        let path = root.join(revision.to_string());
        std::fs::create_dir_all(&path).unwrap();
        let replacement = Arc::new(Runner::spawn_spec(&spawn).await.unwrap());
        runtime
            .reload_codebase(super::CodebaseSpec {
                function: None,
                name: "default".into(),
                manifest: manifest.clone(),
                runner: replacement.clone(),
                spawn: None,
                cleanup_dir: Some(path),
            })
            .unwrap();
        cleanups.push(
            runtime.codebases[0]
                .generation()
                .cleanup_dir
                .as_ref()
                .unwrap()
                .0
                .clone(),
        );
        assert!(
            runners.iter().all(|runner| runner.is_alive()),
            "busy old runners must survive publication"
        );
        runners.push(replacement);
        let (_, _, admission) = runtime.admit_http_stream(&target, 4).unwrap();
        // A route resolved before publication must select the new runner at admission.
        runtime
            .current_http_addr(&target, &admission.key)
            .await
            .unwrap();
        assert_eq!(
            runtime.inner.lock().unwrap().running_runners[&admission.key],
            runners.last().unwrap().diagnostic_id()
        );
        admissions.push(admission);
    }
    drop(admissions.remove(1));
    assert!(
        !runners[1].is_alive(),
        "a retired runner stops at its own last release"
    );
    assert!(runners[0].is_alive(), "another generation still has work");
    assert!(!cleanups[0].exists(), "idle retired snapshots are removed");
    let retained_cleanup = runtime.codebases[0]
        .generation()
        .cleanup_dir
        .clone()
        .unwrap();
    runtime.shutdown().await;
    assert!(
        runners.iter().all(|runner| !runner.is_alive()),
        "shutdown stops busy retired and current runners"
    );
    assert!(
        cleanups.iter().all(|cleanup| !cleanup.exists()) && !retained_cleanup.0.exists(),
        "shutdown removes snapshots even with retained runtime references"
    );
    let recreated = retained_cleanup.0.clone();
    std::fs::create_dir_all(&recreated).unwrap();
    std::fs::write(recreated.join("replacement"), "keep").unwrap();
    drop(retained_cleanup);
    assert!(
        recreated.join("replacement").exists(),
        "explicit cleanup disarms retained owners"
    );
    drop(admissions);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn reload_replaces_manual_eventarc_registrations_with_the_manifest_generation() {
    let runtime = runtime().await;
    let trigger = "us-central1-customEvent-manual";
    let body = br#"{"eventTrigger":{"eventType":"com.example.done","channel":"locations/us-central1/channels/custom","eventFilters":{"region":"eu"}}}"#;
    let parsed = crate::eventarc::parse_event_trigger("demo-app", trigger, body).unwrap();
    runtime
        .register_eventarc_trigger("demo-app", trigger, parsed)
        .unwrap();
    assert!(runtime
        .eventarc_triggers()
        .unwrap()
        .to_string()
        .contains(trigger));

    let spec = SpawnSpec {
        command: vec![
            "python3".to_owned(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py").to_owned(),
        ],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(60),
    };
    let replacement = Arc::new(Runner::spawn_spec(&spec).await.unwrap());
    let manifest = runtime.manifest().clone();
    runtime
        .reload_codebase(super::CodebaseSpec {
            function: None,
            name: "default".to_owned(),
            manifest,
            runner: replacement,
            spawn: Some(spec),
            cleanup_dir: None,
        })
        .unwrap();
    let table = runtime.eventarc_triggers().unwrap().to_string();
    assert!(!table.contains(trigger));
    assert!(table.contains("us-central1-customEvent-1-locations/us-central1/channels/custom"));
    runtime.shutdown().await;
}

#[test]
fn task_timestamps_preserve_exact_utc_microseconds() {
    let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::from_nanos(0))));
    let runtime = FunctionsRuntime::new(
        super::FunctionManifest::default(),
        FunctionsConfig {
            clock_policy: crate::application_clock::ApplicationClockPolicy {
                tasks_virtual: true,
                ..Default::default()
            },
            ..FunctionsConfig::for_tests(1, "test-only".to_owned())
        },
        clock.clone(),
        Arc::new(Runner::unstarted("timestamp-test")),
        None,
    );
    for (nanos, expected) in [
        (0, "1970-01-01T00:00:00.000000Z"),
        (-1_000, "1969-12-31T23:59:59.999999Z"),
        (1_234_567_890, "1970-01-01T00:00:01.234567Z"),
        (1_788_004_860_123_456_789, "2026-08-29T12:01:00.123456Z"),
    ] {
        clock
            .lock()
            .unwrap()
            .set_allow_backwards(LogicalInstant::from_nanos(nanos));
        assert_eq!(super::task_timestamp_from_nanos(nanos), expected);
        assert_eq!(runtime.task_timestamp(), expected);
    }
}

#[test]
fn strict_get_rejects_unserved_resources_before_accessing_scheduler_state() {
    let mut manifest = parse_manifest(&json!({"functions": [
        {"name": "q", "trigger": {"type": "http", "callable": false}},
        {"name": "http", "trigger": {"type": "http", "callable": false}}
    ]}))
    .unwrap();
    manifest.functions[0].trigger = Trigger::TaskQueue {
        retry: TaskRetryConfig::default(),
        rate_limits: TaskRateLimits::default(),
    };
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig::for_tests(1, "test-only".to_owned()),
        Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::from_nanos(0)))),
        Arc::new(Runner::unstarted("strict-get-test")),
        None,
    );
    // Resource validation must still return NOT_FOUND when scheduler state is unavailable.
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _state = runtime.inner.lock().unwrap();
        panic!("poison scheduler state for the validation-order test");
    }))
    .is_err());
    for (project, region, queue) in [
        ("demo-app", "europe-west1", "q"),
        ("other", "us-central1", "q"),
        ("demo-app", "us-central1", "http"),
        ("demo-app", "us-central1", "missing"),
    ] {
        for full in [false, true] {
            let error = runtime
                .get_task_strict(project, region, queue, "missing", full)
                .unwrap_err();
            assert_eq!(error.status, 404, "{project}/{region}/{queue}, full={full}");
            assert_eq!(
                error.body,
                crate::tasks_production::Refusal::task_not_found()
                    .body()
                    .to_string()
            );
        }
    }
    assert_eq!(
        runtime
            .get_task_strict("demo-app", "us-central1", "q", "missing", false)
            .unwrap_err()
            .status,
        500
    );
}
