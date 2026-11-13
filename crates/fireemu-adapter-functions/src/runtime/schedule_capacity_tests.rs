use super::{CatchUpPolicy, FunctionsConfig, FunctionsRuntime, MAX_ACTIVE_EVENT_RECORDS};
use crate::manifest_json::parse_manifest;
use crate::runner::{Runner, SpawnSpec};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule, FaultState};
use fireemu_core_types::ids::SessionId;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use proptest::strategy::Strategy as _;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 2026-08-29T12:01:00Z: `tick` (every 5 minutes) is next due at 12:05, `nightly` and
/// `failSchedule` (`0 3 * * *`) at 03:00 the next day.
const START: i64 = 1_788_004_860;

type Clock = Arc<Mutex<VirtualClock>>;

async fn runtime(catch_up: CatchUpPolicy) -> (Arc<FunctionsRuntime>, Clock) {
    // Large enough that the catch-up cap never limits these tests: only event admission
    // does.
    runtime_with(catch_up, super::OverlapPolicy::Allow, 100_000, START).await
}

async fn runtime_with(
    catch_up: CatchUpPolicy,
    overlap: super::OverlapPolicy,
    max_catch_up_runs: usize,
    start: i64,
) -> (Arc<FunctionsRuntime>, Clock) {
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
    let manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(start),
    )));
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            retry_attempts: 1,
            overlap,
            catch_up,
            functions_host: Some("127.0.0.1:5001".to_owned()),
            ..FunctionsConfig::for_tests(max_catch_up_runs, "test-secret".to_owned())
        },
        clock.clone(),
        Arc::new(runner),
        Some(spec),
    );
    (runtime, clock)
}

fn advance(clock: &Clock, seconds: i64) {
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(seconds))
        .unwrap();
}

/// Leaves room for exactly `room` more event records (the rest is held as reserved
/// capacity, as an in-flight source reservation would hold it).
fn set_room(runtime: &FunctionsRuntime, room: usize) {
    let mut inner = runtime.inner.lock().unwrap();
    inner.reserved_event_records =
        MAX_ACTIVE_EVENT_RECORDS.saturating_sub(inner.payloads.len() + room);
}

/// Admitted schedule runs in admission order: (function, scheduleTime).
fn admitted(runtime: &FunctionsRuntime) -> Vec<(String, String)> {
    let inner = runtime.inner.lock().unwrap();
    inner
        .payloads
        .values()
        .map(|queued| {
            (
                queued.function.clone(),
                queued.payload["data"]["scheduleTime"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        })
        .collect()
}

/// Releases the simulated reservation (shutdown waits for reservations to settle), then
/// shuts the runtime down.
async fn finish(runtime: &FunctionsRuntime) {
    runtime.inner.lock().unwrap().reserved_event_records = 0;
    runtime.shutdown().await;
}

fn pending(runtime: &FunctionsRuntime) -> bool {
    runtime.inner.lock().unwrap().catch_up_pending
}

fn run(function: &str, time: &str) -> (String, String) {
    (function.to_owned(), time.to_owned())
}

#[tokio::test]
async fn an_automatic_run_refused_for_capacity_stays_due_and_runs_once_room_frees() {
    for policy in [CatchUpPolicy::All, CatchUpPolicy::Latest] {
        let (runtime, clock) = runtime(policy).await;
        set_room(&runtime, 0);
        advance(&clock, 300);
        runtime.on_clock_changed();
        assert!(admitted(&runtime).is_empty(), "{policy:?}");
        assert!(
            pending(&runtime),
            "{policy:?}: the refused run is still due"
        );
        // Still full: a second sweep at the same instant admits nothing and loses nothing.
        runtime.on_clock_changed();
        assert!(admitted(&runtime).is_empty(), "{policy:?}");
        set_room(&runtime, 10);
        runtime.on_clock_changed();
        assert_eq!(
            admitted(&runtime),
            vec![run("tick", "2026-08-29T12:05:00Z")],
            "{policy:?}"
        );
        assert!(!pending(&runtime), "{policy:?}");
        // A further sweep at the same instant delivers nothing twice.
        runtime.on_clock_changed();
        assert_eq!(admitted(&runtime).len(), 1, "{policy:?}");
        finish(&runtime).await;
    }
}

#[tokio::test]
async fn a_manual_run_refused_for_capacity_is_an_error_and_enqueues_nothing() {
    let (runtime, _clock) = runtime(CatchUpPolicy::All).await;
    set_room(&runtime, 0);
    let refused = runtime.run_schedule("tick").unwrap_err();
    assert!(
        matches!(&refused, super::ScheduleRunError::Capacity(m) if m.contains("capacity")),
        "{refused:?}"
    );
    assert!(admitted(&runtime).is_empty());
    // The refusal is counted (the resource report lists it as `admission.capacity`).
    let refusals = runtime
        .inner
        .lock()
        .unwrap()
        .admission_refusals
        .get("capacity")
        .copied();
    assert_eq!(refusals, Some(1));
    set_room(&runtime, 1);
    runtime.run_schedule("tick").unwrap();
    assert_eq!(
        admitted(&runtime),
        vec![run("tick", "2026-08-29T12:01:00Z")]
    );
    finish(&runtime).await;
}

#[tokio::test]
async fn duplicate_copies_of_a_schedule_run_are_admitted_all_or_none() {
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    let faults = Arc::new(Mutex::new(FaultState::default()));
    faults.lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "functions.deliver".to_owned(),
                nth: None,
                function: Some("tick".to_owned()),
                event_type: None,
            },
            action: FaultAction::Duplicate { count: 1 },
        }],
    });
    runtime.set_faults(faults);
    set_room(&runtime, 1);
    assert!(runtime.run_schedule("tick").is_err());
    advance(&clock, 300);
    runtime.on_clock_changed();
    assert!(admitted(&runtime).is_empty(), "no partial fan-out");
    assert!(pending(&runtime));
    set_room(&runtime, 2);
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![
            run("tick", "2026-08-29T12:05:00Z"),
            run("tick", "2026-08-29T12:05:00Z")
        ]
    );
    finish(&runtime).await;
}

/// A job's later runs wait behind its refused one, even when a later run would fit: here
/// only the first delivery decision duplicates, so 12:05 needs two slots and 12:10 one.
#[tokio::test]
async fn a_later_run_of_a_job_never_overtakes_its_refused_run() {
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    let faults = Arc::new(Mutex::new(FaultState::default()));
    faults.lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "functions.deliver".to_owned(),
                nth: Some(1),
                function: Some("tick".to_owned()),
                event_type: None,
            },
            action: FaultAction::Duplicate { count: 1 },
        }],
    });
    runtime.set_faults(faults);
    set_room(&runtime, 1);
    advance(&clock, 600);
    runtime.on_clock_changed();
    assert!(admitted(&runtime).is_empty(), "{:?}", admitted(&runtime));
    set_room(&runtime, 10);
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![
            run("tick", "2026-08-29T12:05:00Z"),
            run("tick", "2026-08-29T12:10:00Z")
        ]
    );
    finish(&runtime).await;
}

#[tokio::test]
async fn freed_capacity_goes_to_the_oldest_due_run_across_jobs() {
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    // Up to 03:05 the next day: `tick` is due every five minutes from 12:05, `nightly` and
    // `failSchedule` at 03:00, and `tick` again at 03:05.
    set_room(&runtime, 0);
    advance(&clock, 15 * 3600 + 4 * 60);
    runtime.on_clock_changed();
    assert!(admitted(&runtime).is_empty());
    // One slot at a time: each goes to the oldest due occurrence, whatever its job.
    let mut order = Vec::new();
    for _ in 0..200 {
        set_room(&runtime, 1);
        runtime.on_clock_changed();
        if !pending(&runtime) {
            break;
        }
    }
    order.extend(admitted(&runtime));
    assert_eq!(order.len(), 15 * 12 + 1 + 2);
    let times: Vec<&str> = order.iter().map(|(_, t)| t.as_str()).collect();
    let mut sorted = times.clone();
    sorted.sort_unstable();
    assert_eq!(
        times, sorted,
        "admission is in occurrence order across jobs"
    );
    assert!(order.contains(&run("nightly", "2026-08-30T03:00:00Z")));
    assert!(order.contains(&run("failSchedule", "2026-08-30T03:00:00Z")));
    assert_eq!(order.last().unwrap(), &run("tick", "2026-08-30T03:05:00Z"));
    finish(&runtime).await;
}

#[tokio::test]
async fn a_completion_that_frees_capacity_delivers_the_refused_run() {
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    // One slot left, taken by a Pub/Sub event: the queue is full.
    set_room(&runtime, 1);
    runtime
        .publish("jobs", &[serde_json::json!({"data": "YQ=="})])
        .unwrap();
    advance(&clock, 300);
    runtime.on_clock_changed();
    assert_eq!(
        runtime.inner.lock().unwrap().payloads.len(),
        1,
        "only the Pub/Sub event"
    );
    assert!(pending(&runtime));
    // Its completion frees the slot and re-enters the schedule sweep.
    tokio::spawn(runtime.clone().dispatch_loop());
    let delivered = |runtime: &FunctionsRuntime| {
        runtime
            .history()
            .iter()
            .any(|record| record.function == "tick" && record.outcome == "ok")
    };
    for _ in 0..300 {
        if delivered(&runtime) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(delivered(&runtime), "{:?}", runtime.history());
    assert!(!pending(&runtime));
    finish(&runtime).await;
}

/// Review M-D1: a cancelled source reservation that frees the last slot re-enters the
/// schedule sweep, as a completion does, so the refused run is delivered without a clock
/// change and await-idle settles.
#[tokio::test]
async fn a_cancelled_reservation_that_frees_capacity_delivers_the_refused_run() {
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    let commit = super::task_completion_tests::created_commit();
    // A pending source mutation's two reserved deliveries take the last two slots.
    set_room(&runtime, 2);
    let reservation = runtime.reserve_commit_events(&commit).unwrap();
    advance(&clock, 300);
    runtime.on_clock_changed();
    assert!(admitted(&runtime).is_empty());
    assert!(pending(&runtime));
    tokio::spawn(runtime.clone().dispatch_loop());
    // The source mutation is cancelled; no clock change follows.
    drop(reservation);
    runtime
        .await_idle(Duration::from_secs(5))
        .await
        .expect("the refused run is delivered and the session settles");
    assert!(runtime
        .history()
        .iter()
        .any(|record| record.function == "tick" && record.outcome == "ok"));
    assert!(!pending(&runtime));
    finish(&runtime).await;
}

/// Review S-D1: freed capacity goes strictly to the oldest due run. Here every `tick`
/// delivery is duplicated, so tick 12:05 needs two slots; with one free slot nothing is
/// admitted, and in particular not the newer single-copy `nightly` 03:00.
#[tokio::test]
async fn a_newer_run_of_another_job_never_takes_the_slot_of_an_older_refused_run() {
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    duplicate_tick(&runtime);
    set_room(&runtime, 1);
    advance(&clock, 15 * 3600 + 4 * 60);
    runtime.on_clock_changed();
    assert!(admitted(&runtime).is_empty(), "{:?}", admitted(&runtime));
    assert!(pending(&runtime));
    set_room(&runtime, 10_000);
    runtime.on_clock_changed();
    let order = admitted(&runtime);
    assert_eq!(order.len(), 2 * (15 * 12 + 1) + 2);
    let times: Vec<&str> = order.iter().map(|(_, t)| t.as_str()).collect();
    let mut sorted = times.clone();
    sorted.sort_unstable();
    assert_eq!(
        times, sorted,
        "admission is in occurrence order across jobs"
    );
    assert!(!pending(&runtime));
    finish(&runtime).await;
}

/// Duplicates every `tick` delivery once (two copies per occurrence).
fn duplicate_tick(runtime: &FunctionsRuntime) {
    let faults = Arc::new(Mutex::new(FaultState::default()));
    faults.lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "functions.deliver".to_owned(),
                nth: None,
                function: Some("tick".to_owned()),
                event_type: None,
            },
            action: FaultAction::Duplicate { count: 1 },
        }],
    });
    runtime.set_faults(faults);
}

#[derive(Clone, Debug)]
enum Step {
    /// Moves the clock forward and sweeps.
    Advance(i64),
    /// Leaves room for this many more events and sweeps at the same instant.
    Room(usize),
}

/// Independent model of the fixture's schedules: `tick` at every multiple of 300 s (twice
/// when its deliveries are duplicated), `nightly` and `failSchedule` at 03:00 UTC, each
/// strictly after START up to `end`.
fn model(end: i64, tick_copies: usize) -> Vec<(String, i64)> {
    let mut runs = Vec::new();
    for t in (START + 1)..=end {
        if t % 300 == 0 {
            for _ in 0..tick_copies {
                runs.push(("tick".to_owned(), t));
            }
        }
        if t.rem_euclid(86_400) == 10_800 {
            runs.push(("nightly".to_owned(), t));
            runs.push(("failSchedule".to_owned(), t));
        }
    }
    runs.sort();
    runs
}

fn seconds(time: &str) -> i64 {
    i64::try_from(LogicalInstant::parse_rfc3339(time).unwrap().as_nanos() / 1_000_000_000).unwrap()
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: 32,
        ..proptest::test_runner::Config::default()
    })]

    /// Model: under any interleaving of clock jumps and capacity limits, a sweep admits no
    /// more runs than there is room for, nothing while full, and in occurrence order
    /// across jobs; once room frees, every occurrence in the window runs exactly once.
    #[test]
    fn refused_schedule_runs_are_conserved_and_admitted_oldest_first(
        steps in proptest::collection::vec(
            proptest::prop_oneof![
                proptest::sample::select(vec![0i64, 60, 300, 900, 3_600, 21_600])
                    .prop_map(Step::Advance),
                (0usize..=3).prop_map(Step::Room),
            ],
            1..8,
        ),
        duplicated in proptest::bool::ANY,
    ) {
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        tokio.block_on(async {
            let (runtime, clock) = runtime(CatchUpPolicy::All).await;
            if duplicated {
                duplicate_tick(&runtime);
            }
            let mut room = 0usize;
            let mut end = START;
            for step in &steps {
                let before = admitted(&runtime).len();
                match step {
                    Step::Advance(by) => {
                        advance(&clock, *by);
                        end += by;
                    }
                    Step::Room(k) => room = *k,
                }
                set_room(&runtime, room);
                runtime.on_clock_changed();
                let after = admitted(&runtime).len();
                proptest::prop_assert!(after - before <= room, "{step:?}: {before} -> {after}");
            }
            for _ in 0..4 {
                set_room(&runtime, 10_000);
                runtime.on_clock_changed();
            }
            proptest::prop_assert!(!pending(&runtime));
            let order: Vec<(String, i64)> = admitted(&runtime)
                .into_iter()
                .map(|(function, time)| (function, seconds(&time)))
                .collect();
            proptest::prop_assert!(
                order.windows(2).all(|pair| pair[0].1 <= pair[1].1),
                "admission order {order:?}"
            );
            let mut conserved = order.clone();
            conserved.sort();
            proptest::prop_assert_eq!(conserved, model(end, if duplicated { 2 } else { 1 }));
            finish(&runtime).await;
            Ok(())
        })?;
    }
}

fn t(text: &str) -> LogicalInstant {
    LogicalInstant::parse_rfc3339(text).unwrap()
}

fn advance_to(clock: &Clock, instant: &str) {
    clock.lock().unwrap().advance_to(t(instant)).unwrap();
}

/// The outcomes the history holds for `function`, oldest first.
fn outcomes(runtime: &FunctionsRuntime, function: &str) -> Vec<String> {
    runtime
        .history()
        .iter()
        .filter(|r| r.function == function)
        .map(|r| r.outcome.clone())
        .collect()
}

fn times_of(admitted: &[(String, String)], function: &str) -> Vec<String> {
    admitted
        .iter()
        .filter(|(f, _)| f == function)
        .map(|(_, time)| time.clone())
        .collect()
}

// ----- catch-up: what a clock jump produces ---------------------------------------------

#[tokio::test]
async fn latest_keeps_the_newest_due_occurrence_and_records_what_it_dropped() {
    let (runtime, clock) = runtime(CatchUpPolicy::Latest).await;
    assert_eq!(runtime.catch_up_steps(), 0);
    advance(&clock, 15 * 60);
    runtime.on_clock_changed();
    assert!(runtime.catch_up_steps() > 0);
    assert_eq!(
        admitted(&runtime),
        vec![run("tick", "2026-08-29T12:15:00Z")],
        "the run it keeps is the most recent of the three due ones"
    );
    assert_eq!(
        outcomes(&runtime, "tick"),
        vec!["skipped: catch-up latest (2 runs)".to_owned()]
    );
    finish(&runtime).await;
}

#[tokio::test]
async fn none_records_one_summary_and_a_repeated_notification_adds_none() {
    let (runtime, clock) = runtime(CatchUpPolicy::None).await;
    advance(&clock, 15 * 60);
    runtime.on_clock_changed();
    runtime.on_clock_changed();
    assert!(admitted(&runtime).is_empty());
    assert_eq!(
        outcomes(&runtime, "tick"),
        vec!["skipped: catch-up none (3 runs)".to_owned()],
        "a second notification at the same instant drops nothing more"
    );
    finish(&runtime).await;
}

#[tokio::test]
async fn all_after_a_long_jump_admits_at_most_the_cap_per_job_and_keeps_the_rest_due() {
    use super::OverlapPolicy;
    let (runtime, clock) = runtime_with(CatchUpPolicy::All, OverlapPolicy::Allow, 5, START).await;
    // Ten years: more than a million occurrences of `tick`.
    advance(&clock, 3_652 * 86_400);
    runtime.on_clock_changed();
    let admitted = admitted(&runtime);
    assert_eq!(
        times_of(&admitted, "tick"),
        vec![
            "2026-08-29T12:05:00Z",
            "2026-08-29T12:10:00Z",
            "2026-08-29T12:15:00Z",
            "2026-08-29T12:20:00Z",
            "2026-08-29T12:25:00Z",
        ],
        "the cap's worth of the oldest runs, not a sample of the jump"
    );
    assert_eq!(times_of(&admitted, "nightly").len(), 5);
    assert_eq!(times_of(&admitted, "failSchedule").len(), 5);
    assert!(pending(&runtime), "the rest of the backlog stays due");
    assert!(
        outcomes(&runtime, "tick").is_empty(),
        "`all` drops nothing, so it records no summary"
    );
    finish(&runtime).await;
}

#[tokio::test]
async fn a_cap_filled_exactly_leaves_no_backlog_and_one_more_run_leaves_one() {
    use super::OverlapPolicy;
    // Cap 3, three runs of `tick` due (12:05, 12:10, 12:15): exactly the room, so nothing
    // stays due and the cursor moves on to the current time.
    let (runtime, clock) = runtime_with(CatchUpPolicy::All, OverlapPolicy::Allow, 3, START).await;
    advance(&clock, 15 * 60);
    runtime.on_clock_changed();
    assert_eq!(times_of(&admitted(&runtime), "tick").len(), 3);
    assert!(!pending(&runtime), "nothing is left over");
    finish(&runtime).await;
    // A fourth run (12:20) does not fit: it stays due.
    let (runtime, clock) = runtime_with(CatchUpPolicy::All, OverlapPolicy::Allow, 3, START).await;
    advance(&clock, 20 * 60);
    runtime.on_clock_changed();
    assert_eq!(times_of(&admitted(&runtime), "tick").len(), 3);
    assert!(pending(&runtime), "12:20 stays due");
    finish(&runtime).await;
}

#[tokio::test]
async fn latest_and_none_also_answer_a_schedule_written_as_cron_fields() {
    // `nightly` and `failSchedule` are `0 3 * * *`: three occurrences (08-30, 08-31, 09-01)
    // lie in the window, counted exactly.
    let (latest, latest_clock) = runtime(CatchUpPolicy::Latest).await;
    advance_to(&latest_clock, "2026-09-01T04:00:00Z");
    latest.on_clock_changed();
    let admitted_runs = admitted(&latest);
    assert_eq!(
        times_of(&admitted_runs, "nightly"),
        vec!["2026-09-01T03:00:00Z"]
    );
    assert_eq!(
        times_of(&admitted_runs, "failSchedule"),
        vec!["2026-09-01T03:00:00Z"]
    );
    assert_eq!(
        outcomes(&latest, "nightly"),
        vec!["skipped: catch-up latest (2 runs)".to_owned()]
    );
    finish(&latest).await;
    let (none, none_clock) = runtime(CatchUpPolicy::None).await;
    advance_to(&none_clock, "2026-09-01T04:00:00Z");
    none.on_clock_changed();
    assert!(times_of(&admitted(&none), "nightly").is_empty());
    assert_eq!(
        outcomes(&none, "nightly"),
        vec!["skipped: catch-up none (3 runs)".to_owned()]
    );
    finish(&none).await;
}

#[tokio::test]
async fn a_small_cap_applies_per_job_so_one_backlog_cannot_starve_another() {
    use super::OverlapPolicy;
    let (runtime, clock) = runtime_with(CatchUpPolicy::All, OverlapPolicy::Allow, 2, START).await;
    // 03:05 the next day: 181 runs of `tick`, one each of the 03:00 jobs.
    advance(&clock, 15 * 3600 + 4 * 60);
    runtime.on_clock_changed();
    let admitted = admitted(&runtime);
    assert_eq!(
        times_of(&admitted, "tick"),
        vec!["2026-08-29T12:05:00Z", "2026-08-29T12:10:00Z"]
    );
    assert_eq!(
        times_of(&admitted, "nightly"),
        vec!["2026-08-30T03:00:00Z"],
        "the busy job does not hold the others back"
    );
    assert_eq!(
        times_of(&admitted, "failSchedule"),
        vec!["2026-08-30T03:00:00Z"]
    );
    assert!(pending(&runtime), "the rest of the tick backlog stays due");
    finish(&runtime).await;
}

// ----- clock moves and boundaries -------------------------------------------------------

#[tokio::test]
async fn a_forward_move_to_an_instant_produces_exactly_the_occurrences_up_to_it() {
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    advance_to(&clock, "2026-08-29T12:10:00Z");
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![
            run("tick", "2026-08-29T12:05:00Z"),
            run("tick", "2026-08-29T12:10:00Z")
        ],
        "advanceTo lands on 12:10 and that occurrence is included"
    );
    clock
        .lock()
        .unwrap()
        .set(t("2026-08-29T12:15:00Z"))
        .unwrap();
    runtime.on_clock_changed();
    assert_eq!(admitted(&runtime).len(), 3, "a forward set adds 12:15");
    clock
        .lock()
        .unwrap()
        .set(t("2026-08-29T12:15:00Z"))
        .unwrap();
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime).len(),
        3,
        "a set to the same instant adds nothing"
    );
    assert!(!pending(&runtime));
    finish(&runtime).await;
}

#[tokio::test]
async fn an_occurrence_runs_at_its_instant_and_not_a_nanosecond_before() {
    for policy in [
        CatchUpPolicy::All,
        CatchUpPolicy::Latest,
        CatchUpPolicy::None,
    ] {
        let (runtime, clock) = runtime(policy).await;
        advance_to(&clock, "2026-08-29T12:04:59.999999999Z");
        runtime.on_clock_changed();
        assert!(admitted(&runtime).is_empty(), "{policy:?}: one ns early");
        assert!(
            outcomes(&runtime, "tick").is_empty(),
            "{policy:?}: nothing dropped yet"
        );

        advance_to(&clock, "2026-08-29T12:05:00Z");
        runtime.on_clock_changed();
        let expected = if policy == CatchUpPolicy::None {
            Vec::new()
        } else {
            vec![run("tick", "2026-08-29T12:05:00Z")]
        };
        assert_eq!(admitted(&runtime), expected, "{policy:?}: at the instant");
        let dropped = outcomes(&runtime, "tick");
        if policy == CatchUpPolicy::None {
            assert_eq!(dropped, vec!["skipped: catch-up none (1 run)".to_owned()]);
        } else {
            assert!(dropped.is_empty(), "{policy:?}: {dropped:?}");
        }

        advance(&clock, 0);
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_nanos(1))
            .unwrap();
        runtime.on_clock_changed();
        advance_to(&clock, "2026-08-29T12:09:59.999999999Z");
        runtime.on_clock_changed();
        assert_eq!(
            admitted(&runtime),
            expected,
            "{policy:?}: the next one is not due"
        );
        assert_eq!(
            outcomes(&runtime, "tick"),
            dropped,
            "{policy:?}: no new summary"
        );
        finish(&runtime).await;
    }
}

#[tokio::test]
async fn an_occurrence_at_the_start_instant_is_not_run() {
    // The runtime starts at 12:05:00, exactly on an occurrence of `tick`: due runs are those
    // strictly after the start, so that one never runs.
    let (runtime, clock) = runtime_with(
        CatchUpPolicy::All,
        super::OverlapPolicy::Allow,
        100_000,
        START + 240,
    )
    .await;
    advance(&clock, 1);
    runtime.on_clock_changed();
    assert!(admitted(&runtime).is_empty());
    advance(&clock, 299);
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![run("tick", "2026-08-29T12:10:00Z")]
    );
    finish(&runtime).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Check both recordings, profiles, and catch-up policies together.
async fn calendar_v6_gr02_gr03_gr08_gr12_strict_intervals_keep_the_creation_minute() {
    use super::{CodebaseSpec, FunctionsHttpProfile};
    use fireemu_core_types::determinism::Clock as _;

    // Creation userUpdateTime and scheduleTime from both calendar-v6 recordings.
    for (id, schedule, observations) in [
        (
            "gr02",
            "every 10 minutes",
            [
                ("2026-10-04T23:49:24.063517Z", "2026-10-04T23:59:00Z"),
                ("2026-10-05T00:30:36.383276Z", "2026-10-05T00:40:00Z"),
            ],
        ),
        (
            "gr03",
            "every 3 hours",
            [
                ("2026-10-04T23:49:26.299545Z", "2026-10-05T02:49:00Z"),
                ("2026-10-05T00:30:39.176827Z", "2026-10-05T03:30:00Z"),
            ],
        ),
        (
            "gr08",
            "every 25 hours",
            [
                ("2026-10-04T23:49:40.559351Z", "2026-10-06T00:49:00Z"),
                ("2026-10-05T00:30:51.271454Z", "2026-10-06T01:30:00Z"),
            ],
        ),
        (
            "gr12",
            "every 7 minutes",
            [
                ("2026-10-04T23:49:46.838794Z", "2026-10-04T23:56:00Z"),
                ("2026-10-05T00:30:57.090305Z", "2026-10-05T00:37:00Z"),
            ],
        ),
    ] {
        for (anchor, expected) in observations {
            let created = LogicalInstant::parse_rfc3339(anchor).unwrap();
            let expected = LogicalInstant::parse_rfc3339(expected).unwrap();
            let interval = expected.as_nanos()
                - created.as_nanos().div_euclid(60_000_000_000) * 60_000_000_000;
            for policy in [
                CatchUpPolicy::All,
                CatchUpPolicy::Latest,
                CatchUpPolicy::None,
            ] {
                let (base, _) = runtime(policy).await;
                let runner = base.current_runners()[0].1.clone();
                for profile in [FunctionsHttpProfile::Strict, FunctionsHttpProfile::Emulator] {
                    let manifest = parse_manifest(&json!({"functions": [{"name": id, "generation": 2,
                            "trigger": {"type": "schedule", "schedule": schedule, "timeZone": "UTC"}}]})).unwrap();
                    let parsed = manifest.scheduled().next().unwrap().1.clone();
                    let clock = Arc::new(Mutex::new(VirtualClock::new(created)));
                    let runtime = FunctionsRuntime::with_codebases(
                        vec![CodebaseSpec {
                            function: None,
                            name: "default".to_owned(),
                            manifest,
                            runner: runner.clone(),
                            spawn: None,
                            cleanup_dir: None,
                        }],
                        base.config.clone(),
                        clock.clone(),
                        profile,
                    )
                    .unwrap();
                    let first = match profile {
                        FunctionsHttpProfile::Strict => expected,
                        FunctionsHttpProfile::Emulator => parsed.next_after(created, 0).unwrap(),
                    };
                    for index in 0..3 {
                        let next = first
                            .checked_add(LogicalDuration::from_nanos(interval * index))
                            .unwrap();
                        let before = next.checked_add(LogicalDuration::from_nanos(-1)).unwrap();
                        let delta = before
                            .checked_duration_since(clock.lock().unwrap().now())
                            .unwrap();
                        clock.lock().unwrap().advance(delta).unwrap();
                        runtime.on_clock_changed();
                        let count = admitted(&runtime).len();
                        let summaries = outcomes(&runtime, id);
                        if policy == CatchUpPolicy::None {
                            assert_eq!(
                                summaries.len(),
                                usize::try_from(index).unwrap(),
                                "{id}: {profile:?}: one ns early"
                            );
                        }
                        clock
                            .lock()
                            .unwrap()
                            .advance(LogicalDuration::from_nanos(1))
                            .unwrap();
                        runtime.on_clock_changed();
                        if policy == CatchUpPolicy::None {
                            assert!(admitted(&runtime).is_empty(), "{id}: {profile:?}");
                            let mut expected = summaries;
                            expected.push("skipped: catch-up none (1 run)".to_owned());
                            assert_eq!(
                                outcomes(&runtime, id),
                                expected,
                                "{id}: {profile:?}: at the instant"
                            );
                            runtime.on_clock_changed();
                            assert_eq!(
                                outcomes(&runtime, id),
                                expected,
                                "{id}: {profile:?}: repeated notification"
                            );
                        } else {
                            let runs = admitted(&runtime);
                            assert_eq!(runs.len(), count + 1, "{id}: {profile:?}: {policy:?}");
                            assert_eq!(
                                runs.last(),
                                Some(&run(id, &next.to_rfc3339().unwrap())),
                                "{id}: {profile:?}: {policy:?}"
                            );
                        }
                    }
                }
                finish(&base).await;
            }
        }
    }
}

#[tokio::test]
async fn strict_interval_backlog_over_the_cap_keeps_phase_aligned_runs_due() {
    use super::{CodebaseSpec, FunctionsHttpProfile, OverlapPolicy};

    let (base, clock) = runtime_with(CatchUpPolicy::All, OverlapPolicy::Allow, 2, START).await;
    let manifest = parse_manifest(&json!({"functions": [{"name": "tick", "generation": 2,
            "trigger": {"type": "schedule", "schedule": "every 5 minutes", "timeZone": "UTC"}}]}))
    .unwrap();
    let runtime = FunctionsRuntime::with_codebases(
        vec![CodebaseSpec {
            function: None,
            name: "default".to_owned(),
            manifest,
            runner: base.current_runners()[0].1.clone(),
            spawn: None,
            cleanup_dir: None,
        }],
        base.config.clone(),
        clock.clone(),
        FunctionsHttpProfile::Strict,
    )
    .unwrap();
    advance(&clock, 25 * 60);
    for (first, last) in [
        ("2026-08-29T12:06:00Z", "2026-08-29T12:11:00Z"),
        ("2026-08-29T12:16:00Z", "2026-08-29T12:21:00Z"),
    ] {
        runtime.on_clock_changed();
        assert_eq!(
            admitted(&runtime),
            vec![run("tick", first), run("tick", last)]
        );
        assert_eq!(runtime.inner.lock().unwrap().jobs[0].cursor, t(last));
        assert!(pending(&runtime));
        runtime.on_clock_changed();
        assert_eq!(
            admitted(&runtime),
            vec![run("tick", first), run("tick", last)],
            "a full chunk holds the backlog"
        );
        runtime.inner.lock().unwrap().payloads.clear();
    }
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![run("tick", "2026-08-29T12:26:00Z")]
    );
    assert!(!pending(&runtime));
    assert!(outcomes(&runtime, "tick").is_empty(), "all drops no runs");
    finish(&base).await;
}

// ----- a rewind ---------------------------------------------------------------------------

#[tokio::test]
async fn a_rewind_replays_nothing_until_the_clock_passes_the_old_cursor() {
    for policy in [CatchUpPolicy::All, CatchUpPolicy::None] {
        let (runtime, clock) = runtime(policy).await;
        advance(&clock, 10 * 60);
        runtime.on_clock_changed();
        let first = admitted(&runtime);
        let summaries = outcomes(&runtime, "tick");

        clock
            .lock()
            .unwrap()
            .set_allow_backwards(t("2026-08-29T12:01:00Z"));
        runtime.on_clock_changed();
        advance_to(&clock, "2026-08-29T12:11:00Z");
        runtime.on_clock_changed();
        assert_eq!(
            admitted(&runtime),
            first,
            "{policy:?}: 12:05 and 12:10 are not replayed"
        );
        assert_eq!(
            outcomes(&runtime, "tick"),
            summaries,
            "{policy:?}: no new summary"
        );

        advance_to(&clock, "2026-08-29T12:15:00Z");
        runtime.on_clock_changed();
        let expected = if policy == CatchUpPolicy::All {
            vec![
                run("tick", "2026-08-29T12:05:00Z"),
                run("tick", "2026-08-29T12:10:00Z"),
                run("tick", "2026-08-29T12:15:00Z"),
            ]
        } else {
            Vec::new()
        };
        assert_eq!(
            admitted(&runtime),
            expected,
            "{policy:?}: the schedule resumes at 12:15"
        );
        finish(&runtime).await;
    }
}

#[tokio::test]
async fn a_reset_after_a_rewind_restarts_the_schedule_from_the_rewound_time() {
    // The one path on which a rewound clock replays occurrences: a session reset sets
    // every cursor to the current virtual time.
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    advance(&clock, 10 * 60);
    runtime.on_clock_changed();
    clock
        .lock()
        .unwrap()
        .set_allow_backwards(t("2026-08-29T12:01:00Z"));
    runtime.reset();
    assert!(
        admitted(&runtime).is_empty(),
        "the reset dropped the queued runs"
    );
    advance_to(&clock, "2026-08-29T12:11:00Z");
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![
            run("tick", "2026-08-29T12:05:00Z"),
            run("tick", "2026-08-29T12:10:00Z")
        ]
    );
    finish(&runtime).await;
}

// ----- manual runs ------------------------------------------------------------------------

#[tokio::test]
async fn a_manual_run_carries_the_current_virtual_time_and_the_job_name() {
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    advance(&clock, 7 * 60);
    runtime.run_schedule("tick").unwrap();
    let region = runtime.manifest.get("tick").unwrap().region.clone();
    {
        let inner = runtime.inner.lock().unwrap();
        let queued = inner.payloads.values().next().unwrap();
        assert!(matches!(queued.source, super::EventSource::Manual));
        assert_eq!(queued.payload["time"], "2026-08-29T12:08:00Z");
        assert_eq!(
            queued.payload["data"]["scheduleTime"],
            "2026-08-29T12:08:00Z"
        );
        assert_eq!(
            queued.payload["data"]["jobName"],
            format!("projects/demo-app/locations/{region}/jobs/firebase-schedule-tick-{region}")
        );
    }
    // At an occurrence's own instant a manual run and the scheduler's are the same event.
    advance(&clock, 2 * 60);
    runtime.on_clock_changed();
    runtime.run_schedule("tick").unwrap();
    let shapes = |manual: bool| {
        let inner = runtime.inner.lock().unwrap();
        let mut found: Vec<serde_json::Value> = inner
            .payloads
            .values()
            .filter(|q| q.payload["time"] == "2026-08-29T12:10:00Z")
            .filter(|q| matches!(q.source, super::EventSource::Manual) == manual)
            .map(|q| {
                let mut payload = (*q.payload).clone();
                payload.as_object_mut().unwrap().remove("id");
                payload
            })
            .collect();
        assert_eq!(found.len(), 1, "manual={manual}");
        found.remove(0)
    };
    assert_eq!(
        shapes(true),
        shapes(false),
        "same type, source, time and data"
    );
    finish(&runtime).await;
}

#[tokio::test]
async fn a_manual_run_leaves_the_next_natural_occurrence_alone() {
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    advance(&clock, 2 * 60);
    runtime.run_schedule("tick").unwrap();
    advance(&clock, 2 * 60);
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![
            run("tick", "2026-08-29T12:03:00Z"),
            run("tick", "2026-08-29T12:05:00Z")
        ],
        "the manual run at 12:03 did not consume the 12:05 occurrence"
    );
    assert!(!pending(&runtime));
    finish(&runtime).await;
}

// ----- overlap on the clock-driven path -------------------------------------------------

#[tokio::test]
async fn skip_drops_a_run_that_overlaps_a_queued_one_for_good() {
    use super::OverlapPolicy;
    let (runtime, clock) =
        runtime_with(CatchUpPolicy::All, OverlapPolicy::Skip, 100_000, START).await;
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![run("tick", "2026-08-29T12:05:00Z")]
    );
    assert_eq!(
        outcomes(&runtime, "tick"),
        vec!["skipped: overlap".to_owned()]
    );
    assert!(!pending(&runtime), "a skipped run is dropped, not kept due");
    // Once the queued run is gone the next occurrence runs: the schedule kept moving.
    runtime.inner.lock().unwrap().payloads.clear();
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![run("tick", "2026-08-29T12:15:00Z")]
    );
    finish(&runtime).await;
}

/// Marks `function` as executing a handler, as the dispatch loop does while an invocation runs.
fn start_running(runtime: &FunctionsRuntime, key: &str, function: &str) {
    runtime
        .inner
        .lock()
        .unwrap()
        .running
        .insert(key.to_owned(), function.to_owned());
}

fn stop_running(runtime: &FunctionsRuntime, key: &str) {
    runtime.inner.lock().unwrap().running.remove(key);
}

/// Recorded (run `156715222b86ea44`): the `every 1 minutes` job whose handler ran 100 s started its occurrences
/// 2 to 3 minutes apart, none while one was in flight. The occurrences that fall inside a running handler are
/// dropped, and the schedule keeps moving.
#[tokio::test]
async fn skip_in_flight_drops_an_occurrence_while_a_handler_is_running() {
    use super::OverlapPolicy;
    let (runtime, clock) = runtime_with(
        CatchUpPolicy::All,
        OverlapPolicy::SkipInFlight,
        100_000,
        START,
    )
    .await;
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![run("tick", "2026-08-29T12:05:00Z")]
    );
    // That run starts (leaves the queue, executes), and the next occurrence falls inside it.
    runtime.inner.lock().unwrap().payloads.clear();
    start_running(&runtime, "k1", "tick");
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    assert!(
        admitted(&runtime).is_empty(),
        "nothing runs inside a running handler"
    );
    assert_eq!(
        outcomes(&runtime, "tick"),
        vec!["skipped: in flight".to_owned()]
    );
    assert!(
        !pending(&runtime),
        "a skipped occurrence is dropped, not kept due"
    );
    // Once the handler is done the next occurrence runs: the schedule kept moving.
    stop_running(&runtime, "k1");
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![run("tick", "2026-08-29T12:15:00Z")]
    );
    finish(&runtime).await;
}

/// An occurrence another function's handler overlaps is not skipped: in flight is per function.
#[tokio::test]
async fn skip_in_flight_looks_only_at_the_same_function() {
    use super::OverlapPolicy;
    let (runtime, clock) = runtime_with(
        CatchUpPolicy::All,
        OverlapPolicy::SkipInFlight,
        100_000,
        START,
    )
    .await;
    start_running(&runtime, "k1", "somethingElse");
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    assert_eq!(
        times_of(&admitted(&runtime), "tick"),
        vec!["2026-08-29T12:05:00Z".to_owned()]
    );
    finish(&runtime).await;
}

/// A run that is queued or waiting to be retried is not an executing handler: production's skip is recorded
/// only against a running one, so the next occurrence runs.
#[tokio::test]
async fn skip_in_flight_does_not_count_a_queued_run() {
    use super::OverlapPolicy;
    let (runtime, clock) = runtime_with(
        CatchUpPolicy::All,
        OverlapPolicy::SkipInFlight,
        100_000,
        START,
    )
    .await;
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![
            run("tick", "2026-08-29T12:05:00Z"),
            run("tick", "2026-08-29T12:10:00Z")
        ]
    );
    assert!(outcomes(&runtime, "tick").is_empty());
    finish(&runtime).await;
}

/// Occurrences of one clock move are not in flight against each other: with `catchUp: all` a jump over several
/// of them runs each, as production would have run each when it came (the handler being quick).
#[tokio::test]
async fn skip_in_flight_keeps_every_occurrence_of_one_clock_move() {
    use super::OverlapPolicy;
    let (runtime, clock) = runtime_with(
        CatchUpPolicy::All,
        OverlapPolicy::SkipInFlight,
        100_000,
        START,
    )
    .await;
    advance(&clock, 15 * 60);
    runtime.on_clock_changed();
    assert_eq!(
        times_of(&admitted(&runtime), "tick"),
        vec![
            "2026-08-29T12:05:00Z".to_owned(),
            "2026-08-29T12:10:00Z".to_owned(),
            "2026-08-29T12:15:00Z".to_owned()
        ]
    );
    assert!(outcomes(&runtime, "tick").is_empty());
    finish(&runtime).await;
}

/// A manual run is fireemu's own control, not an occurrence: production's forced run started while a natural run
/// was in flight (run `156715222b86ea44`, frame 535404 inside the run begun at 482655), so it is not refused.
#[tokio::test]
async fn skip_in_flight_never_refuses_a_manual_run() {
    use super::OverlapPolicy;
    let (runtime, _clock) = runtime_with(
        CatchUpPolicy::All,
        OverlapPolicy::SkipInFlight,
        100_000,
        START,
    )
    .await;
    start_running(&runtime, "k1", "tick");
    assert_eq!(runtime.run_schedule("tick"), Ok(()));
    assert_eq!(admitted(&runtime).len(), 1);
    assert_eq!(runtime.status()["overlapRejected"], 0);
    finish(&runtime).await;
}

#[test]
fn the_overlap_policies_parse_by_name() {
    use super::OverlapPolicy;
    for (text, policy) in [
        ("allow", OverlapPolicy::Allow),
        ("skip", OverlapPolicy::Skip),
        ("queue", OverlapPolicy::Queue),
        ("reject", OverlapPolicy::Reject),
        ("skip-in-flight", OverlapPolicy::SkipInFlight),
    ] {
        assert_eq!(OverlapPolicy::parse(text), Some(policy), "{text}");
    }
    for bad in ["", "Skip", "skip_in_flight", "skipInFlight", "in-flight"] {
        assert_eq!(OverlapPolicy::parse(bad), None, "{bad:?}");
    }
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: 32,
        ..proptest::test_runner::Config::default()
    })]

    /// Model: under any sequence of clock moves, each with a handler running or not, a move over the occurrences
    /// of `tick` (every five minutes) runs all of them when no handler was running and none when one was, and
    /// every dropped occurrence is recorded exactly once.
    #[test]
    fn skip_in_flight_matches_a_reference_of_the_running_handler(
        steps in proptest::collection::vec((1i64..=20, proptest::bool::ANY), 1..10),
    ) {
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        tokio.block_on(async {
            let (runtime, clock) = runtime_with(
                CatchUpPolicy::All,
                super::OverlapPolicy::SkipInFlight,
                100_000,
                START,
            )
            .await;
            let mut now = START;
            let mut expected_runs = Vec::new();
            let mut expected_skips = 0usize;
            for (minutes, running) in &steps {
                let next = now + minutes * 60;
                // the occurrences in (now, next]: multiples of 300 s
                let due: Vec<i64> = (now / 300 + 1..=next / 300).map(|n| n * 300).collect();
                if *running {
                    start_running(&runtime, "k", "tick");
                    expected_skips += due.len();
                } else {
                    stop_running(&runtime, "k");
                    expected_runs.extend(due);
                }
                advance(&clock, minutes * 60);
                runtime.on_clock_changed();
                now = next;
            }
            let admitted_times: Vec<i64> = times_of(&admitted(&runtime), "tick")
                .iter()
                .map(|time| seconds(time))
                .collect();
            proptest::prop_assert_eq!(admitted_times, expected_runs);
            proptest::prop_assert_eq!(
                outcomes(&runtime, "tick").iter().filter(|o| *o == "skipped: in flight").count(),
                expected_skips
            );
            finish(&runtime).await;
            Ok(())
        })?;
    }
}

#[tokio::test]
async fn a_clock_move_that_waits_for_the_lock_while_shutdown_begins_enqueues_nothing() {
    use super::OverlapPolicy;
    let (runtime, clock) =
        runtime_with(CatchUpPolicy::All, OverlapPolicy::Allow, 100_000, START).await;
    advance(&clock, 5 * 60);
    // The clock hook starts while the lock is held, so it is past any check made before the
    // lock when shutdown begins, which sets the flag under the same lock.
    let guard = runtime.inner.lock().unwrap();
    let hook = {
        let runtime = Arc::clone(&runtime);
        std::thread::spawn(move || runtime.on_clock_changed())
    };
    std::thread::sleep(Duration::from_millis(300));
    runtime
        .shutting_down
        .store(true, std::sync::atomic::Ordering::SeqCst);
    drop(guard);
    hook.join().unwrap();
    assert!(
        admitted(&runtime).is_empty(),
        "a run enqueued after shutdown began would never be delivered"
    );
    finish(&runtime).await;
}

#[tokio::test]
async fn reject_counts_an_overlapping_scheduler_run_as_a_dead_letter() {
    use super::OverlapPolicy;
    let (runtime, clock) =
        runtime_with(CatchUpPolicy::All, OverlapPolicy::Reject, 100_000, START).await;
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![run("tick", "2026-08-29T12:05:00Z")]
    );
    assert_eq!(runtime.status()["overlapRejected"], 1);
    assert!(runtime
        .dead_letters()
        .iter()
        .any(|r| r.function == "tick" && r.outcome == "rejected: overlap"));
    finish(&runtime).await;
}

#[tokio::test]
async fn allow_and_queue_admit_overlapping_scheduler_runs() {
    use super::OverlapPolicy;
    for overlap in [OverlapPolicy::Allow, OverlapPolicy::Queue] {
        let (runtime, clock) = runtime_with(CatchUpPolicy::All, overlap, 100_000, START).await;
        advance(&clock, 5 * 60);
        runtime.on_clock_changed();
        advance(&clock, 5 * 60);
        runtime.on_clock_changed();
        assert_eq!(
            admitted(&runtime),
            vec![
                run("tick", "2026-08-29T12:05:00Z"),
                run("tick", "2026-08-29T12:10:00Z")
            ],
            "{overlap:?}"
        );
        assert!(outcomes(&runtime, "tick").is_empty(), "{overlap:?}");
        assert_eq!(runtime.status()["overlapRejected"], 0, "{overlap:?}");
        finish(&runtime).await;
    }
}

/// Records what a first-generation schedule publishes: (topic, message id, publish time).
#[derive(Default)]
struct Recorder(Mutex<Vec<(String, String, LogicalInstant)>>);

impl super::ScheduleTopicPublisher for Recorder {
    fn publish(&self, topic: &str, message_id: &str, at: LogicalInstant) -> Result<(), String> {
        self.0
            .lock()
            .unwrap()
            .push((topic.to_owned(), message_id.to_owned(), at));
        Ok(())
    }
}

fn recorded(recorder: &Recorder) -> Vec<(String, String, LogicalInstant)> {
    recorder.0.lock().unwrap().clone()
}

#[tokio::test]
async fn concurrent_virtual_schedule_sweeps_preserve_the_catch_up_cap_and_order() {
    struct BlockedPublisher {
        entered: std::sync::mpsc::Sender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
        first: std::sync::atomic::AtomicBool,
        recorder: Recorder,
    }
    impl super::ScheduleTopicPublisher for BlockedPublisher {
        fn publish(&self, topic: &str, id: &str, at: LogicalInstant) -> Result<(), String> {
            if self.first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                self.entered.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap();
            }
            self.recorder.publish(topic, id, at)
        }
    }
    let spec = SpawnSpec {
        command: vec![
            "python3".into(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py").into(),
        ],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(60),
    };
    let runner = Arc::new(Runner::spawn_spec(&spec).await.unwrap());
    let manifest = parse_manifest(&json!({"functions": [
            {"name": "tick", "generation": 1, "trigger": {"type": "schedule", "schedule": "every 1 minutes"}}
        ]})).unwrap();
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(START),
    )));
    let runtime = FunctionsRuntime::with_codebases(
        vec![super::CodebaseSpec {
            function: None,
            name: "default".into(),
            manifest,
            runner,
            spawn: Some(spec),
            cleanup_dir: None,
        }],
        FunctionsConfig {
            clock_policy: crate::application_clock::ApplicationClockPolicy {
                date_virtual: true,
                ..Default::default()
            },
            ..FunctionsConfig::for_tests(5, "s".into())
        },
        clock.clone(),
        crate::http::FunctionsHttpProfile::Strict,
    )
    .unwrap();
    let (entered, waiting) = std::sync::mpsc::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let publisher = Arc::new(BlockedPublisher {
        entered,
        release: Mutex::new(blocked),
        first: std::sync::atomic::AtomicBool::new(true),
        recorder: Recorder::default(),
    });
    runtime.set_schedule_topic_publisher(publisher.clone());
    advance(&clock, 600);
    let producing = runtime.clone();
    let first = std::thread::spawn(move || producing.on_clock_changed());
    waiting.recv_timeout(Duration::from_secs(10)).unwrap();
    let producing = runtime.clone();
    let (finished, done) = std::sync::mpsc::channel();
    let second = std::thread::spawn(move || {
        producing.on_clock_changed();
        finished.send(()).unwrap();
    });
    let overlapped = done.recv_timeout(Duration::from_millis(500)).is_ok();
    release.send(()).unwrap();
    first.join().unwrap();
    second.join().unwrap();
    let times: Vec<_> = recorded(&publisher.recorder)
        .iter()
        .map(|row| row.2)
        .collect();
    let expected: Vec<_> = (1..=5)
        .map(|minute| LogicalInstant::from_unix_seconds(START + minute * 60))
        .collect();
    let queued = admitted(&runtime);
    finish(&runtime).await;
    assert!(
        overlapped,
        "the second trigger must return while the first publication batch runs"
    );
    assert_eq!(
        times, expected,
        "exactly five ordered occurrences, without duplicates"
    );
    assert_eq!(queued.len(), 5);
}

#[tokio::test]
async fn a_trigger_during_publication_reruns_the_sweep_and_delivers_new_occurrences_once() {
    struct BlockedPublisher {
        entered: std::sync::mpsc::Sender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
        first: std::sync::atomic::AtomicBool,
        recorder: Recorder,
    }
    impl super::ScheduleTopicPublisher for BlockedPublisher {
        fn publish(&self, topic: &str, id: &str, at: LogicalInstant) -> Result<(), String> {
            if self.first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                self.entered.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap();
            }
            self.recorder.publish(topic, id, at)
        }
    }
    let spec = SpawnSpec {
        command: vec![
            "python3".into(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py").into(),
        ],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(60),
    };
    let runner = Arc::new(Runner::spawn_spec(&spec).await.unwrap());
    let manifest = parse_manifest(&json!({"functions": [
            {"name": "tick", "generation": 1, "trigger": {"type": "schedule", "schedule": "every 1 minutes"}}
        ]})).unwrap();
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(START),
    )));
    let runtime = FunctionsRuntime::with_codebases(
        vec![super::CodebaseSpec {
            function: None,
            name: "default".into(),
            manifest,
            runner,
            spawn: Some(spec),
            cleanup_dir: None,
        }],
        FunctionsConfig {
            clock_policy: crate::application_clock::ApplicationClockPolicy {
                date_virtual: true,
                ..Default::default()
            },
            ..FunctionsConfig::for_tests(20, "s".into())
        },
        clock.clone(),
        crate::http::FunctionsHttpProfile::Strict,
    )
    .unwrap();
    let (entered, waiting) = std::sync::mpsc::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let publisher = Arc::new(BlockedPublisher {
        entered,
        release: Mutex::new(blocked),
        first: std::sync::atomic::AtomicBool::new(true),
        recorder: Recorder::default(),
    });
    runtime.set_schedule_topic_publisher(publisher.clone());
    advance(&clock, 60);
    let producing = runtime.clone();
    let first = std::thread::spawn(move || producing.on_clock_changed());
    waiting.recv_timeout(Duration::from_secs(10)).unwrap();
    advance(&clock, 60);
    let producing = runtime.clone();
    let (finished, done) = std::sync::mpsc::channel();
    let second = std::thread::spawn(move || {
        producing.on_clock_changed();
        finished.send(()).unwrap();
    });
    let overlapped = done.recv_timeout(Duration::from_millis(500)).is_ok();
    release.send(()).unwrap();
    first.join().unwrap();
    second.join().unwrap();
    let times: Vec<_> = recorded(&publisher.recorder)
        .iter()
        .map(|row| row.2)
        .collect();
    let expected: Vec<_> = (1..=2)
        .map(|minute| LogicalInstant::from_unix_seconds(START + minute * 60))
        .collect();
    let queued = admitted(&runtime);
    finish(&runtime).await;
    assert!(
        overlapped,
        "a trigger must return while publication is blocked"
    );
    assert_eq!(
        times, expected,
        "both clock windows are delivered once in order"
    );
    assert_eq!(queued.len(), 2);
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config { cases: 16, failure_persistence: None, ..Default::default() })]
    #[test]
    fn concurrent_virtual_schedule_sweeps_never_duplicate_or_reorder_occurrences(
        advances in proptest::collection::vec(0i64..=900, 1..12),
    ) {
        let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        tokio.block_on(async {
            let spec = SpawnSpec {
                command: vec!["python3".into(), concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py").into()],
                cwd: None, env: Vec::new(), hello_timeout: Duration::from_secs(60),
            };
            let runner = Arc::new(Runner::spawn_spec(&spec).await.unwrap());
            let manifest = parse_manifest(&json!({"functions": [
                {"name": "tick", "generation": 1, "trigger": {"type": "schedule", "schedule": "every 1 minutes"}}
            ]})).unwrap();
            let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::from_unix_seconds(START))));
            let runtime = FunctionsRuntime::with_codebases(
                vec![super::CodebaseSpec { function: None, name: "default".into(), manifest, runner, spawn: Some(spec), cleanup_dir: None }],
                FunctionsConfig {
                    clock_policy: crate::application_clock::ApplicationClockPolicy { date_virtual: true, ..Default::default() },
                    ..FunctionsConfig::for_tests(5, "s".into())
                }, clock.clone(), crate::http::FunctionsHttpProfile::Strict,
            ).unwrap();
            let publisher = Arc::new(Recorder::default());
            runtime.set_schedule_topic_publisher(publisher.clone());
            let mut end = START;
            for seconds in advances {
                advance(&clock, seconds);
                end += seconds;
                loop {
                    std::thread::scope(|scope| {
                        scope.spawn(|| runtime.on_clock_changed());
                        scope.spawn(|| runtime.on_clock_changed());
                    });
                    let more = pending(&runtime);
                    runtime.inner.lock().unwrap().payloads.clear();
                    if !more { break; }
                }
            }
            let actual: Vec<_> = recorded(&publisher).iter().map(|row| row.2.as_nanos()).collect();
            let expected: Vec<_> = (START / 60 + 1..=end / 60).map(|minute| LogicalInstant::from_unix_seconds(minute * 60).as_nanos()).collect();
            finish(&runtime).await;
            proptest::prop_assert!(actual.windows(2).all(|pair| pair[0] < pair[1]), "no duplicate or out-of-order occurrence");
            proptest::prop_assert_eq!(actual, expected);
            Ok(())
        })?;
    }
}

/// The `data.messageId` of each queued schedule run, in admission order.
fn queued_message_ids(runtime: &FunctionsRuntime) -> Vec<Option<String>> {
    let inner = runtime.inner.lock().unwrap();
    inner
        .payloads
        .values()
        .map(|queued| {
            queued.payload["data"]["messageId"]
                .as_str()
                .map(str::to_owned)
        })
        .collect()
}

fn is_message_id(id: &str) -> bool {
    id.len() == 17 && id.starts_with('2') && id.bytes().all(|b| b.is_ascii_digit())
}

#[tokio::test]
async fn refused_publications_drain_all_catch_up_chunks_without_recursing() {
    struct DeletedTopic(std::sync::atomic::AtomicUsize);
    impl super::ScheduleTopicPublisher for DeletedTopic {
        fn publish(&self, _: &str, _: &str, _: LogicalInstant) -> Result<(), String> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err("topic not found: deleted topic".to_owned())
        }
    }
    let (runtime, clock) =
        runtime_with(CatchUpPolicy::All, super::OverlapPolicy::Allow, 1, START).await;
    runtime
        .inner
        .lock()
        .unwrap()
        .jobs
        .retain(|job| job.function == "tick");
    let publisher = Arc::new(DeletedTopic(std::sync::atomic::AtomicUsize::new(0)));
    runtime.set_schedule_topic_publisher(publisher.clone());
    let occurrences = 4096;
    advance(&clock, occurrences * 300);
    let producing = runtime.clone();
    std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(move || producing.on_clock_changed())
        .unwrap()
        .join()
        .unwrap();
    let dispatcher = tokio::spawn(runtime.clone().dispatch_loop());
    let settled = runtime.await_idle(Duration::from_secs(10)).await;
    runtime.shutdown().await;
    dispatcher.await.unwrap();
    settled.expect("every refused occurrence finishes without another clock change");
    assert_eq!(
        publisher.0.load(std::sync::atomic::Ordering::SeqCst),
        usize::try_from(occurrences).unwrap()
    );
    assert_eq!(runtime.status()["deadLettered"], occurrences);
    assert!(queued_message_ids(&runtime).is_empty());
    assert!(runtime
        .history()
        .iter()
        .all(|record| record.outcome == "failed: topic not found: deleted topic"));
    assert!(runtime
        .dead_letters()
        .iter()
        .all(|record| record.outcome == "failed: topic not found: deleted topic"));
}

#[tokio::test]
async fn a_manual_run_observes_overlap_while_publication_is_blocked() {
    struct BlockedPublisher {
        entered: std::sync::mpsc::Sender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
        first: std::sync::atomic::AtomicBool,
        recorder: Recorder,
    }
    impl super::ScheduleTopicPublisher for BlockedPublisher {
        fn publish(&self, topic: &str, id: &str, at: LogicalInstant) -> Result<(), String> {
            if self.first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                self.entered.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap();
            }
            self.recorder.publish(topic, id, at)
        }
    }
    for overlap in [super::OverlapPolicy::Skip, super::OverlapPolicy::Reject] {
        for manual in [false, true] {
            let (runtime, clock) = runtime_with(CatchUpPolicy::All, overlap, 1, START).await;
            let (entered, waiting) = std::sync::mpsc::channel();
            let (release, blocked) = std::sync::mpsc::channel();
            let publisher = Arc::new(BlockedPublisher {
                entered,
                release: Mutex::new(blocked),
                first: std::sync::atomic::AtomicBool::new(true),
                recorder: Recorder::default(),
            });
            runtime.set_schedule_topic_publisher(publisher.clone());
            advance(&clock, 300);
            let producing = runtime.clone();
            let publication = std::thread::spawn(move || {
                if manual {
                    producing.run_schedule("tick").unwrap();
                } else {
                    producing.on_clock_changed();
                }
            });
            waiting.recv_timeout(Duration::from_secs(10)).unwrap();
            let second = runtime.run_schedule("tick");
            release.send(()).unwrap();
            publication.join().unwrap();
            let publications = recorded(&publisher.recorder).len();
            let rejected = runtime.status()["overlapRejected"].clone();
            finish(&runtime).await;
            assert!(
                matches!(second, Err(super::ScheduleRunError::Refused(_))),
                "{overlap:?}, manual={manual}: {second:?}"
            );
            assert_eq!(publications, 1);
            assert_eq!(rejected, u64::from(overlap == super::OverlapPolicy::Reject));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_schedule_cannot_dispatch_while_its_publication_is_blocked() {
    struct BlockedPublisher {
        entered: std::sync::mpsc::Sender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
        recorder: Recorder,
    }
    impl super::ScheduleTopicPublisher for BlockedPublisher {
        fn publish(&self, topic: &str, id: &str, at: LogicalInstant) -> Result<(), String> {
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
            self.recorder.publish(topic, id, at)
        }
    }
    for manual in [false, true] {
        let (runtime, clock) = runtime(CatchUpPolicy::All).await;
        let (entered, waiting) = std::sync::mpsc::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let publisher = Arc::new(BlockedPublisher {
            entered,
            release: Mutex::new(blocked),
            recorder: Recorder::default(),
        });
        runtime.set_schedule_topic_publisher(publisher.clone());
        advance(&clock, 300);
        let producing = runtime.clone();
        let publication = std::thread::spawn(move || {
            if manual {
                producing.run_schedule("tick").unwrap();
            } else {
                producing.on_clock_changed();
            }
        });
        waiting.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(recorded(&publisher.recorder).is_empty());
        runtime.dispatch_ready();
        let dispatchable = runtime.inner.lock().unwrap().outbox.dispatchable().count();
        let running = runtime.inner.lock().unwrap().running.len();
        let queued_before_publication = queued_message_ids(&runtime);
        let idle_before_publication = runtime.is_idle();
        release.send(()).unwrap();
        publication.join().unwrap();
        assert!(queued_before_publication.is_empty());
        assert!(!idle_before_publication);
        assert_eq!(dispatchable, 0);
        assert_eq!(
            running, 0,
            "an independently awakened dispatcher must wait for publication"
        );
        assert_eq!(
            queued_message_ids(&runtime),
            vec![Some(recorded(&publisher.recorder)[0].1.clone())]
        );
        finish(&runtime).await;
    }
}

/// Cloud Scheduler publishes a message to the job's topic for every occurrence of a first-generation schedule (runs
/// `156715222b86ea44` and `f123d4fa2d61c5f5`): the message has the id the handler's context reports and the time of
/// the occurrence, and each occurrence has its own id.
#[tokio::test]
async fn a_first_generation_schedule_publishes_its_message_at_each_occurrence() {
    let (runtime, clock) = runtime_with(
        CatchUpPolicy::All,
        super::OverlapPolicy::Allow,
        100_000,
        START,
    )
    .await;
    let recorder = Arc::new(Recorder::default());
    runtime.set_schedule_topic_publisher(recorder.clone());
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    let published = recorded(&recorder);
    assert_eq!(published.len(), 2);
    for (topic, id, _) in &published {
        assert_eq!(topic, "firebase-schedule-tick-us-central1");
        assert!(is_message_id(id), "{id}");
    }
    assert_ne!(published[0].1, published[1].1);
    assert_eq!(
        published[0].2,
        LogicalInstant::from_unix_seconds(1_788_004_860 + 300 - (1_788_004_860 % 300))
    );
    assert_eq!(
        published[1].2.as_nanos() - published[0].2.as_nanos(),
        300_000_000_000
    );
    // the queued event carries the same id, so the handler's context and the message agree
    assert_eq!(
        queued_message_ids(&runtime),
        published
            .iter()
            .map(|p| Some(p.1.clone()))
            .collect::<Vec<_>>()
    );
    finish(&runtime).await;
}

/// A second-generation schedule has no topic in production (its job calls the function's URL): a publisher is
/// never asked, and the event has no message id, whatever else is scheduled.
#[tokio::test]
async fn a_second_generation_schedule_publishes_nothing() {
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
    let manifest = parse_manifest(&json!({"functions": [
            {"name": "tickV2", "generation": 2, "trigger": {"type": "schedule", "schedule": "every 5 minutes"}}
        ]}))
        .unwrap();
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(START),
    )));
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            project: "demo-app".to_owned(),
            default_bucket: "demo-app.appspot.com".to_owned(),
            location: "nam5".to_owned(),
            session: SessionId::new(7),
            max_running: 4,
            debug_mode: false,
            retry_attempts: 1,
            max_catch_up_runs: 100_000,
            runner_secret: "test-secret".to_owned(),
            overlap: super::OverlapPolicy::Allow,
            catch_up: CatchUpPolicy::All,
            functions_host: Some("127.0.0.1:5001".to_owned()),
            clock_policy: crate::application_clock::ApplicationClockPolicy::default(),
            honour_task_schedule_time: false,
            task_name_reuse: crate::tasks_production::NameReuse::Retained,
            task_default_deadline_seconds: 60,
            task_retry_production_gaps: false,
            clock_start_pinned: false,
            subscription_naming: crate::events::SubscriptionNaming::default(),
            auth_context: crate::events::AuthContextNaming::default(),
            database_event_shape: crate::events::DatabaseEventShape::default(),
        },
        clock.clone(),
        Arc::new(runner),
        Some(spec),
    );
    let recorder = Arc::new(Recorder::default());
    runtime.set_schedule_topic_publisher(recorder.clone());
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    runtime.run_schedule("tickV2").unwrap();
    assert!(recorded(&recorder).is_empty());
    assert_eq!(queued_message_ids(&runtime), vec![None, None]);
    finish(&runtime).await;
}

/// Nothing changes without a publisher (the emulator profile): no message, and the event has no `messageId`.
#[tokio::test]
async fn without_a_publisher_a_schedule_publishes_nothing_and_carries_no_message_id() {
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    assert_eq!(queued_message_ids(&runtime), vec![None]);
    finish(&runtime).await;
}

/// A manual run (Cloud Scheduler's run-now) publishes too: the forced runs of the recordings did.
#[tokio::test]
async fn a_manual_run_of_a_first_generation_schedule_publishes_its_message() {
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    let recorder = Arc::new(Recorder::default());
    runtime.set_schedule_topic_publisher(recorder.clone());
    advance(&clock, 17);
    runtime.run_schedule("tick").unwrap();
    let published = recorded(&recorder);
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].0, "firebase-schedule-tick-us-central1");
    assert!(is_message_id(&published[0].1));
    assert_eq!(
        published[0].2,
        LogicalInstant::from_unix_seconds(START + 17)
    );
    assert_eq!(
        queued_message_ids(&runtime),
        vec![Some(published[0].1.clone())]
    );
    finish(&runtime).await;
}

/// An occurrence that is not admitted publishes nothing: skipped or rejected for overlap, or refused for capacity (it
/// publishes once, when it is admitted later).
#[tokio::test]
async fn an_occurrence_that_is_not_admitted_publishes_nothing_until_it_is() {
    use super::OverlapPolicy;
    let (first, first_clock) =
        runtime_with(CatchUpPolicy::All, OverlapPolicy::Skip, 100_000, START).await;
    let recorder = Arc::new(Recorder::default());
    first.set_schedule_topic_publisher(recorder.clone());
    advance(&first_clock, 5 * 60);
    first.on_clock_changed();
    advance(&first_clock, 5 * 60);
    first.on_clock_changed();
    assert_eq!(recorded(&recorder).len(), 1, "the second was skipped");
    finish(&first).await;

    let (second, second_clock) = runtime(CatchUpPolicy::All).await;
    let recorder = Arc::new(Recorder::default());
    second.set_schedule_topic_publisher(recorder.clone());
    set_room(&second, 0);
    advance(&second_clock, 5 * 60);
    second.on_clock_changed();
    assert!(recorded(&recorder).is_empty(), "refused for capacity");
    second.inner.lock().unwrap().reserved_event_records = 0;
    second.on_clock_changed();
    let published = recorded(&recorder);
    assert_eq!(published.len(), 1, "published once it was admitted");
    assert_eq!(
        published[0].2,
        LogicalInstant::from_unix_seconds(1_788_004_860 + 300 - (1_788_004_860 % 300))
    );
    finish(&second).await;
}

/// The ids are pinned, computed independently of the implementation: a 2 followed by sixteen digits of
/// (ordinal x 6364136223846793003 + session) modulo 10^16.
#[test]
fn schedule_message_ids_have_the_pinned_values() {
    for (session, ordinal, expected) in [
        (7, 1, "24136223846793010"),
        (7, 2, "28272447693586013"),
        (7, 3, "22408671540379016"),
        (0, 1, "24136223846793003"),
        (
            123_456_789_012_345_678_901_234_567_890,
            5,
            "26360020468532905",
        ),
        (7, 1_000_000_000_000, "23003000000000007"),
        // the largest session: the arithmetic must not overflow
        (u128::MAX, 1, "28743655615004458"),
    ] {
        assert_eq!(
            super::schedule_message_id(SessionId::new(session), ordinal),
            expected,
            "{session} {ordinal}"
        );
    }
}

/// The `id` of a queued schedule event is the session and the number the runtime gave the event, and the message id
/// is made from that same number: a handler's event and its message name one occurrence.
#[tokio::test]
async fn the_event_id_and_the_message_id_come_from_the_number_of_the_event() {
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    let recorder = Arc::new(Recorder::default());
    runtime.set_schedule_topic_publisher(recorder.clone());
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    runtime.run_schedule("tick").unwrap();
    let queued: Vec<(u128, String, Option<String>)> = {
        let inner = runtime.inner.lock().unwrap();
        inner
            .payloads
            .iter()
            .map(|(id, queued)| {
                (
                    id.value(),
                    queued.payload["id"].as_str().unwrap().to_owned(),
                    queued.payload["data"]["messageId"]
                        .as_str()
                        .map(str::to_owned),
                )
            })
            .collect()
    };
    assert_eq!(queued.len(), 2);
    for (number, id, message_id) in &queued {
        assert_eq!(id, &format!("7-{number}"));
        assert_eq!(
            message_id.as_deref(),
            Some(
                super::schedule_message_id(SessionId::new(7), u64::try_from(*number).unwrap())
                    .as_str()
            )
        );
    }
    let published = recorded(&recorder);
    assert_eq!(
        published.iter().map(|p| p.1.clone()).collect::<Vec<_>>(),
        queued
            .iter()
            .filter_map(|q| q.2.clone())
            .collect::<Vec<_>>()
    );
    finish(&runtime).await;
}

proptest::proptest! {
    /// A message id is 17 digits starting with 2, and no two events of one session share one.
    #[test]
    fn schedule_message_ids_are_well_formed_and_distinct(
        session in proptest::num::u128::ANY,
        first in 0_u64..1_000_000_000_000,
        gap in 1_u64..1_000_000,
    ) {
        let a = super::schedule_message_id(SessionId::new(session), first);
        let b = super::schedule_message_id(SessionId::new(session), first + gap);
        proptest::prop_assert!(is_message_id(&a), "{}", a);
        proptest::prop_assert!(is_message_id(&b), "{}", b);
        proptest::prop_assert_ne!(a, b);
    }
}

/// Pins today's behaviour, which is not necessarily the intended one: with `catchUp = all`
/// one clock jump over several occurrences of a job overlaps itself inside one sweep, so
/// `skip` keeps only the oldest run and `reject` counts the later ones as rejections.
#[tokio::test]
async fn one_jump_over_several_occurrences_overlaps_itself_under_skip_and_reject() {
    use super::OverlapPolicy;
    let (runtime, clock) =
        runtime_with(CatchUpPolicy::All, OverlapPolicy::Skip, 100_000, START).await;
    advance(&clock, 15 * 60);
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![run("tick", "2026-08-29T12:05:00Z")]
    );
    assert_eq!(
        outcomes(&runtime, "tick"),
        vec!["skipped: overlap".to_owned(), "skipped: overlap".to_owned()]
    );
    finish(&runtime).await;

    let (runtime, clock) =
        runtime_with(CatchUpPolicy::All, OverlapPolicy::Reject, 100_000, START).await;
    advance(&clock, 15 * 60);
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![run("tick", "2026-08-29T12:05:00Z")]
    );
    assert_eq!(runtime.status()["overlapRejected"], 2);
    assert_eq!(runtime.dead_letters().len(), 2);
    finish(&runtime).await;
}

#[tokio::test]
async fn a_manual_run_follows_the_overlap_policy_against_a_scheduler_run() {
    use super::{OverlapPolicy, ScheduleRunError};
    for (overlap, refused) in [
        (OverlapPolicy::Skip, true),
        (OverlapPolicy::Reject, true),
        (OverlapPolicy::Allow, false),
        (OverlapPolicy::Queue, false),
    ] {
        let (runtime, clock) = runtime_with(CatchUpPolicy::All, overlap, 100_000, START).await;
        advance(&clock, 5 * 60);
        runtime.on_clock_changed();
        let manual = runtime.run_schedule("tick");
        if refused {
            assert!(
                matches!(&manual, Err(ScheduleRunError::Refused(m)) if m.contains("already queued or running")),
                "{overlap:?}: {manual:?}"
            );
            assert_eq!(admitted(&runtime).len(), 1, "{overlap:?}");
        } else {
            assert_eq!(manual, Ok(()), "{overlap:?}");
            assert_eq!(admitted(&runtime).len(), 2, "{overlap:?}");
        }
        assert_eq!(
            runtime.status()["overlapRejected"],
            u64::from(overlap == OverlapPolicy::Reject),
            "{overlap:?}"
        );
        finish(&runtime).await;
    }
}

#[tokio::test]
async fn a_handler_that_is_still_running_makes_its_function_busy() {
    use super::OverlapPolicy;
    // The payload is gone but the handler has not returned (a timed-out handler keeps its
    // slot): the next due run overlaps it.
    for overlap in [OverlapPolicy::Skip, OverlapPolicy::Reject] {
        let (runtime, clock) = runtime_with(CatchUpPolicy::All, overlap, 100_000, START).await;
        runtime
            .inner
            .lock()
            .unwrap()
            .running
            .insert("7-900".to_owned(), "tick".to_owned());
        advance(&clock, 5 * 60);
        runtime.on_clock_changed();
        assert!(admitted(&runtime).is_empty(), "{overlap:?}");
        match overlap {
            OverlapPolicy::Skip => {
                assert_eq!(
                    outcomes(&runtime, "tick"),
                    vec!["skipped: overlap".to_owned()]
                );
            }
            _ => assert_eq!(runtime.status()["overlapRejected"], 1),
        }
        runtime.inner.lock().unwrap().running.clear();
        advance(&clock, 5 * 60);
        runtime.on_clock_changed();
        assert_eq!(
            admitted(&runtime),
            vec![run("tick", "2026-08-29T12:10:00Z")],
            "{overlap:?}: the handler returned"
        );
        finish(&runtime).await;
    }
}

// ----- lifecycle --------------------------------------------------------------------------

#[tokio::test]
async fn a_reset_restarts_every_schedule_from_now_and_drops_the_backlog() {
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    set_room(&runtime, 0);
    advance(&clock, 10 * 60);
    runtime.on_clock_changed();
    assert!(
        pending(&runtime),
        "12:05 and 12:10 are refused and held due"
    );
    runtime.reset();
    assert!(!pending(&runtime), "the reset cleared the backlog flag");
    assert!(admitted(&runtime).is_empty());
    assert!(runtime.is_idle());
    set_room(&runtime, 10);
    runtime.on_clock_changed();
    assert!(
        admitted(&runtime).is_empty(),
        "the held runs are not replayed"
    );
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![run("tick", "2026-08-29T12:15:00Z")],
        "the next occurrence after the reset runs, once"
    );
    finish(&runtime).await;
}

#[tokio::test]
async fn real_time_passing_without_a_clock_move_produces_no_run() {
    // The scheduler is driven by the virtual clock alone: starting at 12:04:59 with 12:05
    // one second ahead, real time passing makes nothing due.
    let (runtime, _clock) = runtime_with(
        CatchUpPolicy::All,
        super::OverlapPolicy::Allow,
        100_000,
        START + 238,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    runtime.on_clock_changed();
    assert!(admitted(&runtime).is_empty());
    assert!(runtime.is_idle());
    finish(&runtime).await;
}

#[tokio::test]
async fn a_run_held_for_capacity_survives_a_reload_and_is_admitted_once() {
    use super::CodebaseSpec;
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    set_room(&runtime, 0);
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    assert!(pending(&runtime), "12:05 is refused and held due");
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
    runtime
        .reload_codebase(CodebaseSpec {
            function: None,
            name: "default".to_owned(),
            manifest: runtime.manifest().clone(),
            runner: replacement,
            spawn: Some(spec),
            cleanup_dir: None,
        })
        .unwrap();
    assert!(pending(&runtime), "the reload keeps the backlog");
    assert!(admitted(&runtime).is_empty());
    set_room(&runtime, 10);
    runtime.on_clock_changed();
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![run("tick", "2026-08-29T12:05:00Z")],
        "admitted once, after the reload"
    );
    finish(&runtime).await;
}

#[tokio::test]
async fn the_session_is_not_idle_while_only_the_backlog_remains() {
    let (runtime, clock) = runtime(CatchUpPolicy::All).await;
    set_room(&runtime, 0);
    advance(&clock, 5 * 60);
    runtime.on_clock_changed();
    assert!(admitted(&runtime).is_empty(), "nothing is queued");
    assert!(pending(&runtime));
    assert!(!runtime.is_idle(), "a due run is still owed");
    assert_eq!(runtime.status()["catchUpPending"], true);
    assert!(runtime
        .await_idle(Duration::from_millis(200))
        .await
        .is_err());
    set_room(&runtime, 10);
    runtime.on_clock_changed();
    assert_eq!(
        admitted(&runtime),
        vec![run("tick", "2026-08-29T12:05:00Z")]
    );
    assert!(!pending(&runtime));
    finish(&runtime).await;
}
