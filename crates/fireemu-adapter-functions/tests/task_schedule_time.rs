//! Cloud Tasks `scheduleTime` (FN-05): the strict profile holds a task back until it falls due on
//! the native clock, refuses a timestamp that is not RFC 3339, and lets the console release a
//! waiting task with `run_tasks_now`; the emulator profile dispatches at once, as the official
//! emulator does. (The virtual task clock, which tests use to avoid real waiting, is covered by
//! the scheduler's unit tests and the runtime tests that advance the clock.)

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
use fireemu_core_functions::manifest::{TaskRateLimits, TaskRetryConfig, Trigger};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;
use serde_json::json;

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

struct Fixture {
    dir: std::path::PathBuf,
    probe: std::path::PathBuf,
    runtime: Arc<FunctionsRuntime>,
}

async fn start(name: &str, honour: bool) -> Fixture {
    let dir = std::env::temp_dir().join(format!("fireemu-schedule-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("entries");
    std::fs::write(dir.join("entries.taskA.release"), "").unwrap();
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: vec![(
            "FIREEMU_FAKE_TASK_PROBE".to_owned(),
            probe.display().to_string(),
        )],
        hello_timeout: Duration::from_secs(60),
    };
    let runner = Runner::spawn_spec(&spec).await.unwrap();
    let mut manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
    let mut queue = manifest.get("echo").unwrap().clone();
    "taskA".clone_into(&mut queue.name);
    "taskA".clone_into(&mut queue.entry_point);
    queue.trigger = Trigger::TaskQueue {
        retry: TaskRetryConfig::default(),
        rate_limits: TaskRateLimits {
            max_concurrent_dispatches: 4,
            max_dispatches_per_second: 500.0,
        },
    };
    manifest.functions.push(queue);
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            functions_host: Some("127.0.0.1:5001".into()),
            honour_task_schedule_time: honour,
            ..FunctionsConfig::for_tests(1000, "s".into())
        },
        Arc::new(Mutex::new(VirtualClock::new(START))),
        Arc::new(runner),
        Some(spec),
    );
    tokio::spawn(runtime.clone().dispatch_loop());
    Fixture {
        dir,
        probe,
        runtime,
    }
}

fn rfc3339_in(seconds: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let at = i64::try_from(now.as_secs()).unwrap() + seconds;
    LogicalInstant::from_unix_seconds(at).to_rfc3339().unwrap()
}

fn body(id: &str, schedule: Option<&str>) -> serde_json::Value {
    let mut task = json!({
        "name": format!("projects/demo-app/locations/us-central1/queues/taskA/tasks/{id}"),
        "httpRequest": {"url": "", "body": "eyJkYXRhIjp7fX0="}
    });
    if let Some(at) = schedule {
        task["scheduleTime"] = json!(at);
    }
    json!({ "task": task })
}

fn dispatched(probe: &Path) -> usize {
    std::fs::read_to_string(probe)
        .unwrap_or_default()
        .lines()
        .count()
}

async fn wait_for(probe: &Path, count: usize, limit: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < limit {
        if dispatched(probe) >= count {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

impl Fixture {
    async fn stop(self) {
        self.runtime.shutdown().await;
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test]
async fn strict_holds_a_task_until_its_schedule_time_and_dispatches_it_then() {
    let f = start("hold", true).await;
    let due = rfc3339_in(5);
    let enqueued = Instant::now();
    f.runtime
        .enqueue_task(
            "demo-app",
            "us-central1",
            "taskA",
            &body("later", Some(&due)),
        )
        .unwrap();
    f.runtime
        .enqueue_task("demo-app", "us-central1", "taskA", &body("now", None))
        .unwrap();
    // The task without a schedule goes straight away, the scheduled one waits.
    assert!(
        wait_for(&f.probe, 1, Duration::from_secs(5)).await,
        "the unscheduled task runs"
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        dispatched(&f.probe),
        1,
        "the scheduled task must still be waiting"
    );
    let pending = f.runtime.pending_tasks();
    assert_eq!(pending.len(), 1);
    assert!(pending[0].name.ends_with("/later"));
    assert_eq!(pending[0].id, "later");
    assert_eq!(pending[0].schedule_time.as_deref(), Some(due.as_str()));
    // It is dispatched by the time it falls due, not before: the second boundary of the time
    // stamp leaves up to a second of slack.
    assert!(
        wait_for(&f.probe, 2, Duration::from_secs(6)).await,
        "the scheduled task runs"
    );
    assert!(
        enqueued.elapsed() >= Duration::from_secs(2),
        "{:?}",
        enqueued.elapsed()
    );
    f.stop().await;
}

#[tokio::test]
async fn a_schedule_time_in_the_past_dispatches_at_once() {
    let f = start("past", true).await;
    f.runtime
        .enqueue_task(
            "demo-app",
            "us-central1",
            "taskA",
            &body("old", Some("2020-01-01T00:00:00Z")),
        )
        .unwrap();
    assert!(wait_for(&f.probe, 1, Duration::from_secs(5)).await);
    f.stop().await;
}

#[tokio::test]
async fn run_now_releases_a_waiting_task_and_only_the_named_one() {
    let f = start("runnow", true).await;
    let far = rfc3339_in(3600);
    for id in ["a", "b"] {
        f.runtime
            .enqueue_task("demo-app", "us-central1", "taskA", &body(id, Some(&far)))
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert_eq!(dispatched(&f.probe), 0);
    assert_eq!(f.runtime.pending_tasks().len(), 2);

    assert_eq!(f.runtime.run_tasks_now("taskA", Some("nope")), 0);
    assert_eq!(f.runtime.run_tasks_now("elsewhere", None), 0);
    assert_eq!(f.runtime.run_tasks_now("taskA", Some("b")), 1);
    assert!(wait_for(&f.probe, 1, Duration::from_secs(5)).await);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(dispatched(&f.probe), 1, "a is still waiting");
    let pending = f.runtime.pending_tasks();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, "a");

    assert_eq!(f.runtime.run_tasks_now("taskA", None), 1);
    assert!(wait_for(&f.probe, 2, Duration::from_secs(5)).await);
    f.stop().await;
}

#[tokio::test]
async fn strict_refuses_a_schedule_time_that_is_not_rfc_3339() {
    let f = start("invalid", true).await;
    for bad in ["not-a-time", "2026-13-40T00:00:00Z", "tomorrow", ""] {
        let refusal = f
            .runtime
            .enqueue_task("demo-app", "us-central1", "taskA", &body("bad", Some(bad)))
            .expect_err(bad);
        assert_eq!(refusal.status, 400, "{bad}");
    }
    assert!(f.runtime.pending_tasks().is_empty());
    f.stop().await;
}

/// The official emulator never consults `scheduleTime`, so the emulator profile may not wait or
/// refuse because of it.
#[tokio::test]
async fn the_emulator_profile_ignores_the_schedule_time() {
    let f = start("emulator", false).await;
    f.runtime
        .enqueue_task(
            "demo-app",
            "us-central1",
            "taskA",
            &body("far", Some(&rfc3339_in(3600))),
        )
        .unwrap();
    f.runtime
        .enqueue_task(
            "demo-app",
            "us-central1",
            "taskA",
            &body("junk", Some("not-a-time")),
        )
        .unwrap();
    assert!(wait_for(&f.probe, 2, Duration::from_secs(5)).await);
    f.stop().await;
}

/// Releasing a waiting task wakes the dispatch loop at once; without the wake it would sleep
/// until its next tick, up to a second. Five releases at drifting phases of that tick keep the
/// chance that a missing wake goes unnoticed below one in a hundred.
#[tokio::test]
async fn releasing_a_waiting_task_dispatches_it_without_waiting_for_the_next_tick() {
    let f = start("wake", true).await;
    let far = rfc3339_in(3600);
    for id in ["w1", "w2", "w3", "w4", "w5"] {
        f.runtime
            .enqueue_task("demo-app", "us-central1", "taskA", &body(id, Some(&far)))
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(1300)).await;
    for (index, id) in ["w1", "w2", "w3", "w4", "w5"].into_iter().enumerate() {
        assert_eq!(f.runtime.run_tasks_now("taskA", Some(id)), 1);
        let released = Instant::now();
        assert!(
            wait_for(&f.probe, index + 1, Duration::from_secs(3)).await,
            "{id} was never dispatched"
        );
        assert!(
            released.elapsed() < Duration::from_millis(400),
            "{id} waited {:?} for the next tick",
            released.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(170)).await;
    }
    f.stop().await;
}

/// Cloud Tasks takes a task at most 30 days ahead: 29 days is held, 31 days is refused, and the
/// boundary sits at the 30th day, to the second.
#[tokio::test]
async fn strict_refuses_a_schedule_time_more_than_thirty_days_ahead() {
    let f = start("horizon", true).await;
    let day = 24 * 3600;
    f.runtime
        .enqueue_task(
            "demo-app",
            "us-central1",
            "taskA",
            &body("near", Some(&rfc3339_in(29 * day))),
        )
        .expect("29 days ahead is held");
    for (id, seconds) in [("far", 31 * day), ("edge", 30 * day + 5)] {
        let refusal = f
            .runtime
            .enqueue_task(
                "demo-app",
                "us-central1",
                "taskA",
                &body(id, Some(&rfc3339_in(seconds))),
            )
            .expect_err(id);
        assert_eq!(refusal.status, 400, "{id}");
        assert!(refusal.body.contains("30 days"), "{}", refusal.body);
    }
    f.runtime
        .enqueue_task(
            "demo-app",
            "us-central1",
            "taskA",
            &body("inside", Some(&rfc3339_in(30 * day - 5))),
        )
        .expect("just under 30 days ahead is held");
    assert_eq!(f.runtime.pending_tasks().len(), 2);
    // The emulator profile takes any time, as the official emulator does.
    let e = start("horizon-emulator", false).await;
    e.runtime
        .enqueue_task(
            "demo-app",
            "us-central1",
            "taskA",
            &body("far", Some(&rfc3339_in(400 * day))),
        )
        .expect("the emulator profile does not look at the horizon");
    e.stop().await;
    f.stop().await;
}

#[tokio::test]
async fn runnable_idle_retains_future_tasks_without_dispatch_or_schedule_mutation() {
    let f = start("runnable-idle", true).await;
    let far = rfc3339_in(3600);
    f.runtime
        .enqueue_task(
            "demo-app",
            "us-central1",
            "taskA",
            &body("future", Some(&far)),
        )
        .unwrap();
    assert!(!f.runtime.is_idle());
    assert!(f.runtime.is_idle_with_scope(true));
    assert_eq!(
        f.runtime.publish("jobs", &[json!({"data": "e30="})]).len(),
        1
    );
    assert!(
        !f.runtime.is_idle_with_scope(true),
        "unrelated background work still blocks scoped idle"
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        while !f.runtime.is_idle_with_scope(true) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(f.runtime.task_idle_diagnostics()["excluded"], 1);
    assert!(f
        .runtime
        .await_idle(Duration::from_millis(20))
        .await
        .is_err());
    assert_eq!(dispatched(&f.probe), 0);
    assert_eq!(f.runtime.pending_tasks().len(), 1);
    assert_eq!(
        f.runtime.pending_tasks()[0].schedule_time.as_deref(),
        Some(far.as_str())
    );
    f.stop().await;
}
