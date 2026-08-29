//! The functions runtime: events in, invocations out.
//!
//! Every Firestore change, Storage object event and due schedule becomes a `LogicalEvent`
//! in the deterministic outbox; the dispatcher leases pending events (respecting each
//! function's concurrency), invokes the runner with a real-time timeout, and records the
//! outcome: `Succeeded`, `RetryWaiting` (functions declared with `retry`, exponential
//! backoff in virtual time) or `DeadLettered`. `await-idle` waits until no event is
//! pending / leased / running / retry-waiting and no schedule is due.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ftd_adapter_grpc::local::CommitEvent;
use ftd_core_events::event::{EventSource, EventType, LogicalEvent};
use ftd_core_events::outbox::Outbox;
use ftd_core_events::retry::RetryPolicy;
use ftd_core_events::state::{EventState, FailureOutcome};
use ftd_core_functions::cron::{fixed_offset_seconds, Schedule};
use ftd_core_functions::manifest::{FunctionManifest, FunctionSpec, ObjectEvent, Trigger};
use ftd_core_session::clock::VirtualClock;
use ftd_core_storage::store::StorageEvent;
use ftd_core_types::determinism::Clock;
use ftd_core_types::ids::{CorrelationId, Epoch, EventId, SessionId};
use ftd_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};
use tokio::sync::Notify;

use crate::events::{change_kind, firestore_event, schedule_event, storage_event};
use crate::http::{forward, ProxiedResponse};
use crate::runner::{InvokeOutcome, Runner};

/// Default maximum schedule runs enqueued per clock advance and job (spec 11.6); the rest
/// stays due and is enqueued as invocations complete, so nothing is discarded.
pub const MAX_CATCH_UP_RUNS: usize = 1000;
/// Default attempts (first delivery included) for functions declared with `retry`.
pub const RETRY_MAX_ATTEMPTS: u32 = 4;
/// Base backoff of the first retry (virtual time).
pub const RETRY_BASE_BACKOFF_SECONDS: i64 = 10;
/// Cap of the retry backoff (virtual time).
pub const RETRY_MAX_BACKOFF_SECONDS: i64 = 600;

/// One HTTP function the proxy can reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpTarget {
    /// Function name.
    pub function: String,
    /// Runner HTTP address.
    pub addr: String,
}

/// Static runtime configuration.
#[derive(Debug, Clone)]
pub struct FunctionsConfig {
    /// Project ID the functions belong to.
    pub project: String,
    /// Default bucket (Storage triggers without a bucket).
    pub default_bucket: String,
    /// Location reported in Firestore events (`nam5` for multi-region defaults).
    pub location: String,
    /// Session ID reported to the runner.
    pub session: SessionId,
    /// Maximum invocations running at once across every function.
    pub max_running: usize,
    /// Attempts (first delivery included) for functions declared with `retry`.
    pub retry_attempts: u32,
    /// Schedule runs enqueued per clock change and job before the rest waits its turn.
    pub max_catch_up_runs: usize,
    /// Secret the runner's HTTP server requires (`x-ftd-runner-secret`).
    pub runner_secret: String,
}

struct ScheduledJob {
    function: String,
    region: String,
    schedule: Schedule,
    offset_seconds: i64,
    /// Runs strictly after this instant are due.
    cursor: LogicalInstant,
}

/// A recorded invocation (status output, tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationRecord {
    /// Event ID.
    pub event_id: u128,
    /// Function.
    pub function: String,
    /// Attempt (1-based).
    pub attempt: u32,
    /// Outcome text (`ok`, `failed: ...`, `timeout`, ...).
    pub outcome: String,
}

struct Inner {
    outbox: Outbox,
    payloads: BTreeMap<EventId, (String, Value)>,
    running: BTreeMap<EventId, String>,
    next_event: u64,
    epoch: Epoch,
    jobs: Vec<ScheduledJob>,
    history: Vec<InvocationRecord>,
    dead_letters: Vec<InvocationRecord>,
    /// Schedule runs became due beyond the catch-up cap and still have to be enqueued.
    catch_up_pending: bool,
}

/// The runtime.
pub struct FunctionsRuntime {
    manifest: FunctionManifest,
    config: FunctionsConfig,
    clock: Arc<Mutex<VirtualClock>>,
    runner: Arc<Runner>,
    inner: Mutex<Inner>,
    wake: Notify,
    idle: Arc<Notify>,
    retry: RetryPolicy,
}

impl FunctionsRuntime {
    /// Builds the runtime around a started runner; schedules start counting from the
    /// current virtual time.
    #[must_use]
    pub fn new(
        manifest: FunctionManifest,
        config: FunctionsConfig,
        clock: Arc<Mutex<VirtualClock>>,
        runner: Arc<Runner>,
    ) -> Arc<Self> {
        let now = clock
            .lock()
            .map(|c| c.now())
            .unwrap_or(LogicalInstant::UNIX_EPOCH);
        let jobs = manifest
            .scheduled()
            .map(|(f, schedule, tz)| ScheduledJob {
                function: f.name.clone(),
                region: f.region.clone(),
                schedule: schedule.clone(),
                offset_seconds: fixed_offset_seconds(tz).unwrap_or(0),
                cursor: now,
            })
            .collect();
        let retry = RetryPolicy::try_new(
            config.retry_attempts.max(1),
            LogicalDuration::from_seconds(RETRY_BASE_BACKOFF_SECONDS),
            LogicalDuration::from_seconds(RETRY_MAX_BACKOFF_SECONDS),
        )
        .unwrap_or_else(|_| {
            RetryPolicy::try_new(
                1,
                LogicalDuration::from_seconds(0),
                LogicalDuration::from_seconds(0),
            )
            .expect("a single attempt is a valid policy")
        });
        Arc::new(Self {
            manifest,
            config,
            clock,
            runner,
            inner: Mutex::new(Inner {
                outbox: Outbox::new(),
                payloads: BTreeMap::new(),
                running: BTreeMap::new(),
                next_event: 0,
                epoch: Epoch::initial(),
                jobs,
                history: Vec::new(),
                dead_letters: Vec::new(),
                catch_up_pending: false,
            }),
            wake: Notify::new(),
            idle: Arc::new(Notify::new()),
            retry,
        })
    }

    /// The manifest.
    #[must_use]
    pub fn manifest(&self) -> &FunctionManifest {
        &self.manifest
    }

    /// The runner.
    #[must_use]
    pub fn runner(&self) -> &Arc<Runner> {
        &self.runner
    }

    fn now(&self) -> LogicalInstant {
        self.clock
            .lock()
            .map(|c| c.now())
            .unwrap_or(LogicalInstant::UNIX_EPOCH)
    }

    #[allow(clippy::too_many_arguments)]
    fn enqueue(
        inner: &mut Inner,
        session: SessionId,
        source: EventSource,
        function: &str,
        event_type: &str,
        subject: String,
        time: LogicalInstant,
        payload: Value,
    ) {
        inner.next_event += 1;
        let id = EventId::new(u128::from(inner.next_event));
        let Ok(event_type) = EventType::try_new(event_type) else {
            return;
        };
        let event = LogicalEvent {
            event_id: id,
            session_id: session,
            epoch: inner.epoch,
            source,
            event_type,
            subject,
            logical_time: time,
            causation_id: None,
            correlation_id: CorrelationId::new(u128::from(inner.next_event)),
            payload: Vec::new(),
        };
        if inner.outbox.enqueue(event).is_ok() {
            inner.payloads.insert(id, (function.to_owned(), payload));
        }
    }

    /// Turns a Firestore commit into document events for every matching trigger.
    pub fn on_commit(&self, commit: &CommitEvent) {
        let Some(time) = commit.commit_time else {
            return; // reset
        };
        if commit.project != self.config.project {
            return;
        }
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let mut enqueued = false;
        for change in commit.changes.iter() {
            let Some(kind) = change_kind(change.before.as_ref(), change.after.as_ref()) else {
                continue;
            };
            let relative = change.path.relative();
            for m in self
                .manifest
                .firestore_matches(&commit.database, &relative, kind)
            {
                let Trigger::Firestore {
                    event: declared, ..
                } = &m.function.trigger
                else {
                    continue;
                };
                // A `written` trigger receives the written type; others their own kind.
                let reported = if matches!(
                    declared,
                    ftd_core_functions::manifest::DocumentEvent::Written
                ) {
                    *declared
                } else {
                    kind
                };
                let id = format!("{}-{}", self.config.session.value(), inner.next_event + 1);
                let mut payload = firestore_event(
                    &id,
                    &commit.project,
                    &commit.database,
                    &self.config.location,
                    &relative,
                    reported,
                    change.before.as_ref(),
                    change.after.as_ref(),
                    time,
                );
                payload["params"] = json!(m.params);
                Self::enqueue(
                    &mut inner,
                    self.config.session,
                    EventSource::Firestore,
                    &m.function.name,
                    reported.event_type(),
                    format!("documents/{relative}"),
                    time,
                    payload,
                );
                enqueued = true;
            }
        }
        drop(inner);
        if enqueued {
            self.wake.notify_one();
        }
    }

    /// Turns a Storage object event into events for every matching trigger.
    pub fn on_storage_event(&self, event: &StorageEvent) {
        let (kind, object) = match event {
            StorageEvent::Finalized(m) => (ObjectEvent::Finalized, m),
            StorageEvent::Deleted(m) => (ObjectEvent::Deleted, m),
            StorageEvent::MetadataUpdated(m) => (ObjectEvent::MetadataUpdated, m),
        };
        let time = self.now();
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let mut enqueued = false;
        for f in
            self.manifest
                .storage_matches(object.bucket.as_str(), &self.config.default_bucket, kind)
        {
            let id = format!("{}-{}", self.config.session.value(), inner.next_event + 1);
            let payload = storage_event(&id, kind, object, time);
            Self::enqueue(
                &mut inner,
                self.config.session,
                EventSource::Storage,
                &f.name,
                kind.event_type(),
                format!("objects/{}", object.name.as_str()),
                time,
                payload,
            );
            enqueued = true;
        }
        drop(inner);
        if enqueued {
            self.wake.notify_one();
        }
    }

    /// Enqueues every schedule run that became due up to the current virtual time
    /// (catch-up `all`, capped at [`MAX_CATCH_UP_RUNS`]) and releases due retries.
    pub fn on_clock_changed(&self) {
        let now = self.now();
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let mut enqueued = false;
        let cap = self.config.max_catch_up_runs.max(1);
        let mut pending = false;
        let runs: Vec<(String, String, LogicalInstant)> = inner
            .jobs
            .iter_mut()
            .flat_map(|job| {
                let runs = job
                    .schedule
                    .runs_between(job.cursor, now, job.offset_seconds, cap + 1);
                if runs.len() > cap {
                    // Beyond the cap: enqueue `cap` runs now and leave the cursor at the last
                    // one so the rest stays due (keeping the session busy) instead of vanishing.
                    let kept: Vec<LogicalInstant> = runs.into_iter().take(cap).collect();
                    job.cursor = kept.last().copied().unwrap_or(job.cursor);
                    pending = true;
                    kept.into_iter()
                        .map(|t| (job.function.clone(), job.region.clone(), t))
                        .collect::<Vec<_>>()
                } else {
                    if now.as_nanos() > job.cursor.as_nanos() {
                        job.cursor = now;
                    }
                    runs.into_iter()
                        .map(|t| (job.function.clone(), job.region.clone(), t))
                        .collect::<Vec<_>>()
                }
            })
            .collect();
        inner.catch_up_pending = pending;
        for (function, region, at) in runs {
            let id = format!("{}-{}", self.config.session.value(), inner.next_event + 1);
            let payload = schedule_event(&id, &self.config.project, &region, &function, at);
            Self::enqueue(
                &mut inner,
                self.config.session,
                EventSource::Scheduler,
                &function,
                "google.cloud.scheduler.job.v1.executed",
                format!("jobs/{function}"),
                at,
                payload,
            );
            enqueued = true;
        }
        for id in inner.outbox.retries_due(now) {
            if let Ok(r) = inner.outbox.record_mut(id) {
                let _ = r.retry_due(now);
                enqueued = true;
            }
        }
        drop(inner);
        if enqueued {
            self.wake.notify_one();
        }
    }

    /// Runs a scheduled function now (manual trigger).
    pub fn run_schedule(&self, function: &str) -> Result<(), String> {
        let f = self
            .manifest
            .get(function)
            .ok_or_else(|| format!("unknown function {function:?}"))?;
        if !matches!(f.trigger, Trigger::Schedule { .. }) {
            return Err(format!("function {function:?} is not scheduled"));
        }
        let now = self.now();
        let Ok(mut inner) = self.inner.lock() else {
            return Err("runtime poisoned".into());
        };
        let id = format!("{}-{}", self.config.session.value(), inner.next_event + 1);
        let payload = schedule_event(&id, &self.config.project, &f.region, function, now);
        Self::enqueue(
            &mut inner,
            self.config.session,
            EventSource::Manual,
            function,
            "google.cloud.scheduler.job.v1.executed",
            format!("jobs/{function}"),
            now,
            payload,
        );
        drop(inner);
        self.wake.notify_one();
        Ok(())
    }

    /// Session reset: every non-terminal event is discarded and schedules restart from now.
    /// Invocations already running keep their slots until they finish (their results are
    /// ignored), so `await-idle` does not return while old handlers can still write.
    pub fn reset(&self) {
        let now = self.now();
        if let Ok(mut inner) = self.inner.lock() {
            inner.epoch = inner.epoch.next().unwrap_or(inner.epoch);
            let epoch = inner.epoch;
            inner.outbox.discard_stale(epoch);
            let running: Vec<EventId> = inner.running.keys().copied().collect();
            inner.payloads.retain(|id, _| running.contains(id));
            inner.catch_up_pending = false;
            for job in &mut inner.jobs {
                job.cursor = now;
            }
        }
        self.idle.notify_waiters();
        self.wake.notify_one();
    }

    /// Notified whenever an invocation completes or the runtime resets.
    #[must_use]
    pub fn idle_notify(&self) -> Arc<Notify> {
        self.idle.clone()
    }

    /// Whether any causal work is outstanding (spec 10.5 quiescence for events): no event
    /// pending / leased / running / retry-waiting, no HTTP invocation running, no schedule
    /// run due beyond the catch-up cap.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.inner
            .lock()
            .map(|i| !i.outbox.has_active() && i.running.is_empty() && !i.catch_up_pending)
            .unwrap_or(true)
    }

    /// Whether the runner process is alive (a dead runner leaves queued work pending).
    #[must_use]
    pub fn runner_alive(&self) -> bool {
        self.runner.is_alive()
    }

    /// Outstanding work, for `await-idle` timeouts and status output.
    #[must_use]
    pub fn status(&self) -> Value {
        let Ok(inner) = self.inner.lock() else {
            return json!({});
        };
        let mut pending = 0;
        let mut retry_waiting = 0;
        let mut dead = 0;
        let mut succeeded = 0;
        for id in inner.payloads.keys().chain(inner.running.keys()) {
            if let Some(r) = inner.outbox.record(*id) {
                match r.state() {
                    EventState::Pending | EventState::Leased => pending += 1,
                    EventState::RetryWaiting { .. } => retry_waiting += 1,
                    _ => {}
                }
            }
        }
        for r in &inner.history {
            if r.outcome == "ok" {
                succeeded += 1;
            }
        }
        dead += inner.dead_letters.len();
        json!({
            "pending": pending,
            "running": inner.running.len(),
            "retryWaiting": retry_waiting,
            "succeeded": succeeded,
            "deadLettered": dead,
            "catchUpPending": inner.catch_up_pending,
            "runnerAlive": self.runner.is_alive(),
            "epoch": inner.epoch.value(),
            "functions": self.manifest.functions.iter().map(|f| f.name.clone()).collect::<Vec<_>>(),
        })
    }

    /// Waits until the runtime is idle or `timeout` (real time) elapses.
    pub async fn await_idle(&self, timeout: Duration) -> Result<(), Value> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.is_idle() {
                return Ok(());
            }
            let notified = self.idle.notified();
            if self.is_idle() {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(self.status());
            }
            if tokio::time::timeout(remaining, notified).await.is_err() {
                return Err(self.status());
            }
        }
    }

    /// Invocation history (oldest first).
    #[must_use]
    pub fn history(&self) -> Vec<InvocationRecord> {
        self.inner
            .lock()
            .map(|i| i.history.clone())
            .unwrap_or_default()
    }

    /// Dead-lettered invocations.
    #[must_use]
    pub fn dead_letters(&self) -> Vec<InvocationRecord> {
        self.inner
            .lock()
            .map(|i| i.dead_letters.clone())
            .unwrap_or_default()
    }

    /// The runner address for an HTTP function, if it exists.
    #[must_use]
    pub fn http_target(&self, project: &str, region: &str, function: &str) -> Option<HttpTarget> {
        if project != self.config.project {
            return None;
        }
        let f = self.manifest.get(function)?;
        if !matches!(f.trigger, Trigger::Http { .. }) || f.region != region {
            return None;
        }
        let port = self.runner.hello().http_port?;
        Some(HttpTarget {
            function: function.to_owned(),
            addr: format!("127.0.0.1:{port}"),
        })
    }

    /// Proxies one HTTP request to the runner, counting it as running work.
    pub async fn invoke_http(
        &self,
        target: &HttpTarget,
        method: &str,
        path_and_query: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<ProxiedResponse, String> {
        let (timeout, concurrency) = self.manifest.get(&target.function).map_or((60, 1), |f| {
            (u64::from(f.timeout_seconds), f.concurrency as usize)
        });
        let id = {
            let Ok(mut inner) = self.inner.lock() else {
                return Err("runtime poisoned".into());
            };
            // HTTP invocations share the admission limits of event invocations.
            let running_here = inner
                .running
                .values()
                .filter(|f| **f == target.function)
                .count();
            if inner.running.len() >= self.config.max_running || running_here >= concurrency {
                return Err(format!(
                    "function {} is at its concurrency limit; retry later",
                    target.function
                ));
            }
            inner.next_event += 1;
            let id = EventId::new(u128::from(inner.next_event));
            inner.running.insert(id, target.function.clone());
            id
        };
        let mut forwarded: Vec<(String, String)> = headers.to_vec();
        forwarded.push((
            "x-ftd-runner-secret".to_owned(),
            self.config.runner_secret.clone(),
        ));
        let result = tokio::time::timeout(
            Duration::from_secs(timeout),
            forward(&target.addr, method, path_and_query, &forwarded, body),
        )
        .await;
        let outcome = match &result {
            Ok(Ok(r)) => format!("http {}", r.status),
            Ok(Err(e)) => format!("failed: {e}"),
            Err(_) => "timeout".to_owned(),
        };
        if let Ok(mut inner) = self.inner.lock() {
            inner.running.remove(&id);
            inner.history.push(InvocationRecord {
                event_id: id.value(),
                function: target.function.clone(),
                attempt: 1,
                outcome,
            });
        }
        self.idle.notify_waiters();
        // The freed slot may unblock a pending event.
        self.wake.notify_one();
        match result {
            Ok(r) => r,
            Err(_) => Err(format!(
                "function {} did not answer within {timeout}s",
                target.function
            )),
        }
    }

    /// The dispatch loop: run it as a task for the runtime's lifetime.
    pub async fn dispatch_loop(self: Arc<Self>) {
        loop {
            self.dispatch_ready();
            self.wake.notified().await;
        }
    }

    fn dispatch_ready(self: &Arc<Self>) {
        if !self.runner.is_alive() {
            // Queued work stays pending and visible in the status; nothing is retried
            // against a dead process.
            return;
        }
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let ready: Vec<EventId> = inner.outbox.dispatchable().map(|e| e.event_id).collect();
        for id in ready {
            if inner.running.len() >= self.config.max_running {
                break;
            }
            let Some((function_name, _)) = inner.payloads.get(&id) else {
                continue;
            };
            let function_name = function_name.clone();
            let Some(spec) = self.manifest.get(&function_name) else {
                continue;
            };
            let running_here = inner
                .running
                .values()
                .filter(|f| **f == function_name)
                .count();
            if running_here >= spec.concurrency as usize {
                continue;
            }
            let Ok(record) = inner.outbox.record_mut(id) else {
                continue;
            };
            if record.lease().is_err() || record.start().is_err() {
                continue;
            }
            let attempt = record.attempt();
            let epoch = record.event().epoch;
            let Some((_, payload)) = inner.payloads.get(&id) else {
                continue;
            };
            let request = self.invoke_request(id, spec, attempt, epoch, payload);
            inner.running.insert(id, function_name.clone());
            let runtime = self.clone();
            let timeout = Duration::from_secs(u64::from(spec.timeout_seconds));
            let retry = spec.retry;
            tokio::spawn(async move {
                let outcome = runtime.runner.invoke(request, timeout).await;
                runtime.complete(id, &function_name, attempt, epoch, retry, &outcome);
            });
        }
    }

    fn invoke_request(
        &self,
        id: EventId,
        spec: &FunctionSpec,
        attempt: u32,
        epoch: Epoch,
        event: &Value,
    ) -> Value {
        let now = self.now();
        let deadline = now
            .checked_add(LogicalDuration::from_seconds(i64::from(
                spec.timeout_seconds,
            )))
            .unwrap_or(now);
        let trigger = match &spec.trigger {
            Trigger::Firestore { .. } => "firestore",
            Trigger::Storage { .. } => "storage",
            Trigger::Schedule { .. } => "schedule",
            Trigger::Http { .. } => "http",
        };
        json!({
            "invocationId": format!("{}-{attempt}", id.value()),
            "function": spec.name,
            "entryPoint": spec.entry_point,
            "trigger": trigger,
            "event": event,
            "deadline": deadline.to_rfc3339().unwrap_or_default(),
            "attempt": attempt,
            "session": self.config.session.value().to_string(),
            "epoch": epoch.value(),
        })
    }

    fn complete(
        &self,
        id: EventId,
        function: &str,
        attempt: u32,
        epoch: Epoch,
        retry: bool,
        outcome: &InvokeOutcome,
    ) {
        let now = self.now();
        if let Ok(mut inner) = self.inner.lock() {
            inner.running.remove(&id);
            let text = match &outcome {
                InvokeOutcome::Ok => "ok".to_owned(),
                InvokeOutcome::Failed(e) => format!("failed: {e}"),
                InvokeOutcome::TimedOut => "timeout".to_owned(),
                InvokeOutcome::RunnerGone(e) => format!("runner gone: {e}"),
            };
            inner.history.push(InvocationRecord {
                event_id: id.value(),
                function: function.to_owned(),
                attempt,
                outcome: text.clone(),
            });
            if inner.epoch != epoch {
                // Stale epoch: the record was discarded by the reset; nothing to update.
            } else if let Ok(record) = inner.outbox.record_mut(id) {
                if matches!(outcome, InvokeOutcome::Ok) {
                    let _ = record.succeed();
                    inner.payloads.remove(&id);
                } else {
                    let single = RetryPolicy::try_new(
                        1,
                        LogicalDuration::from_seconds(0),
                        LogicalDuration::from_seconds(0),
                    );
                    let policy = if retry {
                        self.retry
                    } else {
                        single.unwrap_or(self.retry)
                    };
                    let scheduled = matches!(
                        record.fail(&policy, now),
                        Ok(FailureOutcome::RetryScheduled { .. })
                    );
                    if !scheduled {
                        inner.payloads.remove(&id);
                        inner.dead_letters.push(InvocationRecord {
                            event_id: id.value(),
                            function: function.to_owned(),
                            attempt,
                            outcome: text,
                        });
                    }
                }
            }
        }
        let more_due = self
            .inner
            .lock()
            .map(|i| i.catch_up_pending)
            .unwrap_or(false);
        if more_due {
            self.on_clock_changed();
        }
        self.idle.notify_waiters();
        self.wake.notify_one();
    }
}
