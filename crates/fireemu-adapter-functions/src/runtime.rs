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

use fireemu_adapter_grpc::local::CommitEvent;
use fireemu_core_auth::store::{UserEvent, UserEventKind};
use fireemu_core_events::event::{EventSource, EventType, LogicalEvent};
use fireemu_core_events::outbox::Outbox;
use fireemu_core_events::retry::RetryPolicy;
use fireemu_core_events::state::{EventState, FailureOutcome};
use fireemu_core_functions::cron::{RunCount, Schedule};
use fireemu_core_functions::manifest::{
    AuthEvent, FunctionManifest, FunctionSpec, ObjectEvent, Trigger,
};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_storage::store::StorageEvent;
use fireemu_core_types::determinism::Clock;
use fireemu_core_types::ids::{CorrelationId, Epoch, EventId, SessionId};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};
use tokio::sync::Notify;

use crate::events::{
    auth_event, change_kind, firestore_event, pubsub_event, schedule_event, storage_event,
};
use crate::http::{forward, ProxiedResponse};
use crate::runner::{Invocation, InvokeOutcome, Runner, SpawnSpec};

/// Default maximum schedule runs enqueued per clock advance and job (spec 11.6); the rest
/// stays due and is enqueued as invocations complete, so nothing is discarded.
pub const MAX_CATCH_UP_RUNS: usize = 1000;
/// Invocation records the runtime keeps for inspection (`GET .../functions`, the UI log
/// stream, `history()`). Older ones are dropped; the cumulative counters in `status()` are
/// not affected.
pub const MAX_RETAINED_INVOCATIONS: usize = 1000;
/// Dead-letter records the runtime keeps, under the same budget rules.
pub const MAX_RETAINED_DEAD_LETTERS: usize = 500;
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
    /// Secret the runner's HTTP server requires (`x-fireemu-runner-secret`).
    pub runner_secret: String,
    /// Overlap policy of schedules.
    pub overlap: OverlapPolicy,
    /// What happens to schedule runs that became due while the clock moved.
    pub catch_up: CatchUpPolicy,
}

/// Which of the schedule runs that became due during a clock move are enqueued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CatchUpPolicy {
    /// Every run (capped by `maxCatchUpRuns`).
    #[default]
    All,
    /// Only the most recent run of each job; the earlier ones are recorded as skipped.
    Latest,
    /// None: due runs are recorded as skipped and the job continues from now.
    None,
}

impl CatchUpPolicy {
    /// Parses the configuration value.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "all" => Some(Self::All),
            "latest" => Some(Self::Latest),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

struct ScheduledJob {
    function: String,
    region: String,
    schedule: Schedule,
    zone: crate::zone::SharedZone,
    /// Runs strictly after this instant are due.
    cursor: LogicalInstant,
}

/// What happens when a schedule comes due while a previous run of the same function is
/// still running or queued (spec 11.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverlapPolicy {
    /// Enqueue anyway (production behaviour).
    #[default]
    Allow,
    /// Drop the due run (recorded in the history as skipped).
    Skip,
    /// Enqueue, but never run two invocations of the function at once.
    Queue,
    /// Treat the overlap as a test failure: the run is dead-lettered and counted.
    Reject,
}

impl OverlapPolicy {
    /// Parses the configuration value.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "skip" => Some(Self::Skip),
            "queue" => Some(Self::Queue),
            "reject" => Some(Self::Reject),
            _ => None,
        }
    }
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

/// A retained diagnostic record with the position a reader resumes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencedRecord {
    /// Position in the runtime's diagnostic stream. Strictly increasing, never reused, and
    /// unaffected by eviction, so two identical records are still told apart.
    pub sequence: u64,
    /// The record itself.
    pub record: InvocationRecord,
}

/// Where a reader of the diagnostic history left off.
///
/// The generation is the runtime epoch the position belongs to. A reset bumps it, so a cursor
/// taken before a reset is refused and the reader starts again from a snapshot rather than
/// interpreting the new session's records as a continuation of the old one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryCursor {
    /// Runtime epoch the position belongs to.
    pub generation: u64,
    /// Sequence of the last record the reader has.
    pub sequence: u64,
}

/// The answer to [`FunctionsRuntime::history_since`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistorySlice {
    /// The cursor to pass next time.
    pub cursor: HistoryCursor,
    /// The records after the cursor that was given, or the whole retained window on a resync.
    pub records: Vec<SequencedRecord>,
    /// Whether the cursor could not be honoured (another generation, or older than the
    /// retained window) and `records` is a fresh snapshot rather than a delta.
    pub resync: bool,
}

/// A bounded diagnostic log: the newest `retention` records, each with its sequence.
#[derive(Debug)]
struct RecordLog {
    records: std::collections::VecDeque<SequencedRecord>,
    retention: usize,
    /// The sequence of the newest record ever appended, eviction included.
    last: u64,
    /// The oldest sequence still retained; when the log is empty, one past `last`.
    oldest: u64,
}

impl RecordLog {
    fn new(retention: usize) -> Self {
        Self {
            records: std::collections::VecDeque::new(),
            retention: retention.max(1),
            last: 0,
            oldest: 1,
        }
    }

    fn push(&mut self, sequence: u64, record: InvocationRecord) {
        self.records.push_back(SequencedRecord { sequence, record });
        self.last = sequence;
        self.trim();
    }

    fn set_retention(&mut self, retention: usize) {
        self.retention = retention.max(1);
        self.trim();
    }

    fn trim(&mut self) {
        while self.records.len() > self.retention {
            self.records.pop_front();
        }
        self.oldest = self.records.front().map_or(self.last + 1, |r| r.sequence);
    }

    fn window(&self) -> Vec<InvocationRecord> {
        self.records.iter().map(|r| r.record.clone()).collect()
    }

    /// The records after `sequence`, or `None` when some of them have been evicted.
    fn since(&self, sequence: u64) -> Option<Vec<SequencedRecord>> {
        if sequence > self.last || sequence + 1 < self.oldest {
            return None;
        }
        Some(
            self.records
                .iter()
                .filter(|r| r.sequence > sequence)
                .cloned()
                .collect(),
        )
    }
}

struct Inner {
    outbox: Outbox,
    payloads: BTreeMap<EventId, (String, Value)>,
    /// Invocations occupying a slot, keyed by invocation key (`<event>-<attempt>` or
    /// `http-<n>`) with the function name; a timed-out handler keeps its slot until it
    /// really finishes.
    running: BTreeMap<String, String>,
    next_event: u64,
    epoch: Epoch,
    jobs: Vec<ScheduledJob>,
    /// The retained window of invocation records.
    history: RecordLog,
    /// The retained window of dead letters.
    dead_letters: RecordLog,
    /// Next sequence for a diagnostic record; shared by both logs, never reset.
    next_sequence: u64,
    /// Successful invocations since the runtime started. Survives eviction.
    succeeded_total: u64,
    /// Dead-lettered invocations and overlap rejections since the runtime started. Survives
    /// eviction.
    dead_lettered_total: u64,
    /// Schedule runs became due beyond the catch-up cap and still have to be enqueued.
    catch_up_pending: bool,
    /// Schedule search steps taken by the `latest` / `none` catch-up policies since the
    /// runtime started; the deterministic work counter the complexity bound is asserted with.
    catch_up_steps: u64,
    /// Schedule runs refused by the `reject` overlap policy.
    overlap_rejected: u64,
    /// Events held back by a `delay` fault until the virtual clock reaches the instant,
    /// with the outcome the same rule set decided for them.
    delayed: BTreeMap<EventId, Held>,
}

impl Inner {
    /// Appends an invocation record, giving it the next sequence and counting a success. The
    /// cumulative counter is kept outside the log, so it stays exact once records are evicted.
    fn record_invocation(&mut self, record: InvocationRecord) {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        if record.outcome == "ok" {
            self.succeeded_total += 1;
        }
        self.history.push(sequence, record);
    }

    /// Appends a dead letter, giving it the next sequence and counting it.
    fn record_dead_letter(&mut self, record: InvocationRecord) {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.dead_lettered_total += 1;
        self.dead_letters.push(sequence, record);
    }
}

/// What a completion did to the event's record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Retirement {
    /// Terminal and successful: the payload is no longer needed.
    Retired,
    /// Retry-waiting or given back to the queue: the payload stays.
    StillActive,
    /// Terminal after the last attempt: the payload goes and a dead letter is recorded.
    DeadLettered,
}

/// An event a `delay` fault holds back.
struct Held {
    /// When it may go.
    until: LogicalInstant,
    /// The outcome decided alongside the delay (an error, a dead letter, ...), if any.
    outcome: Option<(InvokeOutcome, bool)>,
    /// Whether the runner crashes when it goes.
    crash: bool,
}

/// The runtime.
pub struct FunctionsRuntime {
    manifest: FunctionManifest,
    config: FunctionsConfig,
    clock: Arc<Mutex<VirtualClock>>,
    runner: std::sync::RwLock<Arc<Runner>>,
    /// How to restart the runner after a reset; without it a reset only kills it.
    spawn: Option<SpawnSpec>,
    inner: Mutex<Inner>,
    wake: Notify,
    idle: Arc<Notify>,
    retry: RetryPolicy,
    /// The session's fault plan, when one is shared.
    faults: Mutex<Option<fireemu_core_session::fault::SharedFaults>>,
    /// The callable trust boundary, when the callable trusted protocol is active
    /// (specification section 13.4). `None` leaves the pre-App-Check behaviour untouched.
    callable_trust: std::sync::RwLock<Option<Arc<crate::callable::CallableTrust>>>,
    /// Whether background (event) triggers deliver, toggled by the Emulator Hub's
    /// `PUT /functions/{disable,enable}BackgroundTriggers`. Disabled means **dropped**:
    /// a Firestore, Storage, Pub/Sub or Auth event that arrives while it is off is never
    /// enqueued, so re-enabling delivers nothing retroactively. That is what the official
    /// emulator does -- its background-trigger route answers `204 "Background triggers are
    /// currently disabled."` and discards the body -- and it is the property the switch
    /// exists for: seeding data must not fire the triggers a later test asserts on.
    ///
    /// HTTP and callable invocations, manual `functions/{name}:run` requests and virtual
    /// clock schedule runs are unaffected: none of them is a data-change delivery.
    background_triggers: std::sync::atomic::AtomicBool,
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
        spawn: Option<SpawnSpec>,
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
                zone: crate::zone::resolve(tz)
                    .unwrap_or_else(|_| Arc::new(fireemu_core_functions::cron::FixedOffset(0))),
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
            runner: std::sync::RwLock::new(runner),
            spawn,
            inner: Mutex::new(Inner {
                outbox: Outbox::new(),
                payloads: BTreeMap::new(),
                running: BTreeMap::new(),
                next_event: 0,
                epoch: Epoch::initial(),
                jobs,
                history: RecordLog::new(MAX_RETAINED_INVOCATIONS),
                dead_letters: RecordLog::new(MAX_RETAINED_DEAD_LETTERS),
                next_sequence: 1,
                succeeded_total: 0,
                dead_lettered_total: 0,
                catch_up_pending: false,
                catch_up_steps: 0,
                overlap_rejected: 0,
                delayed: BTreeMap::new(),
            }),
            wake: Notify::new(),
            idle: Arc::new(Notify::new()),
            retry,
            faults: Mutex::new(None),
            callable_trust: std::sync::RwLock::new(None),
            background_triggers: std::sync::atomic::AtomicBool::new(true),
        })
    }

    /// The manifest.
    #[must_use]
    pub fn manifest(&self) -> &FunctionManifest {
        &self.manifest
    }

    /// The project the functions belong to.
    #[must_use]
    pub fn project(&self) -> &str {
        &self.config.project
    }

    /// The current runner.
    #[must_use]
    pub fn runner(&self) -> Arc<Runner> {
        match self.runner.read() {
            Ok(r) => r.clone(),
            Err(e) => e.into_inner().clone(),
        }
    }

    /// The virtual-clock instant a request is decided at.
    #[must_use]
    pub fn now(&self) -> LogicalInstant {
        self.clock
            .lock()
            .map(|c| c.now())
            .unwrap_or(LogicalInstant::UNIX_EPOCH)
    }

    /// Shares the session's fault plan with this runtime.
    pub fn set_faults(&self, faults: fireemu_core_session::fault::SharedFaults) {
        if let Ok(mut slot) = self.faults.lock() {
            *slot = Some(faults);
        }
    }

    fn faults(&self) -> Option<fireemu_core_session::fault::SharedFaults> {
        self.faults.lock().ok().and_then(|f| f.clone())
    }

    /// Activates the callable trusted protocol (specification section 13.4).
    ///
    /// Installed after the runner started but before the functions listener serves anything,
    /// because the App Check gate is built from the same configuration that decides whether the
    /// runner may run in debug mode at all.
    pub fn set_callable_trust(&self, trust: Arc<crate::callable::CallableTrust>) {
        if let Ok(mut slot) = self.callable_trust.write() {
            *slot = Some(trust);
        }
    }

    /// The callable trust boundary, when the trusted protocol is active.
    #[must_use]
    pub fn callable_trust(&self) -> Option<Arc<crate::callable::CallableTrust>> {
        self.callable_trust.read().ok().and_then(|t| t.clone())
    }

    /// Turns background (event) trigger delivery on or off, as the Emulator Hub's
    /// `PUT /functions/{disable,enable}BackgroundTriggers` routes do.
    ///
    /// Disabling drops what arrives while it is off. Events already accepted keep their
    /// place in the outbox and are still delivered and retried, exactly as upstream's
    /// `disableBackgroundTriggers` drains the work queue it had already taken on.
    pub fn set_background_triggers(&self, enabled: bool) {
        self.background_triggers
            .store(enabled, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether background (event) triggers deliver.
    #[must_use]
    pub fn background_triggers_enabled(&self) -> bool {
        self.background_triggers
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The callable's declared `enforceAppCheck`, or `None` when the function is not a
    /// callable at all (an `onRequest` function never gets an automatic decision, spec 7.3).
    #[must_use]
    pub fn callable_enforces_app_check(&self, function: &str) -> Option<bool> {
        match self.manifest.get(function).map(|f| &f.trigger) {
            Some(Trigger::Http {
                callable: true,
                enforce_app_check,
                ..
            }) => Some(*enforce_app_check),
            _ => None,
        }
    }

    /// Enqueues an event for `function`, plus the extra deliveries a `duplicate` fault
    /// asks for.
    #[allow(clippy::too_many_arguments)]
    fn enqueue_delivery(
        &self,
        inner: &mut Inner,
        source: EventSource,
        function: &str,
        event_type: &str,
        subject: &str,
        time: LogicalInstant,
        payload: &Value,
    ) {
        let mut copies = 1u32;
        for action in fireemu_core_session::fault::decide_shared(
            self.faults().as_ref(),
            "functions.deliver",
            Some(function),
            Some(event_type),
        ) {
            if let fireemu_core_session::fault::FaultAction::Duplicate { count } = action {
                copies = copies.saturating_add(count);
            }
        }
        for _ in 0..copies {
            Self::enqueue(
                inner,
                self.config.session,
                source,
                function,
                event_type,
                subject.to_owned(),
                time,
                payload.clone(),
            );
        }
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
        if !self.background_triggers_enabled() {
            return; // dropped, never held for a later replay
        }
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
                    fireemu_core_functions::manifest::DocumentEvent::Written
                ) {
                    *declared
                } else {
                    kind
                };
                let with_auth = matches!(
                    &m.function.trigger,
                    Trigger::Firestore {
                        with_auth_context: true,
                        ..
                    }
                );
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
                    with_auth.then_some((
                        commit.actor.auth_type.as_str(),
                        commit.actor.auth_id.as_deref(),
                    )),
                );
                payload["params"] = json!(m.params);
                let event_type = payload
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or(reported.event_type())
                    .to_owned();
                self.enqueue_delivery(
                    &mut inner,
                    EventSource::Firestore,
                    &m.function.name,
                    &event_type,
                    &format!("documents/{relative}"),
                    time,
                    &payload,
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
        if !self.background_triggers_enabled() {
            return; // dropped, never held for a later replay
        }
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
            self.enqueue_delivery(
                &mut inner,
                EventSource::Storage,
                &f.name,
                kind.event_type(),
                &format!("objects/{}", object.name.as_str()),
                time,
                &payload,
            );
            enqueued = true;
        }
        drop(inner);
        if enqueued {
            self.wake.notify_one();
        }
    }

    /// Publishes messages on `topic`: one event per message and subscribed function.
    /// Returns the message IDs (assigned even when nothing is subscribed, as Pub/Sub does).
    pub fn publish(&self, topic: &str, messages: &[Value]) -> Vec<String> {
        let time = self.now();
        let Ok(mut inner) = self.inner.lock() else {
            return Vec::new();
        };
        let mut ids = Vec::with_capacity(messages.len());
        let mut enqueued = false;
        let deliver = self.background_triggers_enabled();
        for message in messages {
            inner.next_event += 1;
            let message_id = format!("{}-{}", self.config.session.value(), inner.next_event);
            ids.push(message_id.clone());
            if !deliver {
                continue; // the message is accepted and dropped, as Pub/Sub does without a subscriber
            }
            for f in self.manifest.pubsub_matches(topic) {
                let payload = pubsub_event(&message_id, &self.config.project, topic, message, time);
                self.enqueue_delivery(
                    &mut inner,
                    EventSource::PubSub,
                    &f.name,
                    "google.cloud.pubsub.topic.v1.messagePublished",
                    &format!("topics/{topic}"),
                    time,
                    &payload,
                );
                enqueued = true;
            }
        }
        drop(inner);
        if enqueued {
            self.wake.notify_one();
        }
        ids
    }

    /// Turns a user lifecycle event into events for every matching Auth trigger.
    pub fn on_user_event(&self, event: &UserEvent) {
        if !self.background_triggers_enabled() {
            return; // dropped, never held for a later replay
        }
        let kind = match event.kind {
            UserEventKind::Created => AuthEvent::Created,
            UserEventKind::Deleted => AuthEvent::Deleted,
        };
        let time = self.now();
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let mut enqueued = false;
        for f in self.manifest.auth_matches(kind) {
            let id = format!("{}-{}", self.config.session.value(), inner.next_event + 1);
            let payload = auth_event(&id, &self.config.project, kind, &event.user, time);
            self.enqueue_delivery(
                &mut inner,
                EventSource::Auth,
                &f.name,
                kind.event_type(),
                &format!("users/{}", event.user.local_id.as_str()),
                time,
                &payload,
            );
            enqueued = true;
        }
        drop(inner);
        if enqueued {
            self.wake.notify_one();
        }
    }

    /// Enqueues the schedule runs that became due up to the current virtual time according
    /// to the catch-up policy and releases due retries. `all` enqueues every run into the
    /// vacant catch-up capacity (the remainder stays due and keeps the session busy);
    /// `latest` enqueues one run per job, the most recent; `none` enqueues nothing.
    ///
    /// `latest` and `none` answer the due window directly (a reverse search for the run they
    /// would keep and a count that stops at the catch-up cap) instead of enumerating every
    /// missed occurrence, so the time this holds the runtime lock does not grow with the size
    /// of the clock jump. What they drop is recorded as one skipped record per job and clock
    /// change, carrying a count that is exact up to the cap and "at least" beyond it.
    #[allow(clippy::too_many_lines)]
    pub fn on_clock_changed(&self) {
        let now = self.now();
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let mut enqueued = false;
        let policy = self.config.catch_up;
        let cap = self.config.max_catch_up_runs.max(1);
        let room = cap.saturating_sub(inner.payloads.len());
        if policy == CatchUpPolicy::All && room == 0 && inner.catch_up_pending {
            return;
        }
        let chunk = room.max(1);
        let mut pending = false;
        let mut steps = 0u64;
        let mut runs: Vec<(String, String, LogicalInstant)> = Vec::new();
        let mut skipped: Vec<(String, RunCount)> = Vec::new();
        for job in &mut inner.jobs {
            match policy {
                CatchUpPolicy::All => {
                    let due = job.schedule.runs_between_in(
                        job.cursor,
                        now,
                        &*job.zone,
                        chunk.saturating_add(1),
                    );
                    if due.len() > chunk {
                        // Beyond the cap: enqueue `chunk` runs now and leave the cursor at
                        // the last one so the rest stays due instead of vanishing.
                        let kept: Vec<LogicalInstant> = due.into_iter().take(chunk).collect();
                        job.cursor = kept.last().copied().unwrap_or(job.cursor);
                        pending = true;
                        runs.extend(
                            kept.into_iter()
                                .map(|t| (job.function.clone(), job.region.clone(), t)),
                        );
                    } else {
                        if now.as_nanos() > job.cursor.as_nanos() {
                            job.cursor = now;
                        }
                        runs.extend(
                            due.into_iter()
                                .map(|t| (job.function.clone(), job.region.clone(), t)),
                        );
                    }
                }
                CatchUpPolicy::Latest | CatchUpPolicy::None => {
                    // Neither policy keeps more than one run, so the due window is answered
                    // directly instead of enumerated: a reverse search for the run `latest`
                    // would keep, and a count that stops at the cap. The work no longer grows
                    // with the number of occurrences the clock jumped over.
                    let window = job
                        .schedule
                        .window_in(job.cursor, now, &*job.zone, cap as u64);
                    steps = steps.saturating_add(window.steps);
                    if now.as_nanos() > job.cursor.as_nanos() {
                        job.cursor = now;
                    }
                    let dropped = match (policy, window.latest) {
                        (CatchUpPolicy::Latest, Some(t)) => {
                            runs.push((job.function.clone(), job.region.clone(), t));
                            window.count.saturating_sub(1)
                        }
                        (CatchUpPolicy::None, Some(_)) => window.count,
                        _ => RunCount::Exact(0),
                    };
                    if !dropped.is_zero() {
                        skipped.push((job.function.clone(), dropped));
                    }
                }
            }
        }
        inner.catch_up_pending = pending;
        inner.catch_up_steps = inner.catch_up_steps.saturating_add(steps);
        let label = match policy {
            CatchUpPolicy::Latest => "latest",
            _ => "none",
        };
        // One record per job and clock change summarises what the policy dropped: the count
        // is exact up to the catch-up cap and "at least" beyond it, so neither the work nor
        // the retained history grows with the size of the jump.
        for (function, count) in skipped {
            inner.record_invocation(InvocationRecord {
                event_id: 0,
                function,
                attempt: 0,
                outcome: format!("skipped: catch-up {label} ({count})"),
            });
        }
        for (function, region, at) in runs {
            if !self.admit_scheduled_run(&mut inner, &function) {
                continue;
            }
            let id = format!("{}-{}", self.config.session.value(), inner.next_event + 1);
            let payload = schedule_event(&id, &self.config.project, &region, &function, at);
            self.enqueue_delivery(
                &mut inner,
                EventSource::Scheduler,
                &function,
                "google.cloud.scheduler.job.v1.executed",
                &format!("jobs/{function}"),
                at,
                &payload,
            );
            enqueued = true;
        }
        // Events a `delay` fault held back became due with the clock.
        if inner.delayed.values().any(|h| h.until <= now) {
            enqueued = true;
        }
        for id in inner.outbox.retries_due(now) {
            if inner.outbox.update(id, |r| r.retry_due(now)).is_ok() {
                enqueued = true;
            }
        }
        drop(inner);
        if enqueued {
            self.wake.notify_one();
        }
    }

    /// The `functions.invoke` faults for one dispatch of `id`: an outcome to report instead
    /// of invoking (with the retry flag to apply), and whether to crash the runner. A
    /// `delay` records the instant the event may go.
    fn invoke_faults(
        inner: &mut Inner,
        id: EventId,
        spec: &FunctionSpec,
        faults: Option<&fireemu_core_session::fault::SharedFaults>,
        now: LogicalInstant,
    ) -> (Option<(InvokeOutcome, bool)>, bool) {
        use fireemu_core_session::fault::FaultAction;
        let mut outcome: Option<(InvokeOutcome, bool)> = None;
        let mut crash = false;
        for action in fireemu_core_session::fault::decide_shared(
            faults,
            "functions.invoke",
            Some(&spec.name),
            None,
        ) {
            match action {
                FaultAction::Delay { seconds } => {
                    let until = now
                        .checked_add(LogicalDuration::from_seconds(seconds.max(0)))
                        .unwrap_or(now);
                    inner.delayed.insert(
                        id,
                        Held {
                            until,
                            outcome: None,
                            crash: false,
                        },
                    );
                }
                FaultAction::ReturnError { code } => {
                    outcome = Some((
                        InvokeOutcome::Failed(format!("fault plan: {code}")),
                        spec.retry,
                    ));
                }
                FaultAction::Timeout => outcome = Some((InvokeOutcome::TimedOut, spec.retry)),
                FaultAction::DeadLetter => {
                    outcome = Some((
                        InvokeOutcome::Failed("fault plan: dead letter".to_owned()),
                        false,
                    ));
                }
                FaultAction::TransactionConflict | FaultAction::DropConnection => {
                    outcome = Some((
                        InvokeOutcome::Failed(format!("fault plan: {action}")),
                        spec.retry,
                    ));
                }
                FaultAction::CrashRunner => crash = true,
                FaultAction::Duplicate { .. } => {}
            }
        }
        // A delay keeps the other actions of the same rule set for when the event goes.
        if let Some(held) = inner.delayed.get_mut(&id) {
            held.outcome.clone_from(&outcome);
            held.crash = crash;
        }
        (outcome, crash)
    }

    /// Applies the overlap policy to a due run of `function`: `true` when it may be
    /// enqueued. `queue` always enqueues (dispatch serialises it); `skip` and `reject`
    /// refuse while a run of the function is queued or running.
    fn admit_scheduled_run(&self, inner: &mut Inner, function: &str) -> bool {
        let busy = inner.running.values().any(|f| f == function)
            || inner.payloads.values().any(|(f, _)| f == function);
        match self.config.overlap {
            OverlapPolicy::Skip if busy => {
                inner.record_invocation(InvocationRecord {
                    event_id: 0,
                    function: function.to_owned(),
                    attempt: 0,
                    outcome: "skipped: overlap".to_owned(),
                });
                false
            }
            OverlapPolicy::Reject if busy => {
                inner.overlap_rejected += 1;
                inner.record_dead_letter(InvocationRecord {
                    event_id: 0,
                    function: function.to_owned(),
                    attempt: 0,
                    outcome: "rejected: overlap".to_owned(),
                });
                false
            }
            OverlapPolicy::Allow
            | OverlapPolicy::Queue
            | OverlapPolicy::Skip
            | OverlapPolicy::Reject => true,
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
        if !self.admit_scheduled_run(&mut inner, function) {
            return Err(format!(
                "a run of {function:?} is already queued or running (scheduler.overlap = {:?})",
                self.config.overlap
            ));
        }
        let id = format!("{}-{}", self.config.session.value(), inner.next_event + 1);
        let payload = schedule_event(&id, &self.config.project, &f.region, function, now);
        self.enqueue_delivery(
            &mut inner,
            EventSource::Manual,
            function,
            "google.cloud.scheduler.job.v1.executed",
            &format!("jobs/{function}"),
            now,
            &payload,
        );
        drop(inner);
        self.wake.notify_one();
        Ok(())
    }

    /// Session reset: the runner is killed (a handler still running must not write into the
    /// reset session) and restarted from its spec, every non-terminal event is discarded,
    /// and schedules restart from now. Dispatch resumes when the new runner is up.
    pub fn reset(self: &Arc<Self>) {
        let now = self.now();
        let mut generation = None;
        if let Ok(mut inner) = self.inner.lock() {
            inner.epoch = inner.epoch.next().unwrap_or(inner.epoch);
            let epoch = inner.epoch;
            generation = Some(epoch);
            // Killed under the same lock the restart installs under: a replacement from an
            // earlier reset cannot slip in between the bump and the kill.
            self.runner().kill_now();
            inner.outbox.discard_stale(epoch);
            inner.payloads.clear();
            inner.running.clear();
            inner.delayed.clear();
            inner.catch_up_pending = false;
            for job in &mut inner.jobs {
                job.cursor = now;
            }
        }
        self.respawn_runner(generation);
        self.idle.notify_waiters();
        self.wake.notify_one();
    }

    /// Restarts the runner from its spec for `generation` (a later reset supersedes it).
    fn respawn_runner(self: &Arc<Self>, generation: Option<Epoch>) {
        if let Some(spec) = self.spawn.clone() {
            let runtime = self.clone();
            tokio::spawn(async move {
                match Runner::spawn_spec(&spec).await {
                    Ok(runner) => {
                        // A later reset supersedes this restart: its own replacement is
                        // the runner of record and this one must not outlive the kill.
                        // Checked and installed under the runtime lock (the lock a reset
                        // bumps the epoch and kills under), so the two cannot interleave.
                        let installed = match runtime.inner.lock() {
                            Ok(inner) if Some(inner.epoch) == generation => {
                                if let Ok(mut slot) = runtime.runner.write() {
                                    *slot = Arc::new(runner);
                                }
                                true
                            }
                            _ => {
                                runner.kill_now();
                                false
                            }
                        };
                        if installed {
                            runtime.wake.notify_one();
                        }
                    }
                    Err(e) => eprintln!("[functions] runner restart failed: {e}"),
                }
            });
        }
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
        self.runner().is_alive()
    }

    /// Outstanding work, for `await-idle` timeouts and status output.
    #[must_use]
    pub fn status(&self) -> Value {
        let Ok(inner) = self.inner.lock() else {
            return json!({});
        };
        let mut pending = 0;
        let mut retry_waiting = 0;
        for id in inner.payloads.keys() {
            if let Some(r) = inner.outbox.record(*id) {
                match r.state() {
                    EventState::Pending | EventState::Leased => pending += 1,
                    EventState::RetryWaiting { .. } => retry_waiting += 1,
                    _ => {}
                }
            }
        }
        // `succeeded` and `deadLettered` are cumulative and counted as the records are made,
        // so evicting the diagnostic window never moves them.
        json!({
            "pending": pending,
            "running": inner.running.len(),
            "retryWaiting": retry_waiting,
            "succeeded": inner.succeeded_total,
            "deadLettered": inner.dead_lettered_total,
            "catchUpPending": inner.catch_up_pending,
            "overlapRejected": inner.overlap_rejected,
            "timeZoneDatabase": crate::zone::database_version(),
            "runnerAlive": self.runner().is_alive(),
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

    /// Schedule search steps the `latest` and `none` catch-up policies have taken since the
    /// runtime started. It is bounded per clock change by the schedules and the catch-up cap,
    /// never by the number of occurrences the clock jumped over; tests hold that bound.
    #[must_use]
    pub fn catch_up_steps(&self) -> u64 {
        self.inner.lock().map(|i| i.catch_up_steps).unwrap_or(0)
    }

    /// The retained window of invocation records, oldest first. Records older than the
    /// retention budget ([`MAX_RETAINED_INVOCATIONS`]) are no longer there; the cumulative
    /// counters in [`Self::status`] still account for them.
    #[must_use]
    pub fn history(&self) -> Vec<InvocationRecord> {
        self.inner
            .lock()
            .map(|i| i.history.window())
            .unwrap_or_default()
    }

    /// The retained window of dead letters, oldest first ([`MAX_RETAINED_DEAD_LETTERS`]).
    #[must_use]
    pub fn dead_letters(&self) -> Vec<InvocationRecord> {
        self.inner
            .lock()
            .map(|i| i.dead_letters.window())
            .unwrap_or_default()
    }

    /// The invocation records after `cursor`, for a reader that follows the history
    /// incrementally (the UI log stream).
    ///
    /// `None` asks for a snapshot of the retained window. A cursor from another generation, or
    /// one older than the retained window, cannot be answered with a delta: the whole window
    /// comes back with `resync` set, and the reader replaces what it holds. The returned
    /// cursor is the position to pass next time.
    #[must_use]
    pub fn history_since(&self, cursor: Option<HistoryCursor>) -> HistorySlice {
        let Ok(inner) = self.inner.lock() else {
            return HistorySlice {
                cursor: HistoryCursor {
                    generation: 0,
                    sequence: 0,
                },
                records: Vec::new(),
                resync: true,
            };
        };
        let generation = inner.epoch.value();
        let delta = cursor
            .filter(|c| c.generation == generation)
            .and_then(|c| inner.history.since(c.sequence));
        let (records, resync) = match delta {
            Some(records) => (records, false),
            None => (
                inner.history.records.iter().cloned().collect::<Vec<_>>(),
                cursor.is_some(),
            ),
        };
        let sequence = records
            .last()
            .map_or_else(|| inner.history.last, |r| r.sequence);
        HistorySlice {
            cursor: HistoryCursor {
                generation,
                sequence,
            },
            records,
            resync,
        }
    }

    /// Sets the diagnostic retention budget: how many invocation records and dead letters the
    /// runtime keeps. The defaults are [`MAX_RETAINED_INVOCATIONS`] and
    /// [`MAX_RETAINED_DEAD_LETTERS`]; lowering it drops the oldest records at once.
    pub fn set_retention(&self, invocations: usize, dead_letters: usize) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.history.set_retention(invocations);
            inner.dead_letters.set_retention(dead_letters);
        }
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
        let port = self.runner().hello().http_port?;
        Some(HttpTarget {
            function: function.to_owned(),
            addr: format!("127.0.0.1:{port}"),
        })
    }

    /// Proxies one HTTP request to the runner, counting it as running work.
    pub async fn invoke_http(
        self: &Arc<Self>,
        target: &HttpTarget,
        method: &str,
        path_and_query: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<ProxiedResponse, String> {
        let (timeout, concurrency) = self.manifest.get(&target.function).map_or((60, 1), |f| {
            (u64::from(f.timeout_seconds), f.concurrency as usize)
        });
        // The fault plan applies to HTTP invocations like to event ones (spec 18): an
        // error answers instead of the handler, a delay moves the clock first, a crash
        // takes the runner down.
        if let Some(faulted) = self.http_faults(&target.function) {
            if let Ok(mut inner) = self.inner.lock() {
                inner.next_event += 1;
                let event_id = inner.next_event;
                inner.record_invocation(InvocationRecord {
                    event_id: u128::from(event_id),
                    function: target.function.clone(),
                    attempt: 1,
                    outcome: match &faulted {
                        Ok(r) => format!("fault plan: http {}", r.status),
                        Err(e) => format!("failed: {e}"),
                    },
                });
            }
            return faulted;
        }
        let (id, key) = {
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
            let key = format!("http-{}", inner.next_event);
            inner.running.insert(key.clone(), target.function.clone());
            (id, key)
        };
        // The slot is released even if the client disconnects and this future is dropped.
        let _admission = Admission { runtime: self, key };
        // The runner secret is ours to add; a caller-supplied copy never passes through. The
        // same goes for the emulator-internal fields `firebase-functions` honours under
        // `skipTokenVerification` to override v1 callable auth context: no client legitimately
        // sends them, and one that does is trying to forge `context.auth`.
        let mut forwarded: Vec<(String, String)> = headers
            .iter()
            .filter(|(k, _)| {
                !crate::callable::ALWAYS_STRIPPED
                    .iter()
                    .any(|owned| k.eq_ignore_ascii_case(owned))
            })
            .cloned()
            .collect();
        forwarded.push((
            "x-fireemu-runner-secret".to_owned(),
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
            inner.record_invocation(InvocationRecord {
                event_id: id.value(),
                function: target.function.clone(),
                attempt: 1,
                outcome,
            });
        }
        match result {
            Ok(r) => r,
            Err(_) => Err(format!(
                "function {} did not answer within {timeout}s",
                target.function
            )),
        }
    }

    /// The `functions.invoke` faults for an HTTP invocation of `function`: the answer to
    /// give instead of calling the handler, if any.
    fn http_faults(self: &Arc<Self>, function: &str) -> Option<Result<ProxiedResponse, String>> {
        use fireemu_core_session::fault::FaultAction;
        let mut answer = None;
        for action in fireemu_core_session::fault::decide_shared(
            self.faults().as_ref(),
            "functions.invoke",
            Some(function),
            None,
        ) {
            match action {
                FaultAction::Delay { seconds } => {
                    if let Ok(mut clock) = self.clock.lock() {
                        let _ = clock.advance(LogicalDuration::from_seconds(seconds.max(0)));
                    }
                    self.on_clock_changed();
                }
                FaultAction::ReturnError { code } => {
                    answer = Some(Ok(ProxiedResponse {
                        status: http_status(&code),
                        headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
                        body: format!("fault plan: {function} returns {code}").into_bytes(),
                    }));
                }
                FaultAction::Timeout => {
                    answer = Some(Err(format!("fault plan: function {function} timed out")));
                }
                FaultAction::CrashRunner => {
                    let generation = self.inner.lock().ok().map(|i| i.epoch);
                    self.runner().kill_now();
                    self.respawn_runner(generation);
                    answer = Some(Err(format!(
                        "fault plan: the runner crashed while serving {function}"
                    )));
                }
                FaultAction::DropConnection => {
                    answer = Some(Err(DROP_CONNECTION.to_owned()));
                }
                FaultAction::DeadLetter | FaultAction::TransactionConflict => {
                    answer = Some(Err(format!("fault plan: {action}")));
                }
                FaultAction::Duplicate { .. } => {}
            }
        }
        answer
    }

    /// The dispatch loop: run it as a task for the runtime's lifetime.
    pub async fn dispatch_loop(self: Arc<Self>) {
        loop {
            self.dispatch_ready();
            self.wake.notified().await;
        }
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch_ready(self: &Arc<Self>) {
        // The runner checked here is the one every invocation of this pass goes to: an event
        // leased before a reset must not reach the runner spawned after it.
        let runner = self.runner();
        if !runner.is_alive() {
            // Queued work stays pending and visible in the status; nothing is retried
            // against a dead process.
            return;
        }
        let now = self.now();
        let faults = self.faults();
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
            let limit = if self.config.overlap == OverlapPolicy::Queue
                && matches!(spec.trigger, Trigger::Schedule { .. })
            {
                1
            } else {
                spec.concurrency as usize
            };
            if running_here >= limit {
                continue;
            }
            // A `delay` fault holds the event until the virtual clock reaches the instant;
            // the plan is consulted once per dispatch attempt, not on every pass over a
            // held event.
            let (fault_outcome, crash) = match inner.delayed.get(&id) {
                Some(held) if now < held.until => continue,
                Some(_) => inner
                    .delayed
                    .remove(&id)
                    .map_or((None, false), |h| (h.outcome, h.crash)),
                None => {
                    let decided = Self::invoke_faults(&mut inner, id, spec, faults.as_ref(), now);
                    if inner.delayed.get(&id).is_some_and(|held| now < held.until) {
                        continue;
                    }
                    inner.delayed.remove(&id);
                    decided
                }
            };
            let leased = inner.outbox.update(id, |record| {
                if record.lease().is_err() || record.start().is_err() {
                    return None;
                }
                Some((record.attempt(), record.event().epoch))
            });
            let Ok(Some((attempt, epoch))) = leased else {
                continue;
            };
            let Some((_, payload)) = inner.payloads.get(&id) else {
                continue;
            };
            let request = self.invoke_request(id, spec, attempt, epoch, payload);
            let key = format!("{}-{attempt}", id.value());
            inner.running.insert(key.clone(), function_name.clone());
            let runtime = self.clone();
            let runner = runner.clone();
            let timeout = Duration::from_secs(u64::from(spec.timeout_seconds));
            let retry = spec.retry;
            if crash {
                // The runner dies mid-invocation: the attempt is given back (RunnerGone) and
                // a fresh runner takes over, as after a crashed instance.
                runner.kill_now();
                let generation = Some(inner.epoch);
                self.respawn_runner(generation);
            }
            tokio::spawn(async move {
                let Invocation { outcome, late } = match fault_outcome {
                    Some((outcome, retry_override)) => {
                        runtime.complete(
                            id,
                            &key,
                            &function_name,
                            attempt,
                            epoch,
                            retry_override,
                            &outcome,
                        );
                        runtime.release(&key);
                        return;
                    }
                    None => runner.invoke(request, timeout).await,
                };
                runtime.complete(id, &key, &function_name, attempt, epoch, retry, &outcome);
                match late {
                    // The handler is still running: its slot stays taken until it finishes
                    // (or the runner dies), so idle and concurrency stay truthful.
                    Some(late) => {
                        let _ = late.await;
                        runtime.release(&key);
                    }
                    None => runtime.release(&key),
                }
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
            Trigger::PubSub { .. } => "pubsub",
            Trigger::Auth { .. } => "auth",
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

    /// Frees an invocation slot.
    fn release(&self, key: &str) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.running.remove(key);
        }
        self.idle.notify_waiters();
        self.wake.notify_one();
    }

    #[allow(clippy::too_many_arguments)]
    fn complete(
        &self,
        id: EventId,
        key: &str,
        function: &str,
        attempt: u32,
        epoch: Epoch,
        retry: bool,
        outcome: &InvokeOutcome,
    ) {
        let now = self.now();
        let _ = key;
        if let Ok(mut inner) = self.inner.lock() {
            // ADR-011: the captured epoch is validated before any observable mutation. Work
            // that resolves after a reset belongs to a session that no longer exists, so it
            // appends neither an invocation record nor a dead letter to the new epoch; only
            // the payload kept for the running invocation goes.
            if inner.epoch != epoch {
                inner.payloads.remove(&id);
                drop(inner);
                self.idle.notify_waiters();
                self.wake.notify_one();
                return;
            }
            let text = match &outcome {
                InvokeOutcome::Ok => "ok".to_owned(),
                InvokeOutcome::Failed(e) => format!("failed: {e}"),
                InvokeOutcome::TimedOut => "timeout".to_owned(),
                InvokeOutcome::RunnerGone(e) => format!("runner gone: {e}"),
            };
            inner.record_invocation(InvocationRecord {
                event_id: id.value(),
                function: function.to_owned(),
                attempt,
                outcome: text.clone(),
            });
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
            // `Retired` means the event reached a terminal state and its payload is no longer
            // needed; `DeadLettered` adds the diagnostic record. Decided inside the outbox
            // update so the record's state and the indexes move together.
            let outcome_of_record = inner.outbox.update(id, |record| {
                if matches!(outcome, InvokeOutcome::Ok) {
                    let _ = record.succeed();
                    Retirement::Retired
                } else if matches!(outcome, InvokeOutcome::RunnerGone(_)) {
                    // Infrastructure failure: the attempt is given back and the event waits,
                    // pending, for a runner (dispatch stops while the runner is dead).
                    let _ = record.interrupt();
                    Retirement::StillActive
                } else if matches!(
                    record.fail(&policy, now),
                    Ok(FailureOutcome::RetryScheduled { .. })
                ) {
                    Retirement::StillActive
                } else {
                    Retirement::DeadLettered
                }
            });
            match outcome_of_record {
                Ok(Retirement::Retired) => {
                    inner.payloads.remove(&id);
                }
                Ok(Retirement::DeadLettered) => {
                    inner.payloads.remove(&id);
                    inner.record_dead_letter(InvocationRecord {
                        event_id: id.value(),
                        function: function.to_owned(),
                        attempt,
                        outcome: text,
                    });
                }
                Ok(Retirement::StillActive) | Err(_) => {}
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

/// The error an HTTP invocation reports for a `dropConnection` fault: the functions port
/// closes the client's connection instead of answering.
pub const DROP_CONNECTION: &str = "fault plan: connection dropped";

/// An HTTP status from a number or a gRPC code name (fault plan `returnError`).
fn http_status(code: &str) -> u16 {
    if let Ok(n) = code.parse::<u16>() {
        return n;
    }
    match code.to_ascii_uppercase().as_str() {
        "INVALID_ARGUMENT" | "FAILED_PRECONDITION" | "OUT_OF_RANGE" => 400,
        "UNAUTHENTICATED" => 401,
        "PERMISSION_DENIED" => 403,
        "NOT_FOUND" => 404,
        "ALREADY_EXISTS" | "ABORTED" => 409,
        "RESOURCE_EXHAUSTED" => 429,
        "CANCELLED" => 499,
        "UNIMPLEMENTED" => 501,
        "UNAVAILABLE" => 503,
        "DEADLINE_EXCEEDED" => 504,
        _ => 500,
    }
}

/// Holds an HTTP invocation's slot; dropping it (normal completion or a cancelled request
/// future) frees the slot and wakes the dispatcher and idle waiters.
struct Admission<'a> {
    runtime: &'a FunctionsRuntime,
    key: String,
}

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        self.runtime.release(&self.key);
    }
}
