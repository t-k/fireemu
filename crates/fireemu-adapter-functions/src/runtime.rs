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
use fireemu_core_types::resources::{
    Gauge, Refusal, RetentionRoot, RootBudget, ServiceResources, Unit,
};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};
use tokio::sync::Notify;

use crate::events::{
    auth_event, change_kind, firestore_event, pubsub_event, schedule_event, storage_event,
};
use crate::http::{
    forward, forward_stream, ProxiedResponse, ProxiedStreamResponse, StreamCompletion,
    StreamStartError,
};
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
/// Maximum non-terminal event records retained by one Functions runtime.
pub const MAX_ACTIVE_EVENT_RECORDS: usize = 4096;
/// Logical events whose causal phases the runtime keeps for `await-idle` diagnostics
/// (spec 10.5). Older entries are evicted and counted; eviction is never a completion.
pub const MAX_CAUSALITY_ENTRIES: usize = 512;
/// Phase transitions kept per causal entry; further ones are counted as dropped.
const MAX_CAUSALITY_PHASES: usize = 32;
/// Causal entries one status projection lists, unfinished ones first.
const MAX_CAUSALITY_PROJECTED: usize = 64;
/// Maximum serialized payload and routing bytes retained by non-terminal event records.
pub const MAX_ACTIVE_EVENT_BYTES: usize = 64 * 1024 * 1024;
/// Eventarc's share, leaving capacity for Firestore, Storage, Auth, Pub/Sub and schedules.
pub const MAX_ACTIVE_EVENTARC_RECORDS: usize = 3072;
/// Eventarc's byte share, leaving 16 MiB for other trigger sources.
pub const MAX_ACTIVE_EVENTARC_BYTES: usize = 48 * 1024 * 1024;
/// Maximum deliveries one Eventarc publication may add after duplicate fault expansion.
pub const MAX_EVENTARC_DELIVERIES_PER_PUBLISH: usize = 256;

async fn forward_with_debug_deadline(
    debug_mode: bool,
    timeout: Duration,
    addr: &str,
    method: &str,
    path_and_query: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<Result<ProxiedResponse, String>, tokio::time::error::Elapsed> {
    if debug_mode {
        Ok(forward(addr, method, path_and_query, headers, body).await)
    } else {
        tokio::time::timeout(
            timeout,
            forward(addr, method, path_and_query, headers, body),
        )
        .await
    }
}

fn runner_headers(headers: &[(String, String)], secret: &str) -> Vec<(String, String)> {
    let mut forwarded: Vec<_> = headers
        .iter()
        .filter(|(key, _)| {
            !crate::callable::ALWAYS_STRIPPED
                .iter()
                .any(|owned| key.eq_ignore_ascii_case(owned))
        })
        .cloned()
        .collect();
    forwarded.push(("x-fireemu-runner-secret".to_owned(), secret.to_owned()));
    forwarded
}

/// One HTTP function the proxy can reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpTarget {
    /// Function name.
    pub function: String,
    /// Runner HTTP address.
    pub addr: String,
}

/// The two response shapes an SSE-capable HTTP invocation can produce.
pub enum HttpStreamStart {
    /// A fault or pre-header timeout that can still be returned as a complete response.
    Buffered(ProxiedResponse),
    /// Runner bytes that must be forwarded incrementally.
    Streaming(ProxiedStreamResponse),
}

/// Internal loopback target for an Identity Platform blocking function.
#[derive(Clone)]
pub struct BlockingAuthTarget {
    /// Exported function name.
    pub function: String,
    /// Function region used by the runner route.
    pub region: String,
    /// Runner HTTP address.
    pub addr: String,
    /// Per-runner proxy secret.
    pub secret: String,
    /// Raw credential fields requested by this exact admitted target generation.
    pub token_policy: fireemu_core_functions::manifest::BlockingAuthTokenPolicy,
    runner: Arc<Runner>,
    revision: u64,
    owner: usize,
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
    /// Whether debugger mode disables handler deadlines.
    pub debug_mode: bool,
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
    /// The functions listener's own `host:port`, when it is bound. A Cloud Tasks queue's
    /// `defaultUri` is the function's public URL, so the runtime has to know its own address
    /// to build one and to recognise a task that named it explicitly.
    pub functions_host: Option<String>,
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

/// One phase of a logical event's life, on the virtual clock.
#[derive(Debug, Clone)]
struct CausalPhase {
    phase: &'static str,
    attempt: u32,
    at: LogicalInstant,
}

/// The bounded causal record of one logical event: what registered it (the source operation,
/// never a payload), which function it targets, and the phases it went through. It is written
/// after the event is registered atomically with its source (F1), so it never describes an
/// event that admission refused.
#[derive(Debug, Clone)]
struct CausalEntry {
    event_id: u128,
    epoch: u64,
    source: EventSource,
    event_type: String,
    function: String,
    parent: Option<String>,
    terminal: bool,
    phases: Vec<CausalPhase>,
    phases_dropped: u32,
}

/// The runtime's bounded causality window.
#[derive(Debug)]
struct CausalityLog {
    entries: BTreeMap<u128, CausalEntry>,
    order: std::collections::VecDeque<u128>,
    retention: usize,
    evicted: u64,
    reset_gaps: u64,
}

impl CausalityLog {
    fn new(retention: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            order: std::collections::VecDeque::new(),
            retention: retention.max(1),
            evicted: 0,
            reset_gaps: 0,
        }
    }

    fn register(&mut self, mut entry: CausalEntry, at: LogicalInstant) {
        entry.phases.push(CausalPhase {
            phase: "registered",
            attempt: 0,
            at,
        });
        let id = entry.event_id;
        if self.entries.insert(id, entry).is_none() {
            self.order.push_back(id);
        }
        while self.order.len() > self.retention {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
                self.evicted = self.evicted.saturating_add(1);
            }
        }
    }

    fn transition(
        &mut self,
        id: u128,
        phase: &'static str,
        attempt: u32,
        at: LogicalInstant,
        terminal: bool,
    ) {
        let Some(entry) = self.entries.get_mut(&id) else {
            return;
        };
        if entry.phases.len() >= MAX_CAUSALITY_PHASES {
            entry.phases_dropped = entry.phases_dropped.saturating_add(1);
        } else {
            entry.phases.push(CausalPhase { phase, attempt, at });
        }
        entry.terminal |= terminal;
    }

    /// A reset discards the old epoch's entries: nothing in them completed, they are a gap.
    fn reset(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.reset_gaps = self.reset_gaps.saturating_add(1);
    }

    fn set_retention(&mut self, retention: usize) {
        self.retention = retention.max(1);
        while self.order.len() > self.retention {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
                self.evicted = self.evicted.saturating_add(1);
            }
        }
    }

    /// The projection `status()` publishes: unfinished entries first, at most
    /// [`MAX_CAUSALITY_PROJECTED`], with the counters that say what the window does not show.
    fn project(&self, epoch: u64) -> Value {
        let mut listed: Vec<&CausalEntry> = self
            .order
            .iter()
            .filter_map(|id| self.entries.get(id))
            .filter(|entry| !entry.terminal)
            .collect();
        listed.extend(
            self.order
                .iter()
                .filter_map(|id| self.entries.get(id))
                .filter(|entry| entry.terminal),
        );
        let truncated = listed.len() > MAX_CAUSALITY_PROJECTED;
        listed.truncate(MAX_CAUSALITY_PROJECTED);
        json!({
            "epoch": epoch,
            "retained": self.entries.len(),
            "retention": self.retention,
            "evicted": self.evicted,
            "resetGaps": self.reset_gaps,
            "truncated": truncated,
            "events": listed.iter().map(|entry| json!({
                "eventId": entry.event_id.to_string(),
                "epoch": entry.epoch,
                "source": source_name(entry.source),
                "eventType": entry.event_type,
                "function": entry.function,
                "parent": entry.parent,
                "terminal": entry.terminal,
                "phasesDropped": entry.phases_dropped,
                "phases": entry.phases.iter().map(|phase| json!({
                    "phase": phase.phase,
                    "attempt": phase.attempt,
                    "at": phase.at.to_rfc3339().ok(),
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        })
    }
}

fn source_name(source: EventSource) -> &'static str {
    match source {
        EventSource::Firestore => "firestore",
        EventSource::Storage => "storage",
        EventSource::Scheduler => "scheduler",
        EventSource::Manual => "manual",
        EventSource::PubSub => "pubsub",
        EventSource::Auth => "auth",
        EventSource::Eventarc => "eventarc",
    }
}

struct Inner {
    /// Bounded per-function Cloud Tasks queues and conservative retained-data accounting.
    task_scheduler: crate::task_scheduler::TaskScheduler,
    /// Supplies the id of a task that did not name itself.
    next_task: u64,
    outbox: Outbox,
    payloads: BTreeMap<EventId, QueuedPayload>,
    active_event_bytes: usize,
    reserved_event_records: usize,
    reserved_event_bytes: usize,
    active_eventarc_records: usize,
    active_eventarc_bytes: usize,
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
    /// Source-event admissions refused since the last reset, by category.
    admission_refusals: BTreeMap<&'static str, u64>,
    /// Events held back by a `delay` fault until the virtual clock reaches the instant,
    /// with the outcome the same rule set decided for them.
    delayed: BTreeMap<EventId, Held>,
    /// Bounded causal phases of registered events (`await-idle` diagnostics).
    causality: CausalityLog,
}

struct QueuedPayload {
    function: String,
    payload: Arc<Value>,
    retained_bytes: usize,
    source: EventSource,
}

struct PlannedDelivery {
    event: LogicalEvent,
    payload: QueuedPayload,
    /// The source operation that produced the event (`firestore-commit:<db>@<version>`,
    /// `storage-generation:<n>`), for the causality window. Never a payload.
    parent: Option<String>,
}

struct DeliveryDraft {
    function: String,
    event_type: String,
    subject: String,
    time: LogicalInstant,
    payload: Arc<Value>,
    parent: Option<String>,
}

/// A complete, capacity-charged batch of source-trigger deliveries that remains invisible
/// until its source mutation has been published.
pub struct EventBatchReservation {
    runtime: std::sync::Weak<FunctionsRuntime>,
    epoch: Epoch,
    deliveries: Option<Vec<PlannedDelivery>>,
    retained_bytes: usize,
}

/// Exact logical-event ownership used by atomic source adapters and formal projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceEventAccounting {
    /// Deliveries charged to source mutations that have not published or cancelled yet.
    pub reserved_records: usize,
    /// Published deliveries that still retain their payload in the runtime.
    pub published_records: usize,
    /// Session generation that owns both sets.
    pub epoch: Epoch,
}

impl EventBatchReservation {
    /// Publishes every reserved delivery without re-matching triggers, re-serializing payloads,
    /// or performing another admission decision.
    pub fn publish(mut self) {
        let Some(deliveries) = self.deliveries.take() else {
            return;
        };
        if deliveries.is_empty() {
            return;
        }
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        let mut inner = runtime
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner.epoch != self.epoch {
            return;
        }
        release_event_reservation(&mut inner, deliveries.len(), self.retained_bytes);
        for delivery in deliveries {
            let id = delivery.event.event_id;
            inner.causality.register(
                CausalEntry {
                    event_id: id.value(),
                    epoch: delivery.event.epoch.value(),
                    source: delivery.event.source,
                    event_type: delivery.event.event_type.as_str().to_owned(),
                    function: delivery.payload.function.clone(),
                    parent: delivery.parent,
                    terminal: false,
                    phases: Vec::new(),
                    phases_dropped: 0,
                },
                delivery.event.logical_time,
            );
            inner
                .outbox
                .enqueue(delivery.event)
                .unwrap_or_else(|_| unreachable!("a reserved event id is unique"));
            inner.active_event_bytes = inner
                .active_event_bytes
                .saturating_add(delivery.payload.retained_bytes);
            inner.payloads.insert(id, delivery.payload);
        }
        drop(inner);
        runtime.idle.notify_waiters();
        runtime.wake.notify_one();
    }
}

impl Drop for EventBatchReservation {
    fn drop(&mut self) {
        let Some(deliveries) = self.deliveries.take() else {
            return;
        };
        if deliveries.is_empty() {
            return;
        }
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        let mut inner = runtime
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner.epoch == self.epoch {
            release_event_reservation(&mut inner, deliveries.len(), self.retained_bytes);
        }
        drop(inner);
        runtime.idle.notify_waiters();
    }
}

fn release_event_reservation(inner: &mut Inner, records: usize, bytes: usize) {
    inner.reserved_event_records = inner.reserved_event_records.saturating_sub(records);
    inner.reserved_event_bytes = inner.reserved_event_bytes.saturating_sub(bytes);
}

/// Why a source mutation could not reserve all of its logical deliveries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceEventAdmissionError {
    /// The complete fan-out would exceed the bounded logical outbox.
    Capacity,
    /// Runtime state is unavailable.
    Unavailable,
    /// A generated logical event was invalid.
    InvalidEvent,
}

/// A bounded Eventarc publication refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventarcPublishError {
    /// The event type cannot become a logical event.
    InvalidEvent,
    /// The per-publication or active-runtime budget would be exceeded.
    Capacity,
    /// Runtime state is unavailable.
    Unavailable,
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

/// One codebase, as it was handed to the runtime: its name, its own manifest and the runner
/// process that serves it.
pub struct CodebaseSpec {
    /// `codebase` from `firebase.json`, `default` when the project names none.
    pub name: String,
    /// What this codebase's runner discovered.
    pub manifest: FunctionManifest,
    /// The runner process serving it.
    pub runner: Arc<Runner>,
    /// How to restart it after a reset; without it a reset only kills it.
    pub spawn: Option<SpawnSpec>,
    /// Immutable source snapshot retained for this runner generation, if hot-reloaded.
    pub cleanup_dir: Option<std::path::PathBuf>,
}

/// A loaded codebase and its live runner.
struct Codebase {
    name: String,
    manifest: FunctionManifest,
    generation: std::sync::RwLock<CodebaseGeneration>,
}

struct CodebaseGeneration {
    revision: u64,
    runner: Arc<Runner>,
    spawn: Option<SpawnSpec>,
    cleanup_dir: Option<Arc<CleanupDir>>,
    blocking_restart_ticket: Option<Arc<()>>,
}

/// One atomic view of the generation a restart is replacing. Keeping the runner, spawn
/// specification, revision and source owner together prevents reload from changing the
/// generation between a crash and its replacement being selected.
struct RespawnGeneration {
    runner: Arc<Runner>,
    spawn: Option<SpawnSpec>,
    revision: u64,
    cleanup_dir: Option<Arc<CleanupDir>>,
}

struct CleanupDir(std::path::PathBuf);

impl Drop for CleanupDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Codebase {
    fn generation(&self) -> std::sync::RwLockReadGuard<'_, CodebaseGeneration> {
        self.generation
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn generation_mut(&self) -> std::sync::RwLockWriteGuard<'_, CodebaseGeneration> {
        self.generation
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn capture_respawn(&self) -> RespawnGeneration {
        let current = self.generation();
        RespawnGeneration {
            runner: current.runner.clone(),
            spawn: current.spawn.clone(),
            revision: current.revision,
            cleanup_dir: current.cleanup_dir.clone(),
        }
    }
}

impl CodebaseGeneration {
    fn cleanup(path: Option<std::path::PathBuf>) -> Option<Arc<CleanupDir>> {
        path.map(|path| Arc::new(CleanupDir(path)))
    }
}

/// Wall-clock milliseconds, for the one header that carries them.
fn epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The runtime.
///
/// A project may declare several Functions codebases (`functions` as an array in
/// `firebase.json`). Each gets its own runner process, exactly as the official emulator gives
/// each backend its own runtime worker pool, and one runtime multiplexes them: the manifests
/// are unioned so that every trigger match, schedule, retry and HTTP route is decided once,
/// and each function is invoked on the runner of the codebase that exported it.
pub struct FunctionsRuntime {
    /// The union of every codebase's manifest.
    manifest: FunctionManifest,
    config: FunctionsConfig,
    clock: Arc<Mutex<VirtualClock>>,
    /// The codebases, in configuration order.
    codebases: Vec<Codebase>,
    /// Function name to its codebase's index in `codebases`.
    owner: BTreeMap<String, usize>,
    /// Live Eventarc registrations, linearized with publication and source reload.
    eventarc_registry: Mutex<crate::eventarc::TriggerRegistry>,
    inner: Mutex<Inner>,
    /// Only active Cloud Tasks dispatches own Tokio tasks. Reset and shutdown replace this set,
    /// which aborts every old-generation attempt and its retry timer.
    task_attempts: Mutex<tokio::task::JoinSet<()>>,
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
    /// How many times the sources have been reloaded (`triggerGeneration`). It is part of an
    /// event trigger's key, which the 404 for an unknown function lists.
    trigger_generation: std::sync::atomic::AtomicU64,
    /// Once set, no reload or respawn may install another child process.
    shutting_down: std::sync::atomic::AtomicBool,
    /// Set only after every source mutation that reserved a logical event batch has either
    /// published or cancelled it. The dispatcher remains alive during that handoff so a
    /// successful source write can never publish into an already stopped runtime.
    dispatch_stopping: std::sync::atomic::AtomicBool,
}

/// Generation-tagged cleanup for one active task dispatch. Dropping the future because of a
/// reset, shutdown or panic releases only the exact scheduler entry it leased.
struct TaskCompletion {
    runtime: std::sync::Weak<FunctionsRuntime>,
    queue: String,
    id: u64,
    generation: u64,
    failed: bool,
}

impl Drop for TaskCompletion {
    fn drop(&mut self) {
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        let finished = runtime.inner.lock().is_ok_and(|mut inner| {
            inner.task_scheduler.finish_with_outcome(
                &self.queue,
                self.id,
                self.generation,
                self.failed,
            )
        });
        if finished {
            runtime.idle.notify_waiters();
            runtime.wake.notify_one();
        }
    }
}

impl FunctionsRuntime {
    fn empty_event_reservation(self: &Arc<Self>) -> EventBatchReservation {
        EventBatchReservation {
            runtime: Arc::downgrade(self),
            epoch: Epoch::initial(),
            deliveries: Some(Vec::new()),
            retained_bytes: 0,
        }
    }
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
        Self::with_codebases(
            vec![CodebaseSpec {
                name: "default".to_owned(),
                manifest,
                runner,
                spawn,
                cleanup_dir: None,
            }],
            config,
            clock,
        )
        .expect("a single codebase cannot collide with itself")
    }

    /// Builds the runtime around one started runner per codebase.
    ///
    /// A function name that two codebases both export is refused here, naming both, because
    /// the emulator serves one function URL per region and name: whichever codebase happened
    /// to load second would otherwise take the name, silently, and the project would find out
    /// from the wrong handler running.
    pub fn with_codebases(
        codebases: Vec<CodebaseSpec>,
        config: FunctionsConfig,
        clock: Arc<Mutex<VirtualClock>>,
    ) -> Result<Arc<Self>, String> {
        let mut manifest = FunctionManifest::default();
        let mut owner: BTreeMap<String, usize> = BTreeMap::new();
        let mut declared_in: BTreeMap<String, String> = BTreeMap::new();
        for (index, codebase) in codebases.iter().enumerate() {
            for f in &codebase.manifest.functions {
                if let Some(first) = declared_in.get(&f.name) {
                    return Err(format!(
                        "the function {:?} is exported by two Functions codebases ({first} and \
                         {}); a function name is unique across the whole project, because the \
                         emulator serves one URL per region and name",
                        f.name, codebase.name
                    ));
                }
                declared_in.insert(f.name.clone(), codebase.name.clone());
                owner.insert(f.name.clone(), index);
                manifest.functions.push(f.clone());
            }
            manifest
                .ignored
                .extend(codebase.manifest.ignored.iter().cloned());
        }
        manifest
            .validate()
            .map_err(|e| format!("the loaded Functions codebases: {e}"))?;
        let eventarc_registry =
            crate::eventarc::TriggerRegistry::from_manifest(&config.project, &manifest, 0)?;
        Ok(Self::build(
            manifest,
            owner,
            codebases,
            config,
            clock,
            eventarc_registry,
        ))
    }

    fn build(
        manifest: FunctionManifest,
        owner: BTreeMap<String, usize>,
        codebases: Vec<CodebaseSpec>,
        config: FunctionsConfig,
        clock: Arc<Mutex<VirtualClock>>,
        eventarc_registry: crate::eventarc::TriggerRegistry,
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
        let task_scheduler = crate::task_scheduler::TaskScheduler::from_manifest(
            &manifest,
            std::time::Instant::now(),
        );
        Arc::new(Self {
            manifest,
            config,
            clock,
            codebases: codebases
                .into_iter()
                .map(|c| Codebase {
                    name: c.name,
                    manifest: c.manifest,
                    generation: std::sync::RwLock::new(CodebaseGeneration {
                        revision: 0,
                        runner: c.runner,
                        spawn: c.spawn,
                        cleanup_dir: CodebaseGeneration::cleanup(c.cleanup_dir),
                        blocking_restart_ticket: None,
                    }),
                })
                .collect(),
            owner,
            eventarc_registry: Mutex::new(eventarc_registry),
            inner: Mutex::new(Inner {
                task_scheduler,
                next_task: 0,
                outbox: Outbox::new(),
                payloads: BTreeMap::new(),
                active_event_bytes: 0,
                reserved_event_records: 0,
                reserved_event_bytes: 0,
                active_eventarc_records: 0,
                active_eventarc_bytes: 0,
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
                admission_refusals: BTreeMap::new(),
                delayed: BTreeMap::new(),
                causality: CausalityLog::new(MAX_CAUSALITY_ENTRIES),
            }),
            task_attempts: Mutex::new(tokio::task::JoinSet::new()),
            wake: Notify::new(),
            idle: Arc::new(Notify::new()),
            retry,
            faults: Mutex::new(None),
            callable_trust: std::sync::RwLock::new(None),
            background_triggers: std::sync::atomic::AtomicBool::new(true),
            trigger_generation: std::sync::atomic::AtomicU64::new(0),
            shutting_down: std::sync::atomic::AtomicBool::new(false),
            dispatch_stopping: std::sync::atomic::AtomicBool::new(false),
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

    /// Configured process-wide Functions concurrency budget.
    #[must_use]
    pub fn max_global_concurrency(&self) -> usize {
        self.config.max_running
    }

    /// The current runner of the first codebase.
    ///
    /// Kept for the single-codebase case, which is every project that does not spell
    /// `functions` as an array. Anything that acts on behalf of one function goes through
    /// [`Self::runner_for`] instead.
    #[must_use]
    pub fn runner(&self) -> Arc<Runner> {
        self.runner_at(0)
    }

    fn runner_at(&self, index: usize) -> Arc<Runner> {
        self.codebases[index.min(self.codebases.len().saturating_sub(1))]
            .generation()
            .runner
            .clone()
    }

    /// The runner of the codebase that exported `function`.
    #[must_use]
    pub fn runner_for(&self, function: &str) -> Arc<Runner> {
        self.runner_at(self.owner.get(function).copied().unwrap_or(0))
    }

    /// The codebase names, in configuration order.
    #[must_use]
    pub fn codebase_names(&self) -> Vec<&str> {
        self.codebases.iter().map(|c| c.name.as_str()).collect()
    }

    /// The current runner generation for every codebase, in configuration order.
    ///
    /// Callers that own process-wide concerns such as logging and shutdown must use this view
    /// rather than the single-codebase compatibility accessor [`Self::runner`]. A hot reload may
    /// replace an `Arc<Runner>`, so long-lived callers should refresh this snapshot periodically.
    #[must_use]
    pub fn current_runners(&self) -> Vec<(String, Arc<Runner>)> {
        self.codebases
            .iter()
            .map(|codebase| (codebase.name.clone(), codebase.generation().runner.clone()))
            .collect()
    }

    /// Closes admission while allowing already reserved source mutations to finish publishing.
    pub fn begin_shutdown(&self) {
        // Reservation admission reads this flag while holding `inner`. Taking the same lock
        // makes this method's return the linearization boundary: a reservation charged before
        // it returns is owned and awaited; one attempting afterward observes the closed flag.
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.shutting_down
            .store(true, std::sync::atomic::Ordering::SeqCst);
        drop(inner);
        self.wake.notify_one();
        self.idle.notify_waiters();
    }

    /// Shuts down every current codebase runner concurrently.
    pub async fn shutdown(&self) {
        self.begin_shutdown();
        let mut retired_attempts = {
            let mut attempts = self
                .task_attempts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Ok(mut inner) = self.inner.lock() {
                inner.task_scheduler.close(std::time::Instant::now());
            }
            std::mem::take(&mut *attempts)
        };
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .inner
                .lock()
                .map(|inner| inner.reserved_event_records == 0)
                .unwrap_or(true)
            {
                break;
            }
            notified.await;
        }
        // Admission is closed and every source mutation has completed its publish/cancel
        // handoff. Only now may the dispatch loop stop and the runners be terminated.
        self.dispatch_stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        retired_attempts.shutdown().await;
        // There is exactly one dispatch loop. A stored permit also covers the narrow window
        // between its shutdown check and awaiting the notification.
        self.wake.notify_one();
        self.idle.notify_waiters();
        let mut shutdowns = tokio::task::JoinSet::new();
        for (_, runner) in self.current_runners() {
            shutdowns.spawn(async move { runner.shutdown().await });
        }
        while shutdowns.join_next().await.is_some() {}
    }

    /// The codebase that exported `function`.
    #[must_use]
    pub fn codebase_of(&self, function: &str) -> Option<&str> {
        self.owner
            .get(function)
            .map(|i| self.codebases[*i].name.as_str())
    }

    /// Replaces one codebase's runner after a successful discovery handshake.
    ///
    /// This first hot-reload boundary intentionally requires the discovered trigger manifest
    /// to stay identical. Handler code and environment change atomically with the runner;
    /// adding or removing triggers keeps the last-known-good generation rather than exposing
    /// a new Node export behind stale Rust routing.
    pub fn reload_codebase(&self, spec: CodebaseSpec) -> Result<u64, String> {
        if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            spec.runner.kill_now();
            if let Some(path) = spec.cleanup_dir {
                let _ = std::fs::remove_dir_all(path);
            }
            return Err("the Functions runtime is shutting down".to_owned());
        }
        let Some(codebase) = self
            .codebases
            .iter()
            .find(|codebase| codebase.name == spec.name)
        else {
            spec.runner.kill_now();
            if let Some(path) = spec.cleanup_dir {
                let _ = std::fs::remove_dir_all(path);
            }
            return Err(format!("unknown Functions codebase {:?}", spec.name));
        };
        if codebase.manifest != spec.manifest {
            spec.runner.kill_now();
            if let Some(path) = spec.cleanup_dir {
                let _ = std::fs::remove_dir_all(path);
            }
            return Err(format!(
                "Functions codebase {:?} changed its trigger manifest; the last-known-good generation remains active",
                spec.name
            ));
        }
        let Ok(mut eventarc_registry) = self.eventarc_registry.lock() else {
            spec.runner.kill_now();
            if let Some(path) = &spec.cleanup_dir {
                let _ = std::fs::remove_dir_all(path);
            }
            return Err("the Eventarc trigger registry is unavailable".to_owned());
        };
        let generation = self
            .trigger_generation
            .load(std::sync::atomic::Ordering::SeqCst)
            .saturating_add(1);
        let next_eventarc_registry = match crate::eventarc::TriggerRegistry::from_manifest(
            self.project(),
            &self.manifest,
            generation,
        ) {
            Ok(registry) => registry,
            Err(error) => {
                spec.runner.kill_now();
                if let Some(path) = &spec.cleanup_dir {
                    let _ = std::fs::remove_dir_all(path);
                }
                return Err(error);
            }
        };
        let old = {
            let mut generation = codebase.generation_mut();
            if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
                spec.runner.kill_now();
                if let Some(path) = spec.cleanup_dir {
                    let _ = std::fs::remove_dir_all(path);
                }
                return Err("the Functions runtime is shutting down".to_owned());
            }
            let revision = generation.revision.saturating_add(1);
            std::mem::replace(
                &mut *generation,
                CodebaseGeneration {
                    revision,
                    runner: spec.runner,
                    spawn: spec.spawn,
                    cleanup_dir: CodebaseGeneration::cleanup(spec.cleanup_dir),
                    blocking_restart_ticket: None,
                },
            )
        };
        self.trigger_generation
            .store(generation, std::sync::atomic::Ordering::SeqCst);
        *eventarc_registry = next_eventarc_registry;
        drop(eventarc_registry);
        // In-flight invocations retain their `Arc`; killing after publication prevents any
        // new dispatch from reaching the old generation and reaps it promptly.
        old.runner.kill_now();
        drop(old);
        Ok(generation)
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
        let copies = self.delivery_copies(function, event_type);
        for _ in 0..copies {
            let _ = Self::enqueue(
                inner,
                self.config.session,
                source,
                function,
                event_type,
                subject,
                time,
                payload,
            );
        }
    }

    fn delivery_copies(&self, function: &str, event_type: &str) -> usize {
        let mut copies = 1usize;
        for action in fireemu_core_session::fault::decide_shared(
            self.faults().as_ref(),
            "functions.deliver",
            Some(function),
            Some(event_type),
        ) {
            if let fireemu_core_session::fault::FaultAction::Duplicate { count } = action {
                copies = copies.saturating_add(count as usize);
            }
        }
        copies.min(MAX_EVENTARC_DELIVERIES_PER_PUBLISH)
    }

    #[allow(clippy::too_many_arguments)]
    fn enqueue(
        inner: &mut Inner,
        session: SessionId,
        source: EventSource,
        function: &str,
        event_type: &str,
        subject: &str,
        time: LogicalInstant,
        payload: &Value,
    ) -> bool {
        let Some(retained_bytes) =
            Self::retained_event_bytes(function, event_type, subject, payload)
        else {
            return false;
        };
        if !Self::can_admit_events(inner, source, 1, retained_bytes) {
            *inner.admission_refusals.entry("capacity").or_default() += 1;
            return false;
        }
        inner.next_event += 1;
        let id = EventId::new(u128::from(inner.next_event));
        let Ok(event_type) = EventType::try_new(event_type) else {
            return false;
        };
        let event = LogicalEvent {
            event_id: id,
            session_id: session,
            epoch: inner.epoch,
            source,
            event_type,
            subject: subject.to_owned(),
            logical_time: time,
            causation_id: None,
            correlation_id: CorrelationId::new(u128::from(inner.next_event)),
            payload: Vec::new(),
        };
        let causal = CausalEntry {
            event_id: id.value(),
            epoch: inner.epoch.value(),
            source,
            event_type: event.event_type.as_str().to_owned(),
            function: function.to_owned(),
            parent: None,
            terminal: false,
            phases: Vec::new(),
            phases_dropped: 0,
        };
        if inner.outbox.enqueue(event).is_ok() {
            inner.causality.register(causal, time);
            inner.payloads.insert(
                id,
                QueuedPayload {
                    function: function.to_owned(),
                    payload: Arc::new(payload.clone()),
                    retained_bytes,
                    source,
                },
            );
            inner.active_event_bytes += retained_bytes;
            if source == EventSource::Eventarc {
                inner.active_eventarc_records += 1;
                inner.active_eventarc_bytes += retained_bytes;
            }
            true
        } else {
            false
        }
    }

    fn retained_event_bytes(
        function: &str,
        event_type: &str,
        subject: &str,
        payload: &Value,
    ) -> Option<usize> {
        Self::retained_event_bytes_from_payload_len(
            function,
            event_type,
            subject,
            serde_json::to_vec(payload).ok()?.len(),
        )
    }

    fn retained_event_bytes_from_payload_len(
        function: &str,
        event_type: &str,
        subject: &str,
        payload_bytes: usize,
    ) -> Option<usize> {
        payload_bytes
            .checked_add(function.len())?
            .checked_add(event_type.len())?
            .checked_add(subject.len())
    }

    fn can_admit_events(inner: &Inner, source: EventSource, count: usize, bytes: usize) -> bool {
        let global = inner
            .payloads
            .len()
            .checked_add(inner.reserved_event_records)
            .and_then(|used| used.checked_add(count))
            .is_some_and(|used| used <= MAX_ACTIVE_EVENT_RECORDS)
            && inner
                .active_event_bytes
                .checked_add(inner.reserved_event_bytes)
                .and_then(|used| used.checked_add(bytes))
                .is_some_and(|used| used <= MAX_ACTIVE_EVENT_BYTES);
        let source = source != EventSource::Eventarc
            || (inner
                .active_eventarc_records
                .checked_add(count)
                .is_some_and(|count| count <= MAX_ACTIVE_EVENTARC_RECORDS)
                && inner
                    .active_eventarc_bytes
                    .checked_add(bytes)
                    .is_some_and(|bytes| bytes <= MAX_ACTIVE_EVENTARC_BYTES));
        global && source
    }

    fn reserve_drafts(
        self: &Arc<Self>,
        source: EventSource,
        drafts: Vec<DeliveryDraft>,
        inner: &mut Inner,
    ) -> Result<EventBatchReservation, SourceEventAdmissionError> {
        // The outer source-specific check is a fast path. This check is linearized with the
        // reservation counters so shutdown cannot close admission between that check and the
        // capacity charge.
        if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(SourceEventAdmissionError::Unavailable);
        }
        let mut retained_bytes = 0usize;
        for draft in &drafts {
            EventType::try_new(&draft.event_type)
                .map_err(|_| SourceEventAdmissionError::InvalidEvent)?;
            let bytes = Self::retained_event_bytes(
                &draft.function,
                &draft.event_type,
                &draft.subject,
                &draft.payload,
            )
            .ok_or(SourceEventAdmissionError::Capacity)?;
            retained_bytes = retained_bytes
                .checked_add(bytes)
                .ok_or(SourceEventAdmissionError::Capacity)?;
        }
        if !Self::can_admit_events(inner, source, drafts.len(), retained_bytes) {
            return Err(SourceEventAdmissionError::Capacity);
        }
        let delivery_count =
            u64::try_from(drafts.len()).map_err(|_| SourceEventAdmissionError::Capacity)?;
        let final_event = inner
            .next_event
            .checked_add(delivery_count)
            .ok_or(SourceEventAdmissionError::Capacity)?;
        let next_reserved_records = inner
            .reserved_event_records
            .checked_add(drafts.len())
            .ok_or(SourceEventAdmissionError::Capacity)?;
        let next_reserved_bytes = inner
            .reserved_event_bytes
            .checked_add(retained_bytes)
            .ok_or(SourceEventAdmissionError::Capacity)?;

        let epoch = inner.epoch;
        let mut next_event = inner.next_event;
        let mut deliveries = Vec::with_capacity(drafts.len());
        for draft in drafts {
            next_event = next_event
                .checked_add(1)
                .ok_or(SourceEventAdmissionError::Capacity)?;
            let id = EventId::new(u128::from(next_event));
            let event_type = EventType::try_new(&draft.event_type)
                .map_err(|_| SourceEventAdmissionError::InvalidEvent)?;
            let retained_bytes = Self::retained_event_bytes(
                &draft.function,
                &draft.event_type,
                &draft.subject,
                &draft.payload,
            )
            .ok_or(SourceEventAdmissionError::Capacity)?;
            deliveries.push(PlannedDelivery {
                event: LogicalEvent {
                    event_id: id,
                    session_id: self.config.session,
                    epoch,
                    source,
                    event_type,
                    subject: draft.subject,
                    logical_time: draft.time,
                    causation_id: None,
                    correlation_id: CorrelationId::new(u128::from(next_event)),
                    payload: Vec::new(),
                },
                payload: QueuedPayload {
                    function: draft.function,
                    payload: draft.payload,
                    retained_bytes,
                    source,
                },
                parent: draft.parent,
            });
        }
        debug_assert_eq!(next_event, final_event);
        inner.next_event = final_event;
        inner.reserved_event_records = next_reserved_records;
        inner.reserved_event_bytes = next_reserved_bytes;
        Ok(EventBatchReservation {
            runtime: Arc::downgrade(self),
            epoch,
            deliveries: Some(deliveries),
            retained_bytes,
        })
    }

    fn remove_payload(inner: &mut Inner, id: EventId) {
        if let Some(payload) = inner.payloads.remove(&id) {
            inner.active_event_bytes = inner
                .active_event_bytes
                .saturating_sub(payload.retained_bytes);
            if payload.source == EventSource::Eventarc {
                inner.active_eventarc_records = inner.active_eventarc_records.saturating_sub(1);
                inner.active_eventarc_bytes = inner
                    .active_eventarc_bytes
                    .saturating_sub(payload.retained_bytes);
            }
        }
    }

    /// Reserves the complete Firestore trigger fan-out before the source commit is published.
    pub fn reserve_commit_events(
        self: &Arc<Self>,
        commit: &CommitEvent,
    ) -> Result<EventBatchReservation, SourceEventAdmissionError> {
        let reservation = self.reserve_commit_events_unmetered(commit);
        if let Err(error) = &reservation {
            self.note_admission_refusal(*error);
        }
        reservation
    }

    /// Counts a refused source-event admission for the resource report.
    fn note_admission_refusal(&self, error: SourceEventAdmissionError) {
        let category = match error {
            SourceEventAdmissionError::Capacity => "capacity",
            SourceEventAdmissionError::Unavailable => "unavailable",
            SourceEventAdmissionError::InvalidEvent => "invalid_event",
        };
        if let Ok(mut inner) = self.inner.lock() {
            *inner.admission_refusals.entry(category).or_default() += 1;
        }
    }

    #[allow(clippy::too_many_lines)]
    fn reserve_commit_events_unmetered(
        self: &Arc<Self>,
        commit: &CommitEvent,
    ) -> Result<EventBatchReservation, SourceEventAdmissionError> {
        if commit.project != self.config.project {
            return Ok(self.empty_event_reservation());
        }
        if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(SourceEventAdmissionError::Unavailable);
        }
        if !self.background_triggers_enabled() {
            return Ok(self.empty_event_reservation());
        }
        let Some(time) = commit.commit_time else {
            return Ok(self.empty_event_reservation());
        };
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| SourceEventAdmissionError::Unavailable)?;
        let mut drafts = Vec::new();
        let mut draft_bytes = 0usize;
        for change in commit.changes.iter() {
            let Some(kind) = change_kind(change.before.as_deref(), change.after.as_deref()) else {
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
                let next = inner
                    .next_event
                    .checked_add(u64::try_from(drafts.len()).unwrap_or(u64::MAX))
                    .and_then(|next| next.checked_add(1))
                    .ok_or(SourceEventAdmissionError::Capacity)?;
                let id = format!("{}-{next}", self.config.session.value());
                let mut payload = firestore_event(
                    &id,
                    &commit.project,
                    &commit.database,
                    &self.config.location,
                    &relative,
                    reported,
                    change.before.as_deref(),
                    change.after.as_deref(),
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
                let copies = self.delivery_copies(&m.function.name, &event_type);
                let subject = format!("documents/{relative}");
                let one_delivery =
                    Self::retained_event_bytes(&m.function.name, &event_type, &subject, &payload)
                        .ok_or(SourceEventAdmissionError::Capacity)?;
                draft_bytes = draft_bytes
                    .checked_add(
                        one_delivery
                            .checked_mul(copies)
                            .ok_or(SourceEventAdmissionError::Capacity)?,
                    )
                    .ok_or(SourceEventAdmissionError::Capacity)?;
                let draft_count = drafts
                    .len()
                    .checked_add(copies)
                    .ok_or(SourceEventAdmissionError::Capacity)?;
                if !Self::can_admit_events(&inner, EventSource::Firestore, draft_count, draft_bytes)
                {
                    return Err(SourceEventAdmissionError::Capacity);
                }
                let payload = Arc::new(payload);
                for _ in 0..copies {
                    drafts.push(DeliveryDraft {
                        function: m.function.name.clone(),
                        event_type: event_type.clone(),
                        subject: subject.clone(),
                        time,
                        payload: Arc::clone(&payload),
                        parent: Some(format!(
                            "firestore-commit:{}@{}",
                            commit.database, commit.version
                        )),
                    });
                }
            }
        }
        self.reserve_drafts(EventSource::Firestore, drafts, &mut inner)
    }

    /// Turns a Firestore commit into document events for every matching trigger.
    pub fn on_commit(self: &Arc<Self>, commit: &CommitEvent) {
        if let Ok(reservation) = self.reserve_commit_events(commit) {
            reservation.publish();
        }
    }

    /// Reserves the complete Storage trigger fan-out before the object mutation is published.
    pub fn reserve_storage_event(
        self: &Arc<Self>,
        event: &StorageEvent,
    ) -> Result<EventBatchReservation, SourceEventAdmissionError> {
        let reservation = self.reserve_storage_event_unmetered(event);
        if let Err(error) = &reservation {
            self.note_admission_refusal(*error);
        }
        reservation
    }

    fn reserve_storage_event_unmetered(
        self: &Arc<Self>,
        event: &StorageEvent,
    ) -> Result<EventBatchReservation, SourceEventAdmissionError> {
        if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(SourceEventAdmissionError::Unavailable);
        }
        if !self.background_triggers_enabled() {
            return Ok(self.empty_event_reservation());
        }
        let (kind, object) = match event {
            StorageEvent::Finalized(m) => (ObjectEvent::Finalized, m),
            StorageEvent::Deleted(m) => (ObjectEvent::Deleted, m),
            StorageEvent::MetadataUpdated(m) => (ObjectEvent::MetadataUpdated, m),
        };
        let time = self.now();
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| SourceEventAdmissionError::Unavailable)?;
        let mut drafts = Vec::new();
        let mut draft_bytes = 0usize;
        for f in
            self.manifest
                .storage_matches(object.bucket.as_str(), &self.config.default_bucket, kind)
        {
            let next = inner
                .next_event
                .checked_add(u64::try_from(drafts.len()).unwrap_or(u64::MAX))
                .and_then(|next| next.checked_add(1))
                .ok_or(SourceEventAdmissionError::Capacity)?;
            let id = format!("{}-{next}", self.config.session.value());
            let payload = storage_event(&id, kind, object, time);
            let event_type = kind.event_type().to_owned();
            let subject = format!("objects/{}", object.name.as_str());
            let copies = self.delivery_copies(&f.name, &event_type);
            let one_delivery = Self::retained_event_bytes(&f.name, &event_type, &subject, &payload)
                .ok_or(SourceEventAdmissionError::Capacity)?;
            draft_bytes = draft_bytes
                .checked_add(
                    one_delivery
                        .checked_mul(copies)
                        .ok_or(SourceEventAdmissionError::Capacity)?,
                )
                .ok_or(SourceEventAdmissionError::Capacity)?;
            let draft_count = drafts
                .len()
                .checked_add(copies)
                .ok_or(SourceEventAdmissionError::Capacity)?;
            if !Self::can_admit_events(&inner, EventSource::Storage, draft_count, draft_bytes) {
                return Err(SourceEventAdmissionError::Capacity);
            }
            let payload = Arc::new(payload);
            for _ in 0..copies {
                drafts.push(DeliveryDraft {
                    function: f.name.clone(),
                    event_type: event_type.clone(),
                    subject: subject.clone(),
                    time,
                    payload: Arc::clone(&payload),
                    parent: Some(format!("storage-generation:{}", object.generation)),
                });
            }
        }
        self.reserve_drafts(EventSource::Storage, drafts, &mut inner)
    }

    /// Turns a Storage object event into events for every matching trigger.
    pub fn on_storage_event(self: &Arc<Self>, event: &StorageEvent) {
        if let Ok(reservation) = self.reserve_storage_event(event) {
            reservation.publish();
        }
    }

    /// Reserves the complete Pub/Sub topic-trigger fan-out for broker messages that already have
    /// stable Pub/Sub message ids. The returned reservation is committed only after the broker
    /// publication becomes visible, so capacity refusal cannot lose a broker event.
    pub fn reserve_pubsub_events(
        self: &Arc<Self>,
        topic: &str,
        messages: &[Value],
    ) -> Result<EventBatchReservation, SourceEventAdmissionError> {
        if !self.background_triggers_enabled() {
            return Ok(self.empty_event_reservation());
        }
        let time = self.now();
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| SourceEventAdmissionError::Unavailable)?;
        let mut drafts = Vec::new();
        for message in messages {
            let message_id = message
                .get("messageId")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or(SourceEventAdmissionError::InvalidEvent)?;
            for function in self.manifest.pubsub_matches(topic) {
                let payload = Arc::new(pubsub_event(
                    message_id,
                    &self.config.project,
                    topic,
                    message,
                    time,
                ));
                let copies = self.delivery_copies(
                    &function.name,
                    "google.cloud.pubsub.topic.v1.messagePublished",
                );
                for _ in 0..copies {
                    drafts.push(DeliveryDraft {
                        function: function.name.clone(),
                        event_type: "google.cloud.pubsub.topic.v1.messagePublished".to_owned(),
                        subject: format!("topics/{topic}"),
                        time,
                        payload: Arc::clone(&payload),
                        parent: None,
                    });
                }
            }
        }
        let reservation = self.reserve_drafts(EventSource::PubSub, drafts, &mut inner);
        drop(inner);
        if let Err(error) = &reservation {
            self.note_admission_refusal(*error);
        }
        reservation
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

    /// Accepts one Cloud Tasks enqueue and starts delivering it.
    ///
    /// The queue is the function: the official emulator creates one queue per
    /// `onTaskDispatched` function at load time, keyed by the function's name, whose
    /// `defaultUri` is that function's own `/{project}/{region}/{name}` URL. There is nothing
    /// to create here, so the queue exists exactly while the function does, and an enqueue
    /// against a name that is not one answers the official `404`.
    pub fn enqueue_task(
        self: &Arc<Self>,
        project: &str,
        location: &str,
        queue: &str,
        body: &Value,
    ) -> Result<Value, crate::tasks::EnqueueRefusal> {
        use crate::task_scheduler::AdmissionError;
        use crate::tasks::EnqueueRefusal;
        let refuse = |status: u16, body: &str| EnqueueRefusal {
            status,
            body: body.to_owned(),
        };
        if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(refuse(503, "the Functions runtime is shutting down"));
        }
        if project != self.config.project {
            return Err(refuse(
                404,
                "Tried to queue a task from a non-existent queue",
            ));
        }
        let spec = self
            .manifest
            .get(queue)
            .filter(|f| matches!(f.trigger, Trigger::TaskQueue { .. }))
            .ok_or_else(|| refuse(404, "Tried to queue a task from a non-existent queue"))?;
        let Trigger::TaskQueue { retry, .. } = spec.trigger else {
            return Err(refuse(
                404,
                "Tried to queue a task from a non-existent queue",
            ));
        };
        if spec.region != location {
            return Err(refuse(
                404,
                "Tried to queue a task from a non-existent queue",
            ));
        }
        let host = self.config.functions_host.as_deref().ok_or_else(|| {
            refuse(
                503,
                "the functions listener is not bound, so a task queue has no default URI",
            )
        })?;
        let default_uri = format!("http://{host}/{project}/{location}/{queue}");
        let next_id = {
            let Ok(mut inner) = self.inner.lock() else {
                return Err(refuse(500, "runtime poisoned"));
            };
            inner.next_task += 1;
            inner.next_task
        };
        let task = crate::tasks::accept(project, location, queue, &default_uri, body, next_id)?;
        // A task may name its own URL (`opts.uri`). Only this emulator's own function URLs
        // are accepted: the official emulator will POST a task to any address, and a local
        // emulator that makes an arbitrary outbound request on a caller's say-so is a
        // request-forgery surface the rest of fireemu does not offer.
        if task.url != default_uri {
            return Err(refuse(
                400,
                "a task may only be dispatched to this emulator's own function URL",
            ));
        }
        // Precharge every per-task allocation that can exist during dispatch. Pending tasks
        // do not own these route strings yet, but reserving their eventual cost before
        // admission keeps activation from escaping the retained-data ceiling.
        let queue_key_bytes = crate::tasks::queue_key(project, location, queue).len();
        let retained_bytes = task
            .retained_bytes()
            .saturating_add(task.name.len())
            .saturating_add(queue.len().saturating_mul(3))
            .saturating_add(project.len())
            .saturating_add(location.len())
            .saturating_add(queue_key_bytes);
        let admission = self
            .inner
            .lock()
            .map_err(|_| refuse(500, "runtime poisoned"))?
            .task_scheduler
            .enqueue(queue, task.clone(), retry, retained_bytes);
        match admission {
            Ok(()) => {}
            Err(AdmissionError::Duplicate | AdmissionError::QueueFull) => {
                return Err(refuse(409, "A task with the same name already exists"));
            }
            Err(AdmissionError::RuntimeFull) => {
                return Err(refuse(429, "the local task queue capacity is exhausted"));
            }
            Err(AdmissionError::Closed) => {
                return Err(refuse(503, "the Functions runtime is shutting down"));
            }
        }
        let answer = crate::tasks::accepted_response(&task);
        self.wake.notify_one();
        Ok(answer)
    }

    /// Delivers one task, retrying on the official schedule until it succeeds or runs out.
    ///
    /// Backoff is real time, as it is upstream: the default unit is 100 ms, so three attempts
    /// cost 300 ms rather than a clock advance. That is the one place in this runtime where a
    /// wait is not on the virtual clock, and it is deliberate -- a task queue's retry policy
    /// is a wall-clock policy in production too.
    async fn dispatch_task(
        self: &Arc<Self>,
        dispatch: &crate::task_scheduler::Dispatch,
        epoch: Epoch,
    ) -> bool {
        let task = &dispatch.task;
        let mut started = None;
        let mut attempt = 1u32;
        let mut execution_count = 0u32;
        let mut previous: Option<u16> = None;
        let body = serde_json::to_vec(&task.body).unwrap_or_default();
        loop {
            // A reset supersedes every task accepted before it.
            if self.inner.lock().ok().map(|i| i.epoch) != Some(epoch) {
                return false;
            }
            if started.is_some_and(|first_delivery| {
                task_retry_exhausted(first_delivery, dispatch.retry, attempt)
            }) {
                eprintln!(
                    "[functions] task {:?} gave up after {} attempt(s)",
                    task.name,
                    attempt - 1
                );
                return true;
            }
            let Some(target) =
                self.http_target(&dispatch.project, &dispatch.region, &dispatch.function)
            else {
                eprintln!(
                    "[functions] task {:?}: {} is no longer served",
                    task.name, dispatch.function
                );
                return true;
            };
            let headers = crate::tasks::dispatch_headers(
                task,
                &dispatch.queue_key,
                attempt,
                execution_count,
                previous,
                epoch_millis(),
            );
            // The runner's HTTP server routes on the public path, and strips it before the
            // handler sees the request, so the dispatch carries the function's own URL path
            // rather than the `/` the queue would send to an arbitrary address.
            let path = format!(
                "/{}/{}/{}",
                dispatch.project, dispatch.region, dispatch.function
            );
            let attempt_started = std::time::Instant::now();
            let outcome = tokio::time::timeout(
                Duration::from_secs(task.dispatch_deadline_seconds),
                self.invoke_http_classified(&target, "POST", &path, &headers, &body),
            )
            .await;
            let status = match outcome {
                Ok(Ok(response)) if (200..300).contains(&response.status) => return false,
                Ok(Ok(response)) => Some(response.status),
                Ok(Err(HttpInvokeError::Capacity { .. })) => {
                    // The task has not reached a runner. Local process contention is
                    // backpressure, not a Cloud Tasks delivery attempt, so it cannot spend
                    // the queue's retry or rate budget.
                    if let Ok(mut inner) = self.inner.lock() {
                        inner.task_scheduler.refund_token(
                            &dispatch.queue,
                            dispatch.id,
                            dispatch.generation,
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    let retry_deadline = started.and_then(|first_delivery| {
                        task_retry_deadline(first_delivery, dispatch.retry, attempt)
                    });
                    if !self.wait_for_task_token(dispatch, retry_deadline).await {
                        return true;
                    }
                    continue;
                }
                // A transport failure or an overrun deadline is a retry with no previous
                // response, exactly as the official `catch` treats an aborted fetch.
                Ok(Err(_)) | Err(_) => None,
            };
            let first_delivery = *started.get_or_insert(attempt_started);
            if let Some(status) = status {
                // Only a non-5xx failure bumps the execution count upstream.
                if !(500..600).contains(&status) {
                    execution_count += 1;
                }
                previous = Some(status);
            }
            attempt += 1;
            if task_retry_exhausted(first_delivery, dispatch.retry, attempt) {
                eprintln!(
                    "[functions] task {:?} gave up after {} attempt(s)",
                    task.name,
                    attempt - 1
                );
                return true;
            }
            tokio::time::sleep(Duration::from_millis(
                dispatch.retry.backoff_millis(attempt),
            ))
            .await;
            let retry_deadline = task_retry_deadline(first_delivery, dispatch.retry, attempt);
            if !self.wait_for_task_token(dispatch, retry_deadline).await {
                return true;
            }
        }
    }

    async fn wait_for_task_token(
        &self,
        dispatch: &crate::task_scheduler::Dispatch,
        retry_deadline: Option<std::time::Instant>,
    ) -> bool {
        loop {
            let decision = {
                let Ok(mut inner) = self.inner.lock() else {
                    return false;
                };
                let now = std::time::Instant::now();
                if retry_deadline.is_some_and(|deadline| now > deadline) {
                    return false;
                }
                inner.task_scheduler.reserve_retry(
                    &dispatch.queue,
                    dispatch.id,
                    dispatch.generation,
                    now,
                )
            };
            match decision {
                crate::task_scheduler::RetryToken::Ready => return true,
                crate::task_scheduler::RetryToken::Gone => return false,
                crate::task_scheduler::RetryToken::WaitUntil(deadline) => {
                    let deadline = retry_deadline.map_or(deadline, |expiry| expiry.min(deadline));
                    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                }
            }
        }
    }

    /// Delivers one custom `CloudEvent` published on `channel` to every matching
    /// `onCustomEventPublished` function, and reports how many were reached.
    ///
    /// `event` is the JSON `CloudEvent` the function receives; `attributes` are the extra
    /// attributes the publisher sent, which is what an `eventFilters` entry is matched
    /// against (`EventarcEmulator.matchesAll`).
    pub fn publish_custom_event(
        &self,
        channel: &str,
        event_type: &str,
        attributes: &BTreeMap<String, String>,
        event: &Value,
    ) -> usize {
        if !self.background_triggers_enabled() {
            // Accepted and dropped, like every other background delivery while the switch is
            // off. The official emulator does the same to the events it holds.
            return 0;
        }
        let time = self.now();
        let Ok(mut inner) = self.inner.lock() else {
            return 0;
        };
        let mut delivered = 0;
        for f in self
            .manifest
            .eventarc_matches(channel, event_type, attributes)
        {
            self.enqueue_delivery(
                &mut inner,
                EventSource::Eventarc,
                &f.name,
                event_type,
                channel,
                time,
                event,
            );
            delivered += 1;
        }
        drop(inner);
        if delivered > 0 {
            self.wake.notify_one();
        }
        delivered
    }

    /// Returns the live Eventarc trigger table.
    pub fn eventarc_triggers(&self) -> Result<Value, EventarcPublishError> {
        self.eventarc_registry
            .lock()
            .map(|registry| registry.as_json())
            .map_err(|_| EventarcPublishError::Unavailable)
    }

    /// Registers one parsed Eventarc trigger against the exact current Functions key.
    pub fn register_eventarc_trigger(
        &self,
        project: &str,
        trigger: &str,
        parsed: crate::eventarc::ParsedTrigger,
    ) -> Result<(), String> {
        let mut registry = self
            .eventarc_registry
            .lock()
            .map_err(|_| "Eventarc registry unavailable.".to_owned())?;
        let generation = self.trigger_generation();
        let function = (project == self.project())
            .then(|| {
                crate::eventarc::registered_function(
                    project,
                    &self.manifest,
                    generation,
                    trigger,
                    parsed.event_trigger(),
                )
            })
            .flatten();
        registry.register_parsed(project, trigger, parsed, function.as_deref())
    }

    /// Removes the first semantically exact Eventarc registration.
    pub fn remove_eventarc_trigger(
        &self,
        project: &str,
        trigger: &str,
        parsed: crate::eventarc::ParsedTrigger,
    ) -> Result<(), String> {
        self.eventarc_registry
            .lock()
            .map_err(|_| "Eventarc registry unavailable.".to_owned())?
            .remove_parsed(project, trigger, parsed)
    }

    /// Atomically admits and enqueues one Eventarc publish request.
    pub fn publish_registered_custom_events(
        &self,
        channel: &str,
        events: &[crate::eventarc::PublishedEvent],
    ) -> Result<usize, EventarcPublishError> {
        if !self.background_triggers_enabled() {
            return Ok(0);
        }
        let time = self.now();
        let registry = self
            .eventarc_registry
            .lock()
            .map_err(|_| EventarcPublishError::Unavailable)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| EventarcPublishError::Unavailable)?;
        let mut planned = Vec::new();
        let mut delivery_count = 0usize;
        let mut retained_bytes = 0usize;
        for event in events {
            EventType::try_new(&event.event_type)
                .map_err(|_| EventarcPublishError::InvalidEvent)?;
            let payload_bytes = serde_json::to_vec(&event.event)
                .map_err(|_| EventarcPublishError::InvalidEvent)?
                .len();
            let remaining = MAX_EVENTARC_DELIVERIES_PER_PUBLISH - delivery_count;
            let functions = registry
                .matching_functions(channel, &event.event_type, &event.attributes, remaining)
                .map_err(|_| EventarcPublishError::Capacity)?;
            for function in functions {
                let served = self
                    .manifest
                    .get(&function)
                    .is_some_and(|spec| matches!(spec.trigger, Trigger::Eventarc { .. }));
                if !served {
                    continue;
                }
                let copies = self.delivery_copies(&function, &event.event_type);
                delivery_count = delivery_count
                    .checked_add(copies)
                    .ok_or(EventarcPublishError::Capacity)?;
                if delivery_count > MAX_EVENTARC_DELIVERIES_PER_PUBLISH {
                    return Err(EventarcPublishError::Capacity);
                }
                let bytes = Self::retained_event_bytes_from_payload_len(
                    &function,
                    &event.event_type,
                    channel,
                    payload_bytes,
                )
                .and_then(|bytes| bytes.checked_mul(copies))
                .ok_or(EventarcPublishError::Capacity)?;
                retained_bytes = retained_bytes
                    .checked_add(bytes)
                    .ok_or(EventarcPublishError::Capacity)?;
                if !Self::can_admit_events(
                    &inner,
                    EventSource::Eventarc,
                    delivery_count,
                    retained_bytes,
                ) {
                    return Err(EventarcPublishError::Capacity);
                }
                planned.push((function, event, copies));
            }
        }
        if !Self::can_admit_events(
            &inner,
            EventSource::Eventarc,
            delivery_count,
            retained_bytes,
        ) {
            return Err(EventarcPublishError::Capacity);
        }
        for (function, event, copies) in planned {
            for _ in 0..copies {
                let admitted = Self::enqueue(
                    &mut inner,
                    self.config.session,
                    EventSource::Eventarc,
                    &function,
                    &event.event_type,
                    channel,
                    time,
                    &event.event,
                );
                debug_assert!(admitted, "pre-admitted Eventarc delivery must enqueue");
            }
        }
        drop(inner);
        drop(registry);
        if delivery_count > 0 {
            self.wake.notify_one();
        }
        Ok(delivery_count)
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
                inner.causality.transition(id.value(), "due", 0, now, false);
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
            || inner
                .payloads
                .values()
                .any(|queued| queued.function == function);
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
        if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let now = self.now();
        let (retired_attempts, generation) = {
            // The supervisor is locked before queue state for both dispatch and lifecycle
            // transitions. No dispatch can be removed from the scheduler without being added
            // to this exact JoinSet generation.
            let mut attempts = self
                .task_attempts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut generation = None;
            if let Ok(mut inner) = self.inner.lock() {
                inner.epoch = inner.epoch.next().unwrap_or(inner.epoch);
                let epoch = inner.epoch;
                generation = Some(epoch);
                // Killed under the same lock the restart installs under: a replacement from an
                // earlier reset cannot slip in between the bump and the kill. Every codebase's
                // runner goes: a handler still running in any of them must not write into the
                // reset session.
                for codebase in &self.codebases {
                    let mut current = codebase.generation_mut();
                    current.blocking_restart_ticket = None;
                    current.runner.kill_now();
                }
                inner.outbox.discard_stale(epoch);
                inner.causality.reset();
                inner.admission_refusals.clear();
                inner.payloads.clear();
                inner.active_event_bytes = 0;
                inner.reserved_event_records = 0;
                inner.reserved_event_bytes = 0;
                inner.active_eventarc_records = 0;
                inner.active_eventarc_bytes = 0;
                inner.running.clear();
                inner.delayed.clear();
                inner.catch_up_pending = false;
                // A task accepted before the reset must not reach the new session's handlers.
                inner.task_scheduler.reset(std::time::Instant::now());
                for job in &mut inner.jobs {
                    job.cursor = now;
                }
            }
            (std::mem::take(&mut *attempts), generation)
        };
        drop(retired_attempts);
        self.respawn_runner(generation);
        self.idle.notify_waiters();
        self.wake.notify_one();
    }

    /// Restarts every codebase's runner from its spec for `generation` (a later reset
    /// supersedes it).
    fn respawn_runner(self: &Arc<Self>, generation: Option<Epoch>) {
        for index in 0..self.codebases.len() {
            self.respawn_one(index, generation);
        }
    }

    /// Restarts the runner of one codebase.
    fn respawn_one(self: &Arc<Self>, index: usize, generation: Option<Epoch>) {
        let Some(respawn) = self.codebases.get(index).map(Codebase::capture_respawn) else {
            return;
        };
        self.spawn_captured(index, generation, respawn);
    }

    /// Crashes and replaces one atomic codebase generation. A reload that wins after the
    /// capture increments the revision, so this older replacement can no longer displace it.
    fn crash_and_respawn(self: &Arc<Self>, index: usize, generation: Option<Epoch>) {
        let Some(respawn) = self.codebases.get(index).map(Codebase::capture_respawn) else {
            return;
        };
        respawn.runner.kill_now();
        self.spawn_captured(index, generation, respawn);
    }

    fn spawn_captured(
        self: &Arc<Self>,
        index: usize,
        generation: Option<Epoch>,
        respawn: RespawnGeneration,
    ) {
        if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let RespawnGeneration {
            runner: retired_runner,
            spawn,
            revision: codebase_revision,
            cleanup_dir: source_generation,
        } = respawn;
        let Some(spawn) = spawn else {
            return;
        };
        let runtime = self.clone();
        tokio::spawn(async move {
            // Retain the immutable source until this spawn either installs or is rejected as
            // stale. A concurrent reload can otherwise drop its last live owner mid-import.
            let _source_generation = source_generation;
            match Runner::spawn_spec(&spawn).await {
                Ok(runner) => {
                    if runtime
                        .shutting_down
                        .load(std::sync::atomic::Ordering::SeqCst)
                    {
                        runner.kill_now();
                        return;
                    }
                    // A later reset supersedes this restart: its own replacement is
                    // the runner of record and this one must not outlive the kill.
                    // Checked and installed under the runtime lock (the lock a reset
                    // bumps the epoch and kills under), so the two cannot interleave.
                    let installed = match runtime.inner.lock() {
                        Ok(inner) if Some(inner.epoch) == generation => {
                            let mut current = runtime.codebases[index].generation_mut();
                            if !runtime
                                .shutting_down
                                .load(std::sync::atomic::Ordering::SeqCst)
                                && current.revision == codebase_revision
                                && Arc::ptr_eq(&current.runner, &retired_runner)
                            {
                                let old = std::mem::replace(&mut current.runner, Arc::new(runner));
                                current.blocking_restart_ticket = None;
                                drop(current);
                                old.kill_now();
                                true
                            } else {
                                runner.kill_now();
                                false
                            }
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

    fn spawn_blocking_auth_restart(
        self: &Arc<Self>,
        index: usize,
        ticket: Arc<()>,
        respawn: RespawnGeneration,
    ) {
        if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let RespawnGeneration {
            spawn,
            cleanup_dir: source_generation,
            ..
        } = respawn;
        let Some(spawn) = spawn else {
            return;
        };
        let runtime = self.clone();
        tokio::spawn(async move {
            let _source_generation = source_generation;
            match Runner::spawn_spec(&spawn).await {
                Ok(runner) => {
                    if runtime
                        .shutting_down
                        .load(std::sync::atomic::Ordering::SeqCst)
                    {
                        runner.kill_now();
                        return;
                    }
                    let installed = if let Ok(_inner) = runtime.inner.lock() {
                        let mut current = runtime.codebases[index].generation_mut();
                        if !runtime
                            .shutting_down
                            .load(std::sync::atomic::Ordering::SeqCst)
                            && current
                                .blocking_restart_ticket
                                .as_ref()
                                .is_some_and(|active| Arc::ptr_eq(active, &ticket))
                        {
                            let old = std::mem::replace(&mut current.runner, Arc::new(runner));
                            current.blocking_restart_ticket = None;
                            drop(current);
                            old.kill_now();
                            true
                        } else {
                            runner.kill_now();
                            false
                        }
                    } else {
                        runner.kill_now();
                        false
                    };
                    if installed {
                        runtime.wake.notify_one();
                    }
                }
                Err(error) => {
                    // The matching ticket deliberately remains set: admission stays fail closed
                    // until an explicit reset or a successful source reload replaces it.
                    eprintln!("[functions] Blocking Auth runner restart failed: {error}");
                }
            }
        });
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
            .map(|i| {
                !i.outbox.has_active()
                    && i.running.is_empty()
                    && !i.catch_up_pending
                    && i.task_scheduler.outstanding() == 0
            })
            .unwrap_or(true)
    }

    /// Returns the exact source-event ownership projection without payload contents.
    #[must_use]
    pub fn source_event_accounting(&self) -> Option<SourceEventAccounting> {
        self.inner.lock().ok().map(|inner| SourceEventAccounting {
            reserved_records: inner.reserved_event_records,
            published_records: inner.payloads.len(),
            epoch: inner.epoch,
        })
    }

    /// Whether every codebase's runner process is alive (a dead runner leaves that
    /// codebase's queued work pending).
    #[must_use]
    pub fn runner_alive(&self) -> bool {
        (0..self.codebases.len()).all(|i| self.runner_at(i).is_alive())
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
            "tasksInFlight": inner.task_scheduler.outstanding(),
            "overlapRejected": inner.overlap_rejected,
            "timeZoneDatabase": crate::zone::database_version(),
            "runnerAlive": self.runner_alive(),
            "epoch": inner.epoch.value(),
            // Bounded causal phases of the registered events (spec 10.5 diagnostics): what
            // an `await-idle` timeout is waiting for and where it came from. Eviction and
            // resets are counted, never presented as completions.
            "causality": inner.causality.project(inner.epoch.value()),
            "functions": self.manifest.functions.iter().map(|f| f.name.clone()).collect::<Vec<_>>(),
            // One entry per loaded codebase, so a multi-codebase project can see which runner
            // is down and which functions went with it.
            "codebases": (0..self.codebases.len()).map(|i| json!({
                "codebase": self.codebases[i].name,
                "runnerAlive": self.runner_at(i).is_alive(),
                "functions": self.manifest.functions.iter()
                    .filter(|f| self.owner.get(&f.name).copied() == Some(i))
                    .map(|f| f.name.clone()).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            // Every export the runners discovered and could not serve, so nothing a codebase
            // declared is invisible from here either.
            "ignored": self.manifest.ignored.iter().map(|f| json!({
                "name": f.name,
                "region": f.region,
                "triggerType": f.trigger_type,
                "scope": f.scope.as_str(),
                "reason": f.reason,
            })).collect::<Vec<_>>(),
        })
    }

    /// The runtime's retention report for the resource diagnostics: outbox records and bytes,
    /// Eventarc records and bytes, the retained history windows and running work, each against
    /// its limit, with one outstanding root per queued event and running invocation. Payloads
    /// are never included; an event root carries its identifier and retained byte count only.
    ///
    /// # Errors
    ///
    /// A poisoned runtime lock is an error, never an empty report: an empty report would read
    /// as "quiescent" while work may still be outstanding.
    pub fn resources(&self, budget: RootBudget) -> Result<ServiceResources, String> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| "the functions runtime state is poisoned".to_owned())?;
        Ok(ServiceResources {
            service: "functions".to_owned(),
            gauges: self.resource_gauges(&inner),
            refusals: std::iter::once(Refusal {
                reason: "schedule.overlap".to_owned(),
                count: inner.overlap_rejected,
            })
            .chain(
                inner
                    .admission_refusals
                    .iter()
                    .map(|(category, count)| Refusal {
                        reason: format!("admission.{category}"),
                        count: *count,
                    }),
            )
            .collect(),
            roots: budget.bound(Self::resource_roots(&inner)),
        })
    }

    fn resource_roots(inner: &Inner) -> Vec<RetentionRoot> {
        let mut roots = Vec::new();
        for (id, payload) in &inner.payloads {
            let Some(record) = inner.outbox.record(*id) else {
                continue;
            };
            let phase = match record.state() {
                EventState::Pending | EventState::Leased => "pending",
                EventState::RetryWaiting { .. } => "retry",
                _ => continue,
            };
            roots.push(RetentionRoot {
                kind: format!("event.{phase}"),
                id: format!("{id:?}"),
                count: 1,
                bytes: u64::try_from(payload.retained_bytes).unwrap_or(u64::MAX),
                outstanding: true,
            });
        }
        for key in inner.running.keys() {
            roots.push(RetentionRoot {
                kind: "invocation".to_owned(),
                id: key.clone(),
                count: 1,
                bytes: 0,
                outstanding: true,
            });
        }
        roots
    }

    fn resource_gauges(&self, inner: &Inner) -> Vec<Gauge> {
        let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
        vec![
            Gauge::logical(
                "outbox.records",
                Unit::Count,
                count(
                    inner
                        .payloads
                        .len()
                        .saturating_add(inner.reserved_event_records),
                ),
                Some(count(MAX_ACTIVE_EVENT_RECORDS)),
            ),
            Gauge::logical(
                "outbox.bytes",
                Unit::Bytes,
                count(
                    inner
                        .active_event_bytes
                        .saturating_add(inner.reserved_event_bytes),
                ),
                Some(count(MAX_ACTIVE_EVENT_BYTES)),
            ),
            Gauge::logical(
                "eventarc.records",
                Unit::Count,
                count(inner.active_eventarc_records),
                Some(count(MAX_ACTIVE_EVENTARC_RECORDS)),
            ),
            Gauge::logical(
                "eventarc.bytes",
                Unit::Bytes,
                count(inner.active_eventarc_bytes),
                Some(count(MAX_ACTIVE_EVENTARC_BYTES)),
            ),
            Gauge::logical(
                "history.records",
                Unit::Count,
                count(inner.history.records.len()),
                Some(count(inner.history.retention)),
            ),
            Gauge::logical(
                "dead_letters.records",
                Unit::Count,
                count(inner.dead_letters.records.len()),
                Some(count(inner.dead_letters.retention)),
            ),
            Gauge::logical(
                "invocations.running",
                Unit::Count,
                count(inner.running.len()),
                Some(count(self.max_global_concurrency())),
            ),
            Gauge::logical(
                "tasks.in_flight",
                Unit::Count,
                count(inner.task_scheduler.outstanding()),
                None,
            ),
        ]
    }

    /// Returns the read-only Cloud Tasks `/queueStats` payload for all loaded task queues.
    #[must_use]
    pub fn task_queue_stats(&self) -> Value {
        let Ok(mut inner) = self.inner.lock() else {
            return json!({});
        };
        inner
            .task_scheduler
            .statistics(&self.config.project, |function| {
                self.manifest.get(function).map(|spec| spec.region.clone())
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

    /// Bounds the causality window to `entries` events (tests and embedders; the default is
    /// [`MAX_CAUSALITY_ENTRIES`]). Entries beyond the bound are evicted oldest first.
    pub fn set_causality_retention(&self, entries: usize) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.causality.set_retention(entries);
        }
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

    /// Every trigger key, in manifest order, as the official emulator spells them.
    ///
    /// `getTriggerKey` (`functionsEmulator.js:909`) is `<region>-<name>` for an HTTP or
    /// callable function and `<region>-<name>-<generation>` for an event one, where the
    /// generation counts source reloads. It is what the 404 for an unknown function lists, so
    /// it is spelled the same way here rather than invented.
    ///
    /// The order is the official one too, and it is not export order: the discovered backend
    /// is `endpoints: Record<region, Record<id, Endpoint>>`, so `emulatedFunctionsByRegion`
    /// walks it grouped by region, and within a region in export order. Recorded against the
    /// oracle in `conformance/fixtures/functions/http-routing-cors-and-timeouts.json`, where
    /// a `europe-west1` function exported before a `us-central1` one is listed after it.
    #[must_use]
    pub fn trigger_keys(&self) -> Vec<String> {
        let mut regions: Vec<&str> = Vec::new();
        for f in &self.manifest.functions {
            if !regions.contains(&f.region.as_str()) {
                regions.push(&f.region);
            }
        }
        let mut keys = Vec::with_capacity(self.manifest.functions.len());
        for region in regions {
            for f in self
                .manifest
                .functions
                .iter()
                .filter(|f| f.region == region)
            {
                if matches!(f.trigger, Trigger::Http { .. } | Trigger::TaskQueue { .. }) {
                    keys.push(format!("{}-{}", f.region, f.name));
                } else {
                    keys.push(format!(
                        "{}-{}-{}",
                        f.region,
                        f.name,
                        self.trigger_generation()
                    ));
                }
            }
        }
        keys
    }

    /// How many times the sources have been reloaded (`triggerGeneration`).
    #[must_use]
    pub fn trigger_generation(&self) -> u64 {
        self.trigger_generation
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The runner address for an HTTP function, if it exists.
    #[must_use]
    pub fn http_target(&self, project: &str, region: &str, function: &str) -> Option<HttpTarget> {
        if project != self.config.project {
            return None;
        }
        let f = self.manifest.get(function)?;
        // A task-queue function is an HTTP function that only its queue calls, and the
        // official emulator serves it at the same URL -- that URL *is* the queue's
        // `defaultUri` (`functionsEmulator.js:454-459`).
        if !matches!(f.trigger, Trigger::Http { .. } | Trigger::TaskQueue { .. })
            || f.region != region
        {
            return None;
        }
        // Each codebase hosts its own HTTP server, so the route resolves to the runner of the
        // codebase that exported this function.
        let port = self.runner_for(function).hello().http_port?;
        Some(HttpTarget {
            function: function.to_owned(),
            addr: format!("127.0.0.1:{port}"),
        })
    }

    /// Whether the immutable manifest contains a Blocking Auth function for `event`.
    #[must_use]
    pub fn handles_blocking_auth(
        &self,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
    ) -> bool {
        self.manifest.functions.iter().any(|function| {
            matches!(function.trigger, Trigger::BlockingAuth { event: candidate, .. } if candidate == event)
        })
    }

    /// Token policy of the first Blocking Auth target selected for `event`.
    #[must_use]
    pub fn blocking_auth_token_policy(
        &self,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
    ) -> fireemu_core_functions::manifest::BlockingAuthTokenPolicy {
        self.manifest
            .functions
            .iter()
            .find_map(|function| match function.trigger {
                Trigger::BlockingAuth {
                    event: candidate,
                    token_policy,
                } if candidate == event => Some(token_policy),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// Atomically selects a ready Blocking Auth runner generation and reserves one slot in the
    /// same process-wide budget used by HTTP, scheduled and background Functions work.
    pub fn try_admit_blocking_auth(
        self: &Arc<Self>,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
    ) -> Result<Option<(BlockingAuthTarget, BlockingAuthAdmission)>, String> {
        if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("the Functions runtime is shutting down".to_owned());
        }
        let Some(spec) = self.manifest.functions.iter().find(|function| {
            matches!(function.trigger, Trigger::BlockingAuth { event: candidate, .. } if candidate == event)
        }) else {
            return Ok(None);
        };
        let function = spec.name.as_str();
        let function_capacity = spec.http_capacity(self.config.max_running);
        let Some(owner) = self.owner.get(function).copied() else {
            return Err(format!(
                "Blocking Auth function {function:?} has no codebase owner"
            ));
        };
        let Ok(mut inner) = self.inner.lock() else {
            return Err("runtime poisoned".into());
        };
        let Some(codebase) = self.codebases.get(owner) else {
            return Err(format!(
                "Blocking Auth function {function:?} has no codebase"
            ));
        };
        let current = codebase.generation();
        if current.blocking_restart_ticket.is_some() || !current.runner.is_alive() {
            return Err(format!(
                "Blocking Auth function {function} is unavailable while its runner restarts"
            ));
        }
        let Some(port) = current.runner.hello().http_port else {
            return Err(format!(
                "Blocking Auth function {function} has no HTTP runner"
            ));
        };
        let running_here = inner
            .running
            .values()
            .filter(|candidate| candidate.as_str() == function)
            .count();
        if inner.running.len() >= self.config.max_running || running_here >= function_capacity {
            return Err(format!(
                "function {function} is at its concurrency limit; retry later"
            ));
        }
        inner.next_event = inner.next_event.saturating_add(1);
        let key = format!("blocking-auth-{}", inner.next_event);
        inner.running.insert(key.clone(), function.to_owned());
        let target = BlockingAuthTarget {
            function: function.to_owned(),
            region: spec.region.clone(),
            addr: format!("127.0.0.1:{port}"),
            secret: self.config.runner_secret.clone(),
            token_policy: match spec.trigger {
                Trigger::BlockingAuth { token_policy, .. } => token_policy,
                _ => unreachable!("the selected function is a Blocking Auth target"),
            },
            runner: current.runner.clone(),
            revision: current.revision,
            owner,
        };
        drop(current);
        drop(inner);
        Ok(Some((
            target,
            BlockingAuthAdmission {
                runtime: self.clone(),
                key,
            },
        )))
    }

    /// Claims one restart for the exact failed runner generation. Later failures from that
    /// generation observe the in-progress ticket and cannot spawn another process.
    pub fn restart_runner_after_blocking_failure(
        self: &Arc<Self>,
        target: &BlockingAuthTarget,
    ) -> bool {
        if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        let Ok(inner) = self.inner.lock() else {
            return false;
        };
        let Some(codebase) = self.codebases.get(target.owner) else {
            return false;
        };
        let mut current = codebase.generation_mut();
        if current.revision != target.revision
            || !Arc::ptr_eq(&current.runner, &target.runner)
            || current.blocking_restart_ticket.is_some()
        {
            return false;
        }
        let Some(spawn) = current.spawn.clone() else {
            return false;
        };
        // Pointer identity makes the claim immune to ABA across reset and hot reload: a later
        // generation can never recreate this exact ticket value.
        let ticket = Arc::new(());
        current.blocking_restart_ticket = Some(ticket.clone());
        let respawn = RespawnGeneration {
            runner: current.runner.clone(),
            spawn: Some(spawn),
            revision: current.revision,
            cleanup_dir: current.cleanup_dir.clone(),
        };
        drop(current);
        drop(inner);
        respawn.runner.kill_now();
        self.spawn_blocking_auth_restart(target.owner, ticket, respawn);
        true
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
        self.invoke_http_classified(target, method, path_and_query, headers, body)
            .await
            .map_err(HttpInvokeError::into_message)
    }

    fn admit_http_stream(
        self: &Arc<Self>,
        target: &HttpTarget,
        function_capacity: usize,
    ) -> Result<(EventId, Admission), String> {
        let Ok(mut inner) = self.inner.lock() else {
            return Err("runtime poisoned".into());
        };
        let running_here = inner
            .running
            .values()
            .filter(|function| **function == target.function)
            .count();
        if inner.running.len() >= self.config.max_running || running_here >= function_capacity {
            return Err(HttpInvokeError::Capacity {
                function: target.function.clone(),
            }
            .into_message());
        }
        inner.next_event += 1;
        let id = EventId::new(u128::from(inner.next_event));
        let key = format!("http-{}", inner.next_event);
        inner.running.insert(key.clone(), target.function.clone());
        Ok((
            id,
            Admission {
                runtime: self.clone(),
                key,
            },
        ))
    }

    fn record_http_invocation(&self, id: EventId, function: String, outcome: String) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.record_invocation(InvocationRecord {
                event_id: id.value(),
                function,
                attempt: 1,
                outcome,
            });
        }
    }

    fn retain_stream_lifecycle(
        self: &Arc<Self>,
        target: &HttpTarget,
        id: EventId,
        status: u16,
        timeout: u64,
        completion: tokio::sync::oneshot::Receiver<StreamCompletion>,
        admission: Admission,
    ) {
        let runtime = self.clone();
        let function = target.function.clone();
        tokio::spawn(async move {
            let completion = completion
                .await
                .unwrap_or_else(|_| StreamCompletion::Upstream("stream pump stopped".to_owned()));
            let outcome = match &completion {
                StreamCompletion::Complete => format!("http {status}"),
                StreamCompletion::ClientGone => "cancelled: client disconnected".to_owned(),
                StreamCompletion::TimedOut => "timeout".to_owned(),
                StreamCompletion::TooLarge => "failed: response too large".to_owned(),
                StreamCompletion::Upstream(error) => format!("failed: {error}"),
            };
            if matches!(completion, StreamCompletion::TimedOut) {
                log_http_timeout(timeout);
            }
            runtime.record_http_invocation(id, function, outcome);
            drop(admission);
        });
    }

    /// Starts an HTTP response whose body remains tied to runtime admission until it ends.
    ///
    /// The caller uses this only for an exact callable `Accept: text/event-stream` request.
    /// Fault-plan responses and a timeout before the runner emits headers are still complete
    /// responses because no public streaming bytes have been committed yet.
    pub async fn invoke_http_stream(
        self: &Arc<Self>,
        target: &HttpTarget,
        method: &str,
        path_and_query: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpStreamStart, String> {
        if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("the Functions runtime is shutting down".to_owned());
        }
        let (timeout, function_capacity) =
            self.manifest
                .get(&target.function)
                .map_or((60, self.config.max_running), |function| {
                    (
                        u64::from(function.timeout_seconds),
                        function.http_capacity(self.config.max_running),
                    )
                });
        if let Some(faulted) = self.http_faults(&target.function) {
            if let Ok(mut inner) = self.inner.lock() {
                inner.next_event += 1;
                let event_id = inner.next_event;
                inner.record_invocation(InvocationRecord {
                    event_id: u128::from(event_id),
                    function: target.function.clone(),
                    attempt: 1,
                    outcome: match &faulted {
                        Ok(response) => format!("fault plan: http {}", response.status),
                        Err(error) => format!("failed: {error}"),
                    },
                });
            }
            return faulted
                .map(HttpStreamStart::Buffered)
                .map_err(HttpInvokeError::Message)
                .map_err(HttpInvokeError::into_message);
        }
        let (id, admission) = self.admit_http_stream(target, function_capacity)?;
        let forwarded = runner_headers(headers, &self.config.runner_secret);
        let deadline = (!self.config.debug_mode)
            .then(|| tokio::time::Instant::now() + Duration::from_secs(timeout));
        match forward_stream(
            &target.addr,
            method,
            path_and_query,
            &forwarded,
            body,
            deadline,
        )
        .await
        {
            Ok(started) => {
                let status = started.response.status;
                self.retain_stream_lifecycle(
                    target,
                    id,
                    status,
                    timeout,
                    started.completion,
                    admission,
                );
                Ok(HttpStreamStart::Streaming(started.response))
            }
            Err(StreamStartError::TimedOut) => {
                self.record_http_invocation(id, target.function.clone(), "timeout".to_owned());
                log_http_timeout(timeout);
                drop(admission);
                Ok(HttpStreamStart::Buffered(ProxiedResponse {
                    status: 500,
                    headers: Vec::new(),
                    body: br#"{"code":"ECONNRESET"}"#.to_vec(),
                }))
            }
            Err(StreamStartError::Upstream(error)) => {
                self.record_http_invocation(
                    id,
                    target.function.clone(),
                    format!("failed: {error}"),
                );
                drop(admission);
                Err(error)
            }
        }
    }

    async fn invoke_http_classified(
        self: &Arc<Self>,
        target: &HttpTarget,
        method: &str,
        path_and_query: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<ProxiedResponse, HttpInvokeError> {
        if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(HttpInvokeError::Message(
                "the Functions runtime is shutting down".to_owned(),
            ));
        }
        let (timeout, function_capacity) =
            self.manifest
                .get(&target.function)
                .map_or((60, self.config.max_running), |function| {
                    (
                        u64::from(function.timeout_seconds),
                        function.http_capacity(self.config.max_running),
                    )
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
            return faulted.map_err(HttpInvokeError::Message);
        }
        let (id, key) = {
            let Ok(mut inner) = self.inner.lock() else {
                return Err(HttpInvokeError::Message("runtime poisoned".into()));
            };
            // HTTP invocations share the admission limits of event invocations.
            let running_here = inner
                .running
                .values()
                .filter(|f| **f == target.function)
                .count();
            if inner.running.len() >= self.config.max_running || running_here >= function_capacity {
                return Err(HttpInvokeError::Capacity {
                    function: target.function.clone(),
                });
            }
            inner.next_event += 1;
            let id = EventId::new(u128::from(inner.next_event));
            let key = format!("http-{}", inner.next_event);
            inner.running.insert(key.clone(), target.function.clone());
            (id, key)
        };
        // The slot is released even if the client disconnects and this future is dropped.
        let _admission = Admission {
            runtime: self.clone(),
            key,
        };
        // The runner secret is ours to add; a caller-supplied copy never passes through. The
        // same goes for the emulator-internal fields `firebase-functions` honours under
        // `skipTokenVerification` to override v1 callable auth context: no client legitimately
        // sends them, and one that does is trying to forge `context.auth`.
        let forwarded = runner_headers(headers, &self.config.runner_secret);
        let result = forward_with_debug_deadline(
            self.config.debug_mode,
            Duration::from_secs(timeout),
            &target.addr,
            method,
            path_and_query,
            &forwarded,
            body,
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
        if let Ok(answer) = result {
            answer.map_err(HttpInvokeError::Message)
        } else {
            // What the official emulator says and answers when a function overruns
            // `timeoutSeconds` (`functionsRuntimeWorker.js:139` logs this sentence, then
            // `proxy.destroy()` lands in the error handler at `:142`, which writes a 500).
            //
            // The one thing not reproduced is `this.runtime.process.kill()`: the official
            // emulator runs one runtime process per trigger, so killing it costs that
            // function's warm start. One fireemu runner serves a whole codebase, and taking
            // it down would abort every other function's in-flight work.
            log_http_timeout(timeout);
            // `{"code":"ECONNRESET"}` with no content-type is literally what the official
            // emulator answers: `proxy.destroy()` makes Node raise a socket hang-up on the
            // request, and the handler writes `JSON.stringify(err)` after a bare
            // `writeHead(500)`. Recorded in
            // `conformance/fixtures/functions/http-routing-cors-and-timeouts.json`.
            Ok(ProxiedResponse {
                status: 500,
                headers: Vec::new(),
                body: br#"{"code":"ECONNRESET"}"#.to_vec(),
            })
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
                    let index = self.owner.get(function).copied().unwrap_or(0);
                    self.crash_and_respawn(index, generation);
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
            let wake = self.wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            if self
                .dispatch_stopping
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                break;
            }
            self.dispatch_ready();
            let next_task_wake = self.dispatch_tasks_ready();
            match next_task_wake {
                Some(deadline) => {
                    tokio::select! {
                        () = &mut wake => {}
                        () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {}
                    }
                }
                None => wake.await,
            }
        }
    }

    /// Moves ready Cloud Tasks from their bounded FIFOs into active dispatch slots. Only an
    /// active slot owns a Tokio task; pending bodies remain plain queue entries.
    fn dispatch_tasks_ready(self: &Arc<Self>) -> Option<std::time::Instant> {
        if self
            .dispatch_stopping
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return None;
        }
        let mut attempts = self
            .task_attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self
            .dispatch_stopping
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return None;
        }
        let (dispatches, next_wake, epoch) = {
            let Ok(mut inner) = self.inner.lock() else {
                return None;
            };
            // A task that is inside invoke_http appears in both sets. Using the larger set
            // avoids double-counting that task while keeping active task futures bounded;
            // invoke_http remains the atomic authority for mixed HTTP/task execution slots.
            let occupied = inner.running.len().max(inner.task_scheduler.active());
            let room = self.config.max_running.saturating_sub(occupied);
            let epoch = inner.epoch;
            let (dispatches, next_wake) = inner.task_scheduler.dispatch_ready(
                std::time::Instant::now(),
                &self.config.project,
                |function| self.manifest.get(function).map(|spec| spec.region.clone()),
                room,
            );
            (dispatches, next_wake, epoch)
        };
        if dispatches.is_empty() {
            return next_wake;
        }
        while attempts.try_join_next().is_some() {}
        for dispatch in dispatches {
            let runtime = self.clone();
            attempts.spawn(async move {
                let mut completion = TaskCompletion {
                    runtime: Arc::downgrade(&runtime),
                    queue: dispatch.queue.clone(),
                    id: dispatch.id,
                    generation: dispatch.generation,
                    failed: false,
                };
                completion.failed = runtime.dispatch_task(&dispatch, epoch).await;
            });
        }
        next_wake
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch_ready(self: &Arc<Self>) {
        if self
            .dispatch_stopping
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }
        // The runners snapshotted here are the ones every invocation of this pass goes to: an
        // event leased before a reset must not reach a runner spawned after it. One per
        // codebase, and a codebase whose runner is down holds only its own queued work: the
        // rest of the project keeps dispatching.
        let runners: Vec<Arc<Runner>> = (0..self.codebases.len())
            .map(|i| self.runner_at(i))
            .collect();
        if runners.iter().all(|r| !r.is_alive()) {
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
            let Some(queued) = inner.payloads.get(&id) else {
                continue;
            };
            let function_name = &queued.function;
            let function_name = function_name.clone();
            let Some(spec) = self.manifest.get(&function_name) else {
                continue;
            };
            let index = self.owner.get(&function_name).copied().unwrap_or(0);
            let Some(runner) = runners.get(index).filter(|r| r.is_alive()) else {
                // This codebase's runner is down: its work stays pending, and the other
                // codebases keep going.
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
                usize::try_from(spec.effective_concurrency()).unwrap_or(usize::MAX)
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
            inner
                .causality
                .transition(id.value(), "running", attempt, now, false);
            let Some(queued) = inner.payloads.get(&id) else {
                continue;
            };
            let request = self.invoke_request(id, spec, attempt, epoch, &queued.payload);
            let key = format!("{}-{attempt}", id.value());
            inner.running.insert(key.clone(), function_name.clone());
            let runtime = self.clone();
            let runner = runner.clone();
            let timeout = Duration::from_secs(u64::from(spec.timeout_seconds));
            let retry = spec.retry;
            if crash {
                // The runner dies mid-invocation: the attempt is given back (RunnerGone) and
                // a fresh runner takes over, as after a crashed instance.
                let generation = Some(inner.epoch);
                self.crash_and_respawn(index, generation);
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
                    None if runtime.config.debug_mode => runner.invoke_unbounded(request).await,
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
            Trigger::BlockingAuth { .. } => "blockingAuth",
            Trigger::Eventarc { .. } => "eventarc",
            Trigger::TaskQueue { .. } => "tasks",
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
    /// Applies the outbox's retirement decision to the causality window, the payload and the
    /// dead-letter log.
    #[allow(clippy::too_many_arguments)]
    fn settle_record(
        inner: &mut Inner,
        id: EventId,
        attempt: u32,
        now: LogicalInstant,
        outcome: &InvokeOutcome,
        retirement: Result<Retirement, fireemu_core_events::outbox::OutboxError>,
        function: &str,
        text: String,
    ) {
        match retirement {
            Ok(Retirement::Retired) => {
                inner
                    .causality
                    .transition(id.value(), "completed", attempt, now, true);
                Self::remove_payload(inner, id);
            }
            Ok(Retirement::StillActive) => {
                let phase = if matches!(outcome, InvokeOutcome::RunnerGone(_)) {
                    "interrupted"
                } else {
                    "retry"
                };
                inner
                    .causality
                    .transition(id.value(), phase, attempt, now, false);
            }
            Ok(Retirement::DeadLettered) => {
                inner
                    .causality
                    .transition(id.value(), "failed", attempt, now, true);
                Self::remove_payload(inner, id);
                inner.record_dead_letter(InvocationRecord {
                    event_id: id.value(),
                    function: function.to_owned(),
                    attempt,
                    outcome: text,
                });
            }
            Err(_) => {}
        }
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
                Self::remove_payload(&mut inner, id);
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
                self.manifest.get(function).map_or(self.retry, |spec| {
                    if let Trigger::Schedule { retry, .. } = &spec.trigger {
                        let seconds = |value: u64| {
                            LogicalDuration::from_seconds(i64::try_from(value).unwrap_or(i64::MAX))
                        };
                        let minimum = seconds(retry.min_backoff_seconds);
                        let maximum =
                            seconds(retry.max_backoff_seconds.max(retry.min_backoff_seconds));
                        RetryPolicy::try_with_limits(
                            retry.retry_count.saturating_add(1),
                            minimum,
                            maximum,
                            retry.max_doublings,
                            (retry.max_retry_seconds > 0).then(|| seconds(retry.max_retry_seconds)),
                        )
                        .unwrap_or(self.retry)
                    } else {
                        self.retry
                    }
                })
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
            Self::settle_record(
                &mut inner,
                id,
                attempt,
                now,
                outcome,
                outcome_of_record,
                function,
                text,
            );
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

enum HttpInvokeError {
    Capacity { function: String },
    Message(String),
}

fn log_http_timeout(timeout: u64) {
    eprintln!(
        "[functions] Your function timed out after ~{timeout}s. To configure this timeout, see\n      https://firebase.google.com/docs/functions/manage-functions#set_timeout_and_memory_allocation."
    );
}

fn task_retry_deadline(
    first_delivery: std::time::Instant,
    retry: fireemu_core_functions::manifest::TaskRetryConfig,
    attempt: u32,
) -> Option<std::time::Instant> {
    (attempt > retry.max_attempts)
        .then_some(retry.max_retry_millis)
        .flatten()
        .filter(|millis| *millis > 0)
        .and_then(|millis| first_delivery.checked_add(Duration::from_millis(millis)))
}

fn task_retry_exhausted(
    first_delivery: std::time::Instant,
    retry: fireemu_core_functions::manifest::TaskRetryConfig,
    attempt: u32,
) -> bool {
    #[allow(clippy::cast_possible_truncation)]
    let elapsed = first_delivery
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    retry.exhausted(attempt, elapsed)
}

impl HttpInvokeError {
    fn into_message(self) -> String {
        match self {
            Self::Capacity { function } => {
                format!("function {function} is at its concurrency limit; retry later")
            }
            Self::Message(message) => message,
        }
    }
}

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
struct Admission {
    runtime: Arc<FunctionsRuntime>,
    key: String,
}

/// Releases a Blocking Auth slot on every completion path, including unwind and transport
/// failure. The bridge owns this value for the entire synchronous runner exchange.
pub struct BlockingAuthAdmission {
    runtime: Arc<FunctionsRuntime>,
    key: String,
}

impl Drop for BlockingAuthAdmission {
    fn drop(&mut self) {
        self.runtime.release(&self.key);
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.runtime.release(&self.key);
    }
}

#[cfg(test)]
mod task_completion_tests {
    use super::{
        FunctionsConfig, FunctionsRuntime, SourceEventAdmissionError, TaskCompletion,
        MAX_ACTIVE_EVENT_BYTES,
    };
    use crate::manifest_json::parse_manifest;
    use crate::runner::{Runner, SpawnSpec};
    use fireemu_adapter_grpc::local::{Actor, CommitEvent};
    use fireemu_core_firestore::path::DocumentPath;
    use fireemu_core_firestore::store::{CommitVersion, Document, DocumentChange};
    use fireemu_core_functions::manifest::{TaskRateLimits, TaskRetryConfig, Trigger};
    use fireemu_core_session::clock::VirtualClock;
    use fireemu_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule, FaultState};
    use fireemu_core_types::ids::{DatabaseId, ProjectId, SessionId};
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
            hello_timeout: Duration::from_secs(20),
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
                project: "demo-app".to_owned(),
                default_bucket: "demo-app.appspot.com".to_owned(),
                location: "nam5".to_owned(),
                session: SessionId::new(7),
                max_running: 4,
                debug_mode: false,
                retry_attempts: 1,
                max_catch_up_runs: 1,
                runner_secret: "test-secret".to_owned(),
                overlap: super::OverlapPolicy::Allow,
                catch_up: super::CatchUpPolicy::All,
                functions_host: Some("127.0.0.1:5001".to_owned()),
            },
            Arc::new(Mutex::new(VirtualClock::new(
                LogicalInstant::from_unix_seconds(1_788_004_860),
            ))),
            Arc::new(runner),
            Some(spec),
        )
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

    fn created_commit() -> CommitEvent {
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
            hello_timeout: Duration::from_secs(20),
        };
        let replacement = Arc::new(Runner::spawn_spec(&spec).await.unwrap());
        let manifest = runtime.manifest().clone();
        runtime
            .reload_codebase(super::CodebaseSpec {
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
}
