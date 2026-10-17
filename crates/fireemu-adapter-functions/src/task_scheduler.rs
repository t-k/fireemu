//! Bounded Cloud Tasks queue admission and dispatch scheduling.
//!
//! The pinned Firebase emulator owns a FIFO per task function, starts its token bucket empty,
//! and keeps one concurrency slot for a task across retry backoff. This state machine mirrors
//! those observable rules while adding a documented process-wide retained-body budget so a
//! local caller cannot grow the daemon without bound.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fireemu_core_functions::manifest::{
    FunctionManifest, TaskRateLimits, TaskRetryConfig, Trigger,
};
use serde_json::{json, Value};

use crate::tasks::Task;

/// Retry and rate deadlines use native time or a host-independent elapsed axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TaskTime {
    Real(Instant),
    Virtual(u128),
}

impl From<Instant> for TaskTime {
    fn from(value: Instant) -> Self {
        Self::Real(value)
    }
}

impl TaskTime {
    pub(crate) fn checked_add(self, duration: Duration) -> Option<Self> {
        match self {
            Self::Real(instant) => instant.checked_add(duration).map(Self::Real),
            Self::Virtual(nanos) => nanos.checked_add(duration.as_nanos()).map(Self::Virtual),
        }
    }
    fn duration_since(self, earlier: Self) -> Duration {
        self.saturating_duration_since(earlier)
    }
    pub(crate) fn saturating_duration_since(self, earlier: Self) -> Duration {
        match (self, earlier) {
            (Self::Real(now), Self::Real(before)) => now.saturating_duration_since(before),
            (Self::Virtual(now), Self::Virtual(before)) => {
                let nanos = now.saturating_sub(before);
                let seconds = nanos / 1_000_000_000;
                match u64::try_from(seconds) {
                    Ok(seconds) => Duration::new(
                        seconds,
                        u32::try_from(nanos % 1_000_000_000).expect("nanosecond remainder"),
                    ),
                    Err(_) => Duration::MAX,
                }
            }
            _ => unreachable!("one task scheduler never changes its clock policy"),
        }
    }
}

impl std::ops::Add<Duration> for TaskTime {
    type Output = Self;
    fn add(self, duration: Duration) -> Self {
        match self {
            Self::Real(instant) => Self::Real(instant + duration),
            Self::Virtual(nanos) => Self::Virtual(nanos.saturating_add(duration.as_nanos())),
        }
    }
}

/// The pinned emulator's `Queue` default capacity.
pub(crate) const MAX_PENDING_PER_QUEUE: usize = 10_000;
/// A local safety ceiling across pending, running and retry-waiting tasks.
const MAX_OUTSTANDING_TASKS: usize = 10_000;
/// A local safety ceiling for task data and duplicate-detection names retained by the runtime.
const MAX_RETAINED_TASK_BYTES: usize = 64 * 1024 * 1024;
/// Completed names retained for duplicate detection across all queues.
const MAX_COMPLETED_NAMES: usize = 65_536;
/// Completed-name storage has a tighter subset ceiling because names outlive task bodies.
const MAX_COMPLETED_HISTORY_BYTES: usize = 8 * 1024 * 1024;
const TOKEN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const MAX_STATISTICS_BUCKETS: usize = 512;
const TASKS_ADDED_WINDOW: Duration = Duration::from_secs(5 * 60);
const COMPLETED_TASKS_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    Duplicate,
    QueueFull,
    RuntimeFull,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetryToken {
    Ready,
    WaitUntil(TaskTime),
    Gone,
}

#[derive(Debug)]
struct QueuedTask {
    id: u64,
    task: Task,
    retry: TaskRetryConfig,
    retained_bytes: usize,
    name: Arc<str>,
    /// Set by [`TaskScheduler::run_now`]: the task no longer waits for its `scheduleTime`.
    run_now: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ActivePhase {
    Dispatch,
    Concurrency,
    Retry(TaskTime),
    Rate(TaskTime),
}

#[derive(Debug)]
struct ActiveTask {
    phase: ActivePhase,
    retained_bytes: usize,
    name: Arc<str>,
}

#[derive(Debug)]
struct StatisticBucket {
    recorded_at: TaskTime,
    count: u64,
}

#[derive(Debug)]
struct StatisticWindow {
    window: Duration,
    buckets: VecDeque<StatisticBucket>,
}

impl StatisticWindow {
    fn new(window: Duration) -> Self {
        Self {
            window,
            buckets: VecDeque::new(),
        }
    }

    fn prune(&mut self, now: TaskTime) {
        while self
            .buckets
            .front()
            .is_some_and(|bucket| now.saturating_duration_since(bucket.recorded_at) >= self.window)
        {
            self.buckets.pop_front();
        }
    }

    fn record(&mut self, now: impl Into<TaskTime>) {
        let now = now.into();
        self.prune(now);
        if let Some(bucket) = self.buckets.back_mut() {
            if bucket.recorded_at == now {
                bucket.count = bucket.count.saturating_add(1);
                return;
            }
        }
        if self.buckets.len() == MAX_STATISTICS_BUCKETS {
            self.buckets.pop_front();
        }
        self.buckets.push_back(StatisticBucket {
            recorded_at: now,
            count: 1,
        });
    }

    fn count(&mut self, now: impl Into<TaskTime>) -> u64 {
        let now = now.into();
        self.prune(now);
        self.buckets
            .iter()
            .fold(0, |total, bucket| total.saturating_add(bucket.count))
    }

    fn clear(&mut self) {
        self.buckets = VecDeque::new();
    }

    #[cfg(test)]
    fn retained_bytes(&self) -> usize {
        self.buckets.capacity() * std::mem::size_of::<StatisticBucket>()
    }
}

#[derive(Debug)]
struct QueueState {
    limits: TaskRateLimits,
    pending: VecDeque<QueuedTask>,
    active: BTreeMap<u64, ActiveTask>,
    names: BTreeSet<Arc<str>>,
    tokens: f64,
    last_refill: TaskTime,
    added_times: StatisticWindow,
    completed_times: StatisticWindow,
    failed_times: StatisticWindow,
}

impl QueueState {
    fn new(limits: TaskRateLimits, now: TaskTime) -> Self {
        Self {
            limits,
            pending: VecDeque::new(),
            active: BTreeMap::new(),
            names: BTreeSet::new(),
            tokens: 0.0,
            last_refill: now,
            added_times: StatisticWindow::new(TASKS_ADDED_WINDOW),
            completed_times: StatisticWindow::new(COMPLETED_TASKS_WINDOW),
            failed_times: StatisticWindow::new(TASKS_ADDED_WINDOW),
        }
    }

    fn refill(&mut self, now: TaskTime) {
        if now.duration_since(self.last_refill) < TOKEN_REFRESH_INTERVAL {
            return;
        }
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let rate = self.limits.max_dispatches_per_second;
        // The pinned emulator uses this exact minimum burst capacity (`TaskQueue.maxTokens`,
        // `taskQueue.js:123`), which lets a fractional-rate queue eventually own one token.
        self.tokens = (self.tokens + elapsed * rate).min(rate.max(1.1));
        self.last_refill = now;
    }

    fn next_refill(&self) -> Option<TaskTime> {
        (self.limits.max_concurrent_dispatches > 0
            && self.limits.max_dispatches_per_second > 0.0
            && !self.pending.is_empty())
        .then_some(self.last_refill + TOKEN_REFRESH_INTERVAL)
    }
}

/// A task that has not been dispatched yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingTask {
    pub function: String,
    pub name: String,
    pub schedule_time: Option<String>,
    pub run_now: bool,
}

/// Whether `task` may be dispatched at `epoch_nanos` (nanoseconds since the Unix epoch on the
/// axis the scheduler is gated on). Without an epoch nothing waits; a task without a
/// `scheduleTime` never waits; a `scheduleTime` that does not parse never waits either (the
/// enqueue route refuses one, so this only meets a task from a profile that does not validate).
fn schedule_is_due(task: &Task, epoch_nanos: Option<i128>) -> bool {
    epoch_nanos.is_none_or(|epoch| {
        task.schedule_time.as_deref().is_none_or(|text| {
            fireemu_core_types::time::LogicalInstant::parse_rfc3339(text)
                .is_ok_and(|instant| instant.as_nanos() <= epoch)
        })
    })
}

impl QueueState {
    /// How long until the earliest pending task that is not yet due becomes due.
    fn next_schedule_in(&self, epoch_nanos: i128) -> Option<Duration> {
        self.pending
            .iter()
            .filter(|queued| !queued.run_now)
            .filter_map(|queued| {
                let text = queued.task.schedule_time.as_deref()?;
                let due = fireemu_core_types::time::LogicalInstant::parse_rfc3339(text)
                    .ok()?
                    .as_nanos();
                let wait = u128::try_from(due.checked_sub(epoch_nanos)?).ok()?;
                (wait > 0).then(|| {
                    Duration::new(
                        u64::try_from(wait / 1_000_000_000).unwrap_or(u64::MAX),
                        u32::try_from(wait % 1_000_000_000).unwrap_or(0),
                    )
                })
            })
            .min()
    }
}

#[derive(Debug)]
pub(crate) struct Dispatch {
    pub id: u64,
    pub generation: u64,
    pub queue: String,
    pub project: String,
    pub region: String,
    pub function: String,
    pub queue_key: String,
    pub task: Task,
    pub retry: TaskRetryConfig,
}

#[derive(Debug)]
pub(crate) struct TaskScheduler {
    generation: u64,
    next_id: u64,
    queues: BTreeMap<String, QueueState>,
    outstanding: usize,
    failed_total: u64,
    retained_bytes: usize,
    completed_names: VecDeque<(String, Arc<str>)>,
    completed_history_bytes: usize,
    next_queue: usize,
    closed: bool,
}

impl TaskScheduler {
    pub(crate) fn from_manifest(manifest: &FunctionManifest, now: impl Into<TaskTime>) -> Self {
        let now = now.into();
        let queues = manifest
            .functions
            .iter()
            .filter_map(|function| match function.trigger {
                Trigger::TaskQueue { rate_limits, .. } => {
                    Some((function.name.clone(), QueueState::new(rate_limits, now)))
                }
                _ => None,
            })
            .collect();
        Self {
            generation: 0,
            next_id: 0,
            queues,
            outstanding: 0,
            failed_total: 0,
            retained_bytes: 0,
            completed_names: VecDeque::new(),
            completed_history_bytes: 0,
            next_queue: 0,
            closed: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn enqueue(
        &mut self,
        queue: &str,
        task: Task,
        retry: TaskRetryConfig,
        retained_bytes: usize,
    ) -> Result<(), AdmissionError> {
        self.enqueue_at(queue, task, retry, retained_bytes, Instant::now())
    }

    pub(crate) fn enqueue_at(
        &mut self,
        queue: &str,
        task: Task,
        retry: TaskRetryConfig,
        retained_bytes: usize,
        now: impl Into<TaskTime>,
    ) -> Result<(), AdmissionError> {
        let now = now.into();
        if self.closed {
            return Err(AdmissionError::Closed);
        }
        let Some(state) = self.queues.get_mut(queue) else {
            return Err(AdmissionError::Closed);
        };
        if state.names.contains(task.name.as_str()) {
            return Err(AdmissionError::Duplicate);
        }
        if state.pending.len() >= MAX_PENDING_PER_QUEUE {
            return Err(AdmissionError::QueueFull);
        }
        let next_outstanding = self
            .outstanding
            .checked_add(1)
            .ok_or(AdmissionError::RuntimeFull)?;
        let next_bytes = self
            .retained_bytes
            .checked_add(retained_bytes)
            .ok_or(AdmissionError::RuntimeFull)?;
        if next_outstanding > MAX_OUTSTANDING_TASKS || next_bytes > MAX_RETAINED_TASK_BYTES {
            return Err(AdmissionError::RuntimeFull);
        }
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let name = Arc::<str>::from(task.name.as_str());
        state.names.insert(name.clone());
        state.pending.push_back(QueuedTask {
            id: self.next_id,
            task,
            retry,
            retained_bytes,
            name,
            run_now: false,
        });
        state.added_times.record(now);
        self.outstanding = next_outstanding;
        self.retained_bytes = next_bytes;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn dispatch_ready(
        &mut self,
        now: Instant,
        project: &str,
        region_for: impl Fn(&str) -> Option<String>,
        maximum: usize,
    ) -> (Vec<Dispatch>, Option<Instant>) {
        let (dispatches, next) = self.dispatch_ready_at(now, None, project, region_for, maximum);
        (
            dispatches,
            next.map(|value| match value {
                TaskTime::Real(instant) => instant,
                TaskTime::Virtual(_) => unreachable!(),
            }),
        )
    }

    pub(crate) fn dispatch_ready_at(
        &mut self,
        now: impl Into<TaskTime>,
        epoch_nanos: Option<i128>,
        project: &str,
        region_for: impl Fn(&str) -> Option<String>,
        maximum: usize,
    ) -> (Vec<Dispatch>, Option<TaskTime>) {
        let now = now.into();
        let mut dispatches = Vec::new();
        for queue in self.queues.values_mut() {
            queue.refill(now);
        }
        let functions = self.queues.keys().cloned().collect::<Vec<_>>();
        while dispatches.len() < maximum && !functions.is_empty() {
            let mut selected = None;
            for offset in 0..functions.len() {
                let index = (self.next_queue + offset) % functions.len();
                let function = &functions[index];
                let queue = self
                    .queues
                    .get_mut(function)
                    .expect("the queue key came from this map");
                if queue.active.len()
                    >= usize::try_from(queue.limits.max_concurrent_dispatches).unwrap_or(usize::MAX)
                    || queue.tokens < 1.0
                {
                    continue;
                }
                let ready = queue.pending.iter().position(|queued| {
                    queued.run_now || schedule_is_due(&queued.task, epoch_nanos)
                });
                let Some(queued) = ready.and_then(|position| queue.pending.remove(position)) else {
                    continue;
                };
                let Some(region) = region_for(function) else {
                    queue.pending.push_front(queued);
                    continue;
                };
                queue.tokens -= 1.0;
                queue.active.insert(
                    queued.id,
                    ActiveTask {
                        phase: ActivePhase::Dispatch,
                        retained_bytes: queued.retained_bytes,
                        name: queued.name,
                    },
                );
                dispatches.push(Dispatch {
                    id: queued.id,
                    generation: self.generation,
                    queue: function.clone(),
                    project: project.to_owned(),
                    region: region.clone(),
                    function: function.clone(),
                    queue_key: crate::tasks::queue_key(project, &region, function),
                    task: queued.task,
                    retry: queued.retry,
                });
                selected = Some(index);
                break;
            }
            let Some(index) = selected else {
                break;
            };
            self.next_queue = (index + 1) % functions.len();
        }
        let refill_wake = self
            .queues
            .values()
            .filter_map(QueueState::next_refill)
            .min();
        // Native time knows when the earliest scheduled task falls due; the virtual axis is
        // woken by the clock change that moves it instead.
        let schedule_wake = match (now, epoch_nanos) {
            (TaskTime::Real(at), Some(epoch)) => self
                .queues
                .values()
                .filter_map(|queue| queue.next_schedule_in(epoch))
                .min()
                .and_then(|wait| at.checked_add(wait))
                .map(TaskTime::Real),
            _ => None,
        };
        let next_wake = match (refill_wake, schedule_wake) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        (dispatches, next_wake)
    }

    /// The tasks waiting in each queue, in dispatch order.
    pub(crate) fn pending_tasks(&self) -> Vec<PendingTask> {
        self.queues
            .iter()
            .flat_map(|(function, queue)| {
                queue.pending.iter().map(|queued| PendingTask {
                    function: function.clone(),
                    name: queued.task.name.clone(),
                    schedule_time: queued.task.schedule_time.clone(),
                    run_now: queued.run_now,
                })
            })
            .collect()
    }

    /// Releases pending tasks of `queue` from waiting for their `scheduleTime`: the one named
    /// `task` (a full resource name or its last path segment), or every pending one when `task`
    /// is `None`. Rate limits and concurrency still apply. Returns how many tasks were released.
    pub(crate) fn run_now(&mut self, queue: &str, task: Option<&str>) -> usize {
        let Some(state) = self.queues.get_mut(queue) else {
            return 0;
        };
        let mut released = 0;
        for queued in &mut state.pending {
            let named = task.is_none_or(|wanted| {
                queued.task.name == wanted || queued.task.name.rsplit('/').next() == Some(wanted)
            });
            if named && !queued.run_now {
                queued.run_now = true;
                released += 1;
            }
        }
        released
    }

    #[cfg(test)]
    pub(crate) fn finish(&mut self, queue: &str, id: u64, generation: u64) -> bool {
        self.finish_with_outcome(queue, id, generation, false)
    }

    #[cfg(test)]
    pub(crate) fn finish_with_outcome(
        &mut self,
        queue: &str,
        id: u64,
        generation: u64,
        failed: bool,
    ) -> bool {
        self.finish_with_outcome_at(queue, id, generation, failed, Instant::now())
    }

    pub(crate) fn finish_with_outcome_at(
        &mut self,
        queue: &str,
        id: u64,
        generation: u64,
        failed: bool,
        now: impl Into<TaskTime>,
    ) -> bool {
        let now = now.into();
        if generation != self.generation {
            return false;
        }
        let Some(state) = self.queues.get_mut(queue) else {
            return false;
        };
        let Some(active) = state.active.remove(&id) else {
            return false;
        };
        state.completed_times.record(now);
        if failed {
            self.failed_total = self.failed_total.saturating_add(1);
            state.failed_times.record(now);
        }
        self.outstanding = self.outstanding.saturating_sub(1);
        // The Task and its payload are gone, but the shared name stays in the duplicate index
        // until its completed-history entry expires. The enqueue charge includes that second
        // name copy, so only release the rest here.
        let history_bytes = active.name.len().saturating_add(queue.len());
        self.retained_bytes = self
            .retained_bytes
            .saturating_sub(active.retained_bytes.saturating_sub(history_bytes));
        self.completed_history_bytes = self.completed_history_bytes.saturating_add(history_bytes);
        self.completed_names
            .push_back((queue.to_owned(), active.name));
        while self.completed_names.len() > MAX_COMPLETED_NAMES
            || self.completed_history_bytes > MAX_COMPLETED_HISTORY_BYTES
        {
            let Some((expired_queue, expired_name)) = self.completed_names.pop_front() else {
                break;
            };
            let expired_bytes = expired_name.len().saturating_add(expired_queue.len());
            self.completed_history_bytes =
                self.completed_history_bytes.saturating_sub(expired_bytes);
            self.retained_bytes = self.retained_bytes.saturating_sub(expired_bytes);
            if let Some(expired_state) = self.queues.get_mut(&expired_queue) {
                expired_state.names.remove(expired_name.as_ref());
            }
        }
        true
    }

    pub(crate) fn reserve_retry(
        &mut self,
        queue: &str,
        id: u64,
        generation: u64,
        now: impl Into<TaskTime>,
    ) -> RetryToken {
        let now = now.into();
        if generation != self.generation {
            return RetryToken::Gone;
        }
        let Some(state) = self.queues.get_mut(queue) else {
            return RetryToken::Gone;
        };
        if !state.active.contains_key(&id) {
            return RetryToken::Gone;
        }
        state.refill(now);
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            RetryToken::Ready
        } else {
            RetryToken::WaitUntil(state.last_refill + TOKEN_REFRESH_INTERVAL)
        }
    }

    pub(crate) fn refund_token(&mut self, queue: &str, id: u64, generation: u64) {
        if generation != self.generation {
            return;
        }
        let Some(state) = self.queues.get_mut(queue) else {
            return;
        };
        if state.active.contains_key(&id) {
            state.tokens =
                (state.tokens + 1.0).min(state.limits.max_dispatches_per_second.max(1.1));
        }
    }

    /// A stale coroutine cannot update a task accepted after reset.
    pub(crate) fn set_phase(&mut self, dispatch: &Dispatch, phase: ActivePhase) {
        if dispatch.generation != self.generation {
            return;
        }
        if let Some(active) = self
            .queues
            .get_mut(&dispatch.queue)
            .and_then(|queue| queue.active.get_mut(&dispatch.id))
        {
            active.phase = phase;
        }
    }

    /// One projection drives both scoped waiting and bounded diagnostics. Due work remains
    /// included even before the dispatch coroutine observes its wakeup.
    pub(crate) fn idle_projection(&self, now: TaskTime, epoch: Option<i128>) -> Value {
        let mut runnable = 0usize;
        let mut excluded = 0usize;
        let mut waiting = Vec::new();
        let mut reasons = BTreeMap::<String, usize>::new();
        let mut record = |function: &str,
                          reason: &str,
                          future: bool,
                          deadline: Option<TaskTime>,
                          schedule: Option<&str>| {
            *reasons.entry(reason.to_owned()).or_default() += 1;
            if future {
                excluded += 1;
            } else {
                runnable += 1;
            }
            if waiting.len() < 32 {
                waiting.push(json!({
                    "queue": function, "function": function, "reason": reason,
                    "excluded": future, "scheduleTime": schedule,
                    "waitMillis": deadline.map(|value| value.saturating_duration_since(now).as_millis().to_string()),
                    "elapsedDeadlineNanos": deadline.and_then(|value| match value { TaskTime::Virtual(nanos) => Some(nanos.to_string()), TaskTime::Real(_) => None }),
                }));
            }
        };
        for (function, queue) in &self.queues {
            for queued in &queue.pending {
                let future = !queued.run_now && !schedule_is_due(&queued.task, epoch);
                let saturated = queue.active.len()
                    >= usize::try_from(queue.limits.max_concurrent_dispatches)
                        .unwrap_or(usize::MAX);
                let (reason, deadline) = if future {
                    ("scheduleTime", None)
                } else if saturated {
                    ("concurrencyLimit", None)
                } else if queue.tokens < 1.0 {
                    (
                        "rateLimit",
                        Some(queue.last_refill + TOKEN_REFRESH_INTERVAL),
                    )
                } else {
                    ("ready", None)
                };
                record(
                    function,
                    reason,
                    future,
                    deadline,
                    queued.task.schedule_time.as_deref(),
                );
            }
            for active in queue.active.values() {
                let (reason, future, deadline) = match active.phase {
                    ActivePhase::Dispatch => ("activeHttp", false, None),
                    ActivePhase::Concurrency => ("concurrencyLimit", false, None),
                    ActivePhase::Retry(deadline) => {
                        ("retryBackoff", now < deadline, Some(deadline))
                    }
                    ActivePhase::Rate(deadline) => ("rateLimit", false, Some(deadline)),
                };
                record(function, reason, future, deadline, None);
            }
        }
        json!({
            "runnable": runnable, "excluded": excluded,
            "omitted": (runnable + excluded).saturating_sub(waiting.len()),
            "waiting": waiting, "reasons": reasons, "failedTotal": self.failed_total,
            "clock": match now { TaskTime::Real(_) => "real", TaskTime::Virtual(_) => "tasks" },
        })
    }

    pub(crate) fn outstanding(&self) -> usize {
        self.outstanding
    }

    pub(crate) fn active(&self) -> usize {
        self.queues.values().map(|queue| queue.active.len()).sum()
    }

    #[cfg(test)]
    pub(crate) fn statistics(
        &mut self,
        project: &str,
        region_for: impl Fn(&str) -> Option<String>,
    ) -> Value {
        self.statistics_at(project, region_for, Instant::now())
    }

    #[allow(clippy::cast_precision_loss)] // queueStats publishes the official floating-point rate shape
    pub(crate) fn statistics_at(
        &mut self,
        project: &str,
        region_for: impl Fn(&str) -> Option<String>,
        now: impl Into<TaskTime>,
    ) -> Value {
        let now = now.into();
        let mut statistics = serde_json::Map::new();
        for (function, queue) in &mut self.queues {
            let key = region_for(function).map_or_else(
                || function.clone(),
                |region| crate::tasks::queue_key(project, &region, function),
            );
            statistics.insert(
                key,
                json!({
                    "numberOfTasks": queue.pending.len(),
                    "tasksAdded": queue.added_times.count(now) as f64 / 5.0,
                    "completedLastMin": queue.completed_times.count(now),
                    "failedTasks": queue.failed_times.count(now) as f64 / 5.0,
                    "runningTasks": queue.limits.max_concurrent_dispatches,
                    "maxRate": queue.limits.max_dispatches_per_second,
                    "maxConcurrent": queue.limits.max_concurrent_dispatches,
                }),
            );
        }
        Value::Object(statistics)
    }

    #[cfg(test)]
    pub(crate) fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    #[cfg(test)]
    fn statistics_retained_bytes(&self) -> usize {
        self.queues
            .values()
            .map(|queue| {
                queue.added_times.retained_bytes()
                    + queue.completed_times.retained_bytes()
                    + queue.failed_times.retained_bytes()
            })
            .sum()
    }

    pub(crate) fn reset(&mut self, now: impl Into<TaskTime>) {
        let now = now.into();
        self.generation = self.generation.wrapping_add(1);
        self.outstanding = 0;
        self.failed_total = 0;
        self.retained_bytes = 0;
        self.completed_names.clear();
        self.completed_history_bytes = 0;
        self.next_queue = 0;
        for queue in self.queues.values_mut() {
            queue.pending.clear();
            queue.active.clear();
            queue.names.clear();
            queue.tokens = 0.0;
            queue.last_refill = now;
            queue.added_times.clear();
            queue.completed_times.clear();
            queue.failed_times.clear();
        }
    }

    pub(crate) fn close(&mut self, now: impl Into<TaskTime>) {
        let now = now.into();
        self.reset(now);
        self.closed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AdmissionError, TaskScheduler, MAX_COMPLETED_HISTORY_BYTES, MAX_PENDING_PER_QUEUE,
        MAX_RETAINED_TASK_BYTES,
    };
    use crate::tasks::Task;
    use fireemu_core_functions::manifest::{
        FunctionGeneration, FunctionManifest, FunctionSpec, PlatformOptions, TaskRateLimits,
        TaskRetryConfig, Trigger, DEFAULT_REGION, DEFAULT_TIMEOUT_SECONDS,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    fn manifest(limits: TaskRateLimits) -> FunctionManifest {
        FunctionManifest {
            functions: vec![FunctionSpec {
                name: "queue".to_owned(),
                region: DEFAULT_REGION.to_owned(),
                entry_point: "queue".to_owned(),
                trigger: Trigger::TaskQueue {
                    retry: TaskRetryConfig::default(),
                    rate_limits: limits,
                },
                timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
                retry: false,
                generation: FunctionGeneration::Second,
                concurrency: None,
                platform_options: PlatformOptions::default(),
            }],
            ignored: Vec::new(),
        }
    }

    fn two_queue_manifest(limits: TaskRateLimits) -> FunctionManifest {
        let mut first = manifest(limits).functions.remove(0);
        first.name = "a".to_owned();
        first.entry_point = "a".to_owned();
        let mut second = first.clone();
        second.name = "b".to_owned();
        second.entry_point = "b".to_owned();
        FunctionManifest {
            functions: vec![first, second],
            ignored: Vec::new(),
        }
    }

    fn task(name: &str) -> Task {
        Task {
            name: name.to_owned(),
            url: "http://127.0.0.1/function".to_owned(),
            headers: BTreeMap::new(),
            body: json!({"data": {"id": name}}),
            schedule_time: None,
            dispatch_deadline_seconds: 60,
        }
    }

    proptest::proptest! {
        #[test]
        fn idle_projection_matches_reference_retry_phase(now in 0u64..10000, deadline in 0u64..10000, phase in 0u8..4) {
            let start = Instant::now();
            let mut scheduler = scheduler_with("hidden", None, start);
            let (dispatches, _) = scheduler.dispatch_ready_at(start + Duration::from_secs(1), None, "demo", |_| Some(DEFAULT_REGION.into()), 1);
            let until = super::TaskTime::Real(start + Duration::from_millis(deadline));
            let active = match phase {
                0 => super::ActivePhase::Dispatch,
                1 => super::ActivePhase::Retry(until),
                2 => super::ActivePhase::Rate(until),
                _ => super::ActivePhase::Concurrency,
            };
            scheduler.set_phase(&dispatches[0], active);
            let actual = scheduler.idle_projection((start + Duration::from_millis(now)).into(), None);
            let excluded = phase == 1 && now < deadline;
            proptest::prop_assert_eq!(actual["excluded"].as_u64(), Some(u64::from(excluded)));
            proptest::prop_assert_eq!(actual["runnable"].as_u64(), Some(u64::from(!excluded)));
        }

    }

    #[test]
    fn idle_projection_is_bounded_and_run_now_keeps_rate_and_concurrency_waits() {
        let start = Instant::now();
        let epoch = nanos("2026-02-01T00:00:00Z");
        let mut scheduler = TaskScheduler::from_manifest(
            &two_queue_manifest(TaskRateLimits {
                max_concurrent_dispatches: 1,
                max_dispatches_per_second: 0.5,
            }),
            start,
        );
        for index in 0..40 {
            let mut queued = task(&format!("secret-{index}"));
            queued.schedule_time = Some("2026-02-01T00:30:00Z".into());
            scheduler
                .enqueue_at(
                    if index % 2 == 0 { "a" } else { "b" },
                    queued,
                    TaskRetryConfig::default(),
                    64,
                    start,
                )
                .unwrap();
        }
        let before = scheduler.idle_projection(start.into(), Some(epoch));
        assert_eq!(before["excluded"], 40);
        assert_eq!(before["reasons"]["scheduleTime"], 40);
        assert_eq!(before["waiting"].as_array().unwrap().len(), 32);
        assert_eq!(before["omitted"], 8);
        assert!(!before.to_string().contains("secret-"));
        scheduler.run_now("a", None);
        let released = scheduler.idle_projection(start.into(), Some(epoch));
        assert_eq!(released["runnable"], 20);
        assert_eq!(released["excluded"], 20);
        assert_eq!(released["waiting"][0]["reason"], "rateLimit");
        let (dispatches, _) = scheduler.dispatch_ready_at(
            start + Duration::from_secs(2),
            Some(epoch),
            "demo",
            |_| Some(DEFAULT_REGION.into()),
            10,
        );
        assert_eq!(dispatches.len(), 1);
        let active =
            scheduler.idle_projection((start + Duration::from_secs(2)).into(), Some(epoch));
        assert_eq!(active["runnable"], 20);
        assert!(active["waiting"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["reason"] == "concurrencyLimit"));
        assert!(scheduler.finish_with_outcome_at(
            "a",
            dispatches[0].id,
            dispatches[0].generation,
            true,
            start
        ));
        assert_eq!(
            scheduler.idle_projection(start.into(), Some(epoch))["failedTotal"],
            1
        );
        scheduler.reset(start);
        assert_eq!(
            scheduler.idle_projection(start.into(), Some(epoch))["failedTotal"],
            0
        );
    }

    #[test]
    fn idle_projection_tracks_schedule_retry_rate_and_generation_boundaries() {
        let start = Instant::now();
        let epoch = nanos("2026-02-01T00:00:05Z");
        let mut scheduler = scheduler_with("secret-payload", Some("2026-02-01T00:00:05Z"), start);
        let future = scheduler.idle_projection(start.into(), Some(epoch - 1));
        assert_eq!(future["excluded"], 1);
        assert_eq!(future["runnable"], 0);
        assert!(!future.to_string().contains("secret-payload"));
        assert_eq!(
            scheduler.idle_projection(start.into(), Some(epoch))["runnable"],
            1
        );
        let (dispatches, _) = scheduler.dispatch_ready_at(
            start + Duration::from_secs(1),
            Some(epoch),
            "demo",
            |_| Some(DEFAULT_REGION.into()),
            1,
        );
        let dispatch = &dispatches[0];
        assert_eq!(
            scheduler.idle_projection(start.into(), Some(epoch))["runnable"],
            1
        );
        let deadline = super::TaskTime::Real(start + Duration::from_secs(5));
        scheduler.set_phase(dispatch, super::ActivePhase::Retry(deadline));
        for offset in 0..=6 {
            let projection = scheduler
                .idle_projection((start + Duration::from_secs(offset)).into(), Some(epoch));
            assert_eq!(projection["runnable"], usize::from(offset >= 5));
            assert_eq!(projection["excluded"], usize::from(offset < 5));
        }
        scheduler.set_phase(dispatch, super::ActivePhase::Rate(deadline));
        assert_eq!(
            scheduler.idle_projection(start.into(), Some(epoch))["runnable"],
            1
        );
        scheduler.set_phase(dispatch, super::ActivePhase::Dispatch);
        assert_eq!(
            scheduler.idle_projection(start.into(), Some(epoch))["runnable"],
            1
        );
        let old_generation = scheduler.generation;
        scheduler.generation += 1;
        scheduler.set_phase(dispatch, super::ActivePhase::Retry(deadline));
        assert_eq!(
            scheduler.idle_projection(start.into(), Some(epoch))["runnable"],
            1
        );
        assert_ne!(old_generation, scheduler.generation);
    }

    #[test]
    fn virtual_schedule_time_gates_dispatch_at_the_exact_instant() {
        let start = Instant::now();
        let mut scheduler = TaskScheduler::from_manifest(
            &manifest(TaskRateLimits {
                max_concurrent_dispatches: 2,
                max_dispatches_per_second: 2.0,
            }),
            start,
        );
        let mut future = task("future");
        future.schedule_time = Some("2026-02-01T00:00:00Z".into());
        scheduler
            .enqueue_at("queue", future, TaskRetryConfig::default(), 64, start)
            .unwrap();
        let end = fireemu_core_types::time::LogicalInstant::parse_rfc3339("2026-02-01T00:00:00Z")
            .unwrap();
        let (early, _) = scheduler.dispatch_ready_at(
            start + Duration::from_secs(1),
            Some(end.as_nanos() - 1),
            "demo-app",
            |_| Some(DEFAULT_REGION.into()),
            2,
        );
        assert!(early.is_empty());
        let (due, _) = scheduler.dispatch_ready_at(
            start + Duration::from_secs(1),
            Some(end.as_nanos()),
            "demo-app",
            |_| Some(DEFAULT_REGION.into()),
            2,
        );
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].task.name, "future");
    }

    fn nanos(text: &str) -> i128 {
        fireemu_core_types::time::LogicalInstant::parse_rfc3339(text)
            .unwrap()
            .as_nanos()
    }

    fn scheduler_with(task_name: &str, schedule: Option<&str>, start: Instant) -> TaskScheduler {
        let mut scheduler = TaskScheduler::from_manifest(
            &manifest(TaskRateLimits {
                max_concurrent_dispatches: 4,
                max_dispatches_per_second: 100.0,
            }),
            start,
        );
        let mut queued = task(task_name);
        queued.schedule_time = schedule.map(str::to_owned);
        scheduler
            .enqueue_at("queue", queued, TaskRetryConfig::default(), 64, start)
            .unwrap();
        scheduler
    }

    /// Native time: a task scheduled for later is held, the scheduler names the instant it falls
    /// due so the dispatch loop sleeps exactly that long, and it goes at that instant.
    #[test]
    fn a_native_schedule_time_holds_the_task_and_names_the_wake() {
        let start = Instant::now();
        let mut scheduler = scheduler_with("later", Some("2026-02-01T00:00:05Z"), start);
        let epoch = nanos("2026-02-01T00:00:00Z");
        let region = |_: &str| Some(DEFAULT_REGION.to_owned());
        let now = start + Duration::from_secs(2);
        let (early, wake) = scheduler.dispatch_ready_at(now, Some(epoch), "demo-app", region, 4);
        assert!(early.is_empty());
        assert_eq!(
            wake.map(|w| w.saturating_duration_since(super::TaskTime::Real(now))),
            Some(Duration::from_secs(1)),
            "the refill tick (1s) comes before the schedule (5s)"
        );
        // Once the refill ticks have passed, the only thing left to wait for is the schedule.
        let (still, wake) = scheduler.dispatch_ready_at(
            start + Duration::from_secs(3),
            Some(epoch + 1_000_000_000),
            "demo-app",
            region,
            4,
        );
        assert!(still.is_empty());
        assert!(wake.is_some());
        let (due, _) = scheduler.dispatch_ready_at(
            start + Duration::from_secs(10),
            Some(epoch + 5_000_000_000),
            "demo-app",
            region,
            4,
        );
        assert_eq!(due.len(), 1);
    }

    #[test]
    fn the_schedule_wake_is_the_earliest_scheduled_task_when_nothing_else_waits() {
        let start = Instant::now();
        let mut scheduler = TaskScheduler::from_manifest(
            &manifest(TaskRateLimits {
                max_concurrent_dispatches: 4,
                // No tokens ever: the refill never names a wake, only the schedule does.
                max_dispatches_per_second: 0.0,
            }),
            start,
        );
        for (name, schedule) in [
            ("far", "2026-02-01T00:10:00Z"),
            ("near", "2026-02-01T00:00:07Z"),
        ] {
            let mut queued = task(name);
            queued.schedule_time = Some(schedule.to_owned());
            scheduler
                .enqueue_at("queue", queued, TaskRetryConfig::default(), 64, start)
                .unwrap();
        }
        let (none, wake) = scheduler.dispatch_ready_at(
            start,
            Some(nanos("2026-02-01T00:00:00Z")),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            4,
        );
        assert!(none.is_empty());
        assert_eq!(
            wake,
            Some(super::TaskTime::Real(start + Duration::from_secs(7)))
        );
    }

    /// The wait until a scheduled task falls due keeps its fraction of a second, names nothing
    /// for a task that is due already, and a due task that only lacks a dispatch token does not
    /// make the loop spin on a zero wait.
    #[test]
    fn the_schedule_wake_keeps_fractions_and_ignores_a_task_that_is_already_due() {
        let start = Instant::now();
        let mut scheduler = TaskScheduler::from_manifest(
            &manifest(TaskRateLimits {
                max_concurrent_dispatches: 4,
                max_dispatches_per_second: 0.0,
            }),
            start,
        );
        let mut later = task("later");
        later.schedule_time = Some("2026-02-01T00:00:07.25Z".to_owned());
        scheduler
            .enqueue_at("queue", later, TaskRetryConfig::default(), 64, start)
            .unwrap();
        let region = |_: &str| Some(DEFAULT_REGION.to_owned());
        let (_, wake) = scheduler.dispatch_ready_at(
            start,
            Some(nanos("2026-02-01T00:00:00Z")),
            "demo-app",
            region,
            4,
        );
        assert_eq!(
            wake,
            Some(super::TaskTime::Real(start + Duration::from_millis(7250)))
        );
        // Due exactly now, but no token to dispatch it: there is nothing to wait for.
        let (none, wake) = scheduler.dispatch_ready_at(
            start,
            Some(nanos("2026-02-01T00:00:07.25Z")),
            "demo-app",
            region,
            4,
        );
        assert!(none.is_empty());
        assert_eq!(wake, None);
    }

    #[test]
    fn run_now_releases_a_task_before_its_schedule_time_and_only_that_task() {
        let start = Instant::now();
        let mut scheduler = TaskScheduler::from_manifest(
            &manifest(TaskRateLimits {
                max_concurrent_dispatches: 4,
                max_dispatches_per_second: 100.0,
            }),
            start,
        );
        for name in [
            "projects/p/locations/l/queues/queue/tasks/a",
            "projects/p/locations/l/queues/queue/tasks/b",
        ] {
            let mut queued = task(name);
            queued.schedule_time = Some("2030-01-01T00:00:00Z".to_owned());
            scheduler
                .enqueue_at("queue", queued, TaskRetryConfig::default(), 64, start)
                .unwrap();
        }
        let epoch = Some(nanos("2026-02-01T00:00:00Z"));
        let region = |_: &str| Some(DEFAULT_REGION.to_owned());
        assert_eq!(scheduler.run_now("queue", Some("nope")), 0);
        assert_eq!(scheduler.run_now("elsewhere", None), 0);
        assert_eq!(scheduler.run_now("queue", Some("b")), 1);
        assert_eq!(scheduler.run_now("queue", Some("b")), 0, "already released");
        let (released, _) = scheduler.dispatch_ready_at(
            start + Duration::from_secs(2),
            epoch,
            "demo-app",
            region,
            4,
        );
        assert_eq!(released.len(), 1);
        assert!(released[0].task.name.ends_with("/b"));
        let pending = scheduler.pending_tasks();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].name.ends_with("/a"));
        assert_eq!(
            pending[0].schedule_time.as_deref(),
            Some("2030-01-01T00:00:00Z")
        );
        assert!(!pending[0].run_now);
        assert_eq!(scheduler.run_now("queue", None), 1);
        let (rest, _) = scheduler.dispatch_ready_at(
            start + Duration::from_secs(3),
            epoch,
            "demo-app",
            region,
            4,
        );
        assert_eq!(rest.len(), 1);
    }

    #[test]
    fn token_bucket_starts_empty_and_concurrency_holds_the_next_task() {
        let start = Instant::now();
        let mut scheduler = TaskScheduler::from_manifest(
            &manifest(TaskRateLimits {
                max_concurrent_dispatches: 1,
                max_dispatches_per_second: 2.0,
            }),
            start,
        );
        scheduler
            .enqueue("queue", task("a"), TaskRetryConfig::default(), 1)
            .unwrap();
        scheduler
            .enqueue("queue", task("b"), TaskRetryConfig::default(), 1)
            .unwrap();

        let (early, wake) = scheduler.dispatch_ready(
            start + Duration::from_millis(999),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            10,
        );
        assert!(early.is_empty());
        assert_eq!(wake, Some(start + Duration::from_secs(1)));

        let (first, _) = scheduler.dispatch_ready(
            start + Duration::from_secs(1),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            10,
        );
        assert_eq!(first.len(), 1);
        let (blocked, _) = scheduler.dispatch_ready(
            start + Duration::from_secs(1),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            10,
        );
        assert!(blocked.is_empty());

        assert!(scheduler.finish("queue", first[0].id, first[0].generation));
        let (second, _) = scheduler.dispatch_ready(
            start + Duration::from_secs(1),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            10,
        );
        assert_eq!(second.len(), 1);
    }

    #[test]
    fn queue_statistics_report_pending_work_and_rate_limits() {
        let start = Instant::now();
        let mut scheduler = TaskScheduler::from_manifest(
            &manifest(TaskRateLimits {
                max_concurrent_dispatches: 3,
                max_dispatches_per_second: 7.5,
            }),
            start,
        );
        scheduler
            .enqueue("queue", task("a"), TaskRetryConfig::default(), 1)
            .unwrap();
        scheduler
            .enqueue("queue", task("b"), TaskRetryConfig::default(), 1)
            .unwrap();

        let stats = scheduler.statistics("demo-app", |_| Some("us-central1".to_owned()));
        assert_eq!(
            stats["queue:demo-app-us-central1-queue"]["numberOfTasks"],
            2
        );
        assert_eq!(stats["queue:demo-app-us-central1-queue"]["tasksAdded"], 0.4);
        assert_eq!(
            stats["queue:demo-app-us-central1-queue"]["completedLastMin"],
            0
        );
        assert_eq!(
            stats["queue:demo-app-us-central1-queue"]["failedTasks"],
            0.0
        );
        assert_eq!(stats["queue:demo-app-us-central1-queue"]["runningTasks"], 3);
        assert_eq!(stats["queue:demo-app-us-central1-queue"]["maxRate"], 7.5);
        assert_eq!(
            stats["queue:demo-app-us-central1-queue"]["maxConcurrent"],
            3
        );
    }

    #[test]
    fn queue_statistics_history_is_bounded_when_queue_stats_is_never_read() {
        let start = Instant::now();
        let mut scheduler = TaskScheduler::from_manifest(
            &manifest(TaskRateLimits {
                max_concurrent_dispatches: 4096,
                max_dispatches_per_second: 4096.0,
            }),
            start,
        );
        for sequence in 0..2048 {
            scheduler
                .enqueue(
                    "queue",
                    task(&format!("history-{sequence}")),
                    TaskRetryConfig::default(),
                    1,
                )
                .unwrap();
        }

        let queue = scheduler.queues.get("queue").expect("queue exists");
        assert!(
            queue.added_times.buckets.len() <= 512,
            "enqueue history grew to {} entries without a statistics read",
            queue.added_times.buckets.len()
        );

        let (dispatches, _) = scheduler.dispatch_ready(
            start + Duration::from_secs(1),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            4096,
        );
        assert_eq!(dispatches.len(), 2048);
        for (sequence, dispatch) in dispatches.iter().enumerate() {
            assert!(scheduler.finish_with_outcome(
                "queue",
                dispatch.id,
                dispatch.generation,
                sequence % 2 == 0,
            ));
        }

        let queue = scheduler.queues.get("queue").expect("queue exists");
        assert!(
            queue.completed_times.buckets.len() <= 512,
            "completed history grew to {} entries without a statistics read",
            queue.completed_times.buckets.len()
        );
        assert!(
            queue.failed_times.buckets.len() <= 512,
            "failed history grew to {} entries without a statistics read",
            queue.failed_times.buckets.len()
        );
        assert!(
            scheduler.statistics_retained_bytes()
                <= 512 * 3 * std::mem::size_of::<super::StatisticBucket>()
        );
    }

    #[test]
    fn queue_statistics_prune_each_record_at_the_exact_window_boundary() {
        let start = Instant::now();
        let mut window = super::StatisticWindow::new(Duration::from_secs(60));
        window.record(start);
        window.record(start + Duration::from_millis(900));

        assert_eq!(window.count(start + Duration::from_millis(60_500)), 1);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one scenario covers the exact and adjacent window boundaries
    fn queue_statistics_preserves_same_timestamp_counts_and_window_boundaries() {
        let start = Instant::now();
        let mut scheduler = TaskScheduler::from_manifest(
            &manifest(TaskRateLimits {
                max_concurrent_dispatches: 2,
                max_dispatches_per_second: 4096.0,
            }),
            start,
        );
        scheduler
            .enqueue_at(
                "queue",
                task("same-a"),
                TaskRetryConfig::default(),
                1,
                start,
            )
            .unwrap();
        scheduler
            .enqueue_at(
                "queue",
                task("same-b"),
                TaskRetryConfig::default(),
                1,
                start,
            )
            .unwrap();
        scheduler
            .enqueue_at(
                "queue",
                task("later"),
                TaskRetryConfig::default(),
                1,
                start + Duration::from_secs(1),
            )
            .unwrap();
        let (dispatches, _) = scheduler.dispatch_ready(
            start + Duration::from_secs(1),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            2,
        );
        assert_eq!(dispatches.len(), 2);
        scheduler.finish_with_outcome_at(
            "queue",
            dispatches[0].id,
            dispatches[0].generation,
            false,
            start + Duration::from_secs(60),
        );
        scheduler.finish_with_outcome_at(
            "queue",
            dispatches[1].id,
            dispatches[1].generation,
            true,
            start + Duration::from_secs(60),
        );

        let completed_before_boundary = scheduler.statistics_at(
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            (start + Duration::from_secs(120))
                .checked_sub(Duration::from_nanos(1))
                .expect("the boundary is after the test start"),
        );
        assert_eq!(
            completed_before_boundary["queue:demo-app-us-central1-queue"]["tasksAdded"],
            0.6
        );
        assert_eq!(
            completed_before_boundary["queue:demo-app-us-central1-queue"]["completedLastMin"],
            2
        );
        assert_eq!(
            completed_before_boundary["queue:demo-app-us-central1-queue"]["failedTasks"],
            0.2
        );

        let completed_at_boundary = scheduler.statistics_at(
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            start + Duration::from_secs(120),
        );
        assert_eq!(
            completed_at_boundary["queue:demo-app-us-central1-queue"]["completedLastMin"],
            0
        );

        let before_added_boundary = scheduler.statistics_at(
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            (start + Duration::from_secs(5 * 60))
                .checked_sub(Duration::from_nanos(1))
                .expect("the boundary is after the test start"),
        );
        assert_eq!(
            before_added_boundary["queue:demo-app-us-central1-queue"]["tasksAdded"],
            0.6
        );
        assert_eq!(
            before_added_boundary["queue:demo-app-us-central1-queue"]["completedLastMin"],
            0
        );

        let at_added_boundary = scheduler.statistics_at(
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            start + Duration::from_secs(5 * 60),
        );
        assert_eq!(
            at_added_boundary["queue:demo-app-us-central1-queue"]["tasksAdded"],
            0.2
        );

        scheduler.reset(start + Duration::from_secs(6 * 60));
        let after_reset = scheduler.statistics_at(
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            start + Duration::from_secs(6 * 60),
        );
        assert_eq!(
            after_reset["queue:demo-app-us-central1-queue"]["tasksAdded"],
            0.0
        );
        assert_eq!(scheduler.statistics_retained_bytes(), 0);
    }

    #[test]
    fn reading_queue_statistics_does_not_change_dispatch_order_or_rate_refill() {
        let start = Instant::now();
        let limits = TaskRateLimits {
            max_concurrent_dispatches: 1,
            max_dispatches_per_second: 1.0,
        };
        let mut with_reads = TaskScheduler::from_manifest(&two_queue_manifest(limits), start);
        let mut without_reads = TaskScheduler::from_manifest(&two_queue_manifest(limits), start);
        for (queue, name) in [("a", "a1"), ("a", "a2"), ("b", "b1"), ("b", "b2")] {
            with_reads
                .enqueue_at(queue, task(name), TaskRetryConfig::default(), 1, start)
                .unwrap();
            without_reads
                .enqueue_at(queue, task(name), TaskRetryConfig::default(), 1, start)
                .unwrap();
        }

        let mut observed = Vec::new();
        let mut expected = Vec::new();
        for tick in 1..=4 {
            let now = start + Duration::from_secs(tick);
            let _ = with_reads.statistics_at("demo-app", |_| Some(DEFAULT_REGION.to_owned()), now);
            if tick % 2 == 0 {
                let _ =
                    with_reads.statistics_at("demo-app", |_| Some(DEFAULT_REGION.to_owned()), now);
            }
            let (actual, _) =
                with_reads.dispatch_ready(now, "demo-app", |_| Some(DEFAULT_REGION.to_owned()), 1);
            let (baseline, _) = without_reads.dispatch_ready(
                now,
                "demo-app",
                |_| Some(DEFAULT_REGION.to_owned()),
                1,
            );
            if let (Some(actual), Some(baseline)) = (actual.first(), baseline.first()) {
                observed.push((actual.queue.clone(), actual.task.name.clone()));
                expected.push((baseline.queue.clone(), baseline.task.name.clone()));
                assert!(with_reads.finish(&actual.queue, actual.id, actual.generation));
                assert!(without_reads.finish(&baseline.queue, baseline.id, baseline.generation));
            }
        }
        assert_eq!(observed, expected);
    }

    #[test]
    fn retained_byte_admission_is_atomic_and_does_not_burn_a_name() {
        let start = Instant::now();
        let mut scheduler =
            TaskScheduler::from_manifest(&manifest(TaskRateLimits::default()), start);
        scheduler
            .enqueue(
                "queue",
                task("fills-budget"),
                TaskRetryConfig::default(),
                MAX_RETAINED_TASK_BYTES,
            )
            .unwrap();
        assert_eq!(
            scheduler.enqueue("queue", task("retry-name"), TaskRetryConfig::default(), 1,),
            Err(AdmissionError::RuntimeFull)
        );
        assert_eq!(scheduler.outstanding(), 1);

        let (filler, _) = scheduler.dispatch_ready(
            start + Duration::from_secs(1),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            1,
        );
        assert!(scheduler.finish("queue", filler[0].id, filler[0].generation));
        scheduler
            .enqueue("queue", task("retry-name"), TaskRetryConfig::default(), 1)
            .unwrap();
        assert_eq!(scheduler.outstanding(), 1);
    }

    #[test]
    fn reset_makes_a_late_completion_a_noop_for_the_new_generation() {
        let start = Instant::now();
        let mut scheduler =
            TaskScheduler::from_manifest(&manifest(TaskRateLimits::default()), start);
        scheduler
            .enqueue("queue", task("same"), TaskRetryConfig::default(), 7)
            .unwrap();
        let (old, _) = scheduler.dispatch_ready(
            start + Duration::from_secs(1),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            1,
        );
        scheduler.reset(start + Duration::from_secs(1));
        scheduler
            .enqueue("queue", task("same"), TaskRetryConfig::default(), 11)
            .unwrap();
        let (new, _) = scheduler.dispatch_ready(
            start + Duration::from_secs(2),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            1,
        );

        assert!(!scheduler.finish("queue", old[0].id, old[0].generation));
        assert_eq!(scheduler.outstanding(), 1);
        assert!(scheduler.finish("queue", new[0].id, new[0].generation));
        assert_eq!(scheduler.outstanding(), 0);
    }

    #[test]
    fn round_robin_dispatch_prevents_a_busy_queue_from_starving_its_peer() {
        let start = Instant::now();
        let mut scheduler = TaskScheduler::from_manifest(
            &two_queue_manifest(TaskRateLimits {
                max_concurrent_dispatches: 1,
                max_dispatches_per_second: 500.0,
            }),
            start,
        );
        for (queue, name) in [("a", "a1"), ("a", "a2"), ("b", "b1")] {
            scheduler
                .enqueue(queue, task(name), TaskRetryConfig::default(), 1)
                .unwrap();
        }

        let ready = start + Duration::from_secs(1);
        let (first, _) =
            scheduler.dispatch_ready(ready, "demo-app", |_| Some(DEFAULT_REGION.to_owned()), 1);
        assert_eq!(first[0].queue, "a");
        assert!(scheduler.finish("a", first[0].id, first[0].generation));

        let (second, _) =
            scheduler.dispatch_ready(ready, "demo-app", |_| Some(DEFAULT_REGION.to_owned()), 1);
        assert_eq!(second[0].queue, "b");
    }

    #[test]
    fn completed_name_history_is_bounded_by_bytes_as_well_as_count() {
        let start = Instant::now();
        let mut scheduler =
            TaskScheduler::from_manifest(&manifest(TaskRateLimits::default()), start);
        let large_name = "n".repeat(MAX_COMPLETED_HISTORY_BYTES + 1);
        scheduler
            .enqueue(
                "queue",
                task(&large_name),
                TaskRetryConfig::default(),
                large_name.len() + "queue".len() + 1,
            )
            .unwrap();
        let (dispatch, _) = scheduler.dispatch_ready(
            start + Duration::from_secs(1),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            1,
        );
        assert!(scheduler.finish("queue", dispatch[0].id, dispatch[0].generation));
        assert_eq!(scheduler.completed_history_bytes, 0);
        assert_eq!(scheduler.retained_bytes, 0);
        assert!(scheduler.completed_names.is_empty());

        scheduler
            .enqueue(
                "queue",
                task(&large_name),
                TaskRetryConfig::default(),
                large_name.len() + "queue".len() + 1,
            )
            .unwrap();
    }

    #[test]
    fn completed_history_charges_each_retained_queue_identifier() {
        let start = Instant::now();
        let queue = "q".repeat(1024 * 1024);
        let mut configured = manifest(TaskRateLimits::default());
        queue.clone_into(&mut configured.functions[0].name);
        queue.clone_into(&mut configured.functions[0].entry_point);
        let mut scheduler = TaskScheduler::from_manifest(&configured, start);

        for sequence in 0..10 {
            let name = format!("task-{sequence}");
            scheduler
                .enqueue(
                    &queue,
                    task(&name),
                    TaskRetryConfig::default(),
                    queue.len() + name.len() + 1,
                )
                .unwrap();
            let (dispatch, _) = scheduler.dispatch_ready(
                start + Duration::from_secs(1),
                "demo-app",
                |_| Some(DEFAULT_REGION.to_owned()),
                1,
            );
            assert!(scheduler.finish(&queue, dispatch[0].id, dispatch[0].generation));
        }

        assert!(scheduler.completed_history_bytes <= MAX_COMPLETED_HISTORY_BYTES);
        assert!(scheduler.retained_bytes <= MAX_COMPLETED_HISTORY_BYTES);
        assert!(scheduler.completed_names.len() < 10);
    }

    #[test]
    fn fractional_dispatch_rate_accumulates_until_one_token_is_available() {
        let start = Instant::now();
        let mut scheduler = TaskScheduler::from_manifest(
            &manifest(TaskRateLimits {
                max_concurrent_dispatches: 1,
                max_dispatches_per_second: 0.5,
            }),
            start,
        );
        scheduler
            .enqueue("queue", task("slow"), TaskRetryConfig::default(), 4)
            .unwrap();

        let (too_early, _) = scheduler.dispatch_ready(
            start + Duration::from_secs(1),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            1,
        );
        assert!(too_early.is_empty());
        let (ready, _) = scheduler.dispatch_ready(
            start + Duration::from_secs(2),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            1,
        );
        assert_eq!(ready.len(), 1);
    }

    #[test]
    fn a_token_refill_is_applied_once_per_scheduler_tick() {
        let start = Instant::now();
        let mut scheduler = TaskScheduler::from_manifest(
            &manifest(TaskRateLimits {
                max_concurrent_dispatches: 3,
                max_dispatches_per_second: 1.0,
            }),
            start,
        );
        for name in ["first", "second", "third"] {
            scheduler
                .enqueue("queue", task(name), TaskRetryConfig::default(), 1)
                .unwrap();
        }

        let (dispatches, _) = scheduler.dispatch_ready(
            start + Duration::from_secs(1),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            10,
        );

        assert_eq!(dispatches.len(), 1);
    }

    #[test]
    fn a_retry_consumes_the_same_fractional_rate_bucket_as_initial_delivery() {
        let start = Instant::now();
        let mut scheduler = TaskScheduler::from_manifest(
            &manifest(TaskRateLimits {
                max_concurrent_dispatches: 1,
                max_dispatches_per_second: 0.5,
            }),
            start,
        );
        scheduler
            .enqueue("queue", task("retry"), TaskRetryConfig::default(), 16)
            .unwrap();
        let (initial, _) = scheduler.dispatch_ready(
            start + Duration::from_secs(2),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            1,
        );
        assert_eq!(initial.len(), 1);
        assert_eq!(
            scheduler.reserve_retry(
                "queue",
                initial[0].id,
                initial[0].generation,
                start + Duration::from_secs(3)
            ),
            super::RetryToken::WaitUntil((start + Duration::from_secs(4)).into())
        );
        assert_eq!(
            scheduler.reserve_retry(
                "queue",
                initial[0].id,
                initial[0].generation,
                start + Duration::from_secs(4)
            ),
            super::RetryToken::Ready
        );
    }

    #[test]
    fn a_locally_deferred_dispatch_refunds_its_rate_token() {
        let start = Instant::now();
        let mut scheduler = TaskScheduler::from_manifest(
            &manifest(TaskRateLimits {
                max_concurrent_dispatches: 1,
                max_dispatches_per_second: 0.5,
            }),
            start,
        );
        scheduler
            .enqueue("queue", task("deferred"), TaskRetryConfig::default(), 16)
            .unwrap();
        let (dispatch, _) = scheduler.dispatch_ready(
            start + Duration::from_secs(2),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            1,
        );
        scheduler.refund_token("queue", dispatch[0].id, dispatch[0].generation);
        assert_eq!(
            scheduler.reserve_retry(
                "queue",
                dispatch[0].id,
                dispatch[0].generation,
                start + Duration::from_secs(2)
            ),
            super::RetryToken::Ready
        );
    }

    #[test]
    fn queue_and_runtime_task_count_boundaries_have_distinct_precedence() {
        let start = Instant::now();
        let mut scheduler =
            TaskScheduler::from_manifest(&two_queue_manifest(TaskRateLimits::default()), start);
        for sequence in 0..MAX_PENDING_PER_QUEUE {
            scheduler
                .enqueue(
                    "a",
                    task(&format!("a-{sequence}")),
                    TaskRetryConfig::default(),
                    1,
                )
                .unwrap();
        }
        assert_eq!(
            scheduler.enqueue("a", task("queue-full"), TaskRetryConfig::default(), 1),
            Err(AdmissionError::QueueFull)
        );
        let (active, _) = scheduler.dispatch_ready(
            start + Duration::from_secs(1),
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            1,
        );
        assert_eq!(
            scheduler.enqueue("b", task("runtime-full"), TaskRetryConfig::default(), 1),
            Err(AdmissionError::RuntimeFull)
        );
        assert!(scheduler.finish("a", active[0].id, active[0].generation));
        scheduler
            .enqueue("b", task("runtime-full"), TaskRetryConfig::default(), 1)
            .expect("a count-refused task name remains reusable");
    }
}

#[cfg(test)]
mod virtual_time_properties {
    use super::TaskTime;
    use proptest::prelude::*;
    use std::time::Duration;
    proptest! {
        #[test]
        fn virtual_deadlines_and_elapsed_are_independent_of_host_instant_bounds(start: u128, nanos: u64) {
            let end = TaskTime::Virtual(start) + Duration::from_nanos(nanos);
            prop_assert_eq!(end, TaskTime::Virtual(start.saturating_add(u128::from(nanos))));
            prop_assert_eq!(end.saturating_duration_since(TaskTime::Virtual(start)).as_nanos(), start.saturating_add(u128::from(nanos))-start);
        }
    }
    #[test]
    fn huge_virtual_elapsed_refills_without_host_time_conversion() {
        let clock = TaskTime::Virtual(0) + Duration::MAX + Duration::MAX;
        assert_eq!(
            clock.saturating_duration_since(TaskTime::Virtual(0)),
            Duration::MAX
        );
    }
}
