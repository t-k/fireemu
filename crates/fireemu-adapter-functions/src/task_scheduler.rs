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
const STATISTICS_BUCKET_WIDTH: Duration = Duration::from_secs(1);
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
    WaitUntil(Instant),
    Gone,
}

#[derive(Debug)]
struct QueuedTask {
    id: u64,
    task: Task,
    retry: TaskRetryConfig,
    retained_bytes: usize,
    name: Arc<str>,
}

#[derive(Debug)]
struct ActiveTask {
    retained_bytes: usize,
    name: Arc<str>,
}

#[derive(Debug)]
struct StatisticBucket {
    first: Instant,
    last: Instant,
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

    fn prune(&mut self, now: Instant) {
        while self
            .buckets
            .front()
            .is_some_and(|bucket| now.saturating_duration_since(bucket.last) > self.window)
        {
            self.buckets.pop_front();
        }
    }

    fn record(&mut self, now: Instant) {
        self.prune(now);
        if let Some(bucket) = self.buckets.back_mut() {
            if now.saturating_duration_since(bucket.first) < STATISTICS_BUCKET_WIDTH {
                bucket.last = now;
                bucket.count = bucket.count.saturating_add(1);
                return;
            }
        }
        self.buckets.push_back(StatisticBucket {
            first: now,
            last: now,
            count: 1,
        });
        while self.buckets.len() > MAX_STATISTICS_BUCKETS {
            self.buckets.pop_front();
        }
    }

    fn count(&mut self, now: Instant) -> u64 {
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
    last_refill: Instant,
    added_times: StatisticWindow,
    completed_times: StatisticWindow,
    failed_times: StatisticWindow,
}

impl QueueState {
    fn new(limits: TaskRateLimits, now: Instant) -> Self {
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

    fn refill(&mut self, now: Instant) {
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

    fn next_refill(&self) -> Option<Instant> {
        (self.limits.max_concurrent_dispatches > 0
            && self.limits.max_dispatches_per_second > 0.0
            && !self.pending.is_empty())
        .then_some(self.last_refill + TOKEN_REFRESH_INTERVAL)
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
    retained_bytes: usize,
    completed_names: VecDeque<(String, Arc<str>)>,
    completed_history_bytes: usize,
    next_queue: usize,
    closed: bool,
}

impl TaskScheduler {
    pub(crate) fn from_manifest(manifest: &FunctionManifest, now: Instant) -> Self {
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
            retained_bytes: 0,
            completed_names: VecDeque::new(),
            completed_history_bytes: 0,
            next_queue: 0,
            closed: false,
        }
    }

    pub(crate) fn enqueue(
        &mut self,
        queue: &str,
        task: Task,
        retry: TaskRetryConfig,
        retained_bytes: usize,
    ) -> Result<(), AdmissionError> {
        self.enqueue_at(queue, task, retry, retained_bytes, Instant::now())
    }

    fn enqueue_at(
        &mut self,
        queue: &str,
        task: Task,
        retry: TaskRetryConfig,
        retained_bytes: usize,
        now: Instant,
    ) -> Result<(), AdmissionError> {
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
        });
        state.added_times.record(now);
        self.outstanding = next_outstanding;
        self.retained_bytes = next_bytes;
        Ok(())
    }

    pub(crate) fn dispatch_ready(
        &mut self,
        now: Instant,
        project: &str,
        region_for: impl Fn(&str) -> Option<String>,
        maximum: usize,
    ) -> (Vec<Dispatch>, Option<Instant>) {
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
                let Some(queued) = queue.pending.pop_front() else {
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
        let next_wake = self
            .queues
            .values()
            .filter_map(QueueState::next_refill)
            .min();
        (dispatches, next_wake)
    }

    #[cfg(test)]
    pub(crate) fn finish(&mut self, queue: &str, id: u64, generation: u64) -> bool {
        self.finish_with_outcome(queue, id, generation, false)
    }

    pub(crate) fn finish_with_outcome(
        &mut self,
        queue: &str,
        id: u64,
        generation: u64,
        failed: bool,
    ) -> bool {
        self.finish_with_outcome_at(queue, id, generation, failed, Instant::now())
    }

    fn finish_with_outcome_at(
        &mut self,
        queue: &str,
        id: u64,
        generation: u64,
        failed: bool,
        now: Instant,
    ) -> bool {
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
        now: Instant,
    ) -> RetryToken {
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

    pub(crate) fn outstanding(&self) -> usize {
        self.outstanding
    }

    pub(crate) fn active(&self) -> usize {
        self.queues.values().map(|queue| queue.active.len()).sum()
    }

    pub(crate) fn statistics(
        &mut self,
        project: &str,
        region_for: impl Fn(&str) -> Option<String>,
    ) -> Value {
        self.statistics_at(project, region_for, Instant::now())
    }

    #[allow(clippy::cast_precision_loss)] // queueStats publishes the official floating-point rate shape
    fn statistics_at(
        &mut self,
        project: &str,
        region_for: impl Fn(&str) -> Option<String>,
        now: Instant,
    ) -> Value {
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

    pub(crate) fn reset(&mut self, now: Instant) {
        self.generation = self.generation.wrapping_add(1);
        self.outstanding = 0;
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

    pub(crate) fn close(&mut self, now: Instant) {
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
        assert!(scheduler.statistics_retained_bytes() <= 512 * 3 * 32);
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

        let completed_exact = scheduler.statistics_at(
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            start + Duration::from_secs(120),
        );
        assert_eq!(
            completed_exact["queue:demo-app-us-central1-queue"]["tasksAdded"],
            0.6
        );
        assert_eq!(
            completed_exact["queue:demo-app-us-central1-queue"]["completedLastMin"],
            2
        );
        assert_eq!(
            completed_exact["queue:demo-app-us-central1-queue"]["failedTasks"],
            0.2
        );

        let after_completed_window = scheduler.statistics_at(
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            start + Duration::from_secs(120) + Duration::from_nanos(1),
        );
        assert_eq!(
            after_completed_window["queue:demo-app-us-central1-queue"]["completedLastMin"],
            0
        );

        let exact = scheduler.statistics_at(
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            start + Duration::from_secs(5 * 60),
        );
        assert_eq!(exact["queue:demo-app-us-central1-queue"]["tasksAdded"], 0.6);
        assert_eq!(
            exact["queue:demo-app-us-central1-queue"]["completedLastMin"],
            0
        );

        let after_added_window = scheduler.statistics_at(
            "demo-app",
            |_| Some(DEFAULT_REGION.to_owned()),
            start + Duration::from_secs(5 * 60) + Duration::from_nanos(1),
        );
        assert_eq!(
            after_added_window["queue:demo-app-us-central1-queue"]["tasksAdded"],
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
            super::RetryToken::WaitUntil(start + Duration::from_secs(4))
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
