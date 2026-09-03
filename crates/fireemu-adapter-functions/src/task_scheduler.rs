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
struct QueueState {
    limits: TaskRateLimits,
    pending: VecDeque<QueuedTask>,
    active: BTreeMap<u64, ActiveTask>,
    names: BTreeSet<Arc<str>>,
    tokens: f64,
    last_refill: Instant,
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

    pub(crate) fn finish(&mut self, queue: &str, id: u64, generation: u64) -> bool {
        if generation != self.generation {
            return false;
        }
        let Some(state) = self.queues.get_mut(queue) else {
            return false;
        };
        let Some(active) = state.active.remove(&id) else {
            return false;
        };
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

    #[cfg(test)]
    pub(crate) fn retained_bytes(&self) -> usize {
        self.retained_bytes
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
