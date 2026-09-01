//! Quint Connect driver for the production event-delivery state machine.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{Arc, Mutex};

use fireemu_core_events::event::{EventSource, EventType, LogicalEvent};
use fireemu_core_events::retry::RetryPolicy;
use fireemu_core_events::state::{EventRecord, EventState};
use fireemu_core_types::ids::{CorrelationId, Epoch, EventId, SessionId};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use quint_connect::{switch, Config, Driver, Result, State, Step};
use serde::Deserialize;

/// Actions covered by the Quint model and exercised through production APIs.
pub const MODELED_ACTIONS: [&str; 10] = [
    "Lease",
    "Start",
    "Succeed",
    "Fail",
    "RetryDue",
    "Interrupt",
    "Cancel",
    "Tick",
    "Reset",
    "DiscardStale",
];

/// Reproducible seeds used by the bounded generated-trace campaigns.
pub const GENERATED_TRACE_SEEDS: [&str; 4] = ["0x1", "0x2", "0x3", "0x4"];

/// Lifecycle representation used at the Quint/Rust comparison boundary.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "tag", deny_unknown_fields)]
pub enum EventLifecycle {
    /// Dispatchable event.
    Pending,
    /// Event claimed by a worker.
    Leased,
    /// Event handler is running.
    Running,
    /// Successfully delivered terminal event.
    Succeeded,
    /// Failed event waiting for its retry deadline.
    RetryWaiting,
    /// Retry-exhausted terminal event.
    DeadLettered,
    /// Policy-cancelled terminal event.
    Cancelled,
    /// Old-epoch terminal event.
    DiscardedStaleEpoch,
}

impl From<&EventState> for EventLifecycle {
    fn from(state: &EventState) -> Self {
        match state {
            EventState::Pending => Self::Pending,
            EventState::Leased => Self::Leased,
            EventState::Running => Self::Running,
            EventState::Succeeded => Self::Succeeded,
            EventState::RetryWaiting { .. } => Self::RetryWaiting,
            EventState::DeadLettered { .. } => Self::DeadLettered,
            EventState::Cancelled => Self::Cancelled,
            EventState::DiscardedStaleEpoch => Self::DiscardedStaleEpoch,
        }
    }
}

/// Complete domain-observable state compared after every Quint Connect action.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventDeliveryState {
    /// Lifecycle by model event name.
    pub state: BTreeMap<String, EventLifecycle>,
    /// Started attempt count by model event name.
    pub attempts: BTreeMap<String, u32>,
    /// Configured maximum attempt count.
    pub max_attempts: u32,
    /// Epoch captured by each event.
    pub captured_epoch: BTreeMap<String, u64>,
    /// Driver's active session epoch.
    pub current_epoch: u64,
    /// Terminal-state flag by model event name.
    pub terminal: BTreeMap<String, bool>,
    /// Cancellation flag by model event name.
    pub cancelled: BTreeMap<String, bool>,
    /// Stale-discard flag by model event name.
    pub stale: BTreeMap<String, bool>,
    /// Current logical time in whole seconds since the Unix epoch.
    pub now: i64,
    /// Retry deadline by event, or `-1` when no retry is scheduled.
    pub retry_at: BTreeMap<String, i64>,
    /// Production retry policy's base backoff in whole seconds.
    pub base_backoff: i64,
    /// Production retry policy's maximum backoff in whole seconds.
    pub max_backoff: i64,
}

/// Test-only perturbation applied after extracting normal production state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProjectionFault {
    /// No perturbation.
    #[default]
    None,
    /// Change only the lifecycle map.
    State,
    /// Change only the attempt map.
    Attempts,
    /// Change only the maximum attempt count.
    MaxAttempts,
    /// Change only the captured-epoch map.
    CapturedEpoch,
    /// Change only the current epoch.
    CurrentEpoch,
    /// Change only the terminal map.
    Terminal,
    /// Change only the cancellation map.
    Cancelled,
    /// Change only the stale-discard map.
    Stale,
    /// Change only the logical clock.
    Now,
    /// Change only the retry-deadline map.
    RetryAt,
    /// Change only the base backoff.
    BaseBackoff,
    /// Change only the maximum backoff.
    MaxBackoff,
}

impl ProjectionFault {
    /// JSON field changed by this fault.
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::State => "state",
            Self::Attempts => "attempts",
            Self::MaxAttempts => "maxAttempts",
            Self::CapturedEpoch => "capturedEpoch",
            Self::CurrentEpoch => "currentEpoch",
            Self::Terminal => "terminal",
            Self::Cancelled => "cancelled",
            Self::Stale => "stale",
            Self::Now => "now",
            Self::RetryAt => "retryAt",
            Self::BaseBackoff => "baseBackoff",
            Self::MaxBackoff => "maxBackoff",
        }
    }
}

/// Thin driver that dispatches Quint actions to real `EventRecord` operations.
pub struct EventDeliveryDriver {
    records: BTreeMap<String, EventRecord>,
    retry_policy: RetryPolicy,
    current_epoch: Epoch,
    initial_now: LogicalInstant,
    now: LogicalInstant,
    event_names: Vec<String>,
    max_attempts: u32,
    action_recorder: Option<Arc<Mutex<BTreeSet<String>>>>,
    projection_fault: ProjectionFault,
}

impl EventDeliveryDriver {
    /// Builds an uninitialized driver for the named model events.
    pub fn try_new(event_names: Vec<String>, max_attempts: u32) -> Result<Self> {
        let retry_policy = RetryPolicy::try_new(
            max_attempts,
            LogicalDuration::from_seconds(1),
            LogicalDuration::from_seconds(4),
        )?;
        Self::try_with_policy(
            event_names,
            retry_policy,
            LogicalInstant::from_unix_seconds(100),
        )
    }

    /// Builds a driver with an explicit production retry policy and initial logical time.
    pub fn try_with_policy(
        event_names: Vec<String>,
        retry_policy: RetryPolicy,
        initial_now: LogicalInstant,
    ) -> Result<Self> {
        let unique_names = event_names.iter().collect::<BTreeSet<_>>();
        if unique_names.len() != event_names.len() || event_names.is_empty() {
            return Err(invalid_data("event names must be non-empty and unique"));
        }
        if event_names
            .iter()
            .any(|name| !matches!(name.as_str(), "e1" | "e2"))
        {
            return Err(invalid_data("the pilot supports only e1 and e2"));
        }
        Ok(Self {
            records: BTreeMap::new(),
            retry_policy,
            current_epoch: Epoch::initial(),
            initial_now,
            now: initial_now,
            event_names,
            max_attempts: retry_policy.max_attempts(),
            action_recorder: None,
            projection_fault: ProjectionFault::None,
        })
    }

    /// Shares successful modeled action names with conformance tests.
    #[must_use]
    pub fn with_action_recorder(mut self, recorder: Arc<Mutex<BTreeSet<String>>>) -> Self {
        self.action_recorder = Some(recorder);
        self
    }

    /// Applies a projection-only fault for a negative conformance test.
    #[must_use]
    pub fn with_projection_fault(mut self, fault: ProjectionFault) -> Self {
        self.projection_fault = fault;
        self
    }

    /// Replaces the projection-only fault without changing domain state.
    pub fn set_projection_fault(&mut self, fault: ProjectionFault) {
        self.projection_fault = fault;
    }

    /// Recreates all event records in the model's initial state.
    pub fn init(&mut self) -> Result {
        self.current_epoch = Epoch::initial();
        self.now = self.initial_now;
        self.records.clear();

        for name in &self.event_names {
            let event_id = match name.as_str() {
                "e1" => EventId::new(1),
                "e2" => EventId::new(2),
                _ => return Err(invalid_data("unsupported event name")),
            };
            let record = EventRecord::new(LogicalEvent {
                event_id,
                session_id: SessionId::new(1),
                epoch: self.current_epoch,
                source: EventSource::Manual,
                event_type: EventType::try_new("fireemu.verification.event")?,
                subject: format!("verification/{name}"),
                logical_time: self.initial_now,
                causation_id: None,
                correlation_id: CorrelationId::new(1),
                payload: Vec::new(),
            });
            self.records.insert(name.clone(), record);
        }
        Ok(())
    }

    /// Applies the modeled lease action.
    pub fn lease(&mut self, event: &str) -> Result {
        self.record_mut(event)?.lease()?;
        self.record_action("Lease")
    }

    /// Applies the modeled start action.
    pub fn start(&mut self, event: &str) -> Result {
        self.record_mut(event)?.start()?;
        self.record_action("Start")
    }

    /// Applies the modeled success action.
    pub fn succeed(&mut self, event: &str) -> Result {
        self.record_mut(event)?.succeed()?;
        self.record_action("Succeed")
    }

    /// Applies the modeled failure action using the real retry policy.
    pub fn fail(&mut self, event: &str) -> Result {
        let retry_policy = self.retry_policy;
        let now = self.now;
        self.record_mut(event)?.fail(&retry_policy, now)?;
        self.record_action("Fail")
    }

    /// Applies the modeled retry-due action at the current logical time.
    pub fn retry_due(&mut self, event: &str) -> Result {
        let now = self.now;
        self.record_mut(event)?.retry_due(now)?;
        self.record_action("RetryDue")
    }

    /// Applies the real runner-interruption transition.
    pub fn interrupt(&mut self, event: &str) -> Result {
        self.record_mut(event)?.interrupt()?;
        self.record_action("Interrupt")
    }

    /// Applies the modeled cancellation action.
    pub fn cancel(&mut self, event: &str) -> Result {
        self.record_mut(event)?.cancel()?;
        self.record_action("Cancel")
    }

    /// Advances the environmental logical clock by one second.
    pub fn tick(&mut self) -> Result {
        self.now = self
            .now
            .checked_add(LogicalDuration::from_seconds(1))
            .ok_or_else(|| invalid_data("logical clock overflowed"))?;
        self.record_action("Tick")
    }

    /// Applies the modeled reset action by advancing the current epoch.
    pub fn reset(&mut self) -> Result {
        self.current_epoch = self
            .current_epoch
            .next()
            .ok_or_else(|| invalid_data("current epoch overflowed"))?;
        self.record_action("Reset")
    }

    /// Applies the modeled stale-discard action with the active epoch.
    pub fn discard_stale(&mut self, event: &str) -> Result {
        let current_epoch = self.current_epoch;
        self.record_mut(event)?.discard_stale(current_epoch)?;
        self.record_action("DiscardStale")
    }

    /// Extracts the same state used by Quint Connect's after-action comparison.
    pub fn project(&self) -> Result<EventDeliveryState> {
        EventDeliveryState::from_driver(self)
    }

    fn record_mut(&mut self, event: &str) -> Result<&mut EventRecord> {
        self.records
            .get_mut(event)
            .ok_or_else(|| invalid_data(&format!("unknown or uninitialized event {event}")))
    }

    fn record_action(&self, action: &str) -> Result {
        if let Some(recorder) = &self.action_recorder {
            recorder
                .lock()
                .map_err(|_| invalid_data("action recorder lock is poisoned"))?
                .insert(action.to_owned());
        }
        Ok(())
    }
}

impl State<EventDeliveryDriver> for EventDeliveryState {
    fn from_driver(driver: &EventDeliveryDriver) -> Result<Self> {
        let mut lifecycle_by_event = BTreeMap::new();
        let mut attempts = BTreeMap::new();
        let mut captured_epoch = BTreeMap::new();
        let mut terminal = BTreeMap::new();
        let mut cancelled = BTreeMap::new();
        let mut stale_by_event = BTreeMap::new();
        let mut retry_at = BTreeMap::new();

        for event in &driver.event_names {
            let record = driver
                .records
                .get(event)
                .ok_or_else(|| invalid_data(&format!("event {event} is not initialized")))?;
            let lifecycle = EventLifecycle::from(record.state());
            lifecycle_by_event.insert(event.clone(), lifecycle.clone());
            attempts.insert(event.clone(), record.attempt());
            captured_epoch.insert(event.clone(), record.event().epoch.value());
            terminal.insert(event.clone(), record.is_terminal());
            cancelled.insert(event.clone(), lifecycle == EventLifecycle::Cancelled);
            stale_by_event.insert(
                event.clone(),
                lifecycle == EventLifecycle::DiscardedStaleEpoch,
            );
            retry_at.insert(
                event.clone(),
                match record.state() {
                    EventState::RetryWaiting { retry_at } => seconds(*retry_at)?,
                    _ => -1,
                },
            );
        }

        let mut projected = Self {
            state: lifecycle_by_event,
            attempts,
            max_attempts: driver.max_attempts,
            captured_epoch,
            current_epoch: driver.current_epoch.value(),
            terminal,
            cancelled,
            stale: stale_by_event,
            now: seconds(driver.now)?,
            retry_at,
            base_backoff: duration_seconds(driver.retry_policy.base_backoff())?,
            max_backoff: duration_seconds(driver.retry_policy.max_backoff())?,
        };
        match driver.projection_fault {
            ProjectionFault::None => {}
            ProjectionFault::State => {
                *projected
                    .state
                    .values_mut()
                    .next()
                    .ok_or_else(|| invalid_data("state projection is empty"))? =
                    EventLifecycle::Cancelled;
            }
            ProjectionFault::Attempts => {
                increment_first_u32(&mut projected.attempts, "attempts")?;
            }
            ProjectionFault::MaxAttempts => {
                projected.max_attempts = projected.max_attempts.saturating_add(1);
            }
            ProjectionFault::CapturedEpoch => {
                increment_first_u64(&mut projected.captured_epoch, "capturedEpoch")?;
            }
            ProjectionFault::CurrentEpoch => {
                projected.current_epoch = projected.current_epoch.saturating_add(1);
            }
            ProjectionFault::Terminal => toggle_first(&mut projected.terminal, "terminal")?,
            ProjectionFault::Cancelled => toggle_first(&mut projected.cancelled, "cancelled")?,
            ProjectionFault::Stale => toggle_first(&mut projected.stale, "stale")?,
            ProjectionFault::Now => projected.now = projected.now.saturating_add(1),
            ProjectionFault::RetryAt => increment_first_i64(&mut projected.retry_at, "retryAt")?,
            ProjectionFault::BaseBackoff => {
                projected.base_backoff = projected.base_backoff.saturating_add(1);
            }
            ProjectionFault::MaxBackoff => {
                projected.max_backoff = projected.max_backoff.saturating_add(1);
            }
        }
        Ok(projected)
    }
}

impl Driver for EventDeliveryDriver {
    type State = EventDeliveryState;

    fn config() -> Config {
        Config {
            state: &["EventDeliveryScenarios::EventDelivery::observable"],
            nondet: &["EventDeliveryScenarios::EventDelivery::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        switch!(step {
            init => self.init()?,
            Lease(event: String) => self.lease(&event)?,
            Start(event: String) => self.start(&event)?,
            Succeed(event: String) => self.succeed(&event)?,
            Fail(event: String) => self.fail(&event)?,
            RetryDue(event: String) => self.retry_due(&event)?,
            Interrupt(event: String) => self.interrupt(&event)?,
            Cancel(event: String) => self.cancel(&event)?,
            Tick => self.tick()?,
            Reset => self.reset()?,
            DiscardStale(event: String) => self.discard_stale(&event)?,
        })
    }
}

/// Driver view configured for the two-event, three-attempt generated-trace instance.
pub struct EventDeliveryConnectDriver {
    inner: EventDeliveryDriver,
}

impl EventDeliveryConnectDriver {
    /// Builds a fresh driver matching the `EventDeliveryConnect` Quint instance.
    pub fn try_new() -> Result<Self> {
        Ok(Self {
            inner: EventDeliveryDriver::try_new(vec!["e1".to_owned(), "e2".to_owned()], 3)?,
        })
    }

    /// Applies a projection-only fault for a generated-trace regression.
    #[must_use]
    pub fn with_projection_fault(mut self, fault: ProjectionFault) -> Self {
        self.inner.set_projection_fault(fault);
        self
    }
}

impl State<EventDeliveryConnectDriver> for EventDeliveryState {
    fn from_driver(driver: &EventDeliveryConnectDriver) -> Result<Self> {
        driver.inner.project()
    }
}

impl Driver for EventDeliveryConnectDriver {
    type State = EventDeliveryState;

    fn config() -> Config {
        Config {
            state: &["EventDeliveryConnect::EventDelivery::observable"],
            nondet: &["EventDeliveryConnect::EventDelivery::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        self.inner.step(step)
    }
}

fn invalid_data(message: &str) -> anyhow::Error {
    anyhow::Error::new(io::Error::new(io::ErrorKind::InvalidData, message))
}

fn increment_first_u32(values: &mut BTreeMap<String, u32>, field: &str) -> Result {
    let value = values
        .values_mut()
        .next()
        .ok_or_else(|| invalid_data(&format!("{field} projection is empty")))?;
    *value = value.saturating_add(1);
    Ok(())
}

fn increment_first_u64(values: &mut BTreeMap<String, u64>, field: &str) -> Result {
    let value = values
        .values_mut()
        .next()
        .ok_or_else(|| invalid_data(&format!("{field} projection is empty")))?;
    *value = value.saturating_add(1);
    Ok(())
}

fn increment_first_i64(values: &mut BTreeMap<String, i64>, field: &str) -> Result {
    let value = values
        .values_mut()
        .next()
        .ok_or_else(|| invalid_data(&format!("{field} projection is empty")))?;
    *value = value.saturating_add(1);
    Ok(())
}

fn seconds(instant: LogicalInstant) -> Result<i64> {
    i64::try_from(instant.as_nanos() / 1_000_000_000)
        .map_err(|_| invalid_data("logical instant does not fit whole seconds"))
}

fn duration_seconds(duration: LogicalDuration) -> Result<i64> {
    i64::try_from(duration.as_seconds())
        .map_err(|_| invalid_data("logical duration does not fit whole seconds"))
}

fn toggle_first(values: &mut BTreeMap<String, bool>, field: &str) -> Result {
    let value = values
        .values_mut()
        .next()
        .ok_or_else(|| invalid_data(&format!("{field} projection is empty")))?;
    *value = !*value;
    Ok(())
}
