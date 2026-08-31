//! Replay of canonical `EventDelivery` traces through the Rust event core.

use fireemu_core_events::event::{EventSource, EventType, LogicalEvent};
use fireemu_core_events::retry::RetryPolicy;
use fireemu_core_events::state::{EventRecord, EventState};
use fireemu_core_types::ids::{CorrelationId, Epoch, EventId, SessionId};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

use crate::event_trace::{EventLifecycle, EventOperation, EventProjection, EventTrace};

/// Successful comparison of one canonical trace with the Rust implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventReplayReport {
    /// Scenario that was replayed.
    pub scenario: String,
    /// Number of post-action projections compared.
    pub steps_checked: usize,
}

/// Replays every operation and compares the Rust projection after each action.
pub fn replay_event_trace(trace: &EventTrace) -> Result<EventReplayReport, String> {
    let policy = RetryPolicy::try_new(
        trace.initial.max_attempts,
        LogicalDuration::from_seconds(1),
        LogicalDuration::from_seconds(60),
    )
    .map_err(|error| error.to_string())?;
    let event = LogicalEvent {
        event_id: EventId::new(1),
        session_id: SessionId::new(1),
        epoch: Epoch::new(trace.initial.captured_epoch),
        source: EventSource::Manual,
        event_type: EventType::try_new("fireemu.formal.eventdelivery")
            .map_err(|error| error.to_string())?,
        subject: "formal/eventdelivery/e1".to_owned(),
        logical_time: LogicalInstant::UNIX_EPOCH,
        causation_id: None,
        correlation_id: CorrelationId::new(1),
        payload: Vec::new(),
    };
    let mut record = EventRecord::new(event);
    let mut current_epoch = Epoch::new(trace.initial.current_epoch);
    let mut retry_at = None;
    compare_projection(
        &format!("{} initial", trace.scenario),
        &trace.initial,
        &record,
        trace.initial.max_attempts,
        current_epoch,
    )?;

    let mut target = None;
    for (index, step) in trace.steps.iter().enumerate() {
        if let Some(step_target) = &step.target {
            match &target {
                Some(target) if target != step_target => {
                    return Err(replay_failure(
                        trace,
                        index,
                        &record,
                        current_epoch,
                        &format!("targets {step_target:?}, after earlier target {target:?}"),
                    ));
                }
                None => target = Some(step_target.clone()),
                _ => {}
            }
        }
        apply_operation(
            &mut record,
            step.operation,
            &policy,
            &mut current_epoch,
            &mut retry_at,
        )
        .map_err(|error| {
            replay_failure(
                trace,
                index,
                &record,
                current_epoch,
                &format!("transition failed: {error}"),
            )
        })?;
        compare_projection(
            &format!("{} step {index} {:?}", trace.scenario, step.operation),
            &step.expected,
            &record,
            trace.initial.max_attempts,
            current_epoch,
        )?;
    }

    Ok(EventReplayReport {
        scenario: trace.scenario.clone(),
        steps_checked: trace.steps.len(),
    })
}

fn apply_operation(
    record: &mut EventRecord,
    operation: EventOperation,
    policy: &RetryPolicy,
    current_epoch: &mut Epoch,
    retry_at: &mut Option<LogicalInstant>,
) -> Result<(), String> {
    match operation {
        EventOperation::Lease => record.lease().map_err(|error| error.to_string()),
        EventOperation::Start => record.start().map_err(|error| error.to_string()),
        EventOperation::Succeed => record.succeed().map_err(|error| error.to_string()),
        EventOperation::Fail => record
            .fail(policy, LogicalInstant::UNIX_EPOCH)
            .map(|outcome| {
                *retry_at = match outcome {
                    fireemu_core_events::state::FailureOutcome::RetryScheduled { retry_at } => {
                        Some(retry_at)
                    }
                    fireemu_core_events::state::FailureOutcome::DeadLettered => None,
                };
            })
            .map_err(|error| error.to_string()),
        EventOperation::RetryDue => record
            .retry_due(retry_at.ok_or_else(|| "has no scheduled retry".to_owned())?)
            .map_err(|error| error.to_string()),
        EventOperation::Cancel => record.cancel().map_err(|error| error.to_string()),
        EventOperation::Reset => {
            *current_epoch = current_epoch
                .next()
                .ok_or_else(|| "overflows the current epoch".to_owned())?;
            Ok(())
        }
        EventOperation::DiscardStale => record
            .discard_stale(*current_epoch)
            .map_err(|error| error.to_string()),
    }
}

fn replay_failure(
    trace: &EventTrace,
    index: usize,
    record: &EventRecord,
    current_epoch: Epoch,
    detail: &str,
) -> String {
    let step = &trace.steps[index];
    let actual = project(record, trace.initial.max_attempts, current_epoch);
    format!(
        "{} step {index} {:?} {detail}; expected {:?}, found {actual:?}",
        trace.scenario, step.operation, step.expected
    )
}

fn compare_projection(
    location: &str,
    expected: &EventProjection,
    record: &EventRecord,
    max_attempts: u32,
    current_epoch: Epoch,
) -> Result<(), String> {
    let actual = project(record, max_attempts, current_epoch);
    if &actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{location} projection mismatch: expected {expected:?}, found {actual:?}"
        ))
    }
}

fn project(record: &EventRecord, max_attempts: u32, current_epoch: Epoch) -> EventProjection {
    let state = match record.state() {
        EventState::Pending => EventLifecycle::Pending,
        EventState::Leased => EventLifecycle::Leased,
        EventState::Running => EventLifecycle::Running,
        EventState::Succeeded => EventLifecycle::Succeeded,
        EventState::RetryWaiting { .. } => EventLifecycle::RetryWaiting,
        EventState::DeadLettered { .. } => EventLifecycle::DeadLettered,
        EventState::Cancelled => EventLifecycle::Cancelled,
        EventState::DiscardedStaleEpoch => EventLifecycle::DiscardedStaleEpoch,
    };
    EventProjection {
        state,
        attempts: record.attempt(),
        max_attempts,
        captured_epoch: record.event().epoch.value(),
        current_epoch: current_epoch.value(),
        terminal: record.is_terminal(),
        cancelled: state == EventLifecycle::Cancelled,
        stale: state == EventLifecycle::DiscardedStaleEpoch,
    }
}
