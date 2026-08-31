//! Canonical finite EventDelivery traces shared by TLC conversion and Rust replay.

use serde::{Deserialize, Serialize};

use crate::SCHEMA_VERSION;

/// One deterministic EventDelivery scenario.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventTrace {
    /// Persisted schema version.
    pub schema_version: u32,
    /// Stable scenario name.
    pub scenario: String,
    /// Projection before the first operation.
    pub initial: EventProjection,
    /// Ordered operations and their expected post-state projections.
    pub steps: Vec<EventTraceStep>,
}

/// One action in a canonical EventDelivery trace.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventTraceStep {
    /// Supported model operation.
    pub operation: EventOperation,
    /// Event identity for event-targeted actions; absent for Reset.
    pub target: Option<String>,
    /// Expected projection immediately after the operation.
    pub expected: EventProjection,
}

/// Operations represented by both the bounded model and the Rust event core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum EventOperation {
    /// Pending to Leased.
    Lease,
    /// Leased to Running.
    Start,
    /// Running to Succeeded.
    Succeed,
    /// Running to RetryWaiting or DeadLettered.
    Fail,
    /// RetryWaiting to Pending.
    RetryDue,
    /// Any non-terminal state to Cancelled.
    Cancel,
    /// Advance the current session epoch.
    Reset,
    /// Discard a non-terminal event captured in an older epoch.
    DiscardStale,
}

/// State visible in both TLA+ and Rust.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventProjection {
    /// Stable lifecycle state name.
    pub state: EventLifecycle,
    /// Attempts started so far.
    pub attempts: u32,
    /// Total allowed attempts.
    pub max_attempts: u32,
    /// Epoch captured by the event.
    pub captured_epoch: u64,
    /// Current session epoch used by reset/stale checks.
    pub current_epoch: u64,
    /// Whether the lifecycle state is terminal.
    pub terminal: bool,
    /// Whether cancellation produced the terminal state.
    pub cancelled: bool,
    /// Whether stale-epoch discard produced the terminal state.
    pub stale: bool,
}

/// Lifecycle names common to the model and Rust core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum EventLifecycle {
    /// Dispatchable.
    Pending,
    /// Worker lease held.
    Leased,
    /// Handler running.
    Running,
    /// Delivery succeeded.
    Succeeded,
    /// Waiting for retry time.
    RetryWaiting,
    /// Attempts exhausted.
    DeadLettered,
    /// Cancelled.
    Cancelled,
    /// Captured epoch is stale.
    DiscardedStaleEpoch,
}

impl EventLifecycle {
    /// Whether this lifecycle state is terminal.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::DeadLettered | Self::Cancelled | Self::DiscardedStaleEpoch
        )
    }
}

/// Parses and validates one strict canonical trace.
pub fn parse_event_trace(json: &str) -> Result<EventTrace, String> {
    let trace: EventTrace = serde_json::from_str(json).map_err(|error| error.to_string())?;
    if trace.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "unsupported schemaVersion {}; expected {SCHEMA_VERSION}",
            trace.schema_version
        ));
    }
    if trace.scenario.trim().is_empty() {
        return Err("event trace scenario must not be empty".to_owned());
    }
    if trace.steps.is_empty() {
        return Err(format!("event trace {} has no steps", trace.scenario));
    }
    validate_projection(&trace.initial)?;
    for (index, step) in trace.steps.iter().enumerate() {
        match step.operation {
            EventOperation::Reset if step.target.is_some() => {
                return Err(format!("step {index} Reset must not have target"));
            }
            EventOperation::Reset => {}
            _ if step
                .target
                .as_deref()
                .is_none_or(|target| target.trim().is_empty()) =>
            {
                return Err(format!("step {index} {:?} requires target", step.operation));
            }
            _ => {}
        }
        validate_projection(&step.expected)?;
    }
    Ok(trace)
}

fn validate_projection(projection: &EventProjection) -> Result<(), String> {
    if projection.max_attempts == 0 || projection.attempts > projection.max_attempts {
        return Err("event projection has invalid attempt bounds".to_owned());
    }
    if projection.terminal != projection.state.is_terminal()
        || projection.cancelled != (projection.state == EventLifecycle::Cancelled)
        || projection.stale != (projection.state == EventLifecycle::DiscardedStaleEpoch)
    {
        return Err("event projection flags do not match lifecycle state".to_owned());
    }
    Ok(())
}
