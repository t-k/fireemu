//! Canonical finite `EventDelivery` traces shared by TLC conversion and Rust replay.

use std::collections::BTreeMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{
    execute_command, sha256_file, Execution, TemporaryDirectory, SCHEMA_VERSION,
    TLA2TOOLS_1_8_0_SHA256, UNIQUE_ID,
};

const EVENTDELIVERY_SCENARIOS: [&str; 4] =
    ["success", "retry-exhaustion", "stale-discard", "cancel"];

/// One deterministic `EventDelivery` scenario.
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

/// One action in a canonical `EventDelivery` trace.
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
    /// `Running` to `RetryWaiting` or `DeadLettered`.
    Fail,
    /// `RetryWaiting` to `Pending`.
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlcDump {
    counterexample: TlcCounterexample,
    vars: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlcCounterexample {
    #[serde(rename = "action")]
    _action: serde_json::Value,
    state: Vec<(u64, TlcEventState)>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TlcEventState {
    state: BTreeMap<String, EventLifecycle>,
    attempts: BTreeMap<String, u32>,
    event_epoch: BTreeMap<String, u64>,
    epoch: u64,
    previous_state: BTreeMap<String, EventLifecycle>,
    previous_attempts: BTreeMap<String, u32>,
    previous_event_epoch: BTreeMap<String, u64>,
    previous_epoch: u64,
    last_action: String,
    last_target: Vec<String>,
}

/// Converts TLC's `-dumpTrace json` output for a one-event `EventDelivery` model.
pub fn convert_eventdelivery_tlc_trace(
    json: &str,
    scenario: &str,
    max_attempts: u32,
) -> Result<EventTrace, String> {
    let dump: TlcDump = serde_json::from_str(json).map_err(|error| error.to_string())?;
    let required_vars = [
        "state",
        "attempts",
        "eventEpoch",
        "epoch",
        "lastAction",
        "lastTarget",
    ];
    if required_vars
        .iter()
        .any(|required| !dump.vars.iter().any(|name| name == required))
    {
        return Err("TLC trace is missing required EventDelivery variables".to_owned());
    }
    let states = dump.counterexample.state;
    let (_, first) = states
        .first()
        .ok_or_else(|| "TLC trace has no states".to_owned())?;
    if first.last_action != "Init" || !first.last_target.is_empty() {
        return Err("TLC EventDelivery trace must begin with Init".to_owned());
    }
    if first.epoch != 0
        || first
            .state
            .values()
            .any(|state| *state != EventLifecycle::Pending)
        || first.attempts.values().any(|attempts| *attempts != 0)
        || first.event_epoch.values().any(|epoch| *epoch != 0)
        || first.previous_state != first.state
        || first.previous_attempts != first.attempts
        || first.previous_event_epoch != first.event_epoch
        || first.previous_epoch != first.epoch
    {
        return Err("TLC EventDelivery Init state does not match the model".to_owned());
    }
    let event = single_event(first)?;
    let initial = projection(first, &event, max_attempts)?;
    let mut previous = initial.clone();
    let mut steps = Vec::with_capacity(states.len().saturating_sub(1));
    for (index, (_, state)) in states.iter().enumerate().skip(1) {
        let previous_state = &states[index - 1].1;
        if state.previous_state != previous_state.state
            || state.previous_attempts != previous_state.attempts
            || state.previous_event_epoch != previous_state.event_epoch
            || state.previous_epoch != previous_state.epoch
        {
            return Err(format!("TLC trace step {index} has inconsistent history"));
        }
        let operation = parse_operation(&state.last_action)?;
        let target = match operation {
            EventOperation::Reset if state.last_target.is_empty() => None,
            EventOperation::Reset => {
                return Err(format!("TLC trace step {index} Reset has a target"));
            }
            _ if state.last_target == [event.clone()] => Some(event.clone()),
            _ => return Err(format!("TLC trace step {index} has invalid target")),
        };
        let actual = projection(state, &event, max_attempts)?;
        let expected = apply_model_operation(&previous, operation)?;
        if actual != expected {
            return Err(format!(
                "TLC trace step {index} does not match operation {operation:?}: expected {expected:?}, found {actual:?}"
            ));
        }
        steps.push(EventTraceStep {
            operation,
            target,
            expected: actual.clone(),
        });
        previous = actual;
    }
    let trace = EventTrace {
        schema_version: SCHEMA_VERSION,
        scenario: scenario.to_owned(),
        initial,
        steps,
    };
    validate_trace(&trace)?;
    validate_scenario_goal(&trace)?;
    Ok(trace)
}

/// Runs TLC for each bounded `EventDelivery` scenario and writes canonical JSON traces.
pub fn generate_eventdelivery_traces(
    root: &Path,
    jar: &Path,
    java_bin: &Path,
    output_dir: &Path,
    timeout: Duration,
) -> Result<Vec<PathBuf>, String> {
    let root = fs::canonicalize(root)
        .map_err(|error| format!("cannot resolve {}: {error}", root.display()))?;
    let jar = fs::canonicalize(jar)
        .map_err(|error| format!("cannot resolve {}: {error}", jar.display()))?;
    let output_dir = if output_dir.is_absolute() {
        output_dir.to_path_buf()
    } else {
        root.join(output_dir)
    };
    let jar_digest =
        sha256_file(&jar).map_err(|error| format!("cannot hash {}: {error}", jar.display()))?;
    if jar_digest != TLA2TOOLS_1_8_0_SHA256 {
        return Err(format!(
            "TLA+ tools digest mismatch: expected {TLA2TOOLS_1_8_0_SHA256}, found {jar_digest}"
        ));
    }
    let module_source = root.join("verification/tla/EventDeliveryTrace.tla");
    let base_module_source = root.join("verification/tla/EventDelivery.tla");
    let base_config = root.join("verification/tla/EventDeliveryTrace.cfg");
    let config_text = fs::read_to_string(&base_config)
        .map_err(|error| format!("cannot read {}: {error}", base_config.display()))?;
    let anchor = "TraceScenario = \"success\"";
    if config_text.matches(anchor).count() != 1 {
        return Err(format!(
            "{} must contain exactly one {anchor:?}",
            base_config.display()
        ));
    }
    let workspace = TemporaryDirectory::new("eventdelivery-traces")?;
    let module = workspace.path.join("EventDeliveryTrace.tla");
    let base_module = workspace.path.join("EventDelivery.tla");
    fs::copy(&module_source, &module)
        .map_err(|error| format!("cannot copy {}: {error}", module_source.display()))?;
    fs::copy(&base_module_source, &base_module)
        .map_err(|error| format!("cannot copy {}: {error}", base_module_source.display()))?;
    let mut generated = Vec::new();
    for scenario in EVENTDELIVERY_SCENARIOS {
        let config = workspace.path.join(format!("{scenario}.cfg"));
        fs::write(
            &config,
            config_text.replace(anchor, &format!("TraceScenario = \"{scenario}\"")),
        )
        .map_err(|error| format!("cannot write {}: {error}", config.display()))?;
        let raw = workspace.path.join(format!("{scenario}-raw.json"));
        let mut command = Command::new(java_bin);
        command
            .current_dir(&workspace.path)
            .arg("-cp")
            .arg(&jar)
            .arg("tlc2.TLC")
            .arg("-workers")
            .arg("1")
            .arg("-deadlock")
            .arg("-config")
            .arg(&config)
            .arg("-dumpTrace")
            .arg("json")
            .arg(&raw)
            .arg(&module)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match execute_command(&mut command, timeout) {
            Execution::Completed { status, .. } => {
                classify_tlc_trace_exit(status.code(), scenario)?;
            }
            Execution::Timeout => return Err(format!("TLC timed out for {scenario}")),
            Execution::LaunchError(error) => {
                return Err(format!("cannot launch TLC for {scenario}: {error}"));
            }
        }
        let raw_json = fs::read_to_string(&raw)
            .map_err(|error| format!("TLC produced no JSON trace for {scenario}: {error}"))?;
        let trace = convert_eventdelivery_tlc_trace(&raw_json, scenario, 2)?;
        let canonical = workspace.path.join(format!("{scenario}.json"));
        let mut json = serde_json::to_vec_pretty(&trace).map_err(|error| error.to_string())?;
        json.push(b'\n');
        fs::write(&canonical, json)
            .map_err(|error| format!("cannot write {}: {error}", canonical.display()))?;
        generated.push((scenario, canonical));
    }
    fs::create_dir_all(&output_dir)
        .map_err(|error| format!("cannot create {}: {error}", output_dir.display()))?;
    let mut outputs = Vec::new();
    for (scenario, source) in generated {
        let destination = output_dir.join(format!("{scenario}.json"));
        let bytes = fs::read(&source)
            .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
        write_trace_atomic(&destination, &bytes)?;
        outputs.push(destination);
    }
    Ok(outputs)
}

fn classify_tlc_trace_exit(code: Option<i32>, scenario: &str) -> Result<(), String> {
    match code {
        // TLC's pinned safety-violation exit code. TraceGoalNotReached is an invariant.
        Some(12) => Ok(()),
        Some(0) => Err(format!(
            "TLC did not reach the {scenario} trace goal within the bounded model"
        )),
        Some(code) => Err(format!(
            "TLC failed for {scenario} with non-counterexample exit code {code}"
        )),
        None => Err(format!(
            "TLC for {scenario} ended without a usable exit code"
        )),
    }
}

fn write_trace_atomic(destination: &Path, bytes: &[u8]) -> Result<(), String> {
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            format!(
                "trace path {} has no UTF-8 file name",
                destination.display()
            )
        })?;
    let temporary = destination.with_file_name(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        UNIQUE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("cannot create {}: {error}", temporary.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("cannot sync {}: {error}", temporary.display()))?;
        fs::rename(&temporary, destination).map_err(|error| {
            format!(
                "cannot rename {} to {}: {error}",
                temporary.display(),
                destination.display()
            )
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn validate_scenario_goal(trace: &EventTrace) -> Result<(), String> {
    let final_projection = trace
        .steps
        .last()
        .map(|step| &step.expected)
        .ok_or_else(|| format!("event trace {} has no final projection", trace.scenario))?;
    let reached = match trace.scenario.as_str() {
        "success" => {
            final_projection.state == EventLifecycle::Succeeded
                && final_projection.current_epoch == 0
        }
        "retry-exhaustion" => {
            final_projection.state == EventLifecycle::DeadLettered
                && final_projection.current_epoch == 0
        }
        "stale-discard" => {
            final_projection.state == EventLifecycle::DiscardedStaleEpoch
                && final_projection.current_epoch == 1
        }
        "cancel" => {
            let previous = trace
                .steps
                .get(trace.steps.len().saturating_sub(2))
                .map_or(&trace.initial, |step| &step.expected);
            trace.steps.last().is_some_and(|step| {
                step.operation == EventOperation::Cancel
                    && previous.state == EventLifecycle::Leased
                    && final_projection.state == EventLifecycle::Cancelled
                    && final_projection.current_epoch == 0
            })
        }
        other => return Err(format!("unsupported EventDelivery scenario {other}")),
    };
    if reached {
        Ok(())
    } else {
        Err(format!(
            "TLC trace did not reach the declared {} scenario goal",
            trace.scenario
        ))
    }
}

fn validate_trace(trace: &EventTrace) -> Result<(), String> {
    let json = serde_json::to_string(trace).map_err(|error| error.to_string())?;
    parse_event_trace(&json).map(|_| ())
}

fn single_event(state: &TlcEventState) -> Result<String, String> {
    if state.state.len() != 1
        || state.attempts.len() != 1
        || state.event_epoch.len() != 1
        || state.previous_state.len() != 1
        || state.previous_attempts.len() != 1
        || state.previous_event_epoch.len() != 1
    {
        return Err("TLC EventDelivery conversion requires exactly one event".to_owned());
    }
    state
        .state
        .keys()
        .next()
        .cloned()
        .ok_or_else(|| "TLC EventDelivery state has no event".to_owned())
}

fn projection(
    state: &TlcEventState,
    event: &str,
    max_attempts: u32,
) -> Result<EventProjection, String> {
    let lifecycle = *state
        .state
        .get(event)
        .ok_or_else(|| format!("TLC state is missing event {event}"))?;
    let projection = EventProjection {
        state: lifecycle,
        attempts: *state
            .attempts
            .get(event)
            .ok_or_else(|| format!("TLC attempts are missing event {event}"))?,
        max_attempts,
        captured_epoch: *state
            .event_epoch
            .get(event)
            .ok_or_else(|| format!("TLC eventEpoch is missing event {event}"))?,
        current_epoch: state.epoch,
        terminal: lifecycle.is_terminal(),
        cancelled: lifecycle == EventLifecycle::Cancelled,
        stale: lifecycle == EventLifecycle::DiscardedStaleEpoch,
    };
    validate_projection(&projection)?;
    Ok(projection)
}

fn parse_operation(value: &str) -> Result<EventOperation, String> {
    match value {
        "Lease" => Ok(EventOperation::Lease),
        "Start" => Ok(EventOperation::Start),
        "Succeed" => Ok(EventOperation::Succeed),
        "Fail" => Ok(EventOperation::Fail),
        "RetryDue" => Ok(EventOperation::RetryDue),
        "Cancel" => Ok(EventOperation::Cancel),
        "Reset" => Ok(EventOperation::Reset),
        "DiscardStale" => Ok(EventOperation::DiscardStale),
        other => Err(format!("unsupported EventDelivery action {other}")),
    }
}

fn apply_model_operation(
    previous: &EventProjection,
    operation: EventOperation,
) -> Result<EventProjection, String> {
    let mut next = previous.clone();
    match operation {
        EventOperation::Lease if previous.state == EventLifecycle::Pending => {
            next.state = EventLifecycle::Leased;
        }
        EventOperation::Start
            if previous.state == EventLifecycle::Leased
                && previous.attempts < previous.max_attempts =>
        {
            next.state = EventLifecycle::Running;
            next.attempts += 1;
        }
        EventOperation::Succeed if previous.state == EventLifecycle::Running => {
            next.state = EventLifecycle::Succeeded;
        }
        EventOperation::Fail if previous.state == EventLifecycle::Running => {
            next.state = if previous.attempts < previous.max_attempts {
                EventLifecycle::RetryWaiting
            } else {
                EventLifecycle::DeadLettered
            };
        }
        EventOperation::RetryDue if previous.state == EventLifecycle::RetryWaiting => {
            next.state = EventLifecycle::Pending;
        }
        EventOperation::Cancel if !previous.state.is_terminal() => {
            next.state = EventLifecycle::Cancelled;
        }
        EventOperation::Reset => {
            next.current_epoch = previous
                .current_epoch
                .checked_add(1)
                .ok_or_else(|| "event trace epoch overflow".to_owned())?;
        }
        EventOperation::DiscardStale
            if !previous.state.is_terminal()
                && previous.captured_epoch < previous.current_epoch =>
        {
            next.state = EventLifecycle::DiscardedStaleEpoch;
        }
        _ => {
            return Err(format!(
                "operation {:?} is invalid from {:?}",
                operation, previous.state
            ));
        }
    }
    next.terminal = next.state.is_terminal();
    next.cancelled = next.state == EventLifecycle::Cancelled;
    next.stale = next.state == EventLifecycle::DiscardedStaleEpoch;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::classify_tlc_trace_exit;

    #[test]
    fn only_the_pinned_tlc_safety_counterexample_exit_is_accepted_for_generation() {
        assert!(classify_tlc_trace_exit(Some(12), "success").is_ok());
        for code in [Some(0), Some(1), Some(13), None] {
            assert!(classify_tlc_trace_exit(code, "success").is_err());
        }
    }
}
