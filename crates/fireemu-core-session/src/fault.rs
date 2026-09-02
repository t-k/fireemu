//! Fault injection plans (spec 18): reproducible, rule-driven faults instead of random
//! instability. A plan lists rules; each rule names an operation (`firestore.commit`,
//! `firestore.read`, `storage.upload`, `functions.invoke`, `functions.deliver`, ...),
//! optionally the nth occurrence and a function / event type, and the action to take. The
//! adapters ask [`FaultState::decide`] at their enforcement points and apply the actions.

use std::collections::BTreeMap;
use std::fmt;

/// What a matched rule does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultAction {
    /// Fail the operation with a status code (gRPC name or HTTP number).
    ReturnError {
        /// `ABORTED`, `UNAVAILABLE`, `503`, ...
        code: String,
    },
    /// Move the virtual clock (or hold an event) by a logical duration.
    Delay {
        /// Seconds.
        seconds: i64,
    },
    /// Deliver an event `count` extra times.
    Duplicate {
        /// Extra deliveries.
        count: u32,
    },
    /// Kill the functions runner process (it is restarted; the event is redelivered).
    CrashRunner,
    /// The operation times out.
    Timeout,
    /// The event goes straight to the dead letters.
    DeadLetter,
    /// The commit aborts as a transaction conflict.
    TransactionConflict,
    /// The connection drops before a response.
    DropConnection,
}

impl fmt::Display for FaultAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReturnError { code } => write!(f, "returnError {code}"),
            Self::Delay { seconds } => write!(f, "delay {seconds}s"),
            Self::Duplicate { count } => write!(f, "duplicate x{count}"),
            Self::CrashRunner => f.write_str("crashRunner"),
            Self::Timeout => f.write_str("timeout"),
            Self::DeadLetter => f.write_str("deadLetter"),
            Self::TransactionConflict => f.write_str("transactionConflict"),
            Self::DropConnection => f.write_str("dropConnection"),
        }
    }
}

/// What a rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultMatch {
    /// Operation name.
    pub operation: String,
    /// Only the nth occurrence (1-based); every occurrence when `None`. Counted per
    /// operation, or per operation and function when `function` is set.
    pub nth: Option<u64>,
    /// Only this function (functions operations).
    pub function: Option<String>,
    /// Only this event type (functions operations).
    pub event_type: Option<String>,
}

/// One rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultRule {
    /// Match.
    pub matches: FaultMatch,
    /// Action.
    pub action: FaultAction,
}

/// A plan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FaultPlan {
    /// Seed (echoed; the rules themselves are deterministic).
    pub seed: u64,
    /// Rules, applied in order.
    pub rules: Vec<FaultRule>,
}

/// A fault that fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultRecord {
    /// Operation.
    pub operation: String,
    /// Occurrence number of the operation.
    pub occurrence: u64,
    /// Occurrence number of the operation for the function (when a function was named).
    pub function_occurrence: Option<u64>,
    /// Function, if any.
    pub function: Option<String>,
    /// Action taken.
    pub action: FaultAction,
}

/// The installed plan plus its occurrence counters and history.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FaultState {
    plan: Option<FaultPlan>,
    counters: BTreeMap<String, u64>,
    fired: Vec<FaultRecord>,
}

impl FaultState {
    /// A cheap, saturating estimate of heap bytes retained by a session snapshot.
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        const BTREE_ENTRY_OVERHEAD: u64 = 128;

        fn bytes(value: usize) -> u64 {
            u64::try_from(value).unwrap_or(u64::MAX)
        }

        fn action_bytes(action: &FaultAction) -> u64 {
            match action {
                FaultAction::ReturnError { code } => bytes(code.capacity()),
                FaultAction::Delay { .. }
                | FaultAction::Duplicate { .. }
                | FaultAction::CrashRunner
                | FaultAction::Timeout
                | FaultAction::DeadLetter
                | FaultAction::TransactionConflict
                | FaultAction::DropConnection => 0,
            }
        }

        let mut total = 0u64;
        if let Some(plan) = &self.plan {
            total = total.saturating_add(
                bytes(plan.rules.capacity())
                    .saturating_mul(bytes(core::mem::size_of::<FaultRule>())),
            );
            for rule in &plan.rules {
                total = total
                    .saturating_add(bytes(rule.matches.operation.capacity()))
                    .saturating_add(
                        rule.matches
                            .function
                            .as_ref()
                            .map_or(0, |value| bytes(value.capacity())),
                    )
                    .saturating_add(
                        rule.matches
                            .event_type
                            .as_ref()
                            .map_or(0, |value| bytes(value.capacity())),
                    )
                    .saturating_add(action_bytes(&rule.action));
            }
        }
        for key in self.counters.keys() {
            total = total
                .saturating_add(BTREE_ENTRY_OVERHEAD)
                .saturating_add(bytes(core::mem::size_of::<(String, u64)>()))
                .saturating_add(bytes(key.capacity()));
        }
        total = total.saturating_add(
            bytes(self.fired.capacity()).saturating_mul(bytes(core::mem::size_of::<FaultRecord>())),
        );
        for record in &self.fired {
            total = total
                .saturating_add(bytes(record.operation.capacity()))
                .saturating_add(
                    record
                        .function
                        .as_ref()
                        .map_or(0, |value| bytes(value.capacity())),
                )
                .saturating_add(action_bytes(&record.action));
        }
        total
    }

    /// Installs a plan; counters and history start over.
    pub fn install(&mut self, plan: FaultPlan) {
        self.plan = Some(plan);
        self.counters.clear();
        self.fired.clear();
    }

    /// Removes the plan.
    pub fn clear(&mut self) {
        self.plan = None;
        self.counters.clear();
        self.fired.clear();
    }

    /// The installed plan.
    #[must_use]
    pub fn plan(&self) -> Option<&FaultPlan> {
        self.plan.as_ref()
    }

    /// Faults that fired so far.
    #[must_use]
    pub fn fired(&self) -> &[FaultRecord] {
        &self.fired
    }

    /// Occurrences counted per operation.
    #[must_use]
    pub fn counters(&self) -> &BTreeMap<String, u64> {
        &self.counters
    }

    /// Counts one occurrence of `operation` (and of `operation` for `function`) and
    /// returns the actions of every rule that matches it (in rule order). Without a plan
    /// nothing is counted.
    pub fn decide(
        &mut self,
        operation: &str,
        function: Option<&str>,
        event_type: Option<&str>,
    ) -> Vec<FaultAction> {
        let Some(plan) = &self.plan else {
            return Vec::new();
        };
        let count = self.counters.entry(operation.to_owned()).or_insert(0);
        *count += 1;
        let occurrence = *count;
        let per_function = function.map(|f| {
            let count = self.counters.entry(format!("{operation}|{f}")).or_insert(0);
            *count += 1;
            *count
        });
        let mut actions = Vec::new();
        for rule in &plan.rules {
            let m = &rule.matches;
            if m.operation != operation
                || m.function.as_deref().is_some_and(|f| Some(f) != function)
                || m.event_type
                    .as_deref()
                    .is_some_and(|t| Some(t) != event_type)
            {
                continue;
            }
            let counted = if m.function.is_some() {
                per_function.unwrap_or(occurrence)
            } else {
                occurrence
            };
            if m.nth.is_some_and(|n| n != counted) {
                continue;
            }
            actions.push(rule.action.clone());
            self.fired.push(FaultRecord {
                operation: operation.to_owned(),
                occurrence,
                function_occurrence: per_function,
                function: function.map(str::to_owned),
                action: rule.action.clone(),
            });
        }
        actions
    }
}

#[cfg(test)]
mod retained_bytes_tests {
    use super::{FaultAction, FaultMatch, FaultPlan, FaultRule, FaultState};

    #[test]
    fn fired_records_increase_the_snapshot_estimate() {
        let mut state = FaultState::default();
        state.install(FaultPlan {
            seed: 1,
            rules: vec![FaultRule {
                matches: FaultMatch {
                    operation: "firestore.commit".repeat(32),
                    nth: None,
                    function: Some("function-name".repeat(32)),
                    event_type: Some("event-type".repeat(32)),
                },
                action: FaultAction::ReturnError {
                    code: "UNAVAILABLE".repeat(32),
                },
            }],
        });
        let before = state.retained_bytes();
        let operation = "firestore.commit".repeat(32);
        let function = "function-name".repeat(32);
        let event_type = "event-type".repeat(32);
        assert_eq!(
            state.decide(&operation, Some(&function), Some(&event_type)),
            vec![FaultAction::ReturnError {
                code: "UNAVAILABLE".repeat(32),
            }]
        );

        assert!(state.retained_bytes() > before);
    }
}

/// The fault state shared by every adapter of a session.
pub type SharedFaults = std::sync::Arc<std::sync::Mutex<FaultState>>;

/// One fault state per session, looked up by project: a registered session project has
/// its own plan and counters; every other project shares the default session's.
#[derive(Debug, Default)]
pub struct FaultRegistry {
    default: SharedFaults,
    others: std::sync::Mutex<BTreeMap<String, SharedFaults>>,
}

impl FaultRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The default session's state.
    #[must_use]
    pub fn default_state(&self) -> SharedFaults {
        self.default.clone()
    }

    /// Gives `project` its own state (idempotent) and returns it.
    pub fn register(&self, project: &str) -> SharedFaults {
        match self.others.lock() {
            Ok(mut others) => others
                .entry(project.to_owned())
                .or_insert_with(SharedFaults::default)
                .clone(),
            Err(_) => self.default.clone(),
        }
    }

    /// Forgets `project`'s state (its faults fall back to the default session's).
    pub fn remove(&self, project: &str) {
        if let Ok(mut others) = self.others.lock() {
            others.remove(project);
        }
    }

    /// The state deciding for `project`.
    #[must_use]
    pub fn for_project(&self, project: &str) -> SharedFaults {
        self.others
            .lock()
            .ok()
            .and_then(|o| o.get(project).cloned())
            .unwrap_or_else(|| self.default.clone())
    }
}

/// The registry shared by every adapter.
pub type SharedFaultRegistry = std::sync::Arc<FaultRegistry>;

/// Decides for `operation` of `project` on a registry (an absent registry means no faults).
#[must_use]
pub fn decide_for(
    registry: Option<&SharedFaultRegistry>,
    project: &str,
    operation: &str,
    function: Option<&str>,
    event_type: Option<&str>,
) -> Vec<FaultAction> {
    let state = registry.map(|r| r.for_project(project));
    decide_shared(state.as_ref(), operation, function, event_type)
}

/// Decides for `operation` on a shared state (an absent or poisoned state means no faults).
#[must_use]
pub fn decide_shared(
    faults: Option<&SharedFaults>,
    operation: &str,
    function: Option<&str>,
    event_type: Option<&str>,
) -> Vec<FaultAction> {
    faults
        .and_then(|f| f.lock().ok())
        .map(|mut f| f.decide(operation, function, event_type))
        .unwrap_or_default()
}
