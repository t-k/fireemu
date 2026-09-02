//! Quint Connect driver for bounded linear repeated alternatives.

use std::collections::BTreeSet;
use std::io;
use std::sync::{Arc, Mutex};

use fireemu_core_rules::regex::{Regex, RegexRuntimeError};
use quint_connect::{switch, Config, Driver, Result, State, Step};
use serde::Deserialize;

/// Actions exercised through the production regex matcher.
pub const MODELED_ACTIONS: [&str; 1] = ["Evaluate"];
/// Reproducible seeds used by generated conformance campaigns.
pub const GENERATED_TRACE_SEEDS: [&str; 4] = ["0x1", "0x2", "0x3", "0x4"];

/// Production-derived bounded regex observation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegexLinearRepeatState {
    /// Stable bounded scenario name.
    pub last_case: String,
    /// Match, rejection, or budget-exhaustion classification.
    pub outcome: String,
    /// Branch charging or fallback classification.
    pub work_class: String,
    /// Constant-depth or nested-fallback classification.
    pub depth_class: String,
    /// Whether every attempted deterministic alternative probe was step-charged.
    pub probe_accounting: String,
}

/// Test-only perturbation of one production projection field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionFault {
    /// Perturb the outcome.
    Outcome,
    /// Perturb the work classification.
    WorkClass,
    /// Perturb the depth classification.
    DepthClass,
    /// Perturb branch-probe accounting.
    ProbeAccounting,
}
impl ProjectionFault {
    /// Serialized field changed by this fault.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::Outcome => "outcome",
            Self::WorkClass => "workClass",
            Self::DepthClass => "depthClass",
            Self::ProbeAccounting => "probeAccounting",
        }
    }
}

/// Stateful adapter over one production regex evaluation.
pub struct RegexLinearRepeatDriver {
    state: RegexLinearRepeatState,
    projection_fault: Option<ProjectionFault>,
    action_recorder: Option<Arc<Mutex<BTreeSet<String>>>>,
}

impl Default for RegexLinearRepeatDriver {
    fn default() -> Self {
        Self::new()
    }
}
impl RegexLinearRepeatDriver {
    /// Builds an unevaluated regex driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: initial_state(),
            projection_fault: None,
            action_recorder: None,
        }
    }
    /// Applies one projection-only fault.
    #[must_use]
    pub fn with_projection_fault(mut self, fault: ProjectionFault) -> Self {
        self.projection_fault = Some(fault);
        self
    }
    /// Changes the projection-only fault.
    pub fn set_projection_fault(&mut self, fault: ProjectionFault) {
        self.projection_fault = Some(fault);
    }
    /// Records each successfully dispatched modeled action.
    #[must_use]
    pub fn with_action_recorder(mut self, recorder: Arc<Mutex<BTreeSet<String>>>) -> Self {
        self.action_recorder = Some(recorder);
        self
    }
    /// Resets the bounded scenario.
    pub fn init(&mut self) -> Result {
        self.state = initial_state();
        Ok(())
    }

    /// Executes one bounded scenario through the production matcher.
    pub fn evaluate(&mut self, case: &str) -> Result {
        if self.state.last_case != "none" {
            return Err(invalid_data("regex case already evaluated"));
        }
        let (pattern, subject) = match case {
            "atomicFirst" => ("(?:a|b|c)*", "aaa".to_owned()),
            "atomicThird" => ("(?:a|b|c)*", "ccc".to_owned()),
            "forbidden" => ("(?:a|b|c)*", "aad".to_owned()),
            "nonAtomic" => ("(?:ab|a)*", "abab".to_owned()),
            "exhausted" => ("(?:a|b|c)*", "c".repeat(40_000)),
            _ => return Err(invalid_data("unknown linear repeat case")),
        };
        let diagnostics = Regex::new(pattern)
            .map_err(|error| invalid_data(&format!("cannot compile regex case: {error}")))?
            .full_match_diagnostics(&subject);
        let outcome = match diagnostics.result {
            Ok(true) => "Matched",
            Ok(false) => "NotMatched",
            Err(
                RegexRuntimeError::StepBudgetExceeded { .. }
                | RegexRuntimeError::DepthBudgetExceeded { .. },
            ) => "Exhausted",
        };
        let work_class = if outcome == "Exhausted" {
            "Exhausted"
        } else if outcome == "NotMatched" {
            "Rejected"
        } else if diagnostics.maximum_depth > 5 {
            "Fallback"
        } else if diagnostics.charged_steps <= 26 {
            "FirstBranch"
        } else {
            "ThirdBranch"
        };
        let depth_class = if diagnostics.maximum_depth <= 5 {
            "Constant"
        } else {
            "Nested"
        };
        let probe_accounting =
            if diagnostics.attempted_branch_probes == diagnostics.charged_branch_probes {
                "Charged"
            } else {
                "Uncharged"
            };
        self.state = RegexLinearRepeatState {
            last_case: case.to_owned(),
            outcome: outcome.to_owned(),
            work_class: work_class.to_owned(),
            depth_class: depth_class.to_owned(),
            probe_accounting: probe_accounting.to_owned(),
        };
        if let Some(recorder) = &self.action_recorder {
            recorder
                .lock()
                .map_err(|_| invalid_data("action recorder lock poisoned"))?
                .insert("Evaluate".to_owned());
        }
        Ok(())
    }

    /// Projects production-derived regex state.
    pub fn project(&self) -> Result<RegexLinearRepeatState> {
        let mut state = self.state.clone();
        match self.projection_fault {
            None => {}
            Some(ProjectionFault::Outcome) => "NotMatched".clone_into(&mut state.outcome),
            Some(ProjectionFault::WorkClass) => {
                "Rejected".clone_into(&mut state.work_class);
            }
            Some(ProjectionFault::DepthClass) => {
                "Nested".clone_into(&mut state.depth_class);
            }
            Some(ProjectionFault::ProbeAccounting) => {
                "Uncharged".clone_into(&mut state.probe_accounting);
            }
        }
        Ok(state)
    }
}

impl State<RegexLinearRepeatDriver> for RegexLinearRepeatState {
    fn from_driver(driver: &RegexLinearRepeatDriver) -> Result<Self> {
        driver.project()
    }
}
impl Driver for RegexLinearRepeatDriver {
    type State = RegexLinearRepeatState;
    fn config() -> Config {
        Config {
            state: &["observable"],
            nondet: &["actionTaken"],
        }
    }
    fn step(&mut self, step: &Step) -> Result {
        switch!(step { init => self.init()?, Evaluate(case: String) => self.evaluate(&case)?, })
    }
}

fn initial_state() -> RegexLinearRepeatState {
    RegexLinearRepeatState {
        last_case: "none".to_owned(),
        outcome: "Running".to_owned(),
        work_class: "None".to_owned(),
        depth_class: "None".to_owned(),
        probe_accounting: "None".to_owned(),
    }
}
fn invalid_data(message: &str) -> anyhow::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned()).into()
}
