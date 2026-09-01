//! Quint Connect driver for regex authorization through the production rules evaluator.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{Arc, Mutex};

use fireemu_core_rules::eval::{
    evaluate_request, Decision, DenyReason, Method, RequestContext, RulesService,
};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::value::RulesValue;
use quint_connect::{switch, Config, Driver, Result, State, Step};
use serde::Deserialize;

/// Actions covered through the production rules evaluator.
pub const MODELED_ACTIONS: [&str; 1] = ["Evaluate"];

/// Reproducible seeds used by generated conformance campaigns.
pub const GENERATED_TRACE_SEEDS: [&str; 4] = ["0x1", "0x2", "0x3", "0x4"];

/// Complete state compared at the Quint Connect boundary.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegexAuthorizationState {
    /// Stable label for the selected evaluator case, or `none` before evaluation.
    pub last_case: String,
    /// Production authorization decision.
    pub decision: String,
    /// Stable production denial category.
    pub denial_class: String,
}

/// Test-only perturbation applied after extracting production results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionFault {
    /// Change only the authorization decision.
    Decision,
    /// Change only the denial category.
    DenialClass,
}

impl ProjectionFault {
    /// Returns the serialized production field affected by the fault.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::Decision => "decision",
            Self::DenialClass => "denialClass",
        }
    }
}

/// Stateful adapter that permits one production evaluation per generated trace.
pub struct RegexAuthorizationDriver {
    state: RegexAuthorizationState,
    projection_fault: Option<ProjectionFault>,
    action_recorder: Option<Arc<Mutex<BTreeSet<String>>>>,
}

impl Default for RegexAuthorizationDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl RegexAuthorizationDriver {
    /// Builds an uninitialized evaluator driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: unevaluated_state(),
            projection_fault: None,
            action_recorder: None,
        }
    }

    /// Records every successfully dispatched action.
    #[must_use]
    pub fn with_action_recorder(mut self, recorder: Arc<Mutex<BTreeSet<String>>>) -> Self {
        self.action_recorder = Some(recorder);
        self
    }

    /// Applies one projection-only fault.
    #[must_use]
    pub fn with_projection_fault(mut self, fault: ProjectionFault) -> Self {
        self.projection_fault = Some(fault);
        self
    }

    /// Changes the projection-only fault without mutating evaluator state.
    pub fn set_projection_fault(&mut self, fault: ProjectionFault) {
        self.projection_fault = Some(fault);
    }

    /// Resets the bounded trace to its unevaluated state.
    pub fn init(&mut self) -> Result {
        self.state = unevaluated_state();
        Ok(())
    }

    /// Parses a bounded real rules source and evaluates it through `evaluate_request`.
    pub fn evaluate(&mut self, case: &str) -> Result {
        if self.state.last_case != "none" {
            return Err(invalid_data(
                "evaluation is disabled after a result is recorded",
            ));
        }
        let fixture = fixture(case)?;
        let ruleset = parse_ruleset(fixture.rules)
            .map_err(|error| invalid_data(&format!("cannot parse {case} rules: {error}")))?;
        let mut request = request();
        if let Some(value) = fixture.resource_value {
            request.resource = Some(document(value));
        }
        let report = evaluate_request(&ruleset, &request);
        let (decision, denial_class) = match report.decision {
            Decision::Allow => ("Allow", "None"),
            Decision::Deny(DenyReason::BudgetExceeded { limit_id, .. }) => ("Deny", limit_id),
            Decision::Deny(_) => ("Deny", "RuleMismatch"),
        };
        self.state = RegexAuthorizationState {
            last_case: case.to_owned(),
            decision: decision.to_owned(),
            denial_class: denial_class.to_owned(),
        };
        self.record_action("Evaluate")
    }

    /// Projects the last real evaluator result plus its harness case label.
    pub fn project(&self) -> Result<RegexAuthorizationState> {
        let mut projected = self.state.clone();
        match self.projection_fault {
            None => {}
            Some(ProjectionFault::Decision) => {
                projected.decision = if projected.decision == "Allow" {
                    "Deny".to_owned()
                } else {
                    "Allow".to_owned()
                };
            }
            Some(ProjectionFault::DenialClass) => {
                projected.denial_class = if projected.denial_class == "RuleMismatch" {
                    "FIREEMU-REGEX-STEPS-PER-MATCH".to_owned()
                } else {
                    "RuleMismatch".to_owned()
                };
            }
        }
        Ok(projected)
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

impl State<RegexAuthorizationDriver> for RegexAuthorizationState {
    fn from_driver(driver: &RegexAuthorizationDriver) -> Result<Self> {
        driver.project()
    }
}

impl Driver for RegexAuthorizationDriver {
    type State = RegexAuthorizationState;

    fn config() -> Config {
        Config {
            state: &["observable"],
            nondet: &["actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        switch!(step {
            init => self.init()?,
            Evaluate(case: String) => self.evaluate(&case)?,
        })
    }
}

/// Driver configured for generated traces.
pub struct RegexAuthorizationConnectDriver {
    inner: RegexAuthorizationDriver,
}

impl Default for RegexAuthorizationConnectDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl RegexAuthorizationConnectDriver {
    /// Builds a fresh generated-trace driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RegexAuthorizationDriver::new(),
        }
    }

    /// Applies one projection-only fault.
    #[must_use]
    pub fn with_projection_fault(mut self, fault: ProjectionFault) -> Self {
        self.inner.set_projection_fault(fault);
        self
    }
}

impl State<RegexAuthorizationConnectDriver> for RegexAuthorizationState {
    fn from_driver(driver: &RegexAuthorizationConnectDriver) -> Result<Self> {
        driver.inner.project()
    }
}

impl Driver for RegexAuthorizationConnectDriver {
    type State = RegexAuthorizationState;

    fn config() -> Config {
        Config {
            state: &["observable"],
            nondet: &["actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        self.inner.step(step)
    }
}

struct Fixture {
    rules: &'static str,
    resource_value: Option<String>,
}

fn fixture(case: &str) -> Result<Fixture> {
    let fixture = match case {
        "matched" => Fixture {
            rules: SIMPLE_MATCH,
            resource_value: None,
        },
        "notMatched" => Fixture {
            rules: SIMPLE_NO_MATCH,
            resource_value: None,
        },
        "stepExhausted" => Fixture {
            rules: STEP_EXHAUSTED,
            resource_value: Some("a".repeat(210_000)),
        },
        "depthExhausted" => Fixture {
            rules: DEPTH_EXHAUSTED_WITH_NESTED_ALLOW,
            resource_value: Some("a".repeat(10_000)),
        },
        "parentNegated" => Fixture {
            rules: PARENT_NEGATED,
            resource_value: None,
        },
        "nestedNegated" => Fixture {
            rules: NESTED_NEGATED,
            resource_value: None,
        },
        _ => {
            return Err(invalid_data(&format!(
                "unknown regex authorization case {case}"
            )))
        }
    };
    Ok(fixture)
}

fn request() -> RequestContext {
    RequestContext {
        service: RulesService::Firestore,
        method: Method::Get,
        path: "/databases/(default)/documents/notes/n1".to_owned(),
        auth: None,
        resource: None,
        request_resource: None,
        time_unix_nanos: 0,
        abstract_path: false,
        request_query: None,
    }
}

fn document(value: String) -> RulesValue {
    RulesValue::Map(BTreeMap::from([(
        "data".to_owned(),
        RulesValue::Map(BTreeMap::from([(
            "value".to_owned(),
            RulesValue::String(value),
        )])),
    )]))
}

fn unevaluated_state() -> RegexAuthorizationState {
    RegexAuthorizationState {
        last_case: "none".to_owned(),
        decision: "Deny".to_owned(),
        denial_class: "NotEvaluated".to_owned(),
    }
}

fn invalid_data(message: &str) -> anyhow::Error {
    anyhow::Error::new(io::Error::new(io::ErrorKind::InvalidData, message))
}

const SIMPLE_MATCH: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} { allow get: if 'cat'.matches('cat'); }
  }
}
";

const SIMPLE_NO_MATCH: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} { allow get: if 'cat'.matches('dog'); }
  }
}
";

const STEP_EXHAUSTED: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} {
      allow get: if resource.data.value.replace('z', 'x') == resource.data.value;
      match /{rest=**} { allow get: if true; }
    }
  }
}
";

const DEPTH_EXHAUSTED_WITH_NESTED_ALLOW: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} {
      allow get: if resource.data.value.matches('(a|aa)*b') == false;
      match /{rest=**} { allow get: if true; }
    }
  }
}
";

const PARENT_NEGATED: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} { allow get: if !('cat'.matches('cat')); }
  }
}
";

const NESTED_NEGATED: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} {
      allow get: if false;
      match /{rest=**} { allow get: if !('cat'.matches('dog')); }
    }
  }
}
";
