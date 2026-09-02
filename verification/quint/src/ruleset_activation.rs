//! Quint Connect driver for atomic ruleset publication and evaluation pinning.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot, RulesetSnapshot};
use quint_connect::{switch, Config, Driver, Result, State, Step};
use serde::Deserialize;

/// Actions exercised through the ruleset publication lifecycle.
pub const MODELED_ACTIONS: [&str; 10] = [
    "Create",
    "Parse",
    "Compile",
    "Check",
    "Reject",
    "Activate",
    "Republish",
    "StartEvaluation",
    "ProgressEvaluation",
    "FinishEvaluation",
];

/// Reproducible seeds used by generated conformance campaigns.
pub const GENERATED_TRACE_SEEDS: [&str; 4] = ["0x1", "0x2", "0x3", "0x4"];

const EVALUATIONS: [&str; 2] = ["r1", "r2"];
const V1: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if false; } } }";
const V2: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if true; } } }";

/// Production ruleset identity and evaluation snapshot versions.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RulesetActivationState {
    /// Version classified from the current production `RulesetSnapshot`.
    pub active_version: String,
    /// Monotonic generation assigned by the production publication boundary.
    pub generation: u64,
    /// Version pinned from production for each bounded logical evaluation.
    pub evaluation_version: BTreeMap<String, String>,
    /// Generation pinned from production for each bounded logical evaluation.
    pub evaluation_generation: BTreeMap<String, u64>,
}

/// Test-only perturbation after reading production state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionFault {
    /// Change only the active version.
    ActiveVersion,
    /// Change only the generation.
    Generation,
    /// Change only one evaluation version.
    EvaluationVersion,
    /// Change only one evaluation generation.
    EvaluationGeneration,
}

impl ProjectionFault {
    /// Returns the serialized production field affected by this fault.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::ActiveVersion => "activeVersion",
            Self::Generation => "generation",
            Self::EvaluationVersion => "evaluationVersion",
            Self::EvaluationGeneration => "evaluationGeneration",
        }
    }
}

/// Stateful adapter around one real atomic `RulesetSlot`.
pub struct RulesetActivationDriver {
    slot: RulesetSlot,
    candidate_phase: String,
    candidate_source: Option<String>,
    candidate_loaded: Option<LoadedRules>,
    evaluation_state: BTreeMap<String, String>,
    evaluation_version: BTreeMap<String, String>,
    evaluation_generation: BTreeMap<String, u64>,
    evaluation_snapshots: BTreeMap<String, RulesetSnapshot>,
    projection_fault: Option<ProjectionFault>,
    action_recorder: Option<Arc<Mutex<BTreeSet<String>>>>,
}

impl Default for RulesetActivationDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl RulesetActivationDriver {
    /// Builds an uninitialized driver around a real production slot.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slot: fresh_slot(),
            candidate_phase: "Absent".to_owned(),
            candidate_source: None,
            candidate_loaded: None,
            evaluation_state: initial_evaluation_map("Idle"),
            evaluation_version: initial_evaluation_map("v1"),
            evaluation_generation: EVALUATIONS
                .into_iter()
                .map(|evaluation| (evaluation.to_owned(), 0))
                .collect(),
            evaluation_snapshots: BTreeMap::new(),
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

    /// Changes the projection-only fault without mutating production state.
    pub fn set_projection_fault(&mut self, fault: ProjectionFault) {
        self.projection_fault = Some(fault);
    }

    /// Recreates generation zero and clears every harness lifecycle field.
    pub fn init(&mut self) -> Result {
        self.slot = fresh_slot();
        "Absent".clone_into(&mut self.candidate_phase);
        self.candidate_source = None;
        self.candidate_loaded = None;
        self.evaluation_state = initial_evaluation_map("Idle");
        self.evaluation_version = initial_evaluation_map("v1");
        self.evaluation_generation = EVALUATIONS
            .into_iter()
            .map(|evaluation| (evaluation.to_owned(), 0))
            .collect();
        self.evaluation_snapshots.clear();
        Ok(())
    }

    /// Creates the bounded candidate without modifying the active slot.
    pub fn create(&mut self) -> Result {
        self.require_candidate_phase("Absent")?;
        self.candidate_source = Some(V2.to_owned());
        "Created".clone_into(&mut self.candidate_phase);
        self.record_action("Create")
    }

    /// Parses the candidate through the production parser.
    pub fn parse(&mut self) -> Result {
        self.require_candidate_phase("Created")?;
        let source = self.candidate_source()?;
        parse_ruleset(source)
            .map_err(|error| invalid_data(&format!("candidate parse failed: {error}")))?;
        "Parsed".clone_into(&mut self.candidate_phase);
        self.record_action("Parse")
    }

    /// Compiles and lints the candidate into a real immutable `LoadedRules` value.
    pub fn compile(&mut self) -> Result {
        self.require_candidate_phase("Parsed")?;
        let loaded = LoadedRules::from_source(self.candidate_source()?)
            .map_err(|error| invalid_data(&format!("candidate compile failed: {error}")))?;
        self.candidate_loaded = Some(loaded);
        "Compiled".clone_into(&mut self.candidate_phase);
        self.record_action("Compile")
    }

    /// Checks the exact loaded candidate that would be published.
    pub fn check(&mut self) -> Result {
        self.require_candidate_phase("Compiled")?;
        let loaded = self
            .candidate_loaded
            .as_ref()
            .ok_or_else(|| invalid_data("compiled candidate is missing"))?;
        if !loaded.is_loaded() || loaded.source.as_deref() != Some(V2) {
            return Err(invalid_data("compiled candidate failed activation checks"));
        }
        "Checked".clone_into(&mut self.candidate_phase);
        self.record_action("Check")
    }

    /// Rejects a non-active candidate without touching the production slot.
    pub fn reject(&mut self) -> Result {
        if !matches!(
            self.candidate_phase.as_str(),
            "Created" | "Parsed" | "Compiled" | "Checked"
        ) {
            return Err(invalid_data("candidate cannot be rejected in this phase"));
        }
        self.candidate_source = None;
        self.candidate_loaded = None;
        "Rejected".clone_into(&mut self.candidate_phase);
        self.record_action("Reject")
    }

    /// Atomically publishes the fully checked real candidate.
    pub fn activate(&mut self) -> Result {
        self.require_candidate_phase("Checked")?;
        let loaded = self
            .candidate_loaded
            .take()
            .ok_or_else(|| invalid_data("checked candidate is missing"))?;
        self.slot
            .replace_loaded(loaded)
            .map_err(|error| invalid_data(&format!("candidate publication failed: {error}")))?;
        "Active".clone_into(&mut self.candidate_phase);
        self.record_action("Activate")
    }

    /// Republishes the active source as a distinct production generation.
    pub fn republish(&mut self) -> Result {
        self.require_candidate_phase("Active")?;
        let active = self
            .slot
            .snapshot()
            .map_err(|error| invalid_data(&format!("active snapshot failed: {error}")))?;
        self.slot
            .replace_loaded((*active).clone())
            .map_err(|error| invalid_data(&format!("ruleset republication failed: {error}")))?;
        self.record_action("Republish")
    }

    /// Admits one logical evaluation and retains its production snapshot.
    pub fn start_evaluation(&mut self, evaluation: &str) -> Result {
        self.require_evaluation_state(evaluation, "Idle")?;
        let snapshot = self
            .slot
            .snapshot()
            .map_err(|error| invalid_data(&format!("evaluation snapshot failed: {error}")))?;
        let version = version_of(&snapshot)?.to_owned();
        self.evaluation_version
            .insert(evaluation.to_owned(), version);
        self.evaluation_generation
            .insert(evaluation.to_owned(), snapshot.generation());
        self.evaluation_snapshots
            .insert(evaluation.to_owned(), snapshot);
        self.evaluation_state
            .insert(evaluation.to_owned(), "Running".to_owned());
        self.record_action("StartEvaluation")
    }

    /// Observes that the retained production snapshot did not rebind.
    pub fn progress_evaluation(&mut self, evaluation: &str) -> Result {
        self.require_evaluation_state(evaluation, "Running")?;
        self.assert_evaluation_snapshot(evaluation)?;
        self.record_action("ProgressEvaluation")
    }

    /// Finishes a evaluation only after validating its retained snapshot once more.
    pub fn finish_evaluation(&mut self, evaluation: &str) -> Result {
        self.require_evaluation_state(evaluation, "Running")?;
        self.assert_evaluation_snapshot(evaluation)?;
        self.evaluation_snapshots.remove(evaluation);
        self.evaluation_state
            .insert(evaluation.to_owned(), "Finished".to_owned());
        self.record_action("FinishEvaluation")
    }

    /// Projects the live slot and versions captured from production snapshots.
    pub fn project(&self) -> Result<RulesetActivationState> {
        let active = self
            .slot
            .snapshot()
            .map_err(|error| invalid_data(&format!("active snapshot failed: {error}")))?;
        let mut evaluation_version = self.evaluation_version.clone();
        for (evaluation, snapshot) in &self.evaluation_snapshots {
            evaluation_version.insert(evaluation.clone(), version_of(snapshot)?.to_owned());
        }
        let mut projected = RulesetActivationState {
            active_version: version_of(&active)?.to_owned(),
            generation: active.generation(),
            evaluation_version,
            evaluation_generation: self.evaluation_generation.clone(),
        };
        for (evaluation, snapshot) in &self.evaluation_snapshots {
            projected
                .evaluation_generation
                .insert(evaluation.clone(), snapshot.generation());
        }
        match self.projection_fault {
            None => {}
            Some(ProjectionFault::ActiveVersion) => {
                projected.active_version = opposite_version(&projected.active_version).to_owned();
            }
            Some(ProjectionFault::Generation) => {
                projected.generation = projected.generation.saturating_add(1);
            }
            Some(ProjectionFault::EvaluationVersion) => {
                if let Some(version) = projected.evaluation_version.get_mut("r1") {
                    *version = opposite_version(version).to_owned();
                }
            }
            Some(ProjectionFault::EvaluationGeneration) => {
                if let Some(generation) = projected.evaluation_generation.get_mut("r1") {
                    *generation = generation.saturating_add(1);
                }
            }
        }
        Ok(projected)
    }

    fn candidate_source(&self) -> Result<&str> {
        self.candidate_source
            .as_deref()
            .ok_or_else(|| invalid_data("candidate source is missing"))
    }

    fn require_candidate_phase(&self, expected: &str) -> Result {
        if self.candidate_phase == expected {
            Ok(())
        } else {
            Err(invalid_data("action is disabled in the candidate phase"))
        }
    }

    fn require_evaluation_state(&self, evaluation: &str, expected: &str) -> Result {
        if !EVALUATIONS.contains(&evaluation) {
            return Err(invalid_data("unknown bounded evaluation"));
        }
        if self.evaluation_state.get(evaluation).map(String::as_str) == Some(expected) {
            Ok(())
        } else {
            Err(invalid_data("action is disabled in the evaluation phase"))
        }
    }

    fn assert_evaluation_snapshot(&self, evaluation: &str) -> Result {
        let snapshot = self
            .evaluation_snapshots
            .get(evaluation)
            .ok_or_else(|| invalid_data("running evaluation snapshot is missing"))?;
        let recorded_version = self
            .evaluation_version
            .get(evaluation)
            .ok_or_else(|| invalid_data("running evaluation version is missing"))?;
        let recorded_generation = self
            .evaluation_generation
            .get(evaluation)
            .ok_or_else(|| invalid_data("running evaluation generation is missing"))?;
        if version_of(snapshot)? != recorded_version
            || snapshot.generation() != *recorded_generation
        {
            return Err(invalid_data("running evaluation snapshot was rebound"));
        }
        Ok(())
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

impl State<RulesetActivationDriver> for RulesetActivationState {
    fn from_driver(driver: &RulesetActivationDriver) -> Result<Self> {
        driver.project()
    }
}

impl Driver for RulesetActivationDriver {
    type State = RulesetActivationState;

    fn config() -> Config {
        Config {
            state: &["RulesetActivationScenarios::RulesetActivation::observable"],
            nondet: &["RulesetActivationScenarios::RulesetActivation::actionTaken"],
        }
    }

    #[allow(non_snake_case)]
    fn step(&mut self, step: &Step) -> Result {
        switch!(step {
            init => self.init()?,
            Create => self.create()?,
            Parse => self.parse()?,
            Compile => self.compile()?,
            Check => self.check()?,
            Reject => self.reject()?,
            Activate => self.activate()?,
            Republish => self.republish()?,
            StartEvaluation(evaluation: String) => self.start_evaluation(&evaluation)?,
            ProgressEvaluation(evaluation: String) => self.progress_evaluation(&evaluation)?,
            FinishEvaluation(evaluation: String) => self.finish_evaluation(&evaluation)?,
        })
    }
}

/// Driver configured for generated traces.
pub struct RulesetActivationConnectDriver {
    inner: RulesetActivationDriver,
}

impl Default for RulesetActivationConnectDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl RulesetActivationConnectDriver {
    /// Builds a fresh generated-trace driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RulesetActivationDriver::new(),
        }
    }
}

impl State<RulesetActivationConnectDriver> for RulesetActivationState {
    fn from_driver(driver: &RulesetActivationConnectDriver) -> Result<Self> {
        driver.inner.project()
    }
}

impl Driver for RulesetActivationConnectDriver {
    type State = RulesetActivationState;

    fn config() -> Config {
        Config {
            state: &["RulesetActivationConnect::RulesetActivation::observable"],
            nondet: &["RulesetActivationConnect::RulesetActivation::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        self.inner.step(step)
    }
}

fn fresh_slot() -> RulesetSlot {
    RulesetSlot::new(
        LoadedRules::from_source(V1)
            .unwrap_or_else(|error| panic!("fixed v1 ruleset must be valid: {error}")),
    )
}

fn initial_evaluation_map(value: &str) -> BTreeMap<String, String> {
    EVALUATIONS
        .into_iter()
        .map(|evaluation| (evaluation.to_owned(), value.to_owned()))
        .collect()
}

fn version_of(snapshot: &RulesetSnapshot) -> Result<&'static str> {
    match snapshot.source.as_deref() {
        Some(V1) => Ok("v1"),
        Some(V2) => Ok("v2"),
        _ => Err(invalid_data("production slot contains an unknown ruleset")),
    }
}

fn opposite_version(version: &str) -> &'static str {
    if version == "v1" {
        "v2"
    } else {
        "v1"
    }
}

fn invalid_data(message: &str) -> anyhow::Error {
    anyhow::anyhow!(message.to_owned())
}
