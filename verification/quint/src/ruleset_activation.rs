//! Quint Connect driver for atomic ruleset publication and request pinning.

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
    "StartRequest",
    "ProgressRequest",
    "FinishRequest",
];

/// Reproducible seeds used by generated conformance campaigns.
pub const GENERATED_TRACE_SEEDS: [&str; 4] = ["0x1", "0x2", "0x3", "0x4"];

const REQUESTS: [&str; 2] = ["r1", "r2"];
const V1: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if false; } } }";
const V2: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if true; } } }";

/// Production ruleset identity and request snapshot versions.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RulesetActivationState {
    /// Version classified from the current production `RulesetSnapshot`.
    pub active_version: String,
    /// Monotonic generation assigned by the production publication boundary.
    pub generation: u64,
    /// Version pinned from production for each bounded logical request.
    pub request_version: BTreeMap<String, String>,
    /// Generation pinned from production for each bounded logical request.
    pub request_generation: BTreeMap<String, u64>,
}

/// Test-only perturbation after reading production state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionFault {
    /// Change only the active version.
    ActiveVersion,
    /// Change only the generation.
    Generation,
    /// Change only one request version.
    RequestVersion,
    /// Change only one request generation.
    RequestGeneration,
}

impl ProjectionFault {
    /// Returns the serialized production field affected by this fault.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::ActiveVersion => "activeVersion",
            Self::Generation => "generation",
            Self::RequestVersion => "requestVersion",
            Self::RequestGeneration => "requestGeneration",
        }
    }
}

/// Stateful adapter around one real atomic `RulesetSlot`.
pub struct RulesetActivationDriver {
    slot: RulesetSlot,
    candidate_phase: String,
    candidate_source: Option<String>,
    candidate_loaded: Option<LoadedRules>,
    request_state: BTreeMap<String, String>,
    request_version: BTreeMap<String, String>,
    request_generation: BTreeMap<String, u64>,
    request_snapshots: BTreeMap<String, RulesetSnapshot>,
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
            request_state: initial_request_map("Idle"),
            request_version: initial_request_map("v1"),
            request_generation: REQUESTS
                .into_iter()
                .map(|request| (request.to_owned(), 0))
                .collect(),
            request_snapshots: BTreeMap::new(),
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
        self.request_state = initial_request_map("Idle");
        self.request_version = initial_request_map("v1");
        self.request_generation = REQUESTS
            .into_iter()
            .map(|request| (request.to_owned(), 0))
            .collect();
        self.request_snapshots.clear();
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

    /// Admits one logical request and retains its production snapshot.
    pub fn start_request(&mut self, request: &str) -> Result {
        self.require_request_state(request, "Idle")?;
        let snapshot = self
            .slot
            .snapshot()
            .map_err(|error| invalid_data(&format!("request snapshot failed: {error}")))?;
        let version = version_of(&snapshot)?.to_owned();
        self.request_version.insert(request.to_owned(), version);
        self.request_generation
            .insert(request.to_owned(), snapshot.generation());
        self.request_snapshots.insert(request.to_owned(), snapshot);
        self.request_state
            .insert(request.to_owned(), "Running".to_owned());
        self.record_action("StartRequest")
    }

    /// Observes that the retained production snapshot did not rebind.
    pub fn progress_request(&mut self, request: &str) -> Result {
        self.require_request_state(request, "Running")?;
        self.assert_request_snapshot(request)?;
        self.record_action("ProgressRequest")
    }

    /// Finishes a request only after validating its retained snapshot once more.
    pub fn finish_request(&mut self, request: &str) -> Result {
        self.require_request_state(request, "Running")?;
        self.assert_request_snapshot(request)?;
        self.request_snapshots.remove(request);
        self.request_state
            .insert(request.to_owned(), "Finished".to_owned());
        self.record_action("FinishRequest")
    }

    /// Projects the live slot and versions captured from production snapshots.
    pub fn project(&self) -> Result<RulesetActivationState> {
        let active = self
            .slot
            .snapshot()
            .map_err(|error| invalid_data(&format!("active snapshot failed: {error}")))?;
        let mut request_version = self.request_version.clone();
        for (request, snapshot) in &self.request_snapshots {
            request_version.insert(request.clone(), version_of(snapshot)?.to_owned());
        }
        let mut projected = RulesetActivationState {
            active_version: version_of(&active)?.to_owned(),
            generation: active.generation(),
            request_version,
            request_generation: self.request_generation.clone(),
        };
        for (request, snapshot) in &self.request_snapshots {
            projected
                .request_generation
                .insert(request.clone(), snapshot.generation());
        }
        match self.projection_fault {
            None => {}
            Some(ProjectionFault::ActiveVersion) => {
                projected.active_version = opposite_version(&projected.active_version).to_owned();
            }
            Some(ProjectionFault::Generation) => {
                projected.generation = projected.generation.saturating_add(1);
            }
            Some(ProjectionFault::RequestVersion) => {
                if let Some(version) = projected.request_version.get_mut("r1") {
                    *version = opposite_version(version).to_owned();
                }
            }
            Some(ProjectionFault::RequestGeneration) => {
                if let Some(generation) = projected.request_generation.get_mut("r1") {
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

    fn require_request_state(&self, request: &str, expected: &str) -> Result {
        if !REQUESTS.contains(&request) {
            return Err(invalid_data("unknown bounded request"));
        }
        if self.request_state.get(request).map(String::as_str) == Some(expected) {
            Ok(())
        } else {
            Err(invalid_data("action is disabled in the request phase"))
        }
    }

    fn assert_request_snapshot(&self, request: &str) -> Result {
        let snapshot = self
            .request_snapshots
            .get(request)
            .ok_or_else(|| invalid_data("running request snapshot is missing"))?;
        let recorded_version = self
            .request_version
            .get(request)
            .ok_or_else(|| invalid_data("running request version is missing"))?;
        let recorded_generation = self
            .request_generation
            .get(request)
            .ok_or_else(|| invalid_data("running request generation is missing"))?;
        if version_of(snapshot)? != recorded_version
            || snapshot.generation() != *recorded_generation
        {
            return Err(invalid_data("running request snapshot was rebound"));
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
            StartRequest(request: String) => self.start_request(&request)?,
            ProgressRequest(request: String) => self.progress_request(&request)?,
            FinishRequest(request: String) => self.finish_request(&request)?,
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

fn initial_request_map(value: &str) -> BTreeMap<String, String> {
    REQUESTS
        .into_iter()
        .map(|request| (request.to_owned(), value.to_owned()))
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
