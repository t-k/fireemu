//! Quint Connect driver for request-local regular expression compilation reuse.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{Arc, Mutex};

use fireemu_core_rules::ast::Ruleset;
use fireemu_core_rules::eval::{evaluate_request, Decision, Method, RequestContext, RulesService};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::value::RulesValue;
use quint_connect::{switch, Config, Driver, Result, State, Step};
use serde::Deserialize;

/// Actions exercised through the production rules evaluator.
pub const MODELED_ACTIONS: [&str; 1] = ["Evaluate"];
/// Reproducible seeds used by generated conformance campaigns.
pub const GENERATED_TRACE_SEEDS: [&str; 4] = ["0x1", "0x2", "0x3", "0x4"];

/// Production-derived regular expression cache observation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegexEvaluationCacheState {
    /// Stable bounded scenario name.
    pub last_case: String,
    /// Authorization result proving that every expected expression ran.
    pub decision: String,
    /// Dynamic patterns compiled during the observed evaluation.
    pub runtime_compiles: u64,
    /// Dynamic pattern lookups served from the evaluation-local cache.
    pub cache_hits: u64,
    /// Greatest number of dynamic patterns retained at once.
    pub peak_cache_entries: usize,
    /// Whether two consecutive evaluations started with independent caches.
    pub evaluation_isolation: bool,
}

/// Test-only perturbation of one production projection field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionFault {
    /// Perturb the authorization result.
    Decision,
    /// Perturb the runtime compilation count.
    RuntimeCompiles,
    /// Perturb the cache-hit count.
    CacheHits,
    /// Perturb the peak retained-entry count.
    PeakCacheEntries,
    /// Perturb the evaluation isolation result.
    EvaluationIsolation,
}

impl ProjectionFault {
    /// All independently checked production projection faults.
    pub const ALL: [Self; 5] = [
        Self::Decision,
        Self::RuntimeCompiles,
        Self::CacheHits,
        Self::PeakCacheEntries,
        Self::EvaluationIsolation,
    ];

    /// Serialized field changed by this fault.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::Decision => "decision",
            Self::RuntimeCompiles => "runtimeCompiles",
            Self::CacheHits => "cacheHits",
            Self::PeakCacheEntries => "peakCacheEntries",
            Self::EvaluationIsolation => "evaluationIsolation",
        }
    }
}

/// Stateful adapter over one bounded production rules evaluation scenario.
pub struct RegexEvaluationCacheDriver {
    state: RegexEvaluationCacheState,
    projection_fault: Option<ProjectionFault>,
    action_recorder: Option<Arc<Mutex<BTreeSet<String>>>>,
}

impl Default for RegexEvaluationCacheDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl RegexEvaluationCacheDriver {
    /// Builds an unevaluated regex cache driver.
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

    /// Executes one bounded scenario through the production parser and evaluator.
    pub fn evaluate(&mut self, case: &str) -> Result {
        if self.state.last_case != "none" {
            return Err(invalid_data("regex cache case already evaluated"));
        }

        let (report, evaluation_isolation) = match case {
            "literal" => (evaluate(LITERAL_RULES, None)?, true),
            "dynamicRepeated" => (evaluate(DYNAMIC_RULES, Some(dynamic_document()))?, true),
            "capacity" => {
                let (rules, document) = capacity_fixture();
                (evaluate(&rules, Some(document))?, true)
            }
            "separateEvaluations" => {
                let document = dynamic_document();
                let ruleset = parse(DYNAMIC_RULES)?;
                let first = evaluate_ruleset(&ruleset, Some(document.clone()));
                let second = evaluate_ruleset(&ruleset, Some(document));
                let isolated = first.regex.runtime_compiles == 1
                    && first.regex.cache_hits == 2
                    && first.regex.peak_cache_entries == 1
                    && second.regex == first.regex;
                (second, isolated)
            }
            _ => return Err(invalid_data("unknown regex cache case")),
        };

        self.state = RegexEvaluationCacheState {
            last_case: case.to_owned(),
            decision: match report.decision {
                Decision::Allow => "Allow",
                Decision::Deny(_) => "Deny",
            }
            .to_owned(),
            runtime_compiles: report.regex.runtime_compiles,
            cache_hits: report.regex.cache_hits,
            peak_cache_entries: report.regex.peak_cache_entries,
            evaluation_isolation,
        };
        if let Some(recorder) = &self.action_recorder {
            recorder
                .lock()
                .map_err(|_| invalid_data("action recorder lock poisoned"))?
                .insert("Evaluate".to_owned());
        }
        Ok(())
    }

    /// Projects production-derived regex cache state.
    pub fn project(&self) -> Result<RegexEvaluationCacheState> {
        let mut state = self.state.clone();
        match self.projection_fault {
            None => {}
            Some(ProjectionFault::Decision) => "Deny".clone_into(&mut state.decision),
            Some(ProjectionFault::RuntimeCompiles) => {
                state.runtime_compiles = state.runtime_compiles.saturating_add(1);
            }
            Some(ProjectionFault::CacheHits) => {
                state.cache_hits = state.cache_hits.saturating_add(1);
            }
            Some(ProjectionFault::PeakCacheEntries) => {
                state.peak_cache_entries = state.peak_cache_entries.saturating_add(1);
            }
            Some(ProjectionFault::EvaluationIsolation) => {
                state.evaluation_isolation = !state.evaluation_isolation;
            }
        }
        Ok(state)
    }
}

impl State<RegexEvaluationCacheDriver> for RegexEvaluationCacheState {
    fn from_driver(driver: &RegexEvaluationCacheDriver) -> Result<Self> {
        driver.project()
    }
}

impl Driver for RegexEvaluationCacheDriver {
    type State = RegexEvaluationCacheState;

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

fn evaluate(
    rules: &str,
    resource: Option<RulesValue>,
) -> Result<fireemu_core_rules::eval::EvaluationReport> {
    let ruleset = parse(rules)?;
    Ok(evaluate_ruleset(&ruleset, resource))
}

fn parse(rules: &str) -> Result<Ruleset> {
    parse_ruleset(rules)
        .map_err(|error| invalid_data(&format!("cannot parse regex cache rules: {error}")))
}

fn evaluate_ruleset(
    ruleset: &Ruleset,
    resource: Option<RulesValue>,
) -> fireemu_core_rules::eval::EvaluationReport {
    let request = RequestContext {
        service: RulesService::Firestore,
        method: Method::Get,
        path: "/databases/(default)/documents/notes/n1".to_owned(),
        auth: None,
        resource,
        request_resource: None,
        time_unix_nanos: 0,
        abstract_path: false,
        request_query: None,
    };
    evaluate_request(ruleset, &request)
}

fn dynamic_document() -> RulesValue {
    document(BTreeMap::from([(
        "pattern".to_owned(),
        RulesValue::String("a+".to_owned()),
    )]))
}

fn capacity_fixture() -> (String, RulesValue) {
    let conditions = (0..17)
        .map(|index| format!("'a'.matches(resource.data.patterns.p{index})"))
        .chain(["'a'.matches(resource.data.patterns.p0)".to_owned()])
        .collect::<Vec<_>>()
        .join(" && ");
    let rules = format!(
        "rules_version = '2'; service cloud.firestore {{ match /databases/{{database}}/documents {{ match /notes/{{id}} {{ allow get: if {conditions}; }} }} }}"
    );
    let patterns = (0..17)
        .map(|index| {
            (
                format!("p{index}"),
                RulesValue::String(format!("a{{1,{}}}", index + 1)),
            )
        })
        .collect::<BTreeMap<_, _>>();
    (
        rules,
        document(BTreeMap::from([(
            "patterns".to_owned(),
            RulesValue::Map(patterns),
        )])),
    )
}

fn document(data: BTreeMap<String, RulesValue>) -> RulesValue {
    RulesValue::Map(BTreeMap::from([("data".to_owned(), RulesValue::Map(data))]))
}

fn initial_state() -> RegexEvaluationCacheState {
    RegexEvaluationCacheState {
        last_case: "none".to_owned(),
        decision: "Deny".to_owned(),
        runtime_compiles: 0,
        cache_hits: 0,
        peak_cache_entries: 0,
        evaluation_isolation: true,
    }
}

fn invalid_data(message: &str) -> anyhow::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned()).into()
}

const LITERAL_RULES: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} {
      allow get: if 'aaa'.matches('a+')
                 && 'aaa'.matches('a+')
                 && 'aaa'.matches('a+');
    }
  }
}
";

const DYNAMIC_RULES: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} {
      allow get: if 'aaa'.matches(resource.data.pattern)
                 && 'aaa'.matches(resource.data.pattern)
                 && 'aaa'.matches(resource.data.pattern);
    }
  }
}
";
