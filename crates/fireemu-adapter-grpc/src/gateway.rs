//! Strict gateway checks (Phase FS-0): canonicalize, Standard query limits, index decision.

use core::fmt;

use fireemu_core_firestore::index::{
    decide, plan_scans, validate_aggregation_query as validate_aggregation_index_query,
    IndexDecision, IndexDefinition, IndexSet, IndexValidationPolicy, PlannedScan, PlanningContext,
};
use fireemu_core_firestore::query::{Query, QueryLimitViolation};
use fireemu_core_firestore::store::{normalize_aggregation_query, Aggregation};
use fireemu_core_types::edition::FirestoreEdition;

use crate::decode::DecodeError;

/// Why a request was rejected.
#[derive(Debug, Clone, PartialEq)]
pub enum Rejection {
    /// Wire decoding failed.
    Decode(DecodeError),
    /// The query is structurally invalid.
    InvalidQuery(String),
    /// Standard query limits are violated.
    QueryLimits(Vec<QueryLimitViolation>),
    /// A required composite index is missing (Standard).
    MissingIndex {
        /// `firestore.indexes.json` fragment.
        fragment: String,
        /// Human-readable description.
        description: String,
        /// The index the query needs.
        requirement: IndexDefinition,
        /// Whether the query has inequality filters on more than one field.
        multiple_inequalities: bool,
    },
    /// The validator cannot model the query; fail closed.
    Unsupported(String),
}

impl Rejection {
    /// gRPC status for the rejection. Codes follow the wire mapping revision in
    /// `fireemu_core_limits::evaluate::WIRE_MAPPING_REVISION`.
    #[must_use]
    pub fn to_status(&self) -> tonic::Status {
        let mut status = match self {
            Self::Decode(e) => tonic::Status::new(e.grpc_code(), e.to_string()),
            Self::InvalidQuery(m) => tonic::Status::invalid_argument(m.clone()),
            // Production refuses with the first limit it checks, in its own words
            // (FS-QUERY-INDEX query-limits, recorded 2026-09-24).
            Self::QueryLimits(v) => tonic::Status::invalid_argument(
                v.first().map_or_else(String::new, |x| x.message.clone()),
            ),
            Self::MissingIndex { fragment, description, .. } => tonic::Status::failed_precondition(format!(
                "The query requires an index. {description}\nAdd to firestore.indexes.json:\n{fragment}"
            )),
            Self::Unsupported(m) => tonic::Status::unimplemented(m.clone()),
        };
        let code = match self {
            Self::Decode(_) => "FS_GW_DECODE",
            Self::InvalidQuery(_) => "FS_GW_INVALID_QUERY",
            Self::QueryLimits(_) => "FS_GW_QUERY_LIMIT",
            Self::MissingIndex { .. } => "FS_GW_MISSING_INDEX",
            Self::Unsupported(_) => "FS_GW_UNSUPPORTED",
        };
        if let Ok(v) = code.parse() {
            status.metadata_mut().insert("fireemu-reason", v);
        }
        status
    }
}

/// `projects/<p>/databases/<d>` of a query parent.
#[must_use]
pub fn database_name(parent: &crate::decode::Parent) -> String {
    format!(
        "projects/{}/databases/{}",
        parent.project.as_str(),
        parent.database.as_str()
    )
}

impl Rejection {
    /// The status for a rejection of a query on `database` (`projects/<p>/databases/<d>`).
    /// A missing index is refused in production's words, with the console link that names
    /// the database; every other rejection is [`Rejection::to_status`].
    #[must_use]
    pub fn to_status_in(&self, database: &str) -> tonic::Status {
        let Self::MissingIndex {
            requirement,
            multiple_inequalities,
            ..
        } = self
        else {
            return self.to_status();
        };
        let mut status =
            tonic::Status::failed_precondition(crate::index_messages::missing_index_message(
                database,
                requirement,
                *multiple_inequalities,
            ));
        if let Ok(v) = "FS_GW_MISSING_INDEX".parse() {
            status.metadata_mut().insert("fireemu-reason", v);
        }
        status
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_status().message())
    }
}

/// Accepted query plan.
#[derive(Debug, Clone, PartialEq)]
pub struct AcceptedQuery {
    /// Canonical query.
    pub query: Query,
    /// Index decision (never `MissingRequired`).
    pub decision: IndexDecision,
    /// The index scans of each DNF disjunct, for Explain; `None` when no index plan
    /// describes the query (kindless, or a full scan on Enterprise).
    pub scans: Option<Vec<PlannedScan>>,
    /// Diagnostics such as `FS_ENT_FULL_COLLECTION_SCAN`.
    pub warnings: Vec<String>,
}

/// The Standard query limits the pinned official Firestore emulator refuses as well, as
/// measured by `conformance/src/firestore-probe` (`errors/rest-shapes`): more than 30
/// disjunctions (`'IN' supports up to 30 comparison values.`) and a second `array-contains`
/// clause (`Only a single array-contains clause is allowed in a query`). They are refused
/// whatever `enforce_limits` says, so the `emulator` profile answers what the official
/// emulator answers.
pub const OFFICIAL_EMULATOR_REFUSES: &[&str] = &[
    "FS-QUERY-LIMIT-DNF-DISJUNCTIONS",
    "FS-QUERY-LIMIT-ARRAY-CONTAINS-PER-DISJUNCTION",
];

/// The warning a query carries when the strict profile served it without its composite index
/// (`firestore.missingIndexes: "report"`); production refuses the same query.
pub const MISSING_INDEX_REPORTED: &str = "FS_MISSING_INDEX_REPORTED";

/// A composite index the strict profile assumed for a query production refuses without it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingIndexReport {
    /// `projects/<p>/databases/<d>`.
    pub database: String,
    /// The `firestore.indexes.json` entry that serves the query.
    pub fragment: String,
    /// Production's refusal of the query, with the console link that creates the index.
    pub message: String,
}

/// Distinct missing indexes kept for [`missing_index_reports`]; later ones are only logged.
const MAX_MISSING_INDEX_REPORTS: usize = 1000;

static MISSING_INDEX_REPORTS: std::sync::Mutex<Vec<MissingIndexReport>> =
    std::sync::Mutex::new(Vec::new());

/// Whether a report is the first of its (database, index).
enum Noted {
    New,
    Seen,
    /// New, but the list is full.
    OverBound,
}

/// The stderr line of a report. Field paths reach it only JSON-escaped (the fragment) or with
/// control characters escaped (production's text), each cut at the shared echo bound.
fn missing_index_log_line(report: &MissingIndexReport) -> String {
    format!(
        "[firestore] {}: served a query without its composite index (firestore.missingIndexes \
         is \"report\"); production refuses it: {}\nAdd to firestore.indexes.json:\n{}",
        report.database,
        fireemu_core_types::codec::echo(&escape_control_characters(&report.message)),
        fireemu_core_types::codec::echo(&report.fragment),
    )
}

/// `text` with every control character but a line feed written as its Rust escape.
fn escape_control_characters(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() && c != '\n' {
            escaped.extend(c.escape_default());
        } else {
            escaped.push(c);
        }
    }
    escaped
}

/// Every distinct (database, index) the strict profile has reported since the process
/// started, in the order first seen, so a test run can fail on any of them.
#[must_use]
pub fn missing_index_reports() -> Vec<MissingIndexReport> {
    MISSING_INDEX_REPORTS
        .lock()
        .map(|reports| reports.clone())
        .unwrap_or_default()
}

/// Strict gateway configuration.
#[derive(Debug, Clone)]
pub struct Gateway {
    /// Planning context (edition, API mode, policy).
    pub ctx: PlanningContext,
    /// Configured indexes.
    pub indexes: IndexSet,
    /// Whether a Standard query limit violation refuses the query (`firestore.enforceLimits`,
    /// which the compatibility profile defaults: `strict` enforces, `firebase` observes).
    /// When it observes, every violation is reported as an `FS_LIMIT_OBSERVED:<id>` warning
    /// and the query runs, which is what the official emulator does with the same query.
    pub enforce_limits: bool,
}

impl Gateway {
    /// Whether requests get the refusals only production makes: the strict profile, whatever
    /// `firestore.missingIndexes` says. The emulator profile may add no rejection
    /// (`spec/compatibility/contract.json`).
    #[must_use]
    pub fn production_refusals(&self) -> bool {
        self.ctx.policy.production_rules()
    }

    /// Records and logs, once per database and index, a query on `database`
    /// (`projects/<p>/databases/<d>`) that this gateway served without the composite index
    /// production refuses it without (`firestore.missingIndexes: "report"`). Anything else,
    /// including the emulator profile's assumptions, is left alone. Returns the line written
    /// to stderr, if any.
    pub fn report_missing_index(&self, database: &str, accepted: &AcceptedQuery) -> Option<String> {
        self.report_missing_index_as(database, accepted, |requirement, multiple_inequalities| {
            crate::index_messages::missing_index_message(
                database,
                requirement,
                multiple_inequalities,
            )
        })
    }

    /// [`Self::report_missing_index`] with production's refusal text from `message` (given the
    /// required index and whether the query has inequalities on several fields), for a caller
    /// that knows the index's state (an Admin create still building it, or its deletion).
    pub fn report_missing_index_as(
        &self,
        database: &str,
        accepted: &AcceptedQuery,
        message: impl FnOnce(&IndexDefinition, bool) -> String,
    ) -> Option<String> {
        use std::io::Write as _;
        let IndexDecision::AssumedIndex { requirement } = &accepted.decision else {
            return None;
        };
        if self.ctx.policy != IndexValidationPolicy::ProductionReport {
            return None;
        }
        let report = MissingIndexReport {
            database: database.to_owned(),
            fragment: requirement.indexes_json_fragment(),
            message: message(requirement, accepted.query.inequality_fields().len() > 1),
        };
        let noted = MISSING_INDEX_REPORTS
            .lock()
            .map(|mut reports| {
                let seen = reports
                    .iter()
                    .any(|r| r.database == report.database && r.fragment == report.fragment);
                if seen {
                    Noted::Seen
                } else if reports.len() < MAX_MISSING_INDEX_REPORTS {
                    reports.push(report.clone());
                    Noted::New
                } else {
                    Noted::OverBound
                }
            })
            .unwrap_or(Noted::Seen);
        let line = match noted {
            Noted::Seen => return None,
            Noted::New => missing_index_log_line(&report),
            Noted::OverBound => {
                static OVER_BOUND: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if OVER_BOUND.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    return None;
                }
                format!(
                    "[firestore] more than {MAX_MISSING_INDEX_REPORTS} distinct missing composite \
                     indexes; later ones are served without being reported"
                )
            }
        };
        let _ = writeln!(std::io::stderr(), "{line}");
        Some(line)
    }

    /// Runs every strict check on a decoded query.
    pub fn validate_query(&self, query: &Query) -> Result<AcceptedQuery, Rejection> {
        self.validate_query_with_indexes(query, &self.indexes)
    }

    /// Runs every strict check for an aggregation query using the gateway's index catalog.
    /// Sum and average target fields participate in index validation without changing the
    /// executable query.
    pub fn validate_aggregation_query(
        &self,
        query: &Query,
        aggregations: &[Aggregation],
    ) -> Result<AcceptedQuery, Rejection> {
        self.validate_aggregation_query_with_indexes(query, aggregations, &self.indexes)
    }

    /// Runs every strict check with a borrowed database-specific index catalog.
    pub fn validate_query_with_indexes(
        &self,
        query: &Query,
        indexes: &IndexSet,
    ) -> Result<AcceptedQuery, Rejection> {
        self.validate_canonical_query(self.canonicalize(query)?, indexes, None)
    }

    /// Runs every strict check for an aggregation query with a borrowed database-specific index
    /// catalog. Preserve caller ordering for Rules metadata; index planning and the store
    /// executor derive the same aggregation ordering with the shared normalizer.
    pub fn validate_aggregation_query_with_indexes(
        &self,
        query: &Query,
        aggregations: &[Aggregation],
        indexes: &IndexSet,
    ) -> Result<AcceptedQuery, Rejection> {
        self.validate_canonical_query(self.canonicalize(query)?, indexes, Some(aggregations))
    }

    /// The canonical query, with the refusals of the profile's policy: production's under
    /// the strict profile, the official emulator's under the emulator profile.
    fn canonicalize(&self, query: &Query) -> Result<Query, Rejection> {
        if self.production_refusals() {
            query.canonicalize()
        } else {
            query.canonicalize_emulator()
        }
        .map_err(|e| Rejection::InvalidQuery(e.to_string()))
    }

    fn validate_canonical_query(
        &self,
        canonical: Query,
        indexes: &IndexSet,
        aggregations: Option<&[Aggregation]>,
    ) -> Result<AcceptedQuery, Rejection> {
        // Production refuses a cursor whose `__name__` value is not a document reference,
        // or whose reference names a document the query does not select. The compatibility
        // contract keeps production-only refusals out of the `emulator` profile.
        if self.production_refusals() {
            canonical
                .check_production_cursor_constraints()
                .map_err(|error| Rejection::InvalidQuery(error.to_string()))?;
        }
        let disjunctions = canonical.dnf_disjunction_count();
        if disjunctions > fireemu_core_firestore::query::MAX_MATERIALIZED_DISJUNCTIONS {
            return Err(Rejection::InvalidQuery(format!(
                "query expands to {disjunctions} disjunctions (bound {})",
                fireemu_core_firestore::query::MAX_MATERIALIZED_DISJUNCTIONS
            )));
        }
        let mut warnings = Vec::new();
        if self.ctx.edition == FirestoreEdition::Standard {
            canonical
                .check_standard_constraints()
                .map_err(|error| Rejection::InvalidQuery(error.to_string()))?;
            if let Err(violations) = canonical.check_standard_limits() {
                // The limits the official emulator refuses too are refused under either
                // setting; the switch only decides the production-only ones.
                let (refused, observed): (Vec<_>, Vec<_>) = violations.into_iter().partition(|v| {
                    self.enforce_limits || OFFICIAL_EMULATOR_REFUSES.contains(&v.limit_id)
                });
                if !refused.is_empty() {
                    return Err(Rejection::QueryLimits(refused));
                }
                warnings.extend(
                    observed
                        .iter()
                        .map(|v| format!("FS_LIMIT_OBSERVED:{}", v.limit_id)),
                );
            }
        }
        // Limits above count the caller's clauses, not implicit aggregation orders.
        let execution_query = match aggregations {
            Some(aggregations) => {
                normalize_aggregation_query(&canonical, aggregations).map_err(|error| {
                    Rejection::InvalidQuery(match error {
                        fireemu_core_firestore::store::FirestoreError::InvalidArgument(m) => m,
                        other => other.to_string(),
                    })
                })?
            }
            None => canonical.clone(),
        };
        let decision = aggregations.map_or_else(
            || decide(&canonical, indexes, &self.ctx),
            |aggregations| {
                validate_aggregation_index_query(&execution_query, aggregations, indexes, &self.ctx)
            },
        );
        match &decision {
            IndexDecision::UseIndex { .. }
            | IndexDecision::MergeIndexes { .. }
            | IndexDecision::KindlessScan => {}
            // The strict profile reports with the database's console link, which only the
            // caller knows ([`Self::report_missing_index`]).
            IndexDecision::AssumedIndex { .. } if self.production_refusals() => {
                warnings.push(MISSING_INDEX_REPORTED.to_owned());
            }
            IndexDecision::AssumedIndex { requirement } => {
                warnings.push("FS_EMULATOR_INDEX_ASSUMED".to_owned());
                note_assumed_index(&requirement.indexes_json_fragment());
            }
            IndexDecision::FullScanAllowed { plan } => {
                warnings.extend(plan.diagnostics.iter().map(|d| (*d).to_owned()));
            }
            IndexDecision::MissingRequired { requirement } => {
                return Err(Rejection::MissingIndex {
                    fragment: requirement.indexes_json_fragment(),
                    description: decision.to_string(),
                    requirement: requirement.clone(),
                    multiple_inequalities: canonical.inequality_fields().len() > 1,
                });
            }
            IndexDecision::Unsupported { feature } => {
                return Err(Rejection::Unsupported((*feature).to_owned()));
            }
        }
        let scans = matches!(
            decision,
            IndexDecision::UseIndex { .. }
                | IndexDecision::MergeIndexes { .. }
                | IndexDecision::AssumedIndex { .. }
        )
        .then(|| {
            plan_scans(
                &execution_query,
                aggregations.unwrap_or_default(),
                indexes,
                &self.ctx,
            )
        })
        .flatten();
        Ok(AcceptedQuery {
            query: canonical,
            decision,
            scans,
            warnings,
        })
    }
}

/// Says once per distinct index which composite index production would need for a query
/// the emulator policy served without it (every surface: unary, REST, Listen, aggregations).
/// The fragment names client field paths, so it is cut at the shared echo bound, and a stderr
/// that cannot take the line (a full non-blocking pipe) never fails the request.
fn note_assumed_index(fragment: &str) {
    use std::io::Write as _;
    static NOTED: std::sync::OnceLock<std::sync::Mutex<std::collections::BTreeSet<String>>> =
        std::sync::OnceLock::new();
    let fragment = fireemu_core_types::codec::echo(fragment);
    let fragment = fragment.as_ref();
    let noted = NOTED.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeSet::new()));
    let first = noted
        .lock()
        .map(|mut set| set.insert(fragment.to_owned()))
        .unwrap_or(false);
    if first {
        let _ = writeln!(
            std::io::stderr(),
            "[firestore] served without a configured composite index (emulator profile); production needs: {fragment}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{escape_control_characters, missing_index_log_line, MissingIndexReport};
    use proptest::prelude::*;

    #[test]
    fn the_log_line_keeps_line_feeds_and_escapes_every_other_control_character() {
        assert_eq!(escape_control_characters("a\nb"), "a\nb");
        assert_eq!(
            escape_control_characters("a\tb\rc\u{1b}d\u{7f}"),
            "a\\tb\\rc\\u{1b}d\\u{7f}"
        );
        assert_eq!(escape_control_characters("名前 `x y`"), "名前 `x y`");
    }

    #[test]
    fn the_log_line_names_the_database_the_refusal_and_the_fragment() {
        let report = MissingIndexReport {
            database: "projects/p/databases/(default)".to_owned(),
            fragment: "{\n  \"collectionGroup\": \"c\"\n}".to_owned(),
            message: "The query requires an index.\tlink".to_owned(),
        };
        assert_eq!(
            missing_index_log_line(&report),
            "[firestore] projects/p/databases/(default): served a query without its composite \
             index (firestore.missingIndexes is \"report\"); production refuses it: The query \
             requires an index.\\tlink\nAdd to firestore.indexes.json:\n{\n  \"collectionGroup\": \"c\"\n}"
        );
    }

    proptest! {
        /// Nothing but a line feed reaches the log as a control character, and text without
        /// one is written as it is.
        #[test]
        fn escaping_leaves_no_control_character_but_line_feeds(text in any::<String>()) {
            let escaped = escape_control_characters(&text);
            prop_assert!(escaped.chars().all(|c| !c.is_control() || c == '\n'));
            if text.chars().all(|c| !c.is_control() || c == '\n') {
                prop_assert_eq!(escaped, text);
            }
        }
    }
}
