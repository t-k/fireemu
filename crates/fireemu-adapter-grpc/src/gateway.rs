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
    /// Whether requests get the refusals only production makes: the strict profile's index
    /// policy. The emulator profile may add no rejection (`spec/compatibility/contract.json`).
    #[must_use]
    pub fn production_refusals(&self) -> bool {
        self.ctx.policy == IndexValidationPolicy::Production
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
        match self.ctx.policy {
            IndexValidationPolicy::Production => query.canonicalize(),
            IndexValidationPolicy::Emulator => query.canonicalize_emulator(),
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
        // contract keeps production-only refusals out of the `emulator` profile, and the
        // production index policy is exactly what the strict profile selects.
        if self.ctx.policy == IndexValidationPolicy::Production {
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
