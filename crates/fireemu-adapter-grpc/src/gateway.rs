//! Strict gateway checks (Phase FS-0): canonicalize, Standard query limits, index decision.

use core::fmt;

use fireemu_core_firestore::index::{decide, IndexDecision, IndexSet, PlanningContext};
use fireemu_core_firestore::query::{Query, QueryLimitViolation};
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
            Self::QueryLimits(v) => {
                let lines: Vec<String> = v.iter().map(|x| format!("{}: {} ({} > {})", x.limit_id, x.detail, x.current, x.maximum)).collect();
                let message = format!("query limit violation: {}", lines.join("; "));
                // A second array-contains clause is INVALID_ARGUMENT with production's own
                // wording (conformance/firestore-production-matrix.json,
                // errors/rest-shapes#two-array-contains); the official emulator answers
                // FAILED_PRECONDITION. Every other limit is INVALID_ARGUMENT.
                if v.iter().all(|x| x.limit_id == "FS-QUERY-LIMIT-ARRAY-CONTAINS-PER-DISJUNCTION") {
                    tonic::Status::invalid_argument(
                        "A maximum of 1 'ARRAY_CONTAINS' filter is allowed per disjunction.",
                    )
                } else {
                    tonic::Status::invalid_argument(message)
                }
            }
            Self::MissingIndex { fragment, description } => tonic::Status::failed_precondition(format!(
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

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_status().message())
    }
}

/// Accepted query plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedQuery {
    /// Canonical query.
    pub query: Query,
    /// Index decision (never `MissingRequired`).
    pub decision: IndexDecision,
    /// Diagnostics such as `FS_ENT_FULL_COLLECTION_SCAN`.
    pub warnings: Vec<String>,
}

/// The Standard query limits the pinned official Firestore emulator refuses as well, as
/// measured by `conformance/src/firestore-probe` (`errors/rest-shapes`): more than 30
/// disjunctions (`'IN' supports up to 30 comparison values.`) and a second `array-contains`
/// clause (`Only a single array-contains clause is allowed in a query`). They are refused
/// whatever `enforce_limits` says, so the `firebase` profile answers what the official
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
    /// Runs every strict check on a decoded query.
    pub fn validate_query(&self, query: &Query) -> Result<AcceptedQuery, Rejection> {
        self.validate_query_with_indexes(query, &self.indexes)
    }

    /// Runs every strict check with a borrowed database-specific index catalog.
    pub fn validate_query_with_indexes(
        &self,
        query: &Query,
        indexes: &IndexSet,
    ) -> Result<AcceptedQuery, Rejection> {
        let canonical = query
            .canonicalize()
            .map_err(|e| Rejection::InvalidQuery(e.to_string()))?;
        let disjunctions = canonical.dnf_disjunction_count();
        if disjunctions > fireemu_core_firestore::query::MAX_MATERIALIZED_DISJUNCTIONS {
            return Err(Rejection::InvalidQuery(format!(
                "query expands to {disjunctions} disjunctions (bound {})",
                fireemu_core_firestore::query::MAX_MATERIALIZED_DISJUNCTIONS
            )));
        }
        let mut warnings = Vec::new();
        if self.ctx.edition == FirestoreEdition::Standard {
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
        let decision = decide(&canonical, indexes, &self.ctx);
        match &decision {
            IndexDecision::UseIndex { .. } | IndexDecision::KindlessScan => {}
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
                });
            }
            IndexDecision::Unsupported { feature } => {
                return Err(Rejection::Unsupported((*feature).to_owned()));
            }
        }
        Ok(AcceptedQuery {
            query: canonical,
            decision,
            warnings,
        })
    }
}

/// Says once per distinct index which composite index production would need for a query
/// the emulator policy served without it (every surface: unary, REST, Listen, aggregations).
fn note_assumed_index(fragment: &str) {
    static NOTED: std::sync::OnceLock<std::sync::Mutex<std::collections::BTreeSet<String>>> =
        std::sync::OnceLock::new();
    let noted = NOTED.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeSet::new()));
    let first = noted
        .lock()
        .map(|mut set| set.insert(fragment.to_owned()))
        .unwrap_or(false);
    if first {
        eprintln!(
            "[firestore] served without a configured composite index (indexValidationPolicy = emulator); production needs: {fragment}"
        );
    }
}
