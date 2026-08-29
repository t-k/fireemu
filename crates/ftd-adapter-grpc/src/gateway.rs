//! Strict gateway checks (Phase FS-0): canonicalize, Standard query limits, index decision.

use core::fmt;

use ftd_core_firestore::index::{decide, IndexDecision, IndexSet, PlanningContext};
use ftd_core_firestore::query::{Query, QueryLimitViolation};
use ftd_core_types::edition::FirestoreEdition;

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
    /// `ftd_core_limits::evaluate::WIRE_MAPPING_REVISION`.
    #[must_use]
    pub fn to_status(&self) -> tonic::Status {
        let mut status = match self {
            Self::Decode(e) => tonic::Status::new(e.grpc_code(), e.to_string()),
            Self::InvalidQuery(m) => tonic::Status::invalid_argument(m.clone()),
            Self::QueryLimits(v) => {
                let lines: Vec<String> = v.iter().map(|x| format!("{}: {} ({} > {})", x.limit_id, x.detail, x.current, x.maximum)).collect();
                tonic::Status::invalid_argument(format!("query limit violation: {}", lines.join("; ")))
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
            status.metadata_mut().insert("ftd-reason", v);
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

/// Strict gateway configuration.
#[derive(Debug, Clone)]
pub struct Gateway {
    /// Planning context (edition, API mode, policy).
    pub ctx: PlanningContext,
    /// Configured indexes.
    pub indexes: IndexSet,
}

impl Gateway {
    /// Runs every strict check on a decoded query.
    pub fn validate_query(&self, query: &Query) -> Result<AcceptedQuery, Rejection> {
        let canonical = query
            .canonicalize()
            .map_err(|e| Rejection::InvalidQuery(e.to_string()))?;
        let disjunctions = canonical.dnf_disjunction_count();
        if disjunctions > ftd_core_firestore::query::MAX_MATERIALIZED_DISJUNCTIONS {
            return Err(Rejection::InvalidQuery(format!(
                "query expands to {disjunctions} disjunctions (bound {})",
                ftd_core_firestore::query::MAX_MATERIALIZED_DISJUNCTIONS
            )));
        }
        if self.ctx.edition == FirestoreEdition::Standard {
            canonical
                .check_standard_limits()
                .map_err(Rejection::QueryLimits)?;
        }
        let decision = decide(&canonical, &self.indexes, &self.ctx);
        let mut warnings = Vec::new();
        match &decision {
            IndexDecision::UseIndex { .. } => {}
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
