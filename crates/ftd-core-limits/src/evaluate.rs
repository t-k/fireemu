//! Limit disposition and near-limit warnings (spec 8.10.8, 8.10.10).
//!
//! Order of evaluation: the limit-specific inclusive / exclusive boundary is checked first;
//! only values inside the boundary are classified into warning severities from their usage
//! ratio. Ratios are compared with checked integer arithmetic, never floating point.

use core::fmt;

use crate::model::{EnforcementPrecision, EnforcementStage, LimitBoundary, LimitDefinition};
use crate::plan::FirestorePlanProfile;

/// An observed or maximum amount in the limit's unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LimitAmount(u64);

impl LimitAmount {
    /// Wraps an amount.
    #[must_use]
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    /// Raw value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Warning severity. Ordered so that higher usage never yields a lower severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WarningSeverity {
    /// Usage is approaching the limit.
    Notice,
    /// Usage is near the limit.
    Warning,
    /// Usage is critically close to (or at) the limit.
    Critical,
}

impl WarningSeverity {
    /// Stable machine-readable code.
    #[must_use]
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::Notice => "LIMIT_APPROACHING",
            Self::Warning => "LIMIT_NEAR",
            Self::Critical => "LIMIT_CRITICAL",
        }
    }
}

/// A warning threshold expressed in basis points of the maximum (10,000 = 100%).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WarningThreshold {
    /// Threshold in basis points.
    pub basis_points: u16,
    /// Severity assigned at or above the threshold.
    pub severity: WarningSeverity,
}

/// Default thresholds: 75% notice, 85% warning, 95% critical.
pub const DEFAULT_THRESHOLDS: &[WarningThreshold] = &[
    WarningThreshold {
        basis_points: 7_500,
        severity: WarningSeverity::Notice,
    },
    WarningThreshold {
        basis_points: 8_500,
        severity: WarningSeverity::Warning,
    },
    WarningThreshold {
        basis_points: 9_500,
        severity: WarningSeverity::Critical,
    },
];

/// Location in a source file for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSpan {
    /// File name.
    pub file: String,
    /// 1-based line.
    pub line: u32,
    /// 1-based column.
    pub column: u32,
}

/// Largest contributor to a usage figure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contributor {
    /// Human-readable name (field path, function name, ...).
    pub name: String,
    /// Contribution in the limit's unit.
    pub amount: LimitAmount,
}

/// Machine-readable remediation hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemediationCode {
    /// Reduce the measured usage.
    ReduceUsage,
    /// Split the request, document or ruleset.
    Split,
    /// Enable billing or request a support override.
    UpgradePlan,
    /// No local remediation; consult the official documentation.
    SeeOfficialDocumentation,
}

/// A near-limit warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitWarning {
    /// Limit ID.
    pub limit_id: &'static str,
    /// Severity.
    pub severity: WarningSeverity,
    /// Observed usage.
    pub current: LimitAmount,
    /// Effective maximum.
    pub maximum: LimitAmount,
    /// Usage ratio in micro-units (1,000,000 = 100%), truncated.
    pub ratio_micros: u32,
    /// Precision of the measurement.
    pub precision: EnforcementPrecision,
    /// Optional source location.
    pub source_span: Option<SourceSpan>,
    /// Largest contributors, if known.
    pub largest_contributors: Vec<Contributor>,
    /// Remediation hint.
    pub remediation: RemediationCode,
}

/// A limit violation. The request must be rejected atomically (spec 8.10.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitViolation {
    /// Limit ID.
    pub limit_id: &'static str,
    /// Observed usage.
    pub current: LimitAmount,
    /// Effective maximum.
    pub maximum: LimitAmount,
    /// Boundary that was violated.
    pub boundary: LimitBoundary,
    /// Precision of the measurement.
    pub precision: EnforcementPrecision,
    /// Revision of the wire error mapping used for this violation.
    pub wire_mapping_revision: &'static str,
}

impl fmt::Display for LimitViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} exceeds maximum {} ({:?}, {:?})",
            self.limit_id,
            self.current.value(),
            self.maximum.value(),
            self.boundary,
            self.precision
        )
    }
}

/// Outcome of evaluating a usage figure against a limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitDisposition {
    /// Within limits, no warning.
    Allow,
    /// Within limits, with near-limit warnings.
    AllowWithWarnings(Vec<LimitWarning>),
    /// Boundary violated; reject without any state change.
    Reject(LimitViolation),
    /// Boundary violated on a limit whose enforcement stage is `Observe`: recorded and
    /// reported, never rejected (free quotas in `observe` accounting mode, for example).
    ObservedOverLimit(LimitViolation),
}

/// Revision of the wire error mapping (spec 8.10.10). Bumped when conformance fixtures change
/// the status-code assignment.
pub const WIRE_MAPPING_REVISION: &str = "wire-mapping-2026-08-29-unverified";

/// Whether `current` violates the boundary relative to `maximum`.
#[must_use]
pub const fn violates_boundary(boundary: LimitBoundary, current: u64, maximum: u64) -> bool {
    match boundary {
        // Range limits carry their minimum in the notes; only the maximum is machine-checked.
        LimitBoundary::InclusiveMaximum
        | LimitBoundary::SyntaxConstraint
        | LimitBoundary::RangeInclusive => current > maximum,
        LimitBoundary::ExclusiveMaximum => current >= maximum,
        LimitBoundary::Exact => current != maximum,
        // The backend truncates instead of rejecting; warnings still fire (spec 8.10.4).
        LimitBoundary::TruncatingMaximum => false,
    }
}

/// `current / maximum >= basis_points / 10_000`, computed without overflow or rounding.
#[must_use]
pub fn reaches_threshold(current: u64, maximum: u64, basis_points: u16) -> bool {
    if maximum == 0 {
        // A zero maximum ("not permitted") has no approach zone: zero usage is fully
        // compliant and anything above it is a boundary violation handled before warnings.
        return current > 0;
    }
    u128::from(current) * 10_000 >= u128::from(maximum) * u128::from(basis_points)
}

/// Highest severity reached by `current` against `maximum`, if any.
#[must_use]
pub fn classify_severity(
    current: u64,
    maximum: u64,
    thresholds: &[WarningThreshold],
) -> Option<WarningSeverity> {
    thresholds
        .iter()
        .filter(|t| reaches_threshold(current, maximum, t.basis_points))
        .map(|t| t.severity)
        .max()
}

/// Usage ratio in micro-units, truncated. Saturates at `u32::MAX` for out-of-boundary values.
#[must_use]
pub fn ratio_micros(current: u64, maximum: u64) -> u32 {
    if maximum == 0 {
        return if current == 0 { 0 } else { u32::MAX };
    }
    let micros = u128::from(current) * 1_000_000 / u128::from(maximum);
    u32::try_from(micros).unwrap_or(u32::MAX)
}

/// Evaluates `current` against a limit definition under a plan profile.
#[must_use]
pub fn evaluate(
    def: &LimitDefinition,
    current: u64,
    plan: &FirestorePlanProfile,
    thresholds: &[WarningThreshold],
) -> LimitDisposition {
    let Some(maximum) = plan.resolve_maximum(def) else {
        return LimitDisposition::Allow;
    };
    if violates_boundary(def.boundary, current, maximum) {
        let violation = LimitViolation {
            limit_id: def.id,
            current: LimitAmount(current),
            maximum: LimitAmount(maximum),
            boundary: def.boundary,
            precision: def.precision,
            wire_mapping_revision: WIRE_MAPPING_REVISION,
        };
        // Observe-stage limits (free quotas, drift monitors) never reject a request.
        return if def.enforcement_stage == EnforcementStage::Observe {
            LimitDisposition::ObservedOverLimit(violation)
        } else {
            LimitDisposition::Reject(violation)
        };
    }
    match classify_severity(current, maximum, thresholds) {
        None => LimitDisposition::Allow,
        Some(severity) => LimitDisposition::AllowWithWarnings(vec![LimitWarning {
            limit_id: def.id,
            severity,
            current: LimitAmount(current),
            maximum: LimitAmount(maximum),
            ratio_micros: ratio_micros(current, maximum),
            precision: def.precision,
            source_span: None,
            largest_contributors: Vec::new(),
            remediation: default_remediation(def),
        }]),
    }
}

fn default_remediation(def: &LimitDefinition) -> RemediationCode {
    use crate::model::{LimitClass, LimitMaximum};
    match (def.class, def.maximum) {
        (LimitClass::PlanCapacity, LimitMaximum::PlanDependent { .. }) => {
            RemediationCode::UpgradePlan
        }
        (LimitClass::HardResource | LimitClass::RuntimeBudget, _) => RemediationCode::Split,
        (LimitClass::BackendOpaque, _) => RemediationCode::SeeOfficialDocumentation,
        _ => RemediationCode::ReduceUsage,
    }
}
