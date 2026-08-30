//! Versioned limit definitions (spec 2.6, 8.10.2, 8.10.3).
//!
//! A limit is not a bare number. It carries its official source, unit, inclusive/exclusive
//! boundary, enforcement precision and implementation status so that the runtime, the
//! Capability Manifest and the conformance fixtures all speak about the same thing.

/// What kind of limit this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitClass {
    /// Syntax rules for identifiers (collection IDs, field names, ...).
    IdentifierSyntax,
    /// Hard resource limits enforced per request or per document.
    HardResource,
    /// Budgets consumed while evaluating a request (Rules expressions, document accesses).
    RuntimeBudget,
    /// Time budgets such as transaction lifetime.
    TimeBudget,
    /// Capacity limits that depend on the billing plan.
    PlanCapacity,
    /// Rate limits (requests per minute).
    RateQuota,
    /// Free-tier or billing quotas.
    BillingQuota,
    /// Limits whose exact backend measurement is not observable locally.
    BackendOpaque,
}

/// How precisely the local implementation reproduces the official limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnforcementPrecision {
    /// The local calculation is exact by construction.
    Exact,
    /// The boundary (N-1 / N / N+1) has been fixed by conformance against the official backend.
    BoundaryConformance,
    /// The local value is a proven upper bound; rejections are safe but may be stricter.
    Conservative,
    /// The local value is an estimate; it must never be the sole basis for a hard error.
    Estimated,
    /// Only observable through an official oracle.
    OracleOnly,
    /// The limit does not apply to this deployment.
    NotApplicable,
    /// Not implemented locally.
    Unsupported,
}

/// How the maximum compares with the observed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitBoundary {
    /// `current <= maximum` is allowed.
    InclusiveMaximum,
    /// `current < maximum` is allowed; the maximum itself is rejected.
    ExclusiveMaximum,
    /// The value must equal the maximum exactly.
    Exact,
    /// The value must fall inside an inclusive range.
    RangeInclusive,
    /// A syntax constraint; the maximum, if any, is the UTF-8 byte cap.
    SyntaxConstraint,
    /// Values above the maximum are truncated by the backend (for example indexed field
    /// values), never rejected. Exceeding it yields a critical warning, not a violation.
    TruncatingMaximum,
}

/// Unit in which `maximum` and observed values are expressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitUnit {
    /// Plain count.
    Count,
    /// UTF-8 encoded bytes.
    Utf8Bytes,
    /// Firestore logical (storage-size formula) bytes.
    LogicalBytes,
    /// Raw bytes (wire payload, transfer).
    Bytes,
    /// Kibibytes.
    KiB,
    /// Mebibytes.
    MiB,
    /// The official text says "KB" and the byte boundary is unconfirmed.
    PublishedKilobytes,
    /// Seconds.
    Seconds,
    /// Requests per minute.
    RequestsPerMinute,
    /// Enterprise Read Units.
    ReadUnits,
    /// Enterprise Write Units.
    WriteUnits,
    /// Enterprise Real-time Update Units.
    RealtimeUpdateUnits,
}

/// Where in the request lifecycle the limit is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnforcementStage {
    /// While loading configuration or index definitions.
    ConfigLoad,
    /// On request acceptance, before any state change.
    Request,
    /// During commit validation.
    Commit,
    /// During query planning.
    QueryPlan,
    /// During Rules compilation / activation.
    RulesCompile,
    /// During Rules evaluation.
    RulesRuntime,
    /// In a management API that may not be implemented locally.
    ManagementApi,
    /// Observed and reported only; never rejects.
    Observe,
}

/// Whether the local runtime implements the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImplementationStatus {
    /// Enforced or observed locally.
    Implemented,
    /// Present in the catalog but not enforced locally; shown in the Capability Manifest.
    Unsupported,
    /// Does not apply to a local test daemon.
    NotApplicable,
}

/// The maximum of a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitMaximum {
    /// A fixed value.
    Fixed(u64),
    /// Depends on whether billing is enabled for the project (support overrides apply).
    PlanDependent {
        /// Maximum when billing is disabled.
        billing_disabled: u64,
        /// Maximum when billing is enabled.
        billing_enabled: u64,
    },
    /// No numeric maximum applies (documented as allowlist / support dependent / n/a).
    NotApplicable,
}

/// A single versioned limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitDefinition {
    /// Stable limit ID such as `FS-LIMIT-DOCUMENT-BYTES`.
    pub id: &'static str,
    /// Limit class.
    pub class: LimitClass,
    /// Boundary semantics.
    pub boundary: LimitBoundary,
    /// Unit.
    pub unit: LimitUnit,
    /// Maximum.
    pub maximum: LimitMaximum,
    /// Precision of the local enforcement.
    pub precision: EnforcementPrecision,
    /// Enforcement stage.
    pub enforcement_stage: EnforcementStage,
    /// Implementation status.
    pub implemented: ImplementationStatus,
    /// Quoted official wording.
    pub official_text: &'static str,
    /// Maintainer notes (may be empty).
    pub notes: &'static str,
}

/// Catalog metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitCatalogMeta {
    /// Immutable catalog ID, e.g. `firestore-standard-2026-08-25`.
    pub id: &'static str,
    /// Product (`firestore`, `firebase-rules`).
    pub product: &'static str,
    /// Edition (`standard`, `enterprise`, `all`).
    pub edition: &'static str,
    /// Title of the official document revision.
    pub official_revision: &'static str,
    /// Official document last-updated date (UTC, `YYYY-MM-DD`).
    pub official_last_updated_utc: &'static str,
    /// Date the maintainers reviewed the catalog against the official document.
    pub reviewed_at_utc: &'static str,
    /// Conformance revision the catalog has been verified against.
    pub conformance_revision: &'static str,
}

/// An immutable, versioned limit catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitCatalog {
    /// Metadata.
    pub meta: LimitCatalogMeta,
    /// Limits in the catalog.
    pub limits: &'static [LimitDefinition],
}

impl LimitCatalog {
    /// Finds a limit by ID.
    #[must_use]
    pub fn find(&self, id: &str) -> Option<&'static LimitDefinition> {
        self.limits.iter().find(|l| l.id == id)
    }
}
