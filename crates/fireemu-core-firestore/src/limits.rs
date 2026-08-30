//! The Firestore Standard limits this crate enforces, named once.
//!
//! Every call site that can refuse a request over a catalog limit goes through one of these
//! constants, and [`ENFORCED_LIMIT_IDS`] lists them all. The catalog
//! (`spec/limits/firestore-standard-2026-08-25.json`) marks a limit `implemented` when the
//! runtime enforces or observes it, and `unsupported` when it does not; the two are kept
//! from drifting by `tests/enforced_limits.rs`, which fails when an id listed here is not
//! `implemented` in the catalog or when the catalog claims an implementation nothing here
//! enforces. `/v1/limits` and the `FS-LIM-1` capability entry are derived from the catalog,
//! so the same test keeps them honest.

/// `FS-LIMIT-DOCUMENT-BYTES`: the storage-size formula total of a document, checked on
/// every write that produces a document (`INV-LIMIT-001`).
pub const DOCUMENT_BYTES: &str = "FS-LIMIT-DOCUMENT-BYTES";

/// `FS-LIMIT-NESTED-MAP-ARRAY-DEPTH`: the nesting depth of every field value, checked on
/// every write that produces a document.
pub const NESTED_MAP_ARRAY_DEPTH: &str = "FS-LIMIT-NESTED-MAP-ARRAY-DEPTH";

/// `FS-LIMIT-FIELD-TRANSFORMS-PER-DOCUMENT`: the transforms one commit applies to one
/// document, summed over its writes.
pub const FIELD_TRANSFORMS_PER_DOCUMENT: &str = "FS-LIMIT-FIELD-TRANSFORMS-PER-DOCUMENT";

/// `FS-LIMIT-TRANSACTION-TOTAL-TIME`: the lifetime of a transaction on the virtual clock.
pub const TRANSACTION_TOTAL_TIME: &str = "FS-LIMIT-TRANSACTION-TOTAL-TIME";

/// `FS-LIMIT-TRANSACTION-IDLE-TIME`: the idle budget of a transaction on the virtual clock.
pub const TRANSACTION_IDLE_TIME: &str = "FS-LIMIT-TRANSACTION-IDLE-TIME";

/// `FS-LIMIT-COLLECTION-ID`: enforced by `fireemu_core_types::ids::CollectionId`, which
/// every document path in this crate is built from.
pub const COLLECTION_ID: &str = "FS-LIMIT-COLLECTION-ID";

/// `FS-LIMIT-DOCUMENT-ID`: enforced by `fireemu_core_types::ids::DocumentId`, likewise.
pub const DOCUMENT_ID: &str = "FS-LIMIT-DOCUMENT-ID";

/// Every catalog limit the local Firestore runtime enforces.
pub const ENFORCED_LIMIT_IDS: &[&str] = &[
    DOCUMENT_BYTES,
    NESTED_MAP_ARRAY_DEPTH,
    FIELD_TRANSFORMS_PER_DOCUMENT,
    TRANSACTION_TOTAL_TIME,
    TRANSACTION_IDLE_TIME,
    COLLECTION_ID,
    DOCUMENT_ID,
];

/// Every Standard query limit `Query::check_standard_limits` evaluates
/// (`firestore-standard-query-2026-08-25`). The strict profile refuses a violation, the
/// firebase profile observes it as an `FS_LIMIT_OBSERVED` warning -- except the limits the
/// official emulator refuses as well, which the gateway refuses under both
/// (`fireemu_adapter_grpc::gateway::OFFICIAL_EMULATOR_REFUSES`).
pub const ENFORCED_QUERY_LIMIT_IDS: &[&str] = &[
    "FS-QUERY-LIMIT-DNF-DISJUNCTIONS",
    "FS-QUERY-LIMIT-ARRAY-CONTAINS-PER-DISJUNCTION",
    "FS-QUERY-LIMIT-ARRAY-CONTAINS-COMBINATION",
    "FS-QUERY-LIMIT-NOT-IN-VALUES",
    "FS-QUERY-LIMIT-NOT-IN-NEQ-COMBINATION",
    "FS-QUERY-LIMIT-INEQUALITY-FIELDS",
    "FS-QUERY-LIMIT-COMPONENTS",
];
