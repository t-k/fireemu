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

/// Enforced by every `DocumentPath` constructor.
pub const SUBCOLLECTION_DEPTH: &str = "FS-LIMIT-SUBCOLLECTION-DEPTH";
/// Enforced on the UTF-8 resource name by every `DocumentPath` constructor.
pub const DOCUMENT_NAME_BYTES: &str = "FS-LIMIT-DOCUMENT-NAME-BYTES";
/// Stored field names are validated recursively, including maps inside arrays.
pub const FIELD_NAME: &str = "FS-LIMIT-FIELD-NAME";
/// `FS-LIMIT-FIELD-VALUE-BYTES`: the largest field value, checked on every stored write.
///
/// A string or bytes value is measured on its raw payload, the metric production was observed
/// using on 2026-09-07, and is refused under either profile. A map or array value is measured
/// with the official storage-size formula (the catalog's `logical-bytes` unit) and is refused
/// only under [`crate::store::LimitScope::Production`], because production has not been
/// observed on an aggregate value.
pub const FIELD_VALUE_BYTES: &str = "FS-LIMIT-FIELD-VALUE-BYTES";

/// `FS-LIMIT-FIELD-PATH-BYTES`: the canonical path of every field, whether a client named it
/// or a document implied it by nesting maps.
pub const FIELD_PATH_BYTES: &str = "FS-LIMIT-FIELD-PATH-BYTES";

/// `FS-LIMIT-INDEXED-FIELD-VALUE-BYTES`: the published truncating maximum for indexed
/// values. [`crate::size::indexed_value_size`] retains the full charge for references,
/// matching the saved production long-reference index-entry refusals. This limit alone
/// refuses nothing; the resulting index-entry size may refuse the write.
pub const INDEXED_FIELD_VALUE_BYTES: &str = "FS-LIMIT-INDEXED-FIELD-VALUE-BYTES";

/// `FS-LIMIT-API-REQUEST-BYTES`: the largest API request, applied at each transport's decode
/// boundary by `fireemu_adapter_grpc::serve::API_REQUEST_BYTES`.
pub const API_REQUEST_BYTES: &str = "FS-LIMIT-API-REQUEST-BYTES";

/// Maximum string or bytes field payload, excluding storage accounting overhead
/// ([`FIELD_VALUE_BYTES`]).
pub const MAX_FIELD_PAYLOAD_BYTES: usize = 1_048_487;
/// Most dimensions a stored vector embedding may have (production: `Vectors must be at most
/// 2048 dimensions.`).
pub const MAX_VECTOR_DIMENSIONS: usize = 2048;

/// Per-document automatic and composite entry count, checked before publication.
pub const INDEX_ENTRIES_PER_DOCUMENT: &str = "FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT";
/// Largest single index entry after indexed-value truncation.
pub const INDEX_ENTRY_BYTES: &str = "FS-LIMIT-INDEX-ENTRY-BYTES";
/// Sum of automatic and composite entry sizes.
pub const INDEX_ENTRY_SUM_PER_DOCUMENT: &str = "FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT";

/// Every catalog limit the local Firestore runtime enforces or applies.
///
/// Most entries refuse a request. [`INDEXED_FIELD_VALUE_BYTES`] is a truncating maximum and
/// refuses nothing: it is listed because the runtime applies it, which is what the catalog
/// means by `implemented`.
pub const ENFORCED_LIMIT_IDS: &[&str] = &[
    DOCUMENT_BYTES,
    NESTED_MAP_ARRAY_DEPTH,
    FIELD_TRANSFORMS_PER_DOCUMENT,
    TRANSACTION_TOTAL_TIME,
    TRANSACTION_IDLE_TIME,
    COLLECTION_ID,
    DOCUMENT_ID,
    SUBCOLLECTION_DEPTH,
    DOCUMENT_NAME_BYTES,
    FIELD_NAME,
    FIELD_PATH_BYTES,
    FIELD_VALUE_BYTES,
    INDEXED_FIELD_VALUE_BYTES,
    API_REQUEST_BYTES,
    INDEX_ENTRIES_PER_DOCUMENT,
    INDEX_ENTRY_BYTES,
    INDEX_ENTRY_SUM_PER_DOCUMENT,
    "FS-LIMIT-FIELDS-PER-COMPOSITE-INDEX",
];

/// Every Standard query limit `Query::check_standard_limits` evaluates
/// (`firestore-standard-query-2026-08-25`). The strict profile refuses a violation, the
/// emulator profile observes it as an `FS_LIMIT_OBSERVED` warning -- except the limits the
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
