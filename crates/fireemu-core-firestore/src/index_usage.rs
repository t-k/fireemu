//! Bounded accounting for Standard automatic and composite index entries.

use std::collections::{BTreeMap, BTreeSet};

use crate::field_path::{implied_path_too_long_message, FieldPath, FieldPathError};
use crate::index::{IndexFieldMode, IndexQueryScope, IndexSet};
use crate::path::DocumentPath;
use crate::size::{document_name_size, index_entry_size, IndexEntryScope};
use crate::store::{get_field, FirestoreError, LimitScope};
use crate::value::{IndexValue, Value};

/// The RPC a write arrived through. Production charges a delete's transaction differently per
/// route; paths that are not a client write (TTL, internal maintenance) are never charged.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum WriteRoute {
    /// `Commit`, including transactions.
    Commit,
    /// `BatchWrite`, each write applied on its own.
    BatchWrite,
    /// `DeleteDocument`, which REST `DELETE` maps to.
    DeleteDocument,
    /// Anything else; never charged for a delete.
    #[default]
    Internal,
}

/// The create transaction budget (owner decision D1, 2026-09-25). A create is charged its index
/// entries (the published entry sizes) plus its stored bytes. Production's budget is not
/// published; this value is fitted to the one recorded create transition
/// (`writes/limits/index-entry-sum/adjacent`: a 2,000-byte name accepts 7,184 distinct
/// integers, 29,650,337 charged bytes, and refuses 7,185, 29,654,463) and is the midpoint of
/// that interval. Every other recorded create point falls within it.
pub const TRANSACTION_BYTES: u64 = 29_652_400;

/// A delete's charge relative to the create formula, per route (owner decisions A and D2,
/// 2026-09-25), as `numerator / denominator`. Production refuses a delete at a smaller size than
/// it accepts a create, and its answer between the two is nondeterministic. These are fitted
/// so that, for a 1,000-byte name, strict refuses exactly from the smallest size every
/// recording refused on that route (REST DELETE and `BatchWrite` 12,113, Commit 12,112) and
/// accepts everything below. Other name lengths are an extrapolation, recorded as a known
/// estimate in the closure.
const fn delete_charge(route: WriteRoute) -> Option<(u64, u64)> {
    match route {
        WriteRoute::DeleteDocument | WriteRoute::BatchWrite => Some((DELETE_REST_NUM, DELETE_DEN)),
        WriteRoute::Commit => Some((DELETE_COMMIT_NUM, DELETE_DEN)),
        WriteRoute::Internal => None,
    }
}
// The midpoints of the fitted intervals: REST DELETE and BatchWrite (T/25,758,391,
// T/25,756,265], Commit (T/25,756,265, T/25,754,139], where T is `TRANSACTION_BYTES` and the
// divisors are the create charges of 12,113, 12,112 and 12,111 elements under a 1,000-byte name.
const DELETE_DEN: u64 = 1_000_000_000;
const DELETE_REST_NUM: u64 = 1_151_221_899;
const DELETE_COMMIT_NUM: u64 = 1_151_316_928;

/// The largest single-field (collection scope) index entry production accepts, in bytes under
/// the documented entry formula ([`index_entry_size`]). Production refuses the entry with
/// "Index entry is too large." well below the published 7,680 bytes: it accepted 5,529
/// (`writes/limits/index-entry-string-name/2641`) and refused 5,531 (`/2642`), and every other
/// recorded write agrees (FS-DATA-WRITE, 2026-09-23 to 2026-09-27). Strict refuses from the
/// smallest recorded refusal; 5,530 is unobserved.
pub const SINGLE_FIELD_ENTRY_BYTES: u64 = 5_530;

/// The published entry limit, kept for the entry kinds production has no recorded point for
/// (composite and collection-group entries).
pub const DOCUMENTED_ENTRY_BYTES: u64 = 7_680;

const fn entry_limit(scope: IndexEntryScope) -> u64 {
    match scope {
        IndexEntryScope::SingleFieldCollection => SINGLE_FIELD_ENTRY_BYTES,
        IndexEntryScope::SingleFieldCollectionGroup
        | IndexEntryScope::CompositeCollection
        | IndexEntryScope::CompositeCollectionGroup => DOCUMENTED_ENTRY_BYTES,
    }
}

/// Index usage of one document, including automatic and configured composite indexes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IndexUsage {
    /// Number of distinct entries across indexes.
    pub entries: u64,
    /// Sum of entry sizes after indexed-value truncation.
    pub total_bytes: u64,
    /// Largest individual entry.
    pub maximum_entry_bytes: u64,
}

impl IndexUsage {
    /// Counts `count` entries of `bytes` each, where `limit` is the largest entry accepted.
    /// With `enforce`, refuses a document over the production entry limits; the emulator
    /// profile only counts.
    fn add(
        &mut self,
        bytes: u64,
        count: u64,
        limit: u64,
        document: &DocumentPath,
        enforce: bool,
    ) -> Result<(), FirestoreError> {
        self.entries = self.entries.saturating_add(count);
        self.total_bytes = self.total_bytes.saturating_add(bytes.saturating_mul(count));
        self.maximum_entry_bytes = self.maximum_entry_bytes.max(bytes);
        if !enforce {
            return Ok(());
        }
        // FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT
        if self.entries > 40_000 {
            return Err(FirestoreError::InvalidArgument(format!(
                "too many index entries for entity /{}",
                document.relative()
            )));
        }
        // FS-LIMIT-INDEX-ENTRY-BYTES
        if bytes > limit {
            return Err(index_entry_too_large());
        }
        Ok(())
    }

    /// The byte sum is judged only once the whole document is counted: production reports an
    /// entry count over its limit even when the byte sum is also over
    /// (`writes/limits/index-entry-sum/adjacent`, 500-byte name, 20,000 elements).
    fn finish(&self, document_bytes: u64) -> Result<(), FirestoreError> {
        if self.total_bytes.saturating_add(document_bytes) > TRANSACTION_BYTES {
            return Err(transaction_too_big());
        }
        Ok(())
    }
}

fn index_entry_too_large() -> FirestoreError {
    FirestoreError::InvalidArgument("Index entry is too large.".into())
}

fn transaction_too_big() -> FirestoreError {
    FirestoreError::InvalidArgument("Transaction too big. Decrease transaction size.".into())
}

fn stored_bytes(
    document: &DocumentPath,
    fields: &BTreeMap<String, Value>,
) -> Result<u64, FirestoreError> {
    crate::size::document_size(document, fields)
        .map(|size| size.total)
        .map_err(|error| FirestoreError::InvalidArgument(error.to_string()))
}

impl IndexSet {
    /// Accounts for every index entry before any document or event is published, refusing
    /// what production refuses.
    pub fn document_index_usage(
        &self,
        document: &DocumentPath,
        fields: &BTreeMap<String, Value>,
    ) -> Result<IndexUsage, FirestoreError> {
        self.document_index_usage_in(document, fields, LimitScope::Production)
    }

    /// [`Self::document_index_usage`] under a limit scope. The index-entry limits, the name
    /// and indexed-string guards and the create transaction budget are production refusals
    /// the pinned official emulator does not make (measured 2026-09-27), so the emulator
    /// profile only counts them. An implied field path over its limit and an invalid
    /// composite index are refused under both scopes.
    pub fn document_index_usage_in(
        &self,
        document: &DocumentPath,
        fields: &BTreeMap<String, Value>,
        scope: LimitScope,
    ) -> Result<IndexUsage, FirestoreError> {
        let enforce = scope == LimitScope::Production;
        let usage = self.index_usage_of(document, fields, enforce)?;
        if enforce {
            usage.finish(stored_bytes(document, fields)?)?;
        }
        Ok(usage)
    }

    /// Refuses deleting a stored document whose transaction is over its route's budget.
    pub fn delete_transaction_check(
        &self,
        document: &DocumentPath,
        fields: &BTreeMap<String, Value>,
        route: WriteRoute,
    ) -> Result<(), FirestoreError> {
        let Some((numerator, denominator)) = delete_charge(route) else {
            return Ok(());
        };
        let create = self
            .index_usage_of(document, fields, true)?
            .total_bytes
            .saturating_add(stored_bytes(document, fields)?);
        let charged = u128::from(create) * u128::from(numerator) / u128::from(denominator);
        if charged > u128::from(TRANSACTION_BYTES) {
            return Err(transaction_too_big());
        }
        Ok(())
    }

    fn index_usage_of(
        &self,
        document: &DocumentPath,
        fields: &BTreeMap<String, Value>,
        enforce: bool,
    ) -> Result<IndexUsage, FirestoreError> {
        let mut usage = IndexUsage::default();
        let parent = document.parent_document();
        // The saved production corpus accepts a 4,622-byte relative name and rejects
        // 5,000 bytes, even for an empty document. The exact transition is not yet
        // recorded; avoid rejecting the unobserved interval until it is bracketed.
        // document_name_size includes 17 bytes beyond the relative name length.
        let name_bytes = document_name_size(document)
            .map_err(|error| FirestoreError::InvalidArgument(error.to_string()))?;
        if enforce && name_bytes >= 5_017 {
            return Err(index_entry_too_large());
        }
        self.automatic_usage(document, fields, &mut Vec::new(), &mut usage, enforce)?;
        for index in self
            .composites()
            .iter()
            .filter(|index| &index.collection_group == document.collection_id())
        {
            if index.fields.len() > 100
                || index
                    .fields
                    .iter()
                    .filter(|f| f.mode == IndexFieldMode::Contains)
                    .count()
                    > 1
            {
                return Err(FirestoreError::InvalidArgument(
                    "Invalid composite index definition".into(),
                ));
            }
            let name = Value::Reference(document.resource_name());
            let mut values = Vec::new();
            let mut array = None;
            for field in &index.fields {
                let value = if field.path.is_document_name() {
                    Some(&name)
                } else {
                    get_field(fields, &field.path)
                };
                let Some(value) = value else {
                    values.clear();
                    break;
                };
                if field.path.is_document_name() {
                    continue;
                } // Already in the document-name charge.
                if field.mode == IndexFieldMode::Contains {
                    let Value::Array(items) = value else {
                        values.clear();
                        break;
                    };
                    array = Some((values.len(), items));
                }
                values.push(("", value));
            }
            if values.is_empty() {
                continue;
            }
            let scope = match index.query_scope {
                IndexQueryScope::Collection => IndexEntryScope::CompositeCollection,
                IndexQueryScope::CollectionGroup => IndexEntryScope::CompositeCollectionGroup,
            };
            if let Some((position, items)) = array {
                for IndexValue(value) in items.iter().map(IndexValue).collect::<BTreeSet<_>>() {
                    values[position].1 = value;
                    usage.add(
                        entry_size(scope, document, parent.as_ref(), &values)?,
                        1,
                        entry_limit(scope),
                        document,
                        enforce,
                    )?;
                }
            } else {
                usage.add(
                    entry_size(scope, document, parent.as_ref(), &values)?,
                    1,
                    entry_limit(scope),
                    document,
                    enforce,
                )?;
            }
        }
        Ok(usage)
    }

    fn automatic_usage(
        &self,
        document: &DocumentPath,
        fields: &BTreeMap<String, Value>,
        path: &mut Vec<String>,
        usage: &mut IndexUsage,
        enforce: bool,
    ) -> Result<(), FirestoreError> {
        let parent = document.parent_document();
        for (name, value) in fields {
            path.push(name.clone());
            let field =
                FieldPath::from_segments(path.iter().map(String::as_str)).map_err(|error| {
                    let message = if matches!(error, FieldPathError::PathTooLong { .. }) {
                        implied_path_too_long_message(&path.join("."))
                    } else {
                        error.to_string()
                    };
                    FirestoreError::InvalidArgument(message)
                })?;
            let canonical = field.canonical();
            for (scope, mode) in self.single_field_modes(document.collection_id(), &field) {
                let scope = match scope {
                    IndexQueryScope::Collection => IndexEntryScope::SingleFieldCollection,
                    IndexQueryScope::CollectionGroup => IndexEntryScope::SingleFieldCollectionGroup,
                };
                if mode == IndexFieldMode::Contains {
                    let Value::Array(items) = value else {
                        continue;
                    };
                    for IndexValue(item) in items.iter().map(IndexValue).collect::<BTreeSet<_>>() {
                        usage.add(
                            entry_size(scope, document, parent.as_ref(), &[(&canonical, item)])?,
                            // Automatic membership indexes have both document-name
                            // directions. Production accepts 19,999 distinct elements
                            // plus two ordered entries, but rejects 20,000 elements.
                            2,
                            entry_limit(scope),
                            document,
                            enforce,
                        )?;
                    }
                } else {
                    usage.add(
                        entry_size(scope, document, parent.as_ref(), &[(&canonical, value)])?,
                        1,
                        entry_limit(scope),
                        document,
                        enforce,
                    )?;
                }
            }
            if let Value::Map(fields) = value {
                self.automatic_usage(document, fields, path, usage, enforce)?;
            }
            path.pop();
        }
        Ok(())
    }
}

fn entry_size(
    scope: IndexEntryScope,
    document: &DocumentPath,
    parent: Option<&DocumentPath>,
    values: &[(&str, &Value)],
) -> Result<u64, FirestoreError> {
    index_entry_size(scope, document, parent, values)
        .map_err(|e| FirestoreError::InvalidArgument(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{
        entry_limit, IndexUsage, WriteRoute, DOCUMENTED_ENTRY_BYTES, SINGLE_FIELD_ENTRY_BYTES,
    };
    use crate::path::DocumentPath;
    use crate::size::IndexEntryScope;
    use fireemu_core_types::ids::{DatabaseId, ProjectId};

    #[test]
    fn every_index_budget_accepts_equality_and_rejects_one_more() {
        let document = DocumentPath::parse(
            &ProjectId::try_new("demo-app").unwrap(),
            &DatabaseId::default_database(),
            "tasks/a",
        )
        .unwrap();
        let limit = DOCUMENTED_ENTRY_BYTES;
        let mut count = IndexUsage::default();
        assert!(count.add(1, 40_000, limit, &document, true).is_ok());
        assert!(count.add(1, 1, limit, &document, true).is_err());
        for limit in [SINGLE_FIELD_ENTRY_BYTES, DOCUMENTED_ENTRY_BYTES] {
            assert!(IndexUsage::default()
                .add(limit, 1, limit, &document, true)
                .is_ok());
            assert!(matches!(
                IndexUsage::default().add(limit + 1, 1, limit, &document, true),
                Err(crate::store::FirestoreError::InvalidArgument(message))
                    if message == "Index entry is too large."
            ));
        }
        let mut sum = IndexUsage::default();
        assert!(sum.add(4_096, 2_048, limit, &document, true).is_ok());
        assert!(sum.finish(super::TRANSACTION_BYTES - 8_388_608).is_ok());
        assert!(sum.add(1, 1, limit, &document, true).is_ok());
        // Without enforcement the same usage is only counted.
        let mut counted = IndexUsage::default();
        assert!(counted.add(1, 40_001, limit, &document, false).is_ok());
        assert!(counted.add(7_681, 1, limit, &document, false).is_ok());
        assert_eq!(counted.entries, 40_002);
        assert_eq!(counted.maximum_entry_bytes, 7_681);
        assert!(matches!(
            sum.finish(super::TRANSACTION_BYTES - 8_388_608),
            Err(crate::store::FirestoreError::InvalidArgument(message))
                if message == "Transaction too big. Decrease transaction size."
        ));
    }

    #[test]
    fn only_single_field_collection_entries_use_the_recorded_threshold() {
        assert_eq!(SINGLE_FIELD_ENTRY_BYTES, 5_530);
        assert_eq!(DOCUMENTED_ENTRY_BYTES, 7_680);
        assert_eq!(
            entry_limit(IndexEntryScope::SingleFieldCollection),
            SINGLE_FIELD_ENTRY_BYTES
        );
        for scope in [
            IndexEntryScope::SingleFieldCollectionGroup,
            IndexEntryScope::CompositeCollection,
            IndexEntryScope::CompositeCollectionGroup,
        ] {
            assert_eq!(entry_limit(scope), DOCUMENTED_ENTRY_BYTES, "{scope:?}");
        }
    }

    fn root_document(collection_bytes: usize, id_bytes: usize) -> DocumentPath {
        DocumentPath::parse(
            &ProjectId::try_new("demo-app").unwrap(),
            &DatabaseId::default_database(),
            &format!("{}/{}", "c".repeat(collection_bytes), "d".repeat(id_bytes)),
        )
        .unwrap()
    }

    fn integers(count: i64) -> std::collections::BTreeMap<String, crate::value::Value> {
        std::collections::BTreeMap::from([(
            "a".to_owned(),
            crate::value::Value::Array((0..count).map(crate::value::Value::Integer).collect()),
        )])
    }

    fn too_big(result: Result<(), crate::store::FirestoreError>) -> bool {
        matches!(
            result,
            Err(crate::store::FirestoreError::InvalidArgument(message))
                if message == "Transaction too big. Decrease transaction size."
        )
    }

    /// D1 (owner, 2026-09-25): a create's transaction is its index entries plus its stored
    /// bytes, refused above a budget fitted to the recorded create pairs
    /// (`writes/limits/index-entry-sum/adjacent`, recorded twice).
    #[test]
    fn create_transactions_match_every_recorded_create_point() {
        let indexes = crate::index::IndexSet::default();
        let create = |document: &DocumentPath, count: i64| {
            indexes
                .document_index_usage(document, &integers(count))
                .map(|_| ())
        };
        let l2000 = root_document(1_400, 599);
        assert_eq!(l2000.relative().len(), 2_000);
        assert!(create(&l2000, 7_184).is_ok());
        assert!(too_big(create(&l2000, 7_185)));
        let l1000 = root_document(998, 1);
        assert!(create(&l1000, 12_123).is_ok());
        assert!(create(&l1000, 12_124).is_ok());
        let l500 = root_document(498, 1);
        assert!(create(&l500, 19_999).is_ok());
    }

    /// A and D2 (owner, 2026-09-25): a delete is refused only from the smallest size every
    /// recording refused on its route (1,000-byte name: REST DELETE and `BatchWrite` 12,113,
    /// Commit 12,112), with a per-route coefficient on the create formula.
    #[test]
    fn delete_transactions_refuse_from_each_route_s_deterministic_minimum() {
        let indexes = crate::index::IndexSet::default();
        let document = root_document(998, 1);
        let delete = |count: i64, route: WriteRoute| {
            indexes.delete_transaction_check(&document, &integers(count), route)
        };
        for route in [WriteRoute::DeleteDocument, WriteRoute::BatchWrite] {
            assert!(delete(12_112, route).is_ok(), "{route:?}");
            assert!(too_big(delete(12_113, route)), "{route:?}");
        }
        assert!(delete(12_111, WriteRoute::Commit).is_ok());
        assert!(too_big(delete(12_112, WriteRoute::Commit)));
        // Paths that are not a client delete route are never charged.
        assert!(delete(12_113, WriteRoute::Internal).is_ok());
    }

    /// `writes/limits/index-entry-sum/adjacent` (recorded twice): with a 500-byte name, 20,000
    /// distinct array elements are refused for their entry count (2 entries per element plus
    /// 2 for the field is 40,002), even though the byte sum is also large. The count wins.
    #[test]
    fn the_entry_count_is_reported_before_the_byte_sum() {
        let collection = format!("g500b{}", "c".repeat(493));
        let document = DocumentPath::parse(
            &ProjectId::try_new("demo-app").unwrap(),
            &DatabaseId::default_database(),
            &format!("{collection}/d"),
        )
        .unwrap();
        assert_eq!(document.relative().len(), 500);
        let fields = |count: i64| {
            std::collections::BTreeMap::from([(
                "a".to_owned(),
                crate::value::Value::Array((0..count).map(crate::value::Value::Integer).collect()),
            )])
        };
        let refused = crate::index::IndexSet::default()
            .document_index_usage(&document, &fields(20_000))
            .expect_err("40,002 entries exceed 40,000");
        assert!(matches!(
            refused,
            crate::store::FirestoreError::InvalidArgument(message)
                if message == format!("too many index entries for entity /{collection}/d")
        ));
        let mut usage = IndexUsage::default();
        crate::index::IndexSet::default()
            .automatic_usage(
                &document,
                &fields(19_999),
                &mut Vec::new(),
                &mut usage,
                true,
            )
            .expect("19,999 elements stay within the entry count");
        assert_eq!(usage.entries, 40_000);
    }
}
