//! Bounded accounting for Standard automatic and composite index entries.

use std::collections::{BTreeMap, BTreeSet};

use crate::field_path::{implied_path_too_long_message, FieldPath, FieldPathError};
use crate::index::{IndexDefinition, IndexFieldMode, IndexQueryScope, IndexSet};
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

/// The largest document name size (`document_name_size`, 17 bytes over the relative name)
/// production accepts, even for an empty document: it accepted
/// `writes/limits/empty-document-name/4627` (4,644) and refused `/4628` (4,645) with "Index entry
/// is too large." (FS-DATA-WRITE partial recording, 2026-09-25; owner decision, 2026-09-28).
/// The documented entry formulas do not explain this refusal; the bound is fitted to that pair.
pub const DOCUMENT_NAME_ENTRY_BYTES: u64 = 4_644;

/// The largest entry accepted per entry kind. Only single-field (collection scope) entries have
/// a recorded production refusal. The published 7,680 bytes is not enforced for the others:
/// production's single-field threshold shows that figure does not match its own accounting,
/// and no composite or collection-group refusal is recorded, so strict refuses none.
const fn entry_limit(scope: IndexEntryScope) -> u64 {
    match scope {
        IndexEntryScope::SingleFieldCollection => SINGLE_FIELD_ENTRY_BYTES,
        IndexEntryScope::SingleFieldCollectionGroup
        | IndexEntryScope::CompositeCollection
        | IndexEntryScope::CompositeCollectionGroup => u64::MAX,
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
    crate::size::document_size_bytes(document, fields)
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
        let name_bytes = document_name_size(document)
            .map_err(|error| FirestoreError::InvalidArgument(error.to_string()))?;
        if enforce && name_bytes > DOCUMENT_NAME_ENTRY_BYTES {
            return Err(index_entry_too_large());
        }
        self.automatic_usage(document, fields, &mut Vec::new(), &mut usage, enforce)?;
        // Only this document's collection group can hold entries for it, so only its own
        // definitions are visited, in the order `composites()` lists them.
        for index in self.composites_for(document.collection_id()) {
            composite_usage(
                index,
                document,
                parent.as_ref(),
                fields,
                &mut usage,
                enforce,
            )?;
        }
        Ok(usage)
    }

    /// The accounting on main before composites were grouped: every definition in the catalog
    /// is visited and filtered by collection group. Kept only to check the grouped selection.
    #[cfg(test)]
    fn index_usage_of_reference(
        &self,
        document: &DocumentPath,
        fields: &BTreeMap<String, Value>,
        enforce: bool,
    ) -> Result<IndexUsage, FirestoreError> {
        let mut usage = IndexUsage::default();
        let parent = document.parent_document();
        let name_bytes = document_name_size(document)
            .map_err(|error| FirestoreError::InvalidArgument(error.to_string()))?;
        if enforce && name_bytes > DOCUMENT_NAME_ENTRY_BYTES {
            return Err(index_entry_too_large());
        }
        self.automatic_usage(document, fields, &mut Vec::new(), &mut usage, enforce)?;
        for index in self
            .composites()
            .iter()
            .inspect(|_| COMPOSITE_VISITS.with(|visits| visits.set(visits.get() + 1)))
            .filter(|index| &index.collection_group == document.collection_id())
        {
            composite_usage(
                index,
                document,
                parent.as_ref(),
                fields,
                &mut usage,
                enforce,
            )?;
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

/// Charges one composite definition's entries for a document of its collection group,
/// refusing an invalid definition before anything is charged for it.
fn composite_usage(
    index: &IndexDefinition,
    document: &DocumentPath,
    parent: Option<&DocumentPath>,
    fields: &BTreeMap<String, Value>,
    usage: &mut IndexUsage,
    enforce: bool,
) -> Result<(), FirestoreError> {
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
        return Ok(());
    }
    let scope = match index.query_scope {
        IndexQueryScope::Collection => IndexEntryScope::CompositeCollection,
        IndexQueryScope::CollectionGroup => IndexEntryScope::CompositeCollectionGroup,
    };
    if let Some((position, items)) = array {
        for IndexValue(value) in items.iter().map(IndexValue).collect::<BTreeSet<_>>() {
            values[position].1 = value;
            usage.add(
                entry_size(scope, document, parent, &values)?,
                1,
                entry_limit(scope),
                document,
                enforce,
            )?;
        }
    } else {
        usage.add(
            entry_size(scope, document, parent, &values)?,
            1,
            entry_limit(scope),
            document,
            enforce,
        )?;
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// Composite definitions the reference (main's) selection scanned.
    static COMPOSITE_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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
    use super::{entry_limit, IndexUsage, WriteRoute, SINGLE_FIELD_ENTRY_BYTES};
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
        let limit = SINGLE_FIELD_ENTRY_BYTES;
        let mut count = IndexUsage::default();
        assert!(count.add(1, 40_000, limit, &document, true).is_ok());
        assert!(count.add(1, 1, limit, &document, true).is_err());
        assert!(IndexUsage::default()
            .add(limit, 1, limit, &document, true)
            .is_ok());
        assert!(matches!(
            IndexUsage::default().add(limit + 1, 1, limit, &document, true),
            Err(crate::store::FirestoreError::InvalidArgument(message))
                if message == "Index entry is too large."
        ));
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
    fn only_single_field_collection_entries_have_a_size_limit() {
        assert_eq!(SINGLE_FIELD_ENTRY_BYTES, 5_530);
        assert_eq!(
            entry_limit(IndexEntryScope::SingleFieldCollection),
            SINGLE_FIELD_ENTRY_BYTES
        );
        for scope in [
            IndexEntryScope::SingleFieldCollectionGroup,
            IndexEntryScope::CompositeCollection,
            IndexEntryScope::CompositeCollectionGroup,
        ] {
            assert_eq!(entry_limit(scope), u64::MAX, "{scope:?}");
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

#[cfg(test)]
mod composite_grouping_tests {
    use super::COMPOSITE_VISITS;
    use crate::field_path::FieldPath;
    use crate::index::COMPOSITES_EXAMINED;
    use crate::index::{IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet};
    use crate::path::DocumentPath;
    use crate::value::Value;
    use fireemu_core_types::ids::{CollectionId, DatabaseId, ProjectId};
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    /// Groups with composites; `g4` never has any.
    const GROUPS: [&str; 5] = ["g0", "g1", "g2", "g3", "g4"];
    const PATHS: [&str; 5] = ["a", "b", "c", "m.x", "__name__"];

    fn path(index: usize) -> FieldPath {
        if PATHS[index] == "__name__" {
            FieldPath::document_name()
        } else {
            FieldPath::parse(PATHS[index]).unwrap()
        }
    }

    fn document(relative: &str) -> DocumentPath {
        DocumentPath::parse(
            &ProjectId::try_new("demo-app").unwrap(),
            &DatabaseId::default_database(),
            relative,
        )
        .unwrap()
    }

    fn mode(code: u8) -> IndexFieldMode {
        match code % 3 {
            0 => IndexFieldMode::Ascending,
            1 => IndexFieldMode::Descending,
            _ => IndexFieldMode::Contains,
        }
    }

    /// A composite: group (0..4), collection-group scope, `(path, mode)` fields, and whether it
    /// is padded past the 100-field limit.
    type CompositeSpec = (usize, bool, Vec<(usize, u8)>, bool);

    fn definition((group, group_scope, fields, oversized): &CompositeSpec) -> IndexDefinition {
        let mut fields: Vec<IndexField> = fields
            .iter()
            .map(|&(p, m)| IndexField {
                path: path(p),
                mode: mode(m),
            })
            .collect();
        if *oversized {
            while fields.len() <= 100 {
                fields.push(IndexField {
                    path: path(0),
                    mode: IndexFieldMode::Ascending,
                });
            }
        }
        IndexDefinition {
            collection_group: CollectionId::try_new(GROUPS[*group]).unwrap(),
            query_scope: if *group_scope {
                IndexQueryScope::CollectionGroup
            } else {
                IndexQueryScope::Collection
            },
            fields,
        }
    }

    fn value(code: u8, seed: i64) -> Value {
        match code % 5 {
            0 => Value::Integer(seed),
            1 => Value::String(format!("s{seed}")),
            2 => Value::Array((0..(seed.rem_euclid(4))).map(Value::Integer).collect()),
            3 => Value::Array(vec![Value::Integer(seed), Value::Integer(seed)]),
            _ => Value::Map(BTreeMap::from([("x".to_owned(), Value::Integer(seed))])),
        }
    }

    fn composite_strategy() -> impl Strategy<Value = CompositeSpec> {
        (
            0usize..4,
            any::<bool>(),
            proptest::collection::vec((0usize..PATHS.len(), any::<u8>()), 1..5),
            proptest::bool::weighted(0.05),
        )
    }

    fn build(specs: &[CompositeSpec], removals: &[usize]) -> IndexSet {
        let mut indexes = IndexSet::default();
        let definitions: Vec<_> = specs.iter().map(definition).collect();
        for definition in &definitions {
            indexes.add_composite(definition.clone());
        }
        for &removal in removals {
            if !definitions.is_empty() {
                indexes.remove_composite(&definitions[removal % definitions.len()]);
            }
        }
        indexes
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn grouped_accounting_matches_the_full_scan_for_every_catalog(
            specs in proptest::collection::vec(composite_strategy(), 0..24),
            removals in proptest::collection::vec(any::<usize>(), 0..4),
            group in 0usize..GROUPS.len(),
            nested in any::<bool>(),
            values in proptest::collection::vec((any::<bool>(), any::<u8>(), -3i64..4), 4),
        ) {
            let indexes = build(&specs, &removals);
            // The grouped selection lists exactly the filtered definitions, in list order.
            for name in GROUPS {
                let collection = CollectionId::try_new(name).unwrap();
                let grouped: Vec<_> = indexes.composites_for(&collection).collect();
                let scanned: Vec<_> = indexes
                    .composites()
                    .iter()
                    .filter(|index| index.collection_group == collection)
                    .collect();
                prop_assert_eq!(grouped, scanned);
            }
            let relative = if nested {
                format!("p/1/{}/d", GROUPS[group])
            } else {
                format!("{}/d", GROUPS[group])
            };
            let document = document(&relative);
            let fields: BTreeMap<String, Value> = ["a", "b", "c", "m"]
                .iter()
                .zip(&values)
                .filter(|(_, (present, _, _))| *present)
                .map(|(name, &(_, code, seed))| {
                    let value = if *name == "m" {
                        value(4, seed)
                    } else {
                        value(code, seed)
                    };
                    ((*name).to_owned(), value)
                })
                .collect();
            for enforce in [true, false] {
                prop_assert_eq!(
                    indexes.index_usage_of(&document, &fields, enforce),
                    indexes.index_usage_of_reference(&document, &fields, enforce),
                    "enforce={}", enforce
                );
            }
        }
    }

    fn ordered(group: &str, field: &str) -> IndexDefinition {
        IndexDefinition {
            collection_group: CollectionId::try_new(group).unwrap(),
            query_scope: IndexQueryScope::Collection,
            fields: vec![
                IndexField {
                    path: FieldPath::parse(field).unwrap(),
                    mode: IndexFieldMode::Ascending,
                },
                IndexField {
                    path: FieldPath::parse("b").unwrap(),
                    mode: IndexFieldMode::Descending,
                },
            ],
        }
    }

    #[test]
    fn the_required_cases_match_the_full_scan() {
        let fields = BTreeMap::from([
            ("a".to_owned(), Value::Integer(1)),
            ("b".to_owned(), Value::Array(vec![Value::Integer(2)])),
        ]);
        let mut indexes = IndexSet::default();
        indexes.add_composite(ordered("g0", "a"));
        let mut refused = ordered("g1", "b");
        refused.fields[0].mode = IndexFieldMode::Contains;
        refused.fields[1].mode = IndexFieldMode::Contains;
        indexes.add_composite(refused);
        indexes.add_composite(ordered("g1", "a"));
        // A group without composites only has automatic entries.
        let lone = document("g4/d");
        let usage = indexes.index_usage_of(&lone, &fields, true);
        assert_eq!(
            usage,
            indexes.index_usage_of_reference(&lone, &fields, true)
        );
        assert_eq!(
            usage,
            IndexSet::default().index_usage_of(&lone, &fields, true)
        );
        // The refused definition is still refused, before the valid one after it is charged.
        let doomed = document("g1/d");
        let refusal = indexes.index_usage_of(&doomed, &fields, true);
        assert_eq!(
            refusal,
            Err(crate::store::FirestoreError::InvalidArgument(
                "Invalid composite index definition".into()
            ))
        );
        assert_eq!(
            refusal,
            indexes.index_usage_of_reference(&doomed, &fields, true)
        );
        // A group whose only definition is valid is charged for it.
        let served = document("g0/d");
        let usage = indexes.index_usage_of(&served, &fields, true).unwrap();
        assert_eq!(
            Ok(usage),
            indexes.index_usage_of_reference(&served, &fields, true)
        );
        assert!(
            usage.entries
                > IndexSet::default()
                    .index_usage_of(&served, &fields, true)
                    .unwrap()
                    .entries
        );
    }

    /// 1,000 composites over 100 collection groups, ten in each.
    fn wide_catalog() -> IndexSet {
        let mut indexes = IndexSet::default();
        for i in 0..1_000 {
            indexes.add_composite(ordered(&format!("g{}", i % 100), &format!("f{}", i / 100)));
        }
        indexes
    }

    fn wide_fields() -> BTreeMap<String, Value> {
        let mut fields: BTreeMap<_, _> = (0..10)
            .map(|i| (format!("f{i}"), Value::Integer(i)))
            .collect();
        fields.insert("b".to_owned(), Value::Integer(7));
        fields
    }

    #[test]
    fn accounting_visits_only_its_own_group_s_composites() {
        let indexes = wide_catalog();
        let fields = wide_fields();
        for group in [0, 42, 99] {
            let document = document(&format!("g{group}/d"));
            COMPOSITE_VISITS.with(|visits| visits.set(0));
            let before = indexes.index_usage_of_reference(&document, &fields, true);
            let before_visits = COMPOSITE_VISITS.with(std::cell::Cell::get);
            COMPOSITES_EXAMINED.with(|visits| visits.set(0));
            let after = indexes.index_usage_of(&document, &fields, true);
            let after_visits = COMPOSITES_EXAMINED.with(std::cell::Cell::get);
            println!(
                "g{group}: composite definitions visited per document: before (main) \
                 {before_visits}, after {after_visits}"
            );
            assert_eq!(after, before);
            assert_eq!(before_visits, 1_000);
            assert_eq!(after_visits, 10);
        }
        // A group without composites visits none.
        COMPOSITES_EXAMINED.with(|visits| visits.set(0));
        indexes
            .index_usage_of(&document("none/d"), &fields, true)
            .unwrap();
        assert_eq!(COMPOSITES_EXAMINED.with(std::cell::Cell::get), 0);
    }

    /// Times 10,000 accounting calls against 1,000 composites, before and after. Run with
    /// `cargo test --release -p fireemu-core-firestore -- --ignored --nocapture composite_accounting_timing`.
    #[test]
    #[ignore = "timing measurement, not a check"]
    fn composite_accounting_timing() {
        let indexes = wide_catalog();
        let fields = wide_fields();
        let documents: Vec<_> = (0..100).map(|g| document(&format!("g{g}/d"))).collect();
        let time = |grouped: bool| {
            let start = std::time::Instant::now();
            for i in 0..10_000 {
                let document = &documents[i % documents.len()];
                let usage = if grouped {
                    indexes.index_usage_of(document, &fields, true)
                } else {
                    indexes.index_usage_of_reference(document, &fields, true)
                };
                std::hint::black_box(usage.unwrap());
            }
            start.elapsed()
        };
        let before = time(false);
        let after = time(true);
        println!("10,000 accounting calls, 1,000 composites: before {before:?}, after {after:?}");
    }
}
