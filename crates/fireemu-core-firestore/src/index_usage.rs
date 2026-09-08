//! Bounded accounting for Standard automatic and composite index entries.

use std::collections::{BTreeMap, BTreeSet};

use crate::field_path::FieldPath;
use crate::index::{IndexFieldMode, IndexQueryScope, IndexSet};
use crate::path::DocumentPath;
use crate::size::{index_entry_size, IndexEntryScope};
use crate::store::{get_field, FirestoreError};
use crate::value::{IndexValue, Value};

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
    fn add(&mut self, bytes: u64, count: u64) -> Result<(), FirestoreError> {
        self.entries = self.entries.saturating_add(count);
        self.total_bytes = self.total_bytes.saturating_add(bytes.saturating_mul(count));
        self.maximum_entry_bytes = self.maximum_entry_bytes.max(bytes);
        for (id, current, maximum) in [
            (
                crate::limits::INDEX_ENTRIES_PER_DOCUMENT,
                self.entries,
                40_000,
            ),
            (
                crate::limits::INDEX_ENTRY_BYTES,
                self.maximum_entry_bytes,
                7_680,
            ),
            (
                crate::limits::INDEX_ENTRY_SUM_PER_DOCUMENT,
                self.total_bytes,
                8_388_608,
            ),
        ] {
            if current > maximum {
                return Err(FirestoreError::InvalidArgument(format!(
                    "{id}: {current} exceeds {maximum}"
                )));
            }
        }
        Ok(())
    }
}

impl IndexSet {
    /// Accounts for every index entry before any document or event is published.
    pub fn document_index_usage(
        &self,
        document: &DocumentPath,
        fields: &BTreeMap<String, Value>,
    ) -> Result<IndexUsage, FirestoreError> {
        let mut usage = IndexUsage::default();
        self.automatic_usage(document, fields, &mut Vec::new(), &mut usage)?;
        let parent = document.parent_document();
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
                    usage.add(entry_size(scope, document, parent.as_ref(), &values)?, 1)?;
                }
            } else {
                usage.add(entry_size(scope, document, parent.as_ref(), &values)?, 1)?;
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
    ) -> Result<(), FirestoreError> {
        let parent = document.parent_document();
        for (name, value) in fields {
            path.push(name.clone());
            let field = FieldPath::from_segments(path.iter().map(String::as_str))
                .map_err(|e| FirestoreError::InvalidArgument(e.to_string()))?;
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
                        )?;
                    }
                } else {
                    usage.add(
                        entry_size(scope, document, parent.as_ref(), &[(&canonical, value)])?,
                        1,
                    )?;
                }
            }
            if let Value::Map(fields) = value {
                self.automatic_usage(document, fields, path, usage)?;
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
    use super::IndexUsage;

    #[test]
    fn every_index_budget_accepts_equality_and_rejects_one_more() {
        let mut count = IndexUsage::default();
        assert!(count.add(1, 40_000).is_ok());
        assert!(count.add(1, 1).is_err());
        assert!(IndexUsage::default().add(7_680, 1).is_ok());
        assert!(IndexUsage::default().add(7_681, 1).is_err());
        let mut sum = IndexUsage::default();
        assert!(sum.add(4_096, 2_048).is_ok());
        assert!(sum.add(1, 1).is_err());
    }
}
