//! Official Firestore storage-size formulas (spec 8.10.5), as pure checked calculators.
//!
//! ```text
//! string_size(s)        = utf8_byte_len(s) + 1
//! document_name_size    = Σ string_size(segment) + 16
//! document_size         = document_name_size + Σ string_size(field_name) + Σ value_size + 32
//! map_size              = Σ string_size(key) + Σ value_size + 32
//! ```

use core::fmt;
use std::collections::BTreeMap;

use ftd_core_limits::model::EnforcementPrecision;

use crate::path::DocumentPath;
use crate::value::Value;

/// Revision of the size model. Bumped when the official formula or its interpretation changes.
pub const SIZE_MODEL_REVISION: &str = "firestore-storage-size-2026-08-25";

/// Maximum bytes of an indexed value (`FS-LIMIT-INDEXED-FIELD-VALUE-BYTES`); larger values
/// are truncated in the index representation only.
pub const INDEXED_VALUE_TRUNCATION_BYTES: u64 = 1_500;

/// Size calculation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeError {
    /// Checked arithmetic overflowed; the input is rejected rather than approximated.
    Overflow,
}

impl fmt::Display for SizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("size calculation overflow")
    }
}

impl std::error::Error for SizeError {}

/// One contributor to a size figure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SizeContributor {
    /// Field name or path.
    pub name: String,
    /// Bytes attributed to it (name and value).
    pub bytes: u64,
}

/// Size with a breakdown of the largest contributors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SizeBreakdown {
    /// Total logical bytes.
    pub total: u64,
    /// Document name bytes.
    pub name_bytes: u64,
    /// Largest contributors, descending, at most [`MAX_CONTRIBUTORS`].
    pub largest_contributors: Vec<SizeContributor>,
    /// Model revision.
    pub model_revision: &'static str,
    /// Precision.
    pub precision: EnforcementPrecision,
}

/// Number of contributors kept in a breakdown; bounded so that diagnostics for huge documents
/// stay small.
pub const MAX_CONTRIBUTORS: usize = 10;

fn add(a: u64, b: u64) -> Result<u64, SizeError> {
    a.checked_add(b).ok_or(SizeError::Overflow)
}

fn string_size(s: &str) -> Result<u64, SizeError> {
    add(u64::try_from(s.len()).map_err(|_| SizeError::Overflow)?, 1)
}

/// Size of a full resource name (`projects/.../documents/a/b`), counted on the relative
/// segments plus the fixed 16 bytes.
pub fn document_name_size(path: &DocumentPath) -> Result<u64, SizeError> {
    let mut total: u64 = 16;
    for (c, d) in path.pairs() {
        total = add(total, string_size(c.as_str())?)?;
        total = add(total, string_size(d.as_str())?)?;
    }
    Ok(total)
}

/// Size of a resource-name string used as a reference value: same formula, applied to the
/// segments after `documents/`.
fn reference_size(resource_name: &str) -> Result<u64, SizeError> {
    let relative = resource_name
        .split_once("/documents/")
        .map_or(resource_name, |(_, rest)| rest);
    let mut total: u64 = 16;
    for segment in relative.split('/') {
        total = add(total, string_size(segment)?)?;
    }
    Ok(total)
}

/// Size of a field value per the official table.
pub fn field_value_size(value: &Value) -> Result<u64, SizeError> {
    Ok(match value {
        Value::Null | Value::Boolean(_) => 1,
        Value::Integer(_) | Value::Double(_) | Value::Timestamp(_) => 8,
        Value::GeoPoint(_) => 16,
        Value::String(s) => string_size(s)?,
        Value::Bytes(b) => u64::try_from(b.len()).map_err(|_| SizeError::Overflow)?,
        Value::Reference(r) => reference_size(r)?,
        Value::Array(items) => {
            let mut total = 0u64;
            for item in items {
                total = add(total, field_value_size(item)?)?;
            }
            total
        }
        Value::Vector(v) => u64::try_from(v.len())
            .map_err(|_| SizeError::Overflow)?
            .checked_mul(8)
            .ok_or(SizeError::Overflow)?,
        Value::Map(entries) => fields_size(entries)?
            .checked_add(32)
            .ok_or(SizeError::Overflow)?,
    })
}

fn fields_size(entries: &BTreeMap<String, Value>) -> Result<u64, SizeError> {
    let mut total = 0u64;
    for (k, v) in entries {
        total = add(total, string_size(k)?)?;
        total = add(total, field_value_size(v)?)?;
    }
    Ok(total)
}

/// Size of a document: name + fields + 32, with a breakdown of the largest fields.
pub fn document_size(
    path: &DocumentPath,
    fields: &BTreeMap<String, Value>,
) -> Result<SizeBreakdown, SizeError> {
    let name_bytes = document_name_size(path)?;
    let mut total = add(name_bytes, 32)?;
    let mut contributors: Vec<SizeContributor> = Vec::new();
    for (k, v) in fields {
        let bytes = add(string_size(k)?, field_value_size(v)?)?;
        total = add(total, bytes)?;
        // Keep only the top-N contributors; insertion keeps the vector sorted descending.
        let pos = contributors.partition_point(|c| c.bytes >= bytes);
        if pos < MAX_CONTRIBUTORS {
            contributors.insert(
                pos,
                SizeContributor {
                    name: k.clone(),
                    bytes,
                },
            );
            contributors.truncate(MAX_CONTRIBUTORS);
        }
    }
    Ok(SizeBreakdown {
        total,
        name_bytes,
        largest_contributors: contributors,
        model_revision: SIZE_MODEL_REVISION,
        precision: EnforcementPrecision::BoundaryConformance,
    })
}

/// Index entry scope, each with its own formula.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexEntryScope {
    /// Single-field index, collection scope.
    SingleFieldCollection,
    /// Single-field index, collection-group scope.
    SingleFieldCollectionGroup,
    /// Composite index, collection scope.
    CompositeCollection,
    /// Composite index, collection-group scope.
    CompositeCollectionGroup,
}

/// Indexed representation size of a value: the value size, truncated at 1,500 bytes.
pub fn indexed_value_size(value: &Value) -> Result<u64, SizeError> {
    Ok(field_value_size(value)?.min(INDEXED_VALUE_TRUNCATION_BYTES))
}

/// Size of one index entry.
///
/// ```text
/// single_field_collection        = document_name + parent_document_name + field_name + indexed_value + 32
/// single_field_collection_group  = document_name + field_name + indexed_value + 48
/// composite_collection           = document_name + parent_document_name + Σ indexed_values + 32
/// composite_collection_group     = document_name + Σ indexed_values + 32
/// ```
///
/// `parent` is the parent document of `document` (required for collection scope; the root
/// collection has no parent and contributes 0).
pub fn index_entry_size(
    scope: IndexEntryScope,
    document: &DocumentPath,
    parent: Option<&DocumentPath>,
    fields: &[(&str, &Value)],
) -> Result<u64, SizeError> {
    let mut total = document_name_size(document)?;
    let parent_bytes = match parent {
        Some(p) => document_name_size(p)?,
        None => 0,
    };
    match scope {
        IndexEntryScope::SingleFieldCollection => {
            let (name, value) = fields.first().ok_or(SizeError::Overflow)?;
            total = add(total, parent_bytes)?;
            total = add(total, string_size(name)?)?;
            total = add(total, indexed_value_size(value)?)?;
            add(total, 32)
        }
        IndexEntryScope::SingleFieldCollectionGroup => {
            let (name, value) = fields.first().ok_or(SizeError::Overflow)?;
            total = add(total, string_size(name)?)?;
            total = add(total, indexed_value_size(value)?)?;
            add(total, 48)
        }
        IndexEntryScope::CompositeCollection => {
            total = add(total, parent_bytes)?;
            for (_, value) in fields {
                total = add(total, indexed_value_size(value)?)?;
            }
            add(total, 32)
        }
        IndexEntryScope::CompositeCollectionGroup => {
            for (_, value) in fields {
                total = add(total, indexed_value_size(value)?)?;
            }
            add(total, 32)
        }
    }
}
