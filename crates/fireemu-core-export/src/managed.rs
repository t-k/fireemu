//! Production's managed export layout: what `exportDocuments` writes under a Cloud Storage
//! prefix and `importDocuments` reads back (`FS-CONFIG-LIFECYCLE`, recorded 2026-09-24).
//!
//! ```text
//! <prefix>/<name>.overall_export_metadata                 one entry per partition
//! <prefix>/all_namespaces/all_kinds/                      no collectionIds, no namespaceIds
//!     all_namespaces_all_kinds.export_metadata
//!     output-0
//! <prefix>/all_namespaces/kind_<collection>/              one per requested collection id
//!     all_namespaces_kind_<collection>.export_metadata    carries the partition's schema
//!     output-0
//! <prefix>/namespace_<ns>/all_kinds/                      one per requested namespace id
//! ```
//!
//! `<name>` is the prefix's last path segment. Entities are written the way production writes
//! them (application = the project id, a named database in field 23), not the emulator's
//! `dev~` form. Production writes a document's fields in the order it stores them; fireemu
//! stores them by name, so an export fireemu writes is production's layout with its fields in
//! name order. Both are read the same way.

use std::collections::BTreeMap;

use fireemu_core_firestore::value::Value;

use crate::firestore::{
    read_entity, read_entity_database, write_managed_entity, ExportDocument, FirestoreExportError,
    PartitionMetadata,
};
use crate::leveldb::{read_log, write_log};
use crate::wire::{Reader, WireType, Writer};

/// Which documents one partition holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Partition {
    /// Every document of the default namespace.
    AllKinds,
    /// The documents of one collection group.
    Kind(String),
    /// A Datastore namespace; a Firestore database has none, so it is always empty.
    Namespace(String),
}

impl Partition {
    fn directory(&self) -> String {
        match self {
            Self::AllKinds => "all_namespaces/all_kinds".to_owned(),
            Self::Kind(kind) => format!("all_namespaces/kind_{kind}"),
            Self::Namespace(ns) => format!("namespace_{ns}/all_kinds"),
        }
    }

    fn metadata_file(&self) -> String {
        let directory = self.directory();
        format!(
            "{directory}/{}.export_metadata",
            directory.replace('/', "_")
        )
    }

    fn kind_name(&self) -> &str {
        match self {
            Self::Kind(kind) => kind,
            Self::AllKinds | Self::Namespace(_) => "__all__",
        }
    }
}

/// What one managed export writes, relative to its prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedExport {
    /// `(relative object name, bytes)`, in the order they are written.
    pub files: Vec<(String, Vec<u8>)>,
    /// How many documents the export holds.
    pub documents: u64,
    /// How many entity bytes it holds (production's `progressBytes`).
    pub bytes: u64,
}

/// The partitions an export request selects: every collection id it names, every namespace
/// it names, or everything.
#[must_use]
pub fn partitions(collection_ids: &[String], namespace_ids: &[String]) -> Vec<Partition> {
    if !namespace_ids.is_empty() {
        return namespace_ids
            .iter()
            .map(|ns| {
                if ns.is_empty() {
                    Partition::AllKinds
                } else {
                    Partition::Namespace(ns.clone())
                }
            })
            .collect();
    }
    if collection_ids.is_empty() {
        return vec![Partition::AllKinds];
    }
    collection_ids
        .iter()
        .cloned()
        .map(Partition::Kind)
        .collect()
}

fn collection_group(document: &ExportDocument) -> &str {
    document
        .path
        .last()
        .map_or("", |(collection, _)| collection.as_str())
}

/// Production's type code of a value in a partition schema.
fn type_code(value: &Value) -> Option<u8> {
    Some(match value {
        Value::Double(_) => 0,
        Value::Integer(_) => 1,
        Value::Boolean(_) => 2,
        Value::String(_) | Value::Null => 3,
        Value::Timestamp(_) => 4,
        Value::Bytes(_) => 14,
        Value::GeoPoint(_) => 17,
        Value::Reference(_) => 18,
        Value::Map(_) | Value::Vector(_) | Value::Array(_) => return None,
    })
}

#[derive(Default)]
struct PropertySchema {
    repeated: bool,
    codes: Vec<u8>,
    nested: Option<Schema>,
}

#[derive(Default)]
struct Schema {
    properties: Vec<(String, PropertySchema)>,
}

impl Schema {
    fn property(&mut self, name: &str) -> &mut PropertySchema {
        if let Some(at) = self.properties.iter().position(|(n, _)| n == name) {
            return &mut self.properties[at].1;
        }
        self.properties
            .push((name.to_owned(), PropertySchema::default()));
        &mut self.properties.last_mut().expect("just pushed").1
    }

    fn observe(&mut self, fields: &BTreeMap<String, Value>) {
        for (name, value) in fields {
            let property = self.property(name);
            let values: Vec<&Value> = match value {
                Value::Array(items) => {
                    property.repeated = true;
                    items.iter().collect()
                }
                other => vec![other],
            };
            for value in values {
                match value {
                    Value::Map(inner) => property
                        .nested
                        .get_or_insert_with(Schema::default)
                        .observe(inner),
                    other => {
                        if let Some(code) = type_code(other) {
                            if !property.codes.contains(&code) {
                                property.codes.push(code);
                            }
                        }
                    }
                }
            }
        }
    }

    fn write(&self, w: &mut Writer) {
        for (name, property) in &self.properties {
            w.write_message(2, |p| {
                p.write_string(1, name);
                p.write_message(2, |t| {
                    if property.repeated {
                        t.write_varint(1, 1);
                    }
                    if !property.codes.is_empty() {
                        t.write_bytes(2, &property.codes);
                    }
                    if let Some(nested) = &property.nested {
                        t.write_message(3, |n| nested.write(n));
                    }
                });
                p.write_string(3, name);
            });
        }
    }
}

fn partition_metadata(
    name: &str,
    partition: &Partition,
    start_micros: u64,
    end_micros: u64,
    documents: &[&ExportDocument],
    output: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_message(1, |h| {
        h.write_string(1, name);
        h.write_varint(2, start_micros);
        h.write_varint(3, end_micros);
    });
    w.write_message(2, |o| {
        o.write_string(1, partition.kind_name());
        o.write_string(2, "output-0");
        o.write_message(3, |schema| {
            schema.write_string(1, partition.kind_name());
            if let Partition::Kind(_) = partition {
                let mut observed = Schema::default();
                for document in documents {
                    observed.observe(&document.fields);
                }
                observed.write(schema);
            }
        });
        o.write_varint(5, u64::from(checksum(output)));
    });
    w.finish()
}

/// A digest of the output file the partition names. Production's own value is not
/// reproducible; this one is deterministic and zero for an empty output, as production's is.
fn checksum(output: &[u8]) -> u32 {
    if output.is_empty() {
        return 0;
    }
    let mut digest = fireemu_core_types::hash::Sha256::new();
    digest.update(output);
    let bytes = digest.finalize();
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) & 0x7fff_ffff
}

fn overall_entry(partition: &Partition, documents: u64, bytes: u64) -> Vec<u8> {
    let mut entry = Writer::new();
    entry.write_message(1, |e| {
        e.write_message(1, |k| match partition {
            Partition::AllKinds => {
                k.write_varint(1, 2);
                k.write_varint(3, 3);
            }
            Partition::Kind(kind) => {
                k.write_varint(1, 1);
                k.write_string(2, kind);
                k.write_varint(3, 3);
            }
            Partition::Namespace(ns) => {
                k.write_varint(1, 2);
                k.write_varint(3, 2);
                k.write_string(4, ns);
            }
        });
        e.write_string(2, &partition.metadata_file());
        e.write_varint(3, documents);
        e.write_varint(4, bytes);
    });
    entry.finish()
}

/// Writes the export of `documents` (every document of `database`) under a prefix whose last
/// segment is `name`, for the partitions `collection_ids` and `namespace_ids` select.
pub fn write_managed_export(
    name: &str,
    database: &str,
    collection_ids: &[String],
    namespace_ids: &[String],
    (start_micros, end_micros): (u64, u64),
    documents: &[ExportDocument],
) -> Result<ManagedExport, FirestoreExportError> {
    let mut files = Vec::new();
    let mut overall = vec![vec![0x33_u8]];
    let (mut total_documents, mut total_bytes) = (0_u64, 0_u64);
    for partition in partitions(collection_ids, namespace_ids) {
        let selected: Vec<&ExportDocument> = documents
            .iter()
            .filter(|d| match &partition {
                Partition::AllKinds => true,
                Partition::Kind(kind) => collection_group(d) == kind,
                Partition::Namespace(_) => false,
            })
            .collect();
        let records: Vec<Vec<u8>> = selected
            .iter()
            .map(|d| write_managed_entity(d, database))
            .collect::<Result<_, _>>()?;
        let bytes: u64 = records.iter().map(|r| r.len() as u64).sum();
        let output = if records.is_empty() {
            Vec::new()
        } else {
            write_log(&records)
        };
        let count = selected.len() as u64;
        files.push((
            partition.metadata_file(),
            partition_metadata(
                name,
                &partition,
                start_micros,
                end_micros,
                &selected,
                &output,
            ),
        ));
        files.push((format!("{}/output-0", partition.directory()), output));
        overall.push(overall_entry(&partition, count, bytes));
        total_documents += count;
        total_bytes += bytes;
    }
    files.insert(
        0,
        (
            format!("{name}.overall_export_metadata"),
            write_log(&overall),
        ),
    );
    Ok(ManagedExport {
        files,
        documents: total_documents,
        bytes: total_bytes,
    })
}

/// One partition an overall metadata file names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverallEntry {
    /// Which documents it holds.
    pub partition: Partition,
    /// Its metadata file, relative to the prefix.
    pub metadata_file: String,
    /// How many documents it holds.
    pub documents: u64,
    /// How many entity bytes it holds.
    pub bytes: u64,
}

fn shape<T>(message: impl Into<String>) -> Result<T, FirestoreExportError> {
    Err(FirestoreExportError::Shape(message.into()))
}

/// Reads an overall metadata file.
pub fn read_overall(bytes: &[u8]) -> Result<Vec<OverallEntry>, FirestoreExportError> {
    let records = read_log(bytes)?;
    let Some((first, rest)) = records.split_first() else {
        return shape("the overall export metadata is empty");
    };
    if first.as_slice() != [0x33] {
        return shape("the overall export metadata does not start with its prefix record");
    }
    let mut entries = Vec::new();
    for record in rest {
        let mut reader = Reader::new(record);
        while let Some((field, wire)) = reader.field()? {
            if (field, wire) != (1, WireType::Delimited) {
                reader.skip(field, wire)?;
                continue;
            }
            let mut entry = Reader::new(reader.delimited()?);
            let (mut kind_mode, mut kind, mut namespace_mode, mut namespace) = (0, None, 0, None);
            let (mut metadata_file, mut documents, mut bytes) = (String::new(), 0, 0);
            while let Some((f, w)) = entry.field()? {
                match (f, w) {
                    (1, WireType::Delimited) => {
                        let mut key = Reader::new(entry.delimited()?);
                        while let Some((kf, kw)) = key.field()? {
                            match (kf, kw) {
                                (1, WireType::Varint) => kind_mode = key.varint()?,
                                (2, WireType::Delimited) => kind = Some(key.string()?),
                                (3, WireType::Varint) => namespace_mode = key.varint()?,
                                (4, WireType::Delimited) => namespace = Some(key.string()?),
                                _ => key.skip(kf, kw)?,
                            }
                        }
                    }
                    (2, WireType::Delimited) => metadata_file = entry.string()?,
                    (3, WireType::Varint) => documents = entry.varint()?,
                    (4, WireType::Varint) => bytes = entry.varint()?,
                    _ => entry.skip(f, w)?,
                }
            }
            if metadata_file.starts_with('/') || metadata_file.split('/').any(|p| p == "..") {
                return shape(format!(
                    "the overall export metadata names {metadata_file:?}"
                ));
            }
            let partition = match (kind_mode, kind, namespace_mode, namespace) {
                (1, Some(kind), _, _) => Partition::Kind(kind),
                (_, _, 2, Some(ns)) if !ns.is_empty() => Partition::Namespace(ns),
                _ => Partition::AllKinds,
            };
            entries.push(OverallEntry {
                partition,
                metadata_file,
                documents,
                bytes,
            });
        }
    }
    Ok(entries)
}

/// The output files a partition metadata file names, relative to the partition's directory.
pub fn read_partition_outputs(bytes: &[u8]) -> Result<Vec<String>, FirestoreExportError> {
    Ok(PartitionMetadata::parse(bytes)?.output_files)
}

/// One imported document with the database its key named.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportedEntity {
    /// The document.
    pub document: ExportDocument,
    /// The database the export was taken from.
    pub database: String,
}

/// Decodes one output file of a managed export.
pub fn read_managed_output(bytes: &[u8]) -> Result<Vec<ImportedEntity>, FirestoreExportError> {
    let mut out = Vec::new();
    for record in read_log(bytes)? {
        out.push(ImportedEntity {
            document: read_entity(&record)?,
            database: read_entity_database(&record)?,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(path: &[(&str, &str)], fields: &[(&str, Value)]) -> ExportDocument {
        ExportDocument {
            project: "demo".to_owned(),
            path: path
                .iter()
                .map(|(c, d)| ((*c).to_owned(), (*d).to_owned()))
                .collect(),
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        }
    }

    #[test]
    fn an_unfiltered_export_has_production_layout_and_reads_back() {
        let documents = vec![
            document(&[("items", "a")], &[("i", Value::Integer(7))]),
            document(
                &[("items", "a"), ("sub", "x")],
                &[("s", Value::String("x".into()))],
            ),
        ];
        let export = write_managed_export("all", "named-db", &[], &[], (1, 2), &documents).unwrap();
        let names: Vec<&str> = export.files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "all.overall_export_metadata",
                "all_namespaces/all_kinds/all_namespaces_all_kinds.export_metadata",
                "all_namespaces/all_kinds/output-0",
            ]
        );
        assert_eq!(export.documents, 2);
        let overall = read_overall(&export.files[0].1).unwrap();
        assert_eq!(overall.len(), 1);
        assert_eq!(overall[0].partition, Partition::AllKinds);
        assert_eq!(overall[0].bytes, export.bytes);
        // The record payloads, as production counts progressBytes: the output minus headers.
        assert_eq!(export.bytes + 7 * 2, export.files[2].1.len() as u64);
        let entities = read_managed_output(&export.files[2].1).unwrap();
        assert_eq!(entities.len(), 2);
        assert!(entities.iter().all(|e| e.database == "named-db"));
        assert_eq!(entities[0].document, documents[0]);
    }

    #[test]
    fn a_filtered_export_writes_one_kind_partition_per_collection_id() {
        let documents = vec![
            document(&[("items", "a")], &[("i", Value::Integer(7))]),
            document(&[("other", "c")], &[("i", Value::Integer(8))]),
        ];
        let export = write_managed_export(
            "items",
            "(default)",
            &["items".to_owned()],
            &[],
            (1, 2),
            &documents,
        )
        .unwrap();
        let names: Vec<&str> = export.files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "items.overall_export_metadata",
                "all_namespaces/kind_items/all_namespaces_kind_items.export_metadata",
                "all_namespaces/kind_items/output-0",
            ]
        );
        assert_eq!(export.documents, 1);
        let overall = read_overall(&export.files[0].1).unwrap();
        assert_eq!(overall[0].partition, Partition::Kind("items".into()));
        let entities = read_managed_output(&export.files[2].1).unwrap();
        assert_eq!(entities[0].database, "(default)");
    }

    #[test]
    fn a_namespace_export_is_an_empty_partition() {
        let documents = vec![document(&[("items", "a")], &[])];
        let export =
            write_managed_export("ns", "d", &[], &["foo".to_owned()], (1, 2), &documents).unwrap();
        assert_eq!(
            export.files[2],
            ("namespace_foo/all_kinds/output-0".to_owned(), Vec::new())
        );
        assert_eq!(export.documents, 0);
        let overall = read_overall(&export.files[0].1).unwrap();
        assert_eq!(overall[0].partition, Partition::Namespace("foo".into()));
    }
}
