//! The Firestore managed-export format: `*.overall_export_metadata`, the per-partition
//! `*.export_metadata` and the `output-*` entity files.
//!
//! The Firestore emulator does not write this format from the CLI; the CLI asks the emulator
//! jar for it over `POST /emulator/v1/projects/{project}:export`, and the jar writes the same
//! managed-export layout Google Cloud produces:
//!
//! ```text
//! firestore_export/
//!   firestore_export.overall_export_metadata        LevelDB log, one entry per partition
//!   all_namespaces/all_kinds/
//!     all_namespaces_all_kinds.export_metadata      a bare proto naming the output files
//!     output-0                                      LevelDB log, one EntityProto per record
//! ```
//!
//! The entities are `apphosting.datastore.v3.EntityProto`, the legacy Datastore schema, not
//! `google.firestore.v1.Document`: a Firestore document becomes an entity whose key path
//! alternates collection id and document id, whose fields become properties, and whose value
//! types are carried by the proto2 *meaning* numbers. The mapping below is the one the pinned
//! emulator jar (`cloud-firestore-emulator-v1.22.0`) writes, recorded from real exports in
//! `crates/fireemu/tests/fixtures/export/`:
//!
//! | Firestore value | meaning | `PropertyValue` |
//! | --- | --- | --- |
//! | null | none | empty |
//! | boolean | none | `booleanValue` |
//! | integer | none | `int64Value` (two's complement) |
//! | double | none | `doubleValue` (exact bits, so NaN and -0.0 survive) |
//! | string | none | `stringValue` |
//! | bytes | 14 (`BLOB`) | `stringValue` |
//! | timestamp | 7 (`GD_WHEN`) | `int64Value`, microseconds since the epoch |
//! | geo point | 9 (`GEORSS_POINT`) | `PointValue` group (`x` = latitude, `y` = longitude) |
//! | reference | none | `ReferenceValue` group |
//! | map | 19 (`ENTITY_PROTO`) | `stringValue` holding a nested `EntityProto` |
//! | array | as the element | one property per element with `multiple = true` |
//! | empty array | 24 (`EMPTY_LIST`) | absent, and written as an *indexed* property |
//!
//! A vector embedding has no Datastore encoding; it travels as the map Firestore itself uses
//! on the wire, `{"__type__": "__vector__", "value": [doubles]}`, and is recognized again on
//! import.

use std::collections::BTreeMap;

use fireemu_core_firestore::value::{GeoPoint, Timestamp, Value};

use crate::leveldb::{for_each_record, read_log, write_log, LogError, LogWriter};
use crate::wire::{Reader, WireError, WireType, Writer};

/// The partition every emulator export writes: all namespaces, all kinds.
pub const PARTITION_DIR: &str = "all_namespaces/all_kinds";
/// The partition metadata file name.
pub const PARTITION_METADATA: &str = "all_namespaces_all_kinds.export_metadata";
/// The single output file name the emulator writes.
pub const OUTPUT_FILE: &str = "output-0";
/// The export name recorded inside the partition metadata.
pub const EXPORT_NAME: &str = "firestore_export";

/// The application id prefix the Firestore emulator gives a project.
const APP_PREFIX: &str = "dev~";

// EntityProto field numbers.
const ENTITY_KEY: u32 = 13;
const ENTITY_PROPERTY: u32 = 14;
const ENTITY_RAW_PROPERTY: u32 = 15;
const ENTITY_GROUP: u32 = 16;

// Reference field numbers.
const REFERENCE_APP: u32 = 13;
const REFERENCE_PATH: u32 = 14;
const REFERENCE_NAMESPACE: u32 = 20;

// Path element group and its members.
const PATH_ELEMENT: u32 = 1;
const ELEMENT_TYPE: u32 = 2;
const ELEMENT_ID: u32 = 3;
const ELEMENT_NAME: u32 = 4;

// Property field numbers.
const PROPERTY_MEANING: u32 = 1;
const PROPERTY_NAME: u32 = 3;
const PROPERTY_MULTIPLE: u32 = 4;
const PROPERTY_VALUE: u32 = 5;

// PropertyValue field numbers.
const VALUE_INT64: u32 = 1;
const VALUE_BOOLEAN: u32 = 2;
const VALUE_STRING: u32 = 3;
const VALUE_DOUBLE: u32 = 4;
const VALUE_POINT: u32 = 5;
const VALUE_REFERENCE: u32 = 12;
const POINT_X: u32 = 6;
const POINT_Y: u32 = 7;
const REFERENCE_VALUE_APP: u32 = 13;
const REFERENCE_VALUE_ELEMENT: u32 = 14;
const REFERENCE_VALUE_NAMESPACE: u32 = 20;
const REFERENCE_ELEMENT_TYPE: u32 = 15;
const REFERENCE_ELEMENT_ID: u32 = 16;
const REFERENCE_ELEMENT_NAME: u32 = 17;

// Meanings.
const MEANING_GD_WHEN: u64 = 7;
const MEANING_GEORSS_POINT: u64 = 9;
const MEANING_BLOB: u64 = 14;
const MEANING_ENTITY_PROTO: u64 = 19;
const MEANING_EMPTY_LIST: u64 = 24;

/// One document of a Firestore export.
#[derive(Debug, Clone, PartialEq)]
pub struct ExportDocument {
    /// The project the entity's application id names.
    pub project: String,
    /// The alternating collection / document identifiers of the document path.
    pub path: Vec<(String, String)>,
    /// The document's fields.
    pub fields: BTreeMap<String, Value>,
}

impl ExportDocument {
    /// The document path relative to `documents/`, as `cities/SF/landmarks/golden-gate`.
    #[must_use]
    pub fn relative_path(&self) -> String {
        let mut out = String::new();
        for (collection, document) in &self.path {
            if !out.is_empty() {
                out.push('/');
            }
            out.push_str(collection);
            out.push('/');
            out.push_str(document);
        }
        out
    }
}

/// Why an export could not be read or written.
#[derive(Debug, Clone, PartialEq)]
pub enum FirestoreExportError {
    /// A log file is malformed.
    Log(LogError),
    /// An entity is malformed.
    Wire(WireError),
    /// The entity does not describe a Firestore document.
    Shape(String),
}

impl core::fmt::Display for FirestoreExportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Log(e) => write!(f, "{e}"),
            Self::Wire(e) => write!(f, "{e}"),
            Self::Shape(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for FirestoreExportError {}

impl From<LogError> for FirestoreExportError {
    fn from(e: LogError) -> Self {
        Self::Log(e)
    }
}

impl From<WireError> for FirestoreExportError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

fn shape<T>(message: impl Into<String>) -> Result<T, FirestoreExportError> {
    Err(FirestoreExportError::Shape(message.into()))
}

/// The `*.overall_export_metadata` entry describing one partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverallMetadata {
    /// The partition metadata file, relative to the section directory.
    pub metadata_file: String,
    /// How many entities the partition holds.
    pub entity_count: u64,
    /// How many bytes the partition's output files hold.
    pub byte_count: u64,
}

/// The single byte the emulator writes as the first record of every overall metadata file.
const OVERALL_PREFIX_RECORD: u8 = 0x33;

impl OverallMetadata {
    /// Encodes the file, `LevelDB` framing included.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut entry = Writer::new();
        entry.write_message(1, |e| {
            // The constant marker the jar writes ahead of every entry.
            e.write_message(1, |k| {
                k.write_varint(1, 2);
                k.write_varint(3, 3);
            });
            e.write_string(2, &self.metadata_file);
            e.write_varint(3, self.entity_count);
            e.write_varint(4, self.byte_count);
        });
        write_log(&[vec![OVERALL_PREFIX_RECORD], entry.finish()])
    }

    /// Decodes the file.
    pub fn parse(bytes: &[u8]) -> Result<Self, FirestoreExportError> {
        let records = read_log(bytes)?;
        let entry = records.iter().find(|r| r.len() > 1).ok_or_else(|| {
            FirestoreExportError::Shape(
                "the overall export metadata holds no partition entry".to_owned(),
            )
        })?;
        let mut reader = Reader::new(entry);
        let mut found = None;
        while let Some((field, wire)) = reader.field()? {
            if field == 1 && wire == WireType::Delimited {
                found = Some(parse_overall_entry(reader.delimited()?)?);
            } else {
                reader.skip(field, wire)?;
            }
        }
        found.ok_or_else(|| {
            FirestoreExportError::Shape(
                "the overall export metadata entry names no partition metadata file".to_owned(),
            )
        })
    }
}

fn parse_overall_entry(bytes: &[u8]) -> Result<OverallMetadata, FirestoreExportError> {
    let mut reader = Reader::new(bytes);
    let mut metadata_file = None;
    let mut entity_count = 0;
    let mut byte_count = 0;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (2, WireType::Delimited) => metadata_file = Some(reader.string()?),
            (3, WireType::Varint) => entity_count = reader.varint()?,
            (4, WireType::Varint) => byte_count = reader.varint()?,
            _ => reader.skip(field, wire)?,
        }
    }
    let metadata_file = metadata_file.ok_or_else(|| {
        FirestoreExportError::Shape(
            "the overall export metadata entry names no partition metadata file".to_owned(),
        )
    })?;
    if metadata_file.starts_with('/') || metadata_file.split('/').any(|p| p == "..") {
        return shape(format!(
            "the overall export metadata names the partition file {metadata_file:?}, which is not inside the export directory"
        ));
    }
    Ok(OverallMetadata {
        metadata_file,
        entity_count,
        byte_count,
    })
}

/// The per-partition `*.export_metadata` file: the export name, its time window and the
/// output files the partition was written to. Unlike the overall file it is a bare proto,
/// with no `LevelDB` framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionMetadata {
    /// The export name (`firestore_export`).
    pub export_name: String,
    /// When the export started, in microseconds since the epoch.
    pub start_micros: u64,
    /// When the export finished, in microseconds since the epoch.
    pub end_micros: u64,
    /// The output files, relative to the partition directory.
    pub output_files: Vec<String>,
}

/// Output files one partition may name (a bound on what an import reads).
pub const MAX_OUTPUT_FILES: usize = 10_000;

impl PartitionMetadata {
    /// Encodes the file.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_message(1, |h| {
            h.write_string(1, &self.export_name);
            h.write_varint(2, self.start_micros);
            h.write_varint(3, self.end_micros);
        });
        w.write_message(2, |o| {
            // An empty entity filter: all namespaces, all kinds.
            o.write_bytes(1, &[]);
            for file in &self.output_files {
                o.write_string(2, file);
            }
        });
        w.finish()
    }

    /// Decodes the file.
    pub fn parse(bytes: &[u8]) -> Result<Self, FirestoreExportError> {
        let mut reader = Reader::new(bytes);
        let mut export_name = String::new();
        let mut start_micros = 0;
        let mut end_micros = 0;
        let mut output_files = Vec::new();
        while let Some((field, wire)) = reader.field()? {
            match (field, wire) {
                (1, WireType::Delimited) => {
                    let mut header = Reader::new(reader.delimited()?);
                    while let Some((f, w)) = header.field()? {
                        match (f, w) {
                            (1, WireType::Delimited) => export_name = header.string()?,
                            (2, WireType::Varint) => start_micros = header.varint()?,
                            (3, WireType::Varint) => end_micros = header.varint()?,
                            _ => header.skip(f, w)?,
                        }
                    }
                }
                (2, WireType::Delimited) => {
                    let mut outputs = Reader::new(reader.delimited()?);
                    while let Some((f, w)) = outputs.field()? {
                        if (f, w) == (2, WireType::Delimited) {
                            let name = outputs.string()?;
                            if name.starts_with('/') || name.split('/').any(|p| p == "..") {
                                return shape(format!(
                                    "the partition metadata names the output file {name:?}, which is not inside the export directory"
                                ));
                            }
                            if output_files.contains(&name) {
                                return shape(format!(
                                    "the partition metadata names the output file {name:?} twice"
                                ));
                            }
                            if output_files.len() >= MAX_OUTPUT_FILES {
                                return shape(format!(
                                    "the partition metadata names more than {MAX_OUTPUT_FILES} output files"
                                ));
                            }
                            output_files.push(name);
                        } else {
                            outputs.skip(f, w)?;
                        }
                    }
                }
                _ => reader.skip(field, wire)?,
            }
        }
        if output_files.is_empty() {
            return shape("the partition metadata names no output file");
        }
        Ok(Self {
            export_name,
            start_micros,
            end_micros,
            output_files,
        })
    }
}

/// Decodes every document of one `output-*` file.
pub fn read_output(bytes: &[u8]) -> Result<Vec<ExportDocument>, FirestoreExportError> {
    read_output_from(std::io::Cursor::new(bytes))
}

/// Decodes documents incrementally from an `output-*` reader.
pub fn read_output_from(
    input: impl std::io::Read,
) -> Result<Vec<ExportDocument>, FirestoreExportError> {
    let mut documents = Vec::new();
    let visited = for_each_record(input, |record| {
        documents.push(read_entity(record)?);
        Ok::<(), FirestoreExportError>(())
    })?;
    visited?;
    Ok(documents)
}

/// Encodes an `output-*` file holding `documents`, in the given order.
pub fn write_output(documents: &[ExportDocument]) -> Result<Vec<u8>, FirestoreExportError> {
    let mut output = Vec::new();
    write_output_to(documents, &mut output)?;
    Ok(output)
}

/// Encodes documents incrementally into an `output-*` writer and returns its byte count.
pub fn write_output_to(
    documents: &[ExportDocument],
    output: impl std::io::Write,
) -> Result<u64, FirestoreExportError> {
    let mut writer = LogWriter::new(output);
    for document in documents {
        writer.push(&write_entity(document)?)?;
    }
    Ok(writer.finish().1)
}

/// Encodes one document as an `EntityProto` record.
pub fn write_entity(document: &ExportDocument) -> Result<Vec<u8>, FirestoreExportError> {
    if document
        .fields
        .values()
        .any(|value| value.nesting_depth() as usize > MAX_VALUE_DEPTH)
    {
        return shape(format!(
            "an exported value is nested more than {MAX_VALUE_DEPTH} levels deep, which no Firestore document can be"
        ));
    }
    let mut w = Writer::new();
    w.write_message(ENTITY_KEY, |key| {
        key.write_string(REFERENCE_APP, &format!("{APP_PREFIX}{}", document.project));
        key.write_message(REFERENCE_PATH, |path| write_path(path, &document.path));
    });
    // Only an empty list is written as an indexed property, exactly as the jar does.
    for (name, value) in &document.fields {
        if matches!(value, Value::Array(items) if items.is_empty()) {
            w.write_message(ENTITY_PROPERTY, |p| {
                p.write_varint(PROPERTY_MEANING, MEANING_EMPTY_LIST);
                p.write_string(PROPERTY_NAME, name);
                p.write_bool(PROPERTY_MULTIPLE, false);
                p.write_bytes(PROPERTY_VALUE, &[]);
            });
        }
    }
    for (name, value) in &document.fields {
        match value {
            Value::Array(items) if items.is_empty() => {}
            Value::Array(items) => {
                for item in items {
                    write_property(&mut w, ENTITY_RAW_PROPERTY, name, item, true);
                }
            }
            other => write_property(&mut w, ENTITY_RAW_PROPERTY, name, other, false),
        }
    }
    w.write_message(ENTITY_GROUP, |group| {
        write_path(group, &document.path[..document.path.len().min(1)]);
    });
    Ok(w.finish())
}

fn write_path(w: &mut Writer, path: &[(String, String)]) {
    for (collection, document) in path {
        w.write_group(PATH_ELEMENT, |e| {
            e.write_string(ELEMENT_TYPE, collection);
            e.write_string(ELEMENT_NAME, document);
        });
    }
}

fn write_property(w: &mut Writer, field: u32, name: &str, value: &Value, multiple: bool) {
    w.write_message(field, |p| {
        if let Some(meaning) = meaning_of(value) {
            p.write_varint(PROPERTY_MEANING, meaning);
        }
        p.write_string(PROPERTY_NAME, name);
        p.write_bool(PROPERTY_MULTIPLE, multiple);
        p.write_message(PROPERTY_VALUE, |v| write_value(v, value));
    });
}

fn meaning_of(value: &Value) -> Option<u64> {
    match value {
        Value::Timestamp(_) => Some(MEANING_GD_WHEN),
        Value::GeoPoint(_) => Some(MEANING_GEORSS_POINT),
        Value::Bytes(_) => Some(MEANING_BLOB),
        Value::Map(_) | Value::Vector(_) => Some(MEANING_ENTITY_PROTO),
        Value::Array(items) if items.is_empty() => Some(MEANING_EMPTY_LIST),
        _ => None,
    }
}

fn write_value(w: &mut Writer, value: &Value) {
    match value {
        // Null is an empty `PropertyValue`; an array is never reached, because
        // `write_entity` has already unrolled it into one property per element.
        Value::Null | Value::Array(_) => {}
        Value::Boolean(b) => w.write_bool(VALUE_BOOLEAN, *b),
        Value::Integer(i) => w.write_int64(VALUE_INT64, *i),
        Value::Double(d) => w.write_double(VALUE_DOUBLE, *d),
        Value::String(s) => w.write_string(VALUE_STRING, s),
        Value::Bytes(b) => w.write_bytes(VALUE_STRING, b),
        Value::Timestamp(t) => w.write_int64(VALUE_INT64, micros_of(*t)),
        Value::GeoPoint(g) => w.write_group(VALUE_POINT, |p| {
            p.write_double(POINT_X, g.latitude());
            p.write_double(POINT_Y, g.longitude());
        }),
        Value::Reference(name) => w.write_group(VALUE_REFERENCE, |r| {
            let (project, path) = split_reference(name);
            r.write_string(REFERENCE_VALUE_APP, &format!("{APP_PREFIX}{project}"));
            for (collection, document) in path {
                r.write_group(REFERENCE_VALUE_ELEMENT, |e| {
                    e.write_string(REFERENCE_ELEMENT_TYPE, &collection);
                    e.write_string(REFERENCE_ELEMENT_NAME, &document);
                });
            }
        }),
        Value::Map(fields) => w.write_bytes(VALUE_STRING, &write_nested_entity(fields)),
        Value::Vector(values) => {
            let mut fields = BTreeMap::new();
            fields.insert(
                "__type__".to_owned(),
                Value::String("__vector__".to_owned()),
            );
            fields.insert(
                "value".to_owned(),
                Value::Array(values.iter().map(|v| Value::Double(*v)).collect()),
            );
            w.write_bytes(VALUE_STRING, &write_nested_entity(&fields));
        }
    }
}

/// A map value is a nested `EntityProto` with an empty key and an empty entity group.
fn write_nested_entity(fields: &BTreeMap<String, Value>) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_message(ENTITY_KEY, |key| {
        key.write_string(REFERENCE_APP, "");
        key.write_bytes(REFERENCE_PATH, &[]);
    });
    for (name, value) in fields {
        if matches!(value, Value::Array(items) if items.is_empty()) {
            w.write_message(ENTITY_PROPERTY, |p| {
                p.write_varint(PROPERTY_MEANING, MEANING_EMPTY_LIST);
                p.write_string(PROPERTY_NAME, name);
                p.write_bool(PROPERTY_MULTIPLE, false);
                p.write_bytes(PROPERTY_VALUE, &[]);
            });
        }
    }
    for (name, value) in fields {
        match value {
            Value::Array(items) if items.is_empty() => {}
            Value::Array(items) => {
                for item in items {
                    write_property(&mut w, ENTITY_RAW_PROPERTY, name, item, true);
                }
            }
            other => write_property(&mut w, ENTITY_RAW_PROPERTY, name, other, false),
        }
    }
    w.write_bytes(ENTITY_GROUP, &[]);
    w.finish()
}

fn micros_of(t: Timestamp) -> i64 {
    t.seconds()
        .saturating_mul(1_000_000)
        .saturating_add(i64::from(t.nanos() / 1_000))
}

/// Splits `projects/p/databases/(default)/documents/a/b` into the project and the path.
fn split_reference(name: &str) -> (String, Vec<(String, String)>) {
    let mut segments = name.split('/');
    let mut project = String::new();
    if segments.next() == Some("projects") {
        segments.next().unwrap_or_default().clone_into(&mut project);
        // databases/{db}/documents
        let _ = segments.next();
        let _ = segments.next();
        let _ = segments.next();
    }
    let rest: Vec<&str> = segments.collect();
    let mut path = Vec::new();
    for pair in rest.chunks(2) {
        if pair.len() == 2 {
            path.push((pair[0].to_owned(), pair[1].to_owned()));
        }
    }
    (project, path)
}

/// Decodes one `EntityProto` record into a document.
pub fn read_entity(bytes: &[u8]) -> Result<ExportDocument, FirestoreExportError> {
    let mut reader = Reader::new(bytes);
    let mut project = String::new();
    let mut path = Vec::new();
    let mut properties: Vec<(String, bool, Option<Value>)> = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (ENTITY_KEY, WireType::Delimited) => {
                let (app, elements) = read_reference(reader.delimited()?)?;
                app.strip_prefix(APP_PREFIX)
                    .unwrap_or(&app)
                    .clone_into(&mut project);
                path = elements;
            }
            (ENTITY_PROPERTY | ENTITY_RAW_PROPERTY, WireType::Delimited) => {
                properties.push(read_property(reader.delimited()?, 0)?);
            }
            _ => reader.skip(field, wire)?,
        }
    }
    if path.is_empty() {
        return shape("an exported entity has no document path");
    }
    Ok(ExportDocument {
        project,
        path,
        fields: collect_fields(properties),
    })
}

/// Rebuilds the field map from the flat property list: repeated properties with
/// `multiple = true` become one array, and an `EMPTY_LIST` property becomes an empty one.
fn collect_fields(properties: Vec<(String, bool, Option<Value>)>) -> BTreeMap<String, Value> {
    let mut fields: BTreeMap<String, Value> = BTreeMap::new();
    for (name, multiple, value) in properties {
        match value {
            None => {
                fields.insert(name, Value::Array(Vec::new()));
            }
            Some(value) if multiple => match fields.get_mut(&name) {
                Some(Value::Array(items)) => items.push(value),
                _ => {
                    fields.insert(name, Value::Array(vec![value]));
                }
            },
            Some(value) => {
                fields.insert(name, value);
            }
        }
    }
    fields
}

/// Reads a `Reference`, returning its application id and alternating path.
fn read_reference(bytes: &[u8]) -> Result<(String, Vec<(String, String)>), FirestoreExportError> {
    let mut reader = Reader::new(bytes);
    let mut app = String::new();
    let mut path = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (REFERENCE_APP, WireType::Delimited) => app = reader.string()?,
            (REFERENCE_NAMESPACE, WireType::Delimited) => {
                let namespace = reader.string()?;
                if !namespace.is_empty() {
                    return shape(format!(
                        "the exported entity is in the Datastore namespace {namespace:?}; Firestore documents carry none"
                    ));
                }
            }
            (REFERENCE_PATH, WireType::Delimited) => path = read_path(reader.delimited()?)?,
            _ => reader.skip(field, wire)?,
        }
    }
    Ok((app, path))
}

fn read_path(bytes: &[u8]) -> Result<Vec<(String, String)>, FirestoreExportError> {
    let mut reader = Reader::new(bytes);
    let mut path = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        if (field, wire) == (PATH_ELEMENT, WireType::StartGroup) {
            let body = reader.group(PATH_ELEMENT)?;
            path.push(read_element(body, ELEMENT_TYPE, ELEMENT_ID, ELEMENT_NAME)?);
        } else {
            reader.skip(field, wire)?;
        }
    }
    Ok(path)
}

fn read_element(
    bytes: &[u8],
    type_field: u32,
    id_field: u32,
    name_field: u32,
) -> Result<(String, String), FirestoreExportError> {
    let mut reader = Reader::new(bytes);
    let mut collection = String::new();
    let mut document: Option<String> = None;
    while let Some((field, wire)) = reader.field()? {
        if field == type_field && wire == WireType::Delimited {
            collection = reader.string()?;
        } else if field == name_field && wire == WireType::Delimited {
            document = Some(reader.string()?);
        } else if field == id_field && wire == WireType::Varint {
            // A production Datastore export can carry numeric ids; Firestore document ids
            // are strings, so the decimal spelling is used.
            document = Some(reader.varint()?.to_string());
        } else {
            reader.skip(field, wire)?;
        }
    }
    match document {
        Some(document) if !collection.is_empty() => Ok((collection, document)),
        _ => shape("an exported key path element names no collection and document"),
    }
}

/// Nesting a decoded value may reach: Firestore allows maps and arrays 20 deep, and a
/// deeper artifact is not one the emulator wrote. The bound keeps a crafted output file from
/// recursing the decoder off the stack.
pub const MAX_VALUE_DEPTH: usize = 20;

/// Reads a `Property`, returning its name, whether it is an array element, and its value
/// (`None` for the empty-list marker). `depth` counts the nested entities above it.
fn read_property(
    bytes: &[u8],
    depth: usize,
) -> Result<(String, bool, Option<Value>), FirestoreExportError> {
    let mut reader = Reader::new(bytes);
    let mut meaning = 0u64;
    let mut name = String::new();
    let mut multiple = false;
    let mut raw: Option<&[u8]> = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (PROPERTY_MEANING, WireType::Varint) => meaning = reader.varint()?,
            (PROPERTY_NAME, WireType::Delimited) => name = reader.string()?,
            (PROPERTY_MULTIPLE, WireType::Varint) => multiple = reader.varint()? != 0,
            (PROPERTY_VALUE, WireType::Delimited) => raw = Some(reader.delimited()?),
            _ => reader.skip(field, wire)?,
        }
    }
    if name.is_empty() {
        return shape("an exported property has no name");
    }
    if meaning == MEANING_EMPTY_LIST {
        return Ok((name, false, None));
    }
    let value = read_value(raw.unwrap_or(&[]), meaning, depth)?;
    Ok((name, multiple, Some(value)))
}

fn read_value(bytes: &[u8], meaning: u64, depth: usize) -> Result<Value, FirestoreExportError> {
    let mut reader = Reader::new(bytes);
    let mut value: Option<Value> = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (VALUE_INT64, WireType::Varint) => {
                // The wrap is the decoding: proto2 stores a negative `int64` as the varint
                // of its unsigned two's complement.
                #[allow(clippy::cast_possible_wrap)]
                let raw = reader.varint()? as i64;
                value = Some(if meaning == MEANING_GD_WHEN {
                    Value::Timestamp(timestamp_from_micros(raw)?)
                } else {
                    Value::Integer(raw)
                });
            }
            (VALUE_BOOLEAN, WireType::Varint) => {
                value = Some(Value::Boolean(reader.varint()? != 0));
            }
            (VALUE_DOUBLE, WireType::Fixed64) => {
                value = Some(Value::Double(f64::from_bits(reader.fixed64()?)));
            }
            (VALUE_STRING, WireType::Delimited) => {
                let raw = reader.delimited()?;
                value = Some(match meaning {
                    MEANING_BLOB => Value::Bytes(raw.to_vec()),
                    MEANING_ENTITY_PROTO => nested_value(raw, depth + 1)?,
                    _ => Value::String(String::from_utf8(raw.to_vec()).map_err(|_| {
                        FirestoreExportError::Shape(
                            "an exported string property is not UTF-8".to_owned(),
                        )
                    })?),
                });
            }
            (VALUE_POINT, WireType::StartGroup) => {
                let body = reader.group(VALUE_POINT)?;
                value = Some(Value::GeoPoint(read_point(body)?));
            }
            (VALUE_REFERENCE, WireType::StartGroup) => {
                let body = reader.group(VALUE_REFERENCE)?;
                value = Some(Value::Reference(read_reference_value(body)?));
            }
            _ => reader.skip(field, wire)?,
        }
    }
    Ok(value.unwrap_or(Value::Null))
}

fn timestamp_from_micros(micros: i64) -> Result<Timestamp, FirestoreExportError> {
    let seconds = micros.div_euclid(1_000_000);
    let nanos = u32::try_from(micros.rem_euclid(1_000_000)).unwrap_or(0) * 1_000;
    Timestamp::new(seconds, nanos).map_err(|_| {
        FirestoreExportError::Shape(format!(
            "an exported timestamp of {micros} microseconds is outside the supported range"
        ))
    })
}

fn read_point(bytes: &[u8]) -> Result<GeoPoint, FirestoreExportError> {
    let mut reader = Reader::new(bytes);
    let mut x = 0.0;
    let mut y = 0.0;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (POINT_X, WireType::Fixed64) => x = f64::from_bits(reader.fixed64()?),
            (POINT_Y, WireType::Fixed64) => y = f64::from_bits(reader.fixed64()?),
            _ => reader.skip(field, wire)?,
        }
    }
    GeoPoint::new(x, y).map_err(|_| {
        FirestoreExportError::Shape(format!(
            "an exported geo point at ({x}, {y}) is outside the valid range"
        ))
    })
}

fn read_reference_value(bytes: &[u8]) -> Result<String, FirestoreExportError> {
    let mut reader = Reader::new(bytes);
    let mut app = String::new();
    let mut path = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (REFERENCE_VALUE_APP, WireType::Delimited) => app = reader.string()?,
            (REFERENCE_VALUE_NAMESPACE, WireType::Delimited) => {
                reader.string()?;
            }
            (REFERENCE_VALUE_ELEMENT, WireType::StartGroup) => {
                let body = reader.group(REFERENCE_VALUE_ELEMENT)?;
                path.push(read_element(
                    body,
                    REFERENCE_ELEMENT_TYPE,
                    REFERENCE_ELEMENT_ID,
                    REFERENCE_ELEMENT_NAME,
                )?);
            }
            _ => reader.skip(field, wire)?,
        }
    }
    let project = app.strip_prefix(APP_PREFIX).unwrap_or(&app);
    let mut name = format!("projects/{project}/databases/(default)/documents");
    for (collection, document) in path {
        name.push('/');
        name.push_str(&collection);
        name.push('/');
        name.push_str(&document);
    }
    Ok(name)
}

/// A nested `EntityProto` carrying a map value (or a vector embedding).
fn nested_value(bytes: &[u8], depth: usize) -> Result<Value, FirestoreExportError> {
    if depth > MAX_VALUE_DEPTH {
        return shape(format!(
            "an exported value is nested more than {MAX_VALUE_DEPTH} levels deep, which no Firestore document can be"
        ));
    }
    let mut reader = Reader::new(bytes);
    let mut properties = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (ENTITY_PROPERTY | ENTITY_RAW_PROPERTY, WireType::Delimited) => {
                properties.push(read_property(reader.delimited()?, depth)?);
            }
            _ => reader.skip(field, wire)?,
        }
    }
    let fields = collect_fields(properties);
    if let Some(vector) = as_vector(&fields) {
        return Ok(vector);
    }
    Ok(Value::Map(fields))
}

/// Recognizes the wire form of a vector embedding.
fn as_vector(fields: &BTreeMap<String, Value>) -> Option<Value> {
    if fields.len() != 2 || fields.get("__type__") != Some(&Value::String("__vector__".to_owned()))
    {
        return None;
    }
    let Some(Value::Array(items)) = fields.get("value") else {
        return None;
    };
    let mut values = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::Double(d) => values.push(*d),
            // A vector component written as a whole number; the widening is what the
            // Firestore wire form does with it too.
            #[allow(clippy::cast_precision_loss)]
            Value::Integer(i) => values.push(*i as f64),
            _ => return None,
        }
    }
    Some(Value::Vector(values))
}

#[cfg(test)]
mod tests {
    use super::{
        read_entity, read_output, read_output_from, write_entity, write_output, write_output_to,
        ExportDocument, OverallMetadata, PartitionMetadata, Value,
    };
    use fireemu_core_firestore::value::{GeoPoint, Timestamp};
    use std::collections::BTreeMap;

    fn document(fields: BTreeMap<String, Value>) -> ExportDocument {
        ExportDocument {
            project: "demo-export".to_owned(),
            path: vec![("cities".to_owned(), "SF".to_owned())],
            fields,
        }
    }

    fn field(name: &str, value: Value) -> BTreeMap<String, Value> {
        let mut map = BTreeMap::new();
        map.insert(name.to_owned(), value);
        map
    }

    fn round_trip(value: Value) -> Value {
        let doc = document(field("f", value));
        let encoded = write_entity(&doc).expect("the entity encodes");
        let decoded = read_entity(&encoded).expect("the entity decodes");
        assert_eq!(decoded.project, "demo-export");
        assert_eq!(decoded.path, doc.path);
        decoded
            .fields
            .get("f")
            .cloned()
            .expect("the field survives")
    }

    #[test]
    fn every_scalar_value_round_trips_through_the_entity_encoding() {
        assert_eq!(round_trip(Value::Null), Value::Null);
        assert_eq!(round_trip(Value::Boolean(true)), Value::Boolean(true));
        assert_eq!(round_trip(Value::Boolean(false)), Value::Boolean(false));
        assert_eq!(round_trip(Value::Integer(0)), Value::Integer(0));
        assert_eq!(
            round_trip(Value::Integer(-9_007_199_254_740_991)),
            Value::Integer(-9_007_199_254_740_991)
        );
        assert_eq!(
            round_trip(Value::Integer(i64::MIN)),
            Value::Integer(i64::MIN)
        );
        assert_eq!(
            round_trip(Value::String(String::new())),
            Value::String(String::new())
        );
        assert_eq!(
            round_trip(Value::String("こんにちは".to_owned())),
            Value::String("こんにちは".to_owned())
        );
        assert_eq!(
            round_trip(Value::Bytes(Vec::new())),
            Value::Bytes(Vec::new())
        );
        assert_eq!(
            round_trip(Value::Bytes(vec![0, 1, 2, 253, 254, 255])),
            Value::Bytes(vec![0, 1, 2, 253, 254, 255])
        );
    }

    #[test]
    fn a_double_keeps_its_exact_bits_including_nan_and_negative_zero() {
        for bits in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.0, 7272.5] {
            let Value::Double(back) = round_trip(Value::Double(bits)) else {
                panic!("a double stays a double");
            };
            assert_eq!(back.to_bits(), bits.to_bits());
        }
    }

    #[test]
    fn a_timestamp_round_trips_at_microsecond_resolution() {
        let t = Timestamp::new(1_700_000_000, 123_456_000).expect("a valid timestamp");
        assert_eq!(round_trip(Value::Timestamp(t)), Value::Timestamp(t));
        let epoch = Timestamp::new(0, 0).expect("a valid timestamp");
        assert_eq!(round_trip(Value::Timestamp(epoch)), Value::Timestamp(epoch));
        let before = Timestamp::new(-1, 500_000_000).expect("a valid timestamp");
        assert_eq!(
            round_trip(Value::Timestamp(before)),
            Value::Timestamp(before)
        );
    }

    #[test]
    fn a_geo_point_round_trips() {
        let g = GeoPoint::new(37.7749, -122.4194).expect("a valid point");
        assert_eq!(round_trip(Value::GeoPoint(g)), Value::GeoPoint(g));
    }

    #[test]
    fn a_reference_round_trips_as_a_full_resource_name() {
        let name = "projects/demo-export/databases/(default)/documents/cities/LA".to_owned();
        assert_eq!(
            round_trip(Value::Reference(name.clone())),
            Value::Reference(name)
        );
    }

    #[test]
    fn arrays_maps_and_their_empty_forms_round_trip() {
        assert_eq!(
            round_trip(Value::Array(Vec::new())),
            Value::Array(Vec::new())
        );
        assert_eq!(
            round_trip(Value::Map(BTreeMap::new())),
            Value::Map(BTreeMap::new())
        );
        let array = Value::Array(vec![
            Value::Integer(1),
            Value::String("two".to_owned()),
            Value::Boolean(true),
        ]);
        assert_eq!(round_trip(array.clone()), array);
        let mut inner = BTreeMap::new();
        inner.insert("c".to_owned(), Value::String("deep".to_owned()));
        inner.insert("d".to_owned(), array);
        let mut outer = BTreeMap::new();
        outer.insert("a".to_owned(), Value::Integer(1));
        outer.insert("b".to_owned(), Value::Map(inner));
        let map = Value::Map(outer);
        assert_eq!(round_trip(map.clone()), map);
    }

    #[test]
    fn a_vector_embedding_round_trips_through_its_wire_map_form() {
        let vector = Value::Vector(vec![1.0, -2.5, 0.0]);
        assert_eq!(round_trip(vector.clone()), vector);
    }

    #[test]
    fn a_document_with_no_fields_round_trips() {
        let doc = document(BTreeMap::new());
        let encoded = write_entity(&doc).expect("the entity encodes");
        let decoded = read_entity(&encoded).expect("the entity decodes");
        assert_eq!(decoded, doc);
    }

    #[test]
    fn a_deep_subcollection_path_round_trips() {
        let doc = ExportDocument {
            project: "demo-edge".to_owned(),
            path: vec![
                ("edge".to_owned(), "deep".to_owned()),
                ("a".to_owned(), "1".to_owned()),
                ("b".to_owned(), "2".to_owned()),
                ("c".to_owned(), "3".to_owned()),
            ],
            fields: field("leaf", Value::Boolean(true)),
        };
        let encoded = write_entity(&doc).expect("the entity encodes");
        assert_eq!(read_entity(&encoded).expect("decodes"), doc);
    }

    #[test]
    fn an_output_file_round_trips_every_document_in_order() {
        let docs: Vec<ExportDocument> = (0..40)
            .map(|i| ExportDocument {
                project: "demo-export".to_owned(),
                path: vec![("bulk".to_owned(), format!("doc-{i:03}"))],
                fields: field("i", Value::Integer(i)),
            })
            .collect();
        let bytes = write_output(&docs).expect("the output encodes");
        assert_eq!(read_output(&bytes).expect("the output decodes"), docs);
    }

    #[test]
    fn streamed_output_is_byte_identical_and_reads_across_short_chunks() {
        let docs = vec![
            document(field("small", Value::Integer(1))),
            document(field("large", Value::String("x".repeat(70_000)))),
            document(field("tail", Value::Boolean(true))),
        ];
        let expected = write_output(&docs).expect("legacy wrapper encodes");
        let mut streamed = Vec::new();

        let byte_count = write_output_to(&docs, &mut streamed).expect("streamed output encodes");

        assert_eq!(byte_count, streamed.len() as u64);
        assert_eq!(streamed, expected);
        let short_reads = std::io::BufReader::with_capacity(7, std::io::Cursor::new(&streamed));
        assert_eq!(
            read_output_from(short_reads).expect("short streamed reads decode"),
            docs
        );
    }

    #[test]
    fn an_entity_without_a_key_path_is_refused() {
        let doc = ExportDocument {
            project: "demo".to_owned(),
            path: Vec::new(),
            fields: BTreeMap::new(),
        };
        let bytes = write_entity(&doc).expect("the entity encodes");
        assert!(read_entity(&bytes).is_err());
    }

    #[test]
    fn a_truncated_entity_is_refused() {
        let doc = document(field("f", Value::String("x".repeat(40))));
        let mut bytes = write_entity(&doc).expect("the entity encodes");
        bytes.truncate(bytes.len() - 5);
        assert!(read_entity(&bytes).is_err());
    }

    #[test]
    fn the_overall_metadata_round_trips_and_starts_with_the_official_prefix_record() {
        let metadata = OverallMetadata {
            metadata_file: "all_namespaces/all_kinds/all_namespaces_all_kinds.export_metadata"
                .to_owned(),
            entity_count: 30,
            byte_count: 3236,
        };
        let bytes = metadata.to_bytes();
        assert_eq!(
            &bytes[..8],
            &[0xb8, 0x6d, 0x44, 0x4e, 0x01, 0x00, 0x01, 0x33]
        );
        assert_eq!(OverallMetadata::parse(&bytes).expect("it parses"), metadata);
    }

    #[test]
    fn the_partition_metadata_round_trips() {
        let metadata = PartitionMetadata {
            export_name: "firestore_export".to_owned(),
            start_micros: 1_788_105_513_000_000,
            end_micros: 1_788_105_513_500_000,
            output_files: vec!["output-0".to_owned()],
        };
        let bytes = metadata.to_bytes();
        assert_eq!(
            PartitionMetadata::parse(&bytes).expect("it parses"),
            metadata
        );
    }

    #[test]
    fn a_partition_metadata_naming_no_output_file_is_refused() {
        assert!(PartitionMetadata::parse(&[]).is_err());
    }

    #[test]
    fn a_metadata_path_escaping_the_export_directory_is_refused() {
        let metadata = OverallMetadata {
            metadata_file: "../../etc/passwd".to_owned(),
            entity_count: 0,
            byte_count: 0,
        };
        assert!(OverallMetadata::parse(&metadata.to_bytes()).is_err());
    }
}
