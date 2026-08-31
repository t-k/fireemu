//! Core → protobuf encoding and the write-side decoding used by the local backend.

use std::collections::BTreeMap;

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{
    Document, FieldTransform, FirestoreError, Precondition, TransactionId, TransformKind, Write,
    WriteOp,
};
use fireemu_core_firestore::value::{Timestamp, Value};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;

use crate::decode::{decode_value, parse_parent, DecodeError};

/// Logical instant → protobuf timestamp.
#[must_use]
pub fn encode_instant(t: LogicalInstant) -> prost_types::Timestamp {
    let nanos = t.as_nanos();
    prost_types::Timestamp {
        seconds: i64::try_from(nanos.div_euclid(1_000_000_000)).unwrap_or(i64::MAX),
        nanos: i32::try_from(nanos.rem_euclid(1_000_000_000)).unwrap_or(0),
    }
}

/// Protobuf timestamp → logical instant.
#[must_use]
pub fn decode_instant(t: &prost_types::Timestamp) -> LogicalInstant {
    LogicalInstant::from_nanos(i128::from(t.seconds) * 1_000_000_000 + i128::from(t.nanos))
}

/// Core value → protobuf value.
#[must_use]
pub fn encode_value(v: &Value) -> pb::Value {
    use pb::value::ValueType as V;
    let value_type = match v {
        Value::Null => V::NullValue(0),
        Value::Boolean(b) => V::BooleanValue(*b),
        Value::Integer(i) => V::IntegerValue(*i),
        Value::Double(d) => V::DoubleValue(*d),
        Value::Timestamp(t) => V::TimestampValue(prost_types::Timestamp {
            seconds: t.seconds(),
            nanos: i32::try_from(t.nanos()).unwrap_or(0),
        }),
        Value::String(s) => V::StringValue(s.clone()),
        Value::Bytes(b) => V::BytesValue(b.clone()),
        Value::Reference(r) => V::ReferenceValue(r.clone()),
        Value::GeoPoint(g) => V::GeoPointValue(fireemu_proto_firestore::google::r#type::LatLng {
            latitude: g.latitude(),
            longitude: g.longitude(),
        }),
        Value::Array(items) => V::ArrayValue(pb::ArrayValue {
            values: items.iter().map(encode_value).collect(),
        }),
        Value::Vector(dims) => {
            let mut fields = std::collections::HashMap::new();
            fields.insert(
                "__type__".to_owned(),
                pb::Value {
                    value_type: Some(V::StringValue("__vector__".to_owned())),
                },
            );
            fields.insert(
                "value".to_owned(),
                pb::Value {
                    value_type: Some(V::ArrayValue(pb::ArrayValue {
                        values: dims
                            .iter()
                            .map(|d| pb::Value {
                                value_type: Some(V::DoubleValue(*d)),
                            })
                            .collect(),
                    })),
                },
            );
            V::MapValue(pb::MapValue { fields })
        }
        Value::Map(m) => V::MapValue(pb::MapValue {
            fields: m
                .iter()
                .map(|(k, v)| (k.clone(), encode_value(v)))
                .collect(),
        }),
    };
    pb::Value {
        value_type: Some(value_type),
    }
}

/// Core document → protobuf document.
#[must_use]
pub fn encode_document(doc: &Document) -> pb::Document {
    pb::Document {
        name: doc.path.resource_name(),
        fields: doc
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), encode_value(v)))
            .collect(),
        create_time: Some(encode_instant(doc.create_time)),
        update_time: Some(encode_instant(doc.update_time)),
    }
}

/// Parses a full document resource name.
pub fn decode_document_name(name: &str) -> Result<DocumentPath, DecodeError> {
    let parent = parse_parent(name)?;
    parent
        .document
        .ok_or_else(|| DecodeError::InvalidParent(format!("{name} is not a document name")))
}

/// Decodes a document's fields.
#[allow(clippy::implicit_hasher)] // prost generates std HashMap with the default hasher
pub fn decode_fields(
    fields: &std::collections::HashMap<String, pb::Value>,
) -> Result<BTreeMap<String, Value>, DecodeError> {
    let mut out = BTreeMap::new();
    for (k, v) in fields {
        out.insert(k.clone(), decode_value(v)?);
    }
    Ok(out)
}

/// Decodes an update mask.
pub fn decode_mask(mask: Option<&pb::DocumentMask>) -> Result<Option<Vec<FieldPath>>, DecodeError> {
    let Some(mask) = mask else { return Ok(None) };
    mask.field_paths
        .iter()
        .map(|p| FieldPath::parse(p).map_err(|e| DecodeError::InvalidFieldPath(e.to_string())))
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// Decodes a precondition. A present but empty precondition is malformed (it must never
/// silently turn a conditional write into an unconditional one).
pub fn decode_precondition(
    p: Option<&pb::Precondition>,
) -> Result<Option<Precondition>, DecodeError> {
    let Some(p) = p else { return Ok(None) };
    match &p.condition_type {
        Some(pb::precondition::ConditionType::Exists(e)) => Ok(Some(Precondition::Exists(*e))),
        Some(pb::precondition::ConditionType::UpdateTime(t)) => {
            // Firestore timestamps span 0001-01-01..9999-12-31 and update times are
            // microsecond-aligned; anything else can never match a stored document.
            if t.nanos < 0
                || t.nanos >= 1_000_000_000
                || t.nanos % 1_000 != 0
                || !(-62_135_596_800..=253_402_300_799).contains(&t.seconds)
            {
                return Err(DecodeError::InvalidQuery(
                    "precondition update_time must be a valid microsecond-aligned timestamp".into(),
                ));
            }
            Ok(Some(Precondition::UpdateTime(decode_instant(t))))
        }
        None => Err(DecodeError::InvalidQuery(
            "precondition without condition_type".into(),
        )),
    }
}

fn decode_transform(
    t: &pb::document_transform::FieldTransform,
) -> Result<FieldTransform, DecodeError> {
    use pb::document_transform::field_transform::TransformType as T;
    let field = FieldPath::parse(&t.field_path)
        .map_err(|e| DecodeError::InvalidFieldPath(e.to_string()))?;
    let kind = match &t.transform_type {
        Some(T::SetToServerValue(v))
            if *v == pb::document_transform::field_transform::ServerValue::RequestTime as i32 =>
        {
            TransformKind::ServerTimestamp
        }
        Some(T::SetToServerValue(_)) => {
            return Err(DecodeError::InvalidQuery(
                "set_to_server_value must be REQUEST_TIME".into(),
            ))
        }
        Some(T::Increment(v)) => TransformKind::Increment(decode_value(v)?),
        Some(T::Maximum(v)) => TransformKind::Maximum(decode_value(v)?),
        Some(T::Minimum(v)) => TransformKind::Minimum(decode_value(v)?),
        Some(T::AppendMissingElements(a)) => TransformKind::AppendMissingElements(
            a.values
                .iter()
                .map(decode_value)
                .collect::<Result<_, _>>()?,
        ),
        Some(T::RemoveAllFromArray(a)) => TransformKind::RemoveAllFromArray(
            a.values
                .iter()
                .map(decode_value)
                .collect::<Result<_, _>>()?,
        ),
        None => {
            return Err(DecodeError::InvalidQuery(
                "field transform without transform_type".into(),
            ))
        }
    };
    Ok(FieldTransform { field, kind })
}

/// Decodes a write.
pub fn decode_write(w: &pb::Write) -> Result<Write, DecodeError> {
    let precondition = decode_precondition(w.current_document.as_ref())?;
    let mut transforms = w
        .update_transforms
        .iter()
        .map(decode_transform)
        .collect::<Result<Vec<_>, _>>()?;
    let op = match &w.operation {
        Some(pb::write::Operation::Update(doc)) => WriteOp::Set {
            path: decode_document_name(&doc.name)?,
            fields: decode_fields(&doc.fields)?,
            update_mask: decode_mask(w.update_mask.as_ref())?,
        },
        Some(pb::write::Operation::Delete(name)) => WriteOp::Delete {
            path: decode_document_name(name)?,
        },
        Some(pb::write::Operation::Verify(name)) => WriteOp::Verify {
            path: decode_document_name(name)?,
        },
        Some(pb::write::Operation::Transform(dt)) => {
            if dt.field_transforms.is_empty() {
                return Err(DecodeError::InvalidQuery(
                    "document transform without field transforms".into(),
                ));
            }
            transforms.extend(
                dt.field_transforms
                    .iter()
                    .map(decode_transform)
                    .collect::<Result<Vec<_>, _>>()?,
            );
            WriteOp::Set {
                path: decode_document_name(&dt.document)?,
                fields: BTreeMap::new(),
                update_mask: Some(Vec::new()),
            }
        }
        None => return Err(DecodeError::InvalidQuery("write without operation".into())),
    };
    if w.update_mask.is_some() && !matches!(op, WriteOp::Set { .. }) {
        return Err(DecodeError::InvalidQuery(
            "update_mask is only valid with an update operation".into(),
        ));
    }
    Ok(Write {
        op,
        precondition,
        transforms,
    })
}

/// Transaction handle ↔ wire bytes.
#[must_use]
pub fn encode_transaction(id: &TransactionId) -> Vec<u8> {
    id.value().to_be_bytes().to_vec()
}

/// Wire bytes → transaction handle.
pub fn decode_transaction(bytes: &[u8]) -> Result<TransactionId, DecodeError> {
    let arr: [u8; 8] = bytes
        .try_into()
        .map_err(|_| DecodeError::InvalidQuery("malformed transaction id".into()))?;
    Ok(TransactionId::from_value(u64::from_be_bytes(arr)))
}

/// Firestore core error → gRPC status (wire mapping revision in `fireemu-core-limits`).
#[must_use]
pub fn status_from_error(e: &FirestoreError) -> tonic::Status {
    let mut status = match e {
        FirestoreError::InvalidArgument(m) => tonic::Status::invalid_argument(m.clone()),
        FirestoreError::FailedPrecondition(m) => tonic::Status::failed_precondition(m.clone()),
        FirestoreError::AlreadyExists(p) => {
            tonic::Status::already_exists(format!("Document already exists: {}", p.resource_name()))
        }
        FirestoreError::NotFound(p) => {
            tonic::Status::not_found(format!("No document to update: {}", p.resource_name()))
        }
        FirestoreError::Aborted(m) => tonic::Status::aborted(m.clone()),
        // A lock contention that reached the wire (a bulk `BatchWrite`, or a path that did
        // not go through the lock-wait loop) is reported as the official emulator reports a
        // held lock: `ABORTED` with this message. The single-write commit paths intercept
        // `LockContended` before this and wait it out on the virtual clock instead.
        FirestoreError::LockContended { .. } => tonic::Status::aborted("Transaction lock timeout."),
        // The official backend reports size / depth violations as INVALID_ARGUMENT.
        FirestoreError::ResourceExhausted(v) => tonic::Status::invalid_argument(format!(
            "{}: {} exceeds {} ({:?})",
            v.limit_id,
            v.current.value(),
            v.maximum.value(),
            v.precision
        )),
        FirestoreError::Unimplemented(m) => tonic::Status::unimplemented(m.clone()),
    };
    if let FirestoreError::ResourceExhausted(v) = e {
        if let Ok(value) = v.limit_id.parse() {
            status.metadata_mut().insert("fireemu-limit-id", value);
        }
    }
    status
}

/// Timestamp conversion helper for tests and adapters.
#[must_use]
pub fn timestamp_to_instant(t: Timestamp) -> LogicalInstant {
    LogicalInstant::from_nanos(i128::from(t.seconds()) * 1_000_000_000 + i128::from(t.nanos()))
}
