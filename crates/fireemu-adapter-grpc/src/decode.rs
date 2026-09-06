//! Protobuf → canonical command decoding. Every unknown or unsupported wire construct is a
//! typed error; nothing is implicitly converted (spec 2.3).

use core::fmt;
use std::collections::BTreeMap;

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{
    Cursor, Direction, FieldOp, FilterExpr, OrderClause, Query, QueryScope, UnaryOp,
};
use fireemu_core_firestore::value::{GeoPoint, Timestamp, Value, MAX_NESTING_DEPTH};
use fireemu_core_types::ids::{CollectionId, DatabaseId, ProjectId};
use fireemu_proto_firestore::google::firestore::v1 as pb;
use fireemu_proto_firestore::google::firestore::v1::structured_query as sq;

/// Decode errors, each mapped to a gRPC status by [`DecodeError::grpc_code`].
#[derive(Debug, Clone, PartialEq)]
pub enum DecodeError {
    /// Malformed resource name.
    InvalidParent(String),
    /// A database id the project cannot have (production answers `NOT_FOUND` for it).
    UnknownDatabase {
        /// The project the request named.
        project: String,
        /// The database id the project cannot have.
        database: String,
    },
    /// Malformed field path.
    InvalidFieldPath(String),
    /// Malformed value.
    InvalidValue(String),
    /// Structurally invalid query.
    InvalidQuery(String),
    /// A wire feature this gateway does not model (fail closed).
    Unsupported(String),
}

impl DecodeError {
    /// gRPC code for the error.
    #[must_use]
    pub fn grpc_code(&self) -> tonic::Code {
        match self {
            Self::Unsupported(_) => tonic::Code::Unimplemented,
            Self::UnknownDatabase { .. } => tonic::Code::NotFound,
            _ => tonic::Code::InvalidArgument,
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParent(m) => write!(f, "invalid parent: {m}"),
            Self::UnknownDatabase { project, database } => write!(
                f,
                "The database {database} does not exist for project {project}"
            ),
            Self::InvalidFieldPath(m) => write!(f, "invalid field path: {m}"),
            Self::InvalidValue(m) => write!(f, "invalid value: {m}"),
            Self::InvalidQuery(m) => write!(f, "invalid query: {m}"),
            Self::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decoded `parent` resource name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parent {
    /// Project.
    pub project: ProjectId,
    /// Database.
    pub database: DatabaseId,
    /// Parent document when the parent is not the database root.
    pub document: Option<DocumentPath>,
}

/// Parses `projects/{p}/databases/{d}/documents[/{path}]`.
pub fn parse_parent(parent: &str) -> Result<Parent, DecodeError> {
    let rest = parent
        .strip_prefix("projects/")
        .ok_or_else(|| DecodeError::InvalidParent(parent.to_owned()))?;
    let (project, rest) = rest
        .split_once("/databases/")
        .ok_or_else(|| DecodeError::InvalidParent(parent.to_owned()))?;
    let Some((database, tail)) = rest.split_once("/documents") else {
        return Err(DecodeError::InvalidParent(parent.to_owned()));
    };
    let project =
        ProjectId::try_new(project).map_err(|e| DecodeError::InvalidParent(e.to_string()))?;
    // A database id production would never have created (uppercase letters, bad length) is a
    // database that does not exist, not a malformed request.
    let database = DatabaseId::try_new(database).map_err(|_| DecodeError::UnknownDatabase {
        project: project.as_str().to_owned(),
        database: database.to_owned(),
    })?;
    let document = match tail {
        "" => None,
        t => {
            let relative = t
                .strip_prefix('/')
                .ok_or_else(|| DecodeError::InvalidParent(parent.to_owned()))?;
            Some(
                DocumentPath::parse(&project, &database, relative)
                    .map_err(|e| DecodeError::InvalidParent(e.to_string()))?,
            )
        }
    };
    Ok(Parent {
        project,
        database,
        document,
    })
}

fn field_path(reference: Option<&sq::FieldReference>) -> Result<FieldPath, DecodeError> {
    let r = reference.ok_or_else(|| DecodeError::InvalidQuery("missing field reference".into()))?;
    FieldPath::parse(&r.field_path).map_err(|e| DecodeError::InvalidFieldPath(e.to_string()))
}

/// Decodes a protobuf value.
pub fn decode_value(value: &pb::Value) -> Result<Value, DecodeError> {
    decode_value_at(value, 0)
}

fn nested_depth(parent_depth: u32) -> Result<u32, DecodeError> {
    let depth = parent_depth.saturating_add(1);
    if depth > MAX_NESTING_DEPTH {
        return Err(DecodeError::InvalidValue(format!(
            "FS-LIMIT-NESTED-MAP-ARRAY-DEPTH has maximum {MAX_NESTING_DEPTH}, got {depth}"
        )));
    }
    Ok(depth)
}

fn decode_value_at(value: &pb::Value, parent_depth: u32) -> Result<Value, DecodeError> {
    use pb::value::ValueType as V;
    let Some(v) = &value.value_type else {
        return Err(DecodeError::InvalidValue("value without value_type".into()));
    };
    Ok(match v {
        V::NullValue(_) => Value::Null,
        V::BooleanValue(b) => Value::Boolean(*b),
        V::IntegerValue(i) => Value::Integer(*i),
        V::DoubleValue(d) => Value::Double(*d),
        V::TimestampValue(t) => {
            let nanos = u32::try_from(t.nanos)
                .map_err(|_| DecodeError::InvalidValue("negative timestamp nanos".into()))?;
            Value::Timestamp(
                Timestamp::new(t.seconds, nanos)
                    .map_err(|e| DecodeError::InvalidValue(format!("timestamp: {e:?}")))?,
            )
        }
        V::StringValue(s) => Value::String(s.clone()),
        V::BytesValue(b) => Value::Bytes(b.clone()),
        V::ReferenceValue(r) => Value::Reference(r.clone()),
        V::GeoPointValue(g) => Value::GeoPoint(
            GeoPoint::new(g.latitude, g.longitude)
                .map_err(|_| DecodeError::InvalidValue("geo point out of range".into()))?,
        ),
        V::ArrayValue(a) => decode_array(a, parent_depth)?,
        V::MapValue(m) => decode_map(m, parent_depth)?,
        V::FieldReferenceValue(_)
        | V::VariableReferenceValue(_)
        | V::FunctionValue(_)
        | V::PipelineValue(_) => {
            return Err(DecodeError::Unsupported(
                "pipeline expression values are not accepted in Core queries".into(),
            ))
        }
    })
}

fn decode_array(array: &pb::ArrayValue, parent_depth: u32) -> Result<Value, DecodeError> {
    let depth = nested_depth(parent_depth)?;
    Ok(Value::Array(
        array
            .values
            .iter()
            .map(|value| decode_value_at(value, depth))
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

fn decode_map(m: &pb::MapValue, parent_depth: u32) -> Result<Value, DecodeError> {
    // Vector values travel as {"__type__": "__vector__", "value": [doubles]}.
    if let (
        Some(pb::Value {
            value_type: Some(pb::value::ValueType::StringValue(t)),
        }),
        Some(pb::Value {
            value_type: Some(pb::value::ValueType::ArrayValue(a)),
        }),
    ) = (m.fields.get("__type__"), m.fields.get("value"))
    {
        if t == "__vector__" && m.fields.len() == 2 {
            let mut dims = Vec::with_capacity(a.values.len());
            for v in &a.values {
                match &v.value_type {
                    Some(pb::value::ValueType::DoubleValue(d)) => dims.push(*d),
                    // Vector components are doubles on the wire; an integer literal is widened
                    // and precision loss beyond 2^53 is accepted as in the official SDKs.
                    #[allow(clippy::cast_precision_loss)]
                    Some(pb::value::ValueType::IntegerValue(i)) => dims.push(*i as f64),
                    _ => {
                        return Err(DecodeError::InvalidValue(
                            "vector element is not a number".into(),
                        ))
                    }
                }
            }
            return Ok(Value::Vector(dims));
        }
    }
    let depth = nested_depth(parent_depth)?;
    let mut out = BTreeMap::new();
    for (k, v) in &m.fields {
        if k.is_empty() || k.chars().any(char::is_control) {
            return Err(DecodeError::InvalidValue(format!("invalid map key {k:?}")));
        }
        out.insert(k.clone(), decode_value_at(v, depth)?);
    }
    Ok(Value::Map(out))
}

fn field_op(op: i32) -> Result<FieldOp, DecodeError> {
    use sq::field_filter::Operator as O;
    Ok(
        match O::try_from(op)
            .map_err(|_| DecodeError::InvalidQuery(format!("unknown field operator {op}")))?
        {
            O::LessThan => FieldOp::LessThan,
            O::LessThanOrEqual => FieldOp::LessThanOrEqual,
            O::GreaterThan => FieldOp::GreaterThan,
            O::GreaterThanOrEqual => FieldOp::GreaterThanOrEqual,
            O::Equal => FieldOp::Equal,
            O::NotEqual => FieldOp::NotEqual,
            O::ArrayContains => FieldOp::ArrayContains,
            O::In => FieldOp::In,
            O::ArrayContainsAny => FieldOp::ArrayContainsAny,
            O::NotIn => FieldOp::NotIn,
            O::Unspecified => {
                return Err(DecodeError::InvalidQuery(
                    "unspecified field operator".into(),
                ))
            }
        },
    )
}

fn decode_filter(filter: &sq::Filter) -> Result<FilterExpr, DecodeError> {
    use sq::filter::FilterType as F;
    match &filter.filter_type {
        None => Err(DecodeError::InvalidQuery(
            "filter without filter_type".into(),
        )),
        Some(F::FieldFilter(f)) => {
            Ok(FilterExpr::Field {
                field: field_path(f.field.as_ref())?,
                op: field_op(f.op)?,
                value: decode_value(f.value.as_ref().ok_or_else(|| {
                    DecodeError::InvalidQuery("field filter without value".into())
                })?)?,
            })
        }
        Some(F::UnaryFilter(u)) => {
            use sq::unary_filter::Operator as O;
            let field = match &u.operand_type {
                Some(sq::unary_filter::OperandType::Field(f)) => FieldPath::parse(&f.field_path)
                    .map_err(|e| DecodeError::InvalidFieldPath(e.to_string()))?,
                None => {
                    return Err(DecodeError::InvalidQuery(
                        "unary filter without operand".into(),
                    ))
                }
            };
            let op = match O::try_from(u.op).map_err(|_| {
                DecodeError::InvalidQuery(format!("unknown unary operator {}", u.op))
            })? {
                O::IsNan => UnaryOp::IsNan,
                O::IsNull => UnaryOp::IsNull,
                O::IsNotNan => UnaryOp::IsNotNan,
                O::IsNotNull => UnaryOp::IsNotNull,
                O::Unspecified => {
                    return Err(DecodeError::InvalidQuery(
                        "unspecified unary operator".into(),
                    ))
                }
            };
            Ok(FilterExpr::Unary { field, op })
        }
        Some(F::CompositeFilter(c)) => {
            use sq::composite_filter::Operator as O;
            let children = c
                .filters
                .iter()
                .map(decode_filter)
                .collect::<Result<Vec<_>, _>>()?;
            match O::try_from(c.op).map_err(|_| {
                DecodeError::InvalidQuery(format!("unknown composite operator {}", c.op))
            })? {
                O::And => Ok(FilterExpr::And(children)),
                O::Or => Ok(FilterExpr::Or(children)),
                O::Unspecified => Err(DecodeError::InvalidQuery(
                    "unspecified composite operator".into(),
                )),
            }
        }
    }
}

/// A `__name__` filter may only name documents of the database the query runs in.
fn check_name_references(filter: &FilterExpr, parent: &Parent) -> Result<(), DecodeError> {
    let database = format!(
        "projects/{}/databases/{}",
        parent.project.as_str(),
        parent.database.as_str()
    );
    let check = |name: &str| -> Result<(), DecodeError> {
        let prefix = format!("{database}/documents/");
        if name.starts_with(&prefix) {
            return Ok(());
        }
        let other = name.splitn(5, '/').take(4).collect::<Vec<_>>().join("/");
        Err(DecodeError::InvalidQuery(format!(
            "The request was for database '{database}' but was attempting to access database '{other}'"
        )))
    };
    match filter {
        FilterExpr::Field { field, value, .. } if field.is_document_name() => match value {
            Value::Reference(name) => check(name),
            Value::Array(items) => items.iter().try_for_each(|v| match v {
                Value::Reference(name) => check(name),
                _ => Ok(()),
            }),
            _ => Ok(()),
        },
        FilterExpr::Field { .. } | FilterExpr::Unary { .. } => Ok(()),
        FilterExpr::And(children) | FilterExpr::Or(children) => children
            .iter()
            .try_for_each(|c| check_name_references(c, parent)),
    }
}

fn decode_cursor(cursor: &pb::Cursor) -> Result<Cursor, DecodeError> {
    Ok(Cursor {
        values: cursor
            .values
            .iter()
            .map(decode_value)
            .collect::<Result<Vec<_>, _>>()?,
        before: cursor.before,
    })
}

/// Decodes a `StructuredQuery` under `parent` into the canonical query.
pub fn decode_structured_query(
    parent: &Parent,
    query: &pb::StructuredQuery,
) -> Result<Query, DecodeError> {
    if query.find_nearest.is_some() {
        return Err(DecodeError::Unsupported(
            "find_nearest (vector search) is not modelled by the strict gateway".into(),
        ));
    }
    let from = match query.from.as_slice() {
        [from] => from,
        [] => {
            // Production and the official emulator both answer a query without a selector
            // with every document under the parent (conformance/firestore-production-
            // matrix.json, errors/rest-shapes#run-query-without-from).
            &pb::structured_query::CollectionSelector {
                collection_id: String::new(),
                all_descendants: true,
            }
        }
        _ => {
            return Err(DecodeError::InvalidQuery(
                "StructuredQuery.from cannot have more than one collection selector.".into(),
            ))
        }
    };
    // An empty collection id selects every document under the parent whatever the
    // `allDescendants` flag says: production serves it, and so does the official emulator.
    let scope = if from.collection_id.is_empty() {
        QueryScope::kindless_all_descendants(parent.document.clone())
    } else {
        let collection_id = CollectionId::try_new(from.collection_id.as_str())
            .map_err(|e| DecodeError::InvalidQuery(format!("collection id: {e}")))?;
        if from.all_descendants {
            // Under a parent document the group is every collection with that id below it.
            QueryScope::collection_group_under(parent.document.clone(), collection_id)
        } else {
            QueryScope::collection(parent.document.clone(), collection_id)
        }
    };
    let mut q = Query::new(scope);
    if let Some(w) = &query.r#where {
        let filter = decode_filter(w)?;
        check_name_references(&filter, parent)?;
        q.filter = Some(filter);
    }
    for o in &query.order_by {
        let direction = match sq::Direction::try_from(o.direction) {
            // An unspecified direction is ascending, as the backend reads it.
            Ok(sq::Direction::Ascending | sq::Direction::Unspecified) => Direction::Ascending,
            Ok(sq::Direction::Descending) => Direction::Descending,
            Err(_) => {
                return Err(DecodeError::InvalidQuery(format!(
                    "unknown order direction {}",
                    o.direction
                )))
            }
        };
        q.order_by.push(OrderClause {
            field: field_path(o.field.as_ref())?,
            direction,
        });
    }
    if let Some(c) = &query.start_at {
        q.start_at = Some(decode_cursor(c)?);
    }
    if let Some(c) = &query.end_at {
        q.end_at = Some(decode_cursor(c)?);
    }
    q.offset = u32::try_from(query.offset)
        .map_err(|_| DecodeError::InvalidQuery("negative offset".into()))?;
    q.limit = match query.limit {
        None => None,
        Some(l) => {
            Some(u32::try_from(l).map_err(|_| DecodeError::InvalidQuery("negative limit".into()))?)
        }
    };
    if let Some(p) = &query.select {
        q.projection = Some(
            p.fields
                .iter()
                .map(|f| {
                    FieldPath::parse(&f.field_path)
                        .map_err(|e| DecodeError::InvalidFieldPath(e.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    Ok(q)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use proptest::prelude::*;

    use super::*;

    fn nested_map(levels: u32) -> pb::Value {
        let mut value = pb::Value {
            value_type: Some(pb::value::ValueType::IntegerValue(1)),
        };
        for _ in 0..levels {
            value = pb::Value {
                value_type: Some(pb::value::ValueType::MapValue(pb::MapValue {
                    fields: HashMap::from([("nested".to_owned(), value)]),
                })),
            };
        }
        value
    }

    fn generated_value() -> impl Strategy<Value = pb::Value> {
        Just(pb::Value {
            value_type: Some(pb::value::ValueType::IntegerValue(1)),
        })
        .prop_recursive(MAX_NESTING_DEPTH + 8, 256, 4, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..=3).prop_map(|values| pb::Value {
                    value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue { values })),
                }),
                proptest::collection::vec(inner, 0..=3).prop_map(|values| pb::Value {
                    value_type: Some(pb::value::ValueType::MapValue(pb::MapValue {
                        fields: values
                            .into_iter()
                            .enumerate()
                            .map(|(index, value)| (format!("field-{index}"), value))
                            .collect(),
                    })),
                }),
            ]
        })
    }

    fn protobuf_nesting_depth(value: &pb::Value) -> u32 {
        let mut maximum = 0;
        let mut pending = vec![(value, 0_u32)];
        while let Some((value, parent_depth)) = pending.pop() {
            match value.value_type.as_ref() {
                Some(pb::value::ValueType::ArrayValue(array)) => {
                    let depth = parent_depth + 1;
                    maximum = maximum.max(depth);
                    pending.extend(array.values.iter().map(|value| (value, depth)));
                }
                Some(pb::value::ValueType::MapValue(map)) => {
                    let depth = parent_depth + 1;
                    maximum = maximum.max(depth);
                    pending.extend(map.fields.values().map(|value| (value, depth)));
                }
                _ => {}
            }
        }
        maximum
    }

    #[test]
    fn value_decoder_accepts_the_firestore_depth_limit_and_rejects_the_next_level() {
        let accepted = decode_value(&nested_map(MAX_NESTING_DEPTH)).expect("limit is accepted");
        assert_eq!(accepted.nesting_depth(), MAX_NESTING_DEPTH);

        let error = decode_value(&nested_map(MAX_NESTING_DEPTH + 1))
            .expect_err("one level past the limit is rejected");
        assert!(error
            .to_string()
            .contains("FS-LIMIT-NESTED-MAP-ARRAY-DEPTH"));
    }

    proptest! {
        #[test]
        fn generated_maps_and_arrays_respect_the_firestore_depth_limit(value in generated_value()) {
            let expected_depth = protobuf_nesting_depth(&value);
            match decode_value(&value) {
                Ok(decoded) => {
                    prop_assert!(expected_depth <= MAX_NESTING_DEPTH);
                    prop_assert_eq!(decoded.nesting_depth(), expected_depth);
                }
                Err(error) => {
                    prop_assert!(expected_depth > MAX_NESTING_DEPTH);
                    prop_assert!(error.to_string().contains("FS-LIMIT-NESTED-MAP-ARRAY-DEPTH"));
                }
            }
        }
    }
}
