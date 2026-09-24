//! Protobuf → canonical command decoding. Every unknown or unsupported wire construct is a
//! typed error; nothing is implicitly converted (spec 2.3).

use core::fmt;
use std::collections::BTreeMap;

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::path::{DocumentPath, PathError};
use fireemu_core_firestore::query::{
    Cursor, Direction, DistanceMeasure, FieldOp, FilterExpr, FindNearest, OrderClause, Query,
    QueryScope, UnaryOp,
};
use fireemu_core_firestore::value::{GeoPoint, Timestamp, Value, MAX_NESTING_DEPTH};
use fireemu_core_types::ids::{CollectionId, DatabaseId, IdSyntaxError, ProjectId};
use fireemu_proto_firestore::google::firestore::v1 as pb;
use fireemu_proto_firestore::google::firestore::v1::structured_query as sq;

/// Decode errors, each mapped to a gRPC status by [`DecodeError::grpc_code`].
#[derive(Debug, Clone, PartialEq)]
pub enum DecodeError {
    /// Malformed resource name.
    InvalidParent(String),
    /// A document name rejected with the observed production message.
    InvalidDocumentName(String),
    /// A database the project does not have: an id the project could never have carried, or
    /// one `databases.create` was never called for. Production answers `NOT_FOUND` for both,
    /// with the same message (`conformance/firestore-production-matrix.json`,
    /// `emulator/routes#database-with-uppercase-name` and `#named-database-document`).
    UnknownDatabase {
        /// The project the request named.
        project: String,
        /// The database id the project does not have.
        database: String,
    },
    /// Malformed field path.
    InvalidFieldPath(String),
    /// A property path rejected with the observed production error text.
    InvalidPropertyPath(String),
    /// A stored field name rejected with the production error text.
    InvalidStoredFieldName(String),
    /// Malformed value.
    InvalidValue(String),
    /// Structurally invalid query.
    InvalidQuery(String),
    /// A write with no operation set.
    EmptyWriteOperation,
    /// A wire feature this gateway does not model (fail closed).
    Unsupported(String),
    /// An argument refused with production's own text (`crate::query_messages`).
    Refused(String),
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
                "The database {database} does not exist for project {project} Please visit \
                 https://console.cloud.google.com/datastore/setup?project={project} to add a \
                 Cloud Datastore or Cloud Firestore database. "
            ),
            Self::InvalidFieldPath(m) => write!(f, "invalid field path: {m}"),
            Self::InvalidDocumentName(m)
            | Self::InvalidStoredFieldName(m)
            | Self::InvalidPropertyPath(m)
            | Self::Refused(m) => f.write_str(m),
            Self::InvalidValue(m) => write!(f, "invalid value: {m}"),
            Self::InvalidQuery(m) => write!(f, "invalid query: {m}"),
            Self::EmptyWriteOperation => write!(f, "empty write operation"),
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

fn observed_document_path_error(name: &str, relative: &str, error: &PathError) -> DecodeError {
    let prefix_bytes = name.len().saturating_sub(relative.len());
    let segments: Vec<&str> = relative.split('/').collect();
    let message = match error {
        PathError::OddSegmentCount { .. } if name.len() <= 8_192 => Some(format!(
            "Document name \"{name}\" lacks \"/\" at index {}.",
            name.len()
        )),
        PathError::InvalidSegment {
            index,
            error: IdSyntaxError::TooManyBytes { .. },
        } if index % 2 == 0 => {
            Some("The key path element kind is longer than 1500 bytes.".to_owned())
        }
        PathError::InvalidSegment {
            index,
            error: IdSyntaxError::DotSegment,
        } if index % 2 == 0 && name.len() <= 8_192 => {
            let segment = segments[*index];
            let offset = prefix_bytes
                + segments[..*index]
                    .iter()
                    .map(|part| part.len() + 1)
                    .sum::<usize>();
            Some(format!("Document name \"{name}\" contains a collection id \"{segment}\" at index {offset}."))
        }
        PathError::InvalidSegment {
            index,
            error: IdSyntaxError::ReservedDunder,
        } if index % 2 == 0 => Some(format!(
            "Collection id \"{}\" is invalid because it is reserved.",
            segments[*index]
        )),
        PathError::TooDeep { .. } => {
            Some("Key path is too long. Cannot exceed 100 elements.".to_owned())
        }
        PathError::NameTooLong { .. } => {
            Some("The document name is longer than 6144 bytes.".to_owned())
        }
        _ => None,
    };
    message.map_or_else(
        || DecodeError::InvalidParent(error.to_string()),
        DecodeError::InvalidDocumentName,
    )
}

/// Parses `projects/{p}/databases/{d}/documents[/{path}]`.
pub fn parse_parent(parent: &str) -> Result<Parent, DecodeError> {
    let rest = parent
        .strip_prefix("projects/")
        .ok_or_else(|| DecodeError::InvalidParent(parent.to_owned()))?;
    let (project, rest) = rest
        .split_once("/databases/")
        .ok_or_else(|| DecodeError::InvalidParent(parent.to_owned()))?;
    let Some((database, after_database)) = rest.split_once('/') else {
        return Err(DecodeError::InvalidParent(parent.to_owned()));
    };
    let Some(tail) = after_database.strip_prefix("documents") else {
        return Err(DecodeError::InvalidParent(parent.to_owned()));
    };
    if !tail.is_empty() && !tail.starts_with('/') {
        return Err(DecodeError::InvalidParent(parent.to_owned()));
    }
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
                    .map_err(|error| observed_document_path_error(parent, relative, &error))?,
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
    let Some(r) = reference else {
        return Err(DecodeError::Refused(
            crate::query_messages::EMPTY_PROPERTY_PATH.into(),
        ));
    };
    property_path(&r.field_path)
}

/// A property path of a query, refused in production's words.
fn property_path(path: &str) -> Result<FieldPath, DecodeError> {
    FieldPath::parse(path).map_err(|e| crate::query_messages::property_path_error(path, &e))
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
        if k == "__name__" {
            return Err(DecodeError::InvalidFieldPath(
                "field name __name__ is reserved".into(),
            ));
        }
        FieldPath::from_segments([k.as_str()])
            .map_err(|error| DecodeError::InvalidFieldPath(error.to_string()))?;
        out.insert(k.clone(), decode_value_at(v, depth)?);
    }
    Ok(Value::Map(out))
}

fn field_op(op: i32) -> Result<FieldOp, DecodeError> {
    use sq::field_filter::Operator as O;
    Ok(
        match O::try_from(op)
            .map_err(|_| DecodeError::Refused("Unknown FieldFilter operator.".into()))?
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
                return Err(DecodeError::Refused("Unknown FieldFilter operator.".into()))
            }
        },
    )
}

fn decode_filter(filter: &sq::Filter) -> Result<FilterExpr, DecodeError> {
    use sq::filter::FilterType as F;
    match &filter.filter_type {
        None => Err(DecodeError::Refused("Unknown Filter type.".into())),
        Some(F::FieldFilter(f)) => Ok(FilterExpr::Field {
            field: field_path(f.field.as_ref())?,
            op: field_op(f.op)?,
            value: decode_value(f.value.as_ref().ok_or_else(|| {
                DecodeError::Refused("Cannot convert firestore.v1.Value with type unset.".into())
            })?)?,
        }),
        Some(F::UnaryFilter(u)) => {
            use sq::unary_filter::Operator as O;
            let field = match &u.operand_type {
                Some(sq::unary_filter::OperandType::Field(f)) => property_path(&f.field_path)?,
                None => {
                    return Err(DecodeError::Refused(
                        "Unsupported UnaryFilter operand type (non-FIELD).".into(),
                    ))
                }
            };
            let op = match O::try_from(u.op)
                .map_err(|_| DecodeError::Refused("Unknown UnaryFilter operator.".into()))?
            {
                O::IsNan => UnaryOp::IsNan,
                O::IsNull => UnaryOp::IsNull,
                O::IsNotNan => UnaryOp::IsNotNan,
                O::IsNotNull => UnaryOp::IsNotNull,
                O::Unspecified => {
                    return Err(DecodeError::Refused("Unknown UnaryFilter operator.".into()))
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
            match O::try_from(c.op).unwrap_or(O::Unspecified) {
                O::And => Ok(FilterExpr::And(children)),
                O::Or => Ok(FilterExpr::Or(children)),
                O::Unspecified => Err(DecodeError::Refused(
                    "Unsupported CompositeFilter operator.".into(),
                )),
            }
        }
    }
}

/// A `__name__` filter may only name documents of the database the query runs in.
/// `projects/{p}/databases/{d}` as the request named it.
fn database_resource(parent: &Parent) -> String {
    format!(
        "projects/{}/databases/{}",
        parent.project.as_str(),
        parent.database.as_str()
    )
}

/// Longest `projects/{p}/databases/{d}` that may be quoted back to the caller. A project ID
/// and a database ID are each at most 63 bytes, so a well-formed prefix is at most
/// `projects/` + 63 + `/databases/` + 63 = 146 bytes. The cap leaves headroom above every
/// prefix that could be real and still stops a caller from choosing the length of a log line.
const MAX_ECHOED_DATABASE_BYTES: usize = 160;

/// What is quoted in place of a reference prefix that may not be echoed. Project and
/// database IDs are lowercase and hyphenated, so this can never collide with a real one.
const UNPRINTABLE_DATABASE: &str = "[unprintable reference]";

/// The `projects/{p}/databases/{d}` prefix of `name`, when it is safe to quote back.
///
/// Production's message names the database the caller reached for, and that stays exact for
/// every well-formed reference. A `referenceValue` is an arbitrary caller string that never
/// passes through [`DocumentPath`], though, so nothing else rejects a NUL, a newline or
/// megabytes of padding before this text reaches a log line. A prefix that is over the cap or
/// carries a control character is therefore replaced wholesale rather than escaped: the
/// caller learns the request was refused without choosing what a log line contains.
fn echoable_database(name: &str) -> &str {
    // The prefix is everything before the fourth `/`, which is the whole string when there
    // are fewer. Taken as a slice, so an oversized reference is never copied.
    let end = name
        .char_indices()
        .filter(|&(_, character)| character == '/')
        .nth(3)
        .map_or(name.len(), |(index, _)| index);
    let prefix = &name[..end];
    if prefix.len() > MAX_ECHOED_DATABASE_BYTES || prefix.chars().any(char::is_control) {
        return UNPRINTABLE_DATABASE;
    }
    prefix
}

/// The guard production applies to every document reference a query uses as a document
/// name: a reference outside the request's database is refused rather than followed.
///
/// `database` is built from the request's own [`Parent`], whose project and database have
/// already passed their identifier validation, so only the caller's reference needs bounding.
fn check_reference_database(name: &str, database: &str) -> Result<(), DecodeError> {
    let prefix = format!("{database}/documents/");
    if name.starts_with(&prefix) {
        return Ok(());
    }
    let other = echoable_database(name);
    Err(DecodeError::Refused(format!(
        "The request was for database '{database}' but was attempting to access database '{other}'"
    )))
}

/// A cursor value standing in a `__name__` position is a document reference, so it gets the
/// same database guard as a `__name__` filter value. This runs on the request rather than on
/// the query scope because a root collection and a database-wide collection group carry no
/// parent document, and the request is then the only place the project and database are
/// known. A reference in any other position is a value compared against stored content, not
/// a document position, so it is left alone.
fn check_cursor_name_references(query: &Query, parent: &Parent) -> Result<(), DecodeError> {
    let order = query.effective_order_by();
    let database = database_resource(parent);
    for cursor in [&query.start_at, &query.end_at].into_iter().flatten() {
        for (position, value) in cursor.values.iter().enumerate() {
            let Some(clause) = order.get(position) else {
                // A cursor longer than the order-by is refused by canonicalization.
                break;
            };
            if !clause.field.is_document_name() {
                continue;
            }
            if let Value::Reference(name) = value {
                check_reference_database(name, &database).map_err(|_| {
                    DecodeError::Refused(
                        "The cursor key is in a different database than the query".into(),
                    )
                })?;
            }
        }
    }
    Ok(())
}

fn check_name_references(
    filter: &FilterExpr,
    parent: &Parent,
    production_refusals: bool,
) -> Result<(), DecodeError> {
    let database = database_resource(parent);
    // A reference outside the request's database is refused first; one that names a
    // collection rather than a document is refused in production's words (a production-only
    // refusal: the emulator profile compares such a name as fireemu did before).
    let check = |name: &str| -> Result<(), DecodeError> {
        check_reference_database(name, &database)?;
        if production_refusals && DocumentPath::from_resource_name(name).is_none() {
            // The name parsed as a parent tells a collection (odd segment count) apart from
            // the other malformed names, each in its own words; the database root itself is
            // no document either.
            return Err(match crate::query_messages::parse_query_parent(name) {
                Err(error) => error,
                Ok(_) => {
                    DecodeError::Refused(crate::query_messages::reference_is_not_a_document(name))
                }
            });
        }
        Ok(())
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
            .try_for_each(|c| check_name_references(c, parent, production_refusals)),
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

fn decode_find_nearest(find_nearest: &sq::FindNearest) -> Result<FindNearest, DecodeError> {
    // Production's texts (FS-QUERY-INDEX vector/validation, recorded 2026-09-24).
    let vector_field = field_path(find_nearest.vector_field.as_ref())?;
    let query_vector = decode_value(find_nearest.query_vector.as_ref().ok_or_else(|| {
        DecodeError::Refused("Cannot convert firestore.v1.Value with type unset.".into())
    })?)?;
    let Value::Vector(query_vector) = query_vector else {
        return Err(DecodeError::Refused(
            "Query Value must be of type vector.".into(),
        ));
    };
    let distance_measure =
        match sq::find_nearest::DistanceMeasure::try_from(find_nearest.distance_measure)
            .unwrap_or(sq::find_nearest::DistanceMeasure::Unspecified)
        {
            sq::find_nearest::DistanceMeasure::Euclidean => DistanceMeasure::Euclidean,
            sq::find_nearest::DistanceMeasure::Cosine => DistanceMeasure::Cosine,
            sq::find_nearest::DistanceMeasure::DotProduct => DistanceMeasure::DotProduct,
            sq::find_nearest::DistanceMeasure::Unspecified => {
                return Err(DecodeError::Refused("Unknown Distance Measure.".into()))
            }
        };
    let limit = find_nearest
        .limit
        .and_then(|limit| u32::try_from(limit).ok())
        .ok_or_else(|| {
            DecodeError::Refused(
                "FindNearest.limit must be a positive integer of no more than 1000".into(),
            )
        })?;
    // Production reads the distance result field as one property name, not a path.
    let distance_result_field = if find_nearest.distance_result_field.is_empty() {
        None
    } else {
        let name = find_nearest.distance_result_field.as_str();
        Some(
            FieldPath::from_segments([name])
                .or_else(|_| FieldPath::parse(name))
                .map_err(|_| {
                    DecodeError::Refused(format!(
                        "The distanceResultField.property.name \"{}\" is reserved.",
                        fireemu_core_types::codec::echo(name)
                    ))
                })?,
        )
    };
    Ok(FindNearest {
        vector_field,
        query_vector,
        distance_measure,
        limit,
        distance_result_field,
        distance_threshold: find_nearest.distance_threshold,
    })
}

/// Decodes a `StructuredQuery` under `parent` into the canonical query, with production's
/// refusals.
pub fn decode_structured_query(
    parent: &Parent,
    query: &pb::StructuredQuery,
) -> Result<Query, DecodeError> {
    decode_structured_query_in(parent, query, true)
}

/// [`decode_structured_query`] under a profile: without `production_refusals` (the emulator
/// profile) the decoder makes only the refusals fireemu made before the strict profile.
pub fn decode_structured_query_in(
    parent: &Parent,
    query: &pb::StructuredQuery,
    production_refusals: bool,
) -> Result<Query, DecodeError> {
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
            return Err(DecodeError::Refused(
                "StructuredQuery.from cannot have more than one collection selector.".into(),
            ))
        }
    };
    // An empty collection id selects documents of any collection: every one under the parent
    // with `allDescendants`, the parent's direct children without it (production, FS-QUERY-INDEX
    // collection-group/scopes#kindless-without-descendants).
    let scope = if from.collection_id.is_empty() {
        if from.all_descendants {
            QueryScope::kindless_all_descendants(parent.document.clone())
        } else {
            QueryScope::kindless_children(parent.document.clone())
        }
    } else {
        let collection_id = CollectionId::try_new(from.collection_id.as_str())
            .map_err(|e| crate::query_messages::collection_id_error(&from.collection_id, &e))?;
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
        check_name_references(&filter, parent, production_refusals)?;
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
        .map_err(|_| DecodeError::Refused("offset is negative".into()))?;
    q.limit = match query.limit {
        None => None,
        Some(l) => {
            Some(u32::try_from(l).map_err(|_| DecodeError::Refused("limit is negative".into()))?)
        }
    };
    if let Some(p) = &query.select {
        q.projection = Some(
            p.fields
                .iter()
                .map(|f| property_path(&f.field_path))
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    if let Some(find_nearest) = &query.find_nearest {
        q.find_nearest = Some(decode_find_nearest(find_nearest)?);
    }
    check_cursor_name_references(&q, parent)?;
    Ok(q)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use proptest::prelude::*;

    use super::*;

    #[test]
    fn parse_parent_accepts_project_and_database_identifiers_containing_documents() {
        for (project, database) in [("documents-project", "documents"), ("demo", "documents-db")] {
            let parent = parse_parent(&format!(
                "projects/{project}/databases/{database}/documents/items/alice"
            ))
            .expect("document resource should parse");
            assert_eq!(parent.project.as_str(), project);
            assert_eq!(parent.database.as_str(), database);
            assert_eq!(
                parent.document.as_ref().map(DocumentPath::relative),
                Some("items/alice".to_owned())
            );
        }
    }

    // A cursor value standing in a `__name__` position is a document reference, so it gets
    // the same database guard the `__name__` filters get. The scope of a root collection or
    // a database-wide collection group carries no parent document, so this request-level
    // check is the only place such a cursor's project and database can be compared.
    fn request_parent() -> Parent {
        parse_parent("projects/demo-app/databases/(default)/documents")
            .expect("the database root parses")
    }

    fn pb_reference(name: &str) -> pb::Value {
        pb::Value {
            value_type: Some(pb::value::ValueType::ReferenceValue(name.to_owned())),
        }
    }

    fn name_ordered(
        all_descendants: bool,
        start_at: Option<pb::Cursor>,
        end_at: Option<pb::Cursor>,
    ) -> pb::StructuredQuery {
        pb::StructuredQuery {
            from: vec![pb::structured_query::CollectionSelector {
                collection_id: "cur".to_owned(),
                all_descendants,
            }],
            order_by: vec![pb::structured_query::Order {
                field: Some(pb::structured_query::FieldReference {
                    field_path: "__name__".to_owned(),
                }),
                direction: sq::Direction::Ascending as i32,
            }],
            start_at,
            end_at,
            ..Default::default()
        }
    }

    fn cursor(name: &str) -> pb::Cursor {
        pb::Cursor {
            values: vec![pb_reference(name)],
            before: true,
        }
    }

    fn foreign_cursor_error(query: &pb::StructuredQuery) -> String {
        let error = decode_structured_query(&request_parent(), query)
            .expect_err("a cursor outside the request database is refused");
        assert_eq!(error.grpc_code(), tonic::Code::InvalidArgument);
        error.to_string()
    }

    #[test]
    fn a_root_collection_cursor_reference_outside_the_request_database_is_refused() {
        // The scope of a root collection carries no parent document, so the request's own
        // `projects/{p}/databases/{d}` is the only identity available to compare against.
        for name in [
            "projects/other-app/databases/(default)/documents/cur/c3",
            "projects/demo-app/databases/other/documents/cur/c3",
        ] {
            let message = foreign_cursor_error(&name_ordered(false, Some(cursor(name)), None));
            assert_eq!(message, FOREIGN_CURSOR);
        }
    }

    #[test]
    fn a_database_wide_collection_group_cursor_reference_outside_the_request_database_is_refused() {
        for name in [
            "projects/other-app/databases/(default)/documents/scope/s1/cur/c3",
            "projects/demo-app/databases/other/documents/scope/s1/cur/c3",
        ] {
            let message = foreign_cursor_error(&name_ordered(true, Some(cursor(name)), None));
            assert_eq!(message, FOREIGN_CURSOR);
        }
    }

    #[test]
    fn an_end_cursor_reference_outside_the_request_database_is_refused() {
        let query = name_ordered(
            false,
            None,
            Some(cursor(
                "projects/other-app/databases/(default)/documents/cur/c3",
            )),
        );
        foreign_cursor_error(&query);
    }

    #[test]
    fn an_implicit_document_name_cursor_reference_is_checked_against_the_request_database() {
        // No explicit order: the effective order is `__name__` alone, so the single cursor
        // value stands in the `__name__` position.
        let query = pb::StructuredQuery {
            from: vec![pb::structured_query::CollectionSelector {
                collection_id: "cur".to_owned(),
                all_descendants: false,
            }],
            start_at: Some(cursor(
                "projects/other-app/databases/(default)/documents/cur/c3",
            )),
            ..Default::default()
        };
        foreign_cursor_error(&query);
    }

    #[test]
    fn a_cursor_reference_inside_the_request_database_decodes() {
        for all_descendants in [false, true] {
            let query = name_ordered(
                all_descendants,
                Some(cursor(
                    "projects/demo-app/databases/(default)/documents/cur/c3",
                )),
                None,
            );
            decode_structured_query(&request_parent(), &query)
                .expect("a reference in the request database is a position, not an error");
        }
    }

    fn name_filtered(reference: &str) -> pb::StructuredQuery {
        pb::StructuredQuery {
            from: vec![pb::structured_query::CollectionSelector {
                collection_id: "cur".to_owned(),
                all_descendants: false,
            }],
            r#where: Some(sq::Filter {
                filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
                    field: Some(pb::structured_query::FieldReference {
                        field_path: "__name__".to_owned(),
                    }),
                    op: sq::field_filter::Operator::Equal as i32,
                    value: Some(pb_reference(reference)),
                })),
            }),
            ..Default::default()
        }
    }

    /// Production's constant refusal of a cursor key outside the request's database; only a
    /// `__name__` filter value echoes the database it reached for.
    const FOREIGN_CURSOR: &str = "The cursor key is in a different database than the query";

    /// The paths that echo a hostile reference: a `__name__` filter value. A cursor value in
    /// a `__name__` position is refused with [`FOREIGN_CURSOR`], which echoes nothing.
    fn both_paths(reference: &str) -> [pb::StructuredQuery; 1] {
        let cursor_message =
            foreign_cursor_error(&name_ordered(false, Some(cursor(reference)), None));
        assert_eq!(cursor_message, FOREIGN_CURSOR);
        [name_filtered(reference)]
    }

    #[test]
    fn a_reference_carrying_control_characters_is_not_echoed_into_the_message() {
        // `referenceValue` never passes through `DocumentPath`, so nothing else rejects a
        // NUL or a newline before the message that quotes it reaches a log line.
        for reference in [
            "projects/other\u{0}app/databases/(default)/documents/cur/c3",
            "projects/other\r\napp/databases/(default)/documents/cur/c3",
            "projects/other\u{7f}app/databases/(default)/documents/cur/c3",
            "projects/other\u{85}app/databases/(default)/documents/cur/c3",
        ] {
            for query in both_paths(reference) {
                let message = foreign_cursor_error(&query);
                assert!(
                    message.contains("[unprintable reference]"),
                    "the caller text must be replaced, got {message:?}"
                );
                assert!(
                    !message.chars().any(char::is_control),
                    "no control character may survive into the message, got {message:?}"
                );
            }
        }
    }

    #[test]
    fn an_oversized_reference_prefix_is_not_echoed_into_the_message() {
        // A project ID is at most 63 bytes, so this prefix could never be well formed; the
        // cap is what stops a caller from choosing the length of a log line.
        let reference = format!(
            "projects/{}/databases/(default)/documents/cur/c3",
            "a".repeat(4096)
        );
        for query in both_paths(&reference) {
            let message = foreign_cursor_error(&query);
            assert!(message.contains("[unprintable reference]"), "{message}");
            assert!(message.len() < 512, "message length {}", message.len());
        }
    }

    #[test]
    fn a_well_formed_foreign_database_is_still_echoed_verbatim() {
        // Production quotes the database the caller reached for, and that stays exact.
        for query in both_paths("projects/other-app/databases/other/documents/cur/c3") {
            let message = foreign_cursor_error(&query);
            assert!(
                message.contains(
                    "but was attempting to access database 'projects/other-app/databases/other'"
                ),
                "{message}"
            );
        }
    }

    #[test]
    fn a_short_malformed_reference_is_still_echoed_verbatim() {
        // Printable and bounded: nothing to sanitize, so the answer stays what it was.
        for query in both_paths("not-a-resource-name") {
            let message = foreign_cursor_error(&query);
            assert!(
                message.contains("access database 'not-a-resource-name'"),
                "{message}"
            );
        }
    }

    #[test]
    fn a_reference_outside_the_document_name_slot_is_left_to_value_comparison() {
        // Position 0 is `owner`, an ordinary field: a reference there is a value compared
        // against stored content, not a document position, so the database guard does not
        // apply to it.
        let query = pb::StructuredQuery {
            from: vec![pb::structured_query::CollectionSelector {
                collection_id: "cur".to_owned(),
                all_descendants: false,
            }],
            order_by: vec![pb::structured_query::Order {
                field: Some(pb::structured_query::FieldReference {
                    field_path: "owner".to_owned(),
                }),
                direction: sq::Direction::Ascending as i32,
            }],
            start_at: Some(cursor(
                "projects/other-app/databases/(default)/documents/people/p1",
            )),
            ..Default::default()
        };
        decode_structured_query(&request_parent(), &query)
            .expect("an ordinary field cursor value is not a document position");
    }

    #[test]
    fn parse_parent_rejects_documents_suffix_that_is_not_a_resource_segment() {
        let error = parse_parent("projects/demo/databases/(default)/documents-extra")
            .expect_err("a documents-like suffix is not a document resource");
        assert!(matches!(error, DecodeError::InvalidParent(_)));
    }

    #[test]
    fn observed_document_name_failures_keep_production_messages() {
        let prefix = "projects/demo-firestore-probe/databases/(default)/documents/";
        let too_long_collection = format!("{prefix}{}/x", "c".repeat(1501));
        let too_deep = format!("{prefix}{}", ["c/d"; 101].join("/"));
        let mut segments = Vec::new();
        for _ in 0..4 {
            segments.extend(["c".to_owned(), "d".repeat(1500)]);
        }
        segments.extend(["c".to_owned(), "d".repeat(114)]);
        let long_name = format!("{prefix}{}", segments.join("/"));
        for (name, expected) in [
            (
                too_long_collection,
                "The key path element kind is longer than 1500 bytes.".to_owned(),
            ),
            (
                too_deep,
                "Key path is too long. Cannot exceed 100 elements.".to_owned(),
            ),
            (
                long_name,
                "The document name is longer than 6144 bytes.".to_owned(),
            ),
            (
                format!("{prefix}./x"),
                format!(
                    "Document name \"{prefix}./x\" contains a collection id \".\" at index 60."
                ),
            ),
            (
                format!("{prefix}../x"),
                format!(
                    "Document name \"{prefix}../x\" contains a collection id \"..\" at index 60."
                ),
            ),
            (
                format!("{prefix}__reserved__/x"),
                "Collection id \"__reserved__\" is invalid because it is reserved.".to_owned(),
            ),
            (
                format!("{prefix}bad/inside/x"),
                format!("Document name \"{prefix}bad/inside/x\" lacks \"/\" at index 72."),
            ),
        ] {
            assert_eq!(parse_parent(&name).unwrap_err().to_string(), expected);
        }
    }

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

    #[test]
    fn structured_query_decodes_find_nearest_vector_search() {
        let parent = parse_parent("projects/demo-app/databases/(default)/documents").unwrap();
        let vector = pb::Value {
            value_type: Some(pb::value::ValueType::MapValue(pb::MapValue {
                fields: [
                    (
                        "__type__".to_owned(),
                        pb::Value {
                            value_type: Some(pb::value::ValueType::StringValue(
                                "__vector__".to_owned(),
                            )),
                        },
                    ),
                    (
                        "value".to_owned(),
                        pb::Value {
                            value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue {
                                values: vec![pb::Value {
                                    value_type: Some(pb::value::ValueType::DoubleValue(1.0)),
                                }],
                            })),
                        },
                    ),
                ]
                .into_iter()
                .collect(),
            })),
        };
        let query = decode_structured_query(
            &parent,
            &pb::StructuredQuery {
                from: vec![pb::structured_query::CollectionSelector {
                    collection_id: "items".to_owned(),
                    ..Default::default()
                }],
                find_nearest: Some(pb::structured_query::FindNearest {
                    vector_field: Some(pb::structured_query::FieldReference {
                        field_path: "embedding".to_owned(),
                    }),
                    query_vector: Some(vector),
                    distance_measure: sq::find_nearest::DistanceMeasure::Euclidean as i32,
                    limit: Some(2),
                    distance_result_field: "distance".to_owned(),
                    distance_threshold: Some(3.0),
                }),
                ..Default::default()
            },
        )
        .unwrap();
        let nearest = query.find_nearest.unwrap();
        assert_eq!(nearest.vector_field.to_string(), "embedding");
        assert_eq!(nearest.query_vector, vec![1.0]);
        assert_eq!(nearest.limit, 2);
        assert_eq!(nearest.distance_threshold, Some(3.0));
    }
}
