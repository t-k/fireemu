//! The JSON transcoding production's REST front end applies to query request bodies before
//! Firestore sees them (FS-QUERY-INDEX request-shape and filter-validation rows, recorded
//! 2026-09-24).
//!
//! It checks a body against the proto schema of its request and refuses with the transcoder's
//! own texts (`Invalid JSON payload received. Unknown name "x" at 'structured_query': Cannot
//! find field.`, `Invalid value at 'structured_query.limit.value' (TYPE_INT32), 2147483648`,
//! ...). What it accepts it normalizes to the canonical proto3 JSON the rest of the REST
//! surface parses: enum names in upper case (production matches them without regard to case,
//! and accepts their numbers), 64-bit integers as strings, booleans from `"true"`/`"false"`.

use serde_json::{Map, Value};
use tonic::Status;

/// A field's type.
#[derive(Clone, Copy)]
enum Kind {
    Message(&'static Schema),
    Enum(&'static EnumSchema),
    Int32,
    Int64,
    Bool,
    Double,
    Str,
    Bytes,
    Timestamp,
    /// `google.protobuf.Int32Value` / `Int64Value` / `DoubleValue`, written as a bare scalar.
    Wrapper(Scalar),
    /// `map<string, Value>`.
    ValueMap,
}

#[derive(Clone, Copy)]
enum Scalar {
    Int32,
    Int64,
    Double,
}

struct Field {
    json: &'static str,
    proto: &'static str,
    kind: Kind,
    repeated: bool,
    oneof: Option<&'static str>,
}

struct Schema {
    fields: &'static [Field],
}

struct EnumSchema {
    type_url: &'static str,
    values: &'static [(&'static str, i64)],
}

const fn f(json: &'static str, proto: &'static str, kind: Kind) -> Field {
    Field {
        json,
        proto,
        kind,
        repeated: false,
        oneof: None,
    }
}

const fn repeated(json: &'static str, proto: &'static str, kind: Kind) -> Field {
    Field {
        json,
        proto,
        kind,
        repeated: true,
        oneof: None,
    }
}

const fn one(json: &'static str, proto: &'static str, kind: Kind, oneof: &'static str) -> Field {
    Field {
        json,
        proto,
        kind,
        repeated: false,
        oneof: Some(oneof),
    }
}

static FIELD_OPERATOR: EnumSchema = EnumSchema {
    type_url: "type.googleapis.com/google.firestore.v1.StructuredQuery.FieldFilter.Operator",
    values: &[
        ("OPERATOR_UNSPECIFIED", 0),
        ("LESS_THAN", 1),
        ("LESS_THAN_OR_EQUAL", 2),
        ("GREATER_THAN", 3),
        ("GREATER_THAN_OR_EQUAL", 4),
        ("EQUAL", 5),
        ("NOT_EQUAL", 6),
        ("ARRAY_CONTAINS", 7),
        ("IN", 8),
        ("ARRAY_CONTAINS_ANY", 9),
        ("NOT_IN", 10),
    ],
};
static COMPOSITE_OPERATOR: EnumSchema = EnumSchema {
    type_url: "type.googleapis.com/google.firestore.v1.StructuredQuery.CompositeFilter.Operator",
    values: &[("OPERATOR_UNSPECIFIED", 0), ("AND", 1), ("OR", 2)],
};
static UNARY_OPERATOR: EnumSchema = EnumSchema {
    type_url: "type.googleapis.com/google.firestore.v1.StructuredQuery.UnaryFilter.Operator",
    values: &[
        ("OPERATOR_UNSPECIFIED", 0),
        ("IS_NAN", 2),
        ("IS_NULL", 3),
        ("IS_NOT_NAN", 4),
        ("IS_NOT_NULL", 5),
    ],
};
static DIRECTION: EnumSchema = EnumSchema {
    type_url: "type.googleapis.com/google.firestore.v1.StructuredQuery.Direction",
    values: &[
        ("DIRECTION_UNSPECIFIED", 0),
        ("ASCENDING", 1),
        ("DESCENDING", 2),
    ],
};
static DISTANCE_MEASURE: EnumSchema = EnumSchema {
    type_url: "type.googleapis.com/google.firestore.v1.StructuredQuery.FindNearest.DistanceMeasure",
    values: &[
        ("DISTANCE_MEASURE_UNSPECIFIED", 0),
        ("EUCLIDEAN", 1),
        ("COSINE", 2),
        ("DOT_PRODUCT", 3),
    ],
};
static NULL_VALUE: EnumSchema = EnumSchema {
    type_url: "type.googleapis.com/google.protobuf.NullValue",
    values: &[("NULL_VALUE", 0)],
};

static LAT_LNG: Schema = Schema {
    fields: &[
        f("latitude", "latitude", Kind::Double),
        f("longitude", "longitude", Kind::Double),
    ],
};
static ARRAY_VALUE: Schema = Schema {
    fields: &[repeated("values", "values", Kind::Message(&VALUE))],
};
static MAP_VALUE: Schema = Schema {
    fields: &[f("fields", "fields", Kind::ValueMap)],
};
static FUNCTION: Schema = Schema {
    fields: &[
        f("name", "name", Kind::Str),
        repeated("args", "args", Kind::Message(&VALUE)),
        f("options", "options", Kind::ValueMap),
    ],
};
static STAGE: Schema = Schema {
    fields: &[
        f("name", "name", Kind::Str),
        repeated("args", "args", Kind::Message(&VALUE)),
        f("options", "options", Kind::ValueMap),
    ],
};
static PIPELINE: Schema = Schema {
    fields: &[repeated("stages", "stages", Kind::Message(&STAGE))],
};
static VALUE: Schema = Schema {
    fields: &[
        one(
            "nullValue",
            "null_value",
            Kind::Enum(&NULL_VALUE),
            "value_type",
        ),
        one("booleanValue", "boolean_value", Kind::Bool, "value_type"),
        one("integerValue", "integer_value", Kind::Int64, "value_type"),
        one("doubleValue", "double_value", Kind::Double, "value_type"),
        one(
            "timestampValue",
            "timestamp_value",
            Kind::Timestamp,
            "value_type",
        ),
        one("stringValue", "string_value", Kind::Str, "value_type"),
        one("bytesValue", "bytes_value", Kind::Bytes, "value_type"),
        one("referenceValue", "reference_value", Kind::Str, "value_type"),
        one(
            "geoPointValue",
            "geo_point_value",
            Kind::Message(&LAT_LNG),
            "value_type",
        ),
        one(
            "arrayValue",
            "array_value",
            Kind::Message(&ARRAY_VALUE),
            "value_type",
        ),
        one(
            "mapValue",
            "map_value",
            Kind::Message(&MAP_VALUE),
            "value_type",
        ),
        one(
            "fieldReferenceValue",
            "field_reference_value",
            Kind::Str,
            "value_type",
        ),
        one(
            "variableReferenceValue",
            "variable_reference_value",
            Kind::Str,
            "value_type",
        ),
        one(
            "functionValue",
            "function_value",
            Kind::Message(&FUNCTION),
            "value_type",
        ),
        one(
            "pipelineValue",
            "pipeline_value",
            Kind::Message(&PIPELINE),
            "value_type",
        ),
    ],
};
static FIELD_REFERENCE: Schema = Schema {
    fields: &[f("fieldPath", "field_path", Kind::Str)],
};
static PROJECTION: Schema = Schema {
    fields: &[repeated(
        "fields",
        "fields",
        Kind::Message(&FIELD_REFERENCE),
    )],
};
static COLLECTION_SELECTOR: Schema = Schema {
    fields: &[
        f("collectionId", "collection_id", Kind::Str),
        f("allDescendants", "all_descendants", Kind::Bool),
    ],
};
static COMPOSITE_FILTER: Schema = Schema {
    fields: &[
        f("op", "op", Kind::Enum(&COMPOSITE_OPERATOR)),
        repeated("filters", "filters", Kind::Message(&FILTER)),
    ],
};
static FIELD_FILTER: Schema = Schema {
    fields: &[
        f("field", "field", Kind::Message(&FIELD_REFERENCE)),
        f("op", "op", Kind::Enum(&FIELD_OPERATOR)),
        f("value", "value", Kind::Message(&VALUE)),
    ],
};
static UNARY_FILTER: Schema = Schema {
    fields: &[
        f("op", "op", Kind::Enum(&UNARY_OPERATOR)),
        one(
            "field",
            "field",
            Kind::Message(&FIELD_REFERENCE),
            "operand_type",
        ),
    ],
};
static FILTER: Schema = Schema {
    fields: &[
        one(
            "compositeFilter",
            "composite_filter",
            Kind::Message(&COMPOSITE_FILTER),
            "filter_type",
        ),
        one(
            "fieldFilter",
            "field_filter",
            Kind::Message(&FIELD_FILTER),
            "filter_type",
        ),
        one(
            "unaryFilter",
            "unary_filter",
            Kind::Message(&UNARY_FILTER),
            "filter_type",
        ),
    ],
};
static ORDER: Schema = Schema {
    fields: &[
        f("field", "field", Kind::Message(&FIELD_REFERENCE)),
        f("direction", "direction", Kind::Enum(&DIRECTION)),
    ],
};
static CURSOR: Schema = Schema {
    fields: &[
        repeated("values", "values", Kind::Message(&VALUE)),
        f("before", "before", Kind::Bool),
    ],
};
static FIND_NEAREST: Schema = Schema {
    fields: &[
        f(
            "vectorField",
            "vector_field",
            Kind::Message(&FIELD_REFERENCE),
        ),
        f("queryVector", "query_vector", Kind::Message(&VALUE)),
        f(
            "distanceMeasure",
            "distance_measure",
            Kind::Enum(&DISTANCE_MEASURE),
        ),
        f("limit", "limit", Kind::Wrapper(Scalar::Int32)),
        f("distanceResultField", "distance_result_field", Kind::Str),
        f(
            "distanceThreshold",
            "distance_threshold",
            Kind::Wrapper(Scalar::Double),
        ),
    ],
};
static STRUCTURED_QUERY: Schema = Schema {
    fields: &[
        f("select", "select", Kind::Message(&PROJECTION)),
        repeated("from", "from", Kind::Message(&COLLECTION_SELECTOR)),
        f("where", "where", Kind::Message(&FILTER)),
        repeated("orderBy", "order_by", Kind::Message(&ORDER)),
        f("startAt", "start_at", Kind::Message(&CURSOR)),
        f("endAt", "end_at", Kind::Message(&CURSOR)),
        f("offset", "offset", Kind::Int32),
        f("limit", "limit", Kind::Wrapper(Scalar::Int32)),
        f("findNearest", "find_nearest", Kind::Message(&FIND_NEAREST)),
    ],
};
static COUNT: Schema = Schema {
    fields: &[f("upTo", "up_to", Kind::Wrapper(Scalar::Int64))],
};
static FIELD_AGGREGATION: Schema = Schema {
    fields: &[f("field", "field", Kind::Message(&FIELD_REFERENCE))],
};
static AGGREGATION: Schema = Schema {
    fields: &[
        one("count", "count", Kind::Message(&COUNT), "operator"),
        one("sum", "sum", Kind::Message(&FIELD_AGGREGATION), "operator"),
        one("avg", "avg", Kind::Message(&FIELD_AGGREGATION), "operator"),
        f("alias", "alias", Kind::Str),
    ],
};
static STRUCTURED_AGGREGATION_QUERY: Schema = Schema {
    fields: &[
        one(
            "structuredQuery",
            "structured_query",
            Kind::Message(&STRUCTURED_QUERY),
            "query_type",
        ),
        repeated("aggregations", "aggregations", Kind::Message(&AGGREGATION)),
    ],
};
static EXPLAIN_OPTIONS: Schema = Schema {
    fields: &[f("analyze", "analyze", Kind::Bool)],
};
static READ_ONLY: Schema = Schema {
    fields: &[one(
        "readTime",
        "read_time",
        Kind::Timestamp,
        "consistency_selector",
    )],
};
static READ_WRITE: Schema = Schema {
    fields: &[f("retryTransaction", "retry_transaction", Kind::Bytes)],
};
static TRANSACTION_OPTIONS: Schema = Schema {
    fields: &[
        one("readOnly", "read_only", Kind::Message(&READ_ONLY), "mode"),
        one(
            "readWrite",
            "read_write",
            Kind::Message(&READ_WRITE),
            "mode",
        ),
    ],
};
static RUN_QUERY: Schema = Schema {
    fields: &[
        f("parent", "parent", Kind::Str),
        one(
            "structuredQuery",
            "structured_query",
            Kind::Message(&STRUCTURED_QUERY),
            "query_type",
        ),
        one(
            "transaction",
            "transaction",
            Kind::Bytes,
            "consistency_selector",
        ),
        one(
            "newTransaction",
            "new_transaction",
            Kind::Message(&TRANSACTION_OPTIONS),
            "consistency_selector",
        ),
        one(
            "readTime",
            "read_time",
            Kind::Timestamp,
            "consistency_selector",
        ),
        f(
            "explainOptions",
            "explain_options",
            Kind::Message(&EXPLAIN_OPTIONS),
        ),
    ],
};
static RUN_AGGREGATION_QUERY: Schema = Schema {
    fields: &[
        f("parent", "parent", Kind::Str),
        one(
            "structuredAggregationQuery",
            "structured_aggregation_query",
            Kind::Message(&STRUCTURED_AGGREGATION_QUERY),
            "query_type",
        ),
        one(
            "transaction",
            "transaction",
            Kind::Bytes,
            "consistency_selector",
        ),
        one(
            "newTransaction",
            "new_transaction",
            Kind::Message(&TRANSACTION_OPTIONS),
            "consistency_selector",
        ),
        one(
            "readTime",
            "read_time",
            Kind::Timestamp,
            "consistency_selector",
        ),
        f(
            "explainOptions",
            "explain_options",
            Kind::Message(&EXPLAIN_OPTIONS),
        ),
    ],
};
static PARTITION_QUERY: Schema = Schema {
    fields: &[
        f("parent", "parent", Kind::Str),
        one(
            "structuredQuery",
            "structured_query",
            Kind::Message(&STRUCTURED_QUERY),
            "query_type",
        ),
        f("partitionCount", "partition_count", Kind::Int64),
        f("pageToken", "page_token", Kind::Str),
        f("pageSize", "page_size", Kind::Int32),
        one(
            "readTime",
            "read_time",
            Kind::Timestamp,
            "consistency_selector",
        ),
    ],
};

/// The request bodies this module checks, by REST custom method.
fn request_schema(method: &str) -> Option<&'static Schema> {
    match method {
        "runQuery" => Some(&RUN_QUERY),
        "runAggregationQuery" => Some(&RUN_AGGREGATION_QUERY),
        "partitionQuery" => Some(&PARTITION_QUERY),
        _ => None,
    }
}

/// Checks and normalizes the body of a REST custom `method`. Bodies of methods this module has
/// no schema for are returned unchanged.
pub fn check_body(method: &str, body: &Value) -> Result<Value, Status> {
    let Some(schema) = request_schema(method) else {
        return Ok(body.clone());
    };
    let Value::Object(object) = body else {
        return Err(crate::production_status::bad_request(&[(
            String::new(),
            "Invalid JSON payload received. Unknown name \"\": Root element must be a message."
                .to_owned(),
        )]));
    };
    let mut errors = Vec::new();
    let normalized = check_message(schema, object, "", &mut errors);
    if errors.is_empty() {
        Ok(Value::Object(normalized))
    } else {
        Err(crate::production_status::bad_request(&errors))
    }
}

fn join(path: &str, segment: &str) -> String {
    if path.is_empty() {
        segment.to_owned()
    } else {
        format!("{path}.{segment}")
    }
}

fn at(path: &str) -> String {
    if path.is_empty() {
        String::new()
    } else {
        format!(" at '{path}'")
    }
}

fn check_message(
    schema: &Schema,
    object: &Map<String, Value>,
    path: &str,
    errors: &mut Vec<(String, String)>,
) -> Map<String, Value> {
    let mut out = Map::new();
    let mut oneofs: Vec<&str> = Vec::new();
    for (key, value) in object {
        let Some(field) = schema
            .fields
            .iter()
            .find(|field| field.json == key || field.proto == key)
        else {
            errors.push((
                path.to_owned(),
                format!(
                    "Invalid JSON payload received. Unknown name \"{key}\"{}: Cannot find field.",
                    at(path)
                ),
            ));
            continue;
        };
        // proto3 JSON: null is the default value, whatever the type, except for
        // `google.protobuf.NullValue`, whose only value it is.
        let null_value =
            matches!(field.kind, Kind::Enum(schema) if schema.type_url == NULL_VALUE.type_url);
        if value.is_null() && !null_value {
            continue;
        }
        if let Some(oneof) = field.oneof {
            if oneofs.contains(&oneof) {
                let place = if path.is_empty() {
                    String::new()
                } else {
                    format!(" at '{path}'")
                };
                errors.push((
                    path.to_owned(),
                    format!(
                        "Invalid value{place} (oneof), oneof field '{oneof}' is already set. Cannot set '{key}'"
                    ),
                ));
                continue;
            }
            oneofs.push(oneof);
        }
        let field_path = join(path, field.proto);
        let normalized = if field.repeated {
            let Value::Array(items) = value else {
                errors.push((
                    field_path.clone(),
                    format!(
                        "Invalid value at '{field_path}' ({}), {value}",
                        kind_name(field.kind)
                    ),
                ));
                continue;
            };
            Value::Array(
                items
                    .iter()
                    .enumerate()
                    .map(|(index, item)| {
                        check_kind(field, item, &format!("{field_path}[{index}]"), errors)
                    })
                    .collect(),
            )
        } else {
            check_kind(field, value, &field_path, errors)
        };
        out.insert(field.json.to_owned(), normalized);
    }
    out
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Int32 | Kind::Wrapper(Scalar::Int32) => "TYPE_INT32",
        Kind::Int64 | Kind::Wrapper(Scalar::Int64) => "TYPE_INT64",
        Kind::Double | Kind::Wrapper(Scalar::Double) => "TYPE_DOUBLE",
        Kind::Bool => "TYPE_BOOL",
        Kind::Str => "TYPE_STRING",
        Kind::Bytes => "TYPE_BYTES",
        Kind::Enum(schema) => schema.type_url,
        Kind::Timestamp => "type.googleapis.com/google.protobuf.Timestamp",
        Kind::Message(_) | Kind::ValueMap => "TYPE_MESSAGE",
    }
}

fn check_kind(
    field: &Field,
    value: &Value,
    path: &str,
    errors: &mut Vec<(String, String)>,
) -> Value {
    match field.kind {
        Kind::Message(schema) => {
            if let Value::Object(object) = value {
                return Value::Object(check_message(schema, object, path, errors));
            }
        }
        Kind::ValueMap => {
            if let Value::Object(entries) = value {
                return Value::Object(
                    entries
                        .iter()
                        .map(|(key, entry)| {
                            let entry_path = format!("{path}[{key}]");
                            let normalized = match entry {
                                Value::Object(object) => Value::Object(check_message(
                                    &VALUE,
                                    object,
                                    &entry_path,
                                    errors,
                                )),
                                other => other.clone(),
                            };
                            (key.clone(), normalized)
                        })
                        .collect(),
                );
            }
        }
        // A wrapper may also be spelled as its message, `{"value": ...}`.
        Kind::Wrapper(_)
            if value
                .as_object()
                .is_some_and(|o| o.len() == 1 && o.contains_key("value")) =>
        {
            return check_kind(field, &value["value"], path, errors);
        }
        Kind::Wrapper(scalar) => {
            let inner = Field {
                kind: match scalar {
                    Scalar::Int32 => Kind::Int32,
                    Scalar::Int64 => Kind::Int64,
                    Scalar::Double => Kind::Double,
                },
                ..*field
            };
            return check_kind(&inner, value, &format!("{path}.value"), errors);
        }
        Kind::Timestamp => {
            if let Value::String(text) = value {
                if let Some(problem) = timestamp_problem(text) {
                    errors.push((
                        path.to_owned(),
                        format!(
                            "Invalid value at '{path}' (type.googleapis.com/google.protobuf.Timestamp), Field '{}', {problem}",
                            field.json
                        ),
                    ));
                }
                return value.clone();
            }
        }
        kind => {
            if let Some(normalized) = check_scalar(kind, value) {
                return normalized;
            }
        }
    }
    errors.push((
        path.to_owned(),
        format!(
            "Invalid value at '{path}' ({}), {value}",
            kind_name(field.kind)
        ),
    ));
    value.clone()
}

/// The normalized form of a scalar or enum value, or `None` when the transcoder refuses it.
fn check_scalar(kind: Kind, value: &Value) -> Option<Value> {
    match kind {
        Kind::Enum(_) if value.is_null() => Some(Value::Null),
        // A name must be known; a number passes whatever it is, as on the wire.
        Kind::Enum(schema) => match value {
            Value::Number(number) if number.as_i64().is_some() => Some(
                enum_name(schema, value)
                    .map_or_else(|| value.clone(), |name| Value::String(name.to_owned())),
            ),
            _ => enum_name(schema, value).map(|name| Value::String(name.to_owned())),
        },
        Kind::Int32 => integer(value, i64::from(i32::MIN), i64::from(i32::MAX)).map(Value::from),
        Kind::Int64 => integer(value, i64::MIN, i64::MAX).map(|n| Value::String(n.to_string())),
        Kind::Bool => match value {
            Value::Bool(_) => Some(value.clone()),
            Value::String(text) if text == "true" || text == "false" => {
                Some(Value::Bool(text == "true"))
            }
            _ => None,
        },
        Kind::Double => match value {
            Value::Number(_) => Some(value.clone()),
            Value::String(text)
                if matches!(text.as_str(), "NaN" | "Infinity" | "-Infinity")
                    || text.parse::<f64>().is_ok_and(f64::is_finite) =>
            {
                Some(value.clone())
            }
            _ => None,
        },
        Kind::Str | Kind::Bytes => value.is_string().then(|| value.clone()),
        Kind::Message(_) | Kind::ValueMap | Kind::Timestamp | Kind::Wrapper(_) => None,
    }
}

/// The canonical name of an enum value given by name (in any case) or by number.
fn enum_name(schema: &EnumSchema, value: &Value) -> Option<&'static str> {
    match value {
        Value::String(text) => schema
            .values
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(text))
            .map(|(name, _)| *name),
        Value::Number(number) => {
            let number = number.as_i64()?;
            schema
                .values
                .iter()
                .find(|(_, value)| *value == number)
                .map(|(name, _)| *name)
        }
        _ => None,
    }
}

/// An integer from a JSON number or a decimal string, within `min..=max`.
fn integer(value: &Value, min: i64, max: i64) -> Option<i64> {
    let parsed = match value {
        Value::Number(number) => number.as_i64().or_else(|| {
            number
                .as_f64()
                .filter(|f| f.fract() == 0.0 && f.abs() < 9.0e18)
                .map(|f| {
                    #[allow(clippy::cast_possible_truncation)]
                    let whole = f as i64;
                    whole
                })
        })?,
        Value::String(text) => text.parse::<i64>().ok()?,
        _ => return None,
    };
    (min..=max).contains(&parsed).then_some(parsed)
}

/// Why production's transcoder refuses an RFC 3339 timestamp, if it does.
fn timestamp_problem(text: &str) -> Option<&'static str> {
    let bytes = text.as_bytes();
    let offset_ok = text.ends_with('Z')
        || (bytes.len() > 6
            && matches!(bytes[bytes.len() - 6], b'+' | b'-')
            && bytes[bytes.len() - 3] == b':');
    if !offset_ok {
        return Some(
            "Illegal timestamp format; timestamps must end with 'Z' or have a valid timezone offset.",
        );
    }
    let year = text.split('-').next().unwrap_or_default();
    if year.len() > 4 || year.parse::<u32>().is_ok_and(|y| y == 0) {
        return Some("Timestamp value exceeds limits");
    }
    None
}

/// Parses a request body as production's transcoder does: a trailing comma before a closing
/// bracket or brace is accepted (FS-QUERY-INDEX request-shape#body-trailing-comma).
pub fn parse_body(body: &[u8]) -> Result<Value, serde_json::Error> {
    serde_json::from_slice(body).or_else(|error| {
        let text = String::from_utf8_lossy(body);
        let lenient = without_trailing_commas(&text);
        if lenient == text {
            return Err(error);
        }
        serde_json::from_str(&lenient).map_err(|_| error)
    })
}

/// `text` with every comma that only whitespace separates from a closing `]` or `}` removed,
/// outside string literals.
fn without_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    for (i, &c) in chars.iter().enumerate() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        if c == '"' {
            in_string = true;
        } else if c == ',' {
            let next = chars[i + 1..].iter().find(|c| !c.is_whitespace());
            if matches!(next, Some(']' | '}')) {
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// The transcoder's refusal of a body that is not JSON: the token it stopped at, echoed with
/// its line and a caret under the column, or the end of the body.
#[must_use]
pub fn syntax_error_message(body: &[u8], error: &serde_json::Error) -> String {
    if error.is_eof() {
        return "Invalid JSON payload received. Unexpected end of string. Expected a value.\n\n^"
            .to_owned();
    }
    let text = String::from_utf8_lossy(body);
    let line = text
        .lines()
        .nth(error.line().saturating_sub(1))
        .unwrap_or_default();
    // The transcoder points at the start of the token it could not read; serde_json reports
    // the character after the part of it that it read.
    let mut column = error.column().saturating_sub(1).min(line.len());
    while column > 0
        && line
            .as_bytes()
            .get(column - 1)
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        column -= 1;
    }
    format!(
        "Invalid JSON payload received. Unexpected token.\n{line}\n{}^",
        " ".repeat(column.min(line.len()))
    )
}

/// Whether a REST path names a method whose answers, errors included, are a JSON array.
#[must_use]
pub fn is_streaming_method(path: &str) -> bool {
    [":runQuery", ":runAggregationQuery", ":executePipeline"]
        .iter()
        .any(|method| path.ends_with(method))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn refusal(method: &str, body: &Value) -> String {
        check_body(method, body).unwrap_err().message().to_owned()
    }

    // Texts recorded from production on 2026-09-24 (FS-QUERY-INDEX).
    #[test]
    fn unknown_fields_are_refused_with_their_path() {
        assert_eq!(
            refusal(
                "runQuery",
                &json!({"structuredQuery": {"from": []}, "extra": 1})
            ),
            "Invalid JSON payload received. Unknown name \"extra\": Cannot find field."
        );
        assert_eq!(
            refusal("runQuery", &json!({"structuredQuery": {"extra": 1}})),
            "Invalid JSON payload received. Unknown name \"extra\" at 'structured_query': Cannot find field."
        );
        assert_eq!(
            refusal("runQuery", &json!({"explainOptions": {"verbose": true}})),
            "Invalid JSON payload received. Unknown name \"verbose\" at 'explain_options': Cannot find field."
        );
        assert_eq!(
            refusal(
                "runQuery",
                &json!({"structuredQuery": {"where": {"fieldFilter": {"value": {"futureValue": 1}}}}})
            ),
            "Invalid JSON payload received. Unknown name \"futureValue\" at 'structured_query.where.field_filter.value': Cannot find field."
        );
        assert_eq!(
            refusal("runAggregationQuery", &json!({"structuredAggregationQuery": {"extra": 1}})),
            "Invalid JSON payload received. Unknown name \"extra\" at 'structured_aggregation_query': Cannot find field."
        );
        assert_eq!(
            refusal("runQuery", &json!([])),
            "Invalid JSON payload received. Unknown name \"\": Root element must be a message."
        );
    }

    #[test]
    fn scalar_enum_and_oneof_values_are_refused_like_production() {
        assert_eq!(
            refusal(
                "runQuery",
                &json!({"structuredQuery": {"limit": 2_147_483_648_i64}})
            ),
            "Invalid value at 'structured_query.limit.value' (TYPE_INT32), 2147483648"
        );
        assert_eq!(
            refusal("runQuery", &json!({"structuredQuery": {"limit": 1.5}})),
            "Invalid value at 'structured_query.limit.value' (TYPE_INT32), 1.5"
        );
        assert_eq!(
            refusal(
                "runQuery",
                &json!({"structuredQuery": {"where": {"fieldFilter": {"op": "SIMILAR_TO"}}}})
            ),
            "Invalid value at 'structured_query.where.field_filter.op' (type.googleapis.com/google.firestore.v1.StructuredQuery.FieldFilter.Operator), \"SIMILAR_TO\""
        );
        assert_eq!(
            refusal(
                "runQuery",
                &json!({"structuredQuery": {"orderBy": [{"direction": "SIDEWAYS"}]}})
            ),
            "Invalid value at 'structured_query.order_by[0].direction' (type.googleapis.com/google.firestore.v1.StructuredQuery.Direction), \"SIDEWAYS\""
        );
        assert_eq!(
            refusal(
                "runQuery",
                &json!({"structuredQuery": {"where": {"fieldFilter": {"value": {"integerValue": "9223372036854775808"}}}}})
            ),
            "Invalid value at 'structured_query.where.field_filter.value.integer_value' (TYPE_INT64), \"9223372036854775808\""
        );
        assert_eq!(
            refusal(
                "runQuery",
                &json!({"structuredQuery": {"where": {"fieldFilter": {"value": {"integerValue": "1", "stringValue": "a"}}}}})
            ),
            "Invalid value at 'structured_query.where.field_filter.value' (oneof), oneof field 'value_type' is already set. Cannot set 'stringValue'"
        );
        assert_eq!(
            refusal(
                "runQuery",
                &json!({"structuredQuery": {"where": {"fieldFilter": {"value": {"timestampValue": "10000-01-01T00:00:00Z"}}}}})
            ),
            "Invalid value at 'structured_query.where.field_filter.value.timestamp_value' (type.googleapis.com/google.protobuf.Timestamp), Field 'timestampValue', Timestamp value exceeds limits"
        );
        assert_eq!(
            refusal("runQuery", &json!({"readTime": "yesterday"})),
            "Invalid value at 'read_time' (type.googleapis.com/google.protobuf.Timestamp), Field 'readTime', Illegal timestamp format; timestamps must end with 'Z' or have a valid timezone offset."
        );
    }

    #[test]
    fn accepted_spellings_are_normalized() {
        let body = check_body(
            "runQuery",
            &json!({"structuredQuery": {
                "where": {"fieldFilter": {"field": {"fieldPath": "n"}, "op": "equal", "value": {"integerValue": 1}}},
                "orderBy": [{"field": {"fieldPath": "n"}, "direction": 2}],
                "limit": "3",
            }, "explainOptions": {"analyze": "true"}}),
        )
        .unwrap();
        assert_eq!(
            body,
            json!({"structuredQuery": {
                "where": {"fieldFilter": {"field": {"fieldPath": "n"}, "op": "EQUAL", "value": {"integerValue": "1"}}},
                "orderBy": [{"field": {"fieldPath": "n"}, "direction": "DESCENDING"}],
                "limit": 3,
            }, "explainOptions": {"analyze": true}})
        );
    }

    #[test]
    fn a_body_that_is_not_json_echoes_the_token() {
        let error = serde_json::from_slice::<Value>(b"not json").unwrap_err();
        assert_eq!(
            syntax_error_message(b"not json", &error),
            "Invalid JSON payload received. Unexpected token.\nnot json\n^"
        );
    }
}
