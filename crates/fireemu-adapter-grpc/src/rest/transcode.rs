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

use core::fmt::Write as _;

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
    /// The message's type URL, which the transcoder names in a type error.
    type_url: &'static str,
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
    type_url: "type.googleapis.com/google.type.LatLng",
    fields: &[
        f("latitude", "latitude", Kind::Double),
        f("longitude", "longitude", Kind::Double),
    ],
};
static ARRAY_VALUE: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.ArrayValue",
    fields: &[repeated("values", "values", Kind::Message(&VALUE))],
};
static MAP_VALUE: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.MapValue",
    fields: &[f("fields", "fields", Kind::ValueMap)],
};
static FUNCTION: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.Function",
    fields: &[
        f("name", "name", Kind::Str),
        repeated("args", "args", Kind::Message(&VALUE)),
        f("options", "options", Kind::ValueMap),
    ],
};
static STAGE: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.Pipeline.Stage",
    fields: &[
        f("name", "name", Kind::Str),
        repeated("args", "args", Kind::Message(&VALUE)),
        f("options", "options", Kind::ValueMap),
    ],
};
static PIPELINE: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.Pipeline",
    fields: &[repeated("stages", "stages", Kind::Message(&STAGE))],
};
static VALUE: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.Value",
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
    type_url: "type.googleapis.com/google.firestore.v1.StructuredQuery.FieldReference",
    fields: &[f("fieldPath", "field_path", Kind::Str)],
};
static PROJECTION: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.StructuredQuery.Projection",
    fields: &[repeated(
        "fields",
        "fields",
        Kind::Message(&FIELD_REFERENCE),
    )],
};
static COLLECTION_SELECTOR: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.StructuredQuery.CollectionSelector",
    fields: &[
        f("collectionId", "collection_id", Kind::Str),
        f("allDescendants", "all_descendants", Kind::Bool),
    ],
};
static COMPOSITE_FILTER: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.StructuredQuery.CompositeFilter",
    fields: &[
        f("op", "op", Kind::Enum(&COMPOSITE_OPERATOR)),
        repeated("filters", "filters", Kind::Message(&FILTER)),
    ],
};
static FIELD_FILTER: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.StructuredQuery.FieldFilter",
    fields: &[
        f("field", "field", Kind::Message(&FIELD_REFERENCE)),
        f("op", "op", Kind::Enum(&FIELD_OPERATOR)),
        f("value", "value", Kind::Message(&VALUE)),
    ],
};
static UNARY_FILTER: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.StructuredQuery.UnaryFilter",
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
    type_url: "type.googleapis.com/google.firestore.v1.StructuredQuery.Filter",
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
    type_url: "type.googleapis.com/google.firestore.v1.StructuredQuery.Order",
    fields: &[
        f("field", "field", Kind::Message(&FIELD_REFERENCE)),
        f("direction", "direction", Kind::Enum(&DIRECTION)),
    ],
};
static CURSOR: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.Cursor",
    fields: &[
        repeated("values", "values", Kind::Message(&VALUE)),
        f("before", "before", Kind::Bool),
    ],
};
static FIND_NEAREST: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.StructuredQuery.FindNearest",
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
    type_url: "type.googleapis.com/google.firestore.v1.StructuredQuery",
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
    type_url:
        "type.googleapis.com/google.firestore.v1.StructuredAggregationQuery.Aggregation.Count",
    fields: &[f("upTo", "up_to", Kind::Wrapper(Scalar::Int64))],
};
const FIELD_AGGREGATION_FIELDS: &[Field] = &[f("field", "field", Kind::Message(&FIELD_REFERENCE))];
static SUM: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.StructuredAggregationQuery.Aggregation.Sum",
    fields: FIELD_AGGREGATION_FIELDS,
};
static AVG: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.StructuredAggregationQuery.Aggregation.Avg",
    fields: FIELD_AGGREGATION_FIELDS,
};
static AGGREGATION: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.StructuredAggregationQuery.Aggregation",
    fields: &[
        one("count", "count", Kind::Message(&COUNT), "operator"),
        one("sum", "sum", Kind::Message(&SUM), "operator"),
        one("avg", "avg", Kind::Message(&AVG), "operator"),
        f("alias", "alias", Kind::Str),
    ],
};
static STRUCTURED_AGGREGATION_QUERY: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.StructuredAggregationQuery",
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
    type_url: "type.googleapis.com/google.firestore.v1.ExplainOptions",
    fields: &[f("analyze", "analyze", Kind::Bool)],
};
static READ_ONLY: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.TransactionOptions.ReadOnly",
    fields: &[one(
        "readTime",
        "read_time",
        Kind::Timestamp,
        "consistency_selector",
    )],
};
static READ_WRITE: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.TransactionOptions.ReadWrite",
    fields: &[f("retryTransaction", "retry_transaction", Kind::Bytes)],
};
static TRANSACTION_OPTIONS: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.TransactionOptions",
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
    type_url: "type.googleapis.com/google.firestore.v1.RunQueryRequest",
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
    type_url: "type.googleapis.com/google.firestore.v1.RunAggregationQueryRequest",
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
    type_url: "type.googleapis.com/google.firestore.v1.PartitionQueryRequest",
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

static REQUEST_OPTIONS: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.RequestOptions",
    fields: &[repeated("requestTags", "request_tags", Kind::Str)],
};
static LIST_COLLECTION_IDS: Schema = Schema {
    type_url: "type.googleapis.com/google.firestore.v1.ListCollectionIdsRequest",
    fields: &[
        f("parent", "parent", Kind::Str),
        f("pageSize", "page_size", Kind::Int32),
        f("pageToken", "page_token", Kind::Str),
        one(
            "readTime",
            "read_time",
            Kind::Timestamp,
            "consistency_selector",
        ),
        f(
            "requestOptions",
            "request_options",
            Kind::Message(&REQUEST_OPTIONS),
        ),
    ],
};

/// The request bodies this module checks, by REST custom method.
fn request_schema(method: &str) -> Option<&'static Schema> {
    match method {
        "runQuery" => Some(&RUN_QUERY),
        "runAggregationQuery" => Some(&RUN_AGGREGATION_QUERY),
        "partitionQuery" => Some(&PARTITION_QUERY),
        "listCollectionIds" => Some(&LIST_COLLECTION_IDS),
        _ => None,
    }
}

/// The JSON names of `google.firestore.v1.Document`.
const DOCUMENT_KEYS: &[&str] = &[
    "name",
    "fields",
    "createTime",
    "create_time",
    "updateTime",
    "update_time",
];

/// Refuses a `Document` body (mapped at `at`) with a key the message does not have, as
/// production's transcoder does (FS-QUERY-INDEX request-shape/rest#parent-is-collection). The
/// values are left to the document decoder.
pub fn check_document_keys(body: &Value, at: &str) -> Result<(), Status> {
    let Value::Object(object) = body else {
        return Ok(());
    };
    // Every unknown key, as the transcoder lists them, within the same bounds.
    let violations: Vec<(String, String)> = object
        .keys()
        .filter(|key| !DOCUMENT_KEYS.contains(&key.as_str()))
        .take(MAX_VIOLATIONS)
        .map(|key| {
            (
                at.to_owned(),
                format!(
                    "Invalid JSON payload received. Unknown name \"{}\" at '{at}': Cannot find field.",
                    echo(key)
                ),
            )
        })
        .collect();
    if violations.is_empty() {
        Ok(())
    } else {
        Err(crate::production_status::bad_request(&violations))
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
    let mut checker = Checker::default();
    let normalized = checker.message(schema, object);
    if checker.violations.is_empty() {
        Ok(Value::Object(normalized))
    } else {
        Err(crate::production_status::bad_request(&checker.violations))
    }
}

/// The most violations one refusal lists. Production's transcoder keeps going after a
/// violation (firestore-production-matrix programs 10 and 11 add a second line, for the
/// URL-bound database name, after a oneof conflict in the body); whether it lists several
/// violations of one body is unrecorded (follow-ups). Past this many the walk stops, so a
/// body of many bad items costs what a body with a few does.
const MAX_VIOLATIONS: usize = 16;
/// The most bytes of a value, key or path one violation echoes; a longer one ends in `...`.
/// Every recorded refusal echoes a short value. The bound all refusal texts share.
const MAX_ECHO: usize = fireemu_core_types::codec::MAX_ECHO_BYTES;

/// A `fmt::Write` that keeps the first [`MAX_ECHO`] bytes and stops the formatting after them.
struct Bounded(String);

impl core::fmt::Write for Bounded {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let room = MAX_ECHO.saturating_sub(self.0.len());
        if text.len() <= room {
            self.0.push_str(text);
            return Ok(());
        }
        let mut end = room;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        self.0.push_str(&text[..end]);
        self.0.push_str("...");
        Err(core::fmt::Error)
    }
}

/// `value` as the refusal echoes it: its display, cut at [`MAX_ECHO`] bytes.
pub(crate) fn echo(value: &dyn core::fmt::Display) -> String {
    let mut out = Bounded(String::new());
    let _ = write!(out, "{value}");
    out.0
}

/// One step of the path the transcoder names in a refusal.
#[derive(Clone, Copy)]
enum Segment<'a> {
    /// A field, by its proto name (`structured_query`).
    Field(&'a str),
    /// An element of a repeated field (`[3]`).
    Index(usize),
    /// An entry of a map field (`[key]`).
    Key(&'a str),
}

/// Walks a body against its schema, collecting violations as production's transcoder does.
/// The path is kept as segments and rendered only for a violation, what a violation echoes is
/// bounded, and the walk stops after [`MAX_VIOLATIONS`].
#[derive(Default)]
struct Checker<'a> {
    path: Vec<Segment<'a>>,
    violations: Vec<(String, String)>,
}

impl<'a> Checker<'a> {
    fn full(&self) -> bool {
        self.violations.len() >= MAX_VIOLATIONS
    }

    fn rendered_path(&self) -> String {
        let mut out = Bounded(String::new());
        for segment in &self.path {
            let written = match segment {
                Segment::Field(name) if out.0.is_empty() => out.write_str(name),
                Segment::Field(name) => write!(out, ".{name}"),
                Segment::Index(index) => write!(out, "[{index}]"),
                Segment::Key(key) => write!(out, "[{key}]"),
            };
            if written.is_err() {
                break;
            }
        }
        out.0
    }

    fn refuse(&mut self, description: String) {
        if !self.full() {
            let path = self.rendered_path();
            self.violations.push((path, description));
        }
    }

    /// `Invalid value at '<path>' (<type>), <value>`.
    fn refuse_value(&mut self, kind: Kind, value: &Value) {
        if !self.full() {
            let path = self.rendered_path();
            let description = format!(
                "Invalid value at '{path}' ({}), {}",
                kind_name(kind),
                echo(value)
            );
            self.violations.push((path, description));
        }
    }

    fn message(&mut self, schema: &Schema, object: &'a Map<String, Value>) -> Map<String, Value> {
        let mut out = Map::new();
        let mut oneofs: Vec<&str> = Vec::new();
        for (key, value) in object {
            if self.full() {
                break;
            }
            let Some(field) = schema
                .fields
                .iter()
                .find(|field| field.json == key || field.proto == key)
            else {
                let path = self.rendered_path();
                self.refuse(format!(
                    "Invalid JSON payload received. Unknown name \"{}\"{}: Cannot find field.",
                    echo(key),
                    at(&path)
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
                    let path = self.rendered_path();
                    self.refuse(format!(
                        "Invalid value{} (oneof), oneof field '{oneof}' is already set. Cannot set '{}'",
                        at(&path),
                        echo(key)
                    ));
                    continue;
                }
                oneofs.push(oneof);
            }
            self.path.push(Segment::Field(field.proto));
            let normalized = if field.repeated {
                if let Value::Array(items) = value {
                    let mut checked = Vec::with_capacity(items.len());
                    for (index, item) in items.iter().enumerate() {
                        if self.full() {
                            break;
                        }
                        self.path.push(Segment::Index(index));
                        checked.push(self.kind(field, item));
                        self.path.pop();
                    }
                    Value::Array(checked)
                } else {
                    self.refuse_value(field.kind, value);
                    Value::Null
                }
            } else {
                self.kind(field, value)
            };
            self.path.pop();
            out.insert(field.json.to_owned(), normalized);
        }
        out
    }

    fn kind(&mut self, field: &Field, value: &'a Value) -> Value {
        match field.kind {
            Kind::Message(schema) => {
                if let Value::Object(object) = value {
                    return Value::Object(self.message(schema, object));
                }
            }
            Kind::ValueMap => {
                if let Value::Object(entries) = value {
                    let mut checked = Map::new();
                    for (key, entry) in entries {
                        if self.full() {
                            break;
                        }
                        let normalized = match entry {
                            Value::Object(object) => {
                                self.path.push(Segment::Key(key));
                                let normalized = Value::Object(self.message(&VALUE, object));
                                self.path.pop();
                                normalized
                            }
                            other => other.clone(),
                        };
                        checked.insert(key.clone(), normalized);
                    }
                    return Value::Object(checked);
                }
            }
            // A wrapper may also be spelled as its message, `{"value": ...}`.
            Kind::Wrapper(_)
                if value
                    .as_object()
                    .is_some_and(|o| o.len() == 1 && o.contains_key("value")) =>
            {
                return self.kind(field, &value["value"]);
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
                self.path.push(Segment::Field("value"));
                let normalized = self.kind(&inner, value);
                self.path.pop();
                return normalized;
            }
            Kind::Timestamp => {
                if let Value::String(text) = value {
                    if let Some(problem) = timestamp_problem(text) {
                        let path = self.rendered_path();
                        self.refuse(format!(
                            "Invalid value at '{path}' (type.googleapis.com/google.protobuf.Timestamp), Field '{}', {problem}",
                            field.json
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
        self.refuse_value(field.kind, value);
        Value::Null
    }
}

fn at(path: &str) -> String {
    if path.is_empty() {
        String::new()
    } else {
        format!(" at '{path}'")
    }
}

/// The type the transcoder names for a value it cannot convert: the scalar's proto type, or
/// the message's type URL (a repeated field names its element type).
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
        Kind::Message(schema) => schema.type_url,
        Kind::ValueMap => "type.googleapis.com/google.firestore.v1.MapValue.FieldsEntry",
    }
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

/// Why production's transcoder refuses an RFC 3339 timestamp, if it does. A fraction of more
/// than nine digits is out of range (FS-DATA-WRITE-LIST read-time#read-time-ten-digits).
pub(crate) fn timestamp_problem(text: &str) -> Option<&'static str> {
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
    let fraction_digits = text.split_once('.').map_or(0, |(_, rest)| {
        rest.bytes().take_while(u8::is_ascii_digit).count()
    });
    if year.len() > 4 || year.parse::<u32>().is_ok_and(|y| y == 0) || fraction_digits > 9 {
        return Some("Timestamp value exceeds limits");
    }
    None
}

/// Parses a request body as production's front end does (see [`super::json_syntax`]).
pub fn parse_body(body: &[u8]) -> Result<Value, super::json_syntax::SyntaxError> {
    super::json_syntax::parse(body)
}

/// The front end's refusal of a body that is not JSON.
#[must_use]
pub fn syntax_error_message(body: &[u8], error: &super::json_syntax::SyntaxError) -> String {
    error.render(body)
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
        let error = parse_body(b"not json").unwrap_err();
        assert_eq!(
            syntax_error_message(b"not json", &error),
            "Invalid JSON payload received. Unexpected token.\nnot json\n^"
        );
    }

    #[test]
    fn document_bodies_take_only_document_keys() {
        for key in DOCUMENT_KEYS {
            assert!(
                check_document_keys(&json!({ *key: null }), "document").is_ok(),
                "{key}"
            );
        }
        assert!(check_document_keys(&json!("not an object"), "document").is_ok());
        // Every unknown key, joined by newlines as the transcoder joins its violations.
        let status =
            check_document_keys(&json!({"a": 1, "fields": {}, "b": 2}), "document").unwrap_err();
        assert_eq!(
            status.message(),
            "Invalid JSON payload received. Unknown name \"a\" at 'document': Cannot find field.\n\
             Invalid JSON payload received. Unknown name \"b\" at 'document': Cannot find field."
        );
    }

    /// A body of many bad items costs what a body with a few does: at most `MAX_VIOLATIONS`
    /// violations, each echoing at most `MAX_ECHO` bytes, and no path built for the items
    /// that are fine (safety review M1, re-review MF1).
    #[test]
    fn a_body_of_many_bad_items_is_refused_within_bounds() {
        let many = vec![json!(1); 1_000_000];
        let status =
            check_body("runQuery", &json!({"structuredQuery": {"from": many}})).unwrap_err();
        let lines: Vec<&str> = status.message().split('\n').collect();
        assert_eq!(lines.len(), MAX_VIOLATIONS);
        assert_eq!(
            lines[0],
            "Invalid value at 'structured_query.from[0]' (type.googleapis.com/google.firestore.v1.StructuredQuery.CollectionSelector), 1"
        );
        // Long values, keys and map keys are echoed only in part.
        let control = "\u{1}".repeat(8 << 20);
        for body in [
            json!({"structuredQuery": {"from": control.clone()}}),
            json!({"structuredQuery": {control.clone(): 1}}),
            json!({"structuredQuery": {"where": {"fieldFilter": {"field": {"fieldPath": "a"}, "op": "EQUAL",
                "value": {"mapValue": {"fields": {control.clone(): {"integerValue": []}}}}}}}}),
        ] {
            let status = check_body("runQuery", &body).unwrap_err();
            assert!(
                status.message().len() < 4 * MAX_ECHO,
                "{}",
                status.message().len()
            );
        }
        let status = check_document_keys(&json!({control.clone(): 1}), "document").unwrap_err();
        assert!(status.message().len() < 2 * MAX_ECHO);
        let key = "k".repeat(1 << 20);
        let values = vec![json!({}); 200_000];
        let body = json!({"structuredQuery": {"where": {"fieldFilter": {
            "field": {"fieldPath": "a"}, "op": "EQUAL",
            "value": {"mapValue": {"fields": {key.clone(): {"arrayValue": {"values": values}}}}}
        }}}});
        let started = std::time::Instant::now();
        assert!(check_body("runQuery", &body).is_ok());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        let mut bad = body;
        bad["structuredQuery"]["where"]["fieldFilter"]["value"]["mapValue"]["fields"][&key]
            ["arrayValue"]["values"][150_000] = json!(1);
        let status = check_body("runQuery", &bad).unwrap_err();
        // The path holds the 1 MiB key, so it is echoed only in part.
        assert!(status
            .message()
            .ends_with("...' (type.googleapis.com/google.firestore.v1.Value), 1"));
        assert!(status.message().len() < 4 * MAX_ECHO);
    }
}
