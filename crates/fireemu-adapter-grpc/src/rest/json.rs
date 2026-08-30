//! Firestore REST JSON <-> protobuf mapping (the documented proto3 JSON form of the
//! `google.firestore.v1` messages, restricted to what the local backend serves).

use std::collections::HashMap;

use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use fireemu_proto_firestore::google::firestore::v1::structured_query as sq;
use serde_json::{json, Map, Value};

use crate::encode::{decode_instant, encode_instant};

/// A malformed JSON request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError(pub String);

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, JsonError> {
    Err(JsonError(msg.into()))
}

// ------------------------------------------------------------------------------------------
// base64 (standard alphabet, padded) — the proto3 JSON encoding of `bytes`
// ------------------------------------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
#[must_use]
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Standard or URL-safe base64, padding optional.
pub fn base64_decode(text: &str) -> Result<Vec<u8>, JsonError> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\n' | b'\r' => continue,
            _ => return err("invalid base64"),
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).unwrap_or(0));
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------
// timestamps
// ------------------------------------------------------------------------------------------

fn timestamp_to_json(t: &prost_types::Timestamp) -> Value {
    Value::String(
        decode_instant(t)
            .to_rfc3339()
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
    )
}

fn timestamp_from_json(v: &Value) -> Result<prost_types::Timestamp, JsonError> {
    let Some(s) = v.as_str() else {
        return err("timestamp must be an RFC 3339 string");
    };
    LogicalInstant::parse_rfc3339(s)
        .map(encode_instant)
        .map_err(|e| JsonError(format!("invalid timestamp {s:?}: {e}")))
}

// ------------------------------------------------------------------------------------------
// values and documents
// ------------------------------------------------------------------------------------------

/// Protobuf value → JSON.
#[must_use]
pub fn value_to_json(v: &pb::Value) -> Value {
    use pb::value::ValueType as V;
    match &v.value_type {
        // Pipeline expression values never come out of the local backend.
        None
        | Some(
            V::NullValue(_)
            | V::FieldReferenceValue(_)
            | V::VariableReferenceValue(_)
            | V::FunctionValue(_)
            | V::PipelineValue(_),
        ) => json!({"nullValue": null}),
        Some(V::BooleanValue(b)) => json!({"booleanValue": b}),
        Some(V::IntegerValue(i)) => json!({"integerValue": i.to_string()}),
        Some(V::DoubleValue(d)) => {
            if d.is_nan() {
                json!({"doubleValue": "NaN"})
            } else if d.is_infinite() {
                json!({"doubleValue": if *d > 0.0 { "Infinity" } else { "-Infinity" }})
            } else {
                json!({"doubleValue": d})
            }
        }
        Some(V::TimestampValue(t)) => json!({"timestampValue": timestamp_to_json(t)}),
        Some(V::StringValue(s)) => json!({"stringValue": s}),
        Some(V::BytesValue(b)) => json!({"bytesValue": base64_encode(b)}),
        Some(V::ReferenceValue(r)) => json!({"referenceValue": r}),
        Some(V::GeoPointValue(g)) => {
            json!({"geoPointValue": {"latitude": g.latitude, "longitude": g.longitude}})
        }
        Some(V::ArrayValue(a)) => {
            json!({"arrayValue": {"values": a.values.iter().map(value_to_json).collect::<Vec<_>>()}})
        }
        Some(V::MapValue(m)) => {
            let fields: Map<String, Value> = m
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), value_to_json(v)))
                .collect();
            json!({"mapValue": {"fields": fields}})
        }
    }
}

/// JSON → protobuf value.
pub fn value_from_json(v: &Value) -> Result<pb::Value, JsonError> {
    use pb::value::ValueType as V;
    let Some(obj) = v.as_object() else {
        return err("a value must be an object with exactly one *Value key");
    };
    if obj.len() != 1 {
        return err("a value must have exactly one *Value key");
    }
    let (key, inner) = obj
        .iter()
        .next()
        .map_or(("", &Value::Null), |(k, v)| (k.as_str(), v));
    let value_type = match key {
        "nullValue" => V::NullValue(0),
        "booleanValue" => V::BooleanValue(
            inner
                .as_bool()
                .ok_or_else(|| JsonError("booleanValue must be a boolean".into()))?,
        ),
        "integerValue" => V::IntegerValue(match inner {
            Value::String(s) => s
                .parse::<i64>()
                .map_err(|_| JsonError(format!("integerValue {s:?} is not an int64")))?,
            Value::Number(n) => n
                .as_i64()
                .ok_or_else(|| JsonError("integerValue must be an int64".into()))?,
            _ => return err("integerValue must be a string or number"),
        }),
        "doubleValue" => V::DoubleValue(match inner {
            Value::Number(n) => n
                .as_f64()
                .ok_or_else(|| JsonError("doubleValue must be a number".into()))?,
            Value::String(s) => match s.as_str() {
                "NaN" => f64::NAN,
                "Infinity" => f64::INFINITY,
                "-Infinity" => f64::NEG_INFINITY,
                _ => s
                    .parse::<f64>()
                    .map_err(|_| JsonError(format!("doubleValue {s:?} is not a number")))?,
            },
            _ => return err("doubleValue must be a number"),
        }),
        "timestampValue" => V::TimestampValue(timestamp_from_json(inner)?),
        "stringValue" => V::StringValue(
            inner
                .as_str()
                .ok_or_else(|| JsonError("stringValue must be a string".into()))?
                .to_owned(),
        ),
        "bytesValue" => {
            V::BytesValue(base64_decode(inner.as_str().ok_or_else(|| {
                JsonError("bytesValue must be a base64 string".into())
            })?)?)
        }
        "referenceValue" => V::ReferenceValue(
            inner
                .as_str()
                .ok_or_else(|| JsonError("referenceValue must be a string".into()))?
                .to_owned(),
        ),
        "geoPointValue" => {
            let coordinate = |key: &str, range: f64| -> Result<f64, JsonError> {
                let v = inner
                    .get(key)
                    .and_then(Value::as_f64)
                    .ok_or_else(|| JsonError(format!("geoPointValue.{key} must be a number")))?;
                if !v.is_finite() || v.abs() > range {
                    return err(format!("geoPointValue.{key} out of range"));
                }
                Ok(v)
            };
            V::GeoPointValue(fireemu_proto_firestore::google::r#type::LatLng {
                latitude: coordinate("latitude", 90.0)?,
                longitude: coordinate("longitude", 180.0)?,
            })
        }
        "arrayValue" => V::ArrayValue(pb::ArrayValue {
            values: inner
                .get("values")
                .and_then(Value::as_array)
                .map(|items| items.iter().map(value_from_json).collect::<Result<_, _>>())
                .transpose()?
                .unwrap_or_default(),
        }),
        "mapValue" => V::MapValue(pb::MapValue {
            fields: fields_from_json(inner.get("fields"))?,
        }),
        other => return err(format!("unknown value key {other:?}")),
    };
    Ok(pb::Value {
        value_type: Some(value_type),
    })
}

/// `fields` object → protobuf map.
pub fn fields_from_json(v: Option<&Value>) -> Result<HashMap<String, pb::Value>, JsonError> {
    let mut out = HashMap::new();
    let Some(v) = v else { return Ok(out) };
    let Some(obj) = v.as_object() else {
        return err("fields must be an object");
    };
    for (k, v) in obj {
        out.insert(k.clone(), value_from_json(v)?);
    }
    Ok(out)
}

/// Protobuf document → JSON.
#[must_use]
pub fn document_to_json(d: &pb::Document) -> Value {
    let fields: Map<String, Value> = d
        .fields
        .iter()
        .map(|(k, v)| (k.clone(), value_to_json(v)))
        .collect();
    let mut out = json!({"name": d.name, "fields": fields});
    if let Some(t) = &d.create_time {
        out["createTime"] = timestamp_to_json(t);
    }
    if let Some(t) = &d.update_time {
        out["updateTime"] = timestamp_to_json(t);
    }
    out
}

/// JSON → protobuf document (`name` may be absent for create).
pub fn document_from_json(v: &Value) -> Result<pb::Document, JsonError> {
    Ok(pb::Document {
        name: v
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        fields: fields_from_json(v.get("fields"))?,
        create_time: None,
        update_time: None,
    })
}

// ------------------------------------------------------------------------------------------
// masks, preconditions, writes
// ------------------------------------------------------------------------------------------

/// `{"fieldPaths": [...]}` → mask.
pub fn mask_from_json(v: Option<&Value>) -> Result<Option<pb::DocumentMask>, JsonError> {
    let Some(v) = v else { return Ok(None) };
    let paths = v
        .get("fieldPaths")
        .and_then(Value::as_array)
        .ok_or_else(|| JsonError("mask.fieldPaths must be an array".into()))?;
    let field_paths = paths
        .iter()
        .map(|p| {
            p.as_str()
                .map(str::to_owned)
                .ok_or_else(|| JsonError("field paths must be strings".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(pb::DocumentMask { field_paths }))
}

/// Mask from repeated query parameters.
#[must_use]
pub fn mask_from_paths(paths: &[String]) -> Option<pb::DocumentMask> {
    if paths.is_empty() {
        None
    } else {
        Some(pb::DocumentMask {
            field_paths: paths.to_vec(),
        })
    }
}

/// `{"exists": bool}` / `{"updateTime": ts}` → precondition.
pub fn precondition_from_json(v: Option<&Value>) -> Result<Option<pb::Precondition>, JsonError> {
    let Some(v) = v else { return Ok(None) };
    let condition_type = if let Some(e) = v.get("exists") {
        Some(pb::precondition::ConditionType::Exists(
            e.as_bool()
                .ok_or_else(|| JsonError("currentDocument.exists must be a boolean".into()))?,
        ))
    } else if let Some(t) = v.get("updateTime") {
        Some(pb::precondition::ConditionType::UpdateTime(
            timestamp_from_json(t)?,
        ))
    } else {
        None
    };
    Ok(Some(pb::Precondition { condition_type }))
}

fn transform_from_json(v: &Value) -> Result<pb::document_transform::FieldTransform, JsonError> {
    use pb::document_transform::field_transform::TransformType as T;
    let field_path = v
        .get("fieldPath")
        .and_then(Value::as_str)
        .ok_or_else(|| JsonError("fieldTransform.fieldPath is required".into()))?
        .to_owned();
    let array = |key: &str| -> Result<pb::ArrayValue, JsonError> {
        Ok(pb::ArrayValue {
            values: v
                .get(key)
                .and_then(|a| a.get("values"))
                .and_then(Value::as_array)
                .map(|items| items.iter().map(value_from_json).collect::<Result<_, _>>())
                .transpose()?
                .unwrap_or_default(),
        })
    };
    let transform_type = if let Some(sv) = v.get("setToServerValue") {
        match sv.as_str() {
            Some("REQUEST_TIME") => T::SetToServerValue(
                pb::document_transform::field_transform::ServerValue::RequestTime as i32,
            ),
            other => return err(format!("unknown setToServerValue {other:?}")),
        }
    } else if let Some(x) = v.get("increment") {
        T::Increment(value_from_json(x)?)
    } else if let Some(x) = v.get("maximum") {
        T::Maximum(value_from_json(x)?)
    } else if let Some(x) = v.get("minimum") {
        T::Minimum(value_from_json(x)?)
    } else if v.get("appendMissingElements").is_some() {
        T::AppendMissingElements(array("appendMissingElements")?)
    } else if v.get("removeAllFromArray").is_some() {
        T::RemoveAllFromArray(array("removeAllFromArray")?)
    } else {
        return err("fieldTransform without a transform");
    };
    Ok(pb::document_transform::FieldTransform {
        field_path,
        transform_type: Some(transform_type),
    })
}

/// JSON → write.
pub fn write_from_json(v: &Value) -> Result<pb::Write, JsonError> {
    let operation = if let Some(d) = v.get("update") {
        Some(pb::write::Operation::Update(document_from_json(d)?))
    } else if let Some(n) = v.get("delete") {
        Some(pb::write::Operation::Delete(
            n.as_str()
                .ok_or_else(|| JsonError("delete must be a document name".into()))?
                .to_owned(),
        ))
    } else if let Some(n) = v.get("verify") {
        Some(pb::write::Operation::Verify(
            n.as_str()
                .ok_or_else(|| JsonError("verify must be a document name".into()))?
                .to_owned(),
        ))
    } else if let Some(t) = v.get("transform") {
        Some(pb::write::Operation::Transform(pb::DocumentTransform {
            document: t
                .get("document")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            field_transforms: t
                .get("fieldTransforms")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(transform_from_json)
                        .collect::<Result<_, _>>()
                })
                .transpose()?
                .unwrap_or_default(),
        }))
    } else {
        None
    };
    Ok(pb::Write {
        update_mask: mask_from_json(v.get("updateMask"))?,
        update_transforms: v
            .get("updateTransforms")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(transform_from_json)
                    .collect::<Result<_, _>>()
            })
            .transpose()?
            .unwrap_or_default(),
        current_document: precondition_from_json(v.get("currentDocument"))?,
        operation,
    })
}

/// Write result → JSON.
#[must_use]
pub fn write_result_to_json(w: &pb::WriteResult) -> Value {
    let mut out = json!({
        "transformResults": w.transform_results.iter().map(value_to_json).collect::<Vec<_>>(),
    });
    if let Some(t) = &w.update_time {
        out["updateTime"] = timestamp_to_json(t);
    }
    out
}

/// Commit response → JSON.
#[must_use]
pub fn commit_to_json(c: &pb::CommitResponse) -> Value {
    let mut out = json!({
        "writeResults": c.write_results.iter().map(write_result_to_json).collect::<Vec<_>>(),
    });
    if let Some(t) = &c.commit_time {
        out["commitTime"] = timestamp_to_json(t);
    }
    out
}

// ------------------------------------------------------------------------------------------
// structured queries
// ------------------------------------------------------------------------------------------

fn field_reference(v: Option<&Value>) -> Result<Option<sq::FieldReference>, JsonError> {
    let Some(v) = v else { return Ok(None) };
    Ok(Some(sq::FieldReference {
        field_path: v
            .get("fieldPath")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonError("field.fieldPath is required".into()))?
            .to_owned(),
    }))
}

fn field_operator(name: &str) -> Result<i32, JsonError> {
    use sq::field_filter::Operator as O;
    Ok(match name {
        "LESS_THAN" => O::LessThan,
        "LESS_THAN_OR_EQUAL" => O::LessThanOrEqual,
        "GREATER_THAN" => O::GreaterThan,
        "GREATER_THAN_OR_EQUAL" => O::GreaterThanOrEqual,
        "EQUAL" => O::Equal,
        "NOT_EQUAL" => O::NotEqual,
        "ARRAY_CONTAINS" => O::ArrayContains,
        "IN" => O::In,
        "ARRAY_CONTAINS_ANY" => O::ArrayContainsAny,
        "NOT_IN" => O::NotIn,
        other => return err(format!("unknown field filter operator {other:?}")),
    } as i32)
}

fn unary_operator(name: &str) -> Result<i32, JsonError> {
    use sq::unary_filter::Operator as O;
    Ok(match name {
        "IS_NAN" => O::IsNan,
        "IS_NULL" => O::IsNull,
        "IS_NOT_NAN" => O::IsNotNan,
        "IS_NOT_NULL" => O::IsNotNull,
        other => return err(format!("unknown unary filter operator {other:?}")),
    } as i32)
}

fn filter_from_json(v: &Value) -> Result<sq::Filter, JsonError> {
    let filter_type = if let Some(c) = v.get("compositeFilter") {
        let op = match c.get("op").and_then(Value::as_str) {
            Some("AND") => sq::composite_filter::Operator::And,
            Some("OR") => sq::composite_filter::Operator::Or,
            _ => return err("compositeFilter.op must be AND or OR"),
        };
        sq::filter::FilterType::CompositeFilter(sq::CompositeFilter {
            op: op as i32,
            filters: c
                .get("filters")
                .and_then(Value::as_array)
                .map(|items| items.iter().map(filter_from_json).collect::<Result<_, _>>())
                .transpose()?
                .unwrap_or_default(),
        })
    } else if let Some(f) = v.get("fieldFilter") {
        sq::filter::FilterType::FieldFilter(sq::FieldFilter {
            field: field_reference(f.get("field"))?,
            op: field_operator(f.get("op").and_then(Value::as_str).unwrap_or(""))?,
            value: f.get("value").map(value_from_json).transpose()?,
        })
    } else if let Some(u) = v.get("unaryFilter") {
        sq::filter::FilterType::UnaryFilter(sq::UnaryFilter {
            op: unary_operator(u.get("op").and_then(Value::as_str).unwrap_or(""))?,
            operand_type: field_reference(u.get("field"))?
                .map(sq::unary_filter::OperandType::Field),
        })
    } else {
        return err("filter must be compositeFilter, fieldFilter or unaryFilter");
    };
    Ok(sq::Filter {
        filter_type: Some(filter_type),
    })
}

fn cursor_from_json(v: Option<&Value>) -> Result<Option<pb::Cursor>, JsonError> {
    let Some(v) = v else { return Ok(None) };
    Ok(Some(pb::Cursor {
        values: v
            .get("values")
            .and_then(Value::as_array)
            .map(|items| items.iter().map(value_from_json).collect::<Result<_, _>>())
            .transpose()?
            .unwrap_or_default(),
        before: v.get("before").and_then(Value::as_bool).unwrap_or(false),
    }))
}

/// Int32 from a JSON number, numeric string or `{"value": n}` wrapper.
pub fn int32(v: Option<&Value>, what: &str) -> Result<Option<i32>, JsonError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_i64()
            .and_then(|i| i32::try_from(i).ok())
            .map(Some)
            .ok_or_else(|| JsonError(format!("{what} must be an int32"))),
        Some(Value::String(s)) => s
            .parse::<i32>()
            .map(Some)
            .map_err(|_| JsonError(format!("{what} must be an int32"))),
        Some(Value::Object(o)) => int32(o.get("value"), what),
        Some(_) => err(format!("{what} must be an int32")),
    }
}

/// JSON → structured query.
pub fn structured_query_from_json(v: &Value) -> Result<pb::StructuredQuery, JsonError> {
    let from = v
        .get("from")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|f| {
                    Ok(sq::CollectionSelector {
                        collection_id: f
                            .get("collectionId")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        all_descendants: f
                            .get("allDescendants")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    })
                })
                .collect::<Result<Vec<_>, JsonError>>()
        })
        .transpose()?
        .unwrap_or_default();
    let order_by = v
        .get("orderBy")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|o| {
                    let direction = match o.get("direction").and_then(Value::as_str) {
                        None | Some("ASCENDING" | "DIRECTION_UNSPECIFIED") => {
                            sq::Direction::Ascending
                        }
                        Some("DESCENDING") => sq::Direction::Descending,
                        Some(other) => return err(format!("unknown order direction {other:?}")),
                    };
                    Ok(sq::Order {
                        field: field_reference(o.get("field"))?,
                        direction: direction as i32,
                    })
                })
                .collect::<Result<Vec<_>, JsonError>>()
        })
        .transpose()?
        .unwrap_or_default();
    let select = match v.get("select") {
        None => None,
        Some(s) => Some(sq::Projection {
            fields: s
                .get("fields")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|f| field_reference(Some(f)).map(Option::unwrap_or_default))
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?
                .unwrap_or_default(),
        }),
    };
    if v.get("findNearest").is_some() {
        return err("findNearest (vector search) is not implemented");
    }
    Ok(pb::StructuredQuery {
        select,
        from,
        r#where: v.get("where").map(filter_from_json).transpose()?,
        order_by,
        start_at: cursor_from_json(v.get("startAt"))?,
        end_at: cursor_from_json(v.get("endAt"))?,
        offset: int32(v.get("offset"), "offset")?.unwrap_or(0),
        limit: int32(v.get("limit"), "limit")?,
        find_nearest: None,
    })
}

/// JSON → aggregation query.
pub fn aggregation_query_from_json(v: &Value) -> Result<pb::StructuredAggregationQuery, JsonError> {
    use pb::structured_aggregation_query::aggregation as agg;
    let aggregations = v
        .get("aggregations")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|a| {
                    let operator = if let Some(c) = a.get("count") {
                        agg::Operator::Count(agg::Count {
                            up_to: int32(c.get("upTo"), "count.upTo")?.map(i64::from),
                        })
                    } else if let Some(s) = a.get("sum") {
                        agg::Operator::Sum(agg::Sum {
                            field: field_reference(s.get("field"))?,
                        })
                    } else if let Some(s) = a.get("avg") {
                        agg::Operator::Avg(agg::Avg {
                            field: field_reference(s.get("field"))?,
                        })
                    } else {
                        return err("aggregation must be count, sum or avg");
                    };
                    Ok(pb::structured_aggregation_query::Aggregation {
                        alias: a
                            .get("alias")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        operator: Some(operator),
                    })
                })
                .collect::<Result<Vec<_>, JsonError>>()
        })
        .transpose()?
        .unwrap_or_default();
    let query_type = v
        .get("structuredQuery")
        .map(structured_query_from_json)
        .transpose()?
        .map(pb::structured_aggregation_query::QueryType::StructuredQuery);
    Ok(pb::StructuredAggregationQuery {
        aggregations,
        query_type,
    })
}

/// Transaction options JSON (`{"readOnly": {}}` / `{"readWrite": {}}`). A
/// `readOnly.readTime` is carried through so the backend can refuse it explicitly;
/// `readWrite.retryTransaction` is accepted (retries start a fresh transaction here).
pub fn transaction_options_from_json(
    v: Option<&Value>,
) -> Result<pb::TransactionOptions, JsonError> {
    let mode = match v {
        Some(o) if o.get("readOnly").is_some() => {
            let read_time = o
                .get("readOnly")
                .and_then(|r| r.get("readTime"))
                .map(timestamp_from_json)
                .transpose()?;
            Some(pb::transaction_options::Mode::ReadOnly(
                pb::transaction_options::ReadOnly {
                    consistency_selector: read_time
                        .map(pb::transaction_options::read_only::ConsistencySelector::ReadTime),
                },
            ))
        }
        Some(o) if o.get("readWrite").is_some() => {
            let retry = o
                .get("readWrite")
                .and_then(|r| r.get("retryTransaction"))
                .and_then(Value::as_str)
                .map(base64_decode)
                .transpose()?
                .unwrap_or_default();
            Some(pb::transaction_options::Mode::ReadWrite(
                pb::transaction_options::ReadWrite {
                    retry_transaction: retry,
                    ..Default::default()
                },
            ))
        }
        _ => None,
    };
    Ok(pb::TransactionOptions { mode })
}

/// `readTime` consistency selector value, if the request carries one.
pub fn read_time_from_json(v: &Value) -> Result<Option<prost_types::Timestamp>, JsonError> {
    v.get("readTime").map(timestamp_from_json).transpose()
}

/// Optional RFC 3339 timestamp field → JSON (used for `readTime` / `commitTime`).
#[must_use]
pub fn optional_timestamp_to_json(t: Option<&prost_types::Timestamp>) -> Value {
    t.map_or(Value::Null, timestamp_to_json)
}

// ------------------------------------------------------------------------------------------
// Listen / Write stream messages (WebChannel carries their proto3 JSON form)
// ------------------------------------------------------------------------------------------

/// JSON → `ListenRequest`.
pub fn listen_request_from_json(v: &Value) -> Result<pb::ListenRequest, JsonError> {
    let target_change = if let Some(t) = v.get("addTarget") {
        let target_type = if let Some(q) = t.get("query") {
            Some(pb::target::TargetType::Query(pb::target::QueryTarget {
                parent: q
                    .get("parent")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                query_type: q
                    .get("structuredQuery")
                    .map(structured_query_from_json)
                    .transpose()?
                    .map(pb::target::query_target::QueryType::StructuredQuery),
            }))
        } else {
            t.get("documents").map(|d| {
                pb::target::TargetType::Documents(pb::target::DocumentsTarget {
                    documents: d
                        .get("documents")
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned)
                                .collect()
                        })
                        .unwrap_or_default(),
                })
            })
        };
        let resume_type = if let Some(token) = t.get("resumeToken").and_then(Value::as_str) {
            Some(pb::target::ResumeType::ResumeToken(base64_decode(token)?))
        } else if let Some(rt) = t.get("readTime") {
            Some(pb::target::ResumeType::ReadTime(timestamp_from_json(rt)?))
        } else {
            None
        };
        Some(pb::listen_request::TargetChange::AddTarget(pb::Target {
            target_id: int32(t.get("targetId"), "targetId")?.unwrap_or(0),
            once: t.get("once").and_then(Value::as_bool).unwrap_or(false),
            expected_count: int32(t.get("expectedCount"), "expectedCount")?,
            target_type,
            resume_type,
        }))
    } else if let Some(id) = v.get("removeTarget") {
        Some(pb::listen_request::TargetChange::RemoveTarget(
            int32(Some(id), "removeTarget")?.unwrap_or(0),
        ))
    } else {
        None
    };
    Ok(pb::ListenRequest {
        database: v
            .get("database")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        labels: HashMap::new(),
        request_options: None,
        target_change,
    })
}

/// JSON → `WriteRequest`.
pub fn write_request_from_json(v: &Value) -> Result<pb::WriteRequest, JsonError> {
    Ok(pb::WriteRequest {
        database: v
            .get("database")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        stream_id: v
            .get("streamId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        writes: v
            .get("writes")
            .and_then(Value::as_array)
            .map(|items| items.iter().map(write_from_json).collect::<Result<_, _>>())
            .transpose()?
            .unwrap_or_default(),
        stream_token: match v.get("streamToken").and_then(Value::as_str) {
            Some(t) => base64_decode(t)?,
            None => Vec::new(),
        },
        labels: HashMap::new(),
        request_options: None,
    })
}

fn target_change_type_name(t: i32) -> &'static str {
    match pb::target_change::TargetChangeType::try_from(t) {
        Ok(pb::target_change::TargetChangeType::Add) => "ADD",
        Ok(pb::target_change::TargetChangeType::Remove) => "REMOVE",
        Ok(pb::target_change::TargetChangeType::Current) => "CURRENT",
        Ok(pb::target_change::TargetChangeType::Reset) => "RESET",
        _ => "NO_CHANGE",
    }
}

/// `ListenResponse` → JSON.
#[must_use]
pub fn listen_response_to_json(r: &pb::ListenResponse) -> Value {
    use pb::listen_response::ResponseType as R;
    match &r.response_type {
        Some(R::TargetChange(t)) => {
            let mut v = json!({
                "targetChange": {
                    "targetChangeType": target_change_type_name(t.target_change_type),
                    "targetIds": t.target_ids,
                }
            });
            if !t.resume_token.is_empty() {
                v["targetChange"]["resumeToken"] = Value::String(base64_encode(&t.resume_token));
            }
            if let Some(rt) = &t.read_time {
                v["targetChange"]["readTime"] = timestamp_to_json(rt);
            }
            if let Some(c) = &t.cause {
                v["targetChange"]["cause"] = json!({"code": c.code, "message": c.message});
            }
            v
        }
        Some(R::DocumentChange(d)) => json!({
            "documentChange": {
                "document": d.document.as_ref().map(document_to_json),
                "targetIds": d.target_ids,
                "removedTargetIds": d.removed_target_ids,
            }
        }),
        Some(R::DocumentDelete(d)) => json!({
            "documentDelete": {
                "document": d.document,
                "removedTargetIds": d.removed_target_ids,
                "readTime": optional_timestamp_to_json(d.read_time.as_ref()),
            }
        }),
        Some(R::DocumentRemove(d)) => json!({
            "documentRemove": {
                "document": d.document,
                "removedTargetIds": d.removed_target_ids,
                "readTime": optional_timestamp_to_json(d.read_time.as_ref()),
            }
        }),
        Some(R::Filter(f)) => json!({"filter": {"targetId": f.target_id, "count": f.count}}),
        None => json!({}),
    }
}

/// `WriteResponse` → JSON.
#[must_use]
pub fn write_response_to_json(r: &pb::WriteResponse) -> Value {
    let mut v = json!({
        "streamToken": base64_encode(&r.stream_token),
        "writeResults": r.write_results.iter().map(write_result_to_json).collect::<Vec<_>>(),
    });
    if !r.stream_id.is_empty() {
        v["streamId"] = Value::String(r.stream_id.clone());
    }
    if let Some(t) = &r.commit_time {
        v["commitTime"] = timestamp_to_json(t);
    }
    v
}
