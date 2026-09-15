//! Firestore REST JSON <-> protobuf mapping (the documented proto3 JSON form of the
//! `google.firestore.v1` messages, restricted to what the local backend serves).

use std::collections::HashMap;

use fireemu_core_firestore::value::MAX_NESTING_DEPTH;
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

/// RFC 3339 with the protobuf JSON fraction: none, three, six or nine digits, whichever
/// is the shortest exact rendering.
fn timestamp_to_json(t: &prost_types::Timestamp) -> Value {
    let full = decode_instant(t)
        .to_rfc3339()
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
    Value::String(shorten_fraction(&full))
}

fn shorten_fraction(rfc3339: &str) -> String {
    let Some((head, fraction)) = rfc3339.strip_suffix('Z').and_then(|s| s.split_once('.')) else {
        return rfc3339.to_owned();
    };
    let trimmed = fraction.trim_end_matches('0');
    let digits = match trimmed.len() {
        0 => 0,
        1..=3 => 3,
        4..=6 => 6,
        _ => 9,
    };
    if digits == 0 {
        format!("{head}Z")
    } else {
        format!("{head}.{}Z", &fraction[..digits])
    }
}

/// Proto3 JSON leaves an unset or empty field out; this is the one place the rule is
/// applied to the request-level objects fireemu builds by hand.
pub fn without_empty(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.retain(|_, v| match v {
            Value::Array(items) => !items.is_empty(),
            Value::Object(fields) => !fields.is_empty(),
            Value::Null => false,
            _ => true,
        });
    }
    value
}

/// The keys a request object may carry; anything else is `Payload isn't valid for
/// request.`, which is what the official emulator answers for an unknown field or a second
/// member of a oneof.
pub fn strict_keys(v: &Value, allowed: &[&str]) -> Result<(), JsonError> {
    let Some(obj) = v.as_object() else {
        return err("Payload isn't valid for request.");
    };
    if obj.keys().any(|k| !allowed.contains(&k.as_str())) {
        return err("Payload isn't valid for request.");
    }
    Ok(())
}

fn struct_to_json(value: &prost_types::Struct) -> Value {
    Value::Object(
        value
            .fields
            .iter()
            .map(|(key, value)| (key.clone(), struct_value_to_json(value)))
            .collect(),
    )
}

fn struct_value_to_json(value: &prost_types::Value) -> Value {
    use prost_types::value::Kind;
    match &value.kind {
        Some(Kind::StringValue(value)) => Value::String(value.clone()),
        Some(Kind::NumberValue(value)) => serde_json::json!(value),
        Some(Kind::BoolValue(value)) => Value::Bool(*value),
        Some(Kind::StructValue(value)) => struct_to_json(value),
        Some(Kind::ListValue(value)) => {
            Value::Array(value.values.iter().map(struct_value_to_json).collect())
        }
        Some(Kind::NullValue(_)) | None => Value::Null,
    }
}

/// Serialize Explain's protobuf messages, including implicit-presence defaults and Struct values.
pub(crate) fn explain_metrics_to_json(metrics: &pb::ExplainMetrics) -> Value {
    let mut out = serde_json::json!({});
    if let Some(plan) = &metrics.plan_summary {
        out["planSummary"] = serde_json::json!({});
        if !plan.indexes_used.is_empty() {
            out["planSummary"]["indexesUsed"] =
                Value::Array(plan.indexes_used.iter().map(struct_to_json).collect());
        }
    }
    if let Some(stats) = &metrics.execution_stats {
        let mut execution = serde_json::json!({});
        if stats.results_returned != 0 {
            execution["resultsReturned"] = Value::String(stats.results_returned.to_string());
        }
        if stats.read_operations != 0 {
            execution["readOperations"] = Value::String(stats.read_operations.to_string());
        }
        if let Some(duration) = &stats.execution_duration {
            execution["executionDuration"] = Value::String(duration.to_string());
        }
        if let Some(debug) = &stats.debug_stats {
            execution["debugStats"] = struct_to_json(debug);
        }
        out["executionStats"] = execution;
    }
    out
}

/// Parses the finite local `ExplainOptions` contract.
pub fn explain_options_from_json(
    v: Option<&Value>,
) -> Result<Option<pb::ExplainOptions>, JsonError> {
    let Some(v) = v else { return Ok(None) };
    strict_keys(v, &["analyze"])?;
    let Some(analyze) = v.get("analyze") else {
        return Ok(Some(pb::ExplainOptions::default()));
    };
    let Some(analyze) = analyze.as_bool() else {
        return err("explainOptions.analyze must be a boolean");
    };
    Ok(Some(pb::ExplainOptions { analyze }))
}

#[cfg(test)]
mod explain_tests {
    use super::*;

    #[test]
    fn explain_options_accepts_only_boolean_analyze() {
        assert!(
            explain_options_from_json(Some(&json!({"analyze": true})))
                .unwrap()
                .unwrap()
                .analyze
        );
        assert!(explain_options_from_json(Some(&json!({"analyze": "true"}))).is_err());
        assert!(explain_options_from_json(Some(&json!({"unknown": false}))).is_err());
    }
}

/// Returns the first request key that is not part of the endpoint's accepted key set.
pub fn first_unknown_key<'a>(v: &'a Value, allowed: &[&str]) -> Option<&'a str> {
    v.as_object()?
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
        .map(String::as_str)
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
            if a.values.is_empty() {
                json!({"arrayValue": {}})
            } else {
                json!({"arrayValue": {"values": a.values.iter().map(value_to_json).collect::<Vec<_>>()}})
            }
        }
        Some(V::MapValue(m)) => {
            if m.fields.is_empty() {
                json!({"mapValue": {}})
            } else {
                let fields: Map<String, Value> = m
                    .fields
                    .iter()
                    .map(|(k, v)| (k.clone(), value_to_json(v)))
                    .collect();
                json!({"mapValue": {"fields": fields}})
            }
        }
    }
}

/// JSON → protobuf value.
pub fn value_from_json(v: &Value) -> Result<pb::Value, JsonError> {
    value_from_json_at(v, 0)
}

fn nested_depth(parent_depth: u32) -> Result<u32, JsonError> {
    let depth = parent_depth.saturating_add(1);
    if depth > MAX_NESTING_DEPTH {
        return err(format!(
            "FS-LIMIT-NESTED-MAP-ARRAY-DEPTH has maximum {MAX_NESTING_DEPTH}, got {depth}"
        ));
    }
    Ok(depth)
}

fn vector_map_from_json(
    inner: &Value,
    parent_depth: u32,
) -> Result<Option<pb::MapValue>, JsonError> {
    let Some(fields) = inner.get("fields").and_then(Value::as_object) else {
        return Ok(None);
    };
    let Some(type_value) = fields.get("__type__").and_then(Value::as_object) else {
        return Ok(None);
    };
    let Some(array_value) = fields.get("value").and_then(Value::as_object) else {
        return Ok(None);
    };
    if fields.len() != 2
        || type_value.len() != 1
        || type_value.get("stringValue").and_then(Value::as_str) != Some("__vector__")
        || array_value.len() != 1
    {
        return Ok(None);
    }
    let Some(array) = array_value.get("arrayValue") else {
        return Ok(None);
    };
    let values = array
        .get("values")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|value| value_from_json_at(value, parent_depth))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(Some(pb::MapValue {
        fields: HashMap::from([
            (
                "__type__".to_owned(),
                pb::Value {
                    value_type: Some(pb::value::ValueType::StringValue("__vector__".to_owned())),
                },
            ),
            (
                "value".to_owned(),
                pb::Value {
                    value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue { values })),
                },
            ),
        ]),
    }))
}

fn value_from_json_at(v: &Value, parent_depth: u32) -> Result<pb::Value, JsonError> {
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
        "arrayValue" => V::ArrayValue(array_from_json(inner, parent_depth)?),
        "mapValue" => {
            if let Some(vector) = vector_map_from_json(inner, parent_depth)? {
                V::MapValue(vector)
            } else {
                let depth = nested_depth(parent_depth)?;
                V::MapValue(pb::MapValue {
                    fields: fields_from_json_at(inner.get("fields"), depth)?,
                })
            }
        }
        other => return err(format!("unknown value key {other:?}")),
    };
    Ok(pb::Value {
        value_type: Some(value_type),
    })
}

fn array_from_json(inner: &Value, parent_depth: u32) -> Result<pb::ArrayValue, JsonError> {
    let depth = nested_depth(parent_depth)?;
    let values = inner
        .get("values")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|value| value_from_json_at(value, depth))
                .collect::<Result<_, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(pb::ArrayValue { values })
}

/// `fields` object → protobuf map.
pub fn fields_from_json(v: Option<&Value>) -> Result<HashMap<String, pb::Value>, JsonError> {
    fields_from_json_at(v, 0)
}

fn fields_from_json_at(
    v: Option<&Value>,
    parent_depth: u32,
) -> Result<HashMap<String, pb::Value>, JsonError> {
    let mut out = HashMap::new();
    let Some(v) = v else { return Ok(out) };
    let Some(obj) = v.as_object() else {
        return err("fields must be an object");
    };
    for (k, v) in obj {
        out.insert(k.clone(), value_from_json_at(v, parent_depth)?);
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
    let mut out = json!({"name": d.name});
    if !fields.is_empty() {
        out["fields"] = Value::Object(fields);
    }
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
    strict_keys(v, &["fieldPaths"])?;
    let field_paths = match v.get("fieldPaths") {
        None => Vec::new(),
        Some(paths) => paths
            .as_array()
            .ok_or_else(|| JsonError("mask.fieldPaths must be an array".into()))?
            .iter()
            .map(|p| {
                p.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| JsonError("field paths must be strings".into()))
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
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
    strict_keys(v, &["exists", "updateTime"])?;
    if v.get("exists").is_some() && v.get("updateTime").is_some() {
        // A oneof carries one member.
        return err("Payload isn't valid for request.");
    }
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
    strict_keys(
        v,
        &[
            "update",
            "delete",
            "verify",
            "transform",
            "updateMask",
            "updateTransforms",
            "currentDocument",
        ],
    )?;
    let operation_count = ["update", "delete", "verify", "transform"]
        .iter()
        .filter(|k| v.get(**k).is_some_and(|value| !value.is_null()))
        .count();
    if operation_count != 1 {
        // A oneof carries one member.
        return err("Payload isn't valid for request.");
    }
    let operation = if let Some(d) = v.get("update").filter(|value| !value.is_null()) {
        Some(pb::write::Operation::Update(document_from_json(d)?))
    } else if let Some(n) = v.get("delete").filter(|value| !value.is_null()) {
        Some(pb::write::Operation::Delete(
            n.as_str()
                .ok_or_else(|| JsonError("delete must be a document name".into()))?
                .to_owned(),
        ))
    } else if let Some(n) = v.get("verify").filter(|value| !value.is_null()) {
        Some(pb::write::Operation::Verify(
            n.as_str()
                .ok_or_else(|| JsonError("verify must be a document name".into()))?
                .to_owned(),
        ))
    } else if let Some(t) = v.get("transform").filter(|value| !value.is_null()) {
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
    without_empty(out)
}

/// Commit response → JSON. A commit without writes answers `{}`: no write results, and no
/// commit time either, which is what the official emulator answers for it.
#[must_use]
pub fn commit_to_json(c: &pb::CommitResponse) -> Value {
    let mut out = json!({
        "writeResults": c.write_results.iter().map(write_result_to_json).collect::<Vec<_>>(),
    });
    if let (Some(t), false) = (&c.commit_time, c.write_results.is_empty()) {
        out["commitTime"] = timestamp_to_json(t);
    }
    without_empty(out)
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
        if !c.is_object() {
            return err("compositeFilter must be an object");
        }
        let op = match c.get("op").and_then(Value::as_str) {
            Some("AND") => sq::composite_filter::Operator::And,
            Some("OR") => sq::composite_filter::Operator::Or,
            _ => return err("compositeFilter.op must be AND or OR"),
        };
        sq::filter::FilterType::CompositeFilter(sq::CompositeFilter {
            op: op as i32,
            filters: match c.get("filters") {
                None | Some(Value::Null) => Vec::new(),
                Some(filters) => filters
                    .as_array()
                    .ok_or_else(|| JsonError("compositeFilter.filters must be an array".into()))?
                    .iter()
                    .map(filter_from_json)
                    .collect::<Result<_, _>>()?,
            },
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
    if v.is_null() {
        return Ok(None);
    }
    let Some(v) = v.as_object() else {
        return err("cursor must be an object");
    };
    let values = match v.get("values") {
        None | Some(Value::Null) => Vec::new(),
        Some(values) => values
            .as_array()
            .ok_or_else(|| JsonError("cursor.values must be an array".into()))?
            .iter()
            .map(value_from_json)
            .collect::<Result<_, _>>()?,
    };
    let before = match v.get("before") {
        None | Some(Value::Null) => false,
        Some(before) => before
            .as_bool()
            .ok_or_else(|| JsonError("cursor.before must be a boolean".into()))?,
    };
    Ok(Some(pb::Cursor { values, before }))
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

/// Parses the optional server request options object. Tags are currently accepted for wire
/// compatibility and intentionally have no local execution effect.
pub fn request_options_from_json(
    v: Option<&Value>,
) -> Result<Option<pb::RequestOptions>, JsonError> {
    let Some(v) = v else { return Ok(None) };
    if v.is_null() {
        return Ok(None);
    }
    strict_keys(v, &["requestTags"])?;
    let request_tags = match v.get("requestTags") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| JsonError("requestOptions.requestTags must be strings".into()))
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return err("requestOptions.requestTags must be an array"),
    };
    Ok(Some(pb::RequestOptions { request_tags }))
}

fn find_nearest_from_json(raw: &Value) -> Result<pb::structured_query::FindNearest, JsonError> {
    strict_keys(
        raw,
        &[
            "vectorField",
            "queryVector",
            "distanceMeasure",
            "limit",
            "distanceResultField",
            "distanceThreshold",
        ],
    )?;
    let vector_field = field_reference(raw.get("vectorField"))?
        .ok_or_else(|| JsonError("findNearest.vectorField is required".into()))?;
    let query_vector = value_from_json(
        raw.get("queryVector")
            .ok_or_else(|| JsonError("findNearest.queryVector is required".into()))?,
    )?;
    let distance_measure = match raw
        .get("distanceMeasure")
        .and_then(Value::as_str)
        .ok_or_else(|| JsonError("findNearest.distanceMeasure is required".into()))?
    {
        "EUCLIDEAN" => sq::find_nearest::DistanceMeasure::Euclidean,
        "COSINE" => sq::find_nearest::DistanceMeasure::Cosine,
        "DOT_PRODUCT" => sq::find_nearest::DistanceMeasure::DotProduct,
        other => return err(format!("unknown distance measure {other:?}")),
    };
    let limit = int32(raw.get("limit"), "findNearest.limit")?
        .ok_or_else(|| JsonError("findNearest.limit is required".into()))?;
    let distance_result_field = raw
        .get("distanceResultField")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| JsonError("findNearest.distanceResultField must be a string".into()))
                .map(str::to_owned)
        })
        .transpose()?
        .unwrap_or_default();
    let distance_threshold = raw
        .get("distanceThreshold")
        .map(|value| {
            value
                .as_f64()
                .ok_or_else(|| JsonError("findNearest.distanceThreshold must be a number".into()))
        })
        .transpose()?;
    Ok(pb::structured_query::FindNearest {
        vector_field: Some(vector_field),
        query_vector: Some(query_vector),
        distance_measure: distance_measure as i32,
        limit: Some(limit),
        distance_result_field,
        distance_threshold,
    })
}

/// JSON → structured query.
#[allow(clippy::too_many_lines)]
pub fn structured_query_from_json(v: &Value) -> Result<pb::StructuredQuery, JsonError> {
    if !v.is_object() {
        return err("structuredQuery must be an object");
    }
    let from = v
        .get("from")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| JsonError("from must be an array".into()))
        })
        .transpose()?
        .map(|items| {
            items
                .iter()
                .map(|f| {
                    if !f.is_object() {
                        return err("from elements must be objects");
                    }
                    Ok(sq::CollectionSelector {
                        collection_id: match f.get("collectionId") {
                            None | Some(Value::Null) => String::new(),
                            Some(value) => value
                                .as_str()
                                .ok_or_else(|| {
                                    JsonError("from.collectionId must be a string".into())
                                })?
                                .to_owned(),
                        },
                        all_descendants: match f.get("allDescendants") {
                            None | Some(Value::Null) => false,
                            Some(value) => value.as_bool().ok_or_else(|| {
                                JsonError("from.allDescendants must be a boolean".into())
                            })?,
                        },
                    })
                })
                .collect::<Result<Vec<_>, JsonError>>()
        })
        .transpose()?
        .unwrap_or_default();
    let order_by = v
        .get("orderBy")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| JsonError("orderBy must be an array".into()))
        })
        .transpose()?
        .map(|items| {
            items
                .iter()
                .map(|o| {
                    if !o.is_object() {
                        return err("orderBy elements must be objects");
                    }
                    let direction = match o.get("direction") {
                        None | Some(Value::Null) => sq::Direction::Ascending,
                        Some(value) => match value.as_str() {
                            Some("ASCENDING" | "DIRECTION_UNSPECIFIED") => sq::Direction::Ascending,
                            Some("DESCENDING") => sq::Direction::Descending,
                            Some(other) => {
                                return err(format!("unknown order direction {other:?}"))
                            }
                            None => match value.as_i64() {
                                Some(0 | 1) => sq::Direction::Ascending,
                                Some(2) => sq::Direction::Descending,
                                Some(other) => {
                                    return err(format!("unknown order direction {other}"))
                                }
                                None => {
                                    return err("orderBy.direction must be a string or enum number")
                                }
                            },
                        },
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
        None | Some(Value::Null) => None,
        Some(s) => {
            let Some(s) = s.as_object() else {
                return err("select must be an object");
            };
            let fields = match s.get("fields") {
                None | Some(Value::Null) => Vec::new(),
                Some(fields) => fields
                    .as_array()
                    .ok_or_else(|| JsonError("select.fields must be an array".into()))?
                    .iter()
                    .map(|f| field_reference(Some(f)).map(Option::unwrap_or_default))
                    .collect::<Result<Vec<_>, _>>()?,
            };
            Some(sq::Projection { fields })
        }
    };
    let find_nearest = v
        .get("findNearest")
        .filter(|value| !value.is_null())
        .map(find_nearest_from_json)
        .transpose()?;
    Ok(pb::StructuredQuery {
        select,
        from,
        r#where: v
            .get("where")
            .filter(|value| !value.is_null())
            .map(filter_from_json)
            .transpose()?,
        order_by,
        start_at: cursor_from_json(v.get("startAt"))?,
        end_at: cursor_from_json(v.get("endAt"))?,
        offset: int32(v.get("offset"), "offset")?.unwrap_or(0),
        limit: int32(v.get("limit"), "limit")?,
        find_nearest,
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
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(pb::TransactionOptions::default());
    };
    strict_keys(v, &["readOnly", "readWrite"])?;
    let read_only = v.get("readOnly").filter(|value| !value.is_null());
    let read_write = v.get("readWrite").filter(|value| !value.is_null());
    if read_only.is_some() && read_write.is_some() {
        return err("readOnly and readWrite are mutually exclusive");
    }
    let mode = match (read_only, read_write) {
        (Some(read_only), None) => {
            strict_keys(read_only, &["readTime"])?;
            let read_time = read_only
                .get("readTime")
                .filter(|value| !value.is_null())
                .map(timestamp_from_json)
                .transpose()?;
            Some(pb::transaction_options::Mode::ReadOnly(
                pb::transaction_options::ReadOnly {
                    consistency_selector: read_time
                        .map(pb::transaction_options::read_only::ConsistencySelector::ReadTime),
                },
            ))
        }
        (None, Some(read_write)) => {
            strict_keys(read_write, &["retryTransaction", "concurrencyMode"])?;
            let retry = match read_write
                .get("retryTransaction")
                .filter(|value| !value.is_null())
            {
                Some(value) => value
                    .as_str()
                    .ok_or_else(|| JsonError("readWrite.retryTransaction must be a string".into()))
                    .and_then(base64_decode)?,
                None => Vec::new(),
            };
            let concurrency_mode = match read_write
                .get("concurrencyMode")
                .filter(|value| !value.is_null())
            {
                None => 0,
                Some(Value::String(value)) => {
                    pb::transaction_options::ConcurrencyMode::from_str_name(value)
                        .map(|mode| mode as i32)
                        .ok_or_else(|| {
                            JsonError("readWrite.concurrencyMode must be a valid enum".into())
                        })?
                }
                Some(Value::Number(value)) => {
                    let value = value
                        .as_i64()
                        .and_then(|value| i32::try_from(value).ok())
                        .ok_or_else(|| {
                            JsonError("readWrite.concurrencyMode must be a valid enum".into())
                        })?;
                    pb::transaction_options::ConcurrencyMode::try_from(value)
                        .map(|mode| mode as i32)
                        .map_err(|_| {
                            JsonError("readWrite.concurrencyMode must be a valid enum".into())
                        })?
                }
                Some(_) => return err("readWrite.concurrencyMode must be a string or integer"),
            };
            Some(pb::transaction_options::Mode::ReadWrite(
                pb::transaction_options::ReadWrite {
                    retry_transaction: retry,
                    concurrency_mode,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn nested_map(levels: u32) -> Value {
        let mut value = json!({"integerValue": "1"});
        for _ in 0..levels {
            value = json!({"mapValue": {"fields": {"nested": value}}});
        }
        value
    }

    fn nested_map_with_vector(levels: u32) -> Value {
        let mut value = json!({
            "mapValue": {
                "fields": {
                    "__type__": {"stringValue": "__vector__"},
                    "value": {"arrayValue": {"values": [{"doubleValue": 1.0}]}}
                }
            }
        });
        for _ in 0..levels {
            value = json!({"mapValue": {"fields": {"nested": value}}});
        }
        value
    }

    #[test]
    fn json_value_decoder_stops_at_the_firestore_depth_limit() {
        assert!(value_from_json(&nested_map(MAX_NESTING_DEPTH)).is_ok());
        let error = value_from_json(&nested_map(MAX_NESTING_DEPTH + 1))
            .expect_err("one level past the limit is rejected");
        assert!(error.0.contains("FS-LIMIT-NESTED-MAP-ARRAY-DEPTH"));
    }

    #[test]
    fn json_vector_sentinel_has_the_same_leaf_depth_as_grpc() {
        assert!(value_from_json(&nested_map_with_vector(MAX_NESTING_DEPTH)).is_ok());
        let error = value_from_json(&nested_map_with_vector(MAX_NESTING_DEPTH + 1))
            .expect_err("one enclosing map past the limit is rejected");
        assert!(error.0.contains("FS-LIMIT-NESTED-MAP-ARRAY-DEPTH"));
    }

    #[test]
    fn structured_query_json_decodes_find_nearest() {
        let query = structured_query_from_json(&json!({
            "from": [{"collectionId": "items"}],
            "findNearest": {
                "vectorField": {"fieldPath": "embedding"},
                "queryVector": {"mapValue": {"fields": {
                    "__type__": {"stringValue": "__vector__"},
                    "value": {"arrayValue": {"values": [{"doubleValue": 1.0}]}}
                }}},
                "distanceMeasure": "COSINE",
                "limit": 2,
                "distanceResultField": "distance",
                "distanceThreshold": 0.5
            }
        }))
        .unwrap();
        let nearest = query.find_nearest.unwrap();
        assert_eq!(
            nearest.distance_measure,
            sq::find_nearest::DistanceMeasure::Cosine as i32
        );
        assert_eq!(nearest.limit, Some(2));
        assert_eq!(nearest.distance_result_field, "distance");
        assert_eq!(nearest.distance_threshold, Some(0.5));
        assert!(query_vector_is_vector(
            nearest.query_vector.as_ref().unwrap()
        ));
    }

    #[test]
    fn structured_query_rejects_non_array_from_and_order_by() {
        for (field, value) in [("from", json!("items")), ("orderBy", json!({}))] {
            let error = structured_query_from_json(&json!({field: value}))
                .expect_err("a present query list must be an array");
            assert!(error.0.contains(&format!("{field} must be an array")));
        }
        for (field, value) in [("from", json!([null])), ("orderBy", json!([1]))] {
            let error = structured_query_from_json(&json!({field: value}))
                .expect_err("a query list element must be an object");
            assert!(error
                .0
                .contains(&format!("{field} elements must be objects")));
        }
    }

    fn query_vector_is_vector(value: &pb::Value) -> bool {
        matches!(
            &value.value_type,
            Some(pb::value::ValueType::MapValue(map)) if map.fields.contains_key("__type__")
        )
    }
}
