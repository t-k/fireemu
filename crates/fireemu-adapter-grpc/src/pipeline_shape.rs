//! The strict profile's shape-match rule for pipeline refusals (coordinator ruling of
//! 2026-10-21 for `PX1d` round 5): the gate answers an `INVALID_ARGUMENT` only when the
//! request's normalized shape equals a request production refused in a committed O-n fixture,
//! and its text is that row's text. Otherwise the gate answers `UNIMPLEMENTED`. Separately, the
//! gRPC service enforces a generalized 32-function nesting limit outside this gate; production
//! recorded the boundary for an array-function chain, while other expression shapes are inferred.
//!
//! A shape keeps the stages in order, stage and function names, the value kinds, the count of
//! array elements, and every map's entries in wire order. It replaces only field names and
//! values of the same kind: a field reference whose path is plain names joined by `.`, and a
//! map key (a select alias or a literal's key) that is a plain name (letters, digits and `_`,
//! not starting with a digit, not reserved `__..__`, at most 100 bytes). Any other path or key
//! (`__name__`, empty, dotted, quoted, reserved, long) and option names stay as written, since
//! production's checks and texts depend on them. A map of two or more entries
//! whose wire order the transport did not keep (gRPC, whose decoded maps are unordered) has no
//! generic shape, so strict answers no generic refusal of such a request. The recorded gRPC
//! select-width request is matched as a decoded request. The TEXT namespace
//! instead compares the decoded request with a recorded one of the same transport, apart from
//! the database, the collection and the `document_matches` literal, which production's
//! search-option checks never read; every option value is kept.
//!
//! The table of recorded shapes is derived from conformance/fs-ent-pipeline-requests.json and
//! conformance/fs-ent-pipeline-production.json when first used. The separate TEXT table uses
//! conformance/fs-ent-text-refusal-requests.json and conformance/fs-ent-text-production.json.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::LazyLock;

use fireemu_proto_firestore::google::firestore::v1 as pb;
use serde_json::Value;
use tonic::Status;

use crate::rest::json_syntax::{self, KeyOrder};

const REQUESTS: &str = include_str!("../../../conformance/fs-ent-pipeline-requests.json");
const PRODUCTION: &str = include_str!("../../../conformance/fs-ent-pipeline-production.json");

#[derive(Debug)]
struct UnknownCandidate {
    fallback: Status,
    text: String,
}

impl std::fmt::Display for UnknownCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("private pipeline refusal candidate")
    }
}
impl std::error::Error for UnknownCandidate {}

fn unknown_carrier(status: &Status) -> Option<&UnknownCandidate> {
    use std::error::Error as _;
    status.source()?.downcast_ref::<UnknownCandidate>()
}

/// Prevents ordinary candidate shape inspection from recursing into unbounded JSON.
pub(crate) fn candidate_json_eligible(body: &Value) -> bool {
    const MAX_DEPTH: usize = 100;
    const MAX_NODES: usize = 32_768;
    let mut stack = vec![(body, 0_usize)];
    let mut seen = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        seen += 1;
        if depth > MAX_DEPTH {
            return false;
        }
        match value {
            Value::Array(values) => {
                if values.len() > MAX_NODES.saturating_sub(seen + stack.len()) {
                    return false;
                }
                stack.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                if values.len() > MAX_NODES.saturating_sub(seen + stack.len()) {
                    return false;
                }
                stack.extend(values.values().map(|value| (value, depth + 1)));
            }
            _ => {}
        }
    }
    true
}

pub(crate) fn unknown_candidate(fallback: Status, text: String) -> Status {
    let mut outer = fallback.clone();
    outer.set_source(std::sync::Arc::new(UnknownCandidate { fallback, text }));
    outer
}

pub(crate) fn unknown_candidate_text(status: &Status) -> Option<&str> {
    unknown_carrier(status).map(|candidate| candidate.text.as_str())
}

pub(crate) fn retain_unknown_candidate(fallback: Status, text: &str) -> Status {
    let fallback = match unknown_carrier(&fallback) {
        Some(candidate) => candidate.fallback.clone(),
        None => fallback,
    };
    unknown_candidate(fallback, text.to_owned())
}

/// How a pipeline's refusals are answered: as fireemu computes them (the emulator profile), or
/// only when the request has a recorded shape (strict; `None` when it has no shape), with the
/// request's database (`projects/{p}/databases/{d}`): a text may name that database in place
/// of the recorded one, never another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalGate {
    /// Every refusal is answered.
    Open,
    /// A refusal is answered only for a request of this recorded shape, in this database.
    Recorded(Option<String>, String),
    /// Ordinary behavior, with recorded-shape admission for a private unknown candidate only.
    Ordinary(Option<String>, String),
}

impl RefusalGate {
    /// The answer for `error`: unchanged unless it is an `INVALID_ARGUMENT` strict cannot trace
    /// to a production row of the request's shape with the same text, which becomes
    /// `UNIMPLEMENTED`.
    #[must_use]
    pub fn answer(&self, error: Status) -> Status {
        if let Some(candidate) = unknown_carrier(&error) {
            let fallback = candidate.fallback.clone();
            let computed = Status::invalid_argument(candidate.text.clone());
            let recorded = match self {
                Self::Recorded(shape, database) | Self::Ordinary(shape, database) => {
                    Self::Recorded(shape.clone(), database.clone()).answer(computed)
                }
                Self::Open => Status::unimplemented("candidate has no recorded shape"),
            };
            if recorded.code() == tonic::Code::InvalidArgument {
                return recorded;
            }
            return match self {
                Self::Recorded(_, _) => self.answer(fallback),
                Self::Open | Self::Ordinary(_, _) => fallback,
            };
        }
        let Self::Recorded(shape, database) = self else {
            return error;
        };
        if error.code() != tonic::Code::InvalidArgument {
            return error;
        }
        // The request's own database stands for the recorded one; a text naming another
        // database (a reference elsewhere) traces to no recorded row.
        let own = if database.is_empty() {
            error.message().to_owned()
        } else {
            own_database(error.message(), database)
        };
        let traced = !own.contains("projects/")
            && shape.as_deref().is_some_and(|shape| {
                let text = normalized_text(&own.replace(OWN_DATABASE, "projects/~/databases/~"));
                recorded_text()
                    .get(shape)
                    .or_else(|| recorded().get(shape))
                    .is_some_and(|texts| texts.contains(&text))
            });
        if traced {
            return error;
        }
        let mut status = Status::unimplemented(format!(
            "{}; production has not refused a request of this shape with this text, so this refusal is not observed locally",
            error.message()
        ));
        if let Ok(code) = "FS_PIPE_UNSUPPORTED_STAGE".parse() {
            status.metadata_mut().insert("fireemu-code", code);
        }
        status
    }
}

/// Where a text names the request's own database while the gate checks it.
const OWN_DATABASE: &str = "\u{1}database\u{1}";

/// `message` with each `projects/{p}/databases/{d}` that is exactly the request's `database`
/// (the whole database id, not a prefix of a longer one) put as [`OWN_DATABASE`].
fn own_database(message: &str, database: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(at) = rest.find("projects/") {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let end = tail.find("/databases/").map_or(0, |databases| {
            let id = &tail[databases + "/databases/".len()..];
            databases
                + "/databases/".len()
                + id.find(|c: char| c == '/' || c == '"' || c.is_whitespace())
                    .unwrap_or(id.len())
        });
        if end > 0 && &tail[..end] == database {
            out.push_str(OWN_DATABASE);
            rest = &tail[end..];
        } else {
            out.push_str("projects/");
            rest = &tail["projects/".len()..];
        }
    }
    out.push_str(rest);
    out
}

/// The shape of a REST `executePipeline` body, read with the wire order of its maps.
#[must_use]
pub fn shape_of_json(body: &Value, order: &KeyOrder) -> Option<String> {
    if let Some(key) = crate::rest::pipeline_json::request_from_json("", body)
        .ok()
        .and_then(|request| text_key_of(&request, false))
    {
        return Some(key);
    }
    let body = body.as_object()?;
    let mut out = String::new();
    // A null message is the unset one, as production's parser reads it (O-8A `precedence-main`).
    if let Some(structured) = body.get("structuredPipeline").filter(|v| !v.is_null()) {
        let structured = structured.as_object()?;
        if let Some(pipeline) = structured.get("pipeline") {
            let pipeline = pipeline.as_object()?;
            if let Some(stages) = pipeline.get("stages") {
                out.push_str("stages[");
                for (at, stage) in stages.as_array()?.iter().enumerate() {
                    let pointer = format!("/structuredPipeline/pipeline/stages/{at}");
                    stage_json(&mut out, stage, order, &pointer)?;
                }
                out.push(']');
            }
            for (key, value) in pipeline {
                if key != "stages" {
                    let _ = write!(out, "+pipeline.{}", raw(key, value));
                }
            }
        }
        if let Some(options) = structured.get("options").filter(|o| !is_empty_object(o)) {
            out.push_str("options");
            map_json(
                &mut out,
                options.as_object()?,
                order,
                "/structuredPipeline/options",
                Keys::Literal,
            )?;
        }
        for (key, value) in structured {
            if !matches!(key.as_str(), "pipeline" | "options") {
                let _ = write!(out, "+structured.{}", raw(key, value));
            }
        }
    }
    for key in body.keys() {
        if !matches!(key.as_str(), "database" | "structuredPipeline") {
            let _ = write!(out, "+{key}");
        }
    }
    Some(out)
}

/// The shape of a body that is no JSON: the body itself, since only an exact recorded text was
/// refused with a recorded answer.
#[must_use]
pub fn raw_shape(body: &[u8]) -> String {
    format!("raw:{}", String::from_utf8_lossy(body))
}

/// The shape of a gRPC request, whose maps carry no wire order.
#[must_use]
pub fn shape_of_request(request: &pb::ExecutePipelineRequest) -> Option<String> {
    if let Some((recorded, _)) = recorded_grpc_select_width() {
        let mut candidate = request.clone();
        candidate.database.clear();
        if &candidate == recorded {
            return Some(GRPC_SELECT_WIDTH_KEY.to_owned());
        }
    }
    if let Some(key) = text_key_of(request, true) {
        return Some(key);
    }
    // A request naming no pipeline was recorded over REST only (O-8A `precedence-main`).
    request.pipeline_type.as_ref()?;
    let mut out = String::new();
    if let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        &request.pipeline_type
    {
        if let Some(pipeline) = &structured.pipeline {
            out.push_str("stages[");
            for stage in &pipeline.stages {
                stage_pb(&mut out, stage)?;
            }
            out.push(']');
        }
        if !structured.options.is_empty() {
            out.push_str("options");
            map_pb(&mut out, &structured.options, Keys::Literal)?;
        }
    }
    match &request.consistency_selector {
        None => {}
        Some(pb::execute_pipeline_request::ConsistencySelector::Transaction(_)) => {
            out.push_str("+transaction");
        }
        Some(pb::execute_pipeline_request::ConsistencySelector::NewTransaction(_)) => {
            out.push_str("+newTransaction");
        }
        Some(pb::execute_pipeline_request::ConsistencySelector::ReadTime(_)) => {
            out.push_str("+readTime");
        }
    }
    Some(out)
}

fn stage_json(out: &mut String, stage: &Value, order: &KeyOrder, pointer: &str) -> Option<()> {
    let stage = stage.as_object()?;
    let name = stage
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let _ = write!(out, "{}(", quoted(name));
    if let Some(args) = stage.get("args") {
        for (at, arg) in args.as_array()?.iter().enumerate() {
            value_json(out, arg, order, &format!("{pointer}/args/{at}"))?;
            out.push(',');
        }
    }
    out.push(')');
    if let Some(options) = stage.get("options").filter(|o| !is_empty_object(o)) {
        out.push_str("options");
        map_json(
            out,
            options.as_object()?,
            order,
            &format!("{pointer}/options"),
            Keys::Literal,
        )?;
    }
    for (key, value) in stage {
        if !matches!(key.as_str(), "name" | "args" | "options") {
            let _ = write!(out, "+{}", raw(key, value));
        }
    }
    out.push(';');
    Some(())
}

fn stage_pb(out: &mut String, stage: &pb::pipeline::Stage) -> Option<()> {
    let _ = write!(out, "{}(", quoted(&stage.name));
    for arg in &stage.args {
        value_pb(out, arg)?;
        out.push(',');
    }
    out.push(')');
    if !stage.options.is_empty() {
        out.push_str("options");
        map_pb(out, &stage.options, Keys::Literal)?;
    }
    out.push(';');
    Some(())
}

/// How a map's keys enter its shape.
#[derive(Clone, Copy)]
enum Keys {
    /// Option names, kept as written.
    Literal,
    /// Field names (select aliases, a literal's keys): a plain name is replaced.
    FieldNames,
}

/// The longest key replaced as a plain name.
const PLAIN_NAME_BYTES: usize = 100;

impl Keys {
    fn shape(self, key: &str) -> String {
        if matches!(self, Self::FieldNames) && is_plain_name(key) {
            "name".to_owned()
        } else {
            quoted(key)
        }
    }
}

/// A name every check treats alike: letters, digits and `_`, not starting with a digit, not
/// reserved (`__..__`), at most [`PLAIN_NAME_BYTES`].
fn is_plain_name(name: &str) -> bool {
    name.len() <= PLAIN_NAME_BYTES
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !(name.len() >= 4 && name.starts_with("__") && name.ends_with("__"))
}

/// A field reference: a path of plain names is replaced; any other path (`__name__`, quoted,
/// reserved or malformed segments) is kept, since production's checks depend on it.
fn field_shape(path: &str) -> String {
    if path.split('.').all(is_plain_name) {
        "field".to_owned()
    } else {
        format!("field{}", quoted(path))
    }
}

/// A map's entries in wire order: `{"key":shape,...}`.
fn map_json(
    out: &mut String,
    map: &serde_json::Map<String, Value>,
    order: &KeyOrder,
    pointer: &str,
    names: Keys,
) -> Option<()> {
    out.push('{');
    let keys: Vec<&String> = if map.len() > 1 {
        let keys = order.keys(pointer)?;
        if keys.len() != map.len() || !keys.iter().all(|k| map.contains_key(k)) {
            return None;
        }
        keys.iter().collect()
    } else {
        map.keys().collect()
    };
    for key in keys {
        out.push_str(&names.shape(key));
        out.push(':');
        value_json(
            out,
            &map[key.as_str()],
            order,
            &format!("{pointer}/{}", json_syntax::pointer_segment(key)),
        )?;
        out.push(',');
    }
    out.push('}');
    Some(())
}

/// A map with no wire order has a shape only with at most one entry.
fn map_pb(out: &mut String, map: &HashMap<String, pb::Value>, names: Keys) -> Option<()> {
    if map.len() > 1 {
        return None;
    }
    out.push('{');
    for (key, value) in map {
        out.push_str(&names.shape(key));
        out.push(':');
        value_pb(out, value)?;
        out.push(',');
    }
    out.push('}');
    Some(())
}

fn value_json(out: &mut String, value: &Value, order: &KeyOrder, pointer: &str) -> Option<()> {
    let Some(object) = value.as_object().filter(|o| o.len() == 1) else {
        out.push_str(&raw("value", value));
        return Some(());
    };
    let (kind, inner) = object.iter().next()?;
    let inner_pointer = format!("{pointer}/{}", json_syntax::pointer_segment(kind));
    match kind.as_str() {
        "nullValue" => out.push_str("null"),
        "booleanValue" => out.push_str("boolean"),
        "integerValue" => out.push_str("integer"),
        "doubleValue" => out.push_str("double"),
        "timestampValue" => out.push_str("timestamp"),
        "stringValue" => out.push_str("string"),
        "bytesValue" => out.push_str("bytes"),
        "referenceValue" => out.push_str("reference"),
        "geoPointValue" => out.push_str("geoPoint"),
        "fieldReferenceValue" => out.push_str(&field_shape(inner.as_str().unwrap_or_default())),
        "variableReferenceValue" => out.push_str("variable"),
        "arrayValue" => {
            out.push('[');
            let array = inner.as_object()?;
            for (key, values) in array {
                if key != "values" {
                    let _ = write!(out, "+{}", raw(key, values));
                    continue;
                }
                for (at, element) in values.as_array()?.iter().enumerate() {
                    value_json(out, element, order, &format!("{inner_pointer}/values/{at}"))?;
                    out.push(',');
                }
            }
            out.push(']');
        }
        "mapValue" => {
            out.push_str("map");
            let map = inner.as_object()?;
            match map.get("fields") {
                Some(fields) => {
                    map_json(
                        out,
                        fields.as_object()?,
                        order,
                        &format!("{inner_pointer}/fields"),
                        Keys::FieldNames,
                    )?;
                }
                None => out.push_str("{}"),
            }
            for (key, value) in map {
                if key != "fields" {
                    let _ = write!(out, "+{}", raw(key, value));
                }
            }
        }
        "functionValue" => function_json(out, inner.as_object()?, order, &inner_pointer)?,
        "pipelineValue" => {
            out.push_str("pipeline[");
            let pipeline = inner.as_object()?;
            for (key, value) in pipeline {
                if key != "stages" {
                    let _ = write!(out, "+{}", raw(key, value));
                    continue;
                }
                for (at, stage) in value.as_array()?.iter().enumerate() {
                    stage_json(out, stage, order, &format!("{inner_pointer}/stages/{at}"))?;
                }
            }
            out.push(']');
        }
        _ => out.push_str(&raw("value", value)),
    }
    Some(())
}

/// A function call: its name, arguments and options.
fn function_json(
    out: &mut String,
    function: &serde_json::Map<String, Value>,
    order: &KeyOrder,
    inner_pointer: &str,
) -> Option<()> {
    let name = function
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let _ = write!(out, "fn {}(", quoted(name));
    if let Some(args) = function.get("args") {
        for (at, arg) in args.as_array()?.iter().enumerate() {
            value_json(out, arg, order, &format!("{inner_pointer}/args/{at}"))?;
            out.push(',');
        }
    }
    out.push(')');
    if let Some(options) = function.get("options").filter(|o| !is_empty_object(o)) {
        out.push_str("options");
        map_json(
            out,
            options.as_object()?,
            order,
            &format!("{inner_pointer}/options"),
            Keys::Literal,
        )?;
    }
    for (key, value) in function {
        if !matches!(key.as_str(), "name" | "args" | "options") {
            let _ = write!(out, "+{}", raw(key, value));
        }
    }
    Some(())
}

fn value_pb(out: &mut String, value: &pb::Value) -> Option<()> {
    use pb::value::ValueType as V;
    match &value.value_type {
        None => out.push_str("none"),
        Some(V::NullValue(_)) => out.push_str("null"),
        Some(V::BooleanValue(_)) => out.push_str("boolean"),
        Some(V::IntegerValue(_)) => out.push_str("integer"),
        Some(V::DoubleValue(_)) => out.push_str("double"),
        Some(V::TimestampValue(_)) => out.push_str("timestamp"),
        Some(V::StringValue(_)) => out.push_str("string"),
        Some(V::BytesValue(_)) => out.push_str("bytes"),
        Some(V::ReferenceValue(_)) => out.push_str("reference"),
        Some(V::GeoPointValue(_)) => out.push_str("geoPoint"),
        Some(V::FieldReferenceValue(path)) => out.push_str(&field_shape(path)),
        Some(V::VariableReferenceValue(_)) => out.push_str("variable"),
        Some(V::ArrayValue(array)) => {
            out.push('[');
            for element in &array.values {
                value_pb(out, element)?;
                out.push(',');
            }
            out.push(']');
        }
        Some(V::MapValue(map)) => {
            out.push_str("map");
            map_pb(out, &map.fields, Keys::FieldNames)?;
        }
        Some(V::FunctionValue(function)) => {
            let _ = write!(out, "fn {}(", quoted(&function.name));
            for arg in &function.args {
                value_pb(out, arg)?;
                out.push(',');
            }
            out.push(')');
            if !function.options.is_empty() {
                out.push_str("options");
                map_pb(out, &function.options, Keys::Literal)?;
            }
        }
        Some(V::PipelineValue(pipeline)) => {
            out.push_str("pipeline[");
            for stage in &pipeline.stages {
                stage_pb(out, stage)?;
            }
            out.push(']');
        }
    }
    Some(())
}

/// An empty options map, which is no options (proto3 reads both alike).
fn is_empty_object(value: &Value) -> bool {
    value.as_object().is_some_and(serde_json::Map::is_empty)
}

/// A part outside the protocol's shapes, kept exactly.
fn raw(key: &str, value: &Value) -> String {
    format!("raw{}={}", quoted(key), value)
}

fn quoted(text: &str) -> String {
    Value::String(text.to_owned()).to_string()
}

/// A refusal text with the project and database it names, and a separator index (which counts
/// their length), put aside.
#[must_use]
pub fn normalized_text(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(at) = rest.find("projects/") {
        out.push_str(&rest[..at]);
        let after = &rest[at + "projects/".len()..];
        let project_end = after.find('/').unwrap_or(after.len());
        let tail = &after[project_end..];
        if let Some(database) = tail.strip_prefix("/databases/") {
            let end = database
                .find(|c: char| c == '/' || c == '"' || c.is_whitespace())
                .unwrap_or(database.len());
            out.push_str("projects/~/databases/~");
            rest = &database[end..];
        } else {
            out.push_str("projects/");
            rest = after;
        }
    }
    out.push_str(rest);
    match out.find(" at index ") {
        Some(at) => {
            let digits = out[at + " at index ".len()..]
                .find(|c: char| !c.is_ascii_digit())
                .map_or(out.len(), |end| at + " at index ".len() + end);
            format!("{} at index ~{}", &out[..at], &out[digits..])
        }
        None => out,
    }
}

const TEXT_REQUESTS: &str = include_str!("../../../conformance/fs-ent-text-refusal-requests.json");
const TEXT_PRODUCTION: &str = include_str!("../../../conformance/fs-ent-text-production.json");

struct TextRequest {
    key: String,
    grpc: bool,
    #[cfg(test)]
    body: Value,
    request: pb::ExecutePipelineRequest,
}

fn text_key(program: &str, step: &Value) -> String {
    let transport = if step["transport"] == "grpc" {
        "grpc"
    } else {
        "rest"
    };
    format!(
        "text-refusal-v1/{transport}/{program}/{}",
        step["id"].as_str().unwrap_or_default()
    )
}

/// The recorded text row of `request`'s transport whose request equals it apart from the
/// literals production's search-option checks never read (review S7): the database, the
/// collection a `collection` stage names and the string a top-level `document_matches` query
/// searches for. Only the classes the recordings cover are cleared: a single valid collection
/// id and a non-empty query (merge review S-b). Every other part, the offending option value
/// included, must be equal.
fn text_key_of(request: &pb::ExecutePipelineRequest, grpc: bool) -> Option<String> {
    let skeleton = text_skeleton(request);
    text_requests()
        .iter()
        .find(|row| row.grpc == grpc && text_skeleton(&row.request) == skeleton)
        .map(|row| row.key.clone())
}

/// `request` with its database cleared and its collection reference and `document_matches`
/// literal replaced by markers no request carries.
fn text_skeleton(request: &pb::ExecutePipelineRequest) -> pb::ExecutePipelineRequest {
    use pb::value::ValueType as V;
    let mut request = request.clone();
    request.database.clear();
    if let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        &mut request.pipeline_type
    {
        for stage in structured
            .pipeline
            .iter_mut()
            .flat_map(|pipeline| &mut pipeline.stages)
        {
            match stage.name.as_str() {
                "collection" => {
                    if let [pb::Value {
                        value_type: Some(V::ReferenceValue(collection)),
                    }] = stage.args.as_mut_slice()
                    {
                        let recorded_class = collection.strip_prefix('/').is_some_and(|id| {
                            !id.contains('/')
                                && fireemu_core_types::ids::CollectionId::try_new(id).is_ok()
                        });
                        if recorded_class {
                            // A NUL never occurs in a request, so no literal equals the marker.
                            "\0collection".clone_into(collection);
                        }
                    }
                }
                "search" => {
                    if let Some(pb::Value {
                        value_type: Some(V::FunctionValue(query)),
                    }) = stage.options.get_mut("query")
                    {
                        if let (
                            "document_matches",
                            [pb::Value {
                                value_type: Some(V::StringValue(text)),
                            }],
                        ) = (query.name.as_str(), query.args.as_mut_slice())
                        {
                            if !text.is_empty() {
                                "\0query".clone_into(text);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    request
}

/// The recorded text requests of each transport, decoded as the server reads them.
fn text_requests() -> &'static Vec<TextRequest> {
    static ROWS: LazyLock<Vec<TextRequest>> = LazyLock::new(|| {
        let fixture: Value = serde_json::from_str(TEXT_REQUESTS).expect("text requests parse");
        fixture["programs"]
            .as_array()
            .expect("text programs")
            .iter()
            .flat_map(|program| {
                program["steps"]
                    .as_array()
                    .expect("text steps")
                    .iter()
                    .map(|step| TextRequest {
                        key: text_key(program["id"].as_str().expect("text program id"), step),
                        grpc: step["transport"] == "grpc",
                        #[cfg(test)]
                        body: step["body"].clone(),
                        request: crate::rest::pipeline_json::request_from_json("", &step["body"])
                            .expect("text request decodes"),
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    });
    &ROWS
}

/// Each transport contributes only its own observed `INVALID_ARGUMENT` message.
fn text_recorded_refusals(requests: &str, production: &str) -> HashMap<String, HashSet<String>> {
    let requests: Value = serde_json::from_str(requests).expect("text requests parse");
    let production: Value = serde_json::from_str(production).expect("text production parses");
    let mut table = HashMap::new();
    for program in requests["programs"].as_array().into_iter().flatten() {
        let Some(id) = program["id"].as_str() else {
            continue;
        };
        for step in program["steps"].as_array().into_iter().flatten() {
            if step["rpc"] != "executePipeline" {
                continue;
            }
            let Some(step_id) = step["id"].as_str() else {
                continue;
            };
            let answer = &production["programs"][id]["steps"][step_id];
            let message = if step["transport"] == "grpc" {
                if answer["transport"] != "grpc" || answer["code"] != 3 {
                    continue;
                }
                answer["message"].as_str()
            } else {
                if answer["status"] != 400 || !answer["transport"].is_null() {
                    continue;
                }
                let body = answer["body"]
                    .as_array()
                    .and_then(|body| body.first())
                    .unwrap_or(&answer["body"]);
                if body["error"]["status"] != "INVALID_ARGUMENT" {
                    continue;
                }
                body["error"]["message"].as_str()
            };
            if let Some(message) = message.filter(|message| !message.is_empty()) {
                table
                    .entry(text_key(id, step))
                    .or_insert_with(HashSet::new)
                    .insert(normalized_text(message));
            }
        }
    }
    table
}

/// The recorded refusals: each refused request's shape and its normalized texts.
fn recorded_text() -> &'static HashMap<String, HashSet<String>> {
    static RECORDED: LazyLock<HashMap<String, HashSet<String>>> =
        LazyLock::new(|| text_recorded_refusals(TEXT_REQUESTS, TEXT_PRODUCTION));
    &RECORDED
}

const GRPC_SELECT_WIDTH_KEY: &str = "grpc:fs-ent-pipeline/o2/select-width#select-65-grpc";

/// gRPC has no map order; compare the decoded request with the exact recorded width case.
fn recorded_grpc_select_width() -> Option<&'static (pb::ExecutePipelineRequest, String)> {
    static ROW: LazyLock<Option<(pb::ExecutePipelineRequest, String)>> = LazyLock::new(|| {
        let requests: Value = serde_json::from_str(REQUESTS).ok()?;
        let production: Value = serde_json::from_str(PRODUCTION).ok()?;
        let id = "fs-ent-pipeline/o2/select-width";
        let program = requests["programs"]
            .as_array()?
            .iter()
            .find(|p| p["id"] == id)?;
        // The corpus sends the same body for select-65 and select-65-grpc.
        let step = program["steps"]
            .as_array()?
            .iter()
            .find(|s| s["id"] == "select-65")?;
        let answer = &production["programs"][id]["steps"]["select-65-grpc"];
        if answer["transport"] != "grpc" || answer["code"] != 3 {
            return None;
        }
        let message = answer["message"].as_str()?.to_owned();
        let request = crate::rest::pipeline_json::request_from_json("", &step["body"]).ok()?;
        Some((request, message))
    });
    ROW.as_ref()
}

fn recorded() -> &'static HashMap<String, HashSet<String>> {
    static RECORDED: LazyLock<HashMap<String, HashSet<String>>> = LazyLock::new(|| {
        let mut table = recorded_refusals(REQUESTS, PRODUCTION);
        if let Some((_, message)) = recorded_grpc_select_width() {
            table
                .entry(GRPC_SELECT_WIDTH_KEY.to_owned())
                .or_default()
                .insert(normalized_text(message));
        }
        table
    });
    &RECORDED
}

/// Builds the table from the request and production fixtures' texts.
fn recorded_refusals(requests: &str, production: &str) -> HashMap<String, HashSet<String>> {
    let (requests, order) =
        json_syntax::parse_with_key_order(requests.as_bytes()).expect("request fixture parses");
    let production: Value = serde_json::from_str(production).expect("production fixture parses");
    let mut table: HashMap<String, HashSet<String>> = HashMap::new();
    let programs = requests["programs"].as_array().into_iter().flatten();
    for (p, program) in programs.enumerate() {
        let id = program["id"].as_str().unwrap_or_default();
        for (s, step) in program["steps"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            if step["rpc"] != "executePipeline" {
                continue;
            }
            let step_id = step["id"].as_str().unwrap_or_default();
            let answer = &production["programs"][id]["steps"][step_id];
            if answer["status"] != 400 {
                continue;
            }
            let element = answer["body"]
                .as_array()
                .and_then(|a| a.first())
                .unwrap_or(&answer["body"]);
            // Only an INVALID_ARGUMENT row answers a refusal the gate lets through (another
            // status on HTTP 400, such as FAILED_PRECONDITION, is no evidence for it).
            if element["error"]["status"] != "INVALID_ARGUMENT" {
                continue;
            }
            let Some(message) = element["error"]["message"].as_str() else {
                continue;
            };
            // A body sent as written (O-8A `rawBody`) is the shape of its parsed JSON, or, when
            // it is no JSON, its own text: only that exact body was refused with that text.
            let shape = if let Some(raw) = step["rawBody"].as_str() {
                match json_syntax::parse_with_key_order(raw.as_bytes()) {
                    Ok((body, order)) => shape_of_json(&body, &order),
                    Err(_) => Some(raw_shape(raw.as_bytes())),
                }
            } else {
                let body_order = order.rebased(&format!("/programs/{p}/steps/{s}/body"), "");
                shape_of_json(&step["body"], &body_order)
            };
            if let Some(shape) = shape {
                table
                    .entry(shape)
                    .or_default()
                    .insert(normalized_text(message));
            }
        }
    }
    table
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod text_refusal_tests {
    use super::*;
    use serde_json::json;

    const TEXT_REQUESTS: &str =
        include_str!("../../../conformance/fs-ent-text-refusal-requests.json");
    const DB: &str = "projects/local/databases/(default)";

    #[test]
    fn text_evidence_requires_each_matching_transport_status_and_message() {
        let requests: Value = serde_json::from_str(TEXT_REQUESTS).unwrap();
        let production: Value = serde_json::from_str(TEXT_PRODUCTION).unwrap();
        let table = text_recorded_refusals(TEXT_REQUESTS, TEXT_PRODUCTION);
        assert_eq!(table.len(), 9);
        let program = &requests["programs"][0];
        let id = program["id"].as_str().unwrap();
        for step in program["steps"].as_array().unwrap() {
            let key = text_key(id, step);
            let step_id = step["id"].as_str().unwrap();
            let grpc = step["transport"] == "grpc";
            for field in if grpc {
                vec!["code", "transport", "message"]
            } else {
                vec!["status", "error-status", "message"]
            } {
                let mut changed = production.clone();
                let answer = &mut changed["programs"][id]["steps"][step_id];
                match field {
                    "code" => answer["code"] = json!(9),
                    "transport" => answer["transport"] = json!("rest"),
                    "status" => answer["status"] = json!(200),
                    _ if grpc => answer["message"] = json!("different refusal"),
                    _ => {
                        let body = if answer["body"].is_array() {
                            &mut answer["body"][0]
                        } else {
                            &mut answer["body"]
                        };
                        body["error"][if field == "message" {
                            "message"
                        } else {
                            "status"
                        }] = json!("different refusal");
                    }
                }
                let changed_table = text_recorded_refusals(TEXT_REQUESTS, &changed.to_string());
                assert!(
                    !changed_table
                        .get(&key)
                        .is_some_and(|texts| texts == &table[&key]),
                    "{step_id}: {field}"
                );
            }
            let mut missing = production.clone();
            missing["programs"][id]["steps"]
                .as_object_mut()
                .unwrap()
                .remove(step_id);
            assert!(!text_recorded_refusals(TEXT_REQUESTS, &missing.to_string()).contains_key(&key));
            let mut missing = requests.clone();
            missing["programs"][0]["steps"]
                .as_array_mut()
                .unwrap()
                .retain(|row| row["id"] != step["id"]);
            assert!(
                !text_recorded_refusals(&missing.to_string(), TEXT_PRODUCTION).contains_key(&key)
            );
        }
    }

    /// The recorded body with another collection and, for a `document_matches` query, another
    /// query literal: production's option checks read neither (review S7).
    fn with_literals(body: &Value, collection: &str, query: &str) -> Value {
        let mut body = body.clone();
        body["structuredPipeline"]["pipeline"]["stages"][0]["args"][0]["referenceValue"] =
            json!(format!("/{collection}"));
        let root = &mut body["structuredPipeline"]["pipeline"]["stages"][1]["options"]["query"]
            ["functionValue"];
        if root["name"] == "document_matches" {
            root["args"][0]["stringValue"] = json!(query);
        }
        body
    }

    proptest::proptest! {
        #[test]
        fn changed_collection_and_query_literals_keep_text_authority(
            collection in "[a-z][a-z0-9_]{0,11}", query in "[a-z]{1,24}"
        ) {
            for row in text_requests() {
                let body = with_literals(&row.body, &collection, &query);
                let key = if row.grpc {
                    shape_of_request(&crate::rest::pipeline_json::request_from_json(DB, &body).unwrap())
                } else {
                    let (_, order) = json_syntax::parse_with_key_order(body.to_string().as_bytes()).unwrap();
                    shape_of_json(&body, &order)
                };
                proptest::prop_assert_eq!(key.as_deref(), Some(row.key.as_str()));
            }
        }
    }

    fn text_request_neighbors(body: &Value) -> Vec<Value> {
        let mut neighbors = Vec::new();
        // Collection and query classes the recordings do not cover (merge review S-b).
        for collection in ["/a/b", "/__x__", "/", ""] {
            let mut changed = body.clone();
            changed["structuredPipeline"]["pipeline"]["stages"][0]["args"][0]["referenceValue"] =
                json!(collection);
            neighbors.push(changed);
        }
        let root = &body["structuredPipeline"]["pipeline"]["stages"][1]["options"]["query"]
            ["functionValue"];
        if root["name"] == "document_matches" {
            let mut changed = body.clone();
            changed["structuredPipeline"]["pipeline"]["stages"][1]["options"]["query"]
                ["functionValue"]["args"][0]["stringValue"] = json!("");
            neighbors.push(changed);
        }
        // The collection may be any reference, never another kind of value.
        let mut changed = body.clone();
        changed["structuredPipeline"]["pipeline"]["stages"][0]["args"][0] =
            json!({"stringValue":"/textobs1"});
        neighbors.push(changed);
        // The query stays a document_matches call with one string argument.
        let mut changed = body.clone();
        changed["structuredPipeline"]["pipeline"]["stages"][1]["options"]["query"]
            ["functionValue"]["name"] = json!("document_matches_x");
        neighbors.push(changed);
        for field in ["extra", "retrieval_depth", "language_code"] {
            let mut changed = body.clone();
            changed["structuredPipeline"]["pipeline"]["stages"][1]["options"][field] =
                if field == "retrieval_depth" {
                    json!({"integerValue":"1"})
                } else {
                    json!({"stringValue":"en"})
                };
            neighbors.push(changed);
        }
        let mut changed = body.clone();
        changed["structuredPipeline"]["pipeline"]["stages"][1]["options"]["query"]
            ["functionValue"]["options"] = json!({"extra":{"booleanValue":true}});
        neighbors.push(changed);
        let mut changed = body.clone();
        changed["structuredPipeline"]["pipeline"]["stages"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"limit","args":[{"integerValue":"1"}]}));
        neighbors.push(changed);
        let mut changed = body.clone();
        changed["structuredPipeline"]["pipeline"]["stages"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        neighbors.push(changed);
        for (field, value) in [
            ("transaction", json!("AQ==")),
            ("autoCommitTransaction", json!(true)),
        ] {
            let mut changed = body.clone();
            changed[field] = value;
            neighbors.push(changed);
        }
        neighbors
    }

    #[test]
    fn exact_text_requests_and_neighbors() {
        let fixture: Value = serde_json::from_str(TEXT_REQUESTS).unwrap();
        let production: Value = serde_json::from_str(include_str!(
            "../../../conformance/fs-ent-text-production.json"
        ))
        .unwrap();
        for program in fixture["programs"].as_array().unwrap() {
            for step in program["steps"].as_array().unwrap() {
                let grpc = step["transport"] == "grpc";
                let shape = |body: &Value| {
                    if grpc {
                        let request =
                            crate::rest::pipeline_json::request_from_json(DB, body).unwrap();
                        shape_of_request(&request)
                    } else {
                        let (_, order) =
                            json_syntax::parse_with_key_order(body.to_string().as_bytes()).unwrap();
                        shape_of_json(body, &order)
                    }
                };
                let body = &step["body"];
                let key = shape(body).unwrap();
                assert!(key.starts_with("text-refusal-v1/"), "{}: {key}", step["id"]);
                let answer = &production["programs"][program["id"].as_str().unwrap()]["steps"]
                    [step["id"].as_str().unwrap()];
                let message = if grpc {
                    answer["message"].as_str().unwrap()
                } else {
                    let body = if answer["body"].is_array() {
                        &answer["body"][0]
                    } else {
                        &answer["body"]
                    };
                    body["error"]["message"].as_str().unwrap()
                };
                let gate = RefusalGate::Recorded(Some(key.clone()), DB.to_owned());
                assert_eq!(
                    gate.answer(Status::invalid_argument(message)).code(),
                    tonic::Code::InvalidArgument
                );
                assert_eq!(
                    gate.answer(Status::invalid_argument(format!("{message}!")))
                        .code(),
                    tonic::Code::Unimplemented
                );
                for neighbor in text_request_neighbors(body) {
                    let neighbor_key = shape(&neighbor);
                    assert_ne!(neighbor_key.as_ref(), Some(&key));
                    assert_eq!(
                        RefusalGate::Recorded(neighbor_key, DB.to_owned())
                            .answer(Status::invalid_argument(message))
                            .code(),
                        tonic::Code::Unimplemented,
                        "{}: {neighbor}",
                        step["id"]
                    );
                }
            }
        }
    }
}
