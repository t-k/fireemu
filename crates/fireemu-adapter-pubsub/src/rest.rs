//! JSON transcoding for the supported Pub/Sub REST operations.
//!
//! The REST surface deliberately calls the same `PubSubState` operations as gRPC. It is a
//! transport adapter only: it does not keep a second broker or a second clock.

use std::collections::BTreeMap;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use axum::response::Response;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use fireemu_core_pubsub::subscription::{
    DeadLetterPolicy, ExpirationPolicy, PushConfig, RetryPolicy, DEFAULT_ACK_DEADLINE_SECONDS,
    DEFAULT_RETRY_MINIMUM_BACKOFF_SECONDS, MAX_RETRY_BACKOFF_SECONDS,
};
use fireemu_core_pubsub::{
    Code, Filter, PubSubError, PubSubState, PubsubMessage, ReceivedMessage, Snapshot,
    StoredMessage, SubscriptionConfig, SubscriptionName, TopicName,
};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Map, Value};

use crate::convert::{
    is_declared_subscription_field, is_declared_topic_field, validate_subscription_update_paths,
    validate_topic_options, SUPPORTED_SUBSCRIPTION_FIELDS,
};
use crate::rest_json::Schema;
use crate::{PubSubHandle, MAX_MESSAGE_BYTES};
use fireemu_proto_pubsub::google::pubsub::v1 as pb;

const MAX_JSON_BYTES: usize = MAX_MESSAGE_BYTES + 1024 * 1024;

#[derive(Debug)]
pub(crate) struct RestError {
    status: StatusCode,
    code: &'static str,
    message: String,
    details: Option<Value>,
}

impl RestError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            details: None,
            status: StatusCode::BAD_REQUEST,
            code: "INVALID_ARGUMENT",
            message: message.into(),
        }
    }

    fn unknown_json_field(name: &str) -> Self {
        let description =
            format!("Invalid JSON payload received. Unknown name \"{name}\": Cannot find field.");
        let mut error = Self::invalid(description.clone());
        error.details = Some(
            json!([{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"description":description}]}]),
        );
        error
    }

    fn method_not_allowed() -> Self {
        Self {
            details: None,
            status: StatusCode::METHOD_NOT_ALLOWED,
            code: "METHOD_NOT_ALLOWED",
            message: "method is not supported for this Pub/Sub resource".to_owned(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            details: None,
            status: StatusCode::NOT_FOUND,
            code: "NOT_FOUND",
            message: message.into(),
        }
    }

    fn unimplemented(message: impl Into<String>) -> Self {
        Self {
            details: None,
            status: StatusCode::NOT_IMPLEMENTED,
            code: "UNIMPLEMENTED",
            message: message.into(),
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn from_core(error: PubSubError) -> Self {
        let (status, code) = match error.code() {
            Code::InvalidArgument => (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT"),
            Code::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Code::AlreadyExists => (StatusCode::CONFLICT, "ALREADY_EXISTS"),
            Code::FailedPrecondition => (StatusCode::BAD_REQUEST, "FAILED_PRECONDITION"),
            Code::ResourceExhausted => (StatusCode::TOO_MANY_REQUESTS, "RESOURCE_EXHAUSTED"),
            Code::Unimplemented => (StatusCode::NOT_IMPLEMENTED, "UNIMPLEMENTED"),
        };
        Self {
            details: None,
            status,
            code,
            message: crate::convert::wire_error_message(&error),
        }
    }

    fn from_resource_get(error: PubSubError, leaf: &str) -> Self {
        if error.code() == Code::NotFound {
            Self::not_found(format!("Resource not found (resource={leaf})."))
        } else {
            Self::from_core(error)
        }
    }
}

pub(crate) fn unauthenticated(
    method: &Method,
    path: &str,
    policy: crate::PagingPolicy,
) -> Response {
    let details = recorded_auth_method(method, path).map(|method| {
        json!([{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"CREDENTIALS_MISSING","metadata":{"method":format!("google.pubsub.v1.Publisher.{method}"),"service":"pubsub.googleapis.com"}}])
    });
    error_response(
        RestError {
            status: StatusCode::UNAUTHORIZED,
            code: "UNAUTHENTICATED",
            message: crate::authentication::INVALID_CREDENTIAL_MESSAGE.to_owned(),
            details,
        },
        policy,
    )
}

fn recorded_auth_method(method: &Method, path: &str) -> Option<&'static str> {
    let (project, resource) = path.strip_prefix("/v1/projects/")?.split_once('/')?;
    let leaf = resource.strip_prefix("topics/")?;
    if project.is_empty() || leaf.is_empty() || leaf.contains('/') {
        return None;
    }
    match (method, leaf.split_once(':')) {
        (&Method::GET, None) => Some("GetTopic"),
        (&Method::PUT, None) => Some("CreateTopic"),
        (&Method::POST, Some((topic, "publish"))) if !topic.is_empty() => Some("Publish"),
        _ => None,
    }
}

/// Handles one HTTP/JSON request that was not matched by a gRPC service route.
pub(crate) async fn handle(request: Request<Body>, handle: PubSubHandle) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or_default().to_owned();
    let limit = if handle.paging_policy == crate::PagingPolicy::Strict {
        MAX_MESSAGE_BYTES
    } else {
        MAX_JSON_BYTES
    };
    let body = match to_bytes(request.into_body(), limit).await {
        Ok(body) => body,
        Err(error) => {
            let message = if handle.paging_policy == crate::PagingPolicy::Strict
                && error.to_string() == "length limit exceeded"
            {
                "Request payload size exceeds the limit: 10485760 bytes.".to_owned()
            } else {
                format!("request body is too large: {error}")
            };
            return error_response(RestError::invalid(message), handle.paging_policy);
        }
    };
    let value = if body.is_empty() {
        Value::Object(Map::new())
    } else {
        match serde_json::from_slice::<Value>(&body) {
            Ok(value) => value,
            Err(error) => {
                return error_response(
                    RestError::invalid(format!("request body is not JSON: {error}")),
                    handle.paging_policy,
                );
            }
        }
    };

    match dispatch(&method, &path, &query, &value, &body, &handle) {
        Ok((status, response, schema)) => {
            json_response(status, response, handle.paging_policy, schema)
        }
        Err(error)
            if handle.paging_policy == crate::PagingPolicy::Strict
                && method == Method::GET
                && matches!(
                    error.message.as_str(),
                    "Pub/Sub REST paths must start with /v1/"
                        | "invalid Pub/Sub REST resource path"
                        | "unknown Pub/Sub REST resource"
                ) =>
        {
            route_not_found_response(&path)
        }
        Err(mut error) => {
            if handle.paging_policy == crate::PagingPolicy::Strict && error.details.is_none() {
                error.details = filter_error_details(&error.message);
            }
            error_response(error, handle.paging_policy)
        }
    }
}

fn filter_error_details(message: &str) -> Option<Value> {
    let suffix = message
        .strip_prefix("Invalid filter expression: failed to parse (syntax error at line ")?;
    let (line, suffix) = suffix.split_once(", column ")?;
    let (column, suffix) = suffix.split_once(", token '")?;
    let token = suffix.strip_suffix("').")?;
    line.parse::<usize>().ok()?;
    column.parse::<usize>().ok()?;
    Some(
        json!([{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"FILTER_EXPRESSION_FAILED_TO_PARSE","domain":"pubsub.googleapis.com","metadata":{"column":column,"line":line,"token":token,"message":"syntax error"}}]),
    )
}

fn escape_html_path(path: &str) -> String {
    path.chars()
        .map(|character| match character {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&#39;".to_owned(),
            _ => character.to_string(),
        })
        .collect()
}

fn route_not_found_response(path: &str) -> Response {
    let body = include_str!("route_not_found.html").replace("{{PATH}}", &escape_html_path(path));
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::NOT_FOUND;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/html; charset=UTF-8"),
    );
    response
}

fn dispatch(
    method: &Method,
    path: &str,
    query: &str,
    body: &Value,
    raw_body: &[u8],
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value, Schema), RestError> {
    let parts = path
        .strip_prefix("/v1/")
        .ok_or_else(|| RestError::not_found("Pub/Sub REST paths must start with /v1/"))?
        .split('/')
        .collect::<Vec<_>>();
    if parts.len() < 3 || parts[0] != "projects" || parts[1].is_empty() {
        return Err(RestError::not_found("invalid Pub/Sub REST resource path"));
    }
    let project = parts[1];
    if parts[2] == "topics" {
        return dispatch_topic(method, &parts[3..], project, query, body, handle);
    }
    if parts[2] == "subscriptions" {
        return dispatch_subscription(method, &parts[3..], project, query, body, raw_body, handle);
    }
    if parts[2] == "snapshots" {
        return dispatch_snapshot(method, &parts[3..], project, query, body, handle);
    }
    Err(RestError::not_found("unknown Pub/Sub REST resource"))
}

#[allow(clippy::too_many_lines)]
fn dispatch_topic(
    method: &Method,
    parts: &[&str],
    project: &str,
    query: &str,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value, Schema), RestError> {
    if parts.is_empty() {
        if *method != Method::GET {
            return Err(RestError::method_not_allowed());
        }
        let mut state = handle.state();
        let topics = state
            .list_topics(project)
            .into_iter()
            .map(|name| {
                let labels = state.topic_labels(&name).cloned().unwrap_or_default();
                topic_json(
                    &name,
                    &labels,
                    state.topic_retention(&name).unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        return Ok((
            StatusCode::OK,
            paged_collection_json(
                "topics",
                topics,
                query,
                handle,
                &mut state,
                &format!("projects/{project}/topics"),
            )?,
            Schema::Topics,
        ));
    }
    if parts.len() == 2
        && *method == Method::GET
        && matches!(parts[1], "subscriptions" | "snapshots")
    {
        let topic = TopicName::new(project, parts[0]).map_err(RestError::from_core)?;
        let now = handle.now();
        let mut state = handle.state();
        let names = if parts[1] == "subscriptions" {
            if !state.topic_exists(&topic) && handle.paging_policy == crate::PagingPolicy::Strict {
                return Err(RestError::not_found(format!(
                    "Resource not found (resource={}).",
                    parts[0]
                )));
            }
            state.topic_subscriptions(&topic)
        } else if !state.topic_exists(&topic)
            && handle.paging_policy == crate::PagingPolicy::Emulator
        {
            Vec::new()
        } else {
            state
                .list_topic_snapshots(&topic, now)
                .map_err(RestError::from_core)?
        };
        let resources = names.into_iter().map(Value::String).collect();
        return Ok((
            StatusCode::OK,
            paged_collection_json(
                parts[1],
                resources,
                query,
                handle,
                &mut state,
                &format!("{}/{}", topic.to_full(), parts[1]),
            )?,
            if parts[1] == "subscriptions" {
                Schema::Subscriptions
            } else {
                Schema::Snapshots
            },
        ));
    }
    if parts.len() != 1 {
        return Err(RestError::not_found("invalid topic resource path"));
    }

    let (topic_id, operation) = split_operation(parts);
    let topic = TopicName::new(project, topic_id).map_err(RestError::from_core)?;
    let schema = if operation == Some("publish") {
        Schema::Publish
    } else {
        Schema::Topic
    };
    match (method, operation) {
        (&Method::PUT, None) => create_topic(&topic, body, handle),
        (&Method::PATCH, None) => update_topic(&topic, body),
        (&Method::GET, None) => {
            let state = handle.state();
            let labels = state
                .topic_labels(&topic)
                .cloned()
                .map_err(|error| RestError::from_resource_get(error, topic.topic()))?;
            Ok((
                StatusCode::OK,
                topic_json(
                    &topic,
                    &labels,
                    state.topic_retention(&topic).unwrap_or_default(),
                ),
            ))
        }
        (&Method::DELETE, None) => {
            handle
                .state()
                .delete_topic(&topic)
                .map_err(RestError::from_core)?;
            handle.retry_pending_dead_letters();
            Ok((StatusCode::OK, json!({})))
        }
        (&Method::POST, Some("publish")) => publish(topic, body, handle),
        _ => Err(RestError::method_not_allowed()),
    }
    .map(|(status, value)| (status, value, schema))
}

fn create_topic(
    topic: &TopicName,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    let topic_options = topic_from_json(
        topic,
        body,
        handle.paging_policy == crate::PagingPolicy::Strict,
    )?;
    validate_topic_options(&topic_options).map_err(RestError::from_core)?;
    let labels = topic_options.labels.into_iter().collect();
    if handle.paging_policy == crate::PagingPolicy::Strict {
        fireemu_core_pubsub::configuration::validate_labels(&labels)
            .map_err(RestError::from_core)?;
    }
    let mut state = handle.state();
    state
        .create_topic_with_retention(
            topic.clone(),
            labels,
            topic_options
                .message_retention_duration
                .as_ref()
                .map(crate::convert::duration_from_proto)
                .transpose()
                .map_err(RestError::from_core)?,
        )
        .map_err(RestError::from_core)?;
    let labels = state
        .topic_labels(topic)
        .cloned()
        .map_err(RestError::from_core)?;
    let retention = state.topic_retention(topic).map_err(RestError::from_core)?;
    drop(state);
    handle.retry_pending_dead_letters();
    Ok((StatusCode::OK, topic_json(topic, &labels, retention)))
}

fn collection_json(field: &str, resources: Vec<Value>) -> Value {
    let mut response = Map::new();
    if !resources.is_empty() {
        response.insert(field.to_owned(), Value::Array(resources));
    }
    Value::Object(response)
}

fn paged_collection_json(
    field: &str,
    resources: Vec<Value>,
    query: &str,
    handle: &PubSubHandle,
    state: &mut PubSubState,
    context: &str,
) -> Result<Value, RestError> {
    let mut size = 0;
    let mut token = String::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let decoded =
            decode_query(key).and_then(|key| decode_query(value).map(|value| (key, value)));
        let (key, value) = match decoded {
            Ok(pair) => pair,
            Err(_) if handle.paging_policy == crate::PagingPolicy::Emulator => continue,
            Err(error) => return Err(error),
        };
        match key.as_str() {
            "pageSize" | "page_size" => match value.parse::<i32>() {
                Ok(parsed) => size = parsed,
                Err(_) if handle.paging_policy == crate::PagingPolicy::Emulator => {}
                Err(_) => return Err(RestError::invalid("pageSize must be an integer")),
            },
            "pageToken" | "page_token" => token = value,
            _ => {}
        }
    }
    let page = state
        .paginate(
            context,
            resources,
            size,
            &token,
            handle.paging_policy,
            |resource| {
                resource
                    .as_str()
                    .or_else(|| resource.get("name").and_then(Value::as_str))
                    .unwrap_or_default()
                    .to_owned()
            },
        )
        .map_err(RestError::from_core)?;
    let mut response = collection_json(field, page.resources);
    if !page.next_page_token.is_empty() {
        response.as_object_mut().expect("collection object").insert(
            "nextPageToken".to_owned(),
            Value::String(page.next_page_token),
        );
    }
    Ok(response)
}

pub(crate) fn decode_query(value: &str) -> Result<String, RestError> {
    use fireemu_core_types::codec::{
        percent_decode_bytes, percent_escapes_are_well_formed, PlusMode,
    };
    if !percent_escapes_are_well_formed(value) {
        return Err(RestError::invalid("invalid percent encoding in query"));
    }
    String::from_utf8(percent_decode_bytes(value, PlusMode::Space))
        .map_err(|_| RestError::invalid("query must be UTF-8"))
}

fn update_topic(topic: &TopicName, body: &Value) -> Result<(StatusCode, Value), RestError> {
    let topic_body = field(body, "topic").unwrap_or(body);
    let topic_options = topic_from_json(topic, topic_body, false)?;
    let update_mask = field(body, "updateMask")
        .and_then(Value::as_str)
        .ok_or_else(|| RestError::invalid("updateMask must be a comma-separated string"))?;
    if update_mask.is_empty() {
        validate_subscription_update_paths(&[""]).map_err(RestError::from_core)?;
    }
    let paths = update_mask.split(',').map(snake_case_field).collect();
    let request = pb::UpdateTopicRequest {
        topic: Some(topic_options),
        update_mask: Some(prost_types::FieldMask { paths }),
    };
    crate::convert::validate_topic_update_options(&request).map_err(RestError::from_core)?;
    Err(RestError::unimplemented(
        "UpdateTopic is not supported by the Pub/Sub emulator",
    ))
}

fn dispatch_subscription(
    method: &Method,
    parts: &[&str],
    project: &str,
    query: &str,
    body: &Value,
    raw_body: &[u8],
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value, Schema), RestError> {
    if parts.is_empty() {
        if *method != Method::GET {
            return Err(RestError::method_not_allowed());
        }
        let mut state = handle.state();
        let subscriptions = state
            .list_subscriptions(project)
            .into_iter()
            .map(|config| subscription_json(&state, &config, handle.paging_policy))
            .collect::<Vec<_>>();
        return Ok((
            StatusCode::OK,
            paged_collection_json(
                "subscriptions",
                subscriptions,
                query,
                handle,
                &mut state,
                &format!("projects/{project}/subscriptions"),
            )?,
            Schema::Subscriptions,
        ));
    }
    if parts.len() != 1 {
        return Err(RestError::not_found("invalid subscription resource path"));
    }

    let (subscription_id, operation) = split_operation(parts);
    let subscription =
        SubscriptionName::new(project, subscription_id).map_err(RestError::from_core)?;
    let schema = if operation == Some("pull") {
        Schema::Pull
    } else {
        Schema::Subscription
    };
    match (method, operation) {
        (&Method::PUT, None) => create_subscription(&subscription, body, handle),
        (&Method::GET, None) => get_subscription(subscription, handle),
        (&Method::PATCH, None) => update_subscription(subscription, body, handle),
        (&Method::DELETE, None) => {
            handle.invalidate_push_worker(&subscription);
            handle
                .state()
                .delete_subscription(&subscription)
                .map_err(RestError::from_core)?;
            handle.retry_pending_dead_letters();
            Ok((StatusCode::OK, json!({})))
        }
        (&Method::POST, Some("pull")) => pull(subscription, body, handle),
        (&Method::POST, Some("acknowledge")) => acknowledge(subscription, body, handle),
        (&Method::POST, Some("modifyAckDeadline")) => {
            modify_ack_deadline(subscription, body, handle)
        }
        (&Method::POST, Some("modifyPushConfig")) => {
            let push = field(body, "pushConfig")
                .map(|value| parse_push_config(value, handle.paging_policy))
                .transpose()?
                .unwrap_or_default();
            handle
                .state()
                .update_push_config(&subscription, push)
                .map_err(RestError::from_core)?;
            let topic = handle
                .state()
                .subscription_config(&subscription)
                .map_err(RestError::from_core)?
                .topic
                .clone();
            handle.schedule_push(&topic);
            Ok((StatusCode::OK, json!({})))
        }
        (&Method::POST, Some("seek")) => seek(subscription, body, raw_body, handle),
        _ => Err(RestError::method_not_allowed()),
    }
    .map(|(status, value)| (status, value, schema))
}

fn dispatch_snapshot(
    method: &Method,
    parts: &[&str],
    project: &str,
    query: &str,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value, Schema), RestError> {
    if parts.is_empty() {
        if *method != Method::GET {
            return Err(RestError::method_not_allowed());
        }
        let mut state = handle.state();
        let snapshots = state
            .list_snapshots(project, handle.now())
            .into_iter()
            .map(|snapshot| snapshot_json(&snapshot))
            .collect::<Vec<_>>();
        return Ok((
            StatusCode::OK,
            paged_collection_json(
                "snapshots",
                snapshots,
                query,
                handle,
                &mut state,
                &format!("projects/{project}/snapshots"),
            )?,
            Schema::Snapshots,
        ));
    }
    if parts.len() != 1 {
        return Err(RestError::not_found("invalid snapshot resource path"));
    }

    let (snapshot_id, operation) = split_operation(parts);
    let name = format!("projects/{project}/snapshots/{snapshot_id}");
    match (method, operation) {
        (&Method::PUT, None) => {
            let object = body
                .as_object()
                .ok_or_else(|| RestError::invalid("snapshot request must be an object"))?;
            reject_duplicate_spellings("snapshot", object)?;
            for key in object.keys() {
                let field = snake_case_field(key);
                if matches!(field.as_str(), "name" | "subscription" | "labels") {
                    continue;
                }
                if matches!(field.as_str(), "topic" | "expire_time" | "tags") {
                    return Err(RestError::unimplemented(format!(
                        "snapshot.{field} is not supported by the Pub/Sub emulator"
                    )));
                }
                return Err(RestError::invalid(format!("unknown snapshot field {key}")));
            }
            if let Some(body_name) = json_field(object, "name") {
                let body_name = body_name
                    .as_str()
                    .ok_or_else(|| RestError::invalid("snapshot.name must be a string"))?;
                if body_name != name {
                    return Err(RestError::invalid(
                        "snapshot.name must match the request path",
                    ));
                }
            }
            let subscription = string_field(body, "subscription")?;
            let subscription =
                SubscriptionName::parse(subscription).map_err(RestError::from_core)?;
            let snapshot = handle
                .state()
                .create_snapshot(
                    &name,
                    &subscription,
                    object_strings(body, "labels")?,
                    handle.now(),
                )
                .map_err(|error| {
                    RestError::from_core(crate::admission::snapshot_creation_error(
                        &name,
                        error,
                        handle.paging_policy,
                    ))
                })?;
            Ok((StatusCode::OK, snapshot_json(&snapshot)))
        }
        (&Method::GET, None) => {
            let snapshot = handle
                .state()
                .get_snapshot(&name, handle.now())
                .map_err(RestError::from_core)?;
            Ok((StatusCode::OK, snapshot_json(&snapshot)))
        }
        (&Method::DELETE, None) => {
            handle
                .state()
                .delete_snapshot(&name, handle.now())
                .map_err(RestError::from_core)?;
            Ok((StatusCode::OK, json!({})))
        }
        _ => Err(RestError::method_not_allowed()),
    }
    .map(|(status, value)| (status, value, Schema::Snapshot))
}

#[allow(clippy::needless_pass_by_value)]
fn publish(
    topic: TopicName,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    let messages = field(body, "messages")
        .and_then(Value::as_array)
        .ok_or_else(|| RestError::invalid("publish requires a messages array"))?
        .iter()
        .map(message_from_json)
        .collect::<Result<Vec<_>, _>>()?;
    if handle.paging_policy == crate::PagingPolicy::Strict {
        crate::admission::message_count(messages.len()).map_err(RestError::from_core)?;
    }
    let published = handle
        .publish(&topic, messages)
        .map_err(RestError::from_core)?;
    let ids = published
        .iter()
        .map(|message| message.message_id.clone())
        .collect::<Vec<_>>();
    Ok((StatusCode::OK, json!({"messageIds": ids})))
}

#[allow(clippy::needless_pass_by_value)]
fn validate_subscription_body(
    subscription: &SubscriptionName,
    body: &Value,
    route_name_precedence: bool,
) -> Result<(), RestError> {
    let object = body
        .as_object()
        .ok_or_else(|| RestError::invalid("subscription must be an object"))?;
    reject_duplicate_spellings("subscription", object)?;
    for key in object.keys() {
        let field = snake_case_field(key);
        if SUPPORTED_SUBSCRIPTION_FIELDS.contains(&field.as_str()) {
            continue;
        }
        if is_declared_subscription_field(&field) {
            return Err(RestError::unimplemented(format!(
                "subscription.{field} is not supported by the Pub/Sub emulator"
            )));
        }
        return Err(RestError::unknown_json_field(key));
    }
    if let Some(name) = json_field(object, "name") {
        let name = name
            .as_str()
            .ok_or_else(|| RestError::invalid("subscription.name must be a string"))?;
        if !route_name_precedence && name != subscription.to_full() {
            return Err(RestError::invalid(
                "subscription.name must match the request path",
            ));
        }
    }
    Ok(())
}

fn create_subscription(
    subscription: &SubscriptionName,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    validate_subscription_body(
        subscription,
        body,
        handle.paging_policy == crate::PagingPolicy::Strict,
    )?;
    let topic = TopicName::parse(string_field(body, "topic")?).map_err(RestError::from_core)?;
    let ack_deadline_seconds = parse_ack_deadline(field(body, "ackDeadlineSeconds"))?;
    let filter_source = field(body, "filter")
        .map(|filter| {
            filter
                .as_str()
                .ok_or_else(|| RestError::invalid("filter must be a string"))
        })
        .transpose()?
        .unwrap_or_default();
    let filter = Filter::parse(filter_source).map_err(RestError::from_core)?;
    let enable_message_ordering = field(body, "enableMessageOrdering")
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| RestError::invalid("enableMessageOrdering must be a boolean"))
        })
        .transpose()?
        .unwrap_or(false);
    let push_config = field(body, "pushConfig")
        .map(|value| parse_push_config(value, handle.paging_policy))
        .transpose()?
        .unwrap_or_default();
    let dead_letter_policy = field(body, "deadLetterPolicy")
        .map(parse_dead_letter_policy)
        .transpose()?;
    let retry_policy = field(body, "retryPolicy")
        .map(parse_retry_policy)
        .transpose()?;
    let retain_acked_messages = field(body, "retainAckedMessages")
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| RestError::invalid("retainAckedMessages must be a boolean"))
        })
        .transpose()?
        .unwrap_or(false);
    let message_retention_duration = field(body, "messageRetentionDuration")
        .map(parse_duration)
        .transpose()?;
    let mut config = SubscriptionConfig {
        labels: object_strings(body, "labels")?,
        expiration_policy: field(body, "expirationPolicy")
            .map(parse_expiration_policy)
            .transpose()?,
        retain_acked_messages,
        message_retention_duration,
        name: subscription.clone(),
        topic: topic.clone(),
        ack_deadline_seconds,
        enable_message_ordering,
        filter,
        dead_letter_policy,
        retry_policy,
        push_config,
    };
    if handle.paging_policy == crate::PagingPolicy::Strict {
        crate::convert::validate_strict_ack_deadline(
            i32::try_from(ack_deadline_seconds).unwrap_or(i32::MAX),
        )
        .map_err(RestError::from_core)?;
        if config.message_retention_duration.is_none() {
            config.message_retention_duration = Some(
                config
                    .expiration_policy
                    .and_then(|policy| policy.ttl)
                    .map_or(LogicalDuration::from_seconds(604_800), |ttl| {
                        ttl.min(LogicalDuration::from_seconds(604_800))
                    }),
            );
        }
        config
            .validate_production_configuration()
            .map_err(RestError::from_core)?;
    }
    let mut state = handle.state();
    state
        .create_subscription(config)
        .map_err(RestError::from_core)?;
    let config = state
        .subscription_config(subscription)
        .map_err(RestError::from_core)?
        .clone();
    let mut response = subscription_json(&state, &config, handle.paging_policy);
    if config.is_push() && handle.paging_policy == crate::PagingPolicy::Strict {
        response["pushConfig"]["attributes"]["x-goog-version"] = json!("v1");
    }
    drop(state);
    handle.retry_pending_dead_letters();
    handle.schedule_push(&topic);
    Ok((StatusCode::OK, response))
}

#[allow(clippy::needless_pass_by_value)]
fn get_subscription(
    subscription: SubscriptionName,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    let state = handle.state();
    let config = state
        .subscription_config(&subscription)
        .map_err(|error| RestError::from_resource_get(error, subscription.subscription()))?;
    Ok((
        StatusCode::OK,
        subscription_json(&state, config, handle.paging_policy),
    ))
}

#[allow(clippy::needless_pass_by_value)]
fn update_subscription(
    subscription: SubscriptionName,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    let update = field(body, "subscription")
        .and_then(Value::as_object)
        .ok_or_else(|| RestError::invalid("update requires a subscription object"))?;
    reject_duplicate_spellings("subscription", update)?;
    if let Some(name) = json_field(update, "name") {
        let name = name
            .as_str()
            .ok_or_else(|| RestError::invalid("subscription.name must be a string"))?;
        if name != subscription.to_full() {
            return Err(RestError::invalid(
                "subscription.name must match the request path",
            ));
        }
    }
    let update_mask = field(body, "updateMask")
        .and_then(Value::as_str)
        .ok_or_else(|| RestError::invalid("updateMask must be a comma-separated string"))?;
    if update_mask.is_empty() {
        return Err(RestError::invalid("The update_mask in the UpdateSubscriptionRequest must be set, and must contain a non-empty paths list."));
    }
    let paths = update_mask
        .split(',')
        .map(snake_case_field)
        .collect::<Vec<_>>();
    validate_subscription_update_paths(&paths).map_err(RestError::from_core)?;
    let ack_deadline_seconds = paths
        .iter()
        .any(|path| path == "ack_deadline_seconds")
        .then(|| parse_ack_deadline(json_field(update, "ackDeadlineSeconds")))
        .transpose()?;
    let push_config = if paths.iter().any(|path| path == "push_config") {
        Some(
            json_field(update, "pushConfig")
                .map(|value| parse_push_config(value, handle.paging_policy))
                .transpose()?
                .unwrap_or_default(),
        )
    } else {
        None
    };
    let change = parse_subscription_update(update, &paths, ack_deadline_seconds, push_config)?;
    let strict = handle.paging_policy == crate::PagingPolicy::Strict;
    if strict {
        if let Some(ack) = ack_deadline_seconds {
            crate::convert::validate_strict_ack_deadline(i32::try_from(ack).unwrap_or(i32::MAX))
                .map_err(RestError::from_core)?;
        }
    }
    let (topic, mut response) = {
        let mut state = handle.state();
        state
            .update_subscription_configuration(&subscription, change, strict)
            .map_err(RestError::from_core)?;
        let config = state
            .subscription_config(&subscription)
            .map_err(RestError::from_core)?
            .clone();
        (
            config.topic.clone(),
            subscription_json(&state, &config, handle.paging_policy),
        )
    };
    if strict {
        response["pushConfig"]["attributes"]["x-goog-version"] = json!("v1");
    }
    handle.schedule_push(&topic);
    Ok((StatusCode::OK, response))
}

fn parse_subscription_update(
    update: &Map<String, Value>,
    paths: &[String],
    ack_deadline_seconds: Option<u32>,
    push_config: Option<PushConfig>,
) -> Result<fireemu_core_pubsub::SubscriptionUpdate, RestError> {
    let selected = |path: &str| paths.iter().any(|value| value == path);
    let update_value = Value::Object(update.clone());
    Ok(fireemu_core_pubsub::SubscriptionUpdate {
        ack_deadline_seconds,
        push_config,
        labels: selected("labels")
            .then(|| object_strings(&update_value, "labels"))
            .transpose()?,
        retain_acked_messages: selected("retain_acked_messages")
            .then(|| {
                json_field(update, "retainAckedMessages")
                    .map(|value| {
                        value.as_bool().ok_or_else(|| {
                            RestError::invalid("retainAckedMessages must be a boolean")
                        })
                    })
                    .transpose()
                    .map(|value| value.unwrap_or(false))
            })
            .transpose()?,
        message_retention_duration: selected("message_retention_duration")
            .then(|| {
                json_field(update, "messageRetentionDuration")
                    .map(parse_duration)
                    .transpose()
            })
            .transpose()?,
        expiration_policy: selected("expiration_policy")
            .then(|| {
                json_field(update, "expirationPolicy")
                    .map(parse_expiration_policy)
                    .transpose()
            })
            .transpose()?,
        retry_policy: selected("retry_policy")
            .then(|| {
                json_field(update, "retryPolicy")
                    .map(parse_retry_policy)
                    .transpose()
            })
            .transpose()?,
        dead_letter_policy: selected("dead_letter_policy")
            .then(|| {
                json_field(update, "deadLetterPolicy")
                    .map(parse_dead_letter_policy)
                    .transpose()
            })
            .transpose()?,
    })
}

fn parse_push_config(value: &Value, policy: crate::PagingPolicy) -> Result<PushConfig, RestError> {
    let object = value
        .as_object()
        .ok_or_else(|| RestError::invalid("pushConfig must be an object"))?;
    reject_duplicate_spellings("pushConfig", object)?;
    for key in object.keys() {
        if !["push_endpoint", "attributes", "oidc_token"].contains(&snake_case_field(key).as_str())
        {
            return Err(RestError::unimplemented(format!(
                "pushConfig.{key} is not supported by the Pub/Sub emulator"
            )));
        }
    }
    let endpoint = json_field(object, "pushEndpoint")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| RestError::invalid("pushConfig.pushEndpoint must be a string"))
        })
        .transpose()?
        .unwrap_or_default()
        .to_owned();
    let oidc = json_field(object, "oidcToken")
        .map(|value| {
            let object = value
                .as_object()
                .ok_or_else(|| RestError::invalid("oidcToken must be an object"))?;
            if !object.is_empty() {
                return Err(RestError::unimplemented(
                    "pushConfig.oidcToken is not supported by the Pub/Sub emulator",
                ));
            }
            Ok(pb::push_config::AuthenticationMethod::OidcToken(
                pb::push_config::OidcToken::default(),
            ))
        })
        .transpose()?;
    crate::convert::push_config_from_proto(
        Some(&pb::PushConfig {
            push_endpoint: endpoint,
            attributes: object_strings(value, "attributes")?.into_iter().collect(),
            authentication_method: oidc,
            ..Default::default()
        }),
        policy,
    )
    .map_err(RestError::from_core)
}

fn parse_expiration_policy(value: &Value) -> Result<ExpirationPolicy, RestError> {
    let object = value
        .as_object()
        .ok_or_else(|| RestError::invalid("expirationPolicy must be an object"))?;
    reject_duplicate_spellings("expirationPolicy", object)?;
    if object.keys().any(|key| key != "ttl") {
        return Err(RestError::invalid("unknown expirationPolicy field"));
    }
    Ok(ExpirationPolicy {
        ttl: json_field(object, "ttl").map(parse_duration).transpose()?,
    })
}

fn parse_ack_deadline(value: Option<&Value>) -> Result<u32, RestError> {
    let seconds = value.map(parse_u32).transpose()?.unwrap_or_default();
    Ok(if seconds == 0 {
        DEFAULT_ACK_DEADLINE_SECONDS
    } else {
        seconds
    })
}

fn parse_dead_letter_policy(value: &Value) -> Result<DeadLetterPolicy, RestError> {
    let policy = value
        .as_object()
        .ok_or_else(|| RestError::invalid("deadLetterPolicy must be an object"))?;
    reject_duplicate_spellings("deadLetterPolicy", policy)?;
    for key in policy.keys() {
        if !matches!(
            snake_case_field(key).as_str(),
            "dead_letter_topic" | "max_delivery_attempts"
        ) {
            return Err(RestError::invalid(format!(
                "unknown deadLetterPolicy field {key}"
            )));
        }
    }
    Ok(DeadLetterPolicy {
        dead_letter_topic: TopicName::parse(string_field(value, "deadLetterTopic")?)
            .map_err(RestError::from_core)?,
        max_delivery_attempts: match json_field(policy, "maxDeliveryAttempts")
            .map(parse_u32)
            .transpose()?
            .unwrap_or_default()
        {
            0 => fireemu_core_pubsub::subscription::MIN_DEAD_LETTER_ATTEMPTS,
            attempts => attempts,
        },
    })
}

fn parse_retry_policy(value: &Value) -> Result<RetryPolicy, RestError> {
    let policy = value
        .as_object()
        .ok_or_else(|| RestError::invalid("retryPolicy must be an object"))?;
    reject_duplicate_spellings("retryPolicy", policy)?;
    for key in policy.keys() {
        if !matches!(
            snake_case_field(key).as_str(),
            "minimum_backoff" | "maximum_backoff"
        ) {
            return Err(RestError::invalid(format!(
                "unknown retryPolicy field {key}"
            )));
        }
    }
    Ok(RetryPolicy {
        minimum_backoff: json_field(policy, "minimumBackoff")
            .map(parse_duration)
            .transpose()?
            .unwrap_or_else(|| {
                LogicalDuration::from_seconds(DEFAULT_RETRY_MINIMUM_BACKOFF_SECONDS)
            }),
        maximum_backoff: json_field(policy, "maximumBackoff")
            .map(parse_duration)
            .transpose()?
            .unwrap_or_else(|| LogicalDuration::from_seconds(MAX_RETRY_BACKOFF_SECONDS)),
    })
}

fn parse_duration(value: &Value) -> Result<LogicalDuration, RestError> {
    let raw = value
        .as_str()
        .ok_or_else(|| RestError::invalid("duration must be a string"))?;
    let number = raw
        .strip_suffix('s')
        .ok_or_else(|| RestError::invalid("duration must end in s"))?;
    let has_fraction = number.contains('.');
    let (seconds, fraction) = number.split_once('.').map_or((number, ""), |parts| parts);
    if seconds.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || (has_fraction && fraction.is_empty())
        || fraction.len() > 9
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(RestError::invalid(
            "duration must be a non-negative protobuf duration",
        ));
    }
    let seconds = seconds
        .parse::<i128>()
        .map_err(|_| RestError::invalid("duration seconds are out of range"))?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        format!("{fraction:0<9}")
            .parse::<i128>()
            .map_err(|_| RestError::invalid("duration fraction is invalid"))?
    };
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|nanos| nanos.checked_add(fraction))
        .map(LogicalDuration::from_nanos)
        .ok_or_else(|| RestError::invalid("duration is out of range"))
}

#[allow(clippy::needless_pass_by_value)]
fn pull(
    subscription: SubscriptionName,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    if handle.paging_policy == crate::PagingPolicy::Strict
        && handle
            .state()
            .subscription_config(&subscription)
            .map_err(RestError::from_core)?
            .is_push()
    {
        return Err(RestError::from_core(PubSubError::failed_precondition(
            "This method is not supported for this subscription type.",
        )));
    }
    let max = if handle.paging_policy == crate::PagingPolicy::Strict {
        let value = field(body, "maxMessages")
            .map_or(Some(0), Value::as_i64)
            .ok_or_else(|| RestError::invalid("maxMessages must be an integer"))?;
        crate::admission::max_messages(value).map_err(RestError::from_core)?
    } else {
        field(body, "maxMessages")
            .map(parse_usize)
            .transpose()?
            .unwrap_or(100)
    };
    let report_attempt = handle.paging_policy == crate::PagingPolicy::Emulator
        || handle
            .state()
            .subscription_config(&subscription)
            .map_err(RestError::from_core)?
            .dead_letter_policy
            .is_some();
    let received = handle
        .pull(&subscription, max)
        .map_err(RestError::from_core)?;
    let mut body = json!({});
    if !received.is_empty() {
        body["receivedMessages"] = json!(received
            .iter()
            .map(|message| received_json(message, report_attempt, handle.paging_policy))
            .collect::<Vec<_>>());
    }
    Ok((StatusCode::OK, body))
}

#[allow(clippy::needless_pass_by_value)]
fn acknowledge(
    subscription: SubscriptionName,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    let mut ack_ids = string_array(body, "ackIds")?;
    if handle.paging_policy == crate::PagingPolicy::Strict {
        ack_ids = crate::admission::ack_ids(&ack_ids).map_err(RestError::from_core)?;
    }
    handle
        .acknowledge(&subscription, &ack_ids)
        .map_err(RestError::from_core)?;
    Ok((StatusCode::OK, json!({})))
}

#[allow(clippy::needless_pass_by_value)]
fn modify_ack_deadline(
    subscription: SubscriptionName,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    let mut ack_ids = string_array(body, "ackIds")?;
    let seconds =
        if handle.paging_policy == crate::PagingPolicy::Strict {
            ack_ids = crate::admission::ack_ids(&ack_ids).map_err(RestError::from_core)?;
            let value = field(body, "ackDeadlineSeconds")
                .map_or(Some(0), Value::as_i64)
                .ok_or_else(|| RestError::invalid("ackDeadlineSeconds must be an integer"))?;
            crate::admission::ack_deadline(value).map_err(RestError::from_core)?
        } else {
            parse_u32(field(body, "ackDeadlineSeconds").ok_or_else(|| {
                RestError::invalid("modifyAckDeadline requires ackDeadlineSeconds")
            })?)?
        };
    handle
        .state()
        .modify_ack_deadline(&subscription, &ack_ids, seconds, handle.now())
        .map_err(RestError::from_core)?;
    Ok((StatusCode::OK, json!({})))
}

// The ordinary Value map sorts keys. Inspect only Seek's top-level target occurrence order;
// serde_json consumes each value so nested fields and escaped strings cannot act as keys.
fn seek_conflicting_target(raw_body: &[u8]) -> Result<&'static str, RestError> {
    let invalid = || RestError::invalid("seek target order could not be read");
    let mut rest = raw_body
        .trim_ascii_start()
        .strip_prefix(b"{")
        .ok_or_else(invalid)?;
    let mut conflict = None;
    loop {
        rest = rest.trim_ascii_start();
        if rest.starts_with(b"}") {
            break;
        }
        let mut key = serde_json::Deserializer::from_slice(rest).into_iter::<String>();
        let key_name = key.next().ok_or_else(invalid)?.map_err(|_| invalid())?;
        rest = rest[key.byte_offset()..]
            .trim_ascii_start()
            .strip_prefix(b":")
            .ok_or_else(invalid)?;
        let mut value = serde_json::Deserializer::from_slice(rest).into_iter::<Value>();
        value.next().ok_or_else(invalid)?.map_err(|_| invalid())?;
        rest = rest[value.byte_offset()..].trim_ascii_start();
        match key_name.as_str() {
            "time" => conflict = Some("time"),
            "snapshot" => conflict = Some("snapshot"),
            _ => {}
        }
        if let Some(tail) = rest.strip_prefix(b",") {
            rest = tail;
        } else {
            break;
        }
    }
    conflict.ok_or_else(invalid)
}

#[allow(clippy::needless_pass_by_value)]
fn seek(
    subscription: SubscriptionName,
    body: &Value,
    raw_body: &[u8],
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    match (field(body, "snapshot"), field(body, "time")) {
        (Some(_), Some(_)) => {
            if handle.paging_policy == crate::PagingPolicy::Strict {
                let conflict = seek_conflicting_target(raw_body)?;
                let mut descriptions = vec![format!("Invalid value (oneof), oneof field 'target' is already set. Cannot set '{conflict}'")];
                if field(body, "subscription").is_some() {
                    descriptions.push("Invalid JSON payload received. Unknown name \"subscription\": Root element must be a message.".to_owned());
                }
                let mut error = RestError::invalid(descriptions.join("\n"));
                error.details = Some(
                    json!([{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":descriptions.iter().map(|description|json!({"description":description})).collect::<Vec<_>>()}]),
                );
                return Err(error);
            }
            return Err(RestError::invalid("seek takes either a time or a snapshot"));
        }
        (Some(snapshot), None) => {
            let snapshot = snapshot
                .as_str()
                .ok_or_else(|| RestError::invalid("seek snapshot must be a string"))?;
            handle
                .seek_to_snapshot(&subscription, snapshot)
                .map_err(RestError::from_core)?;
        }
        (None, Some(time)) => {
            let time = time
                .as_str()
                .ok_or_else(|| RestError::invalid("seek time must be an RFC 3339 string"))?;
            let time = LogicalInstant::parse_rfc3339(time)
                .map_err(|_| RestError::invalid("seek time must be an RFC 3339 string"))?;
            handle
                .seek_to_time(&subscription, time)
                .map_err(RestError::from_core)?;
        }
        (None, None) => {
            return Err(RestError::invalid(crate::admission::missing_seek_target(
                handle.paging_policy,
            )));
        }
    }
    Ok((StatusCode::OK, json!({})))
}

fn split_operation<'a>(parts: &'a [&'a str]) -> (&'a str, Option<&'a str>) {
    let last = parts.last().copied().unwrap_or_default();
    last.split_once(':')
        .map_or((last, None), |(resource, operation)| {
            (resource, Some(operation))
        })
}

fn string_field<'a>(body: &'a Value, name: &str) -> Result<&'a str, RestError> {
    field(body, name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RestError::invalid(format!("{name} must be a non-empty string")))
}

fn string_array(body: &Value, name: &str) -> Result<Vec<String>, RestError> {
    field(body, name)
        .and_then(Value::as_array)
        .ok_or_else(|| RestError::invalid(format!("{name} must be an array")))
        .and_then(|values| {
            values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| RestError::invalid(format!("{name} must contain strings")))
                })
                .collect()
        })
}

fn object_strings(body: &Value, name: &str) -> Result<BTreeMap<String, String>, RestError> {
    let Some(value) = field(body, name) else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| RestError::invalid(format!("{name} must be an object")))?;
    object
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_owned()))
                .ok_or_else(|| RestError::invalid(format!("{name} values must be strings")))
        })
        .collect()
}

fn parse_u32(value: &Value) -> Result<u32, RestError> {
    value
        .as_u64()
        .ok_or_else(|| RestError::invalid("number must be a non-negative integer"))
        .and_then(|value| {
            u32::try_from(value).map_err(|_| RestError::invalid("number is too large"))
        })
}

fn parse_usize(value: &Value) -> Result<usize, RestError> {
    value
        .as_u64()
        .ok_or_else(|| RestError::invalid("number must be a non-negative integer"))
        .and_then(|value| {
            usize::try_from(value).map_err(|_| RestError::invalid("number is too large"))
        })
}

fn message_from_json(value: &Value) -> Result<PubsubMessage, RestError> {
    let object = value
        .as_object()
        .ok_or_else(|| RestError::invalid("each published message must be an object"))?;
    let data = json_field(object, "data")
        .and_then(Value::as_str)
        .map(|data| {
            BASE64
                .decode(data)
                .map_err(|error| RestError::invalid(format!("message data is not base64: {error}")))
        })
        .transpose()?
        .unwrap_or_default();
    let attributes = json_field(object, "attributes")
        .map(|_| object_strings(value, "attributes"))
        .transpose()?
        .unwrap_or_default();
    let ordering_key = json_field(object, "orderingKey")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok(PubsubMessage {
        data,
        attributes,
        ordering_key,
    })
}

fn topic_json(
    name: &TopicName,
    labels: &BTreeMap<String, String>,
    retention: Option<LogicalDuration>,
) -> Value {
    let mut value = json!({"name": name.to_full()});
    if !labels.is_empty() {
        value["labels"] = json!(labels);
    }
    if let Some(retention) = retention {
        value["messageRetentionDuration"] = json!(duration_json(retention));
    }
    value
}

fn topic_from_json(
    topic: &TopicName,
    body: &Value,
    route_name_precedence: bool,
) -> Result<pb::Topic, RestError> {
    let object = body
        .as_object()
        .ok_or_else(|| RestError::invalid("topic must be an object"))?;
    reject_duplicate_spellings("topic", object)?;
    for key in object.keys() {
        let field = snake_case_field(key);
        if is_declared_topic_field(&field) {
            continue;
        }
        return Err(RestError::unknown_json_field(key));
    }
    if let Some(name) = json_field(object, "name") {
        let name = name
            .as_str()
            .ok_or_else(|| RestError::invalid("topic.name must be a string"))?;
        if !route_name_precedence && name != topic.to_full() {
            return Err(RestError::invalid("topic.name must match the request path"));
        }
    }
    let mut options = pb::Topic {
        name: topic.to_full(),
        labels: object_strings(body, "labels")?.into_iter().collect(),
        ..Default::default()
    };
    if json_field(object, "schemaSettings").is_some_and(|value| !value.is_null()) {
        options.schema_settings = Some(pb::SchemaSettings::default());
    }
    if let Some(value) =
        json_field(object, "messageRetentionDuration").filter(|value| !value.is_null())
    {
        options.message_retention_duration =
            Some(crate::convert::duration_to_proto(parse_duration(value)?));
    }
    if let Some(value) = json_field(object, "kmsKeyName") {
        if !value.is_null() {
            value
                .as_str()
                .ok_or_else(|| RestError::invalid("topic.kmsKeyName must be a string"))?
                .clone_into(&mut options.kms_key_name);
        }
    }
    if json_field(object, "messageStoragePolicy").is_some_and(|value| !value.is_null()) {
        options.message_storage_policy = Some(pb::MessageStoragePolicy::default());
    }
    if json_field(object, "ingestionDataSourceSettings").is_some_and(|value| !value.is_null()) {
        options.ingestion_data_source_settings = Some(pb::IngestionDataSourceSettings::default());
    }
    if let Some(value) = json_field(object, "messageTransforms") {
        if !value.is_null() {
            let transforms = value
                .as_array()
                .ok_or_else(|| RestError::invalid("topic.messageTransforms must be an array"))?;
            if !transforms.is_empty() {
                options
                    .message_transforms
                    .push(pb::MessageTransform::default());
            }
        }
    }
    if let Some(value) = json_field(object, "tags") {
        if !value.is_null() {
            let tags = value
                .as_object()
                .ok_or_else(|| RestError::invalid("topic.tags must be an object"))?;
            if !tags.is_empty() {
                options.tags.insert(String::new(), String::new());
            }
        }
    }
    Ok(options)
}

/// Reads one field of a JSON object by its `lowerCamelCase` name, also accepting the `snake_case`
/// spelling of the same protobuf field, which proto3 JSON accepts on input. Every reader goes
/// through this, so a spelling that admission accepts is never dropped by the reader.
fn json_field<'a>(object: &'a Map<String, Value>, camel_name: &str) -> Option<&'a Value> {
    object.get(camel_name).or_else(|| {
        let snake = snake_case_field(camel_name);
        (snake != camel_name).then(|| object.get(&snake)).flatten()
    })
}

/// [`json_field`] for a body that is expected to be an object.
fn field<'a>(body: &'a Value, camel_name: &str) -> Option<&'a Value> {
    body.as_object()
        .and_then(|object| json_field(object, camel_name))
}

/// Refuses a body that spells the same protobuf field twice, which proto3 JSON rejects as a
/// duplicate name rather than silently picking one.
fn reject_duplicate_spellings(
    resource: &str,
    object: &Map<String, Value>,
) -> Result<(), RestError> {
    let mut seen = BTreeMap::new();
    for key in object.keys() {
        if let Some(previous) = seen.insert(snake_case_field(key), key) {
            return Err(RestError::invalid(format!(
                "{resource} names the same field twice: {previous} and {key}"
            )));
        }
    }
    Ok(())
}

/// Normalizes a JSON field name or field-mask path to its protobuf spelling. The Pub/Sub JSON API
/// accepts both the `lowerCamelCase` and the original `snake_case` spelling, so both reach the
/// shared option validators, and the readers, under one name. Every segment of a nested path is
/// normalized, so a REST refusal names the same path a gRPC refusal names.
fn snake_case_field(field: &str) -> String {
    let mut normalized = String::with_capacity(field.len() + 4);
    for (index, segment) in field.split('.').enumerate() {
        if index > 0 {
            normalized.push('.');
        }
        for ch in segment.chars() {
            if ch.is_ascii_uppercase() {
                normalized.push('_');
                normalized.push(ch.to_ascii_lowercase());
            } else {
                normalized.push(ch);
            }
        }
    }
    normalized
}

fn subscription_json(
    state: &PubSubState,
    config: &SubscriptionConfig,
    policy: crate::PagingPolicy,
) -> Value {
    let topic = state
        .reported_topic(&config.name)
        .unwrap_or_else(|| config.topic.to_full());
    // The defaults below are the recorded production REST response of a created pull subscription
    // (capture-only evidence, not closure evidence): fireemu-oracle-idp run
    // shape-001-6a666e3ffa9444cc80de18944b38ae36, subscription-create.json and subscription-get.json
    // (recorded 2026-09-30T13:13:53Z, status 200, 372 bytes, sha256
    // e744f1e67909fc9abd1931ae547e8eb3aecf15dd98184542b884cd8ed086bf8f; docs.local/runs/codex-lane7/),
    // and fireemu-oracle-sbx, docs.local/runs/codex-lane8/recorded-shape-responses/create-subscription.json
    // (resource fe-scheduled-shape-96db1cb7ca5fcb35, the same defaults). They apply when the request set
    // no retention, ordering, retain-acked or push configuration; explicit values override them below.
    let mut value = json!({
        "name": config.name.to_full(),
        "topic": topic,
        "ackDeadlineSeconds": config.ack_deadline_seconds,
        "pushConfig": {},
        "messageRetentionDuration": "604800s",
        "expirationPolicy": {"ttl": "2678400s"},
        "state": "ACTIVE",
    });
    if config.enable_message_ordering {
        value["enableMessageOrdering"] = json!(true);
    }
    if config.retain_acked_messages {
        value["retainAckedMessages"] = json!(true);
    }
    if let Some(duration) = config.message_retention_duration {
        value["messageRetentionDuration"] = json!(duration_json(duration));
    }
    if !config.labels.is_empty() {
        value["labels"] = json!(config.labels);
    }
    if let Some(policy) = config.expiration_policy {
        value["expirationPolicy"] = policy
            .ttl
            .map_or_else(|| json!({}), |ttl| json!({"ttl":duration_json(ttl)}));
    }
    if !config.push_config.push_endpoint.is_empty() {
        value["pushConfig"] = json!({"pushEndpoint": config.push_config.push_endpoint});
        let attributes = config
            .push_config
            .attributes
            .iter()
            .filter(|(key, _)| {
                policy == crate::PagingPolicy::Emulator || key.as_str() != "x-goog-version"
            })
            .collect::<BTreeMap<_, _>>();
        if !attributes.is_empty() {
            value["pushConfig"]["attributes"] = json!(attributes);
        }
    }
    if !config.filter.as_str().is_empty() {
        value["filter"] = json!(config.filter.as_str());
    }
    if let Some(policy) = &config.dead_letter_policy {
        value["deadLetterPolicy"] = json!({
            "deadLetterTopic": policy.dead_letter_topic.to_full(),
            "maxDeliveryAttempts": policy.max_delivery_attempts,
        });
    }
    if let Some(policy) = config.retry_policy {
        value["retryPolicy"] = json!({
            "minimumBackoff": duration_json(policy.minimum_backoff),
            "maximumBackoff": duration_json(policy.maximum_backoff),
        });
    }
    value
}

fn duration_json(duration: LogicalDuration) -> String {
    let nanos = duration.as_nanos();
    let seconds = nanos.div_euclid(1_000_000_000);
    let fraction = nanos.rem_euclid(1_000_000_000);
    if fraction == 0 {
        return format!("{seconds}s");
    }
    let (divisor, width) = if fraction % 1_000_000 == 0 {
        (1_000_000, 3)
    } else if fraction % 1_000 == 0 {
        (1_000, 6)
    } else {
        (1, 9)
    };
    format!("{seconds}.{:0width$}s", fraction / divisor)
}

fn snapshot_json(snapshot: &Snapshot) -> Value {
    let mut value = json!({
        "name": snapshot.name,
        "topic": snapshot.topic.to_full(),
        "expireTime": timestamp_json(snapshot.expire_at),
    });
    if !snapshot.labels.is_empty() {
        value["labels"] = json!(snapshot.labels);
    }
    value
}

fn received_json(
    received: &ReceivedMessage,
    report_attempt: bool,
    policy: crate::PagingPolicy,
) -> Value {
    let mut value = json!({"ackId":crate::ack_token::rest_wire(&received.ack_id,policy),"message":stored_message_json(&received.message)});
    if report_attempt {
        value["deliveryAttempt"] = json!(received.delivery_attempt);
    }
    value
}

fn stored_message_json(message: &StoredMessage) -> Value {
    let mut value = json!({
        "messageId": message.message_id,
        "publishTime": timestamp_json(message.publish_time),
    });
    if !message.message.data.is_empty() {
        value["data"] = json!(BASE64.encode(&message.message.data));
    }
    if !message.message.attributes.is_empty() {
        value["attributes"] = json!(message.message.attributes);
    }
    if !message.message.ordering_key.is_empty() {
        value["orderingKey"] = json!(message.message.ordering_key);
    }
    value
}

fn timestamp_json(instant: LogicalInstant) -> String {
    let nanos = instant.as_nanos();
    let seconds = nanos.div_euclid(1_000_000_000);
    let fraction = nanos.rem_euclid(1_000_000_000);
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }).div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era.div_euclid(1_460) + day_of_era.div_euclid(36_524)
        - day_of_era.div_euclid(146_096))
    .div_euclid(365);
    let year = year_of_era + era * 400;
    let day_of_year =
        day_of_era - (365 * year_of_era + year_of_era.div_euclid(4) - year_of_era.div_euclid(100));
    let month_part = (5 * day_of_year + 2).div_euclid(153);
    let day = day_of_year - (153 * month_part + 2).div_euclid(5) + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    let year = year + i128::from(month <= 2);
    let hour = day_seconds.div_euclid(3_600);
    let minute = day_seconds.rem_euclid(3_600).div_euclid(60);
    let second = day_seconds.rem_euclid(60);
    if fraction == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    } else {
        let (divisor, width) = if fraction % 1_000_000 == 0 {
            (1_000_000, 3)
        } else if fraction % 1_000 == 0 {
            (1_000, 6)
        } else {
            (1, 9)
        };
        format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:0width$}Z",
            fraction / divisor
        )
    }
}

#[allow(clippy::needless_pass_by_value)]
fn json_response(
    status: StatusCode,
    value: Value,
    policy: crate::PagingPolicy,
    schema: Schema,
) -> Response {
    let body = crate::rest_json::encode(&value, policy, schema);
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("valid JSON response")
}

#[allow(clippy::needless_pass_by_value)]
fn error_response(error: RestError, policy: crate::PagingPolicy) -> Response {
    let mut body =
        json!({"error":{"code":error.status.as_u16(),"status":error.code,"message":error.message}});
    if let Some(details) = error.details {
        body["error"]["details"] = details;
    }
    json_response(error.status, body, policy, Schema::ErrorEnvelope)
}

#[cfg(test)]
mod production_shape_tests {
    use super::*;
    use proptest::prelude::*;

    fn local_handle(policy: crate::PagingPolicy) -> PubSubHandle {
        PubSubHandle::new(
            std::sync::Arc::new(std::sync::Mutex::new(PubSubState::new(1))),
            std::sync::Arc::new(std::sync::Mutex::new(
                fireemu_core_session::clock::VirtualClock::new(LogicalInstant::from_unix_seconds(
                    0,
                )),
            )),
            None,
        )
        .with_paging_policy(policy)
    }

    proptest! {
        #[test]
        fn seek_target_order_ignores_escaped_and_nested_targets(time_first in any::<bool>(), noise in ".{0,80}", spaces in 0usize..8) {
            let nested = serde_json::to_string(&json!({"time":noise,"snapshot":[{"time":"ignored"}]})).unwrap();
            let padding=" ".repeat(spaces);
            let (first, second)=if time_first { ("time", "snapshot") } else { ("snapshot", "time") };
            let request=format!("{{{padding}\"noise\":{nested},\"{first}\":\"value\",\"{second}\":\"value\"{padding}}}");
            prop_assert_eq!(seek_conflicting_target(request.as_bytes()).unwrap(),second);
        }

        #[test]
        fn authentication_method_details_match_only_recorded_route_classes(project in "[a-z]{1,20}", leaf in "[a-z]{1,30}") {
            let resource = format!("/v1/projects/{project}/topics/{leaf}");
            prop_assert_eq!(recorded_auth_method(&Method::GET, &resource), Some("GetTopic"));
            prop_assert_eq!(recorded_auth_method(&Method::PUT, &resource), Some("CreateTopic"));
            prop_assert_eq!(recorded_auth_method(&Method::POST, &format!("{resource}:publish")), Some("Publish"));
            for (method, path) in [
                (Method::DELETE, resource.clone()),
                (Method::POST, resource.clone()),
                (Method::POST, format!("{resource}:other")),
                (Method::GET, format!("{resource}:publish")),
                (Method::GET, format!("{resource}/child")),
                (Method::GET, format!("/v1/projects//topics/{leaf}")),
                (Method::GET, format!("/v1/projects/{project}/subscriptions/{leaf}")),
                (Method::GET, format!("/projects/{project}/topics/{leaf}")),
                (Method::GET, format!("/v1/projects/{project}/topics/")),
                (Method::POST, format!("/v1/projects/{project}/topics/:publish")),
            ] {
                prop_assert_eq!(recorded_auth_method(&method, &path), None);
            }
        }

        #[test]
        fn strict_rest_default_retention_matches_ttl_reference(ttl in 86_400i64..=2_678_400, explicit in any::<bool>()) {
            let handle = local_handle(crate::PagingPolicy::Strict);
            let topic = TopicName::new("demo-app", "ttl-property").unwrap();
            handle.state().create_topic(topic.clone(), BTreeMap::new()).unwrap();
            let mut body = json!({"topic":topic.to_full(), "expirationPolicy":{"ttl":format!("{ttl}s")}});
            if explicit { body["messageRetentionDuration"] = json!("600s"); }
            let subscription = SubscriptionName::new("demo-app", "ttl-property").unwrap();
            let (_, response) = create_subscription(&subscription, &body, &handle).unwrap();
            let expected = format!("{}s", if explicit {600} else {ttl.min(604_800)});
            prop_assert_eq!(response["messageRetentionDuration"].as_str(), Some(expected.as_str()));
        }
        #[test]
        fn rest_snapshot_and_topic_labels_are_present_exactly_when_nonempty(labels in prop::collection::btree_map("[a-z]{1,8}","[a-z0-9]{0,8}",0..4)) {
            let topic = TopicName::new("demo-app", "label-property").unwrap();
            let config = crate::convert::subscription_from_proto(&pb::Subscription { name:"projects/demo-app/subscriptions/label-property".into(), topic:topic.to_full(), ..Default::default() }).unwrap();
            let mut state = PubSubState::new(1);
            state.create_topic(topic.clone(), labels.clone()).unwrap();
            state.create_subscription(config.clone()).unwrap();
            let snapshot = state.create_snapshot("projects/demo-app/snapshots/label-property", &config.name, labels.clone(), LogicalInstant::from_unix_seconds(0)).unwrap();
            for rendered in [topic_json(&topic, &labels, None), snapshot_json(&snapshot)] {
                prop_assert_eq!(rendered.get("labels").is_some(), !labels.is_empty());
                if !labels.is_empty() { prop_assert_eq!(&rendered["labels"], &json!(labels)); }
            }
        }
        #[test]
        fn rest_delivery_attempt_presence_matches_policy_and_dead_letter_model(attempt in 1u32..100, dead_letter in any::<bool>()) {
            for policy in [crate::PagingPolicy::Strict, crate::PagingPolicy::Emulator] {
                let handle = local_handle(policy);
                let topic = TopicName::new("demo-app", "attempt-property").unwrap();
                let subscription = SubscriptionName::new("demo-app", "attempt-property").unwrap();
                let input = pb::Subscription { name:subscription.to_full(), topic:topic.to_full(), dead_letter_policy:dead_letter.then(|| pb::DeadLetterPolicy {dead_letter_topic:"projects/demo-app/topics/attempt-sink".into(),max_delivery_attempts:100}), ..Default::default() };
                let config = crate::convert::subscription_from_proto_with_policy(&input, policy).unwrap();
                handle.state().create_topic(topic.clone(), BTreeMap::new()).unwrap();
                if dead_letter {
                    handle.state().create_topic(TopicName::new("demo-app", "attempt-sink").unwrap(), BTreeMap::new()).unwrap();
                }
                handle.state().create_subscription(config).unwrap();
                handle.state().publish(&topic, vec![PubsubMessage {data:vec![b'x'], ..Default::default()}], LogicalInstant::from_unix_seconds(0)).unwrap();
                let (_, response) = pull(subscription, &json!({"maxMessages":1}), &handle).unwrap();
                let report = policy == crate::PagingPolicy::Emulator || dead_letter;
                prop_assert_eq!(response["receivedMessages"][0].get("deliveryAttempt").is_some(), report);
                if report { prop_assert_eq!(&response["receivedMessages"][0]["deliveryAttempt"], &json!(1)); }
                let received = ReceivedMessage {ack_id:"ack-0000000000000001".into(),message:std::sync::Arc::new(StoredMessage { message:PubsubMessage::default(),message_id:"22254029608272384".into(),publish_time:LogicalInstant::from_unix_seconds(0)}), delivery_attempt:attempt};
                let rendered = received_json(&received, report, policy);
                prop_assert_eq!(rendered.get("deliveryAttempt").is_some(), report);
                if report { prop_assert_eq!(&rendered["deliveryAttempt"], &json!(attempt)); }
            }
        }
    }

    proptest! {
        #[test]
        fn emulator_invalid_query_pairs_match_absent_pair_reference(size in 1i32..8, count in 2usize..12, invalid in prop::sample::select(vec!["pageSize=abc", "pageSize=99999999999", "pageSize=-99999999999", "pageSize=%", "pageSize=%0", "pageSize=%gg", "pageSize=%FF", "pageToken=%zz", "pageToken=%FF", "%FF=1", "%gg=1"])) {
            let handle = PubSubHandle::new(
                std::sync::Arc::new(std::sync::Mutex::new(PubSubState::new(1))),
                std::sync::Arc::new(std::sync::Mutex::new(fireemu_core_session::clock::VirtualClock::new(LogicalInstant::from_unix_seconds(0)))),
                None,
            ).with_paging_policy(crate::PagingPolicy::Emulator);
            let resources: Vec<_> = (0..count).map(|i| json!({"name":format!("projects/p/topics/query-{i:03}")})).collect();
            let valid = format!("pageSize={size}&pageToken=projects%2Fp%2Ftopics%2Fquery-001");
            let expected = paged_collection_json("topics", resources.clone(), &valid, &handle, &mut handle.state(), "projects/p/topics").unwrap();
            for query in [format!("{valid}&{invalid}"), format!("{invalid}&{valid}")] {
                let result = paged_collection_json("topics", resources.clone(), &query, &handle, &mut handle.state(), "projects/p/topics");
                prop_assert!(result.is_ok(), "{}", query);
                prop_assert_eq!(result.unwrap(), expected.clone());
            }
        }
    }

    #[test]
    fn emulator_rest_push_get_preserves_version_attributes() {
        let topic = TopicName::new("demo-app", "push-attributes").unwrap();
        let config = crate::convert::subscription_from_proto_with_policy(
            &pb::Subscription {
                name: "projects/demo-app/subscriptions/push-attributes".to_owned(),
                topic: topic.to_full(),
                push_config: Some(pb::PushConfig {
                    push_endpoint: "https://example.com/push".to_owned(),
                    attributes: [("x-goog-version".to_owned(), "v1".to_owned())].into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            crate::PagingPolicy::Emulator,
        )
        .unwrap();
        let mut state = PubSubState::new(1);
        state.create_topic(topic, BTreeMap::new()).unwrap();
        state.create_subscription(config.clone()).unwrap();
        assert_eq!(
            subscription_json(&state, &config, crate::PagingPolicy::Emulator)["pushConfig"]
                ["attributes"]["x-goog-version"],
            "v1"
        );
    }

    proptest! {
        #[test]
        fn push_attributes_serialize_by_profile(version in "[a-z0-9]{1,12}") {
            let config = crate::convert::subscription_from_proto_with_policy(&pb::Subscription {
                name:"projects/demo-app/subscriptions/push-property".to_owned(),
                topic:"projects/demo-app/topics/push-property".to_owned(),
                push_config:Some(pb::PushConfig {push_endpoint:"https://example.com/push".to_owned(),attributes:[("x-goog-version".to_owned(),version.clone())].into(),..Default::default()}),
                ..Default::default()
            },crate::PagingPolicy::Emulator).unwrap();
            let state = PubSubState::new(1);
            let permissive = subscription_json(&state,&config,crate::PagingPolicy::Emulator);
            let strict = subscription_json(&state,&config,crate::PagingPolicy::Strict);
            prop_assert_eq!(permissive["pushConfig"]["attributes"]["x-goog-version"].as_str(),Some(version.as_str()));
            prop_assert!(strict["pushConfig"].get("attributes").is_none());
        }
    }

    proptest! {
        #[test]
        fn canonical_timestamp_round_trips_nanos(seconds in -2_208_988_800i64..4_102_444_800, fraction in 0i128..1_000_000_000) {
            let instant = LogicalInstant::from_nanos(i128::from(seconds)*1_000_000_000+fraction);
            let rendered = timestamp_json(instant);
            prop_assert_eq!(LogicalInstant::parse_rfc3339(&rendered).unwrap(), instant);
            let width = rendered.split_once('.').map_or(0, |(_,rest)|rest.len()-1);
            let expected = if fraction == 0 {0} else if fraction % 1_000_000 == 0 {3} else if fraction % 1_000 == 0 {6} else {9};
            prop_assert_eq!(width, expected);
        }

        #[test]
        fn optional_message_fields_round_trip(data in proptest::collection::vec(any::<u8>(),0..100), attributes in proptest::collection::btree_map("[a-z]{1,10}","[a-z0-9]{0,10}",0..5), ordering_key in "[a-z0-9]{0,10}") {
            let message = PubsubMessage {data,attributes,ordering_key};
            let stored = StoredMessage {message:message.clone(),message_id:"22254029608272384".to_owned(),publish_time:LogicalInstant::from_unix_seconds(0)};
            let rendered = stored_message_json(&stored);
            prop_assert_eq!(rendered.get("data").is_some(),!message.data.is_empty());
            prop_assert_eq!(rendered.get("attributes").is_some(),!message.attributes.is_empty());
            prop_assert_eq!(rendered.get("orderingKey").is_some(),!message.ordering_key.is_empty());
            prop_assert_eq!(message_from_json(&rendered).unwrap(),message);
        }
    }

    #[test]
    fn recorded_json_omits_empty_message_members_and_uses_canonical_timestamp_precision() {
        let stored = StoredMessage {
            message: PubsubMessage {
                data: vec![0, 255],
                ..Default::default()
            },
            message_id: "22254029608272384".to_owned(),
            publish_time: LogicalInstant::from_nanos(1_700_000_000_123_000_000),
        };
        assert_eq!(
            stored_message_json(&stored),
            json!({"data":"AP8=","messageId":"22254029608272384","publishTime":"2023-11-14T22:13:20.123Z"})
        );
        for (fraction, suffix) in [
            (0, "Z"),
            (123_000_000, ".123Z"),
            (123_456_000, ".123456Z"),
            (123_456_789, ".123456789Z"),
        ] {
            assert_eq!(
                timestamp_json(LogicalInstant::from_nanos(
                    1_700_000_000_000_000_000 + fraction
                )),
                format!("2023-11-14T22:13:20{suffix}")
            );
        }
    }
}

#[cfg(test)]
mod route_error_tests {
    use super::escape_html_path;

    #[tokio::test]
    async fn route_response_escapes_markup_in_the_inserted_path() {
        let response = super::route_not_found_response("/v1/topics/<&\"'>");
        let body = axum::body::to_bytes(response.into_body(), 10000)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("<code>/v1/topics/&lt;&amp;&quot;&#39;&gt;</code>"));
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn route_path_escaping_preserves_text_and_never_injects_markup(path in ".{0,200}") {
            let escaped = escape_html_path(&path);
            prop_assert!(!escaped.contains(['<', '>', '\'', '"']));
            let decoded = escaped.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'").replace("&amp;", "&");
            prop_assert_eq!(decoded, path);
        }
    }
}

#[cfg(test)]
mod filter_error_tests {
    use super::filter_error_details;
    use proptest::prelude::*;
    proptest! {
        #[test]
        fn syntax_metadata_preserves_parser_location(line in 1usize..200,column in 1usize..200,token in "[a-z=]{1,12}") {
            let message=format!("Invalid filter expression: failed to parse (syntax error at line {line}, column {column}, token '{token}').");
            let details=filter_error_details(&message).unwrap();
            let line_text=line.to_string();let column_text=column.to_string();
            prop_assert_eq!(details[0]["metadata"]["line"].as_str(),Some(line_text.as_str()));
            prop_assert_eq!(details[0]["metadata"]["column"].as_str(),Some(column_text.as_str()));
            prop_assert_eq!(details[0]["metadata"]["token"].as_str(),Some(token.as_str()));
            let unrelated=format!("unrelated {message}");prop_assert!(filter_error_details(&unrelated).is_none());
        }
    }
}
