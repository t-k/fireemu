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
    DEFAULT_EXPIRATION_TTL_SECONDS, DEFAULT_RETRY_MINIMUM_BACKOFF_SECONDS,
    MAX_RETRY_BACKOFF_SECONDS,
};
use fireemu_core_pubsub::{
    Code, Filter, PubSubError, PubSubState, PubsubMessage, ReceivedMessage, Snapshot,
    StoredMessage, SubscriptionConfig, SubscriptionName, TopicName,
};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Map, Value};

use crate::convert::{
    is_declared_subscription_field, is_declared_topic_field, validate_subscription_update_paths,
    validate_topic_options, DEFAULT_MESSAGE_RETENTION_SECONDS, SUPPORTED_SUBSCRIPTION_FIELDS,
};
use crate::rest_json::Schema;
use crate::{PubSubHandle, PubSubProfile, MAX_MESSAGE_BYTES};
use fireemu_proto_pubsub::google::pubsub::v1 as pb;

const MAX_JSON_BYTES: usize = MAX_MESSAGE_BYTES + 1024 * 1024;

#[derive(Debug)]
struct RestError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl RestError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "INVALID_ARGUMENT",
            message: message.into(),
        }
    }

    fn method_not_allowed() -> Self {
        Self {
            status: StatusCode::METHOD_NOT_ALLOWED,
            code: "METHOD_NOT_ALLOWED",
            message: "method is not supported for this Pub/Sub resource".to_owned(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "NOT_FOUND",
            message: message.into(),
        }
    }

    fn unimplemented(message: impl Into<String>) -> Self {
        Self {
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
            Code::FailedPrecondition => (StatusCode::PRECONDITION_FAILED, "FAILED_PRECONDITION"),
            Code::ResourceExhausted => (StatusCode::TOO_MANY_REQUESTS, "RESOURCE_EXHAUSTED"),
            Code::Unimplemented => (StatusCode::NOT_IMPLEMENTED, "UNIMPLEMENTED"),
        };
        Self {
            status,
            code,
            message: error.message().to_owned(),
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

/// Handles one HTTP/JSON request that was not matched by a gRPC service route.
pub(crate) async fn handle(request: Request<Body>, handle: PubSubHandle) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or_default().to_owned();
    let body = match to_bytes(request.into_body(), MAX_JSON_BYTES).await {
        Ok(body) => body,
        Err(error) => {
            return error_response(
                RestError::invalid(format!("request body is too large: {error}")),
                handle.profile,
            );
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
                    handle.profile,
                );
            }
        }
    };

    match dispatch(&method, &path, &query, &value, &handle) {
        Ok((status, response)) => json_response(
            status,
            strict_response_defaults(response, handle.profile, schema_for(&path)),
            handle.profile,
            schema_for(&path),
        ),
        Err(error) => error_response(error, handle.profile),
    }
}

fn dispatch(
    method: &Method,
    path: &str,
    query: &str,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
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
        return dispatch_subscription(method, &parts[3..], project, query, body, handle);
    }
    if parts[2] == "snapshots" {
        return dispatch_snapshot(method, &parts[3..], project, query, body, handle);
    }
    Err(RestError::not_found("unknown Pub/Sub REST resource"))
}

fn dispatch_topic(
    method: &Method,
    parts: &[&str],
    project: &str,
    query: &str,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    if parts.is_empty() {
        if *method != Method::GET {
            return Err(RestError::method_not_allowed());
        }
        let state = handle.state();
        let topics = state
            .list_topics(project)
            .into_iter()
            .map(|name| {
                let labels = state.topic_labels(&name).cloned().unwrap_or_default();
                topic_json(&name, &labels)
            })
            .collect::<Vec<_>>();
        return Ok((
            StatusCode::OK,
            paged_collection_json("topics", topics, query, handle)?,
        ));
    }
    if handle.profile == PubSubProfile::Strict
        && parts.len() == 2
        && *method == Method::GET
        && matches!(parts[1], "subscriptions" | "snapshots")
    {
        let topic = TopicName::new(project, parts[0]).map_err(RestError::from_core)?;
        let mut state = handle.state();
        if !state.topic_exists(&topic) {
            return Err(RestError::not_found(format!(
                "Resource not found (resource={}).",
                parts[0]
            )));
        }
        let names = if parts[1] == "subscriptions" {
            state.topic_subscriptions(&topic)
        } else {
            state
                .list_topic_snapshots(&topic, handle.now())
                .map_err(RestError::from_core)?
        };
        return Ok((
            StatusCode::OK,
            paged_collection_json(
                parts[1],
                names.into_iter().map(Value::String).collect(),
                query,
                handle,
            )?,
        ));
    }
    if parts.len() != 1 {
        return Err(RestError::not_found("invalid topic resource path"));
    }

    let (topic_id, operation) = split_operation(parts);
    let topic = TopicName::new(project, topic_id).map_err(RestError::from_core)?;
    match (method, operation) {
        (&Method::PUT, None) => {
            let topic_options = topic_from_json(&topic, body)?;
            validate_topic_options(&topic_options).map_err(RestError::from_core)?;
            let labels = topic_options.labels.into_iter().collect();
            let mut state = handle.state();
            state
                .create_topic(topic.clone(), labels)
                .map_err(RestError::from_core)?;
            let labels = state
                .topic_labels(&topic)
                .cloned()
                .map_err(RestError::from_core)?;
            drop(state);
            handle.retry_pending_dead_letters();
            Ok((StatusCode::OK, topic_json(&topic, &labels)))
        }
        (&Method::PATCH, None) => update_topic(&topic, body),
        (&Method::GET, None) => {
            let state = handle.state();
            let labels = state
                .topic_labels(&topic)
                .cloned()
                .map_err(|error| RestError::from_resource_get(error, topic.topic()))?;
            Ok((StatusCode::OK, topic_json(&topic, &labels)))
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
) -> Result<Value, RestError> {
    if handle.profile == PubSubProfile::Emulator {
        return Ok(collection_json(field, resources));
    }
    let mut size = 0;
    let mut token = String::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let decoded =
            decode_query(key).and_then(|key| decode_query(value).map(|value| (key, value)));
        let (key, value) = match decoded {
            Ok(pair) => pair,
            Err(_) if handle.profile == PubSubProfile::Emulator => continue,
            Err(error) => return Err(error),
        };
        match key.as_str() {
            "pageSize" | "page_size" => match value.parse::<i32>() {
                Ok(parsed) => size = parsed,
                Err(_) if handle.profile == PubSubProfile::Emulator => {}
                Err(_) => return Err(RestError::invalid("pageSize must be an integer")),
            },
            "pageToken" | "page_token" => token = value,
            _ => {}
        }
    }
    let page = handle
        .page(resources, size, &token, |resource| {
            resource
                .as_str()
                .or_else(|| resource.get("name").and_then(Value::as_str))
                .unwrap_or_default()
                .to_owned()
        })
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

fn decode_query(value: &str) -> Result<String, RestError> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'+' => b' ',
            b'%' => {
                let high = bytes.next().and_then(|b| char::from(b).to_digit(16));
                let low = bytes.next().and_then(|b| char::from(b).to_digit(16));
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(RestError::invalid("invalid percent encoding in query"));
                };
                u8::try_from(high * 16 + low).expect("decoded byte")
            }
            other => other,
        });
    }
    String::from_utf8(decoded).map_err(|_| RestError::invalid("query must be UTF-8"))
}

fn update_topic(topic: &TopicName, body: &Value) -> Result<(StatusCode, Value), RestError> {
    let topic_body = field(body, "topic").unwrap_or(body);
    let topic_options = topic_from_json(topic, topic_body)?;
    let update_mask = field(body, "updateMask")
        .and_then(Value::as_str)
        .ok_or_else(|| RestError::invalid("updateMask must be a comma-separated string"))?;
    if update_mask.is_empty() {
        return Err(RestError::invalid("updateMask must not be empty"));
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
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    if parts.is_empty() {
        if *method != Method::GET {
            return Err(RestError::method_not_allowed());
        }
        let state = handle.state();
        let subscriptions = state
            .list_subscriptions(project)
            .into_iter()
            .map(|config| subscription_json(&state, &config, handle.profile))
            .collect::<Vec<_>>();
        return Ok((
            StatusCode::OK,
            paged_collection_json("subscriptions", subscriptions, query, handle)?,
        ));
    }
    if parts.len() != 1 {
        return Err(RestError::not_found("invalid subscription resource path"));
    }

    let (subscription_id, operation) = split_operation(parts);
    let subscription =
        SubscriptionName::new(project, subscription_id).map_err(RestError::from_core)?;
    match (method, operation) {
        (&Method::PUT, None) => create_subscription(subscription, body, handle),
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
        (&Method::POST, Some("seek")) => seek(subscription, body, handle),
        _ => Err(RestError::method_not_allowed()),
    }
}

fn dispatch_snapshot(
    method: &Method,
    parts: &[&str],
    project: &str,
    query: &str,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    if parts.is_empty() {
        if *method != Method::GET {
            return Err(RestError::method_not_allowed());
        }
        let snapshots = handle
            .state()
            .list_snapshots(project, handle.now())
            .into_iter()
            .map(|snapshot| snapshot_json(&snapshot, handle.profile))
            .collect::<Vec<_>>();
        return Ok((
            StatusCode::OK,
            if handle.profile == PubSubProfile::Strict {
                paged_collection_json("snapshots", snapshots, query, handle)?
            } else {
                json!({"snapshots": snapshots, "nextPageToken": ""})
            },
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
                .map_err(RestError::from_core)?;
            Ok((StatusCode::OK, snapshot_json(&snapshot, handle.profile)))
        }
        (&Method::GET, None) => {
            let snapshot = handle
                .state()
                .get_snapshot(&name, handle.now())
                .map_err(RestError::from_core)?;
            Ok((StatusCode::OK, snapshot_json(&snapshot, handle.profile)))
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
    let published = handle
        .publish(&topic, messages)
        .map_err(RestError::from_core)?;
    let ids = published
        .iter()
        .map(|message| handle.wire_message_id(&message.message_id))
        .collect::<Vec<_>>();
    Ok((StatusCode::OK, json!({"messageIds": ids})))
}

#[allow(clippy::needless_pass_by_value)]
fn create_subscription(
    subscription: SubscriptionName,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
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
        return Err(RestError::invalid(format!(
            "unknown subscription field {key}"
        )));
    }
    if let Some(name) = json_field(object, "name") {
        let name = name
            .as_str()
            .ok_or_else(|| RestError::invalid("subscription.name must be a string"))?;
        if name != subscription.to_full() {
            return Err(RestError::invalid(
                "subscription.name must match the request path",
            ));
        }
    }
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
        .map(parse_push_config)
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
    let labels = object_strings(body, "labels")?;
    let expiration_policy = field(body, "expirationPolicy")
        .map(parse_expiration_policy)
        .transpose()?;
    ignore_output_only_state(body)?;
    let config = SubscriptionConfig {
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
        labels,
        expiration_policy,
    };
    let mut state = handle.state();
    state
        .create_subscription(config)
        .map_err(RestError::from_core)?;
    let config = state
        .subscription_config(&subscription)
        .map_err(RestError::from_core)?
        .clone();
    let response = subscription_json(&state, &config, handle.profile);
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
        subscription_json(&state, config, handle.profile),
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
        return Err(RestError::invalid("updateMask must not be empty"));
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
                .map(parse_push_config)
                .transpose()?
                .unwrap_or_default(),
        )
    } else {
        None
    };
    let (topic, response) = {
        let mut state = handle.state();
        state
            .update_subscription(&subscription, ack_deadline_seconds, push_config)
            .map_err(RestError::from_core)?;
        let config = state
            .subscription_config(&subscription)
            .map_err(RestError::from_core)?
            .clone();
        (
            config.topic.clone(),
            subscription_json(&state, &config, handle.profile),
        )
    };
    handle.schedule_push(&topic);
    Ok((StatusCode::OK, response))
}

fn parse_push_config(value: &Value) -> Result<PushConfig, RestError> {
    let push_config = value
        .as_object()
        .ok_or_else(|| RestError::invalid("pushConfig must be an object"))?;
    reject_duplicate_spellings("pushConfig", push_config)?;
    for key in push_config.keys() {
        let field = snake_case_field(key);
        if field != "push_endpoint" {
            return Err(RestError::unimplemented(format!(
                "pushConfig.{field} is not supported by the Pub/Sub emulator"
            )));
        }
    }
    let endpoint = json_field(push_config, "pushEndpoint")
        .map(|endpoint| {
            endpoint
                .as_str()
                .ok_or_else(|| RestError::invalid("pushConfig.pushEndpoint must be a string"))
        })
        .transpose()?
        .unwrap_or_default()
        .to_owned();
    crate::push::validate_endpoint(&endpoint).map_err(RestError::invalid)?;
    Ok(PushConfig {
        push_endpoint: endpoint,
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

/// `state` is output only: a client may send the state a GET returned, and any state it names is
/// ignored. Only a state name is accepted.
fn ignore_output_only_state(body: &Value) -> Result<(), RestError> {
    match field(body, "state") {
        None => Ok(()),
        Some(state)
            if matches!(
                state.as_str(),
                Some("STATE_UNSPECIFIED" | "ACTIVE" | "RESOURCE_ERROR")
            ) =>
        {
            Ok(())
        }
        Some(_) => Err(RestError::invalid(
            "state must be STATE_UNSPECIFIED, ACTIVE or RESOURCE_ERROR",
        )),
    }
}

fn parse_expiration_policy(value: &Value) -> Result<ExpirationPolicy, RestError> {
    let object = value
        .as_object()
        .ok_or_else(|| RestError::invalid("expirationPolicy must be an object"))?;
    reject_duplicate_spellings("expirationPolicy", object)?;
    if let Some(key) = object.keys().find(|key| key.as_str() != "ttl") {
        return Err(RestError::invalid(format!(
            "unknown expirationPolicy field {key}"
        )));
    }
    let ttl = object.get("ttl").map(parse_duration).transpose()?;
    Ok(ExpirationPolicy { ttl })
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
    let max = field(body, "maxMessages")
        .map(parse_usize)
        .transpose()?
        .unwrap_or(100);
    let received = handle
        .pull(&subscription, max)
        .map_err(RestError::from_core)?;
    let report_attempt = handle
        .state()
        .subscription_config(&subscription)
        .map_err(RestError::from_core)?
        .dead_letter_policy
        .is_some();
    Ok((
        StatusCode::OK,
        json!({
            "receivedMessages": received.iter().map(|r| received_json(r, handle, report_attempt)).collect::<Vec<_>>()
        }),
    ))
}

#[allow(clippy::needless_pass_by_value)]
fn acknowledge(
    subscription: SubscriptionName,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    let ack_ids = string_array(body, "ackIds")?;
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
    let ack_ids = string_array(body, "ackIds")?;
    let ack_ids: Vec<String> = ack_ids
        .iter()
        .map(|id| crate::ack_token::internal(id, handle.profile))
        .collect();
    let seconds = parse_u32(
        field(body, "ackDeadlineSeconds")
            .ok_or_else(|| RestError::invalid("modifyAckDeadline requires ackDeadlineSeconds"))?,
    )?;
    handle
        .state()
        .modify_ack_deadline(&subscription, &ack_ids, seconds, handle.now())
        .map_err(RestError::from_core)?;
    Ok((StatusCode::OK, json!({})))
}

#[allow(clippy::needless_pass_by_value)]
fn seek(
    subscription: SubscriptionName,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    match (field(body, "snapshot"), field(body, "time")) {
        (Some(_), Some(_)) => {
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
            return Err(RestError::invalid("seek requires a time or a snapshot"));
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

fn topic_json(name: &TopicName, labels: &BTreeMap<String, String>) -> Value {
    json!({"name": name.to_full(), "labels": labels})
}

fn topic_from_json(topic: &TopicName, body: &Value) -> Result<pb::Topic, RestError> {
    let object = body
        .as_object()
        .ok_or_else(|| RestError::invalid("topic must be an object"))?;
    reject_duplicate_spellings("topic", object)?;
    for key in object.keys() {
        let field = snake_case_field(key);
        if is_declared_topic_field(&field) {
            continue;
        }
        return Err(RestError::invalid(format!("unknown topic field {key}")));
    }
    if let Some(name) = json_field(object, "name") {
        let name = name
            .as_str()
            .ok_or_else(|| RestError::invalid("topic.name must be a string"))?;
        if name != topic.to_full() {
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
    if json_field(object, "messageRetentionDuration").is_some_and(|value| !value.is_null()) {
        options.message_retention_duration = Some(prost_types::Duration::default());
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
    profile: PubSubProfile,
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
        "messageRetentionDuration": duration_json(LogicalDuration::from_seconds(
            DEFAULT_MESSAGE_RETENTION_SECONDS,
        )),
        "expirationPolicy": {"ttl": duration_json(LogicalDuration::from_seconds(
            DEFAULT_EXPIRATION_TTL_SECONDS,
        ))},
        "state": "ACTIVE",
    });
    if let Some(policy) = config.expiration_policy {
        value["expirationPolicy"] = policy
            .ttl
            .map_or_else(|| json!({}), |ttl| json!({"ttl": duration_json(ttl)}));
    }
    if !config.labels.is_empty() {
        value["labels"] = json!(config.labels);
    }
    if config.enable_message_ordering {
        value["enableMessageOrdering"] = json!(true);
    }
    if config.retain_acked_messages {
        value["retainAckedMessages"] = json!(true);
    }
    if let Some(duration) = config.message_retention_duration {
        value["messageRetentionDuration"] = json!(duration_json(duration));
    }
    if !config.push_config.push_endpoint.is_empty() {
        value["pushConfig"] = json!({"pushEndpoint": config.push_config.push_endpoint});
        if profile == PubSubProfile::Strict {
            value["pushConfig"]["attributes"] = json!({"x-goog-version":"v1"});
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

fn snapshot_json(snapshot: &Snapshot, profile: PubSubProfile) -> Value {
    json!({
        "name": snapshot.name,
        "topic": snapshot.topic.to_full(),
        "expireTime": timestamp_json_profile(snapshot.expire_at, profile),
        "labels": snapshot.labels,
    })
}

fn received_json(received: &ReceivedMessage, handle: &PubSubHandle, report_attempt: bool) -> Value {
    let mut message = stored_message_json(&received.message);
    if handle.profile == PubSubProfile::Strict {
        let object = message.as_object_mut().expect("message object");
        object.insert(
            "messageId".into(),
            Value::String(handle.wire_message_id(&received.message.message_id)),
        );
        object.insert(
            "publishTime".into(),
            Value::String(timestamp_json_profile(
                received.message.publish_time,
                handle.profile,
            )),
        );
        if received.message.message.attributes.is_empty() {
            object.remove("attributes");
        }
        if received.message.message.ordering_key.is_empty() {
            object.remove("orderingKey");
        }
    }
    let mut value = json!({"ackId": crate::ack_token::wire(&received.ack_id, handle.profile), "message": message, "deliveryAttempt": received.delivery_attempt});
    if handle.profile == PubSubProfile::Strict && !report_attempt {
        value
            .as_object_mut()
            .expect("received object")
            .remove("deliveryAttempt");
    }
    value
}

fn stored_message_json(message: &StoredMessage) -> Value {
    json!({
        "data": BASE64.encode(&message.message.data),
        "attributes": message.message.attributes,
        "messageId": message.message_id,
        "publishTime": timestamp_json(message.publish_time),
        "orderingKey": message.message.ordering_key,
    })
}

fn timestamp_json_profile(instant: LogicalInstant, profile: PubSubProfile) -> String {
    let mut value = timestamp_json(instant);
    if profile == PubSubProfile::Strict && value.contains('.') {
        for _ in 0..2 {
            if value.ends_with("000Z") {
                value.truncate(value.len() - 4);
                value.push('Z');
            }
        }
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
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{fraction:09}Z")
    }
}

fn schema_for(path: &str) -> Schema {
    if path.ends_with(":publish") {
        Schema::Publish
    } else if path.ends_with(":pull") {
        Schema::Pull
    } else if path.ends_with("/topics") {
        Schema::Topics
    } else if path.ends_with("/subscriptions") {
        Schema::Subscriptions
    } else if path.ends_with("/snapshots") {
        Schema::Snapshots
    } else if path.contains("/topics/") {
        Schema::Topic
    } else if path.contains("/subscriptions/") {
        Schema::Subscription
    } else {
        Schema::Snapshot
    }
}

fn strict_response_defaults(mut value: Value, profile: PubSubProfile, schema: Schema) -> Value {
    if profile == PubSubProfile::Strict {
        let collection = match schema {
            Schema::Topics => Some(("topics", Schema::Topic)),
            Schema::Snapshots => Some(("snapshots", Schema::Snapshot)),
            _ => None,
        };
        if let Some((field, child_schema)) = collection {
            if let Some(resources) = value.get_mut(field).and_then(Value::as_array_mut) {
                for resource in resources {
                    *resource =
                        strict_response_defaults(std::mem::take(resource), profile, child_schema);
                }
            }
        }
        if matches!(schema, Schema::Topic | Schema::Snapshot)
            && value
                .get("labels")
                .and_then(Value::as_object)
                .is_some_and(serde_json::Map::is_empty)
        {
            value
                .as_object_mut()
                .expect("resource object")
                .remove("labels");
        }
        if schema == Schema::Pull
            && value
                .get("receivedMessages")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
        {
            value
                .as_object_mut()
                .expect("pull object")
                .remove("receivedMessages");
        }
    }
    value
}

#[allow(clippy::needless_pass_by_value)]
fn json_response(
    status: StatusCode,
    value: Value,
    profile: PubSubProfile,
    schema: Schema,
) -> Response {
    let body = crate::rest_json::encode(&value, profile, schema);
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("valid JSON response")
}

#[allow(clippy::needless_pass_by_value)]
fn error_response(error: RestError, profile: PubSubProfile) -> Response {
    json_response(
        error.status,
        json!({
            "error": {
                "code": error.status.as_u16(),
                "message": error.message,
                "status": error.code,
            }
        }),
        profile,
        Schema::ErrorEnvelope,
    )
}
