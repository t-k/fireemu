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
    DeadLetterPolicy, PushConfig, RetryPolicy, DEFAULT_ACK_DEADLINE_SECONDS,
    DEFAULT_RETRY_MINIMUM_BACKOFF_SECONDS, MAX_RETRY_BACKOFF_SECONDS,
};
use fireemu_core_pubsub::{
    Code, Filter, PubSubError, PubSubState, PubsubMessage, ReceivedMessage, Snapshot,
    StoredMessage, SubscriptionConfig, SubscriptionName, TopicName,
};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Map, Value};

use crate::{BridgeMessage, PubSubHandle, MAX_MESSAGE_BYTES};

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
}

/// Handles one HTTP/JSON request that was not matched by a gRPC service route.
pub(crate) async fn handle(request: Request<Body>, handle: PubSubHandle) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let body = match to_bytes(request.into_body(), MAX_JSON_BYTES).await {
        Ok(body) => body,
        Err(error) => {
            return error_response(RestError::invalid(format!(
                "request body is too large: {error}"
            )))
        }
    };
    let value = if body.is_empty() {
        Value::Object(Map::new())
    } else {
        match serde_json::from_slice::<Value>(&body) {
            Ok(value) => value,
            Err(error) => {
                return error_response(RestError::invalid(format!(
                    "request body is not JSON: {error}"
                )))
            }
        }
    };

    match dispatch(&method, &path, &value, &handle) {
        Ok((status, response)) => json_response(status, response),
        Err(error) => error_response(error),
    }
}

fn dispatch(
    method: &Method,
    path: &str,
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
        return dispatch_topic(method, &parts[3..], project, body, handle);
    }
    if parts[2] == "subscriptions" {
        return dispatch_subscription(method, &parts[3..], project, body, handle);
    }
    if parts[2] == "snapshots" {
        return dispatch_snapshot(method, &parts[3..], project, body, handle);
    }
    Err(RestError::not_found("unknown Pub/Sub REST resource"))
}

fn dispatch_topic(
    method: &Method,
    parts: &[&str],
    project: &str,
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
            json!({"topics": topics, "nextPageToken": ""}),
        ));
    }
    if parts.len() != 1 {
        return Err(RestError::not_found("invalid topic resource path"));
    }

    let (topic_id, operation) = split_operation(parts);
    let topic = TopicName::new(project, topic_id).map_err(RestError::from_core)?;
    match (method, operation) {
        (&Method::PUT, None) => {
            let object = body
                .as_object()
                .ok_or_else(|| RestError::invalid("topic must be an object"))?;
            for key in object.keys() {
                match key.as_str() {
                    "name" | "labels" => {}
                    _ => {
                        return Err(RestError::unimplemented(format!(
                            "topic.{key} is not supported by the Pub/Sub emulator"
                        )))
                    }
                }
            }
            if let Some(name) = object.get("name") {
                let name = name
                    .as_str()
                    .ok_or_else(|| RestError::invalid("topic.name must be a string"))?;
                if name != topic.to_full() {
                    return Err(RestError::invalid("topic.name must match the request path"));
                }
            }
            let labels = object_strings(body, "labels")?;
            let mut state = handle.state();
            state
                .create_topic(topic.clone(), labels)
                .map_err(RestError::from_core)?;
            let labels = state
                .topic_labels(&topic)
                .cloned()
                .map_err(RestError::from_core)?;
            Ok((StatusCode::OK, topic_json(&topic, &labels)))
        }
        (&Method::GET, None) => {
            let state = handle.state();
            let labels = state
                .topic_labels(&topic)
                .cloned()
                .map_err(RestError::from_core)?;
            Ok((StatusCode::OK, topic_json(&topic, &labels)))
        }
        (&Method::DELETE, None) => {
            handle
                .state()
                .delete_topic(&topic)
                .map_err(RestError::from_core)?;
            Ok((StatusCode::OK, json!({})))
        }
        (&Method::POST, Some("publish")) => publish(topic, body, handle),
        _ => Err(RestError::method_not_allowed()),
    }
}

fn dispatch_subscription(
    method: &Method,
    parts: &[&str],
    project: &str,
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
            .map(|config| subscription_json(&state, &config))
            .collect::<Vec<_>>();
        return Ok((
            StatusCode::OK,
            json!({"subscriptions": subscriptions, "nextPageToken": ""}),
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
            .map(|snapshot| snapshot_json(&snapshot))
            .collect::<Vec<_>>();
        return Ok((
            StatusCode::OK,
            json!({"snapshots": snapshots, "nextPageToken": ""}),
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
            for key in object.keys() {
                if !matches!(key.as_str(), "name" | "subscription" | "labels") {
                    return Err(RestError::unimplemented(format!(
                        "snapshot.{key} is not supported by the Pub/Sub emulator"
                    )));
                }
            }
            if let Some(body_name) = object.get("name") {
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
}

#[allow(clippy::needless_pass_by_value)]
fn publish(
    topic: TopicName,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| RestError::invalid("publish requires a messages array"))?
        .iter()
        .map(message_from_json)
        .collect::<Result<Vec<_>, _>>()?;
    let published = {
        let mut state = handle.state();
        state
            .publish_shared(&topic, messages, handle.now())
            .map_err(RestError::from_core)?
    };
    let ids = published
        .iter()
        .map(|message| message.message_id.clone())
        .collect::<Vec<_>>();
    let bridge = published
        .into_iter()
        .map(|message| BridgeMessage { message })
        .collect::<Vec<_>>();
    handle.bridge_deliver(&topic.to_full(), &bridge);
    handle.schedule_push(&topic);
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
    for key in object.keys() {
        match key.as_str() {
            "name"
            | "topic"
            | "ackDeadlineSeconds"
            | "enableMessageOrdering"
            | "filter"
            | "deadLetterPolicy"
            | "retryPolicy"
            | "pushConfig" => {}
            _ => {
                return Err(RestError::unimplemented(format!(
                    "subscription.{key} is not supported by the Pub/Sub emulator"
                )))
            }
        }
    }
    if let Some(name) = object.get("name") {
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
    let ack_deadline_seconds = parse_ack_deadline(body.get("ackDeadlineSeconds"))?;
    let filter_source = body
        .get("filter")
        .map(|filter| {
            filter
                .as_str()
                .ok_or_else(|| RestError::invalid("filter must be a string"))
        })
        .transpose()?
        .unwrap_or_default();
    let filter = Filter::parse(filter_source).map_err(RestError::from_core)?;
    let enable_message_ordering = body
        .get("enableMessageOrdering")
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| RestError::invalid("enableMessageOrdering must be a boolean"))
        })
        .transpose()?
        .unwrap_or(false);
    let push_config = body
        .get("pushConfig")
        .map(parse_push_config)
        .transpose()?
        .unwrap_or_default();
    let dead_letter_policy = body
        .get("deadLetterPolicy")
        .map(parse_dead_letter_policy)
        .transpose()?;
    let retry_policy = body
        .get("retryPolicy")
        .map(parse_retry_policy)
        .transpose()?;
    let config = SubscriptionConfig {
        name: subscription.clone(),
        topic: topic.clone(),
        ack_deadline_seconds,
        enable_message_ordering,
        filter,
        dead_letter_policy,
        retry_policy,
        push_config,
    };
    let mut state = handle.state();
    state
        .create_subscription(config)
        .map_err(RestError::from_core)?;
    let config = state
        .subscription_config(&subscription)
        .map_err(RestError::from_core)?
        .clone();
    let response = subscription_json(&state, &config);
    drop(state);
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
        .map_err(RestError::from_core)?;
    Ok((StatusCode::OK, subscription_json(&state, config)))
}

#[allow(clippy::needless_pass_by_value)]
fn update_subscription(
    subscription: SubscriptionName,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    let update = body
        .get("subscription")
        .and_then(Value::as_object)
        .ok_or_else(|| RestError::invalid("update requires a subscription object"))?;
    if let Some(name) = update.get("name") {
        let name = name
            .as_str()
            .ok_or_else(|| RestError::invalid("subscription.name must be a string"))?;
        if name != subscription.to_full() {
            return Err(RestError::invalid(
                "subscription.name must match the request path",
            ));
        }
    }
    let update_mask = body
        .get("updateMask")
        .and_then(Value::as_str)
        .ok_or_else(|| RestError::invalid("updateMask must be a comma-separated string"))?;
    if update_mask.is_empty() {
        return Err(RestError::invalid("updateMask must not be empty"));
    }
    let paths = update_mask.split(',').collect::<Vec<_>>();
    for path in &paths {
        match *path {
            "ackDeadlineSeconds" | "pushConfig" => {}
            "deadLetterPolicy" | "retryPolicy" | "filter" | "enableMessageOrdering" => {
                return Err(RestError::unimplemented(format!(
                    "updating {path} is not supported by the Pub/Sub emulator"
                )))
            }
            _ => {
                return Err(RestError::invalid(format!(
                    "unknown updateMask path {path}"
                )))
            }
        }
    }
    let ack_deadline_seconds = paths
        .contains(&"ackDeadlineSeconds")
        .then(|| parse_ack_deadline(update.get("ackDeadlineSeconds")))
        .transpose()?;
    let push_config = if paths.contains(&"pushConfig") {
        Some(
            update
                .get("pushConfig")
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
        (config.topic.clone(), subscription_json(&state, &config))
    };
    handle.schedule_push(&topic);
    Ok((StatusCode::OK, response))
}

fn parse_push_config(value: &Value) -> Result<PushConfig, RestError> {
    let push_config = value
        .as_object()
        .ok_or_else(|| RestError::invalid("pushConfig must be an object"))?;
    for key in push_config.keys() {
        if key != "pushEndpoint" {
            return Err(RestError::unimplemented(format!(
                "pushConfig.{key} is not supported by the Pub/Sub emulator"
            )));
        }
    }
    let endpoint = push_config
        .get("pushEndpoint")
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
    for key in policy.keys() {
        if !matches!(key.as_str(), "deadLetterTopic" | "maxDeliveryAttempts") {
            return Err(RestError::invalid(format!(
                "unknown deadLetterPolicy field {key}"
            )));
        }
    }
    Ok(DeadLetterPolicy {
        dead_letter_topic: TopicName::parse(string_field(value, "deadLetterTopic")?)
            .map_err(RestError::from_core)?,
        max_delivery_attempts: match policy
            .get("maxDeliveryAttempts")
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
    for key in policy.keys() {
        if !matches!(key.as_str(), "minimumBackoff" | "maximumBackoff") {
            return Err(RestError::invalid(format!(
                "unknown retryPolicy field {key}"
            )));
        }
    }
    Ok(RetryPolicy {
        minimum_backoff: policy
            .get("minimumBackoff")
            .map(parse_duration)
            .transpose()?
            .unwrap_or_else(|| {
                LogicalDuration::from_seconds(DEFAULT_RETRY_MINIMUM_BACKOFF_SECONDS)
            }),
        maximum_backoff: policy
            .get("maximumBackoff")
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
    let max = body
        .get("maxMessages")
        .map(parse_usize)
        .transpose()?
        .unwrap_or(100);
    let received = handle
        .state()
        .pull(&subscription, max, handle.now())
        .map_err(RestError::from_core)?;
    Ok((
        StatusCode::OK,
        json!({
            "receivedMessages": received.iter().map(received_json).collect::<Vec<_>>()
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
        .state()
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
    let seconds = parse_u32(
        body.get("ackDeadlineSeconds")
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
    let now = handle.now();
    if let Some(snapshot) = body.get("snapshot").and_then(Value::as_str) {
        handle
            .state()
            .seek_to_snapshot(&subscription, snapshot, now)
            .map_err(RestError::from_core)?;
    } else {
        return Err(RestError::invalid(
            "REST seek currently requires a snapshot resource",
        ));
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

fn string_field<'a>(body: &'a Value, field: &str) -> Result<&'a str, RestError> {
    body.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RestError::invalid(format!("{field} must be a non-empty string")))
}

fn string_array(body: &Value, field: &str) -> Result<Vec<String>, RestError> {
    body.get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| RestError::invalid(format!("{field} must be an array")))
        .and_then(|values| {
            values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| RestError::invalid(format!("{field} must contain strings")))
                })
                .collect()
        })
}

fn object_strings(body: &Value, field: &str) -> Result<BTreeMap<String, String>, RestError> {
    let Some(value) = body.get(field) else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| RestError::invalid(format!("{field} must be an object")))?;
    object
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_owned()))
                .ok_or_else(|| RestError::invalid(format!("{field} values must be strings")))
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
    let data = object
        .get("data")
        .and_then(Value::as_str)
        .map(|data| {
            BASE64
                .decode(data)
                .map_err(|error| RestError::invalid(format!("message data is not base64: {error}")))
        })
        .transpose()?
        .unwrap_or_default();
    let attributes = object
        .get("attributes")
        .map(|_| object_strings(value, "attributes"))
        .transpose()?
        .unwrap_or_default();
    let ordering_key = object
        .get("orderingKey")
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

fn subscription_json(state: &PubSubState, config: &SubscriptionConfig) -> Value {
    let topic = state
        .reported_topic(&config.name)
        .unwrap_or_else(|| config.topic.to_full());
    let mut value = json!({
        "name": config.name.to_full(),
        "topic": topic,
        "ackDeadlineSeconds": config.ack_deadline_seconds,
        "enableMessageOrdering": config.enable_message_ordering,
    });
    if !config.push_config.push_endpoint.is_empty() {
        value["pushConfig"] = json!({"pushEndpoint": config.push_config.push_endpoint});
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
    json!({
        "name": snapshot.name,
        "topic": snapshot.topic.to_full(),
        "expireTime": timestamp_json(snapshot.expire_at),
        "labels": snapshot.labels,
    })
}

fn received_json(received: &ReceivedMessage) -> Value {
    json!({
        "ackId": received.ack_id,
        "message": stored_message_json(&received.message),
        "deliveryAttempt": received.delivery_attempt,
    })
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

#[allow(clippy::needless_pass_by_value)]
fn json_response(status: StatusCode, value: Value) -> Response {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("valid JSON response")
}

#[allow(clippy::needless_pass_by_value)]
fn error_response(error: RestError) -> Response {
    json_response(
        error.status,
        json!({
            "error": {
                "code": error.status.as_u16(),
                "message": error.message,
                "status": error.code,
            }
        }),
    )
}
