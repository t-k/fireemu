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
use fireemu_core_pubsub::subscription::{PushConfig, DEFAULT_ACK_DEADLINE_SECONDS};
use fireemu_core_pubsub::{
    Code, Filter, PubSubError, PubSubState, PubsubMessage, ReceivedMessage, Snapshot,
    StoredMessage, SubscriptionConfig, SubscriptionName, TopicName,
};
use fireemu_core_types::time::LogicalInstant;
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

    let (topic_id, operation) = split_operation(parts);
    let topic = TopicName::new(project, topic_id).map_err(RestError::from_core)?;
    match (method, operation) {
        (&Method::POST, None) => {
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

    let (subscription_id, operation) = split_operation(parts);
    let subscription =
        SubscriptionName::new(project, subscription_id).map_err(RestError::from_core)?;
    match (method, operation) {
        (&Method::POST, None) => create_subscription(subscription, body, handle),
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

    let (snapshot_id, operation) = split_operation(parts);
    let name = format!("projects/{project}/snapshots/{snapshot_id}");
    match (method, operation) {
        (&Method::POST, None) => {
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
    handle.bridge_deliver(topic.topic(), &bridge);
    handle.schedule_push(&topic);
    Ok((StatusCode::OK, json!({"messageIds": ids})))
}

#[allow(clippy::needless_pass_by_value)]
fn create_subscription(
    subscription: SubscriptionName,
    body: &Value,
    handle: &PubSubHandle,
) -> Result<(StatusCode, Value), RestError> {
    let topic = TopicName::parse(string_field(body, "topic")?).map_err(RestError::from_core)?;
    if topic.project() != subscription.project() {
        return Err(RestError::invalid(
            "subscription and topic must belong to the same project",
        ));
    }
    let ack_deadline_seconds = body
        .get("ackDeadlineSeconds")
        .map(parse_u32)
        .transpose()?
        .unwrap_or(DEFAULT_ACK_DEADLINE_SECONDS);
    let filter = Filter::parse(body.get("filter").and_then(Value::as_str).unwrap_or(""))
        .map_err(RestError::from_core)?;
    let push_endpoint = body
        .get("pushConfig")
        .and_then(Value::as_object)
        .and_then(|config| config.get("pushEndpoint"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    crate::push::validate_endpoint(&push_endpoint).map_err(RestError::invalid)?;
    let config = SubscriptionConfig {
        name: subscription.clone(),
        topic: topic.clone(),
        ack_deadline_seconds,
        enable_message_ordering: body
            .get("enableMessageOrdering")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        filter,
        dead_letter_policy: None,
        retry_policy: None,
        push_config: PushConfig { push_endpoint },
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
    if let Some(value) = body.get("ackDeadlineSeconds") {
        handle
            .state()
            .update_ack_deadline(&subscription, parse_u32(value)?)
            .map_err(RestError::from_core)?;
    }
    if let Some(push_config) = body.get("pushConfig") {
        let endpoint = push_config
            .get("pushEndpoint")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        crate::push::validate_endpoint(&endpoint).map_err(RestError::invalid)?;
        handle
            .state()
            .update_push_config(
                &subscription,
                PushConfig {
                    push_endpoint: endpoint,
                },
            )
            .map_err(RestError::from_core)?;
    }
    let topic = handle
        .state()
        .subscription_config(&subscription)
        .map_err(RestError::from_core)?
        .topic
        .clone();
    handle.schedule_push(&topic);
    get_subscription(subscription, handle)
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
    value
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
