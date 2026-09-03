//! The canonical manifest JSON (spec 12.3) ⇄ [`FunctionManifest`].
//!
//! ```json
//! {"functions": [
//!   {"name": "onTodo", "region": "us-central1", "entryPoint": "onTodo", "generation": 2,
//!    "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.created",
//!                "database": "(default)", "document": "todos/{id}"},
//!    "timeoutSeconds": 60, "retry": false, "concurrency": 1},
//!   {"name": "api", "trigger": {"type": "http", "callable": false}},
//!   {"name": "onUpload", "trigger": {"type": "storage", "eventType": "google.cloud.storage.object.v1.finalized", "bucket": "demo-app.appspot.com"}},
//!   {"name": "nightly", "trigger": {"type": "schedule", "schedule": "0 3 * * *", "timeZone": "Asia/Tokyo"}},
//!   {"name": "onMessage", "trigger": {"type": "pubsub", "topic": "jobs"}},
//!   {"name": "onUser", "trigger": {"type": "auth", "eventType": "google.firebase.auth.user.v1.created"}}
//! ]}
//!
//! A Firestore `eventType` ending in `.withAuthContext` asks for the principal of the change.
//! ```

use fireemu_core_functions::cron::Schedule;
use fireemu_core_functions::manifest::{
    AuthEvent, ConsumeAppCheckToken, DocumentEvent, FunctionGeneration, FunctionManifest,
    FunctionSpec, IgnoredFunction, IgnoredScope, ObjectEvent, PlatformOptions, ScheduleRetryConfig,
    TaskRateLimits, TaskRetryConfig, Trigger, DEFAULT_REGION, DEFAULT_TIMEOUT_SECONDS,
};
use fireemu_core_functions::pattern::PathPattern;
use fireemu_core_types::ids::DatabaseId;
use serde_json::{json, Value};

/// The manifest spells task-queue durations in (fractional) seconds and the runtime keeps
/// milliseconds; a negative or absurd value is clamped rather than wrapped.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn seconds_to_millis(seconds: f64) -> u64 {
    (seconds * 1000.0).max(0.0).min(u64::MAX as f64).round() as u64
}

#[allow(clippy::cast_precision_loss)]
fn millis_to_seconds(millis: u64) -> f64 {
    millis as f64 / 1000.0
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn non_negative_u32(n: f64) -> u32 {
    n.max(0.0).min(f64::from(u32::MAX)) as u32
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn non_negative_u64(n: f64) -> u64 {
    n.max(0.0).min(u64::MAX as f64) as u64
}

/// Parses the canonical manifest JSON.
pub fn parse_manifest(v: &Value) -> Result<FunctionManifest, String> {
    let functions = v
        .get("functions")
        .and_then(Value::as_array)
        .ok_or_else(|| "manifest: \"functions\" array is required".to_owned())?;
    let mut out = Vec::with_capacity(functions.len());
    for f in functions {
        out.push(parse_function(f)?);
    }
    let mut ignored = Vec::new();
    for entry in v
        .get("ignored")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
    {
        ignored.push(parse_ignored(entry)?);
    }
    let manifest = FunctionManifest {
        functions: out,
        ignored,
    };
    manifest.validate().map_err(|e| format!("manifest: {e}"))?;
    Ok(manifest)
}

fn parse_ignored(v: &Value) -> Result<IgnoredFunction, String> {
    let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    let name = text("name").ok_or_else(|| "manifest: ignored entry without a name".to_owned())?;
    let scope_text = text("scope")
        .ok_or_else(|| format!("manifest: ignored function {name:?}: scope is required"))?;
    let scope = IgnoredScope::parse(&scope_text).ok_or_else(|| {
        format!("manifest: ignored function {name:?}: unknown scope {scope_text:?}")
    })?;
    Ok(IgnoredFunction {
        region: text("region").unwrap_or_else(|| DEFAULT_REGION.to_owned()),
        trigger_type: text("triggerType").unwrap_or_else(|| "unknown".to_owned()),
        reason: text("reason")
            .ok_or_else(|| format!("manifest: ignored function {name:?}: reason is required"))?,
        scope,
        name,
    })
}

fn parse_platform_options(
    function: &str,
    value: Option<&Value>,
) -> Result<PlatformOptions, String> {
    let Some(value) = value else {
        return Ok(PlatformOptions::default());
    };
    let object = value.as_object().ok_or_else(|| {
        format!("manifest: function {function:?}: platformOptions must be an object")
    })?;
    let u32_value = |key: &str| -> Result<Option<u32>, String> {
        match object.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => value
                .as_u64()
                .and_then(|number| u32::try_from(number).ok())
                .map(Some)
                .ok_or_else(|| {
                    format!(
                        "manifest: function {function:?}: platformOptions.{key} must be an integer"
                    )
                }),
        }
    };
    let string_value = |key: &str| -> Result<Option<String>, String> {
        match object.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(value)) => Ok(Some(value.clone())),
            Some(_) => Err(format!(
                "manifest: function {function:?}: platformOptions.{key} must be a string"
            )),
        }
    };
    let string_array = |key: &str| -> Result<Vec<String>, String> {
        let Some(value) = object.get(key) else {
            return Ok(Vec::new());
        };
        let values = value.as_array().ok_or_else(|| {
            format!("manifest: function {function:?}: platformOptions.{key} must be an array")
        })?;
        values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    format!(
                        "manifest: function {function:?}: platformOptions.{key} entries must be strings"
                    )
                })
            })
            .collect()
    };
    let bool_value = |key: &str| -> Result<Option<bool>, String> {
        match object.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bool(value)) => Ok(Some(*value)),
            Some(_) => Err(format!(
                "manifest: function {function:?}: platformOptions.{key} must be a boolean"
            )),
        }
    };
    let mut labels = std::collections::BTreeMap::new();
    if let Some(value) = object.get("labels") {
        let values = value.as_object().ok_or_else(|| {
            format!("manifest: function {function:?}: platformOptions.labels must be an object")
        })?;
        for (key, value) in values {
            let value = value.as_str().ok_or_else(|| {
                format!(
                    "manifest: function {function:?}: platformOptions.labels.{key} must be a string"
                )
            })?;
            labels.insert(key.clone(), value.to_owned());
        }
    }
    let network_interfaces = object
        .get("networkInterfaces")
        .map_or(Ok(Vec::new()), |value| {
            value
                .as_array()
                .ok_or_else(|| {
                    format!(
                        "manifest: function {function:?}: platformOptions.networkInterfaces must be an array"
                    )
                })
                .map(|values| values.iter().map(Value::to_string).collect())
        })?;
    Ok(PlatformOptions {
        preserve_external_changes: bool_value("preserveExternalChanges")?,
        available_memory_mb: u32_value("availableMemoryMb")?,
        min_instances: u32_value("minInstances")?,
        max_instances: u32_value("maxInstances")?,
        cpu: string_value("cpu")?,
        ingress_settings: string_value("ingressSettings")?,
        invokers: string_array("invoker")?,
        service_account_email: string_value("serviceAccountEmail")?,
        vpc_connector: string_value("vpcConnector")?,
        vpc_egress_settings: string_value("vpcEgressSettings")?,
        network_interfaces,
        labels,
        secrets: string_array("secrets")?,
    })
}

#[allow(clippy::too_many_lines)]
fn parse_function(f: &Value) -> Result<FunctionSpec, String> {
    let name = f
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "manifest: function without a name".to_owned())?
        .to_owned();
    let trigger = f
        .get("trigger")
        .ok_or_else(|| format!("manifest: function {name:?} has no trigger"))?;
    let kind = trigger
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("manifest: function {name:?}: trigger.type is required"))?;
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    let trigger = match kind {
        "http" | "https" | "callable" => {
            let callable = kind == "callable"
                || trigger
                    .get("callable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            // Absent means undetermined, never `false`: a manifest that does not say has not
            // observed the option, and guessing it away is what section 13.4 forbids.
            let consume = match trigger.get("consumeAppCheckToken") {
                None => ConsumeAppCheckToken::Undetermined,
                Some(v) => v
                    .as_str()
                    .and_then(ConsumeAppCheckToken::parse)
                    .ok_or_else(|| {
                        format!(
                            "manifest: function {name:?}: consumeAppCheckToken must be \"disabled\", \"enabled\" or \"undetermined\""
                        )
                    })?,
            };
            Trigger::Http {
                callable,
                enforce_app_check: trigger
                    .get("enforceAppCheck")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                consume_app_check_token: consume,
            }
        }
        "firestore" => {
            let event_type = s(trigger, "eventType")
                .ok_or_else(|| format!("manifest: function {name:?}: eventType is required"))?;
            let event = DocumentEvent::from_event_type(&event_type).ok_or_else(|| {
                format!("manifest: function {name:?}: unknown Firestore event type {event_type:?}")
            })?;
            let document = s(trigger, "document").ok_or_else(|| {
                format!("manifest: function {name:?}: document pattern is required")
            })?;
            let document = PathPattern::parse(&document)
                .map_err(|e| format!("manifest: function {name:?}: document pattern: {e}"))?;
            if !document.is_document_pattern() {
                return Err(format!(
                    "manifest: function {name:?}: document pattern {:?} names a collection",
                    document.as_str()
                ));
            }
            Trigger::Firestore {
                event,
                database: s(trigger, "database").unwrap_or_else(|| DatabaseId::DEFAULT.to_owned()),
                document,
                with_auth_context: event_type.ends_with(".withAuthContext"),
            }
        }
        "blockingAuth" => {
            let event_type = s(trigger, "eventType")
                .ok_or_else(|| format!("manifest: function {name:?}: eventType is required"))?;
            let event = fireemu_core_functions::manifest::BlockingAuthEvent::parse(&event_type)
                .ok_or_else(|| {
                    format!(
                        "manifest: function {name:?}: unknown blocking Auth event {event_type:?}"
                    )
                })?;
            Trigger::BlockingAuth { event }
        }
        "pubsub" => {
            let topic = s(trigger, "topic")
                .ok_or_else(|| format!("manifest: function {name:?}: topic is required"))?;
            // Full resource names are accepted; the short name is what matches.
            let topic = topic
                .rsplit_once("/topics/")
                .map_or(topic.clone(), |(_, t)| t.to_owned());
            if topic.is_empty() {
                return Err(format!("manifest: function {name:?}: topic is empty"));
            }
            Trigger::PubSub { topic }
        }
        "auth" => {
            let event_type = s(trigger, "eventType")
                .ok_or_else(|| format!("manifest: function {name:?}: eventType is required"))?;
            let event = AuthEvent::from_event_type(&event_type).ok_or_else(|| {
                format!("manifest: function {name:?}: unknown Auth event type {event_type:?}")
            })?;
            Trigger::Auth { event }
        }
        "storage" => {
            let event_type = s(trigger, "eventType")
                .ok_or_else(|| format!("manifest: function {name:?}: eventType is required"))?;
            let event = ObjectEvent::from_event_type(&event_type).ok_or_else(|| {
                format!("manifest: function {name:?}: unknown Storage event type {event_type:?}")
            })?;
            Trigger::Storage {
                event,
                bucket: s(trigger, "bucket").filter(|b| !b.is_empty()),
            }
        }
        "tasks" => {
            // Both an absent value and the explicit `null` the discovered manifest carries
            // fall through to the default, as the emulator's `??` does.
            let number = |section: &str, key: &str| -> Option<f64> {
                trigger.get(section)?.get(key)?.as_f64()
            };
            let millis = |section: &str, key: &str| number(section, key).map(seconds_to_millis);
            let count = |section: &str, key: &str| number(section, key).map(non_negative_u32);
            let defaults = TaskRetryConfig::default();
            let limits = TaskRateLimits::default();
            Trigger::TaskQueue {
                retry: TaskRetryConfig {
                    max_attempts: count("retryConfig", "maxAttempts")
                        .unwrap_or(defaults.max_attempts),
                    max_retry_millis: millis("retryConfig", "maxRetrySeconds"),
                    max_backoff_millis: millis("retryConfig", "maxBackoffSeconds")
                        .unwrap_or(defaults.max_backoff_millis),
                    max_doublings: count("retryConfig", "maxDoublings")
                        .unwrap_or(defaults.max_doublings),
                    min_backoff_millis: millis("retryConfig", "minBackoffSeconds")
                        .unwrap_or(defaults.min_backoff_millis),
                },
                rate_limits: TaskRateLimits {
                    max_concurrent_dispatches: count("rateLimits", "maxConcurrentDispatches")
                        .unwrap_or(limits.max_concurrent_dispatches),
                    max_dispatches_per_second: count("rateLimits", "maxDispatchesPerSecond")
                        .unwrap_or(limits.max_dispatches_per_second),
                },
            }
        }
        "eventarc" => {
            let event_type = s(trigger, "eventType")
                .ok_or_else(|| format!("manifest: function {name:?}: eventType is required"))?;
            if event_type.is_empty() {
                return Err(format!("manifest: function {name:?}: eventType is empty"));
            }
            let channel = s(trigger, "channel")
                .unwrap_or_else(|| "locations/us-central1/channels/firebase".to_owned());
            let mut filters = std::collections::BTreeMap::new();
            if let Some(map) = trigger.get("filters").and_then(Value::as_object) {
                for (k, v) in map {
                    let v = v.as_str().ok_or_else(|| {
                        format!("manifest: function {name:?}: filters.{k} must be a string")
                    })?;
                    filters.insert(k.clone(), v.to_owned());
                }
            }
            Trigger::Eventarc {
                event_type,
                channel,
                filters,
            }
        }
        "schedule" => {
            let text = s(trigger, "schedule")
                .ok_or_else(|| format!("manifest: function {name:?}: schedule is required"))?;
            let schedule = Schedule::parse(&text)
                .map_err(|e| format!("manifest: function {name:?}: schedule: {e}"))?;
            let time_zone = s(trigger, "timeZone").filter(|z| !z.is_empty());
            crate::zone::resolve(time_zone.as_deref())
                .map_err(|e| format!("manifest: function {name:?}: time zone: {e}"))?;
            let defaults = ScheduleRetryConfig::default();
            let retry_number = |key: &str| {
                trigger
                    .get("retryConfig")
                    .and_then(|retry| retry.get(key))
                    .and_then(Value::as_f64)
            };
            Trigger::Schedule {
                schedule,
                time_zone,
                retry: ScheduleRetryConfig {
                    retry_count: retry_number("retryCount")
                        .map_or(defaults.retry_count, non_negative_u32),
                    max_retry_seconds: retry_number("maxRetrySeconds")
                        .map_or(defaults.max_retry_seconds, non_negative_u64),
                    max_backoff_seconds: retry_number("maxBackoffSeconds")
                        .map_or(defaults.max_backoff_seconds, non_negative_u64),
                    max_doublings: retry_number("maxDoublings")
                        .map_or(defaults.max_doublings, non_negative_u32),
                    min_backoff_seconds: retry_number("minBackoffSeconds")
                        .map_or(defaults.min_backoff_seconds, non_negative_u64),
                },
            }
        }
        other => {
            return Err(format!(
                "manifest: function {name:?}: unsupported trigger type {other:?}"
            ))
        }
    };
    let u32_field = |k: &str, default: u32| -> Result<u32, String> {
        match f.get(k) {
            None | Some(Value::Null) => Ok(default),
            Some(v) => v
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| format!("manifest: function {name:?}: {k} must be an integer")),
        }
    };
    let generation_value = f.get("generation");
    let generation = match generation_value {
        None | Some(Value::Null) => FunctionGeneration::First,
        Some(Value::Number(number)) if number.as_u64() == Some(1) => FunctionGeneration::First,
        Some(Value::Number(number)) if number.as_u64() == Some(2) => FunctionGeneration::Second,
        Some(_) => {
            return Err(format!(
                "manifest: function {name:?}: generation must be 1 or 2"
            ))
        }
    };
    let concurrency = match f.get("concurrency") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_u64()
                .and_then(|number| u32::try_from(number).ok())
                .ok_or_else(|| {
                    format!("manifest: function {name:?}: concurrency must be an integer")
                })?,
        ),
    };
    let platform_options = parse_platform_options(&name, f.get("platformOptions"))?;
    if generation_value.is_none_or(Value::is_null) {
        let gen2_only_field = if concurrency.is_some() {
            Some("concurrency")
        } else if platform_options.cpu.is_some() {
            Some("platformOptions.cpu")
        } else if !platform_options.network_interfaces.is_empty() {
            Some("platformOptions.networkInterfaces")
        } else {
            None
        };
        if let Some(field) = gen2_only_field {
            return Err(format!(
                "manifest: function {name:?}: generation is required when {field} is set"
            ));
        }
    }
    Ok(FunctionSpec {
        region: s(f, "region").unwrap_or_else(|| DEFAULT_REGION.to_owned()),
        entry_point: s(f, "entryPoint").unwrap_or_else(|| name.clone()),
        timeout_seconds: u32_field("timeoutSeconds", DEFAULT_TIMEOUT_SECONDS)?,
        retry: f.get("retry").and_then(Value::as_bool).unwrap_or(false),
        generation,
        concurrency,
        platform_options,
        name,
        trigger,
    })
}

fn platform_options_to_json(options: &PlatformOptions) -> Option<Value> {
    if options == &PlatformOptions::default() {
        return None;
    }
    let network_interfaces: Vec<Value> = options
        .network_interfaces
        .iter()
        .map(|value| serde_json::from_str(value).unwrap_or_else(|_| json!(value)))
        .collect();
    Some(json!({
        "preserveExternalChanges": options.preserve_external_changes,
        "availableMemoryMb": options.available_memory_mb,
        "minInstances": options.min_instances,
        "maxInstances": options.max_instances,
        "cpu": options.cpu,
        "ingressSettings": options.ingress_settings,
        "invoker": options.invokers,
        "serviceAccountEmail": options.service_account_email,
        "vpcConnector": options.vpc_connector,
        "vpcEgressSettings": options.vpc_egress_settings,
        "networkInterfaces": network_interfaces,
        "labels": options.labels,
        "secrets": options.secrets,
    }))
}

fn ignored_to_json(ignored: &IgnoredFunction) -> Value {
    json!({
        "name": ignored.name,
        "region": ignored.region,
        "triggerType": ignored.trigger_type,
        "scope": ignored.scope.as_str(),
        "reason": ignored.reason,
    })
}

/// The manifest as canonical JSON (capabilities / status output).
#[must_use]
pub fn manifest_to_json(m: &FunctionManifest) -> Value {
    let functions: Vec<Value> = m
        .functions
        .iter()
        .map(|f| {
            let trigger = match &f.trigger {
                Trigger::Http {
                    callable,
                    enforce_app_check,
                    consume_app_check_token,
                } => json!({
                    "type": "http",
                    "callable": callable,
                    "enforceAppCheck": enforce_app_check,
                    "consumeAppCheckToken": consume_app_check_token.as_str(),
                }),
                Trigger::Firestore {
                    event,
                    database,
                    document,
                    with_auth_context,
                } => json!({"type": "firestore", "eventType": format!("{}{}", event.event_type(), if *with_auth_context { ".withAuthContext" } else { "" }), "database": database, "document": document.as_str()}),
                Trigger::PubSub { topic } => json!({"type": "pubsub", "topic": topic}),
                Trigger::TaskQueue { retry, rate_limits } => json!({
                    "type": "tasks",
                    "retryConfig": {
                        "maxAttempts": retry.max_attempts,
                        "maxRetrySeconds": retry.max_retry_millis.map(millis_to_seconds),
                        "maxBackoffSeconds": millis_to_seconds(retry.max_backoff_millis),
                        "maxDoublings": retry.max_doublings,
                        "minBackoffSeconds": millis_to_seconds(retry.min_backoff_millis),
                    },
                    "rateLimits": {
                        "maxConcurrentDispatches": rate_limits.max_concurrent_dispatches,
                        "maxDispatchesPerSecond": rate_limits.max_dispatches_per_second,
                    },
                }),
                Trigger::Eventarc {
                    event_type,
                    channel,
                    filters,
                } => json!({
                    "type": "eventarc",
                    "eventType": event_type,
                    "channel": channel,
                    "filters": filters,
                }),
                Trigger::Auth { event } => {
                    json!({"type": "auth", "eventType": event.event_type()})
                }
                Trigger::BlockingAuth { event } => {
                    json!({"type": "blockingAuth", "eventType": event.as_str()})
                }
                Trigger::Storage { event, bucket } => {
                    json!({"type": "storage", "eventType": event.event_type(), "bucket": bucket})
                }
                Trigger::Schedule {
                    schedule,
                    time_zone,
                    retry,
                } => json!({
                    "type": "schedule",
                    "schedule": schedule.as_str(),
                    "timeZone": time_zone,
                    "retryConfig": {
                        "retryCount": retry.retry_count,
                        "maxRetrySeconds": retry.max_retry_seconds,
                        "maxBackoffSeconds": retry.max_backoff_seconds,
                        "maxDoublings": retry.max_doublings,
                        "minBackoffSeconds": retry.min_backoff_seconds,
                    },
                }),
            };
            let mut function = json!({
                "name": f.name,
                "region": f.region,
                "entryPoint": f.entry_point,
                "trigger": trigger,
                "timeoutSeconds": f.timeout_seconds,
                "retry": f.retry,
                "generation": f.generation.as_u8(),
                "concurrency": f.concurrency,
            });
            if let Some(options) = platform_options_to_json(&f.platform_options) {
                function["platformOptions"] = options;
            }
            function
        })
        .collect();
    let ignored: Vec<Value> = m.ignored.iter().map(ignored_to_json).collect();
    json!({"functions": functions, "ignored": ignored})
}
