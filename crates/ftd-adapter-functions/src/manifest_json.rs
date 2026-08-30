//! The canonical manifest JSON (spec 12.3) ⇄ [`FunctionManifest`].
//!
//! ```json
//! {"functions": [
//!   {"name": "onTodo", "region": "us-central1", "entryPoint": "onTodo",
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

use ftd_core_functions::cron::Schedule;
use ftd_core_functions::manifest::{
    AuthEvent, DocumentEvent, FunctionManifest, FunctionSpec, ObjectEvent, Trigger,
    DEFAULT_CONCURRENCY, DEFAULT_REGION, DEFAULT_TIMEOUT_SECONDS,
};
use ftd_core_functions::pattern::PathPattern;
use serde_json::{json, Value};

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
    let manifest = FunctionManifest { functions: out };
    manifest.validate().map_err(|e| format!("manifest: {e}"))?;
    Ok(manifest)
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
        "http" | "https" | "callable" => Trigger::Http {
            callable: kind == "callable"
                || trigger
                    .get("callable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
        },
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
                database: s(trigger, "database").unwrap_or_else(|| "(default)".to_owned()),
                document,
                with_auth_context: event_type.ends_with(".withAuthContext"),
            }
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
        "schedule" => {
            let text = s(trigger, "schedule")
                .ok_or_else(|| format!("manifest: function {name:?}: schedule is required"))?;
            let schedule = Schedule::parse(&text)
                .map_err(|e| format!("manifest: function {name:?}: schedule: {e}"))?;
            let time_zone = s(trigger, "timeZone").filter(|z| !z.is_empty());
            crate::zone::resolve(time_zone.as_deref())
                .map_err(|e| format!("manifest: function {name:?}: time zone: {e}"))?;
            Trigger::Schedule {
                schedule,
                time_zone,
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
    Ok(FunctionSpec {
        region: s(f, "region").unwrap_or_else(|| DEFAULT_REGION.to_owned()),
        entry_point: s(f, "entryPoint").unwrap_or_else(|| name.clone()),
        timeout_seconds: u32_field("timeoutSeconds", DEFAULT_TIMEOUT_SECONDS)?,
        retry: f.get("retry").and_then(Value::as_bool).unwrap_or(false),
        concurrency: u32_field("concurrency", DEFAULT_CONCURRENCY)?,
        name,
        trigger,
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
                Trigger::Http { callable } => json!({"type": "http", "callable": callable}),
                Trigger::Firestore {
                    event,
                    database,
                    document,
                    with_auth_context,
                } => json!({"type": "firestore", "eventType": format!("{}{}", event.event_type(), if *with_auth_context { ".withAuthContext" } else { "" }), "database": database, "document": document.as_str()}),
                Trigger::PubSub { topic } => json!({"type": "pubsub", "topic": topic}),
                Trigger::Auth { event } => {
                    json!({"type": "auth", "eventType": event.event_type()})
                }
                Trigger::Storage { event, bucket } => {
                    json!({"type": "storage", "eventType": event.event_type(), "bucket": bucket})
                }
                Trigger::Schedule {
                    schedule,
                    time_zone,
                } => json!({"type": "schedule", "schedule": schedule.as_str(), "timeZone": time_zone}),
            };
            json!({
                "name": f.name,
                "region": f.region,
                "entryPoint": f.entry_point,
                "trigger": trigger,
                "timeoutSeconds": f.timeout_seconds,
                "retry": f.retry,
                "concurrency": f.concurrency,
            })
        })
        .collect();
    json!({"functions": functions})
}
