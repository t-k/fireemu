//! Eventarc custom events: the `publishEvents` surface the Admin SDK writes to, and the
//! `CloudEvent` an `onCustomEventPublished` function receives.
//!
//! The official Local Emulator Suite runs an Eventarc emulator of its own on port 9299 and
//! points `CLOUD_EVENTARC_EMULATOR_HOST` at it. fireemu serves the same route on the
//! functions port instead -- a custom event has nowhere to go without functions -- and
//! exports the variable accordingly, so the Admin SDK reaches it unchanged.
//!
//! Two shapes are involved, and they are not the same:
//!
//! - What `firebase-admin`'s `getEventarc().channel().publish()` sends is the *proto* JSON of
//!   a `CloudEvent` (`firebase-admin/lib/eventarc/eventarc-utils.js` `toCloudEventProtoFormat`):
//!   `id`, `type`, `specVersion` and `source` at the top level, everything else under
//!   `attributes` as `{"ceString": ...}` or `{"ceTimestamp": ...}`, and the payload in
//!   `textData`.
//! - What the function receives is the ordinary JSON `CloudEvent`
//!   (`eventarcEmulatorUtils.js` `cloudEventFromProtoToJson`): lower-case `specversion`,
//!   `time`, `datacontenttype` and `subject` flattened back out, `data` parsed out of
//!   `textData` according to `datacontenttype`, and every other attribute copied across as a
//!   string.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

/// The channel a publish without an explicit one belongs to, as the official emulator names
/// it (`GOOGLE_CHANNEL`).
pub const GOOGLE_CHANNEL: &str = "google";

/// One published event, converted for delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedEvent {
    /// The `type` attribute, which is what a trigger subscribes to.
    pub event_type: String,
    /// The attributes an `eventFilters` entry is matched against. Built the way
    /// `EventarcEmulator.matchesAll` reads them: the top-level members plus every
    /// `attributes` entry, unwrapped from its `ceString` / `ceTimestamp` box.
    pub attributes: BTreeMap<String, String>,
    /// The JSON `CloudEvent` the function receives.
    pub event: Value,
}

/// Converts one proto-format `CloudEvent` into what a function receives, or says what is
/// missing.
///
/// The four required members and the two required attributes are the official ones
/// (`cloudEventFromProtoToJson`), including its messages, because a publisher that gets one
/// wrong should read the same sentence from either emulator.
pub fn convert(proto: &Value) -> Result<PublishedEvent, String> {
    let text = |key: &str| proto.get(key).and_then(Value::as_str);
    for required in ["id", "type", "specVersion", "source"] {
        if text(required).is_none() {
            let spelled = if required == "specVersion" {
                "specVersion"
            } else {
                required
            };
            return Err(format!("CloudEvent '{spelled}' is required."));
        }
    }
    let attribute = |name: &str, kind: &str| {
        proto
            .get("attributes")
            .and_then(|a| a.get(name))
            .and_then(|a| a.get(kind))
            .and_then(Value::as_str)
    };
    let time = attribute("time", "ceTimestamp")
        .ok_or_else(|| "CloudEvent must contain time attribute".to_owned())?;
    let content_type = attribute("datacontenttype", "ceString")
        .ok_or_else(|| "CloudEvent must contain datacontenttype attribute".to_owned())?;
    let data = match content_type {
        "application/json" => {
            let raw = proto.get("textData").and_then(Value::as_str).unwrap_or("");
            serde_json::from_str(raw)
                .map_err(|e| format!("CloudEvent textData is not JSON: {e}"))?
        }
        "text/plain" => Value::String(
            proto
                .get("textData")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
        ),
        other => return Err(format!("Unsupported content type: {other}")),
    };

    let mut event = Map::new();
    event.insert(
        "id".to_owned(),
        Value::String(text("id").unwrap_or("").into()),
    );
    let event_type = text("type").unwrap_or("").to_owned();
    event.insert("type".to_owned(), Value::String(event_type.clone()));
    event.insert(
        "specversion".to_owned(),
        Value::String(text("specVersion").unwrap_or("").into()),
    );
    event.insert(
        "source".to_owned(),
        Value::String(text("source").unwrap_or("").into()),
    );
    // `subject` is optional: the official converter assigns `undefined` when it is absent,
    // and `JSON.stringify` drops the key rather than emitting a null.
    if let Some(subject) = attribute("subject", "ceString") {
        event.insert("subject".to_owned(), Value::String(subject.to_owned()));
    }
    event.insert("time".to_owned(), Value::String(time.to_owned()));
    event.insert("data".to_owned(), data);
    event.insert(
        "datacontenttype".to_owned(),
        Value::String(content_type.to_owned()),
    );

    // Attributes the CloudEvent spec does not define are copied across as strings, and are
    // also what a filter matches on.
    // `matchesAll` resolves a filter as `event[key] ?? event.attributes[key]` over the *proto*
    // event, so the top-level members are part of the filterable set -- `specVersion` with its
    // capital V included, because that is how the proto spells it.
    let mut attributes = BTreeMap::new();
    for key in ["id", "type", "source", "specVersion"] {
        attributes.insert(key.to_owned(), text(key).unwrap_or("").to_owned());
    }
    attributes.insert("time".to_owned(), time.to_owned());
    attributes.insert("datacontenttype".to_owned(), content_type.to_owned());
    if let Some(subject) = attribute("subject", "ceString") {
        attributes.insert("subject".to_owned(), subject.to_owned());
    }
    if let Some(extra) = proto.get("attributes").and_then(Value::as_object) {
        for (name, value) in extra {
            if ["time", "datacontenttype", "subject"].contains(&name.as_str()) {
                continue;
            }
            let text = value
                .get("ceString")
                .or_else(|| value.get("ceTimestamp"))
                .and_then(Value::as_str)
                .ok_or_else(|| format!("CloudEvent must contain {name} attribute"))?;
            event.insert(name.clone(), Value::String(text.to_owned()));
            attributes.insert(name.clone(), text.to_owned());
        }
    }
    Ok(PublishedEvent {
        event_type,
        attributes,
        event: Value::Object(event),
    })
}

/// One event published on the `google` channel, which the emulator forwards verbatim.
///
/// `triggerEventFunction` converts only for a custom channel
/// (`channel === GOOGLE_CHANNEL ? event : cloudEventFromProtoToJson(event)`), so an event on
/// the sentinel channel reaches the handler exactly as it was published. That is the path
/// every Firebase alert takes: the alert providers register an ordinary event trigger with no
/// channel, the emulator indexes it under `<eventType>-google`, and the payload is a plain
/// JSON `CloudEvent` carrying `alerttype` and `appid` at the top level.
pub fn accept_verbatim(event: &Value) -> Result<PublishedEvent, String> {
    let event_type = event
        .get("type")
        .and_then(Value::as_str)
        // `publishEventsHandler` answers a bare 400 for an event with no type and says
        // nothing else; the sentence is fireemu's own, on a route the official one leaves
        // silent.
        .ok_or_else(|| "CloudEvent 'type' is required.".to_owned())?
        .to_owned();
    // `matchesAll` resolves `event[key] ?? event.attributes[key]`, so a top-level member wins
    // and only what it does not carry is looked up in `attributes`.
    let mut attributes = BTreeMap::new();
    if let Some(extra) = event.get("attributes").and_then(Value::as_object) {
        for (name, value) in extra {
            let text = value
                .get("ceString")
                .or_else(|| value.get("ceTimestamp"))
                .and_then(Value::as_str)
                .or_else(|| value.as_str());
            if let Some(text) = text {
                attributes.insert(name.clone(), text.to_owned());
            }
        }
    }
    if let Some(members) = event.as_object() {
        for (name, value) in members {
            if let Some(text) = value.as_str() {
                attributes.insert(name.clone(), text.to_owned());
            }
        }
    }
    Ok(PublishedEvent {
        event_type,
        attributes,
        event: event.clone(),
    })
}

/// The channel a `POST .../channels/{channel}:publishEvents` path names, or `None` when the
/// path is not that route.
///
/// The two accepted forms are the official emulator's two routes: the Cloud Eventarc one,
/// `/projects/{p}/locations/{l}/channels/{c}:publishEvents`, and its own
/// `/google/publishEvents`, which publishes onto the sentinel `google` channel.
#[must_use]
pub fn publish_channel(path: &str) -> Option<String> {
    if path == "/google/publishEvents" {
        return Some(GOOGLE_CHANNEL.to_owned());
    }
    let rest = path.strip_suffix(":publishEvents")?.trim_start_matches('/');
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.as_slice() {
        ["projects", project, "locations", location, "channels", channel]
            if !project.is_empty() && !location.is_empty() && !channel.is_empty() =>
        {
            Some(format!(
                "projects/{project}/locations/{location}/channels/{channel}"
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{convert, publish_channel, GOOGLE_CHANNEL};
    use serde_json::json;

    fn proto() -> serde_json::Value {
        json!({
            "@type": "type.googleapis.com/io.cloudevents.v1.CloudEvent",
            "id": "e-1",
            "type": "com.example.thing.done",
            "specVersion": "1.0",
            "source": "https://example.com/thing",
            "attributes": {
                "time": {"ceTimestamp": "2026-01-01T00:00:00.000Z"},
                "datacontenttype": {"ceString": "application/json"},
                "subject": {"ceString": "things/1"},
                "region": {"ceString": "emea"}
            },
            "textData": "{\"n\":3}"
        })
    }

    #[test]
    fn the_proto_form_becomes_the_cloudevent_a_handler_receives() {
        let converted = convert(&proto()).expect("a complete event converts");
        assert_eq!(converted.event_type, "com.example.thing.done");
        assert_eq!(
            converted.event,
            json!({
                "id": "e-1",
                "type": "com.example.thing.done",
                "specversion": "1.0",
                "source": "https://example.com/thing",
                "subject": "things/1",
                "time": "2026-01-01T00:00:00.000Z",
                "data": {"n": 3},
                "datacontenttype": "application/json",
                "region": "emea"
            })
        );
        // A filter matches on the attributes, the extra ones included.
        assert_eq!(
            converted.attributes.get("region").map(String::as_str),
            Some("emea")
        );
        assert_eq!(
            converted.attributes.get("subject").map(String::as_str),
            Some("things/1")
        );
    }

    #[test]
    fn a_text_payload_arrives_as_a_string_and_an_unknown_type_is_refused() {
        let mut event = proto();
        event["attributes"]["datacontenttype"]["ceString"] = json!("text/plain");
        event["textData"] = json!("hello");
        assert_eq!(
            convert(&event).expect("text converts").event["data"],
            "hello"
        );

        event["attributes"]["datacontenttype"]["ceString"] = json!("application/octet-stream");
        assert_eq!(
            convert(&event).expect_err("an unsupported content type is refused"),
            "Unsupported content type: application/octet-stream"
        );
    }

    #[test]
    fn the_four_required_members_and_two_required_attributes_are_named_when_missing() {
        for (key, message) in [
            ("id", "CloudEvent 'id' is required."),
            ("type", "CloudEvent 'type' is required."),
            ("specVersion", "CloudEvent 'specVersion' is required."),
            ("source", "CloudEvent 'source' is required."),
        ] {
            let mut event = proto();
            event.as_object_mut().expect("an object").remove(key);
            assert_eq!(
                convert(&event).expect_err("a missing member is named"),
                message
            );
        }
        let mut event = proto();
        event["attributes"]
            .as_object_mut()
            .expect("an object")
            .remove("time");
        assert_eq!(
            convert(&event).expect_err("a missing time is named"),
            "CloudEvent must contain time attribute"
        );
    }

    #[test]
    fn the_publish_route_names_its_channel() {
        assert_eq!(
            publish_channel(
                "/projects/demo-app/locations/us-central1/channels/firebase:publishEvents"
            ),
            Some("projects/demo-app/locations/us-central1/channels/firebase".to_owned())
        );
        assert_eq!(
            publish_channel("/google/publishEvents"),
            Some(GOOGLE_CHANNEL.to_owned())
        );
        for path in [
            "/demo-app/us-central1/someFunction",
            "/projects/demo-app/locations/us-central1/channels/firebase",
            "/projects/demo-app/channels/firebase:publishEvents",
        ] {
            assert_eq!(publish_channel(path), None, "{path}");
        }
    }
}
