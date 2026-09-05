//! Eventarc custom events: the `publishEvents` surface the Admin SDK writes to, and the
//! `CloudEvent` an `onCustomEventPublished` function receives.
//!
//! The official Local Emulator Suite runs an Eventarc emulator of its own on port 9299 and
//! points `CLOUD_EVENTARC_EMULATOR_HOST` at it. fireemu binds the same dedicated support
//! listener whenever a Functions runtime is loaded, so the Admin SDK reaches it unchanged.
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

/// Maximum trigger registrations retained by one Eventarc listener.
pub const MAX_REGISTERED_TRIGGERS: usize = 4096;
/// Maximum serialized trigger bytes retained by one Eventarc listener.
pub const MAX_REGISTERED_TRIGGER_BYTES: usize = 16 * 1024 * 1024;
/// Maximum expanded JSON definition accepted for one trigger.
pub const MAX_TRIGGER_DEFINITION_BYTES: usize = 256 * 1024;
/// Maximum `CloudEvents` accepted in one publish request before any matching work begins.
pub const MAX_EVENTS_PER_PUBLISH: usize = 256;
/// Firebase project IDs cannot exceed 63 bytes.
pub const MAX_PROJECT_ID_BYTES: usize = 63;
const MAX_TRIGGER_NAME_BYTES: usize = 8 * 1024;
const MAX_EVENT_TYPE_BYTES: usize = 1024;
const MAX_CHANNEL_BYTES: usize = 8 * 1024;
const MAX_EVENT_FILTERS: usize = 128;
const MAX_EVENT_FILTER_FIELD_BYTES: usize = 1024;
const PROJECT_PLACEHOLDER: &str = "${PROJECT_ID}";

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

/// Matching would exceed the caller's bounded delivery budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchLimitExceeded;

/// One Eventarc listener route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Register one Functions trigger.
    Register {
        /// Firebase project ID.
        project: String,
        /// Functions emulator trigger key.
        trigger: String,
    },
    /// Remove one exact Functions trigger registration.
    Remove {
        /// Firebase project ID.
        project: String,
        /// Functions emulator trigger key.
        trigger: String,
    },
    /// Return the trigger table used by the Emulator UI.
    GetTriggers,
    /// Publish events onto one channel.
    Publish {
        /// Project parsed from a custom channel route. Google publications have no project.
        project: Option<String>,
        /// Full custom channel resource name or the `google` sentinel.
        channel: String,
    },
}

/// One validated trigger definition, parsed exactly once before registry admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTrigger {
    event_trigger: Value,
    display_key: String,
    match_key: String,
    match_channel: String,
}

impl ParsedTrigger {
    /// The validated `eventTrigger` object used to resolve a loaded function.
    #[must_use]
    pub fn event_trigger(&self) -> &Value {
        &self.event_trigger
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegisteredTrigger {
    project_id: String,
    trigger_name: String,
    event_trigger: Value,
    display_key: String,
    match_channel: String,
    function: Option<String>,
    retained_bytes: usize,
}

/// The trigger table owned by one Eventarc listener.
///
/// The official emulator indexes registrations by `<eventType>-<channel>` and permits
/// duplicate definitions. fireemu keeps the same externally visible table while bounding
/// its retained count and bytes before insertion.
#[derive(Debug)]
pub struct TriggerRegistry {
    events: BTreeMap<String, Vec<RegisteredTrigger>>,
    count: usize,
    retained_bytes: usize,
    max_count: usize,
    max_bytes: usize,
}

impl Default for TriggerRegistry {
    fn default() -> Self {
        Self::with_limits(MAX_REGISTERED_TRIGGERS, MAX_REGISTERED_TRIGGER_BYTES)
    }
}

impl TriggerRegistry {
    /// Creates a registry with explicit safety limits.
    #[must_use]
    pub const fn with_limits(max_count: usize, max_bytes: usize) -> Self {
        Self {
            events: BTreeMap::new(),
            count: 0,
            retained_bytes: 0,
            max_count,
            max_bytes,
        }
    }

    /// Builds the registrations the Functions emulator would publish after loading a manifest.
    pub fn from_manifest(
        project: &str,
        manifest: &fireemu_core_functions::manifest::FunctionManifest,
        generation: u64,
    ) -> Result<Self, String> {
        use fireemu_core_functions::manifest::Trigger;

        let mut registry = Self::default();
        for function in &manifest.functions {
            let Trigger::Eventarc {
                event_type,
                channel,
                filters,
            } = &function.trigger
            else {
                continue;
            };
            let mut event_trigger = serde_json::json!({
                "eventType": event_type,
                "eventFilters": filters,
                "service": if channel == GOOGLE_CHANNEL {
                    "firebasealerts.googleapis.com"
                } else {
                    "eventarc.googleapis.com"
                },
            });
            let trigger_name = if channel == GOOGLE_CHANNEL {
                format!("{}-{}-{generation}", function.region, function.name)
            } else {
                event_trigger["channel"] = Value::String(channel.clone());
                format!(
                    "{}-{}-{generation}-{channel}",
                    function.region, function.name
                )
            };
            let body = serde_json::json!({"eventTrigger": event_trigger}).to_string();
            registry.register(
                project,
                &trigger_name,
                body.as_bytes(),
                Some(&function.name),
            )?;
        }
        Ok(registry)
    }

    /// Registers the exact event trigger body sent by the Functions emulator.
    pub fn register(
        &mut self,
        project: &str,
        trigger: &str,
        body: &[u8],
        function: Option<&str>,
    ) -> Result<(), String> {
        let parsed = parse_event_trigger(project, trigger, body)?;
        self.register_parsed(project, trigger, parsed, function)
    }

    /// Admits a trigger definition that the HTTP boundary already parsed and validated.
    pub fn register_parsed(
        &mut self,
        project: &str,
        trigger: &str,
        parsed: ParsedTrigger,
        function: Option<&str>,
    ) -> Result<(), String> {
        let ParsedTrigger {
            event_trigger,
            display_key,
            match_key,
            match_channel,
        } = parsed;
        // Charge every owned string, including the lookup and display indexes. `match_key` is
        // shared by duplicate registrations in the map, but charging it per record is a safe
        // upper bound that keeps the advertised registry budget meaningful.
        let event_trigger_bytes = serde_json::to_vec(&event_trigger)
            .map_err(|_| registry_limit_error())?
            .len();
        let retained_bytes = project
            .len()
            .checked_add(trigger.len())
            .and_then(|total| total.checked_add(event_trigger_bytes))
            .and_then(|total| total.checked_add(display_key.len()))
            .and_then(|total| total.checked_add(match_key.len()))
            .and_then(|total| total.checked_add(match_channel.len()))
            .and_then(|total| total.checked_add(function.map_or(0, str::len)))
            .ok_or_else(registry_limit_error)?;
        let next_count = self.count.checked_add(1).ok_or_else(registry_limit_error)?;
        let next_bytes = self
            .retained_bytes
            .checked_add(retained_bytes)
            .ok_or_else(registry_limit_error)?;
        if next_count > self.max_count || next_bytes > self.max_bytes {
            return Err(registry_limit_error());
        }
        self.events
            .entry(match_key)
            .or_default()
            .push(RegisteredTrigger {
                project_id: project.to_owned(),
                trigger_name: trigger.to_owned(),
                event_trigger,
                display_key,
                match_channel,
                function: function.map(str::to_owned),
                retained_bytes,
            });
        self.count = next_count;
        self.retained_bytes = next_bytes;
        Ok(())
    }

    /// Removes the first exact registration, as the official emulator does.
    pub fn remove(&mut self, project: &str, trigger: &str, body: &[u8]) -> Result<(), String> {
        let parsed = parse_event_trigger(project, trigger, body)?;
        self.remove_parsed(project, trigger, parsed)
    }

    /// Removes a trigger definition that the HTTP boundary already parsed and validated.
    pub fn remove_parsed(
        &mut self,
        project: &str,
        trigger: &str,
        parsed: ParsedTrigger,
    ) -> Result<(), String> {
        let ParsedTrigger {
            event_trigger,
            match_key,
            ..
        } = parsed;
        let mut remove_key = false;
        let removed = self.events.get_mut(&match_key).and_then(|registrations| {
            let index = registrations.iter().position(|registration| {
                registration.project_id == project
                    && registration.trigger_name == trigger
                    && registration.event_trigger == event_trigger
            })?;
            let removed = registrations.remove(index);
            remove_key = registrations.is_empty();
            Some(removed)
        });
        let Some(removed) = removed else {
            return Err(format!("Unable to delete function trigger {trigger}"));
        };
        if remove_key {
            self.events.remove(&match_key);
        }
        self.count = self.count.saturating_sub(1);
        self.retained_bytes = self.retained_bytes.saturating_sub(removed.retained_bytes);
        Ok(())
    }

    /// Returns the official `/google/getTriggers` JSON shape.
    #[must_use]
    pub fn as_json(&self) -> Value {
        let mut events = Map::new();
        for registration in self.events.values().flatten() {
            let entry = events
                .entry(registration.display_key.clone())
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Some(registrations) = entry.as_array_mut() {
                registrations.push(serde_json::json!({
                    "projectId": registration.project_id,
                    "triggerName": registration.trigger_name,
                    "eventTrigger": registration.event_trigger,
                }));
            }
        }
        Value::Object(events)
    }

    /// Resolves matching registrations to their local function names.
    pub fn matching_functions(
        &self,
        channel: &str,
        event_type: &str,
        attributes: &BTreeMap<String, String>,
        limit: usize,
    ) -> Result<Vec<String>, MatchLimitExceeded> {
        let key = format!("{event_type}-{channel}");
        let mut functions = Vec::new();
        for function in self
            .events
            .get(&key)
            .into_iter()
            .flatten()
            .filter(|registration| {
                let registered_type = registration
                    .event_trigger
                    .get("eventType")
                    .and_then(Value::as_str);
                registered_type == Some(event_type)
                    && registration.match_channel == channel
                    && registration
                        .event_trigger
                        .get("eventFilters")
                        .and_then(Value::as_object)
                        .is_none_or(|filters| {
                            filters.iter().all(|(name, expected)| {
                                expected.as_str().is_some_and(|expected| {
                                    attributes
                                        .get(name)
                                        .is_some_and(|actual| actual == expected)
                                })
                            })
                        })
            })
            .filter_map(|registration| registration.function.as_ref())
        {
            if functions.len() == limit {
                return Err(MatchLimitExceeded);
            }
            functions.push(function.clone());
        }
        Ok(functions)
    }
}

/// Resolves a Functions-emulator registration to the loaded Eventarc function it names.
#[must_use]
pub fn registered_function(
    project: &str,
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
    generation: u64,
    trigger_name: &str,
    event_trigger: &Value,
) -> Option<String> {
    use fireemu_core_functions::manifest::Trigger;

    let event_type = event_trigger.get("eventType")?.as_str()?;
    let channel = event_trigger
        .get("channel")
        .and_then(Value::as_str)
        .unwrap_or(GOOGLE_CHANNEL);
    let channel = canonical_channel(project, channel).ok()?;
    let filters = event_trigger
        .get("eventFilters")
        .and_then(Value::as_object)
        .map(|filters| {
            filters
                .iter()
                .filter_map(|(name, value)| {
                    value.as_str().map(|value| (name.clone(), value.to_owned()))
                })
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    manifest
        .functions
        .iter()
        .find(|function| {
            let event_matches = matches!(
                &function.trigger,
                Trigger::Eventarc {
                    event_type: registered_type,
                    channel: registered_channel,
                    filters: registered_filters,
                } if registered_type == event_type
                    && canonical_channel(project, registered_channel).ok().as_deref()
                        == Some(channel.as_str())
                    && registered_filters == &filters
            );
            let key = match &function.trigger {
                Trigger::Eventarc {
                    channel: registered_channel,
                    ..
                } if registered_channel != GOOGLE_CHANNEL => format!(
                    "{}-{}-{generation}-{registered_channel}",
                    function.region, function.name
                ),
                _ => format!("{}-{}-{generation}", function.region, function.name),
            };
            event_matches && trigger_name == key
        })
        .map(|function| function.name.clone())
}

fn registry_limit_error() -> String {
    "Eventarc trigger registry limit exceeded.".to_owned()
}

pub(crate) fn parse_event_trigger(
    project: &str,
    trigger: &str,
    body: &[u8],
) -> Result<ParsedTrigger, String> {
    validate_field("project", project, MAX_PROJECT_ID_BYTES)?;
    validate_field("trigger name", trigger, MAX_TRIGGER_NAME_BYTES)?;
    if body.len() > MAX_TRIGGER_DEFINITION_BYTES {
        return Err("Eventarc trigger definition is too large.".to_owned());
    }
    let body =
        std::str::from_utf8(body).map_err(|_| "Eventarc trigger body is not UTF-8.".to_owned())?;
    let placeholders = body.match_indices(PROJECT_PLACEHOLDER).count();
    let replaced_bytes = body
        .len()
        .checked_sub(placeholders.saturating_mul(PROJECT_PLACEHOLDER.len()))
        .and_then(|base| {
            placeholders
                .checked_mul(project.len())
                .and_then(|expanded| base.checked_add(expanded))
        })
        .ok_or_else(|| "Eventarc trigger definition is too large.".to_owned())?;
    if replaced_bytes > MAX_TRIGGER_DEFINITION_BYTES {
        return Err("Eventarc trigger definition is too large.".to_owned());
    }
    let body = body.replace(PROJECT_PLACEHOLDER, project);
    let parsed: Value =
        serde_json::from_str(&body).map_err(|_| "Eventarc trigger body is not JSON.".to_owned())?;
    let event_trigger = parsed
        .get("eventTrigger")
        .cloned()
        .ok_or_else(|| format!("Missing event trigger for {trigger}."))?;
    let match_channel = validate_event_trigger(project, &event_trigger)?;
    let display_key = trigger_key(&event_trigger)?;
    let match_key = format!(
        "{}-{match_channel}",
        event_trigger["eventType"].as_str().unwrap_or_default()
    );
    Ok(ParsedTrigger {
        event_trigger,
        display_key,
        match_key,
        match_channel,
    })
}

fn validate_field(name: &str, value: &str, max: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(format!("Eventarc trigger {name} is invalid."));
    }
    Ok(())
}

fn canonical_channel(project: &str, channel: &str) -> Result<String, String> {
    if channel == GOOGLE_CHANNEL {
        return Ok(GOOGLE_CHANNEL.to_owned());
    }
    if channel.starts_with("projects/") {
        return Ok(channel.to_owned());
    }
    if channel.starts_with("locations/") && !project.is_empty() {
        return Ok(format!("projects/{project}/{channel}"));
    }
    Err("Eventarc trigger channel must be a full or project-relative resource name.".to_owned())
}

fn validate_event_trigger(project: &str, event_trigger: &Value) -> Result<String, String> {
    let object = event_trigger
        .as_object()
        .ok_or_else(|| "Eventarc eventTrigger must be an object.".to_owned())?;
    let event_type = object
        .get("eventType")
        .and_then(Value::as_str)
        .ok_or_else(|| "Eventarc trigger eventType must be a string.".to_owned())?;
    validate_field("eventType", event_type, MAX_EVENT_TYPE_BYTES)?;
    if let Some(channel) = object.get("channel") {
        let channel = channel
            .as_str()
            .ok_or_else(|| "Eventarc trigger channel must be a string.".to_owned())?;
        validate_field("channel", channel, MAX_CHANNEL_BYTES)?;
        let match_channel = canonical_channel(project, channel)?;
        validate_event_filters(object.get("eventFilters"))?;
        return Ok(match_channel);
    }
    validate_event_filters(object.get("eventFilters"))?;
    Ok(GOOGLE_CHANNEL.to_owned())
}

fn validate_event_filters(filters: Option<&Value>) -> Result<(), String> {
    if let Some(filters) = filters {
        let filters = filters
            .as_object()
            .ok_or_else(|| "Eventarc trigger eventFilters must be an object.".to_owned())?;
        if filters.len() > MAX_EVENT_FILTERS
            || filters.iter().any(|(name, value)| {
                name.is_empty()
                    || name.len() > MAX_EVENT_FILTER_FIELD_BYTES
                    || value
                        .as_str()
                        .is_none_or(|value| value.len() > MAX_EVENT_FILTER_FIELD_BYTES)
            })
        {
            return Err("Eventarc trigger eventFilters are invalid.".to_owned());
        }
    }
    Ok(())
}

fn trigger_key(event_trigger: &Value) -> Result<String, String> {
    let event_type = event_trigger
        .get("eventType")
        .and_then(Value::as_str)
        .ok_or_else(|| "Eventarc trigger eventType must be a string.".to_owned())?;
    let channel = event_trigger
        .get("channel")
        .map(|channel| {
            channel
                .as_str()
                .ok_or_else(|| "Eventarc trigger channel must be a string.".to_owned())
        })
        .transpose()?
        .unwrap_or(GOOGLE_CHANNEL);
    Ok(format!("{event_type}-{channel}"))
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

/// Classifies Eventarc publication and trigger-management routes.
#[must_use]
pub fn route(path: &str) -> Option<Route> {
    if path == "/google/getTriggers" {
        return Some(Route::GetTriggers);
    }
    if let Some(channel) = publish_channel(path) {
        let project = channel
            .strip_prefix("projects/")
            .and_then(|rest| rest.split_once('/'))
            .map(|(project, _)| project.to_owned());
        return Some(Route::Publish { project, channel });
    }
    if let Some(rest) = path.strip_prefix("/emulator/v1/remove/projects/") {
        let (project, trigger) = rest.split_once("/triggers/")?;
        if !project.is_empty() && !trigger.is_empty() {
            return Some(Route::Remove {
                project: project.to_owned(),
                trigger: trigger.to_owned(),
            });
        }
    }
    if let Some(rest) = path.strip_prefix("/emulator/v1/projects/") {
        let (project, trigger) = rest.split_once("/triggers/")?;
        if !project.is_empty() && !trigger.is_empty() {
            return Some(Route::Register {
                project: project.to_owned(),
                trigger: trigger.to_owned(),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        convert, parse_event_trigger, publish_channel, route, Route, TriggerRegistry,
        GOOGLE_CHANNEL, MAX_PROJECT_ID_BYTES, MAX_TRIGGER_DEFINITION_BYTES,
    };
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

    #[test]
    fn management_and_publish_routes_are_classified_without_prefix_overlap() {
        assert_eq!(
            route("/emulator/v1/projects/demo-app/triggers/worker-1-locations/us-central1/channels/custom"),
            Some(Route::Register {
                project: "demo-app".to_owned(),
                trigger: "worker-1-locations/us-central1/channels/custom".to_owned(),
            })
        );
        assert_eq!(
            route("/emulator/v1/remove/projects/demo-app/triggers/worker-1"),
            Some(Route::Remove {
                project: "demo-app".to_owned(),
                trigger: "worker-1".to_owned(),
            })
        );
        assert_eq!(route("/google/getTriggers"), Some(Route::GetTriggers));
        assert_eq!(
            route("/google/publishEvents"),
            Some(Route::Publish {
                project: None,
                channel: GOOGLE_CHANNEL.to_owned(),
            })
        );
        assert_eq!(
            route("/projects/demo-app/locations/us-central1/channels/custom:publishEvents"),
            Some(Route::Publish {
                project: Some("demo-app".to_owned()),
                channel: "projects/demo-app/locations/us-central1/channels/custom".to_owned(),
            })
        );
        assert_eq!(route("/emulator/v1/projects//triggers/worker"), None);
    }

    #[test]
    fn registration_substitutes_project_matches_filters_and_removes_exactly_one_record() {
        let body = br#"{"eventTrigger":{"eventType":"com.example.done","channel":"projects/${PROJECT_ID}/locations/us-central1/channels/custom","eventFilters":{"region":"eu"},"service":"eventarc.googleapis.com"}}"#;
        let mut registry = TriggerRegistry::with_limits(4, 4096);

        registry
            .register("demo-app", "worker-1", body, Some("worker"))
            .expect("a complete trigger registers");
        registry
            .register("demo-app", "worker-2", body, Some("worker"))
            .expect("the official registry permits duplicate definitions");
        let snapshot = registry.as_json();
        let key = "com.example.done-projects/demo-app/locations/us-central1/channels/custom";
        assert_eq!(snapshot[key].as_array().unwrap().len(), 2);
        assert_eq!(snapshot[key][0]["projectId"], "demo-app");
        assert_eq!(snapshot[key][0]["triggerName"], "worker-1");
        assert_eq!(
            snapshot[key][0]["eventTrigger"]["channel"],
            "projects/demo-app/locations/us-central1/channels/custom"
        );

        let attributes = std::collections::BTreeMap::from([("region".to_owned(), "eu".to_owned())]);
        assert_eq!(
            registry
                .matching_functions(
                    "projects/demo-app/locations/us-central1/channels/custom",
                    "com.example.done",
                    &attributes,
                    4,
                )
                .unwrap(),
            vec!["worker".to_owned(), "worker".to_owned()]
        );
        assert!(registry
            .matching_functions(
                "projects/demo-app/locations/us-central1/channels/custom",
                "com.example.done",
                &std::collections::BTreeMap::new(),
                4,
            )
            .unwrap()
            .is_empty());

        registry
            .remove("demo-app", "worker-1", body)
            .expect("the exact first registration is removable");
        assert_eq!(registry.as_json()[key].as_array().unwrap().len(), 1);
        assert_eq!(
            registry.remove("demo-app", "worker-1", body).unwrap_err(),
            "Unable to delete function trigger worker-1"
        );
        let reordered = br#"{"eventTrigger":{"service":"eventarc.googleapis.com","eventFilters":{"region":"eu"},"channel":"projects/${PROJECT_ID}/locations/us-central1/channels/custom","eventType":"com.example.done"}}"#;
        registry
            .remove("demo-app", "worker-2", reordered)
            .expect("production-style semantic equality ignores object member order");
        assert!(registry.as_json().as_object().unwrap().is_empty());
    }

    #[test]
    fn malformed_or_over_budget_registration_changes_nothing() {
        let mut registry = TriggerRegistry::with_limits(1, 1024);
        let valid = br#"{"eventTrigger":{"eventType":"com.example.done"}}"#;
        assert_eq!(
            registry
                .register("demo-app", "missing", b"{}", None)
                .unwrap_err(),
            "Missing event trigger for missing."
        );
        assert!(registry.as_json().as_object().unwrap().is_empty());

        registry
            .register("demo-app", "first", valid, Some("first"))
            .unwrap();
        let before = registry.as_json();
        assert_eq!(
            registry
                .register("demo-app", "second", valid, Some("second"))
                .unwrap_err(),
            "Eventarc trigger registry limit exceeded."
        );
        assert_eq!(registry.as_json(), before);

        registry.remove("demo-app", "first", valid).unwrap();
        registry
            .register("demo-app", "second", valid, Some("second"))
            .expect("removal refunds both registry budgets");
    }

    #[test]
    fn registry_budget_charges_every_owned_index_string_and_removal_refunds_it() {
        let project = "demo-app";
        let trigger = "worker-1";
        let function = "worker";
        let body = br#"{"eventTrigger":{"eventType":"com.example.done","channel":"locations/us-central1/channels/custom"}}"#;
        let parsed = parse_event_trigger(project, trigger, body).unwrap();
        let expected = project
            .len()
            .checked_add(trigger.len())
            .and_then(|total| {
                total.checked_add(serde_json::to_vec(&parsed.event_trigger).unwrap().len())
            })
            .and_then(|total| total.checked_add(parsed.display_key.len()))
            .and_then(|total| total.checked_add(parsed.match_channel.len()))
            .and_then(|total| total.checked_add(parsed.match_key.len()))
            .and_then(|total| total.checked_add(function.len()))
            .unwrap();
        let mut registry = TriggerRegistry::with_limits(1, expected);

        registry
            .register_parsed(project, trigger, parsed, Some(function))
            .unwrap();
        assert_eq!(registry.retained_bytes, expected);

        registry.remove(project, trigger, body).unwrap();
        assert_eq!(registry.retained_bytes, 0);
    }

    #[test]
    fn registration_rejects_bounded_fields_and_placeholder_expansion_before_retaining_state() {
        let valid = br#"{"eventTrigger":{"eventType":"com.example.done"}}"#;
        let mut registry = TriggerRegistry::default();
        assert!(registry
            .register(&"p".repeat(MAX_PROJECT_ID_BYTES + 1), "worker", valid, None)
            .unwrap_err()
            .contains("project"));
        assert!(registry
            .register(
                "demo-app",
                "worker",
                br#"{"eventTrigger":{"eventType":"","eventFilters":{}}}"#,
                None,
            )
            .unwrap_err()
            .contains("eventType"));
        assert!(registry
            .register(
                "demo-app",
                "worker",
                br#"{"eventTrigger":{"eventType":"com.example.done","eventFilters":{"region":4}}}"#,
                None,
            )
            .unwrap_err()
            .contains("eventFilters"));

        let repetitions = (MAX_TRIGGER_DEFINITION_BYTES - 128) / "${PROJECT_ID}".len();
        let expanded = format!(
            r#"{{"eventTrigger":{{"eventType":"com.example.done","channel":"{}"}}}}"#,
            "${PROJECT_ID}".repeat(repetitions)
        );
        assert!(expanded.len() < MAX_TRIGGER_DEFINITION_BYTES);
        assert!(registry
            .register(
                "a-project-id-that-expands-placeholders",
                "worker",
                expanded.as_bytes(),
                None
            )
            .unwrap_err()
            .contains("too large"));
        assert!(registry.as_json().as_object().unwrap().is_empty());

        let prefix = r#"{"eventTrigger":{"eventType":"x","service":""#;
        let suffix = r#""}}"#;
        let filler = "a".repeat(MAX_TRIGGER_DEFINITION_BYTES - prefix.len() - suffix.len());
        let exact = format!("{prefix}{filler}{suffix}");
        assert_eq!(exact.len(), MAX_TRIGGER_DEFINITION_BYTES);
        registry
            .register("demo-app", "boundary", exact.as_bytes(), None)
            .expect("the exact expanded byte boundary is accepted");
        let before = registry.as_json();
        let over = format!("{prefix}{filler}a{suffix}");
        assert_eq!(over.len(), MAX_TRIGGER_DEFINITION_BYTES + 1);
        assert!(registry
            .register("demo-app", "over", over.as_bytes(), None)
            .unwrap_err()
            .contains("too large"));
        assert_eq!(registry.as_json(), before);
    }
}
