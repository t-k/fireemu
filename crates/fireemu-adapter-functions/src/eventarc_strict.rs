//! The strict profile's Eventarc surface: what production answered, as recorded.
//!
//! Source of every answer here is the EVENTARC stage A recordings (2026-10-05, two recordings of
//! `fireemu-oracle-idp`; `tests/fixtures/eventarc-stage-a/rows.json` replays the second one). Those
//! recordings never created a channel (the recorder's create body had no `name`, which production
//! refused with `channel.name is empty`), so what production does with an existing channel is not
//! observed. This module therefore says, for each decision, whether it is recorded or an inference:
//!
//! - recorded: authentication (a missing credential), the consumer check of a project the caller cannot
//!   use, a location that does not exist (create and read), `GetChannel` and `ListChannels` of a project
//!   that has no channel, the page-token refusal, the refused creation without a name, and every
//!   refusal of `PublishEvents` that happens before the channel is looked up (the JSON-to-proto
//!   parse, the count, the size) followed by `Associated channel does not exist.`.
//! - inferred (marked `INFERRED`): the same consumer check for the creation and the publication, the
//!   method name of `GetChannel` in the missing-credential detail, the location rule (the shape of a
//!   region ID), the largest event count (the recordings only show that 8 pass and 256 are refused),
//!   which size the 524288-byte limit is compared with (an event of 262,355 bytes passes and one of
//!   1,048,787 is refused), the message of a type error in an attribute, and the empty `{}` answer of a
//!   delivered publication.
//! - not served: anything about a channel that exists (its resource, a list that has one, a creation
//!   with a name). These answer `501 UNIMPLEMENTED` and say so, rather than invent a shape.
//!
//! A channel "exists" here when a loaded function declares it: a deployed custom-event function is what
//! makes firebase-tools create its channel in production, and the Functions emulator registers the same
//! channel in its trigger table.

use serde_json::{json, Map, Value};

use crate::ordered_json::{parse, Ordered};

/// The largest number of events a publication may carry. INFERRED: 8 events pass and 256 are refused in
/// the recordings; this is the largest count that keeps every recorded pass.
pub const MAX_EVENTS: usize = 255;
/// The limit production names for one event.
pub const MAX_EVENT_BYTES: usize = 524_288;
/// The type URL production accepts for an event.
pub const CLOUD_EVENT_TYPE_URL: &str = "type.googleapis.com/io.cloudevents.v1.CloudEvent";
/// The longest value echoed back into a message.
const MAX_ECHO: usize = 1024;

const EVENTARC_SERVICE: &str = "eventarc.googleapis.com";
const PUBLISHING_SERVICE: &str = "eventarcpublishing.googleapis.com";

/// A JSON answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    /// The HTTP status.
    pub status: u16,
    /// The JSON body.
    pub body: Value,
}

/// Where a request points: the project and the location of its path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    /// The project of the path (an ID).
    pub project: String,
    /// The location of the path (`-` for every location in a list).
    pub location: String,
}

/// The routes the surface serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// `POST .../channels/{channel}:publishEvents`
    Publish {
        /// Project and location.
        place: Place,
        /// The channel ID.
        channel: String,
    },
    /// `GET .../channels/{channel}`
    GetChannel {
        /// Project and location.
        place: Place,
        /// The channel ID.
        channel: String,
    },
    /// `GET .../channels`
    ListChannels(Place),
    /// `POST .../channels`
    CreateChannel(Place),
}

impl Route {
    const fn place(&self) -> &Place {
        match self {
            Self::Publish { place, .. }
            | Self::GetChannel { place, .. }
            | Self::ListChannels(place)
            | Self::CreateChannel(place) => place,
        }
    }

    fn project(&self) -> &str {
        &self.place().project
    }

    fn location(&self) -> &str {
        &self.place().location
    }

    const fn service(&self) -> &'static str {
        match self {
            Self::Publish { .. } => PUBLISHING_SERVICE,
            _ => EVENTARC_SERVICE,
        }
    }

    /// The method named in the missing-credential detail. INFERRED for `GetChannel`.
    const fn method(&self) -> &'static str {
        match self {
            Self::Publish { .. } => "google.cloud.eventarc.publishing.v1.Publisher.PublishEvents",
            Self::GetChannel { .. } => "google.cloud.eventarc.v1.Eventarc.GetChannel",
            Self::ListChannels(_) => "google.cloud.eventarc.v1.Eventarc.ListChannels",
            Self::CreateChannel(_) => "google.cloud.eventarc.v1.Eventarc.CreateChannel",
        }
    }
}

/// Classifies a request. The production path starts with `/v1`; the Admin SDK writes the same path
/// without it to an emulator host, so both are served.
#[must_use]
pub fn route(method: &str, path: &str) -> Option<Route> {
    let path = path.strip_prefix("/v1").unwrap_or(path);
    let rest = path.strip_prefix("/projects/")?;
    let (project, rest) = rest.split_once("/locations/")?;
    let (location, rest) = rest.split_once("/channels")?;
    if project.is_empty() || project.contains('/') || location.is_empty() || location.contains('/')
    {
        return None;
    }
    let place = Place {
        project: project.to_owned(),
        location: location.to_owned(),
    };
    match (method, rest) {
        ("GET", "") => Some(Route::ListChannels(place)),
        ("POST", "") => Some(Route::CreateChannel(place)),
        (_, rest) => {
            let channel = rest.strip_prefix('/')?;
            if channel.is_empty() {
                return None;
            }
            match (method, channel.strip_suffix(":publishEvents")) {
                ("POST", Some(channel)) if !channel.is_empty() && !channel.contains([':', '/']) => {
                    Some(Route::Publish {
                        place,
                        channel: channel.to_owned(),
                    })
                }
                ("GET", None) if !channel.contains([':', '/']) => Some(Route::GetChannel {
                    place,
                    channel: channel.to_owned(),
                }),
                _ => None,
            }
        }
    }
}

/// One request, as the surface sees it.
pub struct Input<'a> {
    /// The route.
    pub route: &'a Route,
    /// The query string, without the `?`.
    pub query: Option<&'a str>,
    /// Whether the request carried an `Authorization: Bearer` credential.
    pub authorized: bool,
    /// The body.
    pub body: &'a [u8],
}

/// What the surface knows about the world it answers in.
pub struct World<'a> {
    /// The one project the caller may use.
    pub project: &'a str,
    /// A fresh 16-hex ID for the answers that carry one.
    pub request_id: &'a str,
    /// Whether a loaded function declares the channel (the full resource name).
    pub declared_channel: &'a dyn Fn(&str) -> bool,
    /// Whether a loaded function declares any channel in the project and location (`-` is every location).
    pub declared_in: &'a dyn Fn(&str, &str) -> bool,
}

/// What to do with a request.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Answer it.
    Answer(Answer),
    /// A valid publication to a declared channel: hand these events (proto JSON) to the emulator's
    /// delivery, which owns what a handler receives.
    Deliver {
        /// The full channel resource name.
        channel: String,
        /// The events as the request wrote them.
        events: Vec<Value>,
    },
}

fn answer(status: u16, body: Value) -> Outcome {
    Outcome::Answer(Answer { status, body })
}

fn error(status: u16, canonical: &str, message: &str, details: Vec<Value>) -> Outcome {
    let mut error = Map::new();
    error.insert("code".to_owned(), json!(status));
    error.insert("message".to_owned(), json!(message));
    error.insert("status".to_owned(), json!(canonical));
    if !details.is_empty() {
        error.insert("details".to_owned(), Value::Array(details));
    }
    answer(status, json!({ "error": error }))
}

fn bad_request_detail(violations: &[(Option<&str>, Option<&str>)]) -> Value {
    json!({
        "@type": "type.googleapis.com/google.rpc.BadRequest",
        "fieldViolations": violations.iter().map(|(field, description)| {
            let mut violation = Map::new();
            if let Some(field) = field {
                violation.insert("field".to_owned(), json!(field));
            }
            if let Some(description) = description {
                violation.insert("description".to_owned(), json!(description));
            }
            Value::Object(violation)
        }).collect::<Vec<_>>(),
    })
}

/// A canonical JSON error with no details.
#[must_use]
pub fn failure(status: u16, canonical: &str, message: &str) -> Answer {
    match error(status, canonical, message, Vec::new()) {
        Outcome::Answer(answer) => answer,
        Outcome::Deliver { .. } => unreachable!("an error is an answer"),
    }
}

fn invalid_argument(message: &str, field: Option<&str>) -> Outcome {
    error(
        400,
        "INVALID_ARGUMENT",
        message,
        vec![bad_request_detail(&[(field, Some(message))])],
    )
}

fn echo(text: &str) -> String {
    if text.len() <= MAX_ECHO {
        return text.to_owned();
    }
    let mut end = MAX_ECHO;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

fn missing_credential(route: &Route) -> Outcome {
    error(
        401,
        "UNAUTHENTICATED",
        "Request is missing required authentication credential. Expected OAuth 2 access token, login cookie or other valid authentication credential. See https://developers.google.com/identity/sign-in/web/devconsole-project.",
        vec![json!({
            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
            "reason": "CREDENTIALS_MISSING",
            "domain": "googleapis.com",
            "metadata": {"service": route.service(), "method": route.method()},
        })],
    )
}

/// The project the caller may not use. INFERRED for the creation and the publication.
fn consumer_invalid(route: &Route) -> Outcome {
    let project = route.project();
    let message = format!("Permission denied on resource project {project}.");
    error(
        403,
        "PERMISSION_DENIED",
        &message,
        vec![
            json!({
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": "CONSUMER_INVALID",
                "domain": "googleapis.com",
                "metadata": {
                    "containerInfo": project,
                    "consumer": format!("projects/{project}"),
                    "service": route.service(),
                },
            }),
            json!({
                "@type": "type.googleapis.com/google.rpc.LocalizedMessage",
                "locale": "en-US",
                "message": message,
            }),
            json!({
                "@type": "type.googleapis.com/google.rpc.Help",
                "links": [{
                    "description": "Google developers console",
                    "url": "https://console.developers.google.com",
                }],
            }),
        ],
    )
}

/// Whether a location can exist. INFERRED: only the shape of a region ID (`us-central1`,
/// `northamerica-northeast2`) or `global` is checked; the recordings name one location that exists and
/// one that does not (`no-such-location1`).
fn plausible_location(location: &str) -> bool {
    if location == "global" {
        return true;
    }
    let Some((geography, direction)) = location.split_once('-') else {
        return false;
    };
    let Some(digits_at) = direction.find(|c: char| c.is_ascii_digit()) else {
        return false;
    };
    let (direction, number) = direction.split_at(digits_at);
    !geography.is_empty()
        && geography.bytes().all(|b| b.is_ascii_lowercase())
        && !direction.is_empty()
        && direction.bytes().all(|b| b.is_ascii_lowercase())
        && !number.is_empty()
        && number.bytes().all(|b| b.is_ascii_digit())
}

fn location_not_found(route: &Route) -> Outcome {
    let location = route.location();
    match route {
        Route::CreateChannel(Place { project, .. }) => {
            let message =
                format!("Permission denied on 'locations/{location}' (or it may not exist).");
            error(
                403,
                "PERMISSION_DENIED",
                &message,
                vec![
                    json!({
                        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                        "reason": "LOCATION_POLICY_VIOLATED",
                        "domain": "googleapis.com",
                        "metadata": {
                            "location": location,
                            "consumer": format!("projects/{project}"),
                            "service": EVENTARC_SERVICE,
                        },
                    }),
                    json!({
                        "@type": "type.googleapis.com/google.rpc.LocalizedMessage",
                        "locale": "en-US",
                        "message": message,
                    }),
                ],
            )
        }
        _ => error(
            403,
            "PERMISSION_DENIED",
            &format!("Location {location} is not found or access is unauthorized."),
            Vec::new(),
        ),
    }
}

fn unobserved(what: &str) -> Outcome {
    error(
        501,
        "UNIMPLEMENTED",
        &format!(
            "fireemu strict does not serve {what}: production has not been observed to answer it."
        ),
        Vec::new(),
    )
}

/// Answers one request.
#[must_use]
pub fn evaluate(input: &Input<'_>, world: &World<'_>) -> Outcome {
    let route = input.route;
    if !input.authorized {
        return missing_credential(route);
    }
    if route.project() != world.project {
        return consumer_invalid(route);
    }
    match route {
        Route::Publish { place, channel } => publish(place, channel, input.body, world),
        Route::GetChannel { place, channel } => {
            let Place { project, location } = place;
            if !plausible_location(location) {
                return location_not_found(route);
            }
            let name = format!("projects/{project}/locations/{location}/channels/{channel}");
            if (world.declared_channel)(&name) {
                return unobserved("the resource of an existing channel");
            }
            error(
                404,
                "NOT_FOUND",
                &format!("Resource '{name}' was not found"),
                vec![json!({
                    "@type": "type.googleapis.com/google.rpc.ResourceInfo",
                    "resourceName": name,
                })],
            )
        }
        Route::ListChannels(Place { project, location }) => {
            if location != "-" && !plausible_location(location) {
                return location_not_found(route);
            }
            if has_value(input.query, "pageToken") {
                return error(
                    400,
                    "INVALID_ARGUMENT",
                    "The request was invalid: invalid page token",
                    vec![bad_request_detail(&[(
                        Some("pageToken"),
                        Some("invalid page token"),
                    )])],
                );
            }
            if (world.declared_in)(project, location) {
                return unobserved("a list of existing channels");
            }
            answer(200, json!({}))
        }
        Route::CreateChannel(_) => create_channel(route, input, world),
    }
}

fn has_value(query: Option<&str>, name: &str) -> bool {
    query.is_some_and(|query| {
        query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .any(|(key, value)| key == name && !value.is_empty())
    })
}

fn create_channel(route: &Route, input: &Input<'_>, world: &World<'_>) -> Outcome {
    if !plausible_location(route.location()) {
        return location_not_found(route);
    }
    let named = match parse(input.body) {
        Ok(Ordered::Object(members)) => members.iter().any(|(name, value)| {
            name == "name" && matches!(value, Ordered::String(text) if !text.is_empty())
        }),
        Ok(_) | Err(_) => {
            return invalid_argument("Invalid JSON payload received.", None);
        }
    };
    if !named {
        return error(
            400,
            "INVALID_ARGUMENT",
            "The request was invalid: channel.name is empty",
            vec![
                bad_request_detail(&[(Some("channel.name"), None)]),
                json!({
                    "@type": "type.googleapis.com/google.rpc.RequestInfo",
                    "requestId": world.request_id,
                }),
            ],
        );
    }
    unobserved("the creation of a channel")
}

// --- publishing ------------------------------------------------------------------------------------

/// The serialized length of a varint.
#[must_use]
pub const fn varint_len(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 128 {
        value >>= 7;
        length += 1;
    }
    length
}

/// The serialized length of a length-delimited field with a one-byte tag.
#[must_use]
pub const fn field_len(payload: usize) -> usize {
    1 + varint_len(payload as u64) + payload
}

/// One attribute value of an event.
#[derive(Debug, Clone, PartialEq)]
enum Attribute {
    Boolean,
    Integer(i32),
    Text(usize),
    Bytes(usize),
    Timestamp { seconds: i64, nanos: u32 },
}

impl Attribute {
    fn size(&self) -> usize {
        match self {
            Self::Boolean => 2,
            Self::Integer(value) => {
                1 + if *value < 0 {
                    10
                } else {
                    varint_len(u64::try_from(*value).unwrap_or(0))
                }
            }
            Self::Text(length) | Self::Bytes(length) => field_len(*length),
            Self::Timestamp { seconds, nanos } => {
                // A negative int64 is ten bytes on the wire; zero is not written at all.
                let seconds_len = match seconds.cmp(&0) {
                    std::cmp::Ordering::Less => 1 + 10,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => {
                        1 + varint_len(u64::try_from(*seconds).unwrap_or(0))
                    }
                };
                let nanos_len = if *nanos == 0 {
                    0
                } else {
                    1 + varint_len(u64::from(*nanos))
                };
                field_len(seconds_len + nanos_len)
            }
        }
    }
}

/// An event as parsed from the proto JSON: the serialized size of each part, and the original value.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedEvent {
    /// The event as the request wrote it (for delivery).
    pub json: Value,
    /// The serialized size of the `CloudEvent` message.
    pub inner_size: usize,
}

impl ParsedEvent {
    /// The serialized size of the event as an `Any`: type URL and value.
    #[must_use]
    pub fn any_size(&self) -> usize {
        field_len(CLOUD_EVENT_TYPE_URL.len()) + field_len(self.inner_size)
    }
}

/// The serialized size of a whole `PublishEventsRequest`: the channel name and each event as an `Any`.
#[must_use]
pub fn request_size(channel: &str, events: &[ParsedEvent]) -> usize {
    field_len(channel.len())
        + events
            .iter()
            .map(|event| field_len(event.any_size()))
            .sum::<usize>()
}

fn publish(place: &Place, channel: &str, body: &[u8], world: &World<'_>) -> Outcome {
    let Place { project, location } = place;
    let name = format!("projects/{project}/locations/{location}/channels/{channel}");
    let events = match parse_publish(body) {
        Ok(events) => events,
        Err(refusal) => return refusal,
    };
    if events.is_empty() {
        return error(
            400,
            "INVALID_ARGUMENT",
            "No events provided.",
            vec![bad_request_detail(&[(
                Some("events"),
                Some("No events provided."),
            )])],
        );
    }
    if events.len() > MAX_EVENTS {
        return error(
            400,
            "OUT_OF_RANGE",
            "Too many events.",
            vec![bad_request_detail(&[(
                Some("events"),
                Some("Too many events."),
            )])],
        );
    }
    // The message names the size of the whole request, not of the event that is too large.
    let too_large: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, event)| event.any_size() > MAX_EVENT_BYTES)
        .map(|(index, _)| index)
        .collect();
    if !too_large.is_empty() {
        let message = format!(
            "The event size ({} bytes) is too large. The maximum size is {MAX_EVENT_BYTES} bytes.",
            request_size(&name, &events)
        );
        let fields: Vec<String> = too_large
            .iter()
            .map(|index| format!("events[{index}]"))
            .collect();
        let violations: Vec<(Option<&str>, Option<&str>)> = fields
            .iter()
            .map(|field| (Some(field.as_str()), Some(message.as_str())))
            .collect();
        return error(
            400,
            "INVALID_ARGUMENT",
            &message,
            vec![bad_request_detail(&violations)],
        );
    }
    if !(world.declared_channel)(&name) {
        return error(
            404,
            "NOT_FOUND",
            "Associated channel does not exist.",
            Vec::new(),
        );
    }
    Outcome::Deliver {
        channel: name,
        events: events.into_iter().map(|event| event.json).collect(),
    }
}

fn parse_publish(body: &[u8]) -> Result<Vec<ParsedEvent>, Outcome> {
    let document =
        parse(body).map_err(|_| invalid_argument("Invalid JSON payload received.", None))?;
    let Ordered::Object(members) = document else {
        return Err(invalid_argument("Invalid JSON payload received.", None));
    };
    let mut events = Vec::new();
    for (name, value) in &members {
        match name.as_str() {
            "events" => match value {
                Ordered::Array(items) => {
                    for (index, item) in items.iter().enumerate() {
                        events.push(parse_event(index, item)?);
                    }
                }
                Ordered::Null => {}
                _ => {
                    return Err(invalid_argument(
                        "Invalid JSON payload received.",
                        Some("events"),
                    ))
                }
            },
            "channel" => {}
            unknown => return Err(unknown_name(unknown, None)),
        }
    }
    Ok(events)
}

fn unknown_name(name: &str, at: Option<&str>) -> Outcome {
    let location = at.map_or_else(String::new, |at| format!(" at '{at}'"));
    let message = format!(
        "Invalid JSON payload received. Unknown name \"{}\"{location}: Cannot find field.",
        echo(name)
    );
    invalid_argument(&message, at)
}

fn invalid_value(path: &str, kind: &str, detail: &str) -> Outcome {
    let message = format!("Invalid value at '{path}' ({kind}), {detail}");
    invalid_argument(&message, Some(path))
}

/// `Invalid value at 'x' (TYPE_STRING), 5`: the form production uses for a value of the wrong type.
/// INFERRED: the recordings show this form for bytes and timestamps only.
fn wrong_type(path: &str, kind: &str, value: &Ordered) -> Outcome {
    invalid_value(path, kind, &echo(&value.to_value().to_string()))
}

fn snake(name: &str) -> &str {
    match name {
        "specVersion" => "spec_version",
        "binaryData" => "binary_data",
        "textData" => "text_data",
        "protoData" => "proto_data",
        other => other,
    }
}

fn parse_event(index: usize, event: &Ordered) -> Result<ParsedEvent, Outcome> {
    let at = format!("events[{index}]");
    let Ordered::Object(members) = event else {
        return Err(invalid_argument(
            "Invalid JSON payload received.",
            Some(&at),
        ));
    };
    let type_url = members
        .iter()
        .find(|(name, _)| name == "@type")
        .and_then(|(_, value)| match value {
            Ordered::String(text) => Some(text.as_str()),
            _ => None,
        });
    let Some(type_url) = type_url else {
        return Err(invalid_value(
            &at,
            "Any",
            "Missing @type for any field in google.cloud.eventarc.publishing.v1.PublishEventsRequest",
        ));
    };
    if type_url != CLOUD_EVENT_TYPE_URL {
        let unknown = type_url.rsplit('/').next().unwrap_or(type_url);
        return Err(invalid_value(
            &at,
            "Any",
            &format!("Invalid type URL, unknown type: {}", echo(unknown)),
        ));
    }
    let mut inner = 0usize;
    let mut data_member: Option<&str> = None;
    for (name, value) in members {
        match name.as_str() {
            "@type" => {}
            "id" | "source" | "specVersion" | "spec_version" | "type" => {
                let Ordered::String(text) = value else {
                    return Err(wrong_type(snake(name), "TYPE_STRING", value));
                };
                if !text.is_empty() {
                    inner += field_len(text.len());
                }
            }
            "attributes" => inner += parse_attributes(value)?,
            "binaryData" | "binary_data" | "textData" | "text_data" | "protoData"
            | "proto_data" => {
                if let Some(first) = data_member {
                    let _ = first;
                    return Err(invalid_argument(
                        &format!(
                            "Invalid value (oneof), oneof field 'data' is already set. Cannot set '{name}'"
                        ),
                        None,
                    ));
                }
                data_member = Some(name);
                match snake(name) {
                    "binary_data" => {
                        let Ordered::String(text) = value else {
                            return Err(wrong_type("binary_data", "TYPE_BYTES", value));
                        };
                        let Some(length) = base64_len(text) else {
                            return Err(invalid_value(
                                "binary_data",
                                "TYPE_BYTES",
                                &format!("Base64 decoding failed for \"{}\"", echo(text)),
                            ));
                        };
                        inner += field_len(length);
                    }
                    "text_data" => {
                        let Ordered::String(text) = value else {
                            return Err(wrong_type("text_data", "TYPE_STRING", value));
                        };
                        inner += field_len(text.len());
                    }
                    _ => return Err(unobserved("an event with proto data")),
                }
            }
            unknown => return Err(unknown_name(unknown, None)),
        }
    }
    Ok(ParsedEvent {
        json: event.to_value(),
        inner_size: inner,
    })
}

/// The map of attributes of one event; returns the serialized size of its entries.
fn parse_attributes(value: &Ordered) -> Result<usize, Outcome> {
    let Ordered::Object(entries) = value else {
        return Err(invalid_argument(
            "Invalid JSON payload received.",
            Some("attributes"),
        ));
    };
    let mut size = 0;
    for (index, (key, attribute)) in entries.iter().enumerate() {
        let path = format!("attributes[{index}].value");
        let parsed = parse_attribute(&path, attribute)?;
        let entry = field_len(key.len()) + field_len(parsed.size());
        size += field_len(entry);
    }
    Ok(size)
}

fn parse_attribute(path: &str, value: &Ordered) -> Result<Attribute, Outcome> {
    let Ordered::Object(members) = value else {
        return Err(invalid_argument(
            "Invalid JSON payload received.",
            Some(path),
        ));
    };
    let mut parsed: Option<Attribute> = None;
    for (name, member) in members {
        let field = match name.as_str() {
            "ceBoolean" | "ce_boolean" => "ce_boolean",
            "ceInteger" | "ce_integer" => "ce_integer",
            "ceString" | "ce_string" => "ce_string",
            "ceBytes" | "ce_bytes" => "ce_bytes",
            "ceUri" | "ce_uri" => "ce_uri",
            "ceUriRef" | "ce_uri_ref" => "ce_uri_ref",
            "ceTimestamp" | "ce_timestamp" => "ce_timestamp",
            unknown => return Err(unknown_name(unknown, Some(path))),
        };
        if parsed.is_some() {
            return Err(invalid_argument(
                &format!(
                    "Invalid value (oneof), oneof field 'attr' is already set. Cannot set '{name}'"
                ),
                None,
            ));
        }
        let at = format!("{path}.{field}");
        parsed = Some(match (field, member) {
            ("ce_boolean", Ordered::Bool(_)) => Attribute::Boolean,
            ("ce_boolean", other) => return Err(wrong_type(&at, "TYPE_BOOL", other)),
            ("ce_integer", Ordered::Number(number)) => {
                let Some(integer) = number.as_i64().and_then(|n| i32::try_from(n).ok()) else {
                    return Err(wrong_type(&at, "TYPE_INT32", member));
                };
                Attribute::Integer(integer)
            }
            ("ce_integer", other) => return Err(wrong_type(&at, "TYPE_INT32", other)),
            ("ce_string" | "ce_uri" | "ce_uri_ref", Ordered::String(text)) => {
                Attribute::Text(text.len())
            }
            ("ce_string" | "ce_uri" | "ce_uri_ref", other) => {
                return Err(wrong_type(&at, "TYPE_STRING", other));
            }
            ("ce_bytes", Ordered::String(text)) => match base64_len(text) {
                Some(length) => Attribute::Bytes(length),
                None => {
                    return Err(invalid_value(
                        &at,
                        "TYPE_BYTES",
                        &format!("Base64 decoding failed for \"{}\"", echo(text)),
                    ));
                }
            },
            ("ce_bytes", other) => return Err(wrong_type(&at, "TYPE_BYTES", other)),
            ("ce_timestamp", Ordered::String(text)) => match timestamp(text) {
                Some((seconds, nanos)) => Attribute::Timestamp { seconds, nanos },
                None => {
                    return Err(invalid_value(
                        &at,
                        "type.googleapis.com/google.protobuf.Timestamp",
                        "Field 'ceTimestamp', Illegal timestamp format; timestamps must end with 'Z' or have a valid timezone offset.",
                    ));
                }
            },
            (_, other) => {
                debug_assert_eq!(field, "ce_timestamp");
                return Err(wrong_type(
                    &at,
                    "type.googleapis.com/google.protobuf.Timestamp",
                    other,
                ));
            }
        });
    }
    parsed.ok_or_else(|| invalid_argument("Invalid JSON payload received.", Some(path)))
}

/// The decoded length of a base64 text, or `None` when it is not base64. Both alphabets are accepted,
/// padding is optional.
#[must_use]
pub fn base64_len(text: &str) -> Option<usize> {
    let trimmed = text.trim_end_matches('=');
    let padding = text.len() - trimmed.len();
    if padding > 2 {
        return None;
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_'))
    {
        return None;
    }
    let remainder = trimmed.len() % 4;
    if remainder == 1 {
        return None;
    }
    if padding > 0 && (trimmed.len() + padding) % 4 != 0 {
        return None;
    }
    let full = trimmed.len() / 4 * 3;
    Some(
        full + match remainder {
            2 => 1,
            3 => 2,
            _ => 0,
        },
    )
}

/// The seconds and nanoseconds of an RFC 3339 timestamp, or `None` when it is not one.
#[must_use]
pub fn timestamp(text: &str) -> Option<(i64, u32)> {
    let parsed = chrono::DateTime::parse_from_rfc3339(text).ok()?;
    if !text.is_ascii() || text.bytes().any(|b| b == b' ' || b == b't' || b == b'z') {
        return None;
    }
    Some((parsed.timestamp(), parsed.timestamp_subsec_nanos()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const PROJECT: &str = "demo";

    fn world<'a>(
        declared: &'a dyn Fn(&str) -> bool,
        declared_in: &'a dyn Fn(&str, &str) -> bool,
    ) -> World<'a> {
        World {
            project: PROJECT,
            request_id: "0123456789abcdef",
            declared_channel: declared,
            declared_in,
        }
    }

    fn run(method: &str, target: &str, authorized: bool, body: &str, declared: &[&str]) -> Outcome {
        let (path, query) = target
            .split_once('?')
            .map_or((target, None), |(path, query)| (path, Some(query)));
        let route = route(method, path).expect("a route");
        let declared: Vec<String> = declared.iter().map(|name| (*name).to_owned()).collect();
        let declared_channel = |name: &str| declared.iter().any(|d| d == name);
        let declared_in = |project: &str, location: &str| {
            declared.iter().any(|d| {
                d.starts_with(&format!("projects/{project}/locations/"))
                    && (location == "-" || d.contains(&format!("/locations/{location}/")))
            })
        };
        evaluate(
            &Input {
                route: &route,
                query,
                authorized,
                body: body.as_bytes(),
            },
            &world(&declared_channel, &declared_in),
        )
    }

    fn status_and_message(outcome: &Outcome) -> (u16, String) {
        match outcome {
            Outcome::Answer(Answer { status, body }) => (
                *status,
                body["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            ),
            Outcome::Deliver { .. } => (200, "delivered".to_owned()),
        }
    }

    fn event_json(extra: &str) -> String {
        format!(
            r#"{{"@type":"{CLOUD_EVENT_TYPE_URL}","id":"i","source":"s","specVersion":"1.0","type":"t","attributes":{{"time":{{"ceTimestamp":"2026-10-05T06:17:17.731Z"}}}},"textData":"x"{extra}}}"#
        )
    }

    const CHANNEL: &str = "/v1/projects/demo/locations/us-central1/channels/c";

    fn publish(events: &[String], declared: &[&str]) -> Outcome {
        run(
            "POST",
            &format!("{CHANNEL}:publishEvents"),
            true,
            &format!(r#"{{"events":[{}]}}"#, events.join(",")),
            declared,
        )
    }

    #[test]
    fn routes_are_the_production_paths_with_or_without_the_version_prefix() {
        let place = |project: &str, location: &str| Place {
            project: project.to_owned(),
            location: location.to_owned(),
        };
        for prefix in ["/v1", ""] {
            let base = format!("{prefix}/projects/p/locations/l/channels");
            assert_eq!(
                route("GET", &base),
                Some(Route::ListChannels(place("p", "l")))
            );
            assert_eq!(
                route("POST", &base),
                Some(Route::CreateChannel(place("p", "l")))
            );
            assert_eq!(
                route("GET", &format!("{base}/c")),
                Some(Route::GetChannel {
                    place: place("p", "l"),
                    channel: "c".to_owned()
                })
            );
            assert_eq!(
                route("POST", &format!("{base}/c:publishEvents")),
                Some(Route::Publish {
                    place: place("p", "l"),
                    channel: "c".to_owned()
                })
            );
        }
        assert_eq!(
            route("GET", "/v1/projects/p/locations/-/channels"),
            Some(Route::ListChannels(place("p", "-")))
        );
        for (method, path) in [
            ("DELETE", "/v1/projects/p/locations/l/channels/c"),
            ("PATCH", "/v1/projects/p/locations/l/channels/c"),
            ("GET", "/v1/projects/p/locations/l/channels/c:publishEvents"),
            ("POST", "/v1/projects/p/locations/l/channels/c"),
            ("POST", "/v1/projects/p/locations/l/channels/:publishEvents"),
            ("GET", "/v1/projects/p/locations/l/channels/"),
            ("GET", "/v1/projects/p/locations/l/channelsx"),
            ("GET", "/v1/projects//locations/l/channels"),
            ("GET", "/v1/projects/p/locations//channels"),
            ("GET", "/v1/projects/p/x/locations/l/channels"),
            ("GET", "/v1/projects/p/locations/l/m/channels"),
            ("GET", "/v1/projects/p/locations/l/channels/a/b"),
            (
                "POST",
                "/v1/projects/p/locations/l/channels/a/b:publishEvents",
            ),
            (
                "POST",
                "/v1/projects/p/locations/l/channels/a:b:publishEvents",
            ),
            ("GET", "/v1x/projects/p/locations/l/channels"),
            ("GET", "/google/getTriggers"),
            ("POST", "/google/publishEvents"),
            ("POST", "/emulator/v1/projects/p/triggers/t"),
        ] {
            assert_eq!(route(method, path), None, "{method} {path}");
        }
    }

    #[test]
    fn a_region_id_is_a_geography_a_direction_and_a_number() {
        for fine in [
            "us-central1",
            "europe-west12",
            "northamerica-northeast2",
            "global",
            "me-central2",
        ] {
            assert!(plausible_location(fine), "{fine}");
        }
        for odd in [
            "no-such-location1",
            "",
            "us",
            "us-",
            "-central1",
            "us-central",
            "us-central1x",
            "US-central1",
            "us-central-1",
            "us-1",
            "1-central1",
            "us_central1",
            "us-cen tral1",
        ] {
            assert!(!plausible_location(odd), "{odd}");
        }
    }

    #[test]
    fn the_first_check_to_fail_is_the_credential_then_the_project_then_the_location() {
        let (status, _) = status_and_message(&run(
            "GET",
            "/v1/projects/other/locations/nowhere1x/channels",
            false,
            "",
            &[],
        ));
        assert_eq!(status, 401);
        let (status, message) = status_and_message(&run(
            "GET",
            "/v1/projects/other/locations/no-such-location1/channels",
            true,
            "",
            &[],
        ));
        assert_eq!(
            (status, message.as_str()),
            (403, "Permission denied on resource project other.")
        );
        let (status, message) = status_and_message(&run(
            "GET",
            "/v1/projects/demo/locations/no-such-location1/channels/c",
            true,
            "",
            &[],
        ));
        assert_eq!(
            (status, message.as_str()),
            (
                403,
                "Location no-such-location1 is not found or access is unauthorized."
            )
        );
        let create = run(
            "POST",
            "/v1/projects/demo/locations/no-such-location1/channels?channelId=x",
            true,
            "{}",
            &[],
        );
        let (status, message) = status_and_message(&create);
        assert_eq!(
            (status, message.as_str()),
            (
                403,
                "Permission denied on 'locations/no-such-location1' (or it may not exist)."
            )
        );
        let Outcome::Answer(Answer { body, .. }) = create else {
            panic!()
        };
        assert_eq!(
            body["error"]["details"][0]["metadata"]["consumer"],
            "projects/demo"
        );
        // A publication does not look at the location; the channel is simply not there.
        let (status, message) = status_and_message(&run(
            "POST",
            "/v1/projects/demo/locations/no-such-location1/channels/c:publishEvents",
            true,
            &format!(r#"{{"events":[{}]}}"#, event_json("")),
            &[],
        ));
        assert_eq!(
            (status, message.as_str()),
            (404, "Associated channel does not exist.")
        );
    }

    #[test]
    fn a_credential_header_is_all_that_is_checked_of_a_credential() {
        let get = "/v1/projects/demo/locations/us-central1/channels";
        assert_eq!(status_and_message(&run("GET", get, true, "", &[])).0, 200);
        let Outcome::Answer(Answer { body, .. }) = run("GET", get, false, "", &[]) else {
            panic!()
        };
        assert_eq!(body["error"]["details"][0]["reason"], "CREDENTIALS_MISSING");
        assert_eq!(body["error"]["details"][0]["domain"], "googleapis.com");
        assert_eq!(
            body["error"]["details"][0]["metadata"]["service"],
            EVENTARC_SERVICE
        );
        for (method, target, service, rpc) in [
            (
                "GET",
                "/v1/projects/demo/locations/l1/channels/c",
                EVENTARC_SERVICE,
                "google.cloud.eventarc.v1.Eventarc.GetChannel",
            ),
            (
                "POST",
                "/v1/projects/demo/locations/l1/channels",
                EVENTARC_SERVICE,
                "google.cloud.eventarc.v1.Eventarc.CreateChannel",
            ),
            (
                "POST",
                "/v1/projects/demo/locations/l1/channels/c:publishEvents",
                PUBLISHING_SERVICE,
                "google.cloud.eventarc.publishing.v1.Publisher.PublishEvents",
            ),
        ] {
            let Outcome::Answer(Answer { status, body }) = run(method, target, false, "", &[])
            else {
                panic!()
            };
            assert_eq!(status, 401);
            assert_eq!(body["error"]["details"][0]["metadata"]["service"], service);
            assert_eq!(body["error"]["details"][0]["metadata"]["method"], rpc);
        }
    }

    #[test]
    fn a_list_refuses_a_page_token_and_never_serves_a_channel_it_cannot_describe() {
        let base = "/v1/projects/demo/locations/us-central1/channels";
        for query in [
            "?pageToken=garbage",
            "?pageSize=1&pageToken=x",
            "?pageToken=%20",
        ] {
            let outcome = run("GET", &format!("{base}{query}"), true, "", &[]);
            let Outcome::Answer(Answer { status, body }) = outcome else {
                panic!()
            };
            assert_eq!(status, 400, "{query}");
            assert_eq!(
                body["error"]["message"],
                "The request was invalid: invalid page token"
            );
            let violation = &body["error"]["details"][0]["fieldViolations"][0];
            assert_eq!(
                (
                    violation["field"].as_str(),
                    violation["description"].as_str()
                ),
                (Some("pageToken"), Some("invalid page token"))
            );
        }
        for query in [
            "",
            "?pageToken=",
            "?pageSize=5",
            "?pageTokenx=1",
            "?x=pageToken=1",
        ] {
            assert_eq!(
                status_and_message(&run("GET", &format!("{base}{query}"), true, "", &[])).0,
                200,
                "{query}"
            );
        }
        let declared = ["projects/demo/locations/us-central1/channels/c"];
        assert_eq!(
            status_and_message(&run("GET", base, true, "", &declared)).0,
            501
        );
        assert_eq!(
            status_and_message(&run(
                "GET",
                "/v1/projects/demo/locations/-/channels",
                true,
                "",
                &declared
            ))
            .0,
            501
        );
        assert_eq!(
            status_and_message(&run(
                "GET",
                "/v1/projects/demo/locations/europe-west1/channels",
                true,
                "",
                &declared
            ))
            .0,
            200
        );
        assert_eq!(
            status_and_message(&run("GET", &format!("{base}/c"), true, "", &declared)).0,
            501
        );
        assert_eq!(
            status_and_message(&run("GET", &format!("{base}/d"), true, "", &declared)).0,
            404
        );
    }

    #[test]
    fn a_creation_needs_a_name_and_is_not_served_with_one() {
        let target = "/v1/projects/demo/locations/us-central1/channels?channelId=c";
        for body in [
            "{}",
            r#"{"name":""}"#,
            r#"{"name":5}"#,
            r#"{"provider":"x"}"#,
            r#"{"Name":"n"}"#,
        ] {
            let Outcome::Answer(Answer {
                status,
                body: answer,
            }) = run("POST", target, true, body, &[])
            else {
                panic!()
            };
            assert_eq!(status, 400, "{body}");
            assert_eq!(
                answer["error"]["message"],
                "The request was invalid: channel.name is empty"
            );
            assert_eq!(
                answer["error"]["details"][0]["fieldViolations"][0]["field"],
                "channel.name"
            );
            assert!(answer["error"]["details"][0]["fieldViolations"][0]
                .get("description")
                .is_none());
            assert_eq!(
                answer["error"]["details"][1]["requestId"],
                "0123456789abcdef"
            );
        }
        let named = run(
            "POST",
            target,
            true,
            r#"{"name":"projects/demo/locations/us-central1/channels/c"}"#,
            &[],
        );
        assert_eq!(status_and_message(&named).0, 501);
        for body in ["", "[]", "not json", "5"] {
            let (status, message) = status_and_message(&run("POST", target, true, body, &[]));
            assert_eq!(
                (status, message.as_str()),
                (400, "Invalid JSON payload received."),
                "{body:?}"
            );
        }
    }

    #[test]
    fn a_publication_is_refused_in_the_order_production_refused_it() {
        // Not JSON, not an object, an unknown member, events of the wrong shape.
        for (body, message) in [
            ("", "Invalid JSON payload received."),
            ("[]", "Invalid JSON payload received."),
            (r#"{"events":5}"#, "Invalid JSON payload received."),
            (r#"{"events":{}}"#, "Invalid JSON payload received."),
            (r#"{"events":[5]}"#, "Invalid JSON payload received."),
            (
                r#"{"events":[],"zzz":1}"#,
                "Invalid JSON payload received. Unknown name \"zzz\": Cannot find field.",
            ),
        ] {
            let outcome = run("POST", &format!("{CHANNEL}:publishEvents"), true, body, &[]);
            assert_eq!(
                status_and_message(&outcome),
                (400, message.to_owned()),
                "{body}"
            );
        }
        // No events (absent, null, empty) and the channel member are not events.
        for body in [
            "{}",
            r#"{"events":null}"#,
            r#"{"events":[]}"#,
            r#"{"channel":"x","events":[]}"#,
        ] {
            let outcome = run("POST", &format!("{CHANNEL}:publishEvents"), true, body, &[]);
            assert_eq!(
                status_and_message(&outcome),
                (400, "No events provided.".to_owned()),
                "{body}"
            );
        }
        // A parse error in a later event comes before the count and before the channel.
        let many: Vec<String> = (0..256).map(|_| event_json("")).collect();
        assert_eq!(
            status_and_message(&publish(&many, &[])),
            (400, "Too many events.".to_owned())
        );
        let mut broken = many.clone();
        broken.push(event_json(r#","zzz":1"#));
        assert_eq!(
            status_and_message(&publish(&broken, &[])).1,
            "Invalid JSON payload received. Unknown name \"zzz\": Cannot find field."
        );
        // 255 events are the most accepted.
        assert_eq!(
            status_and_message(&publish(&many[..255], &[])),
            (404, "Associated channel does not exist.".to_owned())
        );
        let Outcome::Answer(Answer { body, .. }) = publish(&many, &[]) else {
            panic!()
        };
        assert_eq!(body["error"]["status"], "OUT_OF_RANGE");
        assert_eq!(
            body["error"]["details"][0]["fieldViolations"][0]["field"],
            "events"
        );
    }

    /// An event whose serialization as an `Any` is exactly `any_bytes` long: the text is sized to fit
    /// (the size grows by one for each character in this range, so a binary search finds it).
    fn event_of_size(any_bytes: usize) -> String {
        let with = |length: usize| {
            event_json("").replace(
                r#""textData":"x""#,
                &format!(r#""textData":"{}""#, "y".repeat(length)),
            )
        };
        let size = |length: usize| {
            parse_event(0, &parse(with(length).as_bytes()).unwrap())
                .unwrap()
                .any_size()
        };
        let (mut low, mut high) = (1, any_bytes);
        while low < high {
            let middle = usize::midpoint(low, high);
            if size(middle) < any_bytes {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        assert_eq!(size(low), any_bytes, "the size is reachable");
        with(low)
    }

    #[test]
    fn an_event_is_too_large_above_524288_bytes_as_an_any_and_the_message_names_the_whole_request()
    {
        let fits = event_of_size(MAX_EVENT_BYTES);
        let fits_event = parse_event(0, &parse(fits.as_bytes()).unwrap()).unwrap();
        assert_eq!(fits_event.any_size(), MAX_EVENT_BYTES);
        assert_eq!(
            status_and_message(&publish(std::slice::from_ref(&fits), &[])).0,
            404
        );
        let over = fits.replace(r#""textData":""#, r#""textData":"y"#);
        let over_event = parse_event(0, &parse(over.as_bytes()).unwrap()).unwrap();
        assert_eq!(over_event.any_size(), MAX_EVENT_BYTES + 1);
        let outcome = publish(&[fits, over.clone(), over], &[]);
        let Outcome::Answer(Answer { status, body }) = outcome else {
            panic!()
        };
        assert_eq!(status, 400);
        let total = request_size(
            "projects/demo/locations/us-central1/channels/c",
            &[fits_event.clone(), over_event.clone(), over_event],
        );
        let message = format!(
            "The event size ({total} bytes) is too large. The maximum size is 524288 bytes."
        );
        assert_eq!(body["error"]["message"], message.as_str());
        let violations = body["error"]["details"][0]["fieldViolations"]
            .as_array()
            .unwrap();
        let fields: Vec<&str> = violations
            .iter()
            .map(|v| v["field"].as_str().unwrap())
            .collect();
        assert_eq!(
            fields,
            ["events[1]", "events[2]"],
            "only the events over the limit"
        );
        assert!(violations
            .iter()
            .all(|v| v["description"] == message.as_str()));
    }

    #[test]
    fn a_declared_channel_receives_a_valid_publication_and_the_events_are_handed_over_unchanged() {
        let declared = ["projects/demo/locations/us-central1/channels/c"];
        let events = [event_json(""), event_json(r#","extra":null"#)];
        // A member production does not know is refused before delivery.
        assert_eq!(status_and_message(&publish(&events, &declared)).0, 400);
        let events = [event_json(""), event_json("")];
        let Outcome::Deliver {
            channel,
            events: handed,
        } = publish(&events, &declared)
        else {
            panic!("delivered")
        };
        assert_eq!(channel, "projects/demo/locations/us-central1/channels/c");
        assert_eq!(handed.len(), 2);
        assert_eq!(handed[0]["id"], "i");
        assert_eq!(
            handed[0]["attributes"]["time"]["ceTimestamp"],
            "2026-10-05T06:17:17.731Z"
        );
        // The same channel in another location or project is not declared.
        let other = run(
            "POST",
            "/v1/projects/demo/locations/europe-west1/channels/c:publishEvents",
            true,
            &format!(r#"{{"events":[{}]}}"#, event_json("")),
            &declared,
        );
        assert_eq!(status_and_message(&other).0, 404);
    }

    #[test]
    fn an_event_is_checked_member_by_member_in_the_order_it_is_written() {
        let any = |tail: &str| format!(r#"{{"@type":"{CLOUD_EVENT_TYPE_URL}"{tail}}}"#);
        let check = |event: String| status_and_message(&publish(&[event], &[]));
        let message = |text: &str| (400, text.to_owned());
        assert_eq!(
            check(any("")),
            (404, "Associated channel does not exist.".to_owned()),
            "an empty event parses"
        );
        assert_eq!(
            check(r#"{"id":"i"}"#.to_owned()),
            message("Invalid value at 'events[0]' (Any), Missing @type for any field in google.cloud.eventarc.publishing.v1.PublishEventsRequest")
        );
        assert_eq!(
            check(r#"{"@type":5}"#.to_owned()),
            message("Invalid value at 'events[0]' (Any), Missing @type for any field in google.cloud.eventarc.publishing.v1.PublishEventsRequest")
        );
        assert_eq!(
            check(r#"{"@type":"type.googleapis.com/google.protobuf.Empty"}"#.to_owned()),
            message("Invalid value at 'events[0]' (Any), Invalid type URL, unknown type: google.protobuf.Empty")
        );
        assert_eq!(
            check(r#"{"@type":"plain"}"#.to_owned()),
            message("Invalid value at 'events[0]' (Any), Invalid type URL, unknown type: plain")
        );
        // The second event is events[1].
        let outcome = publish(&[any(""), r#"{"id":"i"}"#.to_owned()], &[]);
        assert!(status_and_message(&outcome).1.contains("'events[1]'"));
        // Wrong types and the spellings proto JSON accepts.
        assert_eq!(
            check(any(r#","id":5"#)),
            message("Invalid value at 'id' (TYPE_STRING), 5")
        );
        assert_eq!(
            check(any(r#","spec_version":true"#)),
            message("Invalid value at 'spec_version' (TYPE_STRING), true")
        );
        assert_eq!(
            check(any(
                r#","specVersion":"1.0","spec_version":"1.0","text_data":"a""#
            ))
            .0,
            404
        );
        assert_eq!(
            check(any(r#","text_data":7"#)),
            message("Invalid value at 'text_data' (TYPE_STRING), 7")
        );
        assert_eq!(check(any(r#","binary_data":"eA==""#)).0, 404);
        assert_eq!(
            check(any(r#","binaryData":"eA""#)).0,
            404,
            "padding is optional"
        );
        assert_eq!(
            check(any(r#","binaryData":"e-_A""#)).0,
            404,
            "the URL-safe alphabet"
        );
        assert_eq!(
            check(any(r#","binaryData":5"#)),
            message("Invalid value at 'binary_data' (TYPE_BYTES), 5")
        );
        assert_eq!(
            check(any(r#","binaryData":"a""#)),
            message(
                "Invalid value at 'binary_data' (TYPE_BYTES), Base64 decoding failed for \"a\""
            )
        );
        assert_eq!(
            check(any(r#","textData":"a","binaryData":"eA==""#)),
            message(
                "Invalid value (oneof), oneof field 'data' is already set. Cannot set 'binaryData'"
            )
        );
        assert_eq!(
            check(any(r#","binaryData":"eA==","text_data":"a""#)),
            message(
                "Invalid value (oneof), oneof field 'data' is already set. Cannot set 'text_data'"
            )
        );
        assert_eq!(
            check(any(r#","protoData":{"@type":"x"}"#)).0,
            501,
            "an event with proto data is not served"
        );
        assert_eq!(
            check(any(r#","attributes":[]"#)),
            message("Invalid JSON payload received.")
        );
        assert_eq!(
            check(any(r#","unknown":1,"id":5"#)).1,
            "Invalid JSON payload received. Unknown name \"unknown\": Cannot find field."
        );
        assert_eq!(
            check(any(r#","id":5,"unknown":1"#)).1,
            "Invalid value at 'id' (TYPE_STRING), 5",
            "the first problem written"
        );
    }

    #[test]
    fn an_attribute_is_one_of_seven_kinds_and_is_named_by_its_position_in_the_map() {
        let event = |attributes: &str| {
            format!(r#"{{"@type":"{CLOUD_EVENT_TYPE_URL}","attributes":{attributes}}}"#)
        };
        let check = |attributes: &str| status_and_message(&publish(&[event(attributes)], &[]));
        let message = |text: &str| (400, text.to_owned());
        for fine in [
            r#"{"a":{"ceBoolean":false}}"#,
            r#"{"a":{"ce_boolean":true}}"#,
            r#"{"a":{"ceInteger":-5}}"#,
            r#"{"a":{"ceInteger":2147483647}}"#,
            r#"{"a":{"ceString":""}}"#,
            r#"{"a":{"ceBytes":"eA=="}}"#,
            r#"{"a":{"ceUri":"https://x"}}"#,
            r#"{"a":{"ceUriRef":"/x"}}"#,
            r#"{"a":{"ceTimestamp":"2026-10-05T06:17:17+09:00"}}"#,
            r#"{"a":{"ce_timestamp":"2026-10-05T06:17:17.5Z"}}"#,
        ] {
            assert_eq!(check(fine).0, 404, "{fine}");
        }
        assert_eq!(
            check(r#"{"t":{"ceTimestamp":"2026-10-05T06:17:17Z"},"b":{"ceFoo":"x"}}"#),
            message("Invalid JSON payload received. Unknown name \"ceFoo\" at 'attributes[1].value': Cannot find field.")
        );
        let timestamp = "Invalid value at 'attributes[0].value.ce_timestamp' (type.googleapis.com/google.protobuf.Timestamp), Field 'ceTimestamp', Illegal timestamp format; timestamps must end with 'Z' or have a valid timezone offset.";
        for bad in [
            "not-a-time",
            "2026-10-05T06:17:17",
            "2026-10-05 06:17:17Z",
            "2026-13-05T06:17:17Z",
            "2026-10-05t06:17:17z",
            "",
        ] {
            assert_eq!(
                check(&format!(r#"{{"a":{{"ceTimestamp":"{bad}"}}}}"#)),
                message(timestamp),
                "{bad:?}"
            );
        }
        assert_eq!(
            check(r#"{"a":{"ceString":"x","ceUri":"y"}}"#),
            message("Invalid value (oneof), oneof field 'attr' is already set. Cannot set 'ceUri'")
        );
        for (member, snake, value, kind) in [
            ("ceBoolean", "ce_boolean", "1", "TYPE_BOOL"),
            ("ceInteger", "ce_integer", "\"1\"", "TYPE_INT32"),
            ("ceInteger", "ce_integer", "2147483648", "TYPE_INT32"),
            ("ceInteger", "ce_integer", "1.5", "TYPE_INT32"),
            ("ceString", "ce_string", "5", "TYPE_STRING"),
            ("ceUri", "ce_uri", "null", "TYPE_STRING"),
            ("ceUriRef", "ce_uri_ref", "[]", "TYPE_STRING"),
            ("ceBytes", "ce_bytes", "5", "TYPE_BYTES"),
            (
                "ceTimestamp",
                "ce_timestamp",
                "5",
                "type.googleapis.com/google.protobuf.Timestamp",
            ),
        ] {
            assert_eq!(
                check(&format!(r#"{{"a":{{"{member}":{value}}}}}"#)),
                message(&format!(
                    "Invalid value at 'attributes[0].value.{snake}' ({kind}), {value}"
                )),
                "{member} {value}"
            );
        }
        assert_eq!(
            check(r#"{"a":{}}"#),
            message("Invalid JSON payload received.")
        );
        assert_eq!(
            check(r#"{"a":5}"#),
            message("Invalid JSON payload received.")
        );
        assert_eq!(
            check(r#"{"a":{"ceBytes":"***"}}"#),
            message("Invalid value at 'attributes[0].value.ce_bytes' (TYPE_BYTES), Base64 decoding failed for \"***\"")
        );
    }

    #[test]
    fn an_echoed_value_is_cut_at_a_kilobyte_on_a_character_boundary() {
        assert_eq!(echo("short"), "short");
        assert_eq!(echo(&"a".repeat(MAX_ECHO)), "a".repeat(MAX_ECHO));
        assert_eq!(
            echo(&"a".repeat(MAX_ECHO + 1)),
            format!("{}...", "a".repeat(MAX_ECHO))
        );
        let wide = "\u{3042}".repeat(400);
        let cut = echo(&wide);
        assert!(cut.ends_with("..."));
        assert!(cut.len() <= MAX_ECHO + 3);
        assert!(cut.trim_end_matches("...").chars().all(|c| c == '\u{3042}'));
        let long = format!(
            "Invalid value at 'binary_data' (TYPE_BYTES), Base64 decoding failed for \"{}\"",
            "*".repeat(5000)
        );
        let outcome = publish(
            &[format!(
                r#"{{"@type":"{CLOUD_EVENT_TYPE_URL}","binaryData":"{}"}}"#,
                "*".repeat(5000)
            )],
            &[],
        );
        assert!(status_and_message(&outcome).1.len() < long.len() / 2);
    }

    // --- sizes, against a reference encoder -----------------------------------------------------------

    /// Appends a varint, the way the wire format does.
    fn put_varint(out: &mut Vec<u8>, mut value: u64) {
        while value >= 128 {
            out.push((value & 127) as u8 | 128);
            value >>= 7;
        }
        out.push(u8::try_from(value).unwrap());
    }

    fn put_bytes(out: &mut Vec<u8>, tag: u8, payload: &[u8]) {
        out.push(tag << 3 | 2);
        put_varint(out, payload.len() as u64);
        out.extend_from_slice(payload);
    }

    #[derive(Debug, Clone)]
    enum Value2 {
        Boolean(bool),
        Integer(i32),
        Text(String),
        Bytes(Vec<u8>),
        Uri(String),
        UriRef(String),
        Timestamp(i64, u32),
    }

    fn attribute_message(value: &Value2) -> Vec<u8> {
        let mut out = Vec::new();
        match value {
            Value2::Boolean(b) => {
                out.push(1 << 3);
                out.push(u8::from(*b));
            }
            Value2::Integer(i) => {
                out.push(2 << 3);
                put_varint(&mut out, u64::from_ne_bytes(i64::from(*i).to_ne_bytes()));
            }
            Value2::Text(text) => put_bytes(&mut out, 3, text.as_bytes()),
            Value2::Bytes(bytes) => put_bytes(&mut out, 4, bytes),
            Value2::Uri(text) => put_bytes(&mut out, 5, text.as_bytes()),
            Value2::UriRef(text) => put_bytes(&mut out, 6, text.as_bytes()),
            Value2::Timestamp(seconds, nanos) => {
                let mut inner = Vec::new();
                if *seconds != 0 {
                    inner.push(1 << 3);
                    put_varint(&mut inner, u64::from_ne_bytes(seconds.to_ne_bytes()));
                }
                if *nanos != 0 {
                    inner.push(2 << 3);
                    put_varint(&mut inner, u64::from(*nanos));
                }
                put_bytes(&mut out, 7, &inner);
            }
        }
        out
    }

    fn b64(bytes: &[u8], url: bool, pad: bool) -> String {
        let alphabet: &[u8; 64] = if url {
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        } else {
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        };
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
            for i in 0..=chunk.len() {
                out.push(alphabet[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
            if pad {
                for _ in chunk.len() + 1..4 {
                    out.push('=');
                }
            }
        }
        out
    }

    fn rfc3339(seconds: i64, nanos: u32) -> String {
        chrono::DateTime::from_timestamp(seconds, nanos)
            .expect("a representable time")
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
    }

    fn json_of(value: &Value2) -> String {
        match value {
            Value2::Boolean(b) => format!(r#"{{"ceBoolean":{b}}}"#),
            Value2::Integer(i) => format!(r#"{{"ceInteger":{i}}}"#),
            Value2::Text(text) => {
                format!(r#"{{"ceString":{}}}"#, serde_json::to_string(text).unwrap())
            }
            Value2::Bytes(bytes) => format!(r#"{{"ceBytes":"{}"}}"#, b64(bytes, false, true)),
            Value2::Uri(text) => format!(r#"{{"ceUri":{}}}"#, serde_json::to_string(text).unwrap()),
            Value2::UriRef(text) => {
                format!(r#"{{"ceUriRef":{}}}"#, serde_json::to_string(text).unwrap())
            }
            Value2::Timestamp(seconds, nanos) => {
                format!(r#"{{"ceTimestamp":"{}"}}"#, rfc3339(*seconds, *nanos))
            }
        }
    }

    #[derive(Debug, Clone)]
    struct Sample {
        id: String,
        source: String,
        spec: String,
        kind: String,
        attributes: Vec<(String, Value2)>,
        data: Option<Result<String, Vec<u8>>>,
    }

    fn sample_json(sample: &Sample) -> String {
        let mut members = vec![format!(r#""@type":"{CLOUD_EVENT_TYPE_URL}""#)];
        for (name, value) in [
            ("id", &sample.id),
            ("source", &sample.source),
            ("specVersion", &sample.spec),
            ("type", &sample.kind),
        ] {
            members.push(format!(
                "{}:{}",
                serde_json::to_string(name).unwrap(),
                serde_json::to_string(value).unwrap()
            ));
        }
        let attributes: Vec<String> = sample
            .attributes
            .iter()
            .map(|(name, value)| {
                format!(
                    "{}:{}",
                    serde_json::to_string(name).unwrap(),
                    json_of(value)
                )
            })
            .collect();
        members.push(format!(r#""attributes":{{{}}}"#, attributes.join(",")));
        match &sample.data {
            Some(Ok(text)) => members.push(format!(
                r#""textData":{}"#,
                serde_json::to_string(text).unwrap()
            )),
            Some(Err(bytes)) => {
                members.push(format!(r#""binaryData":"{}""#, b64(bytes, false, true)));
            }
            None => {}
        }
        format!("{{{}}}", members.join(","))
    }

    fn sample_wire(sample: &Sample) -> Vec<u8> {
        let mut event = Vec::new();
        for (tag, value) in [
            (1, &sample.id),
            (2, &sample.source),
            (3, &sample.spec),
            (4, &sample.kind),
        ] {
            if !value.is_empty() {
                put_bytes(&mut event, tag, value.as_bytes());
            }
        }
        for (name, value) in &sample.attributes {
            let mut entry = Vec::new();
            put_bytes(&mut entry, 1, name.as_bytes());
            put_bytes(&mut entry, 2, &attribute_message(value));
            put_bytes(&mut event, 5, &entry);
        }
        match &sample.data {
            Some(Ok(text)) => put_bytes(&mut event, 7, text.as_bytes()),
            Some(Err(bytes)) => put_bytes(&mut event, 6, bytes),
            None => {}
        }
        event
    }

    fn value2() -> impl Strategy<Value = Value2> {
        prop_oneof![
            any::<bool>().prop_map(Value2::Boolean),
            any::<i32>().prop_map(Value2::Integer),
            ".{0,200}".prop_map(Value2::Text),
            proptest::collection::vec(any::<u8>(), 0..200).prop_map(Value2::Bytes),
            "[ -~]{0,200}".prop_map(Value2::Uri),
            "[ -~]{0,200}".prop_map(Value2::UriRef),
            (-62_135_596_800_i64..253_402_300_799, 0u32..1_000_000_000)
                .prop_map(|(seconds, nanos)| Value2::Timestamp(seconds, nanos)),
        ]
    }

    fn sample() -> impl Strategy<Value = Sample> {
        (
            ".{0,200}",
            ".{0,200}",
            ".{0,200}",
            ".{0,300}",
            proptest::collection::vec(("[a-z][a-z0-9]{0,40}", value2()), 0..6),
            prop_oneof![
                Just(None),
                ".{0,2000}".prop_map(|text| Some(Ok(text))),
                proptest::collection::vec(any::<u8>(), 0..2000).prop_map(|bytes| Some(Err(bytes))),
            ],
        )
            .prop_map(|(id, source, spec, kind, attributes, data)| Sample {
                id,
                source,
                spec,
                kind,
                attributes,
                data,
            })
    }

    proptest! {
        #[test]
        fn a_varint_is_as_long_as_its_encoding(value in any::<u64>()) {
            let mut out = Vec::new();
            put_varint(&mut out, value);
            prop_assert_eq!(varint_len(value), out.len());
        }

        #[test]
        fn the_size_of_a_request_is_the_length_of_its_serialization(
            samples in proptest::collection::vec(sample(), 0..4),
            channel in "projects/[a-z][a-z0-9-]{4,20}/locations/[a-z]{2,6}-[a-z]{4,9}[0-9]/channels/[a-z][a-z0-9-]{0,40}",
        ) {
            let mut wire = Vec::new();
            put_bytes(&mut wire, 1, channel.as_bytes());
            let mut parsed = Vec::new();
            for sample in &samples {
                let mut any = Vec::new();
                put_bytes(&mut any, 1, CLOUD_EVENT_TYPE_URL.as_bytes());
                put_bytes(&mut any, 2, &sample_wire(sample));
                put_bytes(&mut wire, 2, &any);
                let event = parse_event(0, &parse(sample_json(sample).as_bytes()).unwrap());
                prop_assert!(event.is_ok(), "{:?}", sample_json(sample));
                let event = event.unwrap();
                prop_assert_eq!(event.inner_size, sample_wire(sample).len());
                prop_assert_eq!(event.any_size(), any.len());
                parsed.push(event);
            }
            prop_assert_eq!(request_size(&channel, &parsed), wire.len());
        }

        #[test]
        fn base64_of_either_alphabet_with_or_without_padding_has_the_decoded_length(
            bytes in proptest::collection::vec(any::<u8>(), 0..300),
            url in any::<bool>(),
            pad in any::<bool>(),
        ) {
            prop_assert_eq!(base64_len(&b64(&bytes, url, pad)), Some(bytes.len()));
        }

        #[test]
        fn base64_with_a_character_outside_both_alphabets_is_refused(
            bytes in proptest::collection::vec(any::<u8>(), 1..60),
            at in any::<proptest::sample::Index>(),
            bad in prop::sample::select(vec!['*', ' ', '\n', '.', '!', '\u{3042}']),
        ) {
            let mut text: Vec<char> = b64(&bytes, false, true).chars().collect();
            let at = at.index(text.len());
            text[at] = bad;
            prop_assert_eq!(base64_len(&text.into_iter().collect::<String>()), None);
        }

        #[test]
        fn a_timestamp_round_trips_through_its_text(
            seconds in -62_135_596_800_i64..253_402_300_799,
            nanos in 0u32..1_000_000_000,
        ) {
            prop_assert_eq!(timestamp(&rfc3339(seconds, nanos)), Some((seconds, nanos)));
        }
    }

    #[test]
    fn base64_edge_cases() {
        for (text, length) in [
            ("", 0),
            ("eA==", 1),
            ("eA", 1),
            ("eHk=", 2),
            ("eHk", 2),
            ("eHl6", 3),
            ("-_-_", 3),
            ("+/+/", 3),
        ] {
            assert_eq!(base64_len(text), Some(length), "{text:?}");
        }
        for text in [
            "a", "eA===", "eA=", "eHk==", "e=A=", "eA==x", "ab=cd", "=", "====",
        ] {
            assert_eq!(base64_len(text), None, "{text:?}");
        }
    }

    #[test]
    fn timestamps_need_a_zone_and_the_capital_letters() {
        for fine in [
            "2026-10-05T06:17:17Z",
            "2026-10-05T06:17:17.123456789Z",
            "2026-10-05T06:17:17+09:00",
            "1970-01-01T00:00:00Z",
        ] {
            assert!(timestamp(fine).is_some(), "{fine}");
        }
        assert_eq!(timestamp("1970-01-01T00:00:00Z"), Some((0, 0)));
        assert_eq!(timestamp("1970-01-01T09:00:00+09:00"), Some((0, 0)));
        assert_eq!(timestamp("1970-01-01T00:00:01.5Z"), Some((1, 500_000_000)));
        for bad in [
            "",
            "x",
            "2026-10-05",
            "2026-10-05T06:17:17",
            "2026-10-05t06:17:17Z",
            "2026-10-05T06:17:17z",
            "2026-10-05 06:17:17Z",
            "2026-10-05T06:17:17Z\u{3042}",
        ] {
            assert!(timestamp(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn the_pieces_of_a_size() {
        assert_eq!(field_len(0), 2);
        assert_eq!(field_len(127), 129);
        assert_eq!(field_len(128), 131);
        assert_eq!(varint_len(0), 1);
        assert_eq!(varint_len(127), 1);
        assert_eq!(varint_len(128), 2);
        assert_eq!(varint_len(16_383), 2);
        assert_eq!(varint_len(16_384), 3);
        assert_eq!(varint_len(u64::MAX), 10);
        // A negative int32 is ten bytes on the wire.
        assert_eq!(Attribute::Integer(-1).size(), 11);
        assert_eq!(Attribute::Integer(0).size(), 2);
        assert_eq!(Attribute::Integer(128).size(), 3);
        assert_eq!(Attribute::Boolean.size(), 2);
        assert_eq!(
            Attribute::Timestamp {
                seconds: 0,
                nanos: 0
            }
            .size(),
            2
        );
        assert_eq!(
            Attribute::Timestamp {
                seconds: -1,
                nanos: 0
            }
            .size(),
            2 + 1 + 10
        );
    }
}
