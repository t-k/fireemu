//! The strict profile's Eventarc surface: what production answered, as recorded.
//!
//! Sources, all of `fireemu-oracle-idp` on 2026-10-05: the two stage A recordings (no channel was ever
//! created in them: the recorder's create body had no `name`, which production refused with
//! `channel.name is empty`; `tests/fixtures/eventarc-stage-a/rows.json` replays the second one), the stage B
//! recording (the first with channels: creation, reads, lists, deletion, the publication to a channel that
//! exists, the credential variants; 233 rows) and the stage C recording (the second record of those cases,
//! and the answers of a channel while its operation runs, a list of eleven channels, page sizes, the edges of
//! a channel ID, locations, an operation never issued, the exact limits of an event; 424 rows). Both are
//! replayed row by row (`tests/eventarc_strict_stage_b.rs`, `tests/eventarc_strict_stage_c.rs`, through
//! `tests/eventarc_replay`). For each decision this module says whether it is recorded or an inference:
//!
//! - recorded: authentication (a missing credential, an invalid value, a JWT in shape), the consumer check
//!   of a project the caller cannot use, a location that does not exist (create, read and list) and the
//!   locations that exist, the creation of a channel and its operation (the channelId of the path names the
//!   channel, whatever the body's name says), the channel resource in each state it was seen in, the list
//!   and its page token (a page size below zero, zero, above the cap; a token carried to another
//!   location), the conflict of a second creation, the channel IDs Eventarc refused and accepted, the
//!   deletion and its operation, the answers for a channel being created or deleted, for a channel that is
//!   gone and for an operation that was never issued, and every check `PublishEvents` makes (the parse, the
//!   count of 100, the size, the channel lookup, the required attributes, the content type, the data, the
//!   attribute quotas and the order of those checks).
//! - inferred (marked `INFERRED`): the locations beyond the seven probed (the documented regions), the page
//!   size when none is given and the cap above which a page is clamped, the order of a list (production's is
//!   stable but follows no rule the recordings reveal: fireemu lists in the order of creation), the method
//!   names in the missing-credential detail beyond the list, the consumer check for the creation and the
//!   publication, a creation of a channel being deleted, and a deletion that arrives early in a creation.
//! - not served: a creation without a channelId (not recorded: the stage C recorder never sends it), a page
//!   size that is not a number, the deletion of a channel a function declares. These answer
//!   `501 UNIMPLEMENTED` and say so, rather than invent a shape.
//! - not reproduced, because they are Google's state or not deterministic: whether a `ya29.` token is valid,
//!   what its scopes are, the project number (a path that names the project by number), and the seconds
//!   after a creation during which a publication to the channel answers `404 Associated channel does not
//!   exist.` although the channel reads as ACTIVE.
//!
//! A channel "exists" here when the API created it and its operation is done, or when a loaded function
//! declares it: a deployed custom-event function is what makes firebase-tools create its channel in
//! production, and the Functions emulator registers the same channel in its trigger table.

use serde_json::Value;

use crate::eventarc_channels::{
    project_number, ChannelStore, Created, Deleted, Lookup, Nanos, Position,
};
use crate::ordered_json::{parse, Ordered};

/// The largest number of events a publication may carry. Recorded (stage B): 100 events pass, 101 are
/// refused with `OUT_OF_RANGE` "Too many events." (stage A had only 8 passing and 256 refused).
pub const MAX_EVENTS: usize = 100;
/// The most attributes a request may carry once the four required ones are counted (the recording: 106
/// refused, with "the maximum allowed is 100"; the Pub/Sub quota).
pub const MAX_ATTRIBUTES: usize = 100;
/// The longest key of an attribute, `ce-` and the name included (259 bytes refused, "the maximum allowed
/// is 256").
pub const MAX_ATTRIBUTE_KEY_BYTES: usize = 256;
/// The limit production names for one event.
pub const MAX_EVENT_BYTES: usize = 524_288;
/// The type URL production accepts for an event.
pub const CLOUD_EVENT_TYPE_URL: &str = "type.googleapis.com/io.cloudevents.v1.CloudEvent";
/// The longest value echoed back into a message.
const MAX_ECHO: usize = 1024;

const EVENTARC_SERVICE: &str = "eventarc.googleapis.com";
const PUBLISHING_SERVICE: &str = "eventarcpublishing.googleapis.com";

/// A JSON answer. The body keeps production's member order and is written the way production writes it
/// (see `Answer::text`): the order and the layout were recorded and are part of what is reproduced.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    /// The HTTP status.
    pub status: u16,
    /// The JSON body.
    pub body: Ordered,
}

impl Answer {
    /// The body as production writes it: pretty-printed with two-space indentation and a final newline
    /// (the 373-byte 404 of `channels/firebase` and the 3-byte `{}` + newline of an empty list of
    /// preflight 002 are reproduced exactly).
    #[must_use]
    pub fn text(&self) -> String {
        format!("{}\n", self.body.to_pretty())
    }
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
    /// `DELETE .../channels/{channel}`
    DeleteChannel {
        /// Project and location.
        place: Place,
        /// The channel ID.
        channel: String,
    },
    /// `GET .../operations/{operation}`
    GetOperation {
        /// Project and location.
        place: Place,
        /// The operation ID.
        operation: String,
    },
}

impl Route {
    const fn place(&self) -> &Place {
        match self {
            Self::Publish { place, .. }
            | Self::GetChannel { place, .. }
            | Self::DeleteChannel { place, .. }
            | Self::GetOperation { place, .. }
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
            Self::DeleteChannel { .. } => "google.cloud.eventarc.v1.Eventarc.DeleteChannel",
            Self::GetOperation { .. } => "google.longrunning.Operations.GetOperation",
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
    let (location, rest) = rest.split_once('/')?;
    if project.is_empty() || project.contains('/') || location.is_empty() || location.contains('/')
    {
        return None;
    }
    let place = Place {
        project: project.to_owned(),
        location: location.to_owned(),
    };
    if let Some(operation) = rest.strip_prefix("operations/") {
        return (method == "GET" && !operation.is_empty() && !operation.contains(['/', ':'])).then(
            || Route::GetOperation {
                place,
                operation: operation.to_owned(),
            },
        );
    }
    let rest = rest.strip_prefix("channels")?;
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
                ("DELETE", None) if !channel.contains([':', '/']) => Some(Route::DeleteChannel {
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
    /// The token of the `Authorization: Bearer` header, if there was one.
    pub bearer: Option<&'a str>,
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
    /// The channels a loaded function declares in the project and location (`-` is every location), by
    /// full resource name.
    pub declared_in: &'a dyn Fn(&str, &str) -> Vec<String>,
    /// The channels created through the API, and their operations.
    pub channels: &'a ChannelStore,
    /// The instant of the request.
    pub now: Nanos,
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

fn answer(status: u16, body: Ordered) -> Outcome {
    Outcome::Answer(Answer { status, body })
}

fn text(value: &str) -> Ordered {
    Ordered::text(value)
}

fn error(status: u16, canonical: &str, message: &str, details: Vec<Ordered>) -> Outcome {
    let mut members = vec![
        ("code", Ordered::unsigned(u64::from(status))),
        ("message", text(message)),
        ("status", text(canonical)),
    ];
    if !details.is_empty() {
        members.push(("details", Ordered::Array(details)));
    }
    answer(
        status,
        Ordered::object([(
            "error",
            Ordered::Object(
                members
                    .into_iter()
                    .map(|(name, value)| (name.to_owned(), value))
                    .collect(),
            ),
        )]),
    )
}

fn bad_request_detail(violations: &[(Option<&str>, Option<&str>)]) -> Ordered {
    Ordered::object([
        ("@type", text("type.googleapis.com/google.rpc.BadRequest")),
        (
            "fieldViolations",
            Ordered::Array(
                violations
                    .iter()
                    .map(|(field, description)| {
                        let mut members = Vec::new();
                        if let Some(field) = field {
                            members.push(("field".to_owned(), text(field)));
                        }
                        if let Some(description) = description {
                            members.push(("description".to_owned(), text(description)));
                        }
                        Ordered::Object(members)
                    })
                    .collect(),
            ),
        ),
    ])
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

/// The credential of a request.
///
/// An OAuth access token that Google issues starts with `ya29.`. Production refused, with "invalid
/// authentication credentials", a bearer value that was neither (the recorded `invalid-token-for-the-
/// recording`, stage A) and also a JWT-shaped one, garbage and expired alike (stage B rows 174 to 177:
/// the answer has no `details`, unlike the one for a value of no known shape). It also refused a
/// `ya29.`-prefixed garbage token (row 172, `ACCESS_TOKEN_TYPE_UNSUPPORTED`) and a real token of
/// another scope (row 179, `ACCESS_TOKEN_SCOPE_INSUFFICIENT`): whether a well-formed token is valid, and
/// what it may do, is Google's state, which a local listener does not have, so a `ya29.` token is
/// accepted here and those two answers are not reproduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    /// No `Authorization: Bearer` header, or an empty token.
    Missing,
    /// A bearer value that is neither an access token nor a JWT in shape.
    Malformed,
    /// A JWT in shape (three base64url parts): refused by production, as garbage or as expired.
    Jwt,
    /// A bearer value in the shape of an access token.
    WellFormed,
}

/// Classifies the token of an `Authorization: Bearer` header.
#[must_use]
pub fn classify_token(token: Option<&str>) -> Credential {
    let Some(token) = token.filter(|token| !token.trim().is_empty()) else {
        return Credential::Missing;
    };
    let access_token = token
        .strip_prefix("ya29.")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_graphic()));
    if access_token {
        return Credential::WellFormed;
    }
    let base64url = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'=')
    };
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() == 3 && parts.iter().all(|part| base64url(part)) {
        Credential::Jwt
    } else {
        Credential::Malformed
    }
}

fn credential_refusal(route: &Route, credential: Credential) -> Outcome {
    if credential == Credential::Jwt {
        // Recorded (stage B): no details at all.
        return error(
            401,
            "UNAUTHENTICATED",
            "Request had invalid authentication credentials. Expected OAuth 2 access token, login cookie or other valid authentication credential. See https://developers.google.com/identity/sign-in/web/devconsole-project.",
            Vec::new(),
        );
    }
    // Recorded: the missing credential names the service first; the invalid one has no `domain`.
    let (message, info) = if credential == Credential::Missing {
        (
            "Request is missing required authentication credential. Expected OAuth 2 access token, login cookie or other valid authentication credential. See https://developers.google.com/identity/sign-in/web/devconsole-project.",
            Ordered::object([
                ("@type", text("type.googleapis.com/google.rpc.ErrorInfo")),
                ("reason", text("CREDENTIALS_MISSING")),
                ("domain", text("googleapis.com")),
                (
                    "metadata",
                    Ordered::object([
                        ("service", text(route.service())),
                        ("method", text(route.method())),
                    ]),
                ),
            ]),
        )
    } else {
        (
            "Request had invalid authentication credentials. Expected OAuth 2 access token, login cookie or other valid authentication credential. See https://developers.google.com/identity/sign-in/web/devconsole-project.",
            Ordered::object([
                ("@type", text("type.googleapis.com/google.rpc.ErrorInfo")),
                ("reason", text("CREDENTIALS_MISSING")),
                (
                    "metadata",
                    Ordered::object([
                        ("method", text(route.method())),
                        ("service", text(route.service())),
                    ]),
                ),
            ]),
        )
    };
    error(401, "UNAUTHENTICATED", message, vec![info])
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
            Ordered::object([
                ("@type", text("type.googleapis.com/google.rpc.ErrorInfo")),
                ("reason", text("CONSUMER_INVALID")),
                ("domain", text("googleapis.com")),
                (
                    "metadata",
                    Ordered::object([
                        ("containerInfo", text(project)),
                        ("consumer", text(&format!("projects/{project}"))),
                        ("service", text(route.service())),
                    ]),
                ),
            ]),
            localized_message(&message),
            Ordered::object([
                ("@type", text("type.googleapis.com/google.rpc.Help")),
                (
                    "links",
                    Ordered::Array(vec![Ordered::object([
                        ("description", text("Google developers console")),
                        ("url", text("https://console.developers.google.com")),
                    ])]),
                ),
            ]),
        ],
    )
}

fn localized_message(message: &str) -> Ordered {
    Ordered::object([
        (
            "@type",
            text("type.googleapis.com/google.rpc.LocalizedMessage"),
        ),
        ("locale", text("en-US")),
        ("message", text(message)),
    ])
}

/// The locations Eventarc serves. Recorded: `us-central1` and `europe-west1` exist, `us-east99` and
/// `no-such-location1` do not (the shape of a region ID is not enough: `us-east99` is refused). The rest
/// of the list is INFERRED from the regions Google Cloud documents for Eventarc and has not been probed.
const LOCATIONS: &[&str] = &[
    "africa-south1",
    "asia-east1",
    "asia-east2",
    "asia-northeast1",
    "asia-northeast2",
    "asia-northeast3",
    "asia-south1",
    "asia-south2",
    "asia-southeast1",
    "asia-southeast2",
    "australia-southeast1",
    "australia-southeast2",
    "europe-central2",
    "europe-north1",
    "europe-southwest1",
    "europe-west1",
    "europe-west10",
    "europe-west12",
    "europe-west2",
    "europe-west3",
    "europe-west4",
    "europe-west6",
    "europe-west8",
    "europe-west9",
    "global",
    "me-central1",
    "me-central2",
    "me-west1",
    "northamerica-northeast1",
    "northamerica-northeast2",
    "southamerica-east1",
    "southamerica-west1",
    "us-central1",
    "us-east1",
    "us-east4",
    "us-east5",
    "us-south1",
    "us-west1",
    "us-west2",
    "us-west3",
    "us-west4",
];

/// Whether a location exists.
fn plausible_location(location: &str) -> bool {
    LOCATIONS.contains(&location)
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
                    Ordered::object([
                        ("@type", text("type.googleapis.com/google.rpc.ErrorInfo")),
                        ("reason", text("LOCATION_POLICY_VIOLATED")),
                        ("domain", text("googleapis.com")),
                        (
                            "metadata",
                            Ordered::object([
                                ("location", text(location)),
                                ("consumer", text(&format!("projects/{project}"))),
                                ("service", text(EVENTARC_SERVICE)),
                            ]),
                        ),
                    ]),
                    localized_message(&message),
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

/// The full resource name of a channel.
fn channel_name(place: &Place, channel: &str) -> String {
    format!(
        "projects/{}/locations/{}/channels/{channel}",
        place.project, place.location
    )
}

/// `404` for a resource that does not exist (recorded for a channel: `GetChannel` and `DeleteChannel`).
fn resource_not_found(name: &str) -> Outcome {
    error(
        404,
        "NOT_FOUND",
        &format!("Resource '{name}' was not found"),
        vec![Ordered::object([
            ("@type", text("type.googleapis.com/google.rpc.ResourceInfo")),
            ("resourceName", text(name)),
        ])],
    )
}

/// A channel a loaded function declares exists from the first request that names it.
fn adopt(world: &World<'_>, name: &str) {
    if (world.declared_channel)(name) {
        world.channels.declare(name, world.now);
    }
}

/// Answers one request.
#[must_use]
pub fn evaluate(input: &Input<'_>, world: &World<'_>) -> Outcome {
    let route = input.route;
    let credential = classify_token(input.bearer);
    if credential != Credential::WellFormed {
        return credential_refusal(route, credential);
    }
    if route.project() != world.project {
        return consumer_invalid(route);
    }
    match route {
        Route::Publish { place, channel } => publish(place, channel, input.body, world),
        Route::GetChannel { place, channel } => {
            if !plausible_location(&place.location) {
                return location_not_found(route);
            }
            let name = channel_name(place, channel);
            adopt(world, &name);
            match world.channels.lookup(&name, world.now) {
                Lookup::Absent => resource_not_found(&name),
                // A channel being created or deleted reads too (stage C): see `eventarc_channels`.
                Lookup::Ready(view) | Lookup::Creating(view) | Lookup::Deleting(view) => {
                    answer(200, view.to_json(false))
                }
            }
        }
        Route::ListChannels(place) => list_channels(route, place, input.query, world),
        Route::CreateChannel(place) => create_channel(route, place, input, world),
        Route::DeleteChannel { place, channel } => {
            if !plausible_location(&place.location) {
                return location_not_found(route);
            }
            let name = channel_name(place, channel);
            if (world.declared_channel)(&name) {
                return unobserved("the deletion of a channel that a loaded function declares");
            }
            match world.channels.delete(&name, world.now) {
                Deleted::Absent => resource_not_found(&name),
                Deleted::Started(started) => {
                    answer(200, world.channels.started(&started, world.now))
                }
            }
        }
        Route::GetOperation { place, operation } => {
            if !plausible_location(&place.location) {
                return location_not_found(route);
            }
            let name = format!(
                "projects/{}/locations/{}/operations/{operation}",
                place.project, place.location
            );
            // An operation that was never issued is `404` (stage C: `operation-0-0-0-0` and `x`, in two locations).
            world
                .channels
                .operation(&name, world.now)
                .map_or_else(|| resource_not_found(&name), |body| answer(200, body))
        }
    }
}

/// The value of a query parameter (not percent-decoded: the values this surface reads are IDs and tokens
/// whose alphabet needs no escaping).
fn query_value<'a>(query: Option<&'a str>, name: &str) -> Option<&'a str> {
    query?
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

/// The page size when none is asked for. INFERRED: the recordings never exceeded one page of ten.
const DEFAULT_PAGE_SIZE: usize = 100;
/// The largest page. INFERRED.
const MAX_PAGE_SIZE: usize = 1000;

fn invalid_page_token() -> Outcome {
    error(
        400,
        "INVALID_ARGUMENT",
        "The request was invalid: invalid page token",
        vec![bad_request_detail(&[(
            Some("pageToken"),
            Some("invalid page token"),
        )])],
    )
}

fn invalid_pagination_token() -> Outcome {
    error(
        400,
        "INVALID_ARGUMENT",
        "The request was invalid: invalid pagination token",
        vec![bad_request_detail(&[(
            Some("pageToken"),
            Some("invalid pagination token"),
        )])],
    )
}

/// `500 INTERNAL`, as production answered a page token carried to another location (stage C, row 124): the
/// message names an identifier of the failure, here the request's.
fn internal_error(world: &World<'_>) -> Outcome {
    let id = world.request_id;
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        id.get(0..8).unwrap_or("00000000"),
        id.get(8..12).unwrap_or("0000"),
        id.get(12..16).unwrap_or("0000"),
        id.get(0..4).unwrap_or("0000"),
        id.get(4..16).unwrap_or("000000000000"),
    );
    error(
        500,
        "INTERNAL",
        &format!("An internal error has occurred ({uuid})"),
        Vec::new(),
    )
}

fn list_channels(route: &Route, place: &Place, query: Option<&str>, world: &World<'_>) -> Outcome {
    let Place { project, location } = place;
    if location != "-" && !plausible_location(location) {
        return location_not_found(route);
    }
    let after = match query_value(query, "pageToken").filter(|token| !token.is_empty()) {
        None => None,
        Some(token) => match Position::parse(token) {
            Some(position) if position.project_number == project_number(project) => {
                if position.location != *location {
                    // A token carried to another location (stage C, one observation each): a concrete location
                    // answers `500 INTERNAL`, the aggregated one `400 invalid pagination token`.
                    return if location == "-" {
                        invalid_pagination_token()
                    } else {
                        internal_error(world)
                    };
                }
                Some(position)
            }
            _ => return invalid_page_token(),
        },
    };
    let limit = match query_value(query, "pageSize").filter(|size| !size.is_empty()) {
        None => DEFAULT_PAGE_SIZE,
        Some(size) => match size.parse::<i64>() {
            // `0` is the default (stage C, row 119).
            Ok(0) => DEFAULT_PAGE_SIZE,
            Ok(size) if size > 0 => {
                usize::try_from(size).map_or(MAX_PAGE_SIZE, |size| size.min(MAX_PAGE_SIZE))
            }
            // Recorded for `-1` (stage C, row 120).
            Ok(_) => {
                return error(
                    400,
                    "INVALID_ARGUMENT",
                    "Invalid argument: 'page_size'",
                    Vec::new(),
                )
            }
            Err(_) => return unobserved("a page size that is not a number"),
        },
    };
    for name in (world.declared_in)(project, location) {
        world.channels.declare(&name, world.now);
    }
    let listing = world
        .channels
        .list(project, location, after.as_ref(), limit, world.now);
    if listing.unknown_position {
        return invalid_page_token();
    }
    let Some(last) = listing.items.last() else {
        return answer(200, Ordered::Object(Vec::new()));
    };
    let mut members = vec![(
        "channels".to_owned(),
        Ordered::Array(
            listing
                .items
                .iter()
                .map(|view| view.to_json(false))
                .collect(),
        ),
    )];
    if listing.more {
        let position = Position {
            location: location.clone(),
            project_number: project_number(project),
            id: last.name.rsplit('/').next().unwrap_or_default().to_owned(),
            uid: last.uid.clone(),
        };
        members.push(("nextPageToken".to_owned(), Ordered::text(position.token())));
    }
    answer(200, Ordered::Object(members))
}

/// Whether a channel ID is valid. Recorded: `a4`, `goog-...` and the run-prefixed IDs (63 characters
/// included) are accepted; an upper-case letter, a leading digit, an underscore, 64 characters, one
/// character, a leading hyphen and a final hyphen are refused. The rule is the DNS label's: a lower-case
/// letter first, then lower-case letters, digits and hyphens, no final hyphen, 2 to 63 characters.
fn valid_channel_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    // Recorded (stage C): one character, a leading hyphen and a final hyphen are refused; 63 characters pass.
    (2..=63).contains(&bytes.len())
        && first.is_ascii_lowercase()
        && *last != b'-'
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn create_channel(route: &Route, place: &Place, input: &Input<'_>, world: &World<'_>) -> Outcome {
    if !plausible_location(&place.location) {
        return location_not_found(route);
    }
    let body_name = match parse(input.body) {
        Ok(Ordered::Object(members)) => members.iter().find_map(|(name, value)| match value {
            Ordered::String(text) if name == "name" && !text.is_empty() => Some(text.clone()),
            _ => None,
        }),
        Ok(_) | Err(_) => {
            return invalid_argument("Invalid JSON payload received.", None);
        }
    };
    let Some(body_name) = body_name else {
        return error(
            400,
            "INVALID_ARGUMENT",
            "The request was invalid: channel.name is empty",
            vec![
                bad_request_detail(&[(Some("channel.name"), None)]),
                request_info(world.request_id),
            ],
        );
    };
    let Some(id) = query_value(input.query, "channelId").filter(|id| !id.is_empty()) else {
        return unobserved("a creation without a channelId");
    };
    // The channelId of the path names the channel; the name of the body is not used when it names another
    // channel (stage C: a body naming `...-mm-b` under `channelId=...-mm-a` created `...-mm-a`).
    let name = channel_name(place, id);
    let _ = body_name;
    if !valid_channel_id(id) {
        // Recorded: the violation and the request info are written twice.
        let violation = bad_request_detail(&[(Some("channel.name"), None)]);
        return error(
            400,
            "INVALID_ARGUMENT",
            &format!("The request was invalid: invalid resource id: {}", echo(id)),
            vec![
                violation.clone(),
                request_info(world.request_id),
                violation,
                request_info(world.request_id),
            ],
        );
    }
    adopt(world, &name);
    match world.channels.create(&name, world.now) {
        Created::Exists => error(
            409,
            "ALREADY_EXISTS",
            &format!("Resource '{name}' already exists"),
            vec![Ordered::object([
                ("@type", text("type.googleapis.com/google.rpc.ResourceInfo")),
                ("resourceName", text(&name)),
            ])],
        ),
        Created::Started(started) => answer(200, world.channels.started(&started, world.now)),
    }
}

fn request_info(request_id: &str) -> Ordered {
    Ordered::object([
        ("@type", text("type.googleapis.com/google.rpc.RequestInfo")),
        ("requestId", text(request_id)),
    ])
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
    /// A `ceUri` or a `ceUriRef`: only its length matters.
    Text(usize),
    /// A `ceString` with its value (the content type is one).
    String(String),
    Bytes(usize),
    Timestamp {
        seconds: i64,
        nanos: u32,
        /// Only the observed canonical whole-second spelling has a known mapped representation.
        mapped_text: Option<String>,
    },
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
            Self::String(value) => field_len(value.len()),
            Self::Timestamp { seconds, nanos, .. } => {
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
    fields: Fields,
}

/// What the semantic checks of an existing channel read from an event.
#[derive(Debug, Clone, PartialEq, Default)]
struct Fields {
    id: String,
    source: String,
    spec_version: String,
    event_type: String,
    attributes: Vec<(String, Attribute)>,
    data: Data,
}

#[derive(Debug, Clone, PartialEq, Default)]
enum Data {
    #[default]
    None,
    Text(String),
    Binary,
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

/// The mapped Pub/Sub request size for a ready channel, separate from CloudEvent/Any size.
///
/// String values, canonical whole-second timestamps and integer zero cover the observed representation
/// families. Other types, spellings, empty strings or colliding map keys remain unknown. This helper
/// does not change publish admission: the upper-payload metric and refusal precedence are unresolved.
#[must_use]
pub fn mapped_publish_request_size(channel: &Lookup, events: &[ParsedEvent]) -> Option<usize> {
    let Lookup::Ready(view) = channel else {
        return None;
    };
    if view.pubsub_topic.is_empty() {
        return None;
    }
    let mut request = field_len(view.pubsub_topic.len());
    for event in events {
        let fields = &event.fields;
        let Data::Text(data) = &fields.data else {
            return None;
        };
        if data.is_empty() {
            return None;
        }
        let mut message = field_len(data.len());
        for (key, value) in [
            ("ce-id", &fields.id),
            ("ce-source", &fields.source),
            ("ce-specversion", &fields.spec_version),
            ("ce-type", &fields.event_type),
        ] {
            if value.is_empty() {
                return None;
            }
            message += field_len(field_len(key.len()) + field_len(value.len()));
        }
        for (index, (key, value)) in fields.attributes.iter().enumerate() {
            if matches!(key.as_str(), "id" | "source" | "specversion" | "type")
                || fields.attributes[..index]
                    .iter()
                    .any(|(previous, _)| previous == key)
            {
                return None;
            }
            let text = match value {
                Attribute::String(text) if !text.is_empty() => text.as_str(),
                Attribute::Timestamp {
                    mapped_text: Some(text),
                    ..
                } => text.as_str(),
                Attribute::Integer(0) => "0",
                _ => return None,
            };
            message += field_len(field_len("ce-".len() + key.len()) + field_len(text.len()));
        }
        request += field_len(message);
    }
    Some(request)
}

fn publish(place: &Place, channel: &str, body: &[u8], world: &World<'_>) -> Outcome {
    let name = channel_name(place, channel);
    let mut events = match parse_publish(body) {
        Ok(events) => events,
        Err(refusal) => return refusal,
    };
    // An event with nothing in it is not an event: a request that holds only such events is empty.
    // INFERRED from one recorded case (a request of one bare event answered "No events provided.").
    events.retain(|event| event.inner_size != 0);
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
    adopt(world, &name);
    match world.channels.lookup(&name, world.now) {
        // A channel being created or deleted is not publishable yet or any more (stage C, rows 131 and 145).
        Lookup::Absent | Lookup::Creating(_) | Lookup::Deleting(_) => {
            return error(
                404,
                "NOT_FOUND",
                "Associated channel does not exist.",
                Vec::new(),
            );
        }
        Lookup::Ready(_) => {}
    }
    if let Some(refusal) = validate_events(&events) {
        return refusal;
    }
    if (world.declared_channel)(&name) {
        return Outcome::Deliver {
            channel: name,
            events: events.into_iter().map(|event| event.json).collect(),
        };
    }
    // A channel created through the API has no trigger: the publication is accepted and goes nowhere.
    answer(200, Ordered::Object(Vec::new()))
}

/// What production checks of the events once the channel is known to exist (stage B, rows 85 to 119 and
/// 148 to 150). The order between the checks is INFERRED: each was recorded alone.
fn validate_events(events: &[ParsedEvent]) -> Option<Outcome> {
    for (index, event) in events.iter().enumerate() {
        if let Some(refusal) = validate_event(index, &event.fields) {
            return Some(refusal);
        }
    }
    let mut seen: Vec<(&str, &str)> = Vec::with_capacity(events.len());
    for (index, event) in events.iter().enumerate() {
        let key = (event.fields.source.as_str(), event.fields.id.as_str());
        if seen.contains(&key) {
            let message = "The source + id pair needs to be unique in a batch call";
            return Some(error(
                400,
                "INVALID_ARGUMENT",
                message,
                vec![bad_request_detail(&[(
                    Some(&format!("events[{index}]")),
                    Some(message),
                )])],
            ));
        }
        seen.push(key);
    }
    None
}

fn validate_event(index: usize, fields: &Fields) -> Option<Outcome> {
    let at = format!("events[{index}]");
    for (name, value) in [
        ("id", &fields.id),
        ("source", &fields.source),
        ("spec_version", &fields.spec_version),
        ("type", &fields.event_type),
    ] {
        if value.is_empty() {
            let message = format!("Attribute '{name}' cannot be empty.");
            return Some(error(
                400,
                "INVALID_ARGUMENT",
                &message,
                vec![bad_request_detail(&[(Some(&at), Some(&message))])],
            ));
        }
    }
    // The four required attributes count with the extension ones against the quota of the transport.
    let attributes = fields.attributes.len() + 4;
    if attributes > MAX_ATTRIBUTES {
        return Some(error(
            400,
            "INVALID_ARGUMENT",
            &format!(
                "There are too many attributes in the request. The request contains {attributes} attributes, but the maximum allowed is {MAX_ATTRIBUTES}. Refer to https://cloud.google.com/pubsub/quotas for more information."
            ),
            Vec::new(),
        ));
    }
    for (name, _) in &fields.attributes {
        let key = 3 + name.len();
        if key > MAX_ATTRIBUTE_KEY_BYTES {
            return Some(error(
                400,
                "INVALID_ARGUMENT",
                &format!(
                    "The attribute \"ce-{name}\" in the request has a key that is too large. The size is {key} bytes, but the maximum allowed is {MAX_ATTRIBUTE_KEY_BYTES}. Refer to https://cloud.google.com/pubsub/quotas for more information."
                ),
                Vec::new(),
            ));
        }
    }
    let attribute = |wanted: &str| {
        fields
            .attributes
            .iter()
            .find(|(name, _)| name == wanted)
            .map(|(_, value)| value)
    };
    if matches!(attribute("time"), Some(value) if !matches!(value, Attribute::Timestamp { .. })) {
        let message = "The type for the attribute 'time' is not valid.";
        return Some(error(
            400,
            "INVALID_ARGUMENT",
            message,
            vec![bad_request_detail(&[(Some(&at), Some(message))])],
        ));
    }
    let Some(content_type) = attribute("datacontenttype") else {
        let message =
            "The attribute 'datacontenttype' has not been defined in the CloudEvent attributes.";
        return Some(error(
            404,
            "NOT_FOUND",
            message,
            vec![bad_request_detail(&[(Some(&at), Some(message))])],
        ));
    };
    // Both checks of the data are reported together when both fail (recorded for a text/plain text).
    let mut violations: Vec<(String, &str)> = Vec::new();
    if !matches!(content_type, Attribute::String(value) if value == "application/json") {
        violations.push((
            format!("{at}.datacontenttype"),
            "CloudEvent attribute `datacontenttype' must have mime-type `application/json'.",
        ));
    }
    match &fields.data {
        Data::Text(text) if serde_json::from_str::<Value>(text).is_ok() => {}
        Data::Text(_) => violations.push((
            at.clone(),
            "Provided CloudEvent data is not a valid json object.",
        )),
        Data::Binary | Data::None => violations.push((
            at.clone(),
            "The provided data needs to be in text format. Please set `text_data` in the CloudEvent.",
        )),
    }
    let first = violations.first()?.1;
    let listed: Vec<(Option<&str>, Option<&str>)> = violations
        .iter()
        .map(|(field, message)| (Some(field.as_str()), Some(*message)))
        .collect();
    Some(error(
        400,
        "INVALID_ARGUMENT",
        first,
        vec![bad_request_detail(&listed)],
    ))
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
    let mut fields = Fields::default();
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
                match snake(name) {
                    "id" => fields.id.clone_from(text),
                    "source" => fields.source.clone_from(text),
                    "spec_version" => fields.spec_version.clone_from(text),
                    _ => fields.event_type.clone_from(text),
                }
            }
            "attributes" => {
                let (size, attributes) = parse_attributes(value)?;
                inner += size;
                fields.attributes = attributes;
            }
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
                        fields.data = Data::Binary;
                    }
                    "text_data" => {
                        let Ordered::String(text) = value else {
                            return Err(wrong_type("text_data", "TYPE_STRING", value));
                        };
                        inner += field_len(text.len());
                        fields.data = Data::Text(text.clone());
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
        fields,
    })
}

/// The map of attributes of one event; returns the serialized size of its entries and the entries.
fn parse_attributes(value: &Ordered) -> Result<(usize, Vec<(String, Attribute)>), Outcome> {
    let Ordered::Object(entries) = value else {
        return Err(invalid_argument(
            "Invalid JSON payload received.",
            Some("attributes"),
        ));
    };
    let mut size = 0;
    let mut parsed_entries = Vec::with_capacity(entries.len());
    for (index, (key, attribute)) in entries.iter().enumerate() {
        let path = format!("attributes[{index}].value");
        let parsed = parse_attribute(&path, attribute)?;
        let entry = field_len(key.len()) + field_len(parsed.size());
        size += field_len(entry);
        parsed_entries.push((key.clone(), parsed));
    }
    Ok((size, parsed_entries))
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
            ("ce_string", Ordered::String(text)) => Attribute::String(text.clone()),
            ("ce_uri" | "ce_uri_ref", Ordered::String(text)) => Attribute::Text(text.len()),
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
                Some((seconds, nanos)) => Attribute::Timestamp {
                    seconds,
                    nanos,
                    mapped_text: (nanos == 0 && text.len() == 20 && text.ends_with('Z'))
                        .then(|| text.clone()),
                },
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
        declared_in: &'a dyn Fn(&str, &str) -> Vec<String>,
        channels: &'a ChannelStore,
    ) -> World<'a> {
        World {
            project: PROJECT,
            request_id: "0123456789abcdef",
            declared_channel: declared,
            declared_in,
            channels,
            now: 1_791_000_000_000_000_000,
        }
    }

    fn run(method: &str, target: &str, authorized: bool, body: &str, declared: &[&str]) -> Outcome {
        let (path, query) = target
            .split_once('?')
            .map_or((target, None), |(path, query)| (path, Some(query)));
        let route = route(method, path).expect("a route");
        let declared: Vec<String> = declared.iter().map(|name| (*name).to_owned()).collect();
        let declared_channel = |name: &str| declared.iter().any(|d| d == name);
        let declared_in = |project: &str, location: &str| -> Vec<String> {
            declared
                .iter()
                .filter(|d| {
                    d.starts_with(&format!("projects/{project}/locations/"))
                        && (location == "-" || d.contains(&format!("/locations/{location}/")))
                })
                .cloned()
                .collect()
        };
        let channels = ChannelStore::default();
        evaluate(
            &Input {
                route: &route,
                query,
                bearer: authorized.then_some("ya29.a-token"),
                body: body.as_bytes(),
            },
            &world(&declared_channel, &declared_in, &channels),
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

    /// An event that an existing channel accepts: the content type is JSON and the data is a JSON text.
    fn delivered_event(id: &str) -> String {
        format!(
            r#"{{"@type":"{CLOUD_EVENT_TYPE_URL}","id":"{id}","source":"s","specVersion":"1.0","type":"t","attributes":{{"time":{{"ceTimestamp":"2026-10-05T06:17:17.731Z"}},"datacontenttype":{{"ceString":"application/json"}}}},"textData":"{{}}"}}"#
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
        assert_eq!(
            route("DELETE", "/v1/projects/p/locations/l/channels/c"),
            Some(Route::DeleteChannel {
                place: place("p", "l"),
                channel: "c".to_owned()
            })
        );
        assert_eq!(
            route(
                "GET",
                "/v1/projects/p/locations/l/operations/operation-1-2-3-4"
            ),
            Some(Route::GetOperation {
                place: place("p", "l"),
                operation: "operation-1-2-3-4".to_owned()
            })
        );
        for (method, path) in [
            ("PATCH", "/v1/projects/p/locations/l/channels/c"),
            ("DELETE", "/v1/projects/p/locations/l/channels"),
            ("DELETE", "/v1/projects/p/locations/l/channels/a/b"),
            ("POST", "/v1/projects/p/locations/l/operations/o"),
            ("GET", "/v1/projects/p/locations/l/operations/"),
            ("GET", "/v1/projects/p/locations/l/operations/a/b"),
            ("GET", "/v1/projects/p/locations/l/operations/a:b"),
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
    fn a_location_exists_when_eventarc_serves_it() {
        for fine in [
            "us-central1",
            "europe-west1",
            "europe-west12",
            "northamerica-northeast2",
            "global",
            "me-central2",
        ] {
            assert!(plausible_location(fine), "{fine}");
        }
        for odd in [
            // The shape of a region ID is not enough: production refused `us-east99` (stage B).
            "us-east99",
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
    fn a_token_is_missing_malformed_or_well_formed_by_its_shape() {
        for missing in [None, Some(""), Some("   ")] {
            assert_eq!(classify_token(missing), Credential::Missing, "{missing:?}");
        }
        for fine in ["ya29.A", "ya29.a0AfH6SMBx_y-z", "ya29.c.b0Aaek~x/y+z="] {
            assert_eq!(classify_token(Some(fine)), Credential::WellFormed, "{fine}");
        }
        // A JWT in shape was refused in the stage B recording, as garbage and as expired.
        for jwt in ["a.b.c", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln-_="] {
            assert_eq!(classify_token(Some(jwt)), Credential::Jwt, "{jwt}");
        }
        for malformed in [
            "invalid-token-for-the-recording",
            "owner",
            "ya29",
            "ya29x",
            "ya29.",
            "Ya29.A",
            "ya29.a b",
            "ya29.a\u{e9}",
            "a.b",
            "a.b.c.d",
            "a..c",
            ".b.c",
            "a.b.",
            "..",
            "a.b.c d",
            "a.b.c!",
        ] {
            assert_eq!(
                classify_token(Some(malformed)),
                Credential::Malformed,
                "{malformed}"
            );
        }
    }

    #[test]
    fn the_two_refusals_of_a_credential_are_the_recorded_ones() {
        let route = route("GET", "/v1/projects/demo/locations/l1/channels").unwrap();
        let wanted = |outcome: Outcome| match outcome {
            Outcome::Answer(answer) => answer,
            Outcome::Deliver { .. } => panic!("an answer"),
        };
        let missing = wanted(credential_refusal(&route, Credential::Missing));
        let malformed = wanted(credential_refusal(&route, Credential::Malformed));
        assert_eq!((missing.status, malformed.status), (401, 401));
        assert_eq!(
            missing.text(),
            "{\n  \"error\": {\n    \"code\": 401,\n    \"message\": \"Request is missing required authentication credential. Expected OAuth 2 access token, login cookie or other valid authentication credential. See https://developers.google.com/identity/sign-in/web/devconsole-project.\",\n    \"status\": \"UNAUTHENTICATED\",\n    \"details\": [\n      {\n        \"@type\": \"type.googleapis.com/google.rpc.ErrorInfo\",\n        \"reason\": \"CREDENTIALS_MISSING\",\n        \"domain\": \"googleapis.com\",\n        \"metadata\": {\n          \"service\": \"eventarc.googleapis.com\",\n          \"method\": \"google.cloud.eventarc.v1.Eventarc.ListChannels\"\n        }\n      }\n    ]\n  }\n}\n"
        );
        assert_eq!(
            malformed.text(),
            "{\n  \"error\": {\n    \"code\": 401,\n    \"message\": \"Request had invalid authentication credentials. Expected OAuth 2 access token, login cookie or other valid authentication credential. See https://developers.google.com/identity/sign-in/web/devconsole-project.\",\n    \"status\": \"UNAUTHENTICATED\",\n    \"details\": [\n      {\n        \"@type\": \"type.googleapis.com/google.rpc.ErrorInfo\",\n        \"reason\": \"CREDENTIALS_MISSING\",\n        \"metadata\": {\n          \"method\": \"google.cloud.eventarc.v1.Eventarc.ListChannels\",\n          \"service\": \"eventarc.googleapis.com\"\n        }\n      }\n    ]\n  }\n}\n"
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
        // A channel a loaded function declares is listed, in its location and in `-`, and read.
        let declared = ["projects/demo/locations/us-central1/channels/c"];
        for target in [base, "/v1/projects/demo/locations/-/channels"] {
            let Outcome::Answer(Answer { status, body }) = run("GET", target, true, "", &declared)
            else {
                panic!()
            };
            assert_eq!(status, 200, "{target}");
            assert_eq!(
                body["channels"][0]["name"],
                "projects/demo/locations/us-central1/channels/c"
            );
            assert_eq!(body["channels"][0]["state"], "ACTIVE");
        }
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
            200
        );
        assert_eq!(
            status_and_message(&run("GET", &format!("{base}/d"), true, "", &declared)).0,
            404
        );
    }

    #[test]
    fn a_creation_needs_a_name() {
        let target = "/v1/projects/demo/locations/us-central1/channels?channelId=cc";
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
        // With the name of the path the creation starts an operation (the replay of the stage B recording
        // pins its shape); a name that is not the path's, or no channelId, is not served.
        let named = run(
            "POST",
            target,
            true,
            r#"{"name":"projects/demo/locations/us-central1/channels/cc"}"#,
            &[],
        );
        assert_eq!(status_and_message(&named).0, 200);
        // A body that names another channel creates the channel of the path (stage C); no channelId is not served.
        let mismatch = run(
            "POST",
            "/v1/projects/demo/locations/us-central1/channels?channelId=dd",
            true,
            r#"{"name":"projects/demo/locations/us-central1/channels/other"}"#,
            &[],
        );
        assert_eq!(status_and_message(&mismatch).0, 200);
        let bare = run(
            "POST",
            "/v1/projects/demo/locations/us-central1/channels",
            true,
            r#"{"name":"projects/demo/locations/us-central1/channels/cc"}"#,
            &[],
        );
        assert_eq!(status_and_message(&bare).0, 501);
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
        let many: Vec<String> = (0..=MAX_EVENTS).map(|_| event_json("")).collect();
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
        // 100 events are the most accepted (stage B: 100 pass, 101 are refused).
        assert_eq!(
            status_and_message(&publish(&many[..MAX_EVENTS], &[])),
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
        let events = [delivered_event("a"), delivered_event("b")];
        let Outcome::Deliver {
            channel,
            events: handed,
        } = publish(&events, &declared)
        else {
            panic!("delivered")
        };
        assert_eq!(channel, "projects/demo/locations/us-central1/channels/c");
        assert_eq!(handed.len(), 2);
        assert_eq!(handed[0]["id"], "a");
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
            message("No events provided."),
            "a bare event is not an event"
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

    fn mapped_channel() -> Lookup {
        let channels = ChannelStore::default();
        let name = "projects/demo-eventarc-shapes1/locations/us-central1/channels/feabcdefabcdef-w";
        channels.declare(name, 0);
        channels.lookup(name, 0)
    }

    fn parsed_samples(samples: &[Sample]) -> Vec<ParsedEvent> {
        samples
            .iter()
            .enumerate()
            .map(|(index, sample)| {
                parse_event(index, &parse(sample_json(sample).as_bytes()).unwrap()).unwrap()
            })
            .collect()
    }

    // Evidence-derived, same-width public-safe metadata; the target is CE wire size, not HTTP size.
    fn mapped_family(count: usize, epoch: bool, probe: bool, target: usize) -> Vec<Sample> {
        let mut samples: Vec<_> = (0..count)
            .map(|index| {
                let mut attributes = vec![
                    (
                        "datacontenttype".to_owned(),
                        Value2::Text("application/json".to_owned()),
                    ),
                    (
                        "time".to_owned(),
                        Value2::Timestamp(if epoch { 0 } else { 1_791_331_200 }, 0),
                    ),
                ];
                if probe {
                    attributes.push(("probe".to_owned(), Value2::Integer(0)));
                }
                Sample {
                    id: format!("abcdefabcdef-02-{index:03}"),
                    source: "//example/w/abcdefabcdef".to_owned(),
                    spec: "1.0".to_owned(),
                    kind: "example.w.abcdefabcdef".to_owned(),
                    attributes,
                    data: Some(Ok("\"\"".to_owned())),
                }
            })
            .collect();
        let Lookup::Ready(view) = mapped_channel() else {
            panic!("ready channel");
        };
        let mut padding = 0_isize;
        for _ in 0..3 {
            padding +=
                target as isize - request_size(&view.name, &parsed_samples(&samples)) as isize;
            let padding = usize::try_from(padding).unwrap();
            for (index, sample) in samples.iter_mut().enumerate() {
                sample.data = Some(Ok(serde_json::to_string(
                    &"x".repeat(padding / count + usize::from(index < padding % count)),
                )
                .unwrap()));
            }
        }
        assert_eq!(request_size(&view.name, &parsed_samples(&samples)), target);
        samples
    }

    // Explicit protobuf field tags provide an encoder independent of field_len and the metric helper.
    fn mapped_wire(topic: &str, samples: &[Sample]) -> Vec<u8> {
        let mut request = Vec::new();
        put_bytes(&mut request, 1, topic.as_bytes());
        for sample in samples {
            let mut message = Vec::new();
            let Some(Ok(data)) = &sample.data else {
                panic!("text data");
            };
            put_bytes(&mut message, 1, data.as_bytes());
            let mut attributes = vec![
                ("ce-id".to_owned(), sample.id.clone()),
                ("ce-source".to_owned(), sample.source.clone()),
                ("ce-specversion".to_owned(), sample.spec.clone()),
                ("ce-type".to_owned(), sample.kind.clone()),
            ];
            for (key, value) in &sample.attributes {
                let value = match value {
                    Value2::Text(text) => text.clone(),
                    Value2::Timestamp(seconds, 0) => rfc3339(*seconds, 0),
                    Value2::Integer(0) => "0".to_owned(),
                    _ => panic!("unsupported mapped test value"),
                };
                attributes.push((format!("ce-{key}"), value));
            }
            for (key, value) in attributes {
                let mut entry = Vec::new();
                put_bytes(&mut entry, 1, key.as_bytes());
                put_bytes(&mut entry, 2, value.as_bytes());
                put_bytes(&mut message, 2, &entry);
            }
            put_bytes(&mut request, 2, &message);
        }
        request
    }

    #[test]
    fn mapped_publish_size_reconstructs_the_three_observed_shapes() {
        let channel = mapped_channel();
        let Lookup::Ready(view) = &channel else {
            panic!("ready channel");
        };
        assert_eq!(view.pubsub_topic.len(), 87);
        for (count, epoch, probe, expected) in [
            (99, false, false, 10_083_108),
            (100, true, false, 10_083_721),
            (100, false, true, 10_083_321),
        ] {
            let samples = mapped_family(count, epoch, probe, 10_081_812);
            let parsed = parsed_samples(&samples);
            assert_eq!(
                mapped_publish_request_size(&channel, &parsed),
                Some(expected)
            );
            assert_eq!(mapped_wire(&view.pubsub_topic, &samples).len(), expected);
        }
    }

    #[test]
    fn mapped_publish_size_reconstructs_numeric_refusals_and_the_boundary_prediction() {
        let channel = mapped_channel();
        for (ce, expected) in [
            (10_475_028, 10_476_337),
            (10_212_884, 10_214_193),
            (10_081_812, 10_083_121),
            (10_016_276, 10_017_585),
            (9_999_892, 10_001_201),
            (9_998_868, 10_000_177),
            (9_998_740, 10_000_049),
            (9_998_708, 10_000_017),
            (9_998_692, 10_000_001),
            // Accepted native answers report no internal size; this is the supported model's prediction.
            (9_998_691, 10_000_000),
        ] {
            let samples = mapped_family(100, false, false, ce);
            assert_eq!(
                mapped_publish_request_size(&channel, &parsed_samples(&samples)),
                Some(expected)
            );
        }
    }

    #[test]
    fn mapped_publish_size_keeps_unobserved_representations_unknown() {
        let channel = mapped_channel();
        let mut sample = mapped_family(1, false, false, 1024).pop().unwrap();
        for value in [
            Value2::Boolean(false),
            Value2::Boolean(true),
            Value2::Integer(1),
            Value2::Uri("urn:example:test".to_owned()),
            Value2::UriRef("test".to_owned()),
            Value2::Bytes(vec![0]),
            Value2::Timestamp(0, 1),
            Value2::Text(String::new()),
        ] {
            let mut unsupported = sample.clone();
            unsupported.attributes.push(("extension".to_owned(), value));
            assert_eq!(
                mapped_publish_request_size(&channel, &parsed_samples(&[unsupported])),
                None
            );
        }
        let original = sample_json(&sample);
        for spelling in ["1970-01-01T00:00:00.000Z", "1970-01-01T00:00:00+00:00"] {
            let value = original.replace("2026-10-07T00:00:00Z", spelling);
            let parsed = parse_event(0, &parse(value.as_bytes()).unwrap()).unwrap();
            assert_eq!(mapped_publish_request_size(&channel, &[parsed]), None);
        }
        for key in ["id", "source", "specversion", "type"] {
            let mut colliding = sample.clone();
            colliding
                .attributes
                .push((key.to_owned(), Value2::Text("extension".to_owned())));
            assert_eq!(
                mapped_publish_request_size(&channel, &parsed_samples(&[colliding])),
                None
            );
        }
        let mut duplicate = sample.clone();
        duplicate.attributes.push(duplicate.attributes[0].clone());
        assert_eq!(
            mapped_publish_request_size(&channel, &parsed_samples(&[duplicate])),
            None
        );
        for field in 0..4 {
            let mut missing = sample.clone();
            match field {
                0 => missing.id.clear(),
                1 => missing.source.clear(),
                2 => missing.spec.clear(),
                _ => missing.kind.clear(),
            }
            assert_eq!(
                mapped_publish_request_size(&channel, &parsed_samples(&[missing])),
                None
            );
        }
        sample.data = Some(Ok(String::new()));
        assert_eq!(
            mapped_publish_request_size(&channel, &parsed_samples(&[sample.clone()])),
            None
        );
        sample.data = None;
        assert_eq!(
            mapped_publish_request_size(&channel, &parsed_samples(&[sample.clone()])),
            None
        );
        sample.data = Some(Err(vec![0]));
        assert_eq!(
            mapped_publish_request_size(&channel, &parsed_samples(&[sample])),
            None
        );
        let Lookup::Ready(view) = channel else {
            panic!("ready channel");
        };
        for state in [
            Lookup::Absent,
            Lookup::Creating(view.clone()),
            Lookup::Deleting(view),
        ] {
            assert_eq!(mapped_publish_request_size(&state, &[]), None);
        }
        let Lookup::Ready(mut view) = mapped_channel() else {
            panic!("ready channel");
        };
        view.pubsub_topic.clear();
        assert_eq!(mapped_publish_request_size(&Lookup::Ready(view), &[]), None);
    }

    #[test]
    fn mapped_publish_size_counts_utf8_and_length_prefix_boundaries() {
        let channel = mapped_channel();
        let Lookup::Ready(view) = &channel else {
            panic!("ready channel");
        };
        let mut sample = mapped_family(1, false, false, 1024).pop().unwrap();
        sample.id = "é".repeat(64);
        sample
            .attributes
            .push(("é".repeat(64), Value2::Text("🙂".repeat(32))));
        for bytes in [2, 126, 127, 128, 16_383, 16_384] {
            sample.data = Some(Ok(serde_json::to_string(&"x".repeat(bytes - 2)).unwrap()));
            let samples = [sample.clone()];
            assert_eq!(
                mapped_publish_request_size(&channel, &parsed_samples(&samples)),
                Some(mapped_wire(&view.pubsub_topic, &samples).len())
            );
        }
    }

    fn mapped_sample() -> impl Strategy<Value = Sample> {
        (
            ".{1,40}",
            ".{1,40}",
            ".{1,40}",
            ".{1,40}",
            ".{0,2000}",
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(|(id, source, spec, kind, data, epoch, probe)| {
                let mut attributes = vec![
                    (
                        "datacontenttype".to_owned(),
                        Value2::Text("application/json".to_owned()),
                    ),
                    (
                        "time".to_owned(),
                        Value2::Timestamp(if epoch { 0 } else { 1_791_331_200 }, 0),
                    ),
                ];
                if probe {
                    attributes.push(("probe".to_owned(), Value2::Integer(0)));
                }
                Sample {
                    id,
                    source,
                    spec,
                    kind,
                    attributes,
                    data: Some(Ok(serde_json::to_string(&data).unwrap())),
                }
            })
    }

    proptest! {
        #[test]
        fn mapped_publish_size_matches_independent_wire_encoding(
            samples in proptest::collection::vec(mapped_sample(), 0..4),
            topic in "projects/demo/topics/[a-z]{1,200}",
        ) {
            let Lookup::Ready(mut view) = mapped_channel() else { panic!("ready channel"); };
            view.pubsub_topic = topic.clone();
            prop_assert_eq!(
                mapped_publish_request_size(&Lookup::Ready(view), &parsed_samples(&samples)),
                Some(mapped_wire(&topic, &samples).len())
            );
        }

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
                nanos: 0,
                mapped_text: None,
            }
            .size(),
            2
        );
        assert_eq!(
            Attribute::Timestamp {
                seconds: -1,
                nanos: 0,
                mapped_text: None,
            }
            .size(),
            2 + 1 + 10
        );
    }
}
