//! The channel API and the publication to an existing channel of the strict Eventarc surface, as the
//! stage B recording showed them. The replay of the recording (`eventarc_strict_stage_b.rs`) pins the
//! bytes of every recorded answer; these tests pin the rules behind them, the cases the recording did not
//! reach, and what the surface refuses to invent: every state production was not observed in answers
//! `501 UNIMPLEMENTED` and says which.

use std::cell::Cell;

use fireemu_adapter_functions::eventarc_channels::{ChannelStore, Entropy, Timing};
use fireemu_adapter_functions::eventarc_strict::{evaluate, route, Input, Outcome, World};
use fireemu_adapter_functions::ordered_json::Ordered;
use proptest::prelude::*;
use serde_json::{json, Value};

const PROJECT: &str = "demo";
const SECOND: u64 = 1_000_000_000;
const T0: u64 = 1_791_198_689 * SECOND;
const PARENT: &str = "projects/demo/locations/us-central1";

/// Identifiers from a counter.
#[derive(Default)]
struct Sequence(u64);

impl Entropy for Sequence {
    fn uuid(&mut self) -> String {
        self.0 += 1;
        fireemu_adapter_functions::eventarc_channels::uuid_from(
            self.0.wrapping_mul(0x9e37_79b9_7f4a_7c15),
            self.0,
        )
    }
    fn hex(&mut self, digits: usize) -> String {
        self.0 += 1;
        format!("{:0digits$x}", self.0)
    }
    fn topic_suffix(&mut self) -> u16 {
        self.0 += 1;
        u16::try_from(self.0 % 1000).unwrap_or(0)
    }
}

/// One server: its channels, its clock and the channels a function declares.
struct Server {
    store: ChannelStore,
    now: Cell<u64>,
    declared: Vec<String>,
}

#[derive(Debug)]
struct Reply {
    status: u16,
    body: Value,
    /// The members in the order they were written (`Value` sorts them).
    ordered: Ordered,
    text: String,
}

#[derive(Debug)]
enum Sent {
    Answered(Reply),
    Delivered { channel: String, events: Vec<Value> },
}

impl Server {
    fn new() -> Self {
        Self::declaring(&[])
    }

    fn declaring(declared: &[&str]) -> Self {
        Self {
            store: ChannelStore::new(
                Box::new(Sequence::default()),
                Timing {
                    create: 5 * SECOND,
                    delete: 4 * SECOND,
                },
            ),
            now: Cell::new(T0),
            declared: declared.iter().map(|name| (*name).to_owned()).collect(),
        }
    }

    fn advance(&self, seconds: u64) {
        self.now.set(self.now.get() + seconds * SECOND);
    }

    fn send(&self, method: &str, target: &str, bearer: Option<&str>, body: &str) -> Sent {
        let (path, query) = target
            .split_once('?')
            .map_or((target, None), |(path, query)| (path, Some(query)));
        let route = route(method, path).unwrap_or_else(|| panic!("{method} {target} is a route"));
        let declared_channel = |name: &str| self.declared.iter().any(|d| d == name);
        let declared_in = |project: &str, location: &str| -> Vec<String> {
            self.declared
                .iter()
                .filter(|d| {
                    d.starts_with(&format!("projects/{project}/locations/"))
                        && (location == "-" || d.contains(&format!("/locations/{location}/")))
                })
                .cloned()
                .collect()
        };
        let world = World {
            project: PROJECT,
            request_id: "0123456789abcdef",
            declared_channel: &declared_channel,
            declared_in: &declared_in,
            channels: &self.store,
            now: self.now.get(),
        };
        let input = Input {
            route: &route,
            query,
            bearer,
            body: body.as_bytes(),
        };
        match evaluate(&input, &world) {
            Outcome::Answer(answer) => Sent::Answered(Reply {
                status: answer.status,
                text: answer.text(),
                body: answer.body.to_value(),
                ordered: answer.body,
            }),
            Outcome::Deliver { channel, events } => Sent::Delivered { channel, events },
        }
    }

    fn call(&self, method: &str, target: &str, body: &str) -> Reply {
        match self.send(method, target, Some("ya29.a-token"), body) {
            Sent::Answered(reply) => reply,
            Sent::Delivered { .. } => panic!("an answer"),
        }
    }

    fn create(&self, location: &str, id: &str) -> Reply {
        self.call(
            "POST",
            &format!("/v1/projects/{PROJECT}/locations/{location}/channels?channelId={id}"),
            &json!({ "name": format!("projects/{PROJECT}/locations/{location}/channels/{id}") })
                .to_string(),
        )
    }

    /// Creates a channel and lets its operation finish.
    fn ready(&self, id: &str) -> String {
        let reply = self.create("us-central1", id);
        assert_eq!(reply.status, 200, "{reply:?}");
        self.advance(6);
        format!("{PARENT}/channels/{id}")
    }
}

fn message(reply: &Reply) -> &str {
    reply.body["error"]["message"].as_str().unwrap_or_default()
}

// --- the lifecycle -----------------------------------------------------------------------------------

#[test]
fn a_channel_is_created_through_an_operation_read_listed_and_deleted_as_production_did() {
    let server = Server::new();
    let created = server.create("us-central1", "c1");
    assert_eq!(created.status, 200, "{}", created.text);
    let operation = created.body["name"].as_str().unwrap().to_owned();
    assert!(operation.starts_with(&format!("{PARENT}/operations/operation-")));
    assert_eq!(created.body["done"], false);
    assert_eq!(created.body["metadata"]["verb"], "create");
    assert_eq!(
        created.body["metadata"]["target"],
        format!("{PARENT}/channels/c1")
    );
    assert_eq!(created.body["metadata"]["requestedCancellation"], false);
    assert_eq!(created.body["metadata"]["apiVersion"], "v1");
    // The members of the answer, in the recorded order.
    let members: Vec<&str> = created
        .ordered
        .members()
        .unwrap()
        .iter()
        .map(|(k, _)| k.as_str())
        .collect();
    assert_eq!(members, ["name", "metadata", "done"]);
    // Read while it runs: not done, the same operation.
    server.advance(2);
    let pending = server.call("GET", &format!("/v1/{operation}"), "");
    assert_eq!(
        (pending.status, &pending.body["done"]),
        (200, &json!(false))
    );
    // Done after its duration, with the channel in its response.
    server.advance(4);
    let finished = server.call("GET", &format!("/v1/{operation}"), "");
    assert_eq!(finished.body["done"], true);
    assert_eq!(
        finished.body["response"]["name"],
        format!("{PARENT}/channels/c1")
    );
    assert_eq!(finished.body["response"]["state"], "ACTIVE");
    // The channel, its listing, and the conflict of a second creation.
    let read = server.call("GET", &format!("/v1/{PARENT}/channels/c1"), "");
    assert_eq!(read.status, 200);
    assert_eq!(read.body["uid"], finished.body["response"]["uid"]);
    let list = server.call("GET", &format!("/v1/{PARENT}/channels"), "");
    assert_eq!(list.body["channels"].as_array().unwrap().len(), 1);
    assert_eq!(list.body["channels"][0], read.body);
    let again = server.create("us-central1", "c1");
    assert_eq!(again.status, 409, "{}", again.text);
    assert_eq!(again.body["error"]["status"], "ALREADY_EXISTS");
    assert_eq!(
        message(&again),
        format!("Resource '{PARENT}/channels/c1' already exists")
    );
    assert_eq!(
        again.body["error"]["details"][0]["resourceName"],
        format!("{PARENT}/channels/c1")
    );
    // The deletion: an operation, then absent.
    let deleted = server.call("DELETE", &format!("/v1/{PARENT}/channels/c1"), "");
    assert_eq!(deleted.status, 200);
    assert_eq!(deleted.body["metadata"]["verb"], "delete");
    let deletion = deleted.body["name"].as_str().unwrap().to_owned();
    server.advance(5);
    let done = server.call("GET", &format!("/v1/{deletion}"), "");
    assert_eq!(done.body["done"], true);
    assert_eq!(done.body["response"]["state"], "INACTIVE");
    for (method, path) in [
        ("GET", format!("/v1/{PARENT}/channels/c1")),
        ("DELETE", format!("/v1/{PARENT}/channels/c1")),
    ] {
        let missing = server.call(method, &path, "");
        assert_eq!(missing.status, 404, "{method}");
        assert_eq!(
            message(&missing),
            format!("Resource '{PARENT}/channels/c1' was not found")
        );
        assert_eq!(
            missing.body["error"]["details"][0]["@type"],
            "type.googleapis.com/google.rpc.ResourceInfo"
        );
    }
    assert_eq!(
        server
            .call("GET", &format!("/v1/{PARENT}/channels"), "")
            .text,
        "{}\n"
    );
    // The channel can be created again.
    assert_eq!(server.create("us-central1", "c1").status, 200);
}

#[test]
fn the_states_production_was_not_observed_in_answer_501_and_say_which() {
    let server = Server::declaring(&[&format!("{PARENT}/channels/declared")]);
    let created = server.create("us-central1", "busy");
    assert_eq!(created.status, 200);
    let operation = created.body["name"].as_str().unwrap().to_owned();
    // While a creation runs: a read, a list, a second creation, a deletion and a publication.
    let event = delivered_event("e1");
    let publish = json!({ "events": [event] }).to_string();
    for (reply, what) in [
        (
            server.call("GET", &format!("/v1/{PARENT}/channels/busy"), ""),
            "read",
        ),
        (
            server.call("GET", &format!("/v1/{PARENT}/channels"), ""),
            "list",
        ),
        (server.create("us-central1", "busy"), "creation"),
        (
            server.call("DELETE", &format!("/v1/{PARENT}/channels/busy"), ""),
            "deletion",
        ),
        (
            server.call(
                "POST",
                &format!("/v1/{PARENT}/channels/busy:publishEvents"),
                &publish,
            ),
            "publication",
        ),
    ] {
        assert_eq!(reply.status, 501, "{what}: {}", reply.text);
        assert_eq!(reply.body["error"]["status"], "UNIMPLEMENTED", "{what}");
        assert!(
            message(&reply).contains("not finished") || message(&reply).contains("is being"),
            "{what}: {}",
            message(&reply)
        );
    }
    // A creation whose name is not the path's, and one without a channelId.
    let other = json!({ "name": format!("{PARENT}/channels/other") }).to_string();
    assert_eq!(
        server
            .call(
                "POST",
                &format!("/v1/{PARENT}/channels?channelId=x"),
                &other
            )
            .status,
        501
    );
    assert_eq!(
        server
            .call("POST", &format!("/v1/{PARENT}/channels"), &other)
            .status,
        501
    );
    // An operation this server did not start, a page size that is not a positive number, the deletion of
    // a channel a function declares.
    let stranger = server.call(
        "GET",
        &format!("/v1/{PARENT}/operations/operation-1-2-3-4"),
        "",
    );
    assert_eq!(stranger.status, 501);
    server.advance(6);
    for size in ["-1", "x", "1.5"] {
        let reply = server.call("GET", &format!("/v1/{PARENT}/channels?pageSize={size}"), "");
        assert_eq!(reply.status, 501, "{size}");
    }
    let declared = server.call("DELETE", &format!("/v1/{PARENT}/channels/declared"), "");
    assert_eq!(declared.status, 501);
    assert!(message(&declared).contains("declares"));
    // Once its operation is done the channel answers as any other.
    assert_eq!(
        server.call("GET", &format!("/v1/{operation}"), "").status,
        200
    );
    assert_eq!(
        server
            .call("GET", &format!("/v1/{PARENT}/channels/busy"), "")
            .status,
        200
    );
}

// --- identifiers and locations -----------------------------------------------------------------------

/// The reference for a channel ID: recorded accepted and refused ones, then the DNS-label rule that stands
/// in for what was not observed.
fn reference_valid(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

#[test]
fn the_recorded_channel_ids_are_accepted_or_refused_as_production_did() {
    let server = Server::new();
    // Accepted in the recording: two characters, `goog-`, the run-prefixed forms.
    for id in ["a4", "goog-43a83839852f", "fe43a83839852f-cp-p1", "abc"] {
        let reply = server.create("us-central1", id);
        assert_eq!(reply.status, 200, "{id}: {}", reply.text);
    }
    // Refused in the recording: upper case, a leading digit, an underscore, 64 characters.
    for id in [
        "GOOG-43A83839852F",
        "1-43a83839852f",
        "bad_43a83839852f",
        &format!("fe43a83839852f-{}", "x".repeat(49)),
    ] {
        let reply = server.create("us-central1", id);
        assert_eq!(reply.status, 400, "{id}");
        assert_eq!(
            message(&reply),
            format!("The request was invalid: invalid resource id: {id}")
        );
        // Written twice, with the same request ID, as production wrote it.
        let details = reply.body["error"]["details"].as_array().unwrap();
        assert_eq!(details.len(), 4);
        assert_eq!(details[0], details[2]);
        assert_eq!(details[1], details[3]);
        assert_eq!(details[0]["fieldViolations"][0]["field"], "channel.name");
        assert_eq!(details[1]["requestId"], "0123456789abcdef");
    }
    // The longest accepted: 63 characters.
    assert_eq!(server.create("us-central1", &"a".repeat(63)).status, 200);
    assert_eq!(server.create("us-central1", &"a".repeat(64)).status, 400);
}

proptest! {
    #[test]
    fn a_channel_id_is_accepted_exactly_when_the_rule_says(id in "[a-zA-Z0-9_-]{1,70}") {
        let server = Server::new();
        let reply = server.create("us-central1", &id);
        prop_assert_eq!(reply.status == 200, reference_valid(&id), "{} -> {}", id, reply.status);
        if reply.status != 200 {
            prop_assert_eq!(reply.status, 400);
        }
    }
}

#[test]
fn a_location_exists_when_eventarc_serves_it_and_a_list_of_every_location_gathers_them() {
    let server = Server::new();
    for location in ["us-central1", "europe-west1", "asia-east1"] {
        assert_eq!(server.create(location, "c").status, 200, "{location}");
    }
    server.advance(6);
    let all = server.call(
        "GET",
        &format!("/v1/projects/{PROJECT}/locations/-/channels"),
        "",
    );
    assert_eq!(all.body["channels"].as_array().unwrap().len(), 3);
    let one = server.call(
        "GET",
        &format!("/v1/projects/{PROJECT}/locations/europe-west1/channels"),
        "",
    );
    assert_eq!(one.body["channels"].as_array().unwrap().len(), 1);
    assert_eq!(
        server
            .call(
                "GET",
                &format!("/v1/projects/{PROJECT}/locations/us-east1/channels"),
                ""
            )
            .text,
        "{}\n"
    );
    // Recorded: a region-shaped name that Eventarc does not serve is refused as `no-such-location1` was.
    for (method, path) in [
        ("GET", "/v1/projects/demo/locations/us-east99/channels"),
        ("GET", "/v1/projects/demo/locations/us-east99/channels/c"),
        ("DELETE", "/v1/projects/demo/locations/us-east99/channels/c"),
        ("GET", "/v1/projects/demo/locations/us-east99/operations/o"),
    ] {
        let reply = server.call(method, path, "");
        assert_eq!(reply.status, 403, "{method} {path}");
        assert_eq!(
            message(&reply),
            "Location us-east99 is not found or access is unauthorized."
        );
    }
    let create = server.create("us-east99", "c");
    assert_eq!(create.status, 403);
    assert_eq!(
        create.body["error"]["details"][0]["reason"],
        "LOCATION_POLICY_VIOLATED"
    );
}

// --- the list ----------------------------------------------------------------------------------------

#[test]
fn a_list_pages_through_tokens_and_refuses_a_token_that_is_not_its_own() {
    let server = Server::new();
    for id in ["a", "b", "c", "d", "e"] {
        server.create("us-central1", id);
        server.advance(1);
    }
    server.advance(6);
    let mut seen = Vec::new();
    let mut target = format!("/v1/{PARENT}/channels?pageSize=2");
    let mut pages = 0;
    loop {
        let page = server.call("GET", &target, "");
        assert_eq!(page.status, 200);
        let names: Vec<String> = page.body["channels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                c["name"]
                    .as_str()
                    .unwrap()
                    .rsplit('/')
                    .next()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        seen.extend(names);
        pages += 1;
        match page.body["nextPageToken"].as_str() {
            Some(token) => target = format!("/v1/{PARENT}/channels?pageSize=2&pageToken={token}"),
            None => break,
        }
    }
    assert_eq!((pages, seen.len()), (3, 5));
    let mut sorted = seen.clone();
    sorted.sort();
    assert_eq!(sorted, ["a", "b", "c", "d", "e"], "every channel once");
    // `pageSize=0` and no size give the default page: all five.
    for query in ["", "?pageSize=0", "?pageSize=100000"] {
        let all = server.call("GET", &format!("/v1/{PARENT}/channels{query}"), "");
        assert_eq!(all.body["channels"].as_array().unwrap().len(), 5, "{query}");
        assert!(all.body.get("nextPageToken").is_none());
    }
    // A token belongs to its location and its project, and is refused anywhere else, and when altered.
    let first = server.call("GET", &format!("/v1/{PARENT}/channels?pageSize=1"), "");
    let token = first.body["nextPageToken"].as_str().unwrap();
    for target in [
        format!("/v1/projects/{PROJECT}/locations/europe-west1/channels?pageToken={token}"),
        format!("/v1/{PARENT}/channels?pageToken={token}x"),
        format!("/v1/{PARENT}/channels?pageToken={}", &token[1..]),
        format!("/v1/{PARENT}/channels?pageToken=garbage"),
    ] {
        let reply = server.call("GET", &target, "");
        assert_eq!(reply.status, 400, "{target}");
        assert_eq!(
            message(&reply),
            "The request was invalid: invalid page token"
        );
    }
    let everywhere = server.call(
        "GET",
        &format!("/v1/projects/{PROJECT}/locations/-/channels?pageToken={token}"),
        "",
    );
    assert_eq!(
        everywhere.status, 200,
        "a token of a location continues an aggregated list"
    );
}

// --- the publication to a channel that exists --------------------------------------------------------

fn delivered_event(id: &str) -> Value {
    json!({
        "@type": "type.googleapis.com/io.cloudevents.v1.CloudEvent",
        "id": id,
        "source": "//test/source",
        "specVersion": "1.0",
        "type": "com.example.done",
        "attributes": {
            "time": {"ceTimestamp": "2026-10-05T06:17:17.731Z"},
            "datacontenttype": {"ceString": "application/json"},
        },
        "textData": "{\"n\":1}",
    })
}

fn publish(server: &Server, channel: &str, events: &[Value]) -> Reply {
    server.call(
        "POST",
        &format!("/v1/{channel}:publishEvents"),
        &json!({ "events": events }).to_string(),
    )
}

fn field_violations(reply: &Reply) -> Vec<(String, String)> {
    reply.body["error"]["details"][0]["fieldViolations"]
        .as_array()
        .map(|list| {
            list.iter()
                .map(|v| {
                    (
                        v["field"].as_str().unwrap_or_default().to_owned(),
                        v["description"].as_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_valid_publication_to_a_channel_the_api_created_is_accepted_and_goes_nowhere() {
    let server = Server::new();
    let channel = server.ready("c");
    let reply = publish(
        &server,
        &channel,
        &[delivered_event("a"), delivered_event("b")],
    );
    assert_eq!((reply.status, reply.text.as_str()), (200, "{}\n"));
    // The same id twice in two requests is fine; in one request it is not.
    assert_eq!(
        publish(&server, &channel, &[delivered_event("a")]).status,
        200
    );
    let twice = publish(
        &server,
        &channel,
        &[delivered_event("a"), delivered_event("a")],
    );
    assert_eq!(twice.status, 400);
    assert_eq!(
        message(&twice),
        "The source + id pair needs to be unique in a batch call"
    );
    assert_eq!(
        field_violations(&twice),
        [(
            "events[1]".to_owned(),
            "The source + id pair needs to be unique in a batch call".to_owned()
        )]
    );
    // After the channel is deleted its publications are refused at once.
    assert_eq!(
        server.call("DELETE", &format!("/v1/{channel}"), "").status,
        200
    );
    server.advance(5);
    let gone = publish(&server, &channel, &[delivered_event("a")]);
    assert_eq!(
        (gone.status, message(&gone)),
        (404, "Associated channel does not exist.")
    );
}

/// Each case changes the first event of a valid publication and says what production answered.
fn changed(f: impl FnOnce(&mut Value)) -> Value {
    let mut event = delivered_event("a");
    f(&mut event);
    event
}

/// What a publication of an event must answer: the status, the message (empty when the message is the
/// "cannot be empty" one of the first violation's attribute) and the violations by field and text.
type Case<'a> = (&'a str, Value, u16, &'a str, Vec<(&'a str, &'a str)>);

const MIME: &str = "CloudEvent attribute `datacontenttype' must have mime-type `application/json'.";
const NOT_OBJECT: &str = "Provided CloudEvent data is not a valid json object.";
const TEXT_FORMAT: &str =
    "The provided data needs to be in text format. Please set `text_data` in the CloudEvent.";

#[test]
fn the_events_an_existing_channel_accepts_are_the_recorded_ones() {
    let server = Server::new();
    let channel = server.ready("c");
    let no_time = changed(|e| {
        e["attributes"].as_object_mut().unwrap().remove("time");
    });
    let accepted: Vec<(&str, Value)> = vec![
        ("no time attribute", no_time),
        ("an object", changed(|_| {})),
        ("a scalar", changed(|e| e["textData"] = json!("1"))),
        ("null", changed(|e| e["textData"] = json!("null"))),
        ("an array", changed(|e| e["textData"] = json!("[1,2,3]"))),
        (
            "every attribute kind",
            changed(|e| {
                e["attributes"]["flag"] = json!({"ceBoolean": true});
                e["attributes"]["count"] = json!({"ceInteger": 1});
                e["attributes"]["link"] = json!({"ceUri": "https://example.com/x"});
                e["attributes"]["relative"] = json!({"ceUriRef": "/x"});
                e["attributes"]["bytes"] = json!({"ceBytes": "AAE="});
                e["attributes"]["subject"] = json!({"ceString": "s"});
            }),
        ),
    ];
    for (what, event) in &accepted {
        let reply = publish(&server, &channel, std::slice::from_ref(event));
        assert_eq!((reply.status, reply.text.as_str()), (200, "{}\n"), "{what}");
    }
}

fn refusals() -> Vec<Case<'static>> {
    let mut cases: Vec<Case<'static>> = Vec::new();
    for (member, wanted) in [
        ("id", "id"),
        ("source", "source"),
        ("type", "type"),
        ("specVersion", "spec_version"),
    ] {
        cases.push((
            member,
            changed(|e| {
                e.as_object_mut().unwrap().remove(member);
            }),
            400,
            "",
            vec![("events[0]", wanted)],
        ));
    }
    let time = "The type for the attribute 'time' is not valid.";
    let content_type =
        "The attribute 'datacontenttype' has not been defined in the CloudEvent attributes.";
    cases.extend([
        (
            "a string time",
            changed(|e| e["attributes"]["time"] = json!({"ceString": "2026-10-05T00:00:00Z"})),
            400,
            time,
            vec![("events[0]", time)],
        ),
        (
            "no content type",
            changed(|e| {
                e["attributes"]
                    .as_object_mut()
                    .unwrap()
                    .remove("datacontenttype");
            }),
            404,
            content_type,
            vec![("events[0]", content_type)],
        ),
        (
            "invalid JSON",
            changed(|e| e["textData"] = json!("{")),
            400,
            NOT_OBJECT,
            vec![("events[0]", NOT_OBJECT)],
        ),
        (
            "no data",
            changed(|e| {
                e.as_object_mut().unwrap().remove("textData");
            }),
            400,
            TEXT_FORMAT,
            vec![("events[0]", TEXT_FORMAT)],
        ),
        (
            "binary data",
            changed(|e| {
                e.as_object_mut().unwrap().remove("textData");
                e["binaryData"] = json!("AAEC/w==");
            }),
            400,
            TEXT_FORMAT,
            vec![("events[0]", TEXT_FORMAT)],
        ),
        (
            "text/plain text",
            changed(|e| {
                e["attributes"]["datacontenttype"] = json!({"ceString": "text/plain"});
                e["textData"] = json!("plain text");
            }),
            400,
            MIME,
            vec![
                ("events[0].datacontenttype", MIME),
                ("events[0]", NOT_OBJECT),
            ],
        ),
        (
            "octet-stream binary",
            changed(|e| {
                e["attributes"]["datacontenttype"] =
                    json!({"ceString": "application/octet-stream"});
                e.as_object_mut().unwrap().remove("textData");
                e["binaryData"] = json!("AAEC/w==");
            }),
            400,
            MIME,
            vec![
                ("events[0].datacontenttype", MIME),
                ("events[0]", TEXT_FORMAT),
            ],
        ),
        (
            "an empty text",
            changed(|e| {
                e["attributes"]["datacontenttype"] = json!({"ceString": "text/plain"});
                e["textData"] = json!("");
            }),
            400,
            MIME,
            vec![
                ("events[0].datacontenttype", MIME),
                ("events[0]", NOT_OBJECT),
            ],
        ),
    ]);
    cases
}

#[test]
fn every_refusal_of_an_existing_channel_answers_as_production_did() {
    let server = Server::new();
    let channel = server.ready("c");
    for (what, event, status, wanted_message, violations) in refusals() {
        let reply = publish(&server, &channel, std::slice::from_ref(&event));
        assert_eq!(reply.status, status, "{what}: {}", reply.text);
        let required = |text: &str| format!("Attribute '{text}' cannot be empty.");
        let expected: Vec<(String, String)> = violations
            .iter()
            .map(|(field, text)| {
                (
                    (*field).to_owned(),
                    if wanted_message.is_empty() {
                        required(text)
                    } else {
                        (*text).to_owned()
                    },
                )
            })
            .collect();
        assert_eq!(message(&reply), expected[0].1, "{what}");
        assert_eq!(field_violations(&reply), expected, "{what}");
    }
    // The first event with a violation is the one reported, by its position.
    let mixed = publish(
        &server,
        &channel,
        &[
            delivered_event("a"),
            changed(|e| {
                e.as_object_mut().unwrap().remove("type");
                e["id"] = json!("b");
            }),
        ],
    );
    assert_eq!(field_violations(&mixed)[0].0, "events[1]");
    // A request of events that hold nothing is empty.
    let bare = json!({"@type": "type.googleapis.com/io.cloudevents.v1.CloudEvent"});
    let only = publish(&server, &channel, &[bare]);
    assert_eq!((only.status, message(&only)), (400, "No events provided."));
}

#[test]
fn the_limits_of_a_publication_are_the_recorded_ones() {
    let server = Server::new();
    let channel = server.ready("c");
    let many =
        |n: usize| -> Vec<Value> { (0..n).map(|i| delivered_event(&format!("e{i}"))).collect() };
    // Recorded: 8, 69 and 100 events pass, 101 and 115 and 255 do not.
    for n in [1, 8, 69, 100] {
        assert_eq!(publish(&server, &channel, &many(n)).status, 200, "{n}");
    }
    for n in [101, 115, 255, 256, 1000] {
        let reply = publish(&server, &channel, &many(n));
        assert_eq!(
            (reply.status, message(&reply)),
            (400, "Too many events."),
            "{n}"
        );
        assert_eq!(reply.body["error"]["status"], "OUT_OF_RANGE");
    }
    // The attributes: the four required ones count with the others against 100. Recorded: 102 extra
    // attributes plus the two of the event were refused with "106 attributes". INFERRED: the boundary.
    let with_attributes = |extra: usize| {
        changed(|e| {
            for i in 0..extra {
                e["attributes"][format!("ext{i}")] = json!({"ceString": "v"});
            }
        })
    };
    assert_eq!(
        publish(&server, &channel, &[with_attributes(94)]).status,
        200
    );
    let too_many = publish(&server, &channel, &[with_attributes(95)]);
    assert_eq!(too_many.status, 400);
    assert_eq!(
        message(&too_many),
        "There are too many attributes in the request. The request contains 101 attributes, but the maximum allowed is 100. Refer to https://cloud.google.com/pubsub/quotas for more information."
    );
    assert!(too_many.body["error"].get("details").is_none());
    let hundred_and_six = publish(&server, &channel, &[with_attributes(100)]);
    assert!(message(&hundred_and_six).contains("contains 106 attributes"));
    // The key of an attribute is `ce-` and its name: 259 bytes were refused. INFERRED: the boundary.
    let named = |length: usize| {
        changed(|e| {
            e["attributes"][format!("n{}", "a".repeat(length - 1))] = json!({"ceString": "v"})
        })
    };
    assert_eq!(publish(&server, &channel, &[named(253)]).status, 200);
    let long = publish(&server, &channel, &[named(254)]);
    assert_eq!(long.status, 400);
    assert!(message(&long).ends_with(
        "in the request has a key that is too large. The size is 257 bytes, but the maximum allowed is 256. Refer to https://cloud.google.com/pubsub/quotas for more information."
    ));
    assert!(message(&long).starts_with("The attribute \"ce-n"));
    assert!(long.body["error"].get("details").is_none());
    // The size of an event: recorded passes at a text of 524032 characters and refusals at 524800.
    let sized = |length: usize| {
        let text = serde_json::to_string(&"x".repeat(length - 2)).unwrap();
        changed(|e| e["textData"] = json!(text))
    };
    assert_eq!(publish(&server, &channel, &[sized(524_032)]).status, 200);
    let large = publish(&server, &channel, &[sized(524_800)]);
    assert_eq!(large.status, 400);
    assert!(message(&large).starts_with("The event size ("));
    assert!(message(&large).ends_with(" bytes) is too large. The maximum size is 524288 bytes."));
}

#[test]
fn a_channel_a_function_declares_receives_only_the_events_that_pass_every_check() {
    let channel = format!("{PARENT}/channels/custom");
    let server = Server::declaring(&[&channel]);
    let Sent::Delivered {
        channel: got,
        events,
    } = server.send(
        "POST",
        &format!("/v1/{channel}:publishEvents"),
        Some("ya29.a-token"),
        &json!({ "events": [delivered_event("a"), delivered_event("b")] }).to_string(),
    )
    else {
        panic!("delivered")
    };
    assert_eq!(got, channel);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["id"], "a");
    // An event that production would refuse is not handed to the function.
    let refused = server.send(
        "POST",
        &format!("/v1/{channel}:publishEvents"),
        Some("ya29.a-token"),
        &json!({ "events": [changed(|e| {
            e["attributes"].as_object_mut().unwrap().remove("datacontenttype");
        })] })
        .to_string(),
    );
    let Sent::Answered(reply) = refused else {
        panic!("answered")
    };
    assert_eq!(reply.status, 404);
    // The declared channel is readable and listed, without a creation.
    assert_eq!(
        server.call("GET", &format!("/v1/{channel}"), "").status,
        200
    );
    assert_eq!(
        server
            .call("GET", &format!("/v1/{PARENT}/channels"), "")
            .body["channels"][0]["name"],
        channel
    );
    // It cannot be created over.
    assert_eq!(server.create("us-central1", "custom").status, 409);
}

// --- credentials -------------------------------------------------------------------------------------

#[test]
fn a_jwt_in_shape_is_refused_like_the_recorded_garbage_and_expired_ones_and_a_header_is_enough_otherwise(
) {
    let server = Server::new();
    let target = format!("/v1/{PARENT}/channels");
    let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.signature";
    let Sent::Answered(refused) = server.send("GET", &target, Some(jwt), "") else {
        panic!("answered")
    };
    assert_eq!(refused.status, 401);
    assert_eq!(refused.body["error"]["status"], "UNAUTHENTICATED");
    assert!(refused.body["error"].get("details").is_none());
    // The text of the recorded answer: 297 bytes.
    assert_eq!(refused.text.len(), 297);
    // An access token in shape is accepted: whether Google would accept it is not known here.
    let Sent::Answered(fine) = server.send("GET", &target, Some("ya29.anything"), "") else {
        panic!("answered")
    };
    assert_eq!(fine.status, 200);
}

#[test]
fn the_operation_of_a_project_the_caller_cannot_use_is_refused_before_it_is_looked_up() {
    let server = Server::new();
    let reply = server.call(
        "GET",
        "/v1/projects/other/locations/us-central1/operations/x",
        "",
    );
    assert_eq!(reply.status, 403);
    assert_eq!(
        reply.body["error"]["details"][0]["reason"],
        "CONSUMER_INVALID"
    );
    let Sent::Answered(unauthenticated) =
        server.send("DELETE", &format!("/v1/{PARENT}/channels/c"), None, "")
    else {
        panic!("answered")
    };
    assert_eq!(unauthenticated.status, 401);
    assert_eq!(
        unauthenticated.body["error"]["details"][0]["metadata"]["method"],
        "google.cloud.eventarc.v1.Eventarc.DeleteChannel"
    );
}

#[test]
fn the_bytes_of_a_channel_resource_are_the_recorded_layout() {
    let server = Server::new();
    server.create("us-central1", "c");
    server.advance(6);
    let read = server.call("GET", &format!("/v1/{PARENT}/channels/c"), "");
    let members: Vec<&str> = read
        .ordered
        .members()
        .unwrap()
        .iter()
        .map(|(k, _)| k.as_str())
        .collect();
    assert_eq!(
        members,
        [
            "name",
            "uid",
            "createTime",
            "updateTime",
            "pubsubTopic",
            "state"
        ]
    );
    // Pretty-printed with two-space indentation and a final newline, six members of one level.
    assert!(read.text.starts_with("{\n  \"name\": "));
    assert!(read.text.ends_with("\n}\n"));
    assert_eq!(read.text.matches('\n').count(), 8);
    let Ordered::Object(_) =
        fireemu_adapter_functions::ordered_json::parse(read.text.as_bytes()).unwrap()
    else {
        panic!("an object")
    };
}

// --- properties of the checks of a publication ---------------------------------------------------------

fn accepted(server: &Server, channel: &str, events: &[Value]) -> bool {
    let reply = publish(server, channel, events);
    match reply.status {
        200 => true,
        400 | 404 => false,
        other => panic!("unexpected {other}: {}", reply.text),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn a_publication_of_n_events_is_accepted_exactly_up_to_a_hundred(n in 1usize..=150) {
        let server = Server::new();
        let channel = server.ready("c");
        let events: Vec<Value> = (0..n).map(|i| delivered_event(&format!("e{i}"))).collect();
        prop_assert_eq!(accepted(&server, &channel, &events), n <= 100);
    }

    #[test]
    fn an_event_is_accepted_exactly_while_its_attributes_and_the_four_required_ones_are_at_most_a_hundred(extra in 0usize..=120) {
        let server = Server::new();
        let channel = server.ready("c");
        let event = changed(|e| {
            for i in 0..extra {
                e["attributes"][format!("ext{i}")] = json!({"ceString": "v"});
            }
        });
        // `time` and `datacontenttype` are two attributes of the event, and four more are counted.
        prop_assert_eq!(accepted(&server, &channel, &[event]), 2 + extra + 4 <= 100);
    }

    #[test]
    fn an_attribute_is_accepted_exactly_while_ce_and_its_name_are_at_most_256_bytes(length in 1usize..=300) {
        let server = Server::new();
        let channel = server.ready("c");
        let name = format!("n{}", "a".repeat(length - 1));
        let event = changed(|e| e["attributes"][name.as_str()] = json!({"ceString": "v"}));
        prop_assert_eq!(accepted(&server, &channel, &[event]), 3 + length <= 256);
    }

    #[test]
    fn the_first_missing_required_attribute_is_the_one_reported(missing in prop::sample::subsequence(vec!["id", "source", "specVersion", "type"], 1..=4)) {
        let server = Server::new();
        let channel = server.ready("c");
        let event = changed(|e| {
            for member in &missing {
                e.as_object_mut().unwrap().remove(*member);
            }
        });
        let reply = publish(&server, &channel, &[event]);
        prop_assert_eq!(reply.status, 400);
        // The order: id, source, spec_version, type (INFERRED: each was recorded alone).
        let first = ["id", "source", "specVersion", "type"]
            .into_iter()
            .find(|member| missing.contains(member))
            .unwrap();
        let named = if first == "specVersion" { "spec_version" } else { first };
        prop_assert_eq!(message(&reply), format!("Attribute '{named}' cannot be empty."));
    }

    #[test]
    fn a_text_is_data_exactly_when_it_is_json_and_the_content_type_is_exactly_json(
        text in prop_oneof![
            any::<i64>().prop_map(|n| n.to_string()),
            "[a-z ]{0,12}",
            Just("{\"a\":[1,true,null]}".to_owned()),
            Just("{".to_owned()),
        ],
        content_type in prop_oneof![
            Just("application/json".to_owned()),
            Just("text/plain".to_owned()),
            Just("application/json; charset=utf-8".to_owned()),
            Just("application/xml".to_owned()),
        ],
    ) {
        let server = Server::new();
        let channel = server.ready("c");
        let event = changed(|e| {
            e["textData"] = json!(text);
            e["attributes"]["datacontenttype"] = json!({"ceString": content_type});
        });
        let json_text = serde_json::from_str::<Value>(&text).is_ok();
        prop_assert_eq!(accepted(&server, &channel, &[event]), json_text && content_type == "application/json");
    }

    #[test]
    fn the_size_limit_is_one_boundary_that_a_longer_text_never_goes_back_across(a in 520_000usize..=530_000, b in 520_000usize..=530_000) {
        let server = Server::new();
        let channel = server.ready("c");
        let sized = |length: usize| {
            let text = serde_json::to_string(&"x".repeat(length - 2)).unwrap();
            changed(|e| e["textData"] = json!(text))
        };
        let (short, long) = (a.min(b), a.max(b));
        let short_ok = accepted(&server, &channel, &[sized(short)]);
        let long_ok = accepted(&server, &channel, &[sized(long)]);
        prop_assert!(short_ok || !long_ok, "{} refused but {} accepted", short, long);
    }
}
