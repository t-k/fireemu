//! REST listDocuments and listCollectionIds as production answers them (FS-DATA-WRITE-LIST,
//! recorded 2026-09-24 in `conformance/fs-data-write-list-production.json`): query parameter
//! binding, value refusals, page tokens, the page-size cap and ordered cursors.

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::{RestRequest, RestState};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const DOCS: &str = "/v1/projects/demo-app/databases/(default)/documents";

fn state(strict: bool) -> RestState {
    let gateway = Gateway {
        enforce_limits: strict,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: if strict {
                IndexValidationPolicy::Production
            } else {
                IndexValidationPolicy::Emulator
            },
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    RestState {
        local: Arc::new(LocalBackend::new(gateway.clone(), clock, 7)),
        gateway: Arc::new(gateway),
        rules: None,
        control_token: None,
        app_check: None,
    }
}

fn call(s: &RestState, method: &str, path_and_query: &str, body: Value) -> (u16, Value) {
    let (path, query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, ""), |(p, q)| (p, q));
    let r = s.handle(&RestRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        browser_metadata: false,
        app_check: Vec::new(),
        body,
    });
    (r.status, r.body)
}

/// Writes `lst/d1`..`lst/d5` with `a` = 1..5; returns the update time of the last write.
fn seeded(strict: bool) -> (RestState, String) {
    let s = state(strict);
    let mut time = String::new();
    for i in 1..=5 {
        let (status, body) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/lst/d{i}"),
            json!({"fields": {"a": {"integerValue": i.to_string()}}}),
        );
        assert_eq!(status, 200, "{body}");
        body["updateTime"].as_str().unwrap().clone_into(&mut time);
    }
    (s, time)
}

fn list(s: &RestState, query: &str) -> (u16, Value) {
    call(s, "GET", &format!("{DOCS}/lst?{query}"), Value::Null)
}

fn ids(body: &Value) -> Vec<String> {
    body["documents"]
        .as_array()
        .map(|documents| {
            documents
                .iter()
                .map(|d| {
                    d["name"]
                        .as_str()
                        .unwrap()
                        .rsplit('/')
                        .next()
                        .unwrap()
                        .to_owned()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn message(body: &Value) -> &str {
    body["error"]["message"].as_str().unwrap_or_default()
}

/// A refusal of the request transcoder: its text, and one `BadRequest` violation for `field`
/// (none for an unbound name).
fn assert_transcoder_refusal(body: &Value, text: &str, field: Option<&str>) {
    assert_eq!(message(body), text, "{body}");
    let violation = &body["error"]["details"][0]["fieldViolations"][0];
    assert_eq!(violation["description"], text, "{body}");
    assert_eq!(
        violation.get("field").and_then(Value::as_str),
        field,
        "{body}"
    );
}

#[test]
fn list_parameters_bind_by_json_and_proto_name_and_the_last_value_wins() {
    let (s, _) = seeded(true);
    let (_, body) = list(&s, "page_size=2");
    assert_eq!(ids(&body), ["d1", "d2"]);
    assert!(body["nextPageToken"].is_string());
    let (_, body) = list(&s, "order_by=a%20desc");
    assert_eq!(ids(&body), ["d5", "d4", "d3", "d2", "d1"]);
    let (_, body) = list(&s, "mask.field_paths=__name__");
    assert!(body["documents"][0].get("fields").is_none(), "{body}");
    let (_, body) = list(&s, "pageSize=1&pageSize=2");
    assert_eq!(ids(&body), ["d1", "d2"]);
}

#[test]
fn an_unknown_list_parameter_is_refused_under_the_strict_profile_only() {
    let text = "Invalid JSON payload received. Unknown name \"unknownParameter\": Cannot bind query parameter. Field 'unknownParameter' could not be found in request message.";
    let (s, _) = seeded(true);
    let (status, body) = list(&s, "unknownParameter=1");
    assert_eq!(status, 400);
    assert_transcoder_refusal(&body, text, None);
    // System parameters are the front end's own.
    let (status, body) = list(&s, "alt=json&prettyPrint=false&key=k");
    assert_eq!(status, 200, "{body}");
    let (s, _) = seeded(false);
    let (status, body) = list(&s, "unknownParameter=1");
    assert_eq!(status, 200, "{body}");
    assert_eq!(ids(&body).len(), 5);
}

#[test]
fn list_parameter_values_are_refused_in_the_transcoder_words() {
    let (s, _) = seeded(true);
    for value in ["abc", "1.5", "1e1", "", "2147483648"] {
        let (status, body) = list(&s, &format!("pageSize={value}"));
        assert_eq!(status, 400, "{value}");
        assert_transcoder_refusal(
            &body,
            &format!("Invalid value at 'page_size' (TYPE_INT32), \"{value}\""),
            Some("page_size"),
        );
    }
    let (status, body) = list(&s, "showMissing=");
    assert_eq!(status, 400);
    assert_transcoder_refusal(
        &body,
        "Invalid value at 'show_missing' (TYPE_BOOL), \"\"",
        Some("show_missing"),
    );
    for (value, text) in [
        ("yesterday", "Illegal timestamp format; timestamps must end with 'Z' or have a valid timezone offset."),
        ("", "Illegal timestamp format; timestamps must end with 'Z' or have a valid timezone offset."),
        ("2099-01-01T00:00:00.1234567891Z", "Timestamp value exceeds limits"),
    ] {
        let (status, body) = list(&s, &format!("readTime={value}"));
        assert_eq!(status, 400, "{value}");
        assert_transcoder_refusal(
            &body,
            &format!("Invalid value at 'read_time' (type.googleapis.com/google.protobuf.Timestamp), Field 'read_time', {text}"),
            Some("read_time"),
        );
    }
    let (status, body) = list(&s, "transaction=AAAA&readTime=2099-01-01T00:00:00Z");
    assert_eq!(status, 400);
    assert_transcoder_refusal(
        &body,
        "Invalid value (oneof), oneof field 'consistency_selector' is already set. Cannot set 'transaction'",
        None,
    );
}

#[test]
fn show_missing_reads_booleans_as_the_front_end_does() {
    let (s, _) = seeded(true);
    let (status, body) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/lst/m/sub/x"),
        json!({"fields": {}}),
    );
    assert_eq!(status, 200, "{body}");
    for value in ["true", "True", "yes", "1", "t"] {
        let (status, body) = list(&s, &format!("showMissing={value}"));
        assert_eq!(status, 200, "{value}: {body}");
        assert_eq!(ids(&body).len(), 6, "{value}");
    }
    for value in ["false", "no", "0", "F"] {
        let (status, body) = list(&s, &format!("showMissing={value}"));
        assert_eq!(status, 200, "{value}: {body}");
        assert_eq!(ids(&body).len(), 5, "{value}");
    }
}

#[test]
fn list_refusals_use_production_texts() {
    let (s, _) = seeded(true);
    for (query, text) in [
        ("pageSize=-1", "Page size must be nonnegative."),
        ("showMissing=true&orderBy=a", "cannot specify an order when show_missing is true"),
        ("orderBy=a..b", "Invalid order by clause \"a..b\"."),
        ("mask.fieldPaths=", "Invalid empty property path string."),
        (
            "mask.fieldPaths=a,b",
            "Invalid property path \"a,b\". Unquoted property paths must match regex ([a-zA-Z_][a-zA-Z_0-9]*), and quoted property paths must match regex (`(?:[^`\\\\]|(?:\\\\.))+`)",
        ),
        ("pageToken=garbage", "invalid page token"),
    ] {
        let (status, body) = list(&s, query);
        assert_eq!((status, message(&body)), (400, text), "{query}");
    }
}

#[test]
fn a_page_holds_at_most_three_hundred_documents() {
    let s = state(true);
    let writes: Vec<Value> = (0..301)
        .map(|i| json!({"update": {"name": format!("projects/demo-app/databases/(default)/documents/big/d{i:03}")}}))
        .collect();
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": writes}),
    );
    assert_eq!(status, 200, "{body}");
    let (_, body) = call(&s, "GET", &format!("{DOCS}/big?pageSize=1000"), Value::Null);
    assert_eq!(body["documents"].as_array().unwrap().len(), 300);
    assert!(body["nextPageToken"].is_string());
    let (_, body) = call(&s, "GET", &format!("{DOCS}/big"), Value::Null);
    assert_eq!(body["documents"].as_array().unwrap().len(), 100);
}

#[test]
fn page_tokens_bind_the_listing_but_not_its_read_time() {
    let (s, time) = seeded(true);
    let (_, first) = list(&s, "pageSize=2");
    let token = first["nextPageToken"].as_str().unwrap().to_owned();
    for query in [
        format!("pageSize=2&orderBy=a&pageToken={token}"),
        format!("pageSize=2&mask.fieldPaths=a&pageToken={token}"),
        format!("pageSize=2&showMissing=true&pageToken={token}"),
    ] {
        let (status, body) = list(&s, &query);
        assert_eq!(
            (status, message(&body)),
            (400, "Invalid page token."),
            "{query}"
        );
    }
    let (status, body) = call(
        &s,
        "GET",
        &format!("{DOCS}/other?pageToken={token}"),
        Value::Null,
    );
    assert_eq!((status, message(&body)), (400, "Invalid page token."));
    // A token issued at a read time continues without it, and the other way round.
    let (_, at) = list(&s, &format!("pageSize=2&readTime={time}"));
    let at_token = at["nextPageToken"].as_str().unwrap().to_owned();
    let (status, body) = list(&s, &format!("pageSize=2&pageToken={at_token}"));
    assert_eq!(status, 200, "{body}");
    assert_eq!(ids(&body), ["d3", "d4"]);
    let (status, body) = list(&s, &format!("pageSize=2&readTime={time}&pageToken={token}"));
    assert_eq!(status, 200, "{body}");
    assert_eq!(ids(&body), ["d3", "d4"]);
}

#[test]
fn an_ordered_page_continues_after_the_values_it_ended_on() {
    let (s, _) = seeded(true);
    let (_, first) = list(&s, "orderBy=a%20desc&pageSize=2");
    assert_eq!(ids(&first), ["d5", "d4"]);
    let token = first["nextPageToken"].as_str().unwrap().to_owned();
    // The last document of the page moves to the end of the order.
    let (status, body) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/lst/d4"),
        json!({"fields": {"a": {"integerValue": "0"}}}),
    );
    assert_eq!(status, 200, "{body}");
    let (_, next) = list(
        &s,
        &format!("orderBy=a%20desc&pageSize=2&pageToken={token}"),
    );
    assert_eq!(ids(&next), ["d3", "d2"]);
}

#[test]
fn list_collection_ids_answers_as_production_does() {
    let (s, _) = seeded(true);
    let (status, body) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/lst/d1/sub/x"),
        json!({"fields": {}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = call(&s, "PATCH", &format!("{DOCS}/zz/x"), json!({"fields": {}}));
    assert_eq!(status, 200, "{body}");
    let time = body["updateTime"].as_str().unwrap().to_owned();
    let ids_of = |parent: &str, body: Value| {
        call(
            &s,
            "POST",
            &format!("{DOCS}{parent}:listCollectionIds"),
            body,
        )
    };
    // No collection: no member.
    let (status, body) = ids_of("/lst/none", json!({}));
    assert_eq!((status, &body), (200, &json!({})));
    // A token is a cursor of collection ids, not bound to its parent or read time.
    let (_, root) = ids_of("", json!({"pageSize": 1, "readTime": time}));
    assert_eq!(root["collectionIds"], json!(["lst"]));
    let token = root["nextPageToken"].as_str().unwrap().to_owned();
    let (status, body) = ids_of("/lst/d1", json!({"pageToken": token}));
    assert_eq!((status, &body), (200, &json!({"collectionIds": ["sub"]})));
    let (status, body) = ids_of("", json!({"pageToken": token}));
    assert_eq!((status, &body), (200, &json!({"collectionIds": ["zz"]})));
    for (request, text, field) in [
        (json!({"pageSize": -1}), "page_size must be greater than or equal to zero.", None),
        (json!({"pageToken": "garbage"}), "invalid page token", None),
        (
            json!({"pageSize": 1.5}),
            "Invalid value at 'page_size' (TYPE_INT32), 1.5",
            Some("page_size"),
        ),
        (
            json!({"pageSize": "2.0"}),
            "Invalid value at 'page_size' (TYPE_INT32), \"2.0\"",
            Some("page_size"),
        ),
        (
            json!({"readTime": ""}),
            "Invalid value at 'read_time' (type.googleapis.com/google.protobuf.Timestamp), Field 'readTime', Illegal timestamp format; timestamps must end with 'Z' or have a valid timezone offset.",
            Some("read_time"),
        ),
        (
            json!({"unknownField": 1}),
            "Invalid JSON payload received. Unknown name \"unknownField\": Cannot find field.",
            Some(""),
        ),
    ] {
        let (status, body) = ids_of("", request.clone());
        assert_eq!(status, 400, "{request}: {body}");
        if field.is_none() {
            assert_eq!(message(&body), text, "{request}");
        } else {
            assert_transcoder_refusal(&body, text, field.filter(|f| !f.is_empty()));
        }
    }
    let (status, body) = ids_of("/lst", json!({}));
    assert_eq!(status, 400);
    assert_eq!(
        message(&body),
        "Document parent name \"projects/demo-app/databases/(default)/documents/lst\" lacks \"/\" at index 51."
    );
}
