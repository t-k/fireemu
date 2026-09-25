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
        assert_eq!(ids(&body), ["d1", "d2", "d3", "d4", "d5", "m"], "{value}");
        // The missing document is listed by name alone.
        assert_eq!(
            body["documents"][5],
            json!({"name": "projects/demo-app/databases/(default)/documents/lst/m"})
        );
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

/// A token stays small whatever the listing is ordered on: order values past the bound are
/// left out and the page continues after its last document's current values (FS-DATA-WRITE-LIST
/// review).
#[test]
fn an_ordered_token_stays_small_for_a_large_order_value() {
    let s = state(true);
    let big = "x".repeat(200_000);
    for (id, value) in [
        ("a", format!("{big}1")),
        ("b", format!("{big}2")),
        ("c", format!("{big}3")),
    ] {
        let (status, body) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/big/{id}"),
            json!({"fields": {"s": {"stringValue": value}}}),
        );
        assert_eq!(
            status,
            200,
            "{}",
            &body.to_string()[..200.min(body.to_string().len())]
        );
    }
    let (status, first) = call(
        &s,
        "GET",
        &format!("{DOCS}/big?orderBy=s&pageSize=1&mask.fieldPaths=__name__"),
        Value::Null,
    );
    assert_eq!(status, 200);
    let token = first["nextPageToken"].as_str().unwrap().to_owned();
    assert!(token.len() < 4096, "{} bytes", token.len());
    let (status, next) = call(
        &s,
        "GET",
        &format!("{DOCS}/big?orderBy=s&pageSize=1&mask.fieldPaths=__name__&pageToken={token}"),
        Value::Null,
    );
    assert_eq!(status, 200, "{next}");
    assert!(next["documents"][0]["name"]
        .as_str()
        .unwrap()
        .ends_with("/big/b"));
}

/// The emulator profile reads list parameters as fireemu did before where production's front
/// end would refuse: proto names are ignored and a read time is read by fireemu's own parser.
#[test]
fn the_emulator_profile_adds_no_list_parameter_refusal() {
    let (strict, time) = seeded(true);
    let (emulator, emulator_time) = seeded(false);
    let (status, body) = list(&strict, "page_size=abc");
    assert_eq!(status, 400, "{body}");
    let (status, body) = list(&emulator, "page_size=abc");
    assert_eq!(status, 200, "{body}");
    assert_eq!(ids(&body).len(), 5);
    let lower = |time: &str| time.replace('Z', "z");
    let (status, body) = list(&strict, &format!("readTime={}", lower(&time)));
    assert_eq!(status, 400, "{body}");
    let (status, body) = list(&emulator, &format!("readTime={}", lower(&emulator_time)));
    assert_eq!(status, 200, "{body}");
    // A request field with no local effect is bound, not refused, under strict.
    let (status, body) = list(&strict, "requestOptions.requestTags=t");
    assert_eq!(status, 200, "{body}");
}

/// Inside a transaction an ordered page also continues after the values the token recorded.
#[test]
fn an_ordered_page_in_a_transaction_continues_after_the_recorded_values() {
    let (s, _) = seeded(true);
    let (_, first) = list(&s, "orderBy=a%20desc&pageSize=2");
    let token = first["nextPageToken"].as_str().unwrap().to_owned();
    let (status, body) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/lst/d4"),
        json!({"fields": {"a": {"integerValue": "0"}}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, begun) = call(
        &s,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readOnly": {}}}),
    );
    assert_eq!(status, 200, "{begun}");
    let transaction = begun["transaction"].as_str().unwrap();
    let (status, next) = list(
        &s,
        &format!(
            "orderBy=a%20desc&pageSize=2&pageToken={token}&transaction={}",
            transaction
                .replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D")
        ),
    );
    assert_eq!(status, 200, "{next}");
    assert_eq!(ids(&next), ["d3", "d2"]);
}

/// Each proto-name parameter binds under strict and is ignored under the emulator profile.
#[test]
fn proto_name_parameters_bind_under_strict_only() {
    let (strict, time) = seeded(true);
    let (emulator, _) = seeded(false);
    for s in [&strict, &emulator] {
        let (status, body) = call(
            s,
            "PATCH",
            &format!("{DOCS}/lst/m/sub/x"),
            json!({"fields": {}}),
        );
        assert_eq!(status, 200, "{body}");
    }
    let all = ["d1", "d2", "d3", "d4", "d5"];
    let (status, body) = list(&strict, "page_token=garbage");
    assert_eq!((status, message(&body)), (400, "invalid page token"));
    let (status, body) = list(&emulator, "page_token=garbage");
    assert_eq!((status, ids(&body)), (200, all.map(String::from).to_vec()));
    let (_, body) = list(&strict, "order_by=a%20desc");
    assert_eq!(ids(&body), ["d5", "d4", "d3", "d2", "d1"]);
    let (_, body) = list(&emulator, "order_by=a%20desc");
    assert_eq!(ids(&body), all);
    let (status, body) = list(&strict, "mask.field_paths=__name__");
    assert_eq!(status, 200, "{body}");
    assert_eq!(ids(&body), all);
    assert!(body["documents"][0].get("fields").is_none(), "{body}");
    let (_, body) = list(&emulator, "mask.field_paths=__name__");
    assert!(body["documents"][0].get("fields").is_some(), "{body}");
    let (_, body) = list(&strict, "show_missing=true");
    assert_eq!(ids(&body), ["d1", "d2", "d3", "d4", "d5", "m"]);
    let (_, body) = list(&emulator, "show_missing=true");
    assert_eq!(ids(&body), all);
    let (status, body) = list(&strict, "read_time=yesterday");
    assert_eq!(status, 400);
    assert!(
        message(&body).starts_with("Invalid value at 'read_time'"),
        "{body}"
    );
    let (status, body) = list(&strict, &format!("read_time={time}"));
    assert_eq!((status, ids(&body)), (200, all.map(String::from).to_vec()));
    let (status, body) = list(&emulator, "read_time=yesterday");
    assert_eq!((status, ids(&body)), (200, all.map(String::from).to_vec()));
}

/// A read-write transaction that pages an ordered listing commits: its read set is the whole
/// query, which a commit re-runs (FS-DATA-WRITE-LIST review, round 2).
#[test]
fn a_read_write_transaction_paging_an_ordered_listing_commits() {
    let (s, _) = seeded(true);
    let (status, begun) = call(
        &s,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readWrite": {}}}),
    );
    assert_eq!(status, 200, "{begun}");
    let transaction = begun["transaction"].as_str().unwrap().to_owned();
    let encoded = transaction
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D");
    let (status, first) = list(
        &s,
        &format!("orderBy=a%20desc&pageSize=2&transaction={encoded}"),
    );
    assert_eq!(status, 200, "{first}");
    assert_eq!(ids(&first), ["d5", "d4"]);
    let token = first["nextPageToken"].as_str().unwrap().to_owned();
    let (status, next) = list(
        &s,
        &format!("orderBy=a%20desc&pageSize=2&pageToken={token}&transaction={encoded}"),
    );
    assert_eq!(status, 200, "{next}");
    assert_eq!(ids(&next), ["d3", "d2"]);
    let (status, committed) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"transaction": transaction}),
    );
    assert_eq!(status, 200, "{committed}");
}

/// A token whose recorded order values do not decode is refused as not issued by the service.
#[test]
fn a_token_with_undecodable_order_values_is_refused() {
    use fireemu_adapter_grpc::rest::json::{base64_decode, base64_encode};
    let (s, _) = seeded(true);
    let (_, first) = list(&s, "orderBy=a&pageSize=1");
    let token = first["nextPageToken"].as_str().unwrap();
    let decoded = String::from_utf8(base64_decode(token).unwrap()).unwrap();
    let (head, _) = decoded.rsplit_once('\n').unwrap();
    let forged = base64_encode(format!("{head}\nAAAA").as_bytes());
    let (status, body) = list(
        &s,
        &format!(
            "orderBy=a&pageSize=1&pageToken={}",
            forged
                .replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D")
        ),
    );
    assert_eq!((status, message(&body)), (400, "invalid page token"));
}

/// Inside a transaction `showMissing` lists a missing document by name alone, in name order.
#[test]
fn show_missing_inside_a_transaction_lists_missing_documents_by_name() {
    let (s, _) = seeded(true);
    let (status, body) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/lst/d3a/sub/x"),
        json!({"fields": {}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, begun) = call(
        &s,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readOnly": {}}}),
    );
    assert_eq!(status, 200, "{begun}");
    let transaction = begun["transaction"]
        .as_str()
        .unwrap()
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D");
    let (status, body) = list(&s, &format!("showMissing=true&transaction={transaction}"));
    assert_eq!(status, 200, "{body}");
    assert_eq!(ids(&body), ["d1", "d2", "d3", "d3a", "d4", "d5"]);
    assert_eq!(
        body["documents"][3],
        json!({"name": "projects/demo-app/databases/(default)/documents/lst/d3a"})
    );
}

/// A token whose order values were forged (here one value where the order has two, the name
/// left out) is not refused: tokens are fireemu's own and a forged value only moves the cursor
/// within the same listing, here past every document. Pins today's behaviour (FS-DATA-WRITE-LIST
/// review, round 4).
#[test]
fn a_token_with_forged_order_values_moves_the_cursor_within_its_listing() {
    use fireemu_adapter_grpc::rest::json::{base64_decode, base64_encode};
    use fireemu_proto_firestore::google::firestore::v1 as pb;
    use prost::Message as _;
    let (s, _) = seeded(true);
    let (_, first) = list(&s, "orderBy=a&pageSize=1");
    let token = first["nextPageToken"].as_str().unwrap();
    let decoded = String::from_utf8(base64_decode(token).unwrap()).unwrap();
    let (head, _) = decoded.rsplit_once('\n').unwrap();
    let values = pb::Cursor {
        values: vec![pb::Value {
            value_type: Some(pb::value::ValueType::IntegerValue(100)),
        }],
        before: false,
    }
    .encode_to_vec();
    let forged = base64_encode(format!("{head}\n{}", base64_encode(&values)).as_bytes());
    let (status, body) = list(
        &s,
        &format!(
            "orderBy=a&pageSize=1&pageToken={}",
            forged
                .replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D")
        ),
    );
    assert_eq!((status, &body), (200, &json!({})));
}
