//! `WebChannel` transport at the hub level: handshake framing, back-channel delivery with
//! contiguous array ids, forward-channel acknowledgements and error payloads.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::RestState;
use fireemu_adapter_grpc::rules::RulesEnforcer;
use fireemu_adapter_grpc::webchannel::{ChannelRequest, ChannelResponse, Hub, StreamKind};
use fireemu_core_auth::jwt::{base64url_encode, TokenAcceptance};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet, IndexValidationPolicy,
    PlanningContext,
};
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::CollectionId;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};
use tokio_stream::StreamExt;

const DB: &str = "projects/demo-app/databases/(default)";
const RULES_ALLOW_ALL: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read, write: if true; } } }";

fn hub(rules: Option<&str>) -> Hub {
    hub_with_acceptance(rules, TokenAcceptance::Verified)
}

fn hub_with_acceptance(rules: Option<&str>, acceptance: TokenAcceptance) -> Hub {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Conservative,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let local = Arc::new(LocalBackend::new(gateway.clone(), clock.clone(), 7));
    let rules = rules.map(|src| {
        let auth = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(3),
            TotpPolicy::default(),
        )));
        Arc::new(
            RulesEnforcer::new(
                Arc::new(RulesetSlot::new(LoadedRules::from_source(src).unwrap())),
                auth,
                clock,
            )
            .with_token_acceptance(acceptance),
        )
    });
    Hub::new(Arc::new(RestState {
        local,
        gateway: Arc::new(gateway),
        rules,
        app_check: None,
    }))
}

fn mock_user_token(sub: &str, project: &str) -> String {
    let header = base64url_encode(br#"{"alg":"none","type":"JWT"}"#);
    let payload = base64url_encode(
        format!(r#"{{"aud":"{project}","exp":3600,"iat":0,"sub":"{sub}"}}"#).as_bytes(),
    );
    format!("{header}.{payload}.")
}

fn auth_handshake(hub: &Hub, project: &str, token: &str) -> (u16, String) {
    let database = format!("projects/{project}/databases/(default)");
    let (status, _, body) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("database", &database), ("VER", "8"), ("RID", "1")]),
        authorization: Some(format!("Bearer {token}")),
        app_check: Vec::new(),
        origin: None,
        body: String::new(),
    }));
    (status, body)
}

#[tokio::test]
async fn webchannel_binds_unknown_mock_tokens_to_the_requested_project() {
    let token = mock_user_token("alice", "demo-app-w0");
    let firebase = hub_with_acceptance(Some(RULES_ALLOW_ALL), TokenAcceptance::EmulatorMock);
    assert_eq!(auth_handshake(&firebase, "demo-app-w0", &token).0, 200);
    assert_eq!(auth_handshake(&firebase, "demo-app", &token).0, 401);

    let strict = hub_with_acceptance(Some(RULES_ALLOW_ALL), TokenAcceptance::Verified);
    assert_eq!(auth_handshake(&strict, "demo-app-w0", &token).0, 401);

    let header = base64url_encode(br#"{"alg":"RS256","typ":"JWT","kid":"nope"}"#);
    let payload = base64url_encode(br#"{"aud":"demo-app-w0","exp":3600,"iat":0,"sub":"alice"}"#);
    assert_eq!(
        auth_handshake(
            &firebase,
            "demo-app-w0",
            &format!("{header}.{payload}.AAAA")
        )
        .0,
        401
    );
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn full(r: ChannelResponse) -> (u16, Vec<(&'static str, String)>, String) {
    match r {
        ChannelResponse::Full {
            status,
            headers,
            body,
        } => (status, headers, body),
        ChannelResponse::Stream { .. } => panic!("expected a full response"),
    }
}

/// Parses `<len>\n<json>` chunks into their JSON arrays.
fn chunks(text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let (len, tail) = rest.split_once('\n').unwrap();
        let n: usize = len.parse().unwrap();
        out.push(serde_json::from_str(&tail[..n]).unwrap());
        rest = &tail[n..];
    }
    out
}

fn read_batch(seen: &mut Vec<u64>, text: &str) {
    for arrays in chunks(text) {
        for a in arrays.as_array().unwrap() {
            seen.push(a[0].as_u64().unwrap());
        }
    }
}

fn listen_target(id: i32, collection: &str) -> String {
    json!({
        "database": DB,
        "addTarget": {
            "targetId": id,
            "query": {"parent": format!("{DB}/documents"), "structuredQuery": {"from": [{"collectionId": collection}]}}
        }
    })
    .to_string()
}

#[tokio::test]
async fn handshake_backchannel_and_forward_channel_keep_array_ids_contiguous() {
    let hub = hub(None);
    let first = listen_target(2, "open");
    let (status, headers, body) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("database", DB), ("VER", "8"), ("RID", "1"), ("CVER", "22")]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[
            ("headers", "X-Goog-Api-Client:test\r\n"),
            ("count", "1"),
            ("ofs", "0"),
            ("req0___data__", &first),
        ]),
    }));
    assert_eq!(status, 200);
    let sid = headers
        .iter()
        .find(|(k, _)| *k == "x-http-session-id")
        .map(|(_, v)| v.clone())
        .unwrap();
    let handshake = chunks(&body);
    assert_eq!(handshake[0][0][0], 0);
    assert_eq!(handshake[0][0][1][0], "c");
    assert_eq!(handshake[0][0][1][1], sid);

    // Give the stream task a moment to answer the first message.
    let ChannelResponse::Stream { mut body, .. } = hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "GET".to_owned(),
        params: params(&[
            ("SID", &sid),
            ("RID", "rpc"),
            ("AID", "0"),
            ("CI", "0"),
            ("TYPE", "xmlhttp"),
        ]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: String::new(),
    }) else {
        panic!("expected a streamed back channel");
    };
    let mut seen_ids: Vec<u64> = Vec::new();
    let first_chunk = tokio::time::timeout(std::time::Duration::from_secs(2), body.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    read_batch(&mut seen_ids, std::str::from_utf8(&first_chunk).unwrap());
    assert!(seen_ids.len() >= 3, "ADD, CURRENT, NO_CHANGE: {seen_ids:?}");

    // A second target through the forward channel; the response reports the back channel.
    let second = listen_target(4, "other");
    let (status, _, body_text) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("SID", &sid), ("RID", "2"), ("AID", "1")]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[("count", "1"), ("ofs", "1"), ("req0___data__", &second)]),
    }));
    assert_eq!(status, 200);
    let ack = chunks(&body_text);
    assert_eq!(ack[0][0], 1, "back channel present");
    // Drain until the global boundary of the second snapshot arrives.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline && seen_ids.len() < 8 {
        if let Ok(Some(Ok(chunk))) =
            tokio::time::timeout(std::time::Duration::from_millis(500), body.next()).await
        {
            read_batch(&mut seen_ids, std::str::from_utf8(&chunk).unwrap());
        }
    }
    let expected: Vec<u64> = (1..=seen_ids.len() as u64).collect();
    assert_eq!(
        seen_ids, expected,
        "array ids are contiguous and none is skipped"
    );

    // A retried map (same ofs) is ignored; an unknown session is a 400.
    let (status, _, _) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("SID", &sid), ("RID", "3"), ("AID", "4")]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[("count", "1"), ("ofs", "1"), ("req0___data__", &second)]),
    }));
    assert_eq!(status, 200);
    let (status, _, _) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("SID", "nope"), ("RID", "4"), ("AID", "0")]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: String::new(),
    }));
    assert_eq!(status, 400);
}

#[tokio::test]
async fn a_long_poll_stays_attached_until_its_response_body_is_released() {
    let hub = hub(None);
    let first = listen_target(2, "open");
    let (status, headers, _) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("database", DB), ("VER", "8"), ("RID", "1"), ("CVER", "22")]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[("count", "1"), ("ofs", "0"), ("req0___data__", &first)]),
    }));
    assert_eq!(status, 200);
    let sid = headers
        .iter()
        .find(|(key, _)| *key == "x-http-session-id")
        .map(|(_, value)| value.clone())
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let ChannelResponse::Stream { mut body, .. } = hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "GET".to_owned(),
        params: params(&[
            ("SID", &sid),
            ("RID", "rpc"),
            ("AID", "0"),
            ("CI", "1"),
            ("TYPE", "xmlhttp"),
        ]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: String::new(),
    }) else {
        panic!("expected a streamed back channel");
    };

    // Consume the queued batch but leave the response stream alive before its final EOF poll.
    // The HTTP layer is still responsible for this response throughout that interval.
    let first_chunk = tokio::time::timeout(std::time::Duration::from_secs(2), body.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!first_chunk.is_empty());
    let second = listen_target(4, "other");
    let forward = || {
        full(hub.handle(&ChannelRequest {
            kind: StreamKind::Listen,
            method: "POST".to_owned(),
            params: params(&[("SID", &sid), ("RID", "2"), ("AID", "0")]),
            authorization: None,
            app_check: Vec::new(),
            origin: None,
            body: form(&[("count", "1"), ("ofs", "1"), ("req0___data__", &second)]),
        }))
    };
    let (status, _, body_text) = forward();
    assert_eq!(status, 200);
    assert_eq!(
        chunks(&body_text)[0][0],
        1,
        "the back channel remains attached until its HTTP response reaches EOF"
    );

    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(2), body.next())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(chunks(&forward().2)[0][0], 0);
}

#[tokio::test]
async fn dropping_a_body_releases_only_the_generation_it_owns() {
    let hub = hub(None);
    let first = listen_target(2, "open");
    let (status, headers, _) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("database", DB), ("VER", "8"), ("RID", "1"), ("CVER", "22")]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[("count", "1"), ("ofs", "0"), ("req0___data__", &first)]),
    }));
    assert_eq!(status, 200);
    let sid = headers
        .iter()
        .find(|(key, _)| *key == "x-http-session-id")
        .map(|(_, value)| value.clone())
        .unwrap();

    let open_body = || {
        let ChannelResponse::Stream { body, .. } = hub.handle(&ChannelRequest {
            kind: StreamKind::Listen,
            method: "GET".to_owned(),
            params: params(&[
                ("SID", &sid),
                ("RID", "rpc"),
                ("AID", "0"),
                ("CI", "0"),
                ("TYPE", "xmlhttp"),
            ]),
            authorization: None,
            app_check: Vec::new(),
            origin: None,
            body: String::new(),
        }) else {
            panic!("expected a streamed back channel");
        };
        body
    };
    let forward_attached = || {
        let (_, _, body) = full(hub.handle(&ChannelRequest {
            kind: StreamKind::Listen,
            method: "POST".to_owned(),
            params: params(&[("SID", &sid), ("RID", "2"), ("AID", "0")]),
            authorization: None,
            app_check: Vec::new(),
            origin: None,
            body: form(&[("count", "0"), ("ofs", "1")]),
        }));
        chunks(&body)[0][0].as_u64().unwrap()
    };

    let superseded = open_body();
    let current = open_body();
    drop(superseded);
    assert_eq!(
        forward_attached(),
        1,
        "a stale body cannot release its replacement"
    );
    drop(current);
    assert_eq!(
        forward_attached(),
        0,
        "dropping the current body releases it"
    );
}

#[tokio::test]
async fn rules_denials_reach_the_browser_as_target_removals() {
    let hub = hub(Some(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /closed/{id} { allow read, write: if false; } } }",
    ));
    let first = listen_target(9, "closed");
    let (status, headers, _) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("database", DB), ("VER", "8"), ("RID", "1")]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[("count", "1"), ("ofs", "0"), ("req0___data__", &first)]),
    }));
    assert_eq!(status, 200);
    let sid = headers
        .iter()
        .find(|(k, _)| *k == "x-http-session-id")
        .map(|(_, v)| v.clone())
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let ChannelResponse::Stream { mut body, .. } = hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "GET".to_owned(),
        params: params(&[
            ("SID", &sid),
            ("RID", "rpc"),
            ("AID", "0"),
            ("CI", "1"),
            ("TYPE", "xmlhttp"),
        ]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: String::new(),
    }) else {
        panic!("expected a streamed back channel");
    };
    let chunk = tokio::time::timeout(std::time::Duration::from_secs(2), body.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let arrays = chunks(std::str::from_utf8(&chunk).unwrap());
    let payloads: Vec<&Value> = arrays[0]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| &a[1][0])
        .collect();
    assert_eq!(payloads[0]["targetChange"]["targetChangeType"], "ADD");
    assert_eq!(payloads[1]["targetChange"]["targetChangeType"], "REMOVE");
    assert_eq!(payloads[1]["targetChange"]["cause"]["code"], 7);
    // CI=1 (long polling): the response ends after the first batch.
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(2), body.next())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn chunks_count_utf16_units_and_maps_are_delivered_in_id_order() {
    let hub = hub(None);
    // Handshake with map 0; then maps 2 and 1 arrive out of order (2 first).
    let first = listen_target(2, "open");
    let (status, headers, _) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("database", DB), ("VER", "8"), ("RID", "1")]),
        authorization: None,
        app_check: Vec::new(),
        origin: Some("http://localhost:5173".to_owned()),
        body: form(&[("count", "1"), ("ofs", "0"), ("req0___data__", &first)]),
    }));
    assert_eq!(status, 200);
    let sid = headers
        .iter()
        .find(|(k, _)| *k == "x-http-session-id")
        .map(|(_, v)| v.clone())
        .unwrap();
    assert_eq!(sid.len(), 32, "128-bit session id");
    // Another origin cannot use the session; a non-loopback origin is refused outright.
    let (status, _, body) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("SID", &sid), ("RID", "2"), ("AID", "0")]),
        authorization: None,
        app_check: Vec::new(),
        origin: Some("http://localhost:9999".to_owned()),
        body: form(&[("count", "0"), ("ofs", "1")]),
    }));
    assert_eq!((status, body.as_str()), (400, "Error: Unknown SID"));
    let (status, _, _) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("database", DB), ("VER", "8"), ("RID", "1")]),
        authorization: None,
        app_check: Vec::new(),
        origin: Some("https://evil.example".to_owned()),
        body: String::new(),
    }));
    assert_eq!(status, 403);

    // Map 2 (target 6) before map 1 (target 4): the stream must see 4 before 6.
    let second = listen_target(4, "open");
    let third = listen_target(6, "open");
    let send = |ofs: &str, data: &str| ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("SID", &sid), ("RID", "3"), ("AID", "0")]),
        authorization: None,
        app_check: Vec::new(),
        origin: Some("http://localhost:5173".to_owned()),
        body: form(&[("count", "1"), ("ofs", ofs), ("req0___data__", data)]),
    };
    assert_eq!(full(hub.handle(&send("2", &third))).0, 200);
    assert_eq!(full(hub.handle(&send("1", &second))).0, 200);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let ChannelResponse::Stream { mut body, .. } = hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "GET".to_owned(),
        params: params(&[
            ("SID", &sid),
            ("RID", "rpc"),
            ("AID", "0"),
            ("CI", "1"),
            ("TYPE", "xmlhttp"),
        ]),
        authorization: None,
        app_check: Vec::new(),
        origin: Some("http://localhost:5173".to_owned()),
        body: String::new(),
    }) else {
        panic!("expected a streamed back channel");
    };
    let chunk = tokio::time::timeout(std::time::Duration::from_secs(2), body.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = std::str::from_utf8(&chunk).unwrap();
    let arrays = chunks(text);
    let adds: Vec<i64> = arrays[0]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| {
            let tc = &a[1][0]["targetChange"];
            (tc["targetChangeType"] == "ADD").then(|| tc["targetIds"][0].as_i64().unwrap())
        })
        .collect();
    assert_eq!(adds, vec![2, 4, 6], "maps delivered in id order");

    // Non-ASCII payloads: the length prefix counts UTF-16 code units.
    let (len, rest) = chunk_parts("13\n[[1,[\"日本語\"]]]");
    assert_eq!(len, 13);
    assert_eq!(rest.encode_utf16().count(), 13);
    assert_ne!(rest.len(), 13, "byte length differs from the UTF-16 length");
}

fn chunk_parts(text: &str) -> (usize, &str) {
    let (len, rest) = text.split_once('\n').unwrap();
    (len.parse().unwrap(), rest)
}

/// A hub whose strict gateway declares one composite index: `tasks` under an `ownerId`
/// equality ordered by `createdAt` descending.
fn indexed_hub() -> Hub {
    let mut indexes = IndexSet::default();
    indexes.add_composite(IndexDefinition {
        collection_group: CollectionId::try_new("tasks").unwrap(),
        query_scope: IndexQueryScope::Collection,
        fields: vec![
            IndexField {
                path: FieldPath::parse("ownerId").unwrap(),
                mode: IndexFieldMode::Ascending,
            },
            IndexField {
                path: FieldPath::parse("createdAt").unwrap(),
                mode: IndexFieldMode::Descending,
            },
        ],
    });
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Conservative,
        },
        indexes,
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let local = Arc::new(LocalBackend::new(gateway.clone(), clock, 7));
    Hub::new(Arc::new(RestState {
        local,
        gateway: Arc::new(gateway),
        rules: None,
        app_check: None,
    }))
}

/// `where ownerId == "u1" order by <field> desc` on `tasks`, in the JSON shape the browser
/// SDK puts on the wire.
fn owner_ordered_target(id: i32, order_field: &str) -> String {
    json!({
        "database": DB,
        "addTarget": {
            "targetId": id,
            "query": {
                "parent": format!("{DB}/documents"),
                "structuredQuery": {
                    "from": [{"collectionId": "tasks"}],
                    "where": {"fieldFilter": {
                        "field": {"fieldPath": "ownerId"},
                        "op": "EQUAL",
                        "value": {"stringValue": "u1"}
                    }},
                    "orderBy": [{"field": {"fieldPath": order_field}, "direction": "DESCENDING"}]
                }
            }
        }
    })
    .to_string()
}

/// FS-WEB-1: the failing `AddTarget` rides along with the handshake, so the session must
/// stay open long enough for the browser to attach its first back channel and read the
/// cause there. Closing the session instead answers the back channel with `Unknown SID`,
/// which the SDK reports as `unavailable` rather than `failed-precondition`.
#[tokio::test]
async fn a_missing_index_on_the_opening_target_reaches_the_first_back_channel() {
    let hub = indexed_hub();
    let opening = owner_ordered_target(31, "updatedAt");
    let (status, headers, _) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("database", DB), ("VER", "8"), ("RID", "1")]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[("count", "1"), ("ofs", "0"), ("req0___data__", &opening)]),
    }));
    assert_eq!(status, 200);
    let sid = headers
        .iter()
        .find(|(k, _)| *k == "x-http-session-id")
        .map(|(_, v)| v.clone())
        .unwrap();
    // The stream task answers the opening message before the back channel exists.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let response = hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "GET".to_owned(),
        params: params(&[
            ("SID", &sid),
            ("RID", "rpc"),
            ("AID", "0"),
            ("CI", "1"),
            ("TYPE", "xmlhttp"),
        ]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: String::new(),
    });
    let ChannelResponse::Stream { mut body, .. } = response else {
        panic!("the session is still open: the back channel must not be an Unknown SID reply");
    };
    let chunk = tokio::time::timeout(std::time::Duration::from_secs(2), body.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let arrays = chunks(std::str::from_utf8(&chunk).unwrap());
    let payloads: Vec<&Value> = arrays[0]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| &a[1][0])
        .collect();
    let removal = payloads
        .iter()
        .find(|p| p["targetChange"]["targetChangeType"] == "REMOVE")
        .expect("the rejected target is removed, not delivered as a stream error");
    assert_eq!(removal["targetChange"]["targetIds"][0], 31);
    assert_eq!(removal["targetChange"]["cause"]["code"], 9);
    let message = removal["targetChange"]["cause"]["message"]
        .as_str()
        .unwrap();
    assert!(
        message.contains("The query requires an index.") && message.contains("updatedAt"),
        "the actionable diagnostic reaches the browser: {message}"
    );
    assert!(
        payloads.iter().all(|p| p.get("error").is_none()),
        "no stream-level error envelope: {payloads:?}"
    );

    // The session survives: a covered query on the same channel still works.
    let covered = owner_ordered_target(32, "createdAt");
    let (status, _, ack) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("SID", &sid), ("RID", "2"), ("AID", "0")]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[("count", "1"), ("ofs", "1"), ("req0___data__", &covered)]),
    }));
    assert_eq!(status, 200, "the session is still known: {ack}");
}
