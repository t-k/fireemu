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
use fireemu_proto_firestore::google::firestore::v1 as pb;
use serde_json::{json, Value};
use tokio_stream::StreamExt;

const DB: &str = "projects/demo-app/databases/(default)";
const RULES_ALLOW_ALL: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read, write: if true; } } }";

fn hub(rules: Option<&str>) -> Hub {
    hub_with_acceptance(rules, TokenAcceptance::Verified)
}

fn hub_with_acceptance(rules: Option<&str>, acceptance: TokenAcceptance) -> Hub {
    hub_and_local(rules, acceptance).0
}

fn hub_and_local(rules: Option<&str>, acceptance: TokenAcceptance) -> (Hub, Arc<LocalBackend>) {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
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
    let hub = Hub::new(Arc::new(RestState {
        local: local.clone(),
        gateway: Arc::new(gateway),
        rules,
        app_check: None,
    }));
    (hub, local)
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

fn remove_target(id: i32) -> String {
    json!({"database": DB, "removeTarget": id}).to_string()
}

fn set_write(name: &str, revision: i64) -> pb::Write {
    pb::Write {
        operation: Some(pb::write::Operation::Update(pb::Document {
            name: format!("{DB}/documents/{name}"),
            fields: [(
                "revision".to_owned(),
                pb::Value {
                    value_type: Some(pb::value::ValueType::IntegerValue(revision)),
                },
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn commit(local: &LocalBackend, writes: Vec<pb::Write>) {
    local
        .commit(&pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .unwrap();
}

fn open_listen_session(hub: &Hub, target: &str) -> String {
    let (status, headers, _) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("database", DB), ("VER", "8"), ("RID", "1")]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[("count", "1"), ("ofs", "0"), ("req0___data__", target)]),
    }));
    assert_eq!(status, 200);
    headers
        .into_iter()
        .find(|(key, _)| *key == "x-http-session-id")
        .map(|(_, value)| value)
        .unwrap()
}

fn send_map(hub: &Hub, sid: &str, rid: &str, aid: u64, offset: u64, data: &str) {
    let (status, _, _) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: params(&[("SID", sid), ("RID", rid), ("AID", &aid.to_string())]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[
            ("count", "1"),
            ("ofs", &offset.to_string()),
            ("req0___data__", data),
        ]),
    }));
    assert_eq!(status, 200);
}

async fn read_long_poll(hub: &Hub, sid: &str, aid: u64) -> Value {
    read_long_poll_kind(hub, StreamKind::Listen, sid, aid).await
}

async fn read_long_poll_kind(hub: &Hub, kind: StreamKind, sid: &str, aid: u64) -> Value {
    let response = hub.handle(&ChannelRequest {
        kind,
        method: "GET".to_owned(),
        params: params(&[
            ("SID", sid),
            ("RID", "rpc"),
            ("AID", &aid.to_string()),
            ("CI", "1"),
            ("TO", "1000"),
            ("TYPE", "xmlhttp"),
        ]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: String::new(),
    });
    let ChannelResponse::Stream { mut body, .. } = response else {
        let (status, _, body) = full(response);
        panic!("expected a streamed back channel, got HTTP {status}: {body}");
    };
    let chunk = tokio::time::timeout(std::time::Duration::from_secs(2), body.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(body.next().await.is_none());
    let parsed = chunks(std::str::from_utf8(&chunk).unwrap());
    assert_eq!(parsed.len(), 1);
    parsed.into_iter().next().unwrap()
}

fn open_write_session(hub: &Hub) -> String {
    let request = json!({"database": DB}).to_string();
    let (status, headers, _) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Write,
        method: "POST".to_owned(),
        params: params(&[("database", DB), ("VER", "8"), ("RID", "1")]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[("count", "1"), ("ofs", "0"), ("req0___data__", &request)]),
    }));
    assert_eq!(status, 200);
    headers
        .iter()
        .find(|(name, _)| *name == "x-http-session-id")
        .map(|(_, value)| value.clone())
        .expect("write handshake must return a session ID")
}

fn last_array_id(batch: &Value) -> u64 {
    batch.as_array().unwrap().last().unwrap()[0]
        .as_u64()
        .unwrap()
}

fn response_payloads(batch: &Value) -> Vec<&Value> {
    batch
        .as_array()
        .unwrap()
        .iter()
        .map(|array| &array[1][0])
        .collect()
}

#[tokio::test]
async fn an_unacknowledged_committed_batch_is_replayed_with_the_same_array_ids() {
    let hub = hub(None);
    let sid = open_listen_session(&hub, &listen_target(2, "replay"));

    let first = read_long_poll(&hub, &sid, 0).await;
    let replay = read_long_poll(&hub, &sid, 0).await;

    assert_eq!(
        replay, first,
        "response commitment is not client acknowledgement"
    );
    let ids = first
        .as_array()
        .unwrap()
        .iter()
        .map(|array| array[0].as_u64().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(ids, (1..=ids.len() as u64).collect::<Vec<_>>());
}

async fn deny_one_write(hub: &Hub) -> (String, u64, String) {
    let sid = open_write_session(hub);
    let handshake = read_long_poll_kind(hub, StreamKind::Write, &sid, 0).await;
    let handshake_aid = last_array_id(&handshake);
    let stream_token = response_payloads(&handshake)[0]["streamToken"]
        .as_str()
        .expect("write handshake must return a stream token");
    let denied_write = json!({
        "streamToken": stream_token,
        "writes": [{
            "update": {
                "name": format!("{DB}/documents/closed/a"),
                "fields": {"value": {"integerValue": "1"}}
            }
        }]
    })
    .to_string();
    let (status, _, _) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Write,
        method: "POST".to_owned(),
        params: params(&[
            ("SID", &sid),
            ("RID", "2"),
            ("AID", &handshake_aid.to_string()),
        ]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[
            ("count", "1"),
            ("ofs", "1"),
            ("req0___data__", &denied_write),
        ]),
    }));
    assert_eq!(status, 200);
    (sid, handshake_aid, denied_write)
}

async fn wait_for_terminal_aid_without_backchannel(
    hub: &Hub,
    sid: &str,
    handshake_aid: u64,
) -> u64 {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let (status, _, body) = full(hub.handle(&ChannelRequest {
                kind: StreamKind::Write,
                method: "POST".to_owned(),
                params: params(&[
                    ("SID", sid),
                    ("RID", "terminal-probe"),
                    ("AID", &handshake_aid.to_string()),
                ]),
                authorization: None,
                app_check: Vec::new(),
                origin: None,
                body: form(&[("count", "0"), ("ofs", "2")]),
            }));
            assert_eq!(status, 200, "terminal probe failed: {body}");
            let acknowledgement = chunks(&body);
            let aid = acknowledgement[0][1]
                .as_u64()
                .expect("forward acknowledgement must include the last generated AID");
            if aid > handshake_aid {
                break aid;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("terminal array was not queued without a backchannel")
}

fn send_write_map(
    hub: &Hub,
    sid: &str,
    rid: &str,
    aid: u64,
    offset: u64,
    message: &str,
) -> (u16, String) {
    let (status, _, body) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Write,
        method: "POST".to_owned(),
        params: params(&[("SID", sid), ("RID", rid), ("AID", &aid.to_string())]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[
            ("count", "1"),
            ("ofs", &offset.to_string()),
            ("req0___data__", message),
        ]),
    }));
    (status, body)
}

#[tokio::test]
async fn rules_denied_write_terminal_error_survives_until_client_acknowledgement() {
    let (hub, local) = hub_and_local(
        Some(
            "rules_version = '2'; service cloud.firestore { match /databases/{d}/documents { match /closed/{id} { allow read, write: if false; } match /allowed/{id} { allow read, write: if true; } } }",
        ),
        TokenAcceptance::Verified,
    );
    let (sid, handshake_aid, _denied_write) = deny_one_write(&hub).await;
    let denied_aid = wait_for_terminal_aid_without_backchannel(&hub, &sid, handshake_aid).await;

    let pipelined_write = json!({
        "writes": [{
            "update": {
                "name": format!("{DB}/documents/allowed/pipelined"),
                "fields": {"value": {"integerValue": "1"}}
            }
        }]
    })
    .to_string();
    let (status, body) = send_write_map(&hub, &sid, "3", handshake_aid, 2, &pipelined_write);
    assert_eq!(
        status, 200,
        "a terminal RPC result must not become an HTTP transport failure: {body}"
    );
    assert_eq!(chunks(&body)[0][1], denied_aid);

    let denied = read_long_poll_kind(&hub, StreamKind::Write, &sid, handshake_aid).await;
    let denied_aid = last_array_id(&denied);
    assert_eq!(
        response_payloads(&denied)[0]["error"]["status"],
        "PERMISSION_DENIED",
        "unexpected write result: {denied}"
    );
    let (status, _, body) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Write,
        method: "GET".to_owned(),
        params: params(&[
            ("SID", &sid),
            ("RID", "wrong-origin"),
            ("AID", &handshake_aid.to_string()),
            ("CI", "1"),
        ]),
        authorization: None,
        app_check: Vec::new(),
        origin: Some("http://localhost:5173".to_owned()),
        body: String::new(),
    }));
    assert_eq!((status, body.as_str()), (400, "Error: Unknown SID"));
    assert_eq!(
        read_long_poll_kind(&hub, StreamKind::Write, &sid, handshake_aid).await,
        denied,
        "HTTP response commitment must not acknowledge the terminal array"
    );

    assert_eq!(
        local
            .get_document(
                &pb::GetDocumentRequest {
                    name: format!("{DB}/documents/allowed/pipelined"),
                    ..Default::default()
                },
                &fireemu_adapter_grpc::rules::allow_all_reads,
            )
            .unwrap_err()
            .code(),
        tonic::Code::NotFound,
        "a map sent after stream termination must not mutate Firestore"
    );

    let (status, _, body) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Write,
        method: "POST".to_owned(),
        params: params(&[
            ("SID", &sid),
            ("RID", "4"),
            ("AID", &denied_aid.to_string()),
        ]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[("count", "0"), ("ofs", "2")]),
    }));
    assert_eq!(status, 200, "terminal acknowledgement failed: {body}");
    let (status, _, body) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Write,
        method: "POST".to_owned(),
        params: params(&[
            ("SID", &sid),
            ("RID", "5"),
            ("AID", &denied_aid.to_string()),
        ]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[("count", "0"), ("ofs", "2")]),
    }));
    assert_eq!((status, body.as_str()), (400, "Error: Unknown SID"));
}

#[tokio::test]
async fn terminal_backchannel_ack_returns_a_framed_end_without_reattaching() {
    let hub = hub(Some(
        "rules_version = '2'; service cloud.firestore { match /databases/{d}/documents { match /closed/{id} { allow read, write: if false; } } }",
    ));
    let (sid, handshake_aid, _write) = deny_one_write(&hub).await;
    wait_for_terminal_aid_without_backchannel(&hub, &sid, handshake_aid).await;
    let denied = read_long_poll_kind(&hub, StreamKind::Write, &sid, handshake_aid).await;
    let denied_aid = last_array_id(&denied);

    let (status, _, body) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Write,
        method: "GET".to_owned(),
        params: params(&[
            ("SID", &sid),
            ("RID", "terminal-ack"),
            ("AID", &denied_aid.to_string()),
            ("CI", "1"),
            ("TYPE", "xmlhttp"),
        ]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: String::new(),
    }));
    assert_eq!(status, 200);
    assert_eq!(chunks(&body), vec![json!([[denied_aid, ["noop"]]])]);

    let (status, _, body) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Write,
        method: "GET".to_owned(),
        params: params(&[
            ("SID", &sid),
            ("RID", "after-terminal-ack"),
            ("AID", &denied_aid.to_string()),
            ("CI", "1"),
        ]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: String::new(),
    }));
    assert_eq!((status, body.as_str()), (400, "Error: Unknown SID"));
}

#[tokio::test]
async fn explicit_terminate_releases_an_unacknowledged_terminal_session() {
    let hub = hub(Some(
        "rules_version = '2'; service cloud.firestore { match /databases/{d}/documents { match /closed/{id} { allow read, write: if false; } } }",
    ));
    let (sid, handshake_aid, _write) = deny_one_write(&hub).await;
    wait_for_terminal_aid_without_backchannel(&hub, &sid, handshake_aid).await;
    let denied = read_long_poll_kind(&hub, StreamKind::Write, &sid, handshake_aid).await;
    assert_eq!(
        response_payloads(&denied)[0]["error"]["status"],
        "PERMISSION_DENIED"
    );

    let (status, _, body) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Write,
        method: "GET".to_owned(),
        params: params(&[("SID", &sid), ("TYPE", "terminate")]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: String::new(),
    }));
    assert_eq!((status, body.as_str()), (200, ""));
    let (status, _, body) = full(hub.handle(&ChannelRequest {
        kind: StreamKind::Write,
        method: "POST".to_owned(),
        params: params(&[("SID", &sid), ("RID", "3"), ("AID", "1")]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: form(&[("count", "0"), ("ofs", "2")]),
    }));
    assert_eq!((status, body.as_str()), (400, "Error: Unknown SID"));
}

#[tokio::test]
async fn remove_readd_retry_and_commits_preserve_the_target_lifetime_boundary() {
    let (hub, local) = hub_and_local(None, TokenAcceptance::Verified);
    commit(
        &local,
        vec![set_write("first/a", 0), set_write("second/b", 0)],
    );
    let sid = open_listen_session(&hub, &listen_target(7, "first"));
    let initial = read_long_poll(&hub, &sid, 0).await;
    let initial_aid = last_array_id(&initial);
    assert!(response_payloads(&initial).iter().any(|payload| {
        payload["documentChange"]["document"]["name"]
            .as_str()
            .is_some_and(|name| name.ends_with("/first/a"))
    }));

    let remove = remove_target(7);
    send_map(&hub, &sid, "2", initial_aid, 1, &remove);
    send_map(&hub, &sid, "3", initial_aid, 1, &remove);
    let removed = read_long_poll(&hub, &sid, initial_aid).await;
    let removed_aid = last_array_id(&removed);
    assert_eq!(
        response_payloads(&removed)
            .iter()
            .filter(|payload| payload["targetChange"]["targetChangeType"] == "REMOVE")
            .count(),
        1,
        "a retried forward map removes one target lifetime once"
    );

    commit(&local, vec![set_write("first/late", 1)]);
    send_map(&hub, &sid, "4", removed_aid, 2, &listen_target(7, "second"));
    let readded = read_long_poll(&hub, &sid, removed_aid).await;
    let readded_aid = last_array_id(&readded);
    let readded_payloads = response_payloads(&readded);
    assert!(readded_payloads.iter().any(|payload| {
        payload["documentChange"]["document"]["name"]
            .as_str()
            .is_some_and(|name| name.ends_with("/second/b"))
    }));
    assert!(readded_payloads.iter().all(|payload| {
        !payload["documentChange"]["document"]["name"]
            .as_str()
            .is_some_and(|name| name.ends_with("/first/late"))
    }));

    commit(
        &local,
        vec![set_write("first/stale", 2), set_write("second/c", 1)],
    );
    let updated = read_long_poll(&hub, &sid, readded_aid).await;
    let changed_names = response_payloads(&updated)
        .into_iter()
        .filter_map(|payload| payload["documentChange"]["document"]["name"].as_str())
        .collect::<Vec<_>>();
    assert!(changed_names.iter().any(|name| name.ends_with("/second/c")));
    assert!(changed_names
        .iter()
        .all(|name| !name.ends_with("/first/stale")));
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
            policy: IndexValidationPolicy::Production,
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
