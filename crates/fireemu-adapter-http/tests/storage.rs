//! Storage surface at the handler level: both protocol dialects, uploads, downloads with
//! tokens and ranges, listing, metadata, rewrite and Storage Rules.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_http::storage::{
    handle, AtomicStorageEventSink, StorageEventPublication, StorageRequest, StorageRulesRegistry,
    StorageState,
};
use fireemu_adapter_http::storage_server::{
    serve_storage_with_budget, BodyBudget, MAX_STORAGE_BODY_BYTES,
};
use fireemu_core_auth::jwt::{base64url_encode, TokenAcceptance};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, NewUser};
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::StorageState as ObjectStore;
use fireemu_core_storage::store::{NewMetadata, Precondition, StorageEvent};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::Strategy as _;
use serde_json::{json, Value};

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const BUCKET: &str = "demo-app.appspot.com";
/// A ruleset that admits every end-user request, for the fixtures whose subject is not the
/// authorization decision. A run with no loaded ruleset denies them all.
const ALLOW_ALL_RULES: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if true; } } }";

struct RefusingStorageEvents;

impl AtomicStorageEventSink for RefusingStorageEvents {
    fn reserve(
        &self,
        _event: &StorageEvent,
    ) -> Result<Box<dyn StorageEventPublication>, fireemu_core_types::admission::EventAdmissionError>
    {
        Err(fireemu_core_types::admission::EventAdmissionError::Capacity("outbox full".to_owned()))
    }
}

/// The control token `state` gives every fixture, as a run's control surface holds it.
const CONTROL_TOKEN: &str = "storage-test-control-token";

fn state(rules: Option<&str>) -> StorageState {
    state_with(rules, TokenAcceptance::Verified)
}

fn state_with(rules: Option<&str>, token_acceptance: TokenAcceptance) -> StorageState {
    StorageState {
        store: Mutex::new(ObjectStore::new(9)),
        clock: Arc::new(Mutex::new(VirtualClock::new(START))),
        auth: Arc::new(fireemu_core_auth::store::AuthRegistry::new(
            "demo-app",
            Arc::new(Mutex::new(AuthStore::new(
                "demo-app",
                SplitMix64::new(3),
                TotpPolicy::default(),
            ))),
        )),
        tenancy: None,
        rules: Arc::new(StorageRulesRegistry::global(Arc::new(RulesetSlot::new(
            rules.map_or_else(LoadedRules::default, |r| {
                LoadedRules::from_source(r).unwrap()
            }),
        )))),
        project: "demo-app".to_owned(),
        events: None,
        barrier: None,
        firestore: None,
        faults: None,
        clock_observer: None,
        app_check_policy: None,
        admin_capability: None,
        token_acceptance,
        control_token: Some(CONTROL_TOKEN.to_owned()),
    }
}

fn req(
    method: &str,
    path_and_query: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> StorageRequest {
    owned_req(method, path_and_query, headers, body.to_vec())
}

/// [`req`] with a body the caller owns (buffer identity is observable).
fn owned_req(
    method: &str,
    path_and_query: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> StorageRequest {
    let (path, query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, ""), |(p, q)| (p, q));
    StorageRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        host: Some("127.0.0.1:9199".to_owned()),
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<BTreeMap<_, _>>(),
        app_check: Vec::new(),
        body,
    }
}

fn json_body(r: &fireemu_adapter_http::storage::StorageResponse) -> Value {
    serde_json::from_slice(&r.body).unwrap_or(Value::Null)
}

fn header<'a>(
    r: &'a fireemu_adapter_http::storage::StorageResponse,
    name: &str,
) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn multipart(meta: &Value, ct: &str, data: &[u8]) -> (String, Vec<u8>) {
    let boundary = "fireemu-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{meta}\r\n--{boundary}\r\nContent-Type: {ct}\r\n\r\n").as_bytes());
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());
    (format!("multipart/related; boundary={boundary}"), body)
}

fn anonymous_multipart_upload(
    s: &StorageState,
    name: &str,
) -> fireemu_adapter_http::storage::StorageResponse {
    let (content_type, body) = multipart(&json!({}), "text/plain", b"content");
    handle(
        s,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name={name}&uploadType=multipart"),
            &[
                ("content-type", &content_type),
                ("x-goog-upload-protocol", "multipart"),
            ],
            &body,
        ),
    )
}

fn anonymous_multipart_upload_to(
    s: &StorageState,
    bucket: &str,
    name: &str,
) -> fireemu_adapter_http::storage::StorageResponse {
    let (content_type, body) = multipart(&json!({}), "text/plain", b"content");
    handle(
        s,
        req(
            "POST",
            &format!("/v0/b/{bucket}/o?name={name}&uploadType=multipart"),
            &[
                ("content-type", &content_type),
                ("x-goog-upload-protocol", "multipart"),
            ],
            &body,
        ),
    )
}

#[test]
fn targeted_storage_rules_are_isolated_by_bucket_and_unknown_buckets_fail_closed() {
    const ALLOW: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow write: if true; } } }";
    const DENY: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow write: if false; } } }";
    let allow = Arc::new(RulesetSlot::new(LoadedRules::from_source(ALLOW).unwrap()));
    let deny = Arc::new(RulesetSlot::new(LoadedRules::from_source(DENY).unwrap()));
    let mut s = state(None);
    s.rules = Arc::new(StorageRulesRegistry::per_bucket(BTreeMap::from([
        ("public.example.test".to_owned(), allow),
        ("private.example.test".to_owned(), deny),
    ])));

    assert_eq!(
        anonymous_multipart_upload_to(&s, "public.example.test", "allowed.txt").status,
        200
    );
    assert_eq!(
        anonymous_multipart_upload_to(&s, "private.example.test", "denied.txt").status,
        403
    );
    assert_eq!(
        anonymous_multipart_upload_to(&s, "unknown.example.test", "unknown.txt").status,
        // A bucket with no release: production's 400 under strict (see the no-ruleset test).
        400
    );
    let (owner_content_type, owner_body) = multipart(&json!({}), "text/plain", b"owner");
    assert_eq!(
        handle(
            &s,
            req(
                "POST",
                "/v0/b/unknown.example.test/o?name=owner.txt&uploadType=multipart",
                &[
                    ("authorization", "Bearer owner"),
                    ("content-type", &owner_content_type),
                    ("x-goog-upload-protocol", "multipart"),
                ],
                &owner_body,
            ),
        )
        .status,
        200
    );
    let store = s.store.lock().unwrap();
    assert!(store
        .get(
            &BucketName::try_new("public.example.test").unwrap(),
            &ObjectName::try_new("allowed.txt").unwrap()
        )
        .is_some());
    for (bucket, object) in [
        ("private.example.test", "denied.txt"),
        ("unknown.example.test", "unknown.txt"),
    ] {
        assert!(store
            .get(
                &BucketName::try_new(bucket).unwrap(),
                &ObjectName::try_new(object).unwrap()
            )
            .is_none());
    }
}

#[test]
fn firebase_protocol_upload_download_list_update_delete() {
    let s = state(None);
    let owner = [("authorization", "Bearer owner")];
    // Multipart upload with a name containing '/' and non-ASCII characters.
    let (ct, body) = multipart(
        &json!({"name": "photos/請求書.png", "contentType": "image/png", "metadata": {"k": "v"}}),
        "image/png",
        b"PNGDATA",
    );
    let r = handle(&s, req("POST", &format!("/v0/b/{BUCKET}/o?name=photos%2F%E8%AB%8B%E6%B1%82%E6%9B%B8.png&uploadType=multipart"), &[("authorization", "Bearer owner"), ("content-type", &ct), ("x-goog-upload-protocol", "multipart")], &body));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let meta = json_body(&r);
    assert_eq!(meta["name"], "photos/請求書.png");
    assert_eq!(meta["size"], "7");
    assert_eq!(meta["contentType"], "image/png");
    assert_eq!(meta["metadata"]["k"], "v");
    let token = meta["downloadTokens"].as_str().unwrap().to_owned();
    assert!(!token.is_empty());

    // Metadata and bytes (download token instead of credentials).
    let enc = "photos%2F%E8%AB%8B%E6%B1%82%E6%9B%B8.png";
    let r = handle(
        &s,
        req("GET", &format!("/v0/b/{BUCKET}/o/{enc}"), &owner, b""),
    );
    // Under strict a generation is the commit's microsecond timestamp (the virtual clock's start
    // here), 16 digits as production's are.
    assert_eq!(json_body(&r)["generation"], "1788004860000000");
    let r = handle(
        &s,
        req(
            "GET",
            &format!("/v0/b/{BUCKET}/o/{enc}?alt=media&token={token}"),
            &[],
            b"",
        ),
    );
    assert_eq!((r.status, r.body.as_ref()), (200, &b"PNGDATA"[..]));
    assert_eq!(header(&r, "content-type"), Some("image/png"));
    let r = handle(
        &s,
        req(
            "GET",
            &format!("/v0/b/{BUCKET}/o/{enc}?alt=media"),
            &[("authorization", "Bearer owner"), ("range", "bytes=1-3")],
            b"",
        ),
    );
    assert_eq!((r.status, r.body.as_ref()), (206, &b"NGD"[..]));
    assert_eq!(header(&r, "content-range"), Some("bytes 1-3/7"));

    // List with a delimiter.
    let _ = handle(
        &s,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=root.txt&uploadType=multipart"),
            &[("authorization", "Bearer owner"), ("content-type", &ct)],
            &multipart(&json!({}), "text/plain", b"r").1,
        ),
    );
    let r = handle(
        &s,
        req(
            "GET",
            &format!("/v0/b/{BUCKET}/o?prefix=&delimiter=%2F"),
            &owner,
            b"",
        ),
    );
    let listed = json_body(&r);
    assert_eq!(listed["prefixes"], json!(["photos/"]));
    assert_eq!(listed["items"][0]["name"], "root.txt");

    // Metadata update bumps the metageneration only.
    let r = handle(
        &s,
        req(
            "PATCH",
            &format!("/v0/b/{BUCKET}/o/{enc}"),
            &[
                ("authorization", "Bearer owner"),
                ("content-type", "application/json"),
            ],
            br#"{"cacheControl": "public, max-age=60", "metadata": {"k": null, "x": "y"}}"#,
        ),
    );
    let patched = json_body(&r);
    assert_eq!(
        (
            patched["generation"].as_str(),
            patched["metageneration"].as_str()
        ),
        (Some("1788004860000000"), Some("2"))
    );
    assert_eq!(patched["cacheControl"], "public, max-age=60");
    assert!(patched["metadata"].get("k").is_none());
    assert_eq!(patched["metadata"]["x"], "y");

    let r = handle(
        &s,
        req("DELETE", &format!("/v0/b/{BUCKET}/o/{enc}"), &owner, b""),
    );
    assert_eq!(r.status, 204);
    let r = handle(
        &s,
        req("GET", &format!("/v0/b/{BUCKET}/o/{enc}"), &owner, b""),
    );
    // Production answers a missing object with the `Not Found.` JSON, where the official
    // Firebase dialect writes a bare status text (see the dedicated test).
    assert_eq!(r.status, 404);
    assert_eq!(json_body(&r)["error"]["message"], "Not Found.");
}

#[test]
fn firebase_and_json_api_list_pages_share_the_combined_entry_budget() {
    let storage = state(None);
    {
        let mut store = storage.store.lock().unwrap();
        let bucket = BucketName::try_new(BUCKET).unwrap();
        for object_name in ["a", "b", "dir/x", "dir2/x", "zz"] {
            store
                .put(
                    &bucket,
                    &ObjectName::try_new(object_name).unwrap(),
                    Vec::new(),
                    NewMetadata::default(),
                    Precondition::default(),
                    START,
                )
                .unwrap();
        }
    }

    // The Firebase route pages as production does (recorded, lean-v5): the token is the standard
    // base64, padding kept, of the last entry returned; the JSON API route names the first entry
    // of the next page.
    for (route, tokens) in [
        (
            format!("/v0/b/{BUCKET}/o"),
            [Some("Yg=="), Some("ZGlyMi8="), None],
        ),
        (
            format!("/storage/v1/b/{BUCKET}/o"),
            [Some("dir/"), Some("zz"), None],
        ),
    ] {
        let mut token: Option<String> = None;
        for ((expected_items, expected_prefixes), expected_token) in [
            (vec!["a", "b"], vec![]),
            (vec![], vec!["dir/", "dir2/"]),
            (vec!["zz"], vec![]),
        ]
        .into_iter()
        .zip(tokens)
        {
            let query = token.as_ref().map_or_else(
                || "delimiter=%2F&maxResults=2".to_owned(),
                |value| {
                    format!(
                        "delimiter=%2F&maxResults=2&pageToken={}",
                        value.replace('=', "%3D")
                    )
                },
            );
            let response = handle(
                &storage,
                req(
                    "GET",
                    &format!("{route}?{query}"),
                    &[("authorization", "Bearer owner")],
                    b"",
                ),
            );
            assert_eq!(
                response.status,
                200,
                "{route}: {}",
                String::from_utf8_lossy(&response.body)
            );
            let body = json_body(&response);
            let items: Vec<&str> = body["items"].as_array().map_or_else(Vec::new, |values| {
                values
                    .iter()
                    .map(|item| item["name"].as_str().unwrap())
                    .collect()
            });
            let prefixes: Vec<&str> = body["prefixes"].as_array().map_or_else(Vec::new, |values| {
                values
                    .iter()
                    .map(|prefix| prefix.as_str().unwrap())
                    .collect()
            });
            assert_eq!(items, expected_items, "{route}");
            assert_eq!(prefixes, expected_prefixes, "{route}");
            assert_eq!(body["nextPageToken"].as_str(), expected_token, "{route}");
            token = expected_token.map(str::to_owned);
        }
    }
}

#[test]
fn event_admission_refusal_returns_429_without_publishing_the_object() {
    let mut s = state(None);
    s.events = Some(Arc::new(RefusingStorageEvents));
    let (content_type, body) = multipart(&json!({}), "text/plain", b"private");

    let response = handle(
        &s,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=refused.txt&uploadType=multipart"),
            &[
                ("authorization", "Bearer owner"),
                ("content-type", &content_type),
                ("x-goog-upload-protocol", "multipart"),
            ],
            &body,
        ),
    );

    assert_eq!(
        response.status,
        429,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let bucket = BucketName::try_new(BUCKET).unwrap();
    let object = ObjectName::try_new("refused.txt").unwrap();
    let mut store = s.store.lock().unwrap();
    assert!(store.get(&bucket, &object).is_none());
    assert!(store.drain_events().is_empty());
    drop(store);

    s.events = None;
    let accepted = handle(
        &s,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=accepted.txt&uploadType=multipart"),
            &[
                ("authorization", "Bearer owner"),
                ("content-type", &content_type),
                ("x-goog-upload-protocol", "multipart"),
            ],
            &body,
        ),
    );
    assert_eq!(json_body(&accepted)["generation"], "1788004860000000");
    let control = state(None);
    let expected = handle(
        &control,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=accepted.txt&uploadType=multipart"),
            &[
                ("authorization", "Bearer owner"),
                ("content-type", &content_type),
                ("x-goog-upload-protocol", "multipart"),
            ],
            &body,
        ),
    );
    assert_eq!(
        json_body(&accepted)["downloadTokens"],
        json_body(&expected)["downloadTokens"],
        "a refused mutation must not consume token RNG state"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn upload_digests_seen_by_rules_match_the_committed_bytes_on_every_firebase_path() {
    // The rules read the official emulator's decimal crc32c; the answers carry production's
    // base64 one (`.2`).
    let expected = |bytes: &[u8]| {
        (
            fireemu_core_storage::hash::base64(&fireemu_core_storage::hash::md5(bytes)),
            fireemu_core_storage::hash::crc32c(bytes).to_string(),
            fireemu_core_storage::hash::base64(
                &fireemu_core_storage::hash::crc32c(bytes).to_be_bytes(),
            ),
        )
    };
    let abc = expected(b"abc");
    let overlap = expected(b"abcdefgh");
    let rules = format!(
        "rules_version = '2';
service firebase.storage {{
  match /b/{{bucket}}/o/{{name}} {{
    allow create: if
      (request.resource.md5Hash == '{}' && request.resource.crc32c == '{}') ||
      (request.resource.md5Hash == '{}' && request.resource.crc32c == '{}');
  }}
}}",
        abc.0, abc.1, overlap.0, overlap.1
    );
    let state = state(Some(&rules));

    let media = handle(
        &state,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=media.bin&uploadType=media"),
            &[("content-type", "application/octet-stream")],
            b"abc",
        ),
    );
    assert_eq!(
        media.status,
        200,
        "{}",
        String::from_utf8_lossy(&media.body)
    );
    assert_eq!(json_body(&media)["md5Hash"], abc.0);
    assert_eq!(json_body(&media)["crc32c"], abc.2);

    let (content_type, body) = multipart(&json!({}), "application/octet-stream", b"abc");
    let multipart_response = handle(
        &state,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=multipart.bin&uploadType=multipart"),
            &[
                ("content-type", &content_type),
                ("x-goog-upload-protocol", "multipart"),
            ],
            &body,
        ),
    );
    assert_eq!(
        multipart_response.status,
        200,
        "{}",
        String::from_utf8_lossy(&multipart_response.body)
    );
    assert_eq!(json_body(&multipart_response)["md5Hash"], abc.0);
    assert_eq!(json_body(&multipart_response)["crc32c"], abc.2);

    let start = handle(
        &state,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=resumable.bin"),
            &[
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "start"),
            ],
            b"{}",
        ),
    );
    let session = header(&start, "x-goog-upload-url")
        .unwrap()
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap();
    assert_eq!(
        handle(
            &state,
            req(
                "POST",
                session,
                &[
                    ("x-goog-upload-command", "upload"),
                    ("x-goog-upload-offset", "0"),
                ],
                b"abcde",
            ),
        )
        .status,
        200
    );
    let finalized = handle(
        &state,
        req(
            "POST",
            session,
            &[
                ("x-goog-upload-command", "upload, finalize"),
                ("x-goog-upload-offset", "3"),
            ],
            b"defgh",
        ),
    );
    assert_eq!(
        finalized.status,
        200,
        "{}",
        String::from_utf8_lossy(&finalized.body)
    );
    assert_eq!(json_body(&finalized)["md5Hash"], overlap.0);
    assert_eq!(json_body(&finalized)["crc32c"], overlap.2);

    for (name, bytes) in [
        ("media.bin", &b"abc"[..]),
        ("multipart.bin", &b"abc"[..]),
        ("resumable.bin", &b"abcdefgh"[..]),
    ] {
        let response = handle(
            &state,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o/{name}?alt=media"),
                &[("authorization", "Bearer owner")],
                b"",
            ),
        );
        assert_eq!((response.status, response.body.as_ref()), (200, bytes));
    }
}

#[test]
fn firebase_resumable_upload_protocol() {
    let s = state(None);
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=big.bin"),
            &[
                ("authorization", "Bearer owner"),
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "start"),
                ("x-goog-upload-header-content-type", "application/zip"),
                ("x-goog-upload-header-content-length", "6"),
                ("content-type", "application/json; charset=utf-8"),
            ],
            br#"{"contentType": "application/zip"}"#,
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(header(&r, "x-goog-upload-status"), Some("active"));
    let url = header(&r, "x-goog-upload-url").unwrap().to_owned();
    let path_and_query = url
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap()
        .to_owned();
    let r = handle(
        &s,
        req(
            "POST",
            &path_and_query,
            &[
                ("authorization", "Bearer owner"),
                ("x-goog-upload-command", "upload"),
                ("x-goog-upload-offset", "0"),
            ],
            b"abc",
        ),
    );
    assert_eq!(
        (r.status, header(&r, "x-goog-upload-status")),
        (200, Some("active"))
    );
    // Only a query reports the received size, as the official emulator answers it.
    assert_eq!(header(&r, "x-goog-upload-size-received"), None);
    let r = handle(
        &s,
        req(
            "POST",
            &path_and_query,
            &[
                ("authorization", "Bearer owner"),
                ("x-goog-upload-command", "query"),
            ],
            b"",
        ),
    );
    assert_eq!(header(&r, "x-goog-upload-size-received"), Some("3"));
    let r = handle(
        &s,
        req(
            "POST",
            &path_and_query,
            &[
                ("authorization", "Bearer owner"),
                ("x-goog-upload-command", "upload, finalize"),
                ("x-goog-upload-offset", "3"),
            ],
            b"def",
        ),
    );
    assert_eq!(
        (r.status, header(&r, "x-goog-upload-status")),
        (200, Some("final"))
    );
    let meta = json_body(&r);
    assert_eq!(
        (meta["size"].as_str(), meta["contentType"].as_str()),
        (Some("6"), Some("application/zip"))
    );
    let r = handle(
        &s,
        req(
            "GET",
            &format!("/v0/b/{BUCKET}/o/big.bin?alt=media"),
            &[("authorization", "Bearer owner")],
            b"",
        ),
    );
    assert_eq!(r.body.as_ref(), b"abcdef");
}

#[test]
#[allow(clippy::too_many_lines)]
fn json_api_dialect_for_the_admin_sdk() {
    let s = state(None);
    let owner = [("authorization", "Bearer owner")];
    // The official emulator serves no bucket metadata: the path falls into its XML-style
    // fallback and answers the missing-object envelope.
    assert_eq!(
        handle(
            &s,
            req("GET", &format!("/storage/v1/b/{BUCKET}"), &owner, b"")
        )
        .status,
        404
    );
    let (ct, body) = multipart(
        &json!({"name": "a/b.txt", "contentType": "text/plain", "metadata": {"owner": "x"}}),
        "text/plain",
        b"hello",
    );
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=multipart"),
            &[("authorization", "Bearer owner"), ("content-type", &ct)],
            &body,
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let obj = json_body(&r);
    assert_eq!(obj["kind"], "storage#object");
    assert_eq!(obj["md5Hash"], "XUFAKrxLKna5cZ2REBfFkg==");
    assert!(obj["mediaLink"]
        .as_str()
        .unwrap()
        .contains("/download/storage/v1/b/"));
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=raw.bin"),
            &[
                ("authorization", "Bearer owner"),
                ("content-type", "application/octet-stream"),
            ],
            b"\x00\x01",
        ),
    );
    assert_eq!(json_body(&r)["size"], "2");

    // Resumable with Content-Range.
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=res.bin"),
            &[
                ("authorization", "Bearer owner"),
                ("content-type", "application/json"),
                ("x-upload-content-type", "application/pdf"),
            ],
            b"{}",
        ),
    );
    assert_eq!(r.status, 200);
    let location = header(&r, "location")
        .unwrap()
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap()
        .to_owned();
    let r = handle(
        &s,
        req(
            "PUT",
            &location,
            &[
                ("authorization", "Bearer owner"),
                ("content-range", "bytes 0-2/6"),
            ],
            b"abc",
        ),
    );
    assert_eq!((r.status, header(&r, "range")), (308, Some("bytes=0-2")));
    let r = handle(
        &s,
        req(
            "PUT",
            &location,
            &[
                ("authorization", "Bearer owner"),
                ("content-range", "bytes */6"),
            ],
            b"",
        ),
    );
    assert_eq!((r.status, header(&r, "range")), (308, Some("bytes=0-2")));
    let r = handle(
        &s,
        req(
            "PUT",
            &location,
            &[
                ("authorization", "Bearer owner"),
                ("content-range", "bytes 3-5/6"),
            ],
            b"def",
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(json_body(&r)["contentType"], "application/pdf");

    // Download with hashes, listing, rewrite, preconditions, delete.
    let r = handle(
        &s,
        req(
            "GET",
            &format!("/download/storage/v1/b/{BUCKET}/o/a%2Fb.txt?alt=media"),
            &owner,
            b"",
        ),
    );
    assert_eq!(r.body.as_ref(), b"hello");
    assert!(header(&r, "x-goog-hash").unwrap().starts_with("crc32c="));
    let r = handle(
        &s,
        req(
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o?prefix=a/"),
            &owner,
            b"",
        ),
    );
    let listed = json_body(&r);
    assert_eq!(listed["kind"], "storage#objects");
    assert_eq!(listed["items"][0]["name"], "a/b.txt");
    // Production JSON API routes also accept the /storage/v1 spelling.
    // https://cloud.google.com/storage/docs/json_api/v1/objects/patch
    // https://cloud.google.com/storage/docs/json_api/v1/objects/rewrite
    // https://cloud.google.com/storage/docs/json_api/v1/objects/copy
    let patched = handle(
        &s,
        req(
            "PATCH",
            &format!("/storage/v1/b/{BUCKET}/o/a%2Fb.txt"),
            &owner,
            br#"{"cacheControl":"no-cache"}"#,
        ),
    );
    assert_eq!(patched.status, 200);
    assert_eq!(json_body(&patched)["cacheControl"], "no-cache");
    let rewritten_long = handle(
        &s,
        req(
            "POST",
            &format!("/storage/v1/b/{BUCKET}/o/a%2Fb.txt/rewriteTo/b/{BUCKET}/o/long-copy.txt"),
            &owner,
            b"",
        ),
    );
    assert_eq!(rewritten_long.status, 200);
    assert_eq!(
        json_body(&rewritten_long)["resource"]["name"],
        "long-copy.txt"
    );
    let copied_long = handle(
        &s,
        req(
            "POST",
            &format!("/storage/v1/b/{BUCKET}/o/a%2Fb.txt/copyTo/b/{BUCKET}/o/long-copied.txt"),
            &owner,
            b"",
        ),
    );
    assert_eq!(copied_long.status, 200);
    assert_eq!(json_body(&copied_long)["name"], "long-copied.txt");
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/b/{BUCKET}/o/a%2Fb.txt/rewriteTo/b/{BUCKET}/o/copy.txt"),
            &owner,
            b"",
        ),
    );
    let rewritten = json_body(&r);
    assert_eq!(rewritten["done"], true);
    assert_eq!(rewritten["resource"]["name"], "copy.txt");
    assert_eq!(rewritten["resource"]["metadata"]["owner"], "x");
    let r = handle(
        &s,
        req(
            "DELETE",
            &format!("/storage/v1/b/{BUCKET}/o/copy.txt?ifGenerationMatch=999"),
            &owner,
            b"",
        ),
    );
    assert_eq!(r.status, 412);
    let r = handle(
        &s,
        req(
            "DELETE",
            &format!("/storage/v1/b/{BUCKET}/o/copy.txt"),
            &owner,
            b"",
        ),
    );
    assert_eq!(r.status, 204);
    let r = handle(
        &s,
        req(
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/copy.txt"),
            &owner,
            b"",
        ),
    );
    assert_eq!(r.status, 404);
    assert!(json_body(&r)["error"]["errors"].is_array());
}

#[test]
fn strict_json_list_rejects_the_filter_it_cannot_apply() {
    // https://cloud.google.com/storage/docs/json_api/v1/objects/list
    let strict = state(None);
    let emulator = state_with(None, TokenAcceptance::EmulatorMock);
    let uploaded = handle(
        &strict,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=current.txt"),
            &[],
            b"current",
        ),
    );
    assert_eq!(uploaded.status, 200);
    // `includeTrailingDelimiter=true` was not recorded; the offsets and the glob are honoured
    // (see `strict_json_list_filters_follow_the_recorded_rows`).
    let filter = "includeTrailingDelimiter=true";
    let path = format!("/storage/v1/b/{BUCKET}/o?{filter}");
    let rejected = handle(&strict, req("GET", &path, &[], b""));
    assert_eq!(rejected.status, 400, "{filter}");
    let compatible = handle(&emulator, req("GET", &path, &[], b""));
    assert_eq!(compatible.status, 200, "{filter}");
    for filter in [
        "versions=false",
        "versions=true",
        "includeTrailingDelimiter=false",
    ] {
        let path = format!("/storage/v1/b/{BUCKET}/o?{filter}");
        assert_eq!(handle(&strict, req("GET", &path, &[], b"")).status, 200);
    }
    let listed = |versions: &str| {
        handle(
            &strict,
            req(
                "GET",
                &format!("/storage/v1/b/{BUCKET}/o?versions={versions}"),
                &[],
                b"",
            ),
        )
    };
    let current_only = listed("false");
    assert_eq!(listed("true").body, current_only.body);
    assert_eq!(json_body(&current_only)["items"][0]["name"], "current.txt");
}

#[test]
fn rules_unit_testing_set_rules_replaces_the_active_ruleset() {
    let s = state(Some(
        "rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{path=**} { allow read, write: if false; }
  }
}",
    ));
    assert_eq!(anonymous_multipart_upload(&s, "before.txt").status, 403);

    let update = json!({
        "rules": {
            "files": [{
                "name": "storage.rules",
                "content": "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if true; } } }"
            }]
        }
    });
    let response = handle(
        &s,
        req(
            "PUT",
            "/internal/setRules",
            &[("content-type", "application/json")],
            &serde_json::to_vec(&update).unwrap(),
        ),
    );

    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(
        header(&response, "content-type"),
        Some("application/json; charset=utf-8")
    );
    assert_eq!(
        json_body(&response),
        json!({"message": "Rules updated successfully"})
    );
    assert_eq!(anonymous_multipart_upload(&s, "after.txt").status, 200);
}

#[test]
#[allow(clippy::too_many_lines)]
fn rules_unit_testing_set_rules_rejects_invalid_updates_without_replacing_rules() {
    const DENY_ALL: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if false; } } }";
    const ALLOW_ALL: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if true; } } }";
    let cases = [
        ("empty body", Vec::new()),
        ("malformed JSON", b"{".to_vec()),
        ("JSON null", b"null".to_vec()),
        ("missing rules", br"{}".to_vec()),
        ("missing files", br#"{"rules":{}}"#.to_vec()),
        ("non-array files", br#"{"rules":{"files":{}}}"#.to_vec()),
        ("empty files", br#"{"rules":{"files":[]}}"#.to_vec()),
        ("non-object file", br#"{"rules":{"files":[null]}}"#.to_vec()),
        (
            "missing name",
            serde_json::to_vec(&json!({"rules":{"files":[{"content":ALLOW_ALL}]}})).unwrap(),
        ),
        (
            "non-string name",
            serde_json::to_vec(&json!({"rules":{"files":[{"name":1,"content":ALLOW_ALL}]}}))
                .unwrap(),
        ),
        (
            "missing content",
            br#"{"rules":{"files":[{"name":"storage.rules"}]}}"#.to_vec(),
        ),
        (
            "non-string content",
            br#"{"rules":{"files":[{"name":"storage.rules","content":1}]}}"#.to_vec(),
        ),
        (
            "multiple files",
            serde_json::to_vec(&json!({"rules":{"files":[
                {"name":"storage.rules","content":ALLOW_ALL},
                {"name":"other.rules","content":ALLOW_ALL}
            ]}}))
            .unwrap(),
        ),
        (
            "invalid rules",
            br#"{"rules":{"files":[{"name":"storage.rules","content":"not rules"}]}}"#.to_vec(),
        ),
    ];

    for (label, body) in cases {
        let s = state(Some(DENY_ALL));
        let response = handle(
            &s,
            req(
                "PUT",
                "/internal/setRules",
                &[("content-type", "application/json")],
                &body,
            ),
        );
        assert_eq!(
            response.status,
            400,
            "{label}: {}",
            String::from_utf8_lossy(&response.body)
        );
        assert_eq!(
            header(&response, "content-type"),
            Some("application/json; charset=utf-8"),
            "{label}"
        );
        assert!(
            json_body(&response)["message"]
                .as_str()
                .is_some_and(|message| !message.is_empty()),
            "{label}"
        );
        assert_eq!(
            anonymous_multipart_upload(&s, &format!("{label}.txt")).status,
            403,
            "{label}"
        );
    }

    let s = state(Some(DENY_ALL));
    assert_eq!(
        handle(&s, req("POST", "/internal/setRules", &[], b""),).status,
        501
    );
    assert_eq!(
        handle(&s, req("PUT", "/internal/setRule", &[], b""),).status,
        501
    );

    let valid_update = serde_json::to_vec(&json!({
        "rules": {"files": [{"name": "storage.rules", "content": ALLOW_ALL}]}
    }))
    .unwrap();
    for path in [
        "internal/setRules",
        "//internal/setRules",
        "/internal/setRules/",
        "///internal/setRules//",
    ] {
        let s = state(Some(DENY_ALL));
        assert_eq!(
            handle(&s, req("PUT", path, &[], &valid_update)).status,
            501,
            "{path}"
        );
        assert_eq!(
            anonymous_multipart_upload(&s, "noncanonical-route.txt").status,
            403,
            "{path}"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn storage_rules_gate_uploads_downloads_and_lists() {
    let s = state(Some(
        "rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /users/{uid}/{file=**} {
      allow read: if request.auth != null && request.auth.uid == uid;
      allow write: if request.auth != null && request.auth.uid == uid
                   && request.resource.size < 1024
                   && request.resource.contentType == 'text/plain';
    }
    match /public/{file} { allow read: if true; }
  }
}",
    ));
    let (uid, token) = {
        let store = s.auth.default_store();
        let mut store = store.lock().unwrap();
        let uid = store
            .create_user(NewUser::email("u@example.com"), START)
            .unwrap();
        let claims = store.id_token_claims(&uid, None, START).unwrap();
        (
            uid.as_str().to_owned(),
            fireemu_core_auth::jwt::encode_unsigned(&claims),
        )
    };
    let firebase_auth = format!("Firebase {token}");
    let (ct, body) = multipart(&json!({"contentType": "text/plain"}), "text/plain", b"mine");
    // Own folder: allowed; someone else's folder: denied; anonymous: denied.
    let own = format!("/v0/b/{BUCKET}/o?name=users%2F{uid}%2Fnote.txt&uploadType=multipart");
    let r = handle(
        &s,
        req(
            "POST",
            &own,
            &[
                ("authorization", &firebase_auth),
                ("content-type", &ct),
                ("x-goog-upload-protocol", "multipart"),
            ],
            &body,
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let other = format!("/v0/b/{BUCKET}/o?name=users%2Fsomeone%2Fnote.txt&uploadType=multipart");
    let r = handle(
        &s,
        req(
            "POST",
            &other,
            &[
                ("authorization", &firebase_auth),
                ("content-type", &ct),
                ("x-goog-upload-protocol", "multipart"),
            ],
            &body,
        ),
    );
    assert_eq!(r.status, 403);
    // The strict profile's denial body is production's (the emulator profile keeps the
    // official emulator's `Permission denied. No WRITE permission.`).
    assert_eq!(json_body(&r)["error"]["message"], "Permission denied.");
    let r = handle(
        &s,
        req(
            "POST",
            &own,
            &[
                ("content-type", &ct),
                ("x-goog-upload-protocol", "multipart"),
            ],
            &body,
        ),
    );
    assert_eq!(r.status, 403);
    // Reads: own object ok, without credentials denied, public readable, token bypass.
    let enc = format!("users%2F{uid}%2Fnote.txt");
    assert_eq!(
        handle(
            &s,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o/{enc}?alt=media"),
                &[("authorization", &firebase_auth)],
                b""
            )
        )
        .status,
        200
    );
    assert_eq!(
        handle(
            &s,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o/{enc}?alt=media"),
                &[],
                b""
            )
        )
        .status,
        403
    );
    let meta = json_body(&handle(
        &s,
        req(
            "GET",
            &format!("/v0/b/{BUCKET}/o/{enc}"),
            &[("authorization", "Bearer owner")],
            b"",
        ),
    ));
    let dl = meta["downloadTokens"].as_str().unwrap();
    assert_eq!(
        handle(
            &s,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o/{enc}?alt=media&token={dl}"),
                &[],
                b""
            )
        )
        .status,
        200
    );
    assert_eq!(
        handle(
            &s,
            req("GET", &format!("/v0/b/{BUCKET}/o/public%2Fx"), &[], b"")
        )
        .status,
        404,
        "public read allowed, object missing"
    );
    // A listing of the own folder is allowed; the root is not.
    assert_eq!(
        handle(
            &s,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o?prefix=users%2F{uid}%2F&delimiter=%2F"),
                &[("authorization", &firebase_auth)],
                b""
            )
        )
        .status,
        200
    );
    assert_eq!(
        handle(
            &s,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o?prefix=&delimiter=%2F"),
                &[("authorization", &firebase_auth)],
                b""
            )
        )
        .status,
        403
    );
    // Admin credentials bypass the rules; a value that is not a token at all is an anonymous
    // caller, so the rules refuse it (production, stage 3 v9: `token-malformed` answers 403).
    assert_eq!(
        handle(
            &s,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o?prefix=&delimiter=%2F"),
                &[("authorization", "Bearer owner")],
                b""
            )
        )
        .status,
        200
    );
    assert_eq!(
        handle(
            &s,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o/{enc}"),
                &[("authorization", "Firebase nope")],
                b""
            )
        )
        .status,
        403
    );
}

#[test]
fn client_library_emulator_paths_and_open_ended_ranges() {
    let s = state(None);
    let owner = [("authorization", "Bearer owner")];
    // @google-cloud/storage against an emulator host omits /storage/v1 and uploads
    // unknown-size streams with `Content-Range: bytes 0-*/*`.
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=stream.bin"),
            &[("content-type", "application/json")],
            b"{}",
        ),
    );
    assert_eq!(r.status, 200);
    let location = header(&r, "location")
        .unwrap()
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap()
        .to_owned();
    let r = handle(
        &s,
        req(
            "PUT",
            &location,
            &[("content-range", "bytes 0-*/*")],
            b"whole object",
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(json_body(&r)["size"], "12");
    let r = handle(
        &s,
        req(
            "GET",
            &format!("/b/{BUCKET}/o/stream.bin?alt=media"),
            &[],
            b"",
        ),
    );
    assert_eq!((r.status, r.body.as_ref()), (200, &b"whole object"[..]));
    let r = handle(
        &s,
        req("GET", &format!("/b/{BUCKET}/o?prefix=stream"), &owner, b""),
    );
    assert_eq!(json_body(&r)["items"][0]["name"], "stream.bin");
    // The official emulator has no bucket-metadata route at all: a bucket GET falls into
    // its XML-style object fallback and answers the missing-object envelope, so
    // `bucket.exists()` is false on both emulators.
    let r = handle(&s, req("GET", &format!("/b/{BUCKET}"), &[], b""));
    assert_eq!(r.status, 404);
    assert_eq!(
        json_body(&r)["error"]["message"],
        format!("No such object: b/{BUCKET}")
    );
}

fn user_token(s: &StorageState) -> (String, String) {
    let store = s.auth.default_store();
    let mut store = store.lock().unwrap();
    let uid = store
        .create_user(NewUser::email("u@example.com"), START)
        .unwrap();
    let claims = store.id_token_claims(&uid, None, START).unwrap();
    (
        uid.as_str().to_owned(),
        format!(
            "Firebase {}",
            fireemu_core_auth::jwt::encode_unsigned(&claims)
        ),
    )
}

#[test]
fn multipart_payloads_keep_their_trailing_line_breaks() {
    let s = state(None);
    for data in [
        &b"line\n"[..],
        b"crlf\r\n",
        b"\r\n\r\n",
        b"--fireemu-boundary-ish\r\n",
    ] {
        let (ct, body) = multipart(&json!({"name": "t.txt"}), "text/plain", data);
        // The Firebase dialect takes the name from the query and the multipart decision
        // from the X-Goog-Upload-Protocol header, as the official emulator reads them.
        let r = handle(
            &s,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=t.txt&uploadType=multipart"),
                &[
                    ("authorization", "Bearer owner"),
                    ("content-type", &ct),
                    ("x-goog-upload-protocol", "multipart"),
                ],
                &body,
            ),
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(json_body(&r)["size"], data.len().to_string());
        let r = handle(
            &s,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o/t.txt?alt=media"),
                &[("authorization", "Bearer owner")],
                b"",
            ),
        );
        assert_eq!(r.body, data, "{data:?}");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn resumable_uploads_are_authorized_at_finalization_against_the_received_bytes() {
    let s = state(Some(
        "rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /small/{file} {
      allow write: if request.resource.size < 5 && request.resource.md5Hash is string;
    }
  }
}",
    ));
    let (_uid, auth) = user_token(&s);
    // No declared length: the received bytes decide at finalization.
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=small%2Fx.bin"),
            &[
                ("authorization", &auth),
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "start"),
            ],
            b"{}",
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let session = header(&r, "x-goog-upload-url")
        .unwrap()
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap()
        .to_owned();
    // Finalizing without credentials still uses the principal that started the session.
    let r = handle(
        &s,
        req(
            "POST",
            &session,
            &[
                ("x-goog-upload-command", "upload, finalize"),
                ("x-goog-upload-offset", "0"),
            ],
            b"ten bytes!",
        ),
    );
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(
        handle(
            &s,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o/small%2Fx.bin"),
                &[("authorization", "Bearer owner")],
                b""
            )
        )
        .status,
        404,
        "nothing was committed"
    );
    // A checksum mismatch is refused before commit.
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=small%2Fy.bin"),
            &[
                ("authorization", &auth),
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "start"),
            ],
            b"{}",
        ),
    );
    let session = header(&r, "x-goog-upload-url")
        .unwrap()
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap()
        .to_owned();
    let r = handle(
        &s,
        req(
            "POST",
            &session,
            &[
                ("x-goog-upload-command", "upload, finalize"),
                ("x-goog-upload-offset", "0"),
                ("x-goog-hash", "crc32c=AAAAAA=="),
            ],
            b"abc",
        ),
    );
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    // The integrity failure ends the session: the same bytes cannot be committed later.
    let r = handle(
        &s,
        req(
            "POST",
            &session,
            &[
                ("x-goog-upload-command", "finalize"),
                ("x-goog-upload-offset", "3"),
            ],
            b"",
        ),
    );
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(
        handle(
            &s,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o/small%2Fy.bin"),
                &[("authorization", "Bearer owner")],
                b""
            )
        )
        .status,
        404
    );
    // A fresh session with the right checksum commits.
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=small%2Fy.bin"),
            &[
                ("authorization", &auth),
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "start"),
            ],
            b"{}",
        ),
    );
    let session = header(&r, "x-goog-upload-url")
        .unwrap()
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap()
        .to_owned();
    let r = handle(
        &s,
        req(
            "POST",
            &session,
            &[
                ("x-goog-upload-command", "upload, finalize"),
                ("x-goog-upload-offset", "0"),
                (
                    "x-goog-hash",
                    &format!(
                        "crc32c={}",
                        fireemu_core_storage::hash::base64(
                            &fireemu_core_storage::hash::crc32c(b"abc").to_be_bytes()
                        )
                    ),
                ),
            ],
            b"abc",
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    // The session reports the committed generation afterwards.
    let r = handle(
        &s,
        req("POST", &session, &[("x-goog-upload-command", "query")], b""),
    );
    assert_eq!(header(&r, "x-goog-upload-status"), Some("final"));
    assert_eq!(header(&r, "x-goog-upload-size-received"), Some("3"));
}

#[test]
fn metadata_updates_are_authorized_on_the_exact_result() {
    let s = state(Some(
        "rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /docs/{file} {
      allow read, create: if true;
      allow update: if request.resource.contentType == 'text/plain'
                    && request.resource.contentLanguage == 'en'
                    && request.resource.generation > 0;
    }
  }
}",
    ));
    let (_uid, auth) = user_token(&s);
    let (ct, body) = multipart(
        &json!({"contentType": "text/plain", "contentLanguage": "en"}),
        "text/plain",
        b"hi",
    );
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=docs%2Fa.txt&uploadType=multipart"),
            &[
                ("authorization", &auth),
                ("content-type", &ct),
                ("x-goog-upload-protocol", "multipart"),
            ],
            &body,
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let patch = |body: &[u8]| {
        handle(
            &s,
            req(
                "PATCH",
                &format!("/v0/b/{BUCKET}/o/docs%2Fa.txt"),
                &[
                    ("authorization", &auth),
                    ("content-type", "application/json"),
                ],
                body,
            ),
        )
    };
    // Clearing the content type or changing the language is refused by the rule.
    assert_eq!(patch(br#"{"contentType": null}"#).status, 403);
    assert_eq!(patch(br#"{"contentLanguage": "fr"}"#).status, 403);
    let r = patch(br#"{"cacheControl": "no-cache"}"#);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(json_body(&r)["cacheControl"], "no-cache");
}

/// Both profiles: a media upload with no custom metadata and no `Authorization` header.
fn anonymous_media_upload(s: &StorageState, path: &str) -> u16 {
    handle(
        s,
        req(
            "POST",
            &format!(
                "/v0/b/{BUCKET}/o?name={}&uploadType=media",
                path.replace('/', "%2F")
            ),
            &[("content-type", "text/plain")],
            b"hello",
        ),
    )
    .status
}

const BOTH_PROFILES: [TokenAcceptance; 2] =
    [TokenAcceptance::Verified, TokenAcceptance::EmulatorMock];

/// An upload over an existing object is the rules method `create`, in both profiles: production
/// was measured (stage 3 v9, `method-create-upload-present` 200 and `method-update-upload-present`
/// 403; `state-upload-create-present` and `state-upload-update-present` agree), and so is the
/// official emulator, whose upload path hard-codes the create method.
#[test]
fn an_upload_over_an_existing_object_is_a_create_for_the_rules_in_both_profiles() {
    for acceptance in BOTH_PROFILES {
        let create_only = state_with(
            Some(
                "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, create: if true; allow update: if false; } } }",
            ),
            acceptance,
        );
        assert_eq!(
            anonymous_media_upload(&create_only, "o.txt"),
            200,
            "{acceptance:?}"
        );
        assert_eq!(
            anonymous_media_upload(&create_only, "o.txt"),
            200,
            "{acceptance:?}: the second upload is a create as well"
        );

        let update_only = state_with(
            Some(
                "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, update: if true; allow create: if false; } } }",
            ),
            acceptance,
        );
        assert_eq!(
            upload_as(&update_only, "o.txt", "Bearer owner"),
            200,
            "{acceptance:?}: the owner bypasses the rules and seeds the object"
        );
        assert_eq!(
            anonymous_media_upload(&update_only, "o.txt"),
            403,
            "{acceptance:?}: an overwrite is not an update"
        );
    }
}

/// A Firebase v0 `PATCH` of an absent object is refused as a write, never reported as
/// missing, for every caller: production answered 403 to the anonymous caller
/// (`method-update-patch-absent`, `method-write-patch-absent`, `stored-null-true-patch-absent`,
/// `precedence-control-absent-firebase-valid`) and to the owner
/// (`boundary-firebase-admin-patch-absent`).
#[test]
fn a_v0_patch_of_an_absent_object_answers_403_in_both_profiles() {
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        for authorization in [None, Some("Bearer owner")] {
            let mut headers = vec![("content-type", "application/json")];
            if let Some(value) = authorization {
                headers.push(("authorization", value));
            }
            let r = handle(
                &s,
                req(
                    "PATCH",
                    &format!("/v0/b/{BUCKET}/o/absent.txt"),
                    &headers,
                    br#"{"cacheControl": "no-cache"}"#,
                ),
            );
            assert_eq!(
                r.status,
                403,
                "{acceptance:?} {authorization:?}: {}",
                String::from_utf8_lossy(&r.body)
            );
        }
    }
}

/// Production evaluates an upload that carries no custom metadata against
/// `request.resource.metadata == null`, so a rule that reads the map (`"owner" in
/// request.resource.metadata`) fails and denies (stage 3 v9, `incoming-upload-simple-metadata-true`:
/// 403, and the object stays absent). The official emulator builds an empty map and the rule
/// passes; the emulator profile keeps that answer (a published divergence).
#[test]
fn an_upload_without_custom_metadata_has_null_request_metadata_only_in_the_strict_profile() {
    const RULES: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read; allow create: if request.resource != null && !(\"owner\" in request.resource.metadata); } } }";
    let strict = state_with(Some(RULES), TokenAcceptance::Verified);
    assert_eq!(anonymous_media_upload(&strict, "plain.txt"), 403);
    assert_eq!(
        handle(
            &strict,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o/plain.txt"),
                &[("authorization", "Bearer owner")],
                b"",
            ),
        )
        .status,
        404,
        "the denied upload leaves nothing behind"
    );

    let emulator = state_with(Some(RULES), TokenAcceptance::EmulatorMock);
    assert_eq!(anonymous_media_upload(&emulator, "plain.txt"), 200);

    // Custom metadata makes `request.resource.metadata` a map in both profiles.
    let (ct, body) = multipart(
        &json!({"contentType": "text/plain", "metadata": {"other": "x"}}),
        "text/plain",
        b"hi",
    );
    for (state, name) in [(&strict, "custom.txt"), (&emulator, "custom.txt")] {
        let r = handle(
            state,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name={name}&uploadType=multipart"),
                &[
                    ("content-type", &ct),
                    ("x-goog-upload-protocol", "multipart"),
                ],
                &body,
            ),
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
}

/// Production's recorded refusal bytes (stage 3 v9, every `Permission denied.` subject row of
/// recordings c and d: 192 rows, one body): two-space pretty JSON, `application/json; charset=UTF-8`.
const PRODUCTION_DENIED_BODY: &str =
    "{\n  \"error\": {\n    \"code\": 403,\n    \"message\": \"Permission denied.\"\n  }\n}";
const PRODUCTION_LIST_V1_BODY: &str = "{\n  \"error\": {\n    \"code\": 400,\n    \"message\": \"Listing objects in a bucket is disallowed for rules_version = \\\"1\\\".\\nPlease update storage security rules to rules_version = \\\"2\\\" to use list.\"\n  }\n}";

/// Strict answers a rules refusal with production's exact status, content type and body; the
/// emulator profile keeps the official emulator's wording (`Permission denied. No WRITE
/// permission.`), a published body divergence.
#[test]
fn strict_refusals_carry_production_bytes_and_the_emulator_profile_the_official_wording() {
    const DENY: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if false; } } }";
    const V1_LIST: &str =
        "service firebase.storage { match /b/{bucket}/o { match /{allPaths=**} { allow read; } } }";
    let denied = |acceptance, authorization: Option<&str>| {
        let s = state_with(Some(DENY), acceptance);
        let mut headers = vec![("content-type", "text/plain")];
        if let Some(value) = authorization {
            headers.push(("authorization", value));
        }
        handle(
            &s,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=o.txt&uploadType=media"),
                &headers,
                b"hello",
            ),
        )
    };
    let strict = denied(TokenAcceptance::Verified, None);
    assert_eq!(strict.status, 403);
    assert_eq!(
        header(&strict, "content-type"),
        Some("application/json; charset=UTF-8")
    );
    assert_eq!(
        String::from_utf8_lossy(&strict.body),
        PRODUCTION_DENIED_BODY
    );

    let emulator = denied(TokenAcceptance::EmulatorMock, None);
    assert_eq!(emulator.status, 403);
    assert_eq!(
        json_body(&emulator)["error"]["message"],
        "Permission denied. No WRITE permission."
    );

    // A token of another project under strict carries the same bytes.
    let foreign = format!("Firebase {}", mock_user_token("alice", "demo-other"));
    let foreign = denied(TokenAcceptance::Verified, Some(&foreign));
    assert_eq!(foreign.status, 403);
    assert_eq!(
        header(&foreign, "content-type"),
        Some("application/json; charset=UTF-8")
    );
    assert_eq!(
        String::from_utf8_lossy(&foreign.body),
        PRODUCTION_DENIED_BODY
    );

    // So does a metadata PATCH of an absent object, and a list under rules_version 1.
    let strict_state = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    let patch = handle(
        &strict_state,
        req(
            "PATCH",
            &format!("/v0/b/{BUCKET}/o/absent.txt"),
            &[("content-type", "application/json")],
            b"{}",
        ),
    );
    assert_eq!(patch.status, 403);
    assert_eq!(String::from_utf8_lossy(&patch.body), PRODUCTION_DENIED_BODY);
    for (acceptance, exact) in [
        (TokenAcceptance::Verified, true),
        (TokenAcceptance::EmulatorMock, false),
    ] {
        let s = state_with(Some(V1_LIST), acceptance);
        let list = handle(&s, req("GET", &format!("/v0/b/{BUCKET}/o"), &[], b""));
        assert_eq!(list.status, 400);
        if exact {
            assert_eq!(
                header(&list, "content-type"),
                Some("application/json; charset=UTF-8")
            );
            assert_eq!(String::from_utf8_lossy(&list.body), PRODUCTION_LIST_V1_BODY);
        } else {
            assert_eq!(
                json_body(&list),
                serde_json::from_str::<Value>(PRODUCTION_LIST_V1_BODY).unwrap()
            );
        }
    }
}

/// The recorded production body of the four `precedence-*-gcs-malformed-*` rows (stage 3 v9).
const PRODUCTION_INVALID_CREDENTIALS_BODY: &str = "{\n  \"error\": {\n    \"code\": 401,\n    \"message\": \"Invalid Credentials\",\n    \"errors\": [\n      {\n        \"message\": \"Invalid Credentials\",\n        \"domain\": \"global\",\n        \"reason\": \"authError\",\n        \"locationType\": \"header\",\n        \"location\": \"Authorization\"\n      }\n    ]\n  }\n}\n";

/// Strict refuses a malformed `Bearer` credential on the Cloud Storage JSON API PATCH with
/// production's recorded 401 (status, content type, headers that were not redacted, body), before
/// the body or the object is read; the emulator profile ignores the credential as the official
/// emulator does, and so does every route production was not recorded refusing it on.
#[test]
fn strict_refuses_a_malformed_bearer_on_the_json_api_patch_as_production_does() {
    assert_eq!(
        PRODUCTION_INVALID_CREDENTIALS_BODY.len(),
        285,
        "the recorded Content-Length, a final line feed included"
    );
    let patch = |s: &StorageState, path: &str, authorization: Option<&str>, body: &[u8]| {
        let mut headers = vec![("content-type", "application/json")];
        if let Some(value) = authorization {
            headers.push(("authorization", value));
        }
        handle(s, req("PATCH", path, &headers, body))
    };
    let malformed = "Bearer ya29.abcdefghijklmnopqrstuvwx";
    let strict = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    assert_eq!(
        anonymous_media_upload(&strict, "present.txt"),
        200,
        "the object the present rows patch"
    );
    let gcs = |name: &str| format!("/storage/v1/b/{BUCKET}/o/{name}");
    for (name, body) in [
        ("present.txt", br#"{"cacheControl": "no-store"}"# as &[u8]),
        ("present.txt", b"{not json"),
        ("absent.txt", br#"{"cacheControl": "no-store"}"#),
        ("absent.txt", b"{not json"),
    ] {
        let r = patch(&strict, &gcs(name), Some(malformed), body);
        assert_eq!(r.status, 401, "{name} {}", String::from_utf8_lossy(body));
        assert_eq!(
            String::from_utf8_lossy(&r.body),
            PRODUCTION_INVALID_CREDENTIALS_BODY
        );
        assert_eq!(
            header(&r, "content-type"),
            Some("application/json; charset=UTF-8")
        );
        assert_eq!(
            header(&r, "cache-control"),
            Some("no-cache, no-store, max-age=0, must-revalidate")
        );
        assert_eq!(header(&r, "expires"), Some("Mon, 01 Jan 1990 00:00:00 GMT"));
        let vary: Vec<&str> = r
            .headers
            .iter()
            .filter(|(k, _)| k == "vary")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(vary, ["Origin", "X-Origin"]);
    }
    // The emulator's owner credential is the valid one; the object was not touched above.
    let r = patch(
        &strict,
        &gcs("present.txt"),
        Some("Bearer owner"),
        br#"{"cacheControl": "no-store"}"#,
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(json_body(&r)["cacheControl"], "no-store");
    // Not recorded, so not refused: no credential, the short spelling and another method.
    assert_ne!(patch(&strict, &gcs("present.txt"), None, b"{}").status, 401);
    assert_ne!(
        patch(
            &strict,
            &format!("/b/{BUCKET}/o/present.txt"),
            Some(malformed),
            b"{}"
        )
        .status,
        401
    );
    let get = handle(
        &strict,
        req(
            "GET",
            &gcs("present.txt"),
            &[("authorization", malformed)],
            b"",
        ),
    );
    assert_ne!(get.status, 401);
    // The emulator profile ignores the credential, as the official emulator does.
    let emulator = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::EmulatorMock);
    assert_eq!(anonymous_media_upload(&emulator, "present.txt"), 200);
    let r = patch(
        &emulator,
        &gcs("present.txt"),
        Some(malformed),
        br#"{"cacheControl": "no-store"}"#,
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}

/// Object timestamps carry exactly three fractional digits in both dialects, cut (not rounded)
/// from the logical clock's nanoseconds, as production writes them (recorded, stage 3 v9:
/// `2026-09-30T10:58:30.639Z` on every `timeCreated`, `updated` and `timeFinalized`).
#[test]
fn object_timestamps_have_millisecond_precision_in_both_dialects() {
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        s.clock
            .lock()
            .unwrap()
            .set(LogicalInstant::from_nanos(START.as_nanos() + 987_654_321))
            .unwrap();
        assert_eq!(anonymous_media_upload(&s, "t.txt"), 200);
        let shape = |value: &Value| {
            let text = value.as_str().unwrap().to_owned();
            assert_eq!(text.len(), 24, "{text}");
            assert_eq!(&text[19..20], ".", "{text}");
            assert_eq!(&text[19..], ".987Z", "{acceptance:?}: {text}");
        };
        let firebase = handle(&s, req("GET", &format!("/v0/b/{BUCKET}/o/t.txt"), &[], b""));
        let firebase = json_body(&firebase);
        shape(&firebase["timeCreated"]);
        shape(&firebase["updated"]);
        let gcs = handle(
            &s,
            req(
                "GET",
                &format!("/storage/v1/b/{BUCKET}/o/t.txt"),
                &[("authorization", "Bearer owner")],
                b"",
            ),
        );
        let gcs = json_body(&gcs);
        shape(&gcs["timeCreated"]);
        shape(&gcs["updated"]);
        shape(&gcs["timeStorageClassUpdated"]);
        shape(&gcs["timeFinalized"]);
        assert_eq!(gcs["timeFinalized"], gcs["timeCreated"]);
        assert!(
            firebase.get("timeFinalized").is_none(),
            "the Firebase dialect never carried it"
        );
    }
}

/// The Firebase dialect spells `crc32c` in base64, as production answers it (recorded, stage 3 v9:
/// `12ox+Q==` and `jxTouw==` for the recorder's four-byte objects), on uploads, metadata reads and
/// updates; the official emulator's decimal spelling stays in the rules.
#[test]
fn the_firebase_dialect_spells_crc32c_in_base64_on_every_answer() {
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let upload = handle(
            &s,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=c.txt&uploadType=media"),
                &[("content-type", "text/plain")],
                b"abc",
            ),
        );
        assert_eq!(json_body(&upload)["crc32c"], "Nks/tw==");
        let read = handle(&s, req("GET", &format!("/v0/b/{BUCKET}/o/c.txt"), &[], b""));
        assert_eq!(json_body(&read)["crc32c"], "Nks/tw==");
        let patch = handle(
            &s,
            req(
                "PATCH",
                &format!("/v0/b/{BUCKET}/o/c.txt"),
                &[("content-type", "application/json")],
                br#"{"cacheControl": "no-cache"}"#,
            ),
        );
        assert_eq!(json_body(&patch)["crc32c"], "Nks/tw==");
    }
}

/// The Firebase dialect mints a download token on the first metadata read of an object that has
/// none, never on a media read (recorded, stage 3 v9: after `get-media` the object keeps
/// metageneration 2 and no token; after `get-metadata` it has a token and metageneration 3). The
/// official emulator mints on both.
#[test]
fn only_a_metadata_read_mints_the_first_download_token() {
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let seeded = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{BUCKET}/o?name=m.txt&uploadType=media"),
                &[
                    ("authorization", "Bearer owner"),
                    ("content-type", "text/plain"),
                ],
                b"hello",
            ),
        );
        assert_eq!(
            seeded.status,
            200,
            "{}",
            String::from_utf8_lossy(&seeded.body)
        );
        let gcs_meta = || {
            json_body(&handle(
                &s,
                req(
                    "GET",
                    &format!("/storage/v1/b/{BUCKET}/o/m.txt"),
                    &[("authorization", "Bearer owner")],
                    b"",
                ),
            ))
        };
        assert_eq!(gcs_meta()["metageneration"], "1");
        let media = handle(
            &s,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o/m.txt?alt=media"),
                &[],
                b"",
            ),
        );
        assert_eq!(media.status, 200);
        let after_media = gcs_meta();
        assert_eq!(after_media["metageneration"], "1", "{acceptance:?}");
        assert!(after_media.get("metadata").is_none(), "no token minted");
        let metadata = handle(&s, req("GET", &format!("/v0/b/{BUCKET}/o/m.txt"), &[], b""));
        let metadata = json_body(&metadata);
        assert_eq!(metadata["metageneration"], "2");
        assert!(!metadata["downloadTokens"].as_str().unwrap().is_empty());
        assert_eq!(gcs_meta()["metageneration"], "2");
    }
}

/// The Firebase dialect writes `downloadTokens` only for an object that has a token and
/// `metadata` only when a custom key is set (recorded, stage 3 v9: a v0 upload with no custom
/// metadata answers a token and no `metadata`; a v0 PATCH of an object that was never read
/// answers no `downloadTokens`; an empty map is never written).
#[test]
fn the_firebase_dialect_omits_empty_metadata_and_absent_tokens() {
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let uploaded = json_body(&handle(
            &s,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=e.txt&uploadType=media"),
                &[("content-type", "text/plain")],
                b"hello",
            ),
        ));
        assert!(!uploaded["downloadTokens"].as_str().unwrap().is_empty());
        assert!(
            uploaded.get("metadata").is_none(),
            "{acceptance:?}: {uploaded}"
        );

        let seeded = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{BUCKET}/o?name=g.txt&uploadType=media"),
                &[
                    ("authorization", "Bearer owner"),
                    ("content-type", "text/plain"),
                ],
                b"hello",
            ),
        );
        assert_eq!(seeded.status, 200);
        let patch = |name: &str, body: &[u8]| {
            json_body(&handle(
                &s,
                req(
                    "PATCH",
                    &format!("/v0/b/{BUCKET}/o/{name}"),
                    &[("content-type", "application/json")],
                    body,
                ),
            ))
        };
        let with_key = patch("g.txt", br#"{"metadata": {"owner": "new"}}"#);
        assert!(with_key.get("downloadTokens").is_none(), "{with_key}");
        assert_eq!(with_key["metadata"], json!({"owner": "new"}));
        let cleared = patch("g.txt", br#"{"metadata": null}"#);
        assert!(cleared.get("metadata").is_none(), "{cleared}");
        let empty = patch("g.txt", br#"{"metadata": {}}"#);
        assert!(empty.get("metadata").is_none(), "{empty}");
    }
}

/// An absent object answers the recorded `Not Found.` JSON on a Firebase read or delete in both
/// profiles (stage 3 v9: 15 rows, `application/json; charset=UTF-8`).
#[test]
fn an_absent_firebase_object_answers_the_recorded_json_not_found() {
    const NOT_FOUND: &str =
        "{\n  \"error\": {\n    \"code\": 404,\n    \"message\": \"Not Found.\"\n  }\n}";
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        for (method, path) in [
            ("GET", format!("/v0/b/{BUCKET}/o/absent.txt")),
            ("GET", format!("/v0/b/{BUCKET}/o/absent.txt?alt=media")),
            ("DELETE", format!("/v0/b/{BUCKET}/o/absent.txt")),
        ] {
            let r = handle(&s, req(method, &path, &[], b""));
            assert_eq!(r.status, 404, "{acceptance:?} {method} {path}");
            assert_eq!(String::from_utf8_lossy(&r.body), NOT_FOUND);
            assert_eq!(
                header(&r, "content-type"),
                Some("application/json; charset=UTF-8")
            );
        }
    }
}

/// A PATCH body that is not JSON is refused with production's recorded bytes (stage 3 v9, the body
/// `{` on an absent and a present object): `Parser Error` on the Firebase dialect, the parser's
/// `Parse Error: ...` with the repeated `errors` entry on the JSON API, in both profiles.
#[test]
fn a_malformed_patch_body_answers_the_recorded_parser_errors() {
    const FIREBASE: &str =
        "{\n  \"error\": {\n    \"code\": 400,\n    \"message\": \"Parser Error\"\n  }\n}";
    const GCS: &str = "{\n  \"error\": {\n    \"code\": 400,\n    \"message\": \"Parse Error: Unexpected end of string. Expected an object key or }.\\n\\n^\",\n    \"errors\": [\n      {\n        \"message\": \"Parse Error: Unexpected end of string. Expected an object key or }.\\n\\n^\",\n        \"domain\": \"global\",\n        \"reason\": \"invalid\"\n      }\n    ]\n  }\n}\n";
    // Recorded: 67 bytes for the Express answer, 318 for the Google-fronted one (a final line feed).
    assert_eq!((FIREBASE.len(), GCS.len()), (67, 318));
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        assert_eq!(anonymous_media_upload(&s, "p.txt"), 200);
        for (path, authorization, expected) in [
            (format!("/v0/b/{BUCKET}/o/p.txt"), "Bearer owner", FIREBASE),
            (
                format!("/v0/b/{BUCKET}/o/absent.txt"),
                "Bearer owner",
                FIREBASE,
            ),
            (
                format!("/storage/v1/b/{BUCKET}/o/p.txt"),
                "Bearer owner",
                GCS,
            ),
            (
                format!("/storage/v1/b/{BUCKET}/o/absent.txt"),
                "Bearer owner",
                GCS,
            ),
        ] {
            let r = handle(
                &s,
                req(
                    "PATCH",
                    &path,
                    &[
                        ("authorization", authorization),
                        ("content-type", "application/json"),
                    ],
                    b"{",
                ),
            );
            assert_eq!(r.status, 400, "{acceptance:?} {path}");
            assert_eq!(String::from_utf8_lossy(&r.body), expected, "{path}");
            assert_eq!(
                header(&r, "content-type"),
                Some("application/json; charset=UTF-8")
            );
        }
    }
}

/// The resumable start answers no body, and cancelling a finished session answers the recorded
/// text (stage 3 v9: `Content-Length: 0` for every start, `Upload has already been finalized.`
/// for the four cancels after a denied session), in both profiles.
#[test]
fn resumable_start_has_no_body_and_a_late_cancel_says_why() {
    const DENY: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if false; } } }";
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(DENY), acceptance);
        let start = handle(
            &s,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=r.txt"),
                &[
                    ("authorization", "Bearer owner"),
                    ("x-goog-upload-protocol", "resumable"),
                    ("x-goog-upload-command", "start"),
                ],
                b"{}",
            ),
        );
        assert_eq!(start.status, 200);
        assert!(start.body.is_empty(), "{acceptance:?}");
        assert_eq!(
            header(&start, "content-type"),
            Some("text/plain; charset=utf-8")
        );
        let session = header(&start, "x-goog-upload-url")
            .unwrap()
            .strip_prefix("http://127.0.0.1:9199")
            .unwrap()
            .to_owned();
        // An anonymous caller is refused at finalization, which ends the session.
        let anonymous = format!("/v0/b/{BUCKET}/o?name=a.txt");
        let start = handle(
            &s,
            req(
                "POST",
                &anonymous,
                &[
                    ("x-goog-upload-protocol", "resumable"),
                    ("x-goog-upload-command", "start"),
                ],
                b"{}",
            ),
        );
        let denied_session = header(&start, "x-goog-upload-url")
            .unwrap()
            .strip_prefix("http://127.0.0.1:9199")
            .unwrap()
            .to_owned();
        let finalize = handle(
            &s,
            req(
                "POST",
                &denied_session,
                &[
                    ("x-goog-upload-command", "upload, finalize"),
                    ("x-goog-upload-offset", "0"),
                ],
                b"hello",
            ),
        );
        assert_eq!(finalize.status, 403);
        let cancel = handle(
            &s,
            req(
                "POST",
                &denied_session,
                &[("x-goog-upload-command", "cancel")],
                b"",
            ),
        );
        assert_eq!(cancel.status, 400);
        assert_eq!(
            String::from_utf8_lossy(&cancel.body),
            "Upload has already been finalized."
        );
        assert_eq!(
            header(&cancel, "content-type"),
            Some("text/plain; charset=utf-8")
        );
        // An active session still cancels cleanly.
        let cancel = handle(
            &s,
            req(
                "POST",
                &session,
                &[("x-goog-upload-command", "cancel")],
                b"",
            ),
        );
        assert_eq!(cancel.status, 200);
    }
}

/// A Firebase-protocol upload that names no `contentDisposition` gets `inline` with the object's
/// last path segment as its file name, in the answer and on later reads of both dialects
/// (recorded, stage 3 v9: `inline; filename*=utf-8''object.bin`); one it names is kept.
#[test]
fn a_firebase_upload_defaults_the_content_disposition_to_inline_with_the_file_name() {
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let upload = |name: &str| {
            json_body(&handle(
                &s,
                req(
                    "POST",
                    &format!("/v0/b/{BUCKET}/o?name={name}&uploadType=media"),
                    &[("content-type", "text/plain")],
                    b"hello",
                ),
            ))
        };
        assert_eq!(
            upload("object.bin")["contentDisposition"],
            "inline; filename*=utf-8''object.bin"
        );
        assert_eq!(
            upload("dir%2Fsub%20dir%2Fb%20c.txt")["contentDisposition"],
            "inline; filename*=utf-8''b%20c.txt"
        );
        let gcs = json_body(&handle(
            &s,
            req(
                "GET",
                &format!("/storage/v1/b/{BUCKET}/o/object.bin"),
                &[("authorization", "Bearer owner")],
                b"",
            ),
        ));
        assert_eq!(
            gcs["contentDisposition"],
            "inline; filename*=utf-8''object.bin"
        );
        let (ct, body) = multipart(
            &json!({"contentType": "text/plain", "contentDisposition": "attachment"}),
            "text/plain",
            b"hi",
        );
        let named = handle(
            &s,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=named.txt&uploadType=multipart"),
                &[
                    ("content-type", &ct),
                    ("x-goog-upload-protocol", "multipart"),
                ],
                &body,
            ),
        );
        assert_eq!(json_body(&named)["contentDisposition"], "attachment");
        // The download header: strict sends the stored value as production does (recorded), the
        // emulator profile keeps the official shape and names the file once.
        let media = handle(
            &s,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o/object.bin?alt=media"),
                &[],
                b"",
            ),
        );
        assert_eq!(
            header(&media, "content-disposition"),
            Some(if acceptance == TokenAcceptance::Verified {
                "inline; filename*=utf-8''object.bin"
            } else {
                "inline; filename*=object.bin"
            })
        );
    }
}

/// In both profiles a value that is no JWT is an anonymous caller (production, stage 3 v9: the rules'
/// 403, and the parser's 400 first for a malformed PATCH body), and an ID token whose refresh tokens
/// were revoked is still honoured on Storage (`token-revoked`: allowed).
#[test]
fn an_undecodable_bearer_is_anonymous_and_a_revoked_id_token_is_honoured() {
    const AUTH_ONLY: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if request.auth != null; } } }";
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(AUTH_ONLY), acceptance);
        assert_eq!(
            upload_as(&s, "garbage.txt", "Firebase not-a-token"),
            403,
            "{acceptance:?}: anonymous, so the rule refuses"
        );
        let malformed = handle(
            &s,
            req(
                "PATCH",
                &format!("/v0/b/{BUCKET}/o/absent.txt"),
                &[
                    ("authorization", "Firebase not-a-token"),
                    ("content-type", "application/json"),
                ],
                b"{",
            ),
        );
        assert_eq!(malformed.status, 400, "{acceptance:?}");
        assert_eq!(json_body(&malformed)["error"]["message"], "Parser Error");

        let store = s.auth.default_store();
        let (uid, token) = {
            let mut store = store.lock().unwrap();
            let uid = store
                .create_user(NewUser::email("revoked@example.com"), START)
                .unwrap();
            let claims = store.id_token_claims(&uid, None, START).unwrap();
            let token = format!(
                "Firebase {}",
                fireemu_core_auth::jwt::encode_unsigned(&claims)
            );
            (uid, token)
        };
        assert_eq!(upload_as(&s, "live.txt", &token), 200, "{acceptance:?}");
        {
            let revoked_at = LogicalInstant::from_nanos(START.as_nanos() + 10_000_000_000);
            s.clock.lock().unwrap().set(revoked_at).unwrap();
            store
                .lock()
                .unwrap()
                .revoke_tokens(&uid, revoked_at)
                .unwrap();
        }
        assert_eq!(
            upload_as(&s, "revoked.txt", &token),
            200,
            "{acceptance:?}: Storage does not check revocation"
        );
    }
}

/// The resumable path evaluates `request.resource.metadata` the same way at finalization: null
/// for a session that carries no custom metadata under strict, the official empty map under the
/// emulator profile, and a map in both once a key is set.
#[test]
fn a_resumable_upload_without_custom_metadata_has_null_request_metadata_only_in_strict() {
    const RULES: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read; allow create: if request.resource != null && !(\"owner\" in request.resource.metadata); } } }";
    let finalize = |acceptance: TokenAcceptance, name: &str, start_body: &[u8]| {
        let s = state_with(Some(RULES), acceptance);
        let start = handle(
            &s,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name={name}"),
                &[
                    ("x-goog-upload-protocol", "resumable"),
                    ("x-goog-upload-command", "start"),
                ],
                start_body,
            ),
        );
        let session = header(&start, "x-goog-upload-url")
            .unwrap()
            .strip_prefix("http://127.0.0.1:9199")
            .unwrap()
            .to_owned();
        handle(
            &s,
            req(
                "POST",
                &session,
                &[
                    ("x-goog-upload-command", "upload, finalize"),
                    ("x-goog-upload-offset", "0"),
                ],
                b"hello",
            ),
        )
        .status
    };
    assert_eq!(finalize(TokenAcceptance::Verified, "r.txt", b"{}"), 403);
    assert_eq!(finalize(TokenAcceptance::EmulatorMock, "r.txt", b"{}"), 200);
    let with_key = br#"{"metadata": {"other": "x"}}"#;
    assert_eq!(finalize(TokenAcceptance::Verified, "k.txt", with_key), 200);
    assert_eq!(
        finalize(TokenAcceptance::EmulatorMock, "k.txt", with_key),
        200
    );
}

/// The JSON API resumable session: the start has no body and repeats its query in the session URL,
/// a status query before any byte is a 308 without `Range`, the cancel (`DELETE` on the session
/// URL) answers 499 and so does a status query after it (recorded, STORAGE-OBJECT probe-v2,
/// 2026-09-30: 224-byte `clientClosedRequest` body, `application/json; charset=UTF-8`), in both
/// profiles.
#[test]
fn a_json_api_session_cancel_answers_the_recorded_499() {
    const BODY: &str = "{\n  \"error\": {\n    \"code\": 499,\n    \"message\": \"clientClosedRequest\",\n    \"errors\": [\n      {\n        \"message\": \"clientClosedRequest\",\n        \"domain\": \"global\",\n        \"reason\": \"clientClosedRequest\"\n      }\n    ]\n  }\n}\n";
    assert_eq!(BODY.len(), 224);
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let owner = [("authorization", "Bearer owner")];
        let start = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=c.bin&ifGenerationMatch=0"),
                &owner,
                b"",
            ),
        );
        assert_eq!(start.status, 200);
        assert!(start.body.is_empty());
        assert_eq!(
            header(&start, "content-type"),
            Some("text/plain; charset=utf-8")
        );
        let location = header(&start, "location").unwrap();
        assert!(
            location.contains("?uploadType=resumable&name=c.bin&ifGenerationMatch=0&upload_id="),
            "{location}"
        );
        let session = location
            .strip_prefix("http://127.0.0.1:9199")
            .unwrap()
            .to_owned();
        let probe = |method: &str| {
            handle(
                &s,
                req(
                    method,
                    &session,
                    &[
                        ("authorization", "Bearer owner"),
                        ("content-range", "bytes */4"),
                        ("content-length", "0"),
                    ],
                    b"",
                ),
            )
        };
        let before = probe("PUT");
        assert_eq!(before.status, 308);
        assert!(header(&before, "range").is_none());
        assert!(before.body.is_empty());
        for response in [
            handle(&s, req("DELETE", &session, &owner, b"")),
            probe("PUT"),
        ] {
            assert_eq!(response.status, 499, "{acceptance:?}");
            assert_eq!(String::from_utf8_lossy(&response.body), BODY);
            assert_eq!(
                header(&response, "content-type"),
                Some("application/json; charset=UTF-8")
            );
        }
        // Nothing was published, and an unknown session is not found.
        let absent = handle(
            &s,
            req(
                "GET",
                &format!("/storage/v1/b/{BUCKET}/o/c.bin"),
                &owner,
                b"",
            ),
        );
        assert_eq!(absent.status, 404);
        let unknown = handle(
            &s,
            req(
                "DELETE",
                &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&upload_id=nope"),
                &owner,
                b"",
            ),
        );
        assert_eq!(unknown.status, 404);
    }
}

/// A finalized JSON API session answers a status query with the committed object (the recovery
/// path of a lost final response) but refuses a chunk sent into it.
#[test]
fn a_finalized_json_api_session_answers_status_queries_and_refuses_chunks() {
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let owner = [("authorization", "Bearer owner")];
        let start = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=f.bin"),
                &owner,
                b"",
            ),
        );
        let session = header(&start, "location")
            .unwrap()
            .strip_prefix("http://127.0.0.1:9199")
            .unwrap()
            .to_owned();
        let put = |range: &str, body: &[u8]| {
            handle(
                &s,
                req(
                    "PUT",
                    &session,
                    &[("authorization", "Bearer owner"), ("content-range", range)],
                    body,
                ),
            )
        };
        assert_eq!(put("bytes 0-3/4", b"abcd").status, 200);
        let status = put("bytes */4", b"");
        assert_eq!(status.status, 200, "{acceptance:?}");
        assert_eq!(json_body(&status)["name"], "f.bin");
        let refused = put("bytes 0-3/4", b"zzzz");
        assert_eq!(refused.status, 400, "{acceptance:?}");
        // Refused by the phase check, before any chunk is appended: the bare status text, not the
        // store's JSON `upload already finalized`.
        assert_eq!(String::from_utf8_lossy(&refused.body), "Bad Request");
        assert_eq!(
            header(&refused, "content-type"),
            Some("text/plain; charset=utf-8")
        );
        // The phase check also comes before the bucket check: a chunk under another bucket's
        // session URL is the same 400, not a 404.
        let other = session.replace(BUCKET, "demo-other.appspot.com");
        let elsewhere = handle(
            &s,
            req(
                "PUT",
                &other,
                &[
                    ("authorization", "Bearer owner"),
                    ("content-range", "bytes 0-3/4"),
                ],
                b"zzzz",
            ),
        );
        assert_eq!(elsewhere.status, 400, "{acceptance:?}");
        assert_eq!(String::from_utf8_lossy(&elsewhere.body), "Bad Request");
    }
}

/// Under strict only the recorded shape is an anonymous caller: `Firebase ` followed by a value
/// without a dot (stage 3 v9: the recorded value is 32 base64url characters; production answered it
/// as it answers no credential; the official emulator, measured with firebase-tools 15.28.2, also
/// treats no dots, two and four segments as unauthenticated). Every other value that fails to
/// decode stays a refusal under strict: two or four segments, `Bearer` on the Firebase dialect, a
/// three-segment value with a tampered signature, an unknown key id or an unsupported algorithm,
/// so none of them becomes a public caller. The emulator profile maps every decode failure to an
/// anonymous caller (never to the claimed user), as before.
#[test]
fn strict_makes_only_the_recorded_shape_anonymous() {
    const PUBLIC: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if true; } } }";
    const AUTHED: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if request.auth != null; } } }";
    let b64 = |text: &str| base64url_encode(text.as_bytes());
    let payload = b64(
        r#"{"iss":"https://securetoken.google.com/demo-app","aud":"demo-app","iat":0,"exp":3600,"sub":"u1","user_id":"u1"}"#,
    );
    let rs256 = b64(r#"{"alg":"RS256","kid":"unknown"}"#);
    let none = b64(r#"{"alg":"none"}"#);
    let dot_free = "abcdefghijklmnopqrstuvwxyz012345";
    // (authorization, anonymous under strict)
    let values: Vec<(String, bool)> = vec![
        (format!("Firebase {dot_free}"), true),
        ("Firebase x".to_owned(), true),
        // Not recorded, so not loosened: `Firebase ` with nothing after it.
        ("Firebase ".to_owned(), false),
        (format!("Bearer {dot_free}"), false),
        (format!("Firebase {none}.{payload}"), false),
        (format!("Firebase {none}.{payload}..x"), false),
        ("Firebase a.b".to_owned(), false),
        ("Firebase a.b.c.d".to_owned(), false),
        ("Firebase a.b.c".to_owned(), false),
        (format!("Firebase {rs256}.{payload}.AAAAAAAAAAAA"), false),
        (format!("Firebase {rs256}.{payload}."), false),
        (format!("Firebase {none}.{}.", b64("not json")), false),
    ];
    for (authorization, anonymous) in &values {
        for acceptance in BOTH_PROFILES {
            let strict = acceptance == TokenAcceptance::Verified;
            let expect_anonymous = *anonymous || !strict;
            let public = state_with(Some(PUBLIC), acceptance);
            let authed = state_with(Some(AUTHED), acceptance);
            let (public_status, authed_status) = (
                upload_as(&public, "p.txt", authorization),
                upload_as(&authed, "p.txt", authorization),
            );
            if expect_anonymous {
                assert_eq!(
                    (public_status, authed_status),
                    (200, 403),
                    "{acceptance:?} {authorization}"
                );
            } else {
                assert_eq!(
                    (public_status, authed_status),
                    (401, 401),
                    "{acceptance:?} {authorization}"
                );
            }
        }
    }
}

/// Strict frames JSON answers as production does (stage 3 v9, compared headers and bytes): an
/// uppercase charset on both dialects, the Google-fronted JSON API's error in its pretty layout
/// with a final line feed, a bare `application/json` on its 204. The emulator profile keeps the
/// official emulator's framing.
#[test]
fn strict_frames_json_answers_as_production_does_and_the_emulator_profile_as_the_official_one() {
    let owner = [("authorization", "Bearer owner")];
    let probe = |acceptance: TokenAcceptance| {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        assert_eq!(anonymous_media_upload(&s, "f.txt"), 200);
        let absent = handle(
            &s,
            req(
                "GET",
                &format!("/storage/v1/b/{BUCKET}/o/absent.txt"),
                &owner,
                b"",
            ),
        );
        let present = handle(
            &s,
            req(
                "GET",
                &format!("/storage/v1/b/{BUCKET}/o/f.txt"),
                &owner,
                b"",
            ),
        );
        let firebase = handle(&s, req("GET", &format!("/v0/b/{BUCKET}/o/f.txt"), &[], b""));
        let deleted = handle(
            &s,
            req(
                "DELETE",
                &format!("/storage/v1/b/{BUCKET}/o/f.txt"),
                &owner,
                b"",
            ),
        );
        (absent, present, firebase, deleted)
    };
    let (absent, present, firebase, deleted) = probe(TokenAcceptance::Verified);
    assert_eq!(absent.status, 404);
    assert_eq!(
        String::from_utf8_lossy(&absent.body),
        format!(
            "{{\n  \"error\": {{\n    \"code\": 404,\n    \"message\": \"No such object: {BUCKET}/absent.txt\",\n    \"errors\": [\n      {{\n        \"message\": \"No such object: {BUCKET}/absent.txt\",\n        \"domain\": \"global\",\n        \"reason\": \"notFound\"\n      }}\n    ]\n  }}\n}}\n"
        )
    );
    for response in [&absent, &present, &firebase] {
        assert_eq!(
            header(response, "content-type"),
            Some("application/json; charset=UTF-8")
        );
    }
    assert_eq!(deleted.status, 204);
    assert_eq!(header(&deleted, "content-type"), Some("application/json"));
    // Only the 204 gains a content type: a status query answers 308 without one, and a non-error
    // JSON body is not rewritten.
    let strict = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    let start = handle(
        &strict,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=r.bin"),
            &owner,
            b"",
        ),
    );
    let session = header(&start, "location")
        .unwrap()
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap()
        .to_owned();
    let status = handle(
        &strict,
        req(
            "PUT",
            &session,
            &[
                ("authorization", "Bearer owner"),
                ("content-range", "bytes */4"),
            ],
            b"",
        ),
    );
    assert_eq!(status.status, 308);
    // Production types the 308 `text/plain` (recorded, lean-v5).
    assert_eq!(
        header(&status, "content-type"),
        Some("text/plain; charset=utf-8")
    );
    // An object resource is laid out too, in its own member order, with the JSON API's final line
    // feed (the layout and order are pinned against recorded rows in `storage_production`).
    assert!(present
        .body
        .starts_with(b"{\n  \"kind\": \"storage#object\",\n  \"id\""));
    assert!(present.body.ends_with(b"}\n"));

    let (absent, present, firebase, deleted) = probe(TokenAcceptance::EmulatorMock);
    for response in [&absent, &present, &firebase] {
        assert_eq!(
            header(response, "content-type"),
            Some("application/json; charset=utf-8")
        );
    }
    assert!(
        absent.body.len() < 200,
        "the official emulator's compact body"
    );
    assert!(header(&deleted, "content-type").is_none());
}

/// Routing edges the JSON API keeps from the official router: the ACL stub answers, an unknown
/// verb after an object is not a copy, and a single-byte range is served while a reversed one is
/// ignored (whole object); strict answers an unsatisfiable range 416 on the XML-style route as on
/// the others, the emulator profile serves the whole object.
#[test]
fn json_api_routing_and_range_edges() {
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let owner = [("authorization", "Bearer owner")];
        assert_eq!(anonymous_media_upload(&s, "f.txt"), 200);
        let acl = handle(
            &s,
            req(
                "POST",
                &format!("/b/{BUCKET}/o/f.txt/acl"),
                &owner,
                br#"{"entity":"allUsers","role":"READER"}"#,
            ),
        );
        assert_eq!(acl.status, 200, "{acceptance:?}");
        assert_eq!(json_body(&acl)["kind"], "storage#objectAccessControl");
        // `copyTo` and `rewriteTo` are the only verbs: anything else falls through to 501.
        let other = handle(
            &s,
            req(
                "POST",
                &format!("/b/{BUCKET}/o/f.txt/moveTo/b/{BUCKET}/o/g.txt"),
                &owner,
                b"",
            ),
        );
        assert_eq!(other.status, 501, "{acceptance:?}");
        let get = |path: &str, range: &str| handle(&s, req("GET", path, &[("range", range)], b""));
        let media = format!("/v0/b/{BUCKET}/o/f.txt?alt=media");
        let one = get(&media, "bytes=2-2");
        assert_eq!(one.status, 206, "{acceptance:?}");
        assert_eq!(one.body.as_ref(), b"l");
        assert_eq!(header(&one, "content-range"), Some("bytes 2-2/5"));
        let reversed = get(&media, "bytes=3-1");
        assert_eq!(reversed.status, 200, "{acceptance:?}");
        assert_eq!(reversed.body.as_ref(), b"hello");
        let xml = format!("/{BUCKET}/f.txt");
        // The XML API's answers were not recorded: both profiles keep the official emulator's.
        let beyond = get(&xml, "bytes=50-60");
        assert_eq!(beyond.status, 200, "{acceptance:?}");
        assert_eq!(beyond.body.as_ref(), b"hello");
    }
}

/// The Firebase list answers `maxResults=0` with production's 400 under strict (recorded, lean-v4
/// and lean-v5: `content-length: 97`, the two-space layout without a final line feed,
/// `application/json; charset=UTF-8`); the emulator profile keeps the official
/// emulator's 200 (measured, firebase-tools 15.28.2: an empty page), since it never refuses what
/// the official emulator admits. An empty list is `{"prefixes":[],"items":[]}` with both keys.
#[test]
fn the_firebase_list_refuses_max_results_zero_only_under_strict_and_keeps_its_key_set() {
    let route = format!("/v0/b/{BUCKET}/o?maxResults=0");
    let strict = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    let refused = handle(&strict, req("GET", &route, &[], b""));
    assert_eq!(refused.status, 400);
    assert_eq!(refused.body.len(), 97);
    assert_eq!(
        String::from_utf8_lossy(&refused.body),
        "{\n  \"error\": {\n    \"code\": 400,\n    \"message\": \"Expect maxResults to be a positive number.\"\n  }\n}"
    );
    assert_eq!(
        header(&refused, "content-type"),
        Some("application/json; charset=UTF-8")
    );
    let emulator = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::EmulatorMock);
    assert_eq!(handle(&emulator, req("GET", &route, &[], b"")).status, 200);
    for state in [&strict, &emulator] {
        let empty = handle(
            state,
            req("GET", &format!("/v0/b/{BUCKET}/o?maxResults=2"), &[], b""),
        );
        assert_eq!(empty.status, 200);
        assert_eq!(json_body(&empty), json!({"prefixes": [], "items": []}));
    }
}

const PRODUCTION_412_BODY: &str = "{\n  \"error\": {\n    \"code\": 412,\n    \"message\": \"At least one of the pre-conditions you specified did not hold.\",\n    \"errors\": [\n      {\n        \"message\": \"At least one of the pre-conditions you specified did not hold.\",\n        \"domain\": \"global\",\n        \"reason\": \"conditionNotMet\",\n        \"locationType\": \"header\",\n        \"location\": \"If-Match\"\n      }\n    ]\n  }\n}\n";

/// The JSON API object guards as production answers them under strict (recorded, probe-v4,
/// lean-v4 and lean-v5; the official emulator reads no preconditions, so the emulator profile
/// ignores them, see the next test): a
/// not-match guard that names the current value is a 304 without a body on PATCH, PUT, DELETE,
/// upload and the reads; a match guard that does not hold, or whose value is the negative number
/// `-1`, is the 412 body; a not-match guard of `-1` is accepted (a value that is no number at all
/// is the 400 of the next test). `PUT` updates the metadata and answers the object resource with
/// the metageneration one higher.
#[test]
#[allow(clippy::too_many_lines)]
fn json_api_object_guards_and_put_answer_as_recorded() {
    for acceptance in [TokenAcceptance::Verified] {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let object = format!("/storage/v1/b/{BUCKET}/o/g.bin");
        let upload = |q: &str| {
            handle(
                &s,
                req(
                    "POST",
                    &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=g.bin{q}"),
                    &[
                        ("authorization", "Bearer owner"),
                        ("content-type", "application/octet-stream"),
                    ],
                    b"hello",
                ),
            )
        };
        let seeded = upload("&ifGenerationMatch=0");
        assert_eq!(seeded.status, 200, "{acceptance:?}");
        let generation = json_body(&seeded)["generation"]
            .as_str()
            .unwrap()
            .to_owned();
        let call = |method: &str, q: &str, body: &[u8]| {
            handle(
                &s,
                req(
                    method,
                    &format!("{object}?{q}"),
                    &[
                        ("authorization", "Bearer owner"),
                        ("content-type", "application/json"),
                    ],
                    body,
                ),
            )
        };
        let body =
            br#"{"contentType":"application/octet-stream","metadata":{"marker":"subject-update"}}"#;
        // 304: no body, `application/json`, on every method; media reads say octet-stream.
        for method in ["PATCH", "PUT"] {
            let r = call(method, &format!("ifGenerationNotMatch={generation}"), body);
            assert_eq!(r.status, 304, "{acceptance:?} {method}");
            assert!(r.body.is_empty());
            assert_eq!(header(&r, "content-type"), Some("application/json"));
            let r = call(
                method,
                &format!("ifGenerationMatch={generation}&ifMetagenerationNotMatch=1"),
                body,
            );
            assert_eq!(r.status, 304, "{acceptance:?} {method}");
        }
        let r = upload(&format!("&ifGenerationNotMatch={generation}"));
        assert_eq!((r.status, r.body.len()), (304, 0), "{acceptance:?} upload");
        assert_eq!(header(&r, "content-type"), Some("application/json"));
        let r = call("DELETE", &format!("ifGenerationNotMatch={generation}"), b"");
        assert_eq!((r.status, r.body.len()), (304, 0), "{acceptance:?} delete");
        assert_eq!(header(&r, "content-type"), Some("application/json"));
        let r = call("GET", &format!("ifGenerationNotMatch={generation}"), b"");
        assert_eq!(r.status, 304);
        assert_eq!(header(&r, "content-type"), Some("application/json"));
        let r = call(
            "GET",
            &format!("alt=media&ifGenerationNotMatch={generation}"),
            b"",
        );
        assert_eq!(r.status, 304);
        assert_eq!(header(&r, "content-type"), Some("application/octet-stream"));
        // 412: the recorded body for a match guard that does not hold or is not a number.
        for (method, q) in [
            ("PATCH", "ifGenerationMatch=999999".to_owned()),
            (
                "PUT",
                format!("ifGenerationMatch={generation}&ifMetagenerationMatch=-1"),
            ),
            (
                "DELETE",
                format!("ifGenerationMatch={generation}&ifMetagenerationMatch=-1"),
            ),
            (
                "GET",
                format!("ifGenerationMatch={generation}&ifMetagenerationMatch=-1"),
            ),
            ("GET", "ifGenerationMatch=999999".to_owned()),
        ] {
            let r = call(method, &q, body);
            assert_eq!(r.status, 412, "{acceptance:?} {method} {q}");
            assert_eq!(String::from_utf8_lossy(&r.body), PRODUCTION_412_BODY);
            assert_eq!(
                header(&r, "content-type"),
                Some("application/json; charset=UTF-8")
            );
        }
        let r = call("GET", "alt=media&ifGenerationMatch=999999", b"");
        assert_eq!(r.status, 412);
        assert_eq!(
            String::from_utf8_lossy(&r.body),
            "At least one of the pre-conditions you specified did not hold."
        );
        assert!(header(&r, "content-type").unwrap().starts_with("text/html"));
        // A not-match guard that is not a number is accepted: PUT updates, the metageneration moves.
        let r = call(
            "PUT",
            &format!("ifGenerationMatch={generation}&ifMetagenerationNotMatch=-1"),
            body,
        );
        assert_eq!(
            r.status,
            200,
            "{acceptance:?}: {}",
            String::from_utf8_lossy(&r.body)
        );
        let put = json_body(&r);
        assert_eq!(put["kind"], "storage#object");
        assert_eq!(put["metageneration"], "2");
        assert_eq!(put["metadata"], json!({"marker": "subject-update"}));
        assert_eq!(put["contentType"], "application/octet-stream");
        assert_eq!(put["generation"], generation);
        // The same guard on DELETE goes ahead and deletes.
        let r = call(
            "DELETE",
            &format!("ifGenerationMatch={generation}&ifMetagenerationNotMatch=-1"),
            b"",
        );
        assert_eq!(r.status, 204);
        assert_eq!(call("GET", "", b"").status, 404);
    }
}

/// The 400 production answers to a guard value that is no `long` (recorded, lean-v4 and lean-v5:
/// `1.5`, `not-a-number` and an empty value, for the match and the not-match metageneration
/// guards of PATCH, PUT and DELETE; the recorded lengths are 311, 314, 317, 320, 335 and 338).
/// A refused DELETE keeps the object.
#[test]
fn strict_guard_values_that_are_no_long_answer_the_recorded_400() {
    let s = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    let object = format!("/storage/v1/b/{BUCKET}/o/l.bin");
    let seeded = handle(
        &s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=l.bin"),
            &[
                ("authorization", "Bearer owner"),
                ("content-type", "application/octet-stream"),
            ],
            b"hello",
        ),
    );
    let generation = json_body(&seeded)["generation"]
        .as_str()
        .unwrap()
        .to_owned();
    let call = |method: &str, q: &str| {
        handle(
            &s,
            req(
                method,
                &format!("{object}?{q}"),
                &[
                    ("authorization", "Bearer owner"),
                    ("content-type", "application/json"),
                ],
                br#"{"metadata":{"k":"v"}}"#,
            ),
        )
    };
    let expected = |value: &str, key: &str| {
        let message = format!("Invalid long value: '{value}'.");
        format!(
            "{{\n  \"error\": {{\n    \"code\": 400,\n    \"message\": \"{message}\",\n    \"errors\": [\n      {{\n        \"message\": \"{message}\",\n        \"domain\": \"global\",\n        \"reason\": \"invalidParameter\",\n        \"locationType\": \"parameter\",\n        \"location\": \"{key}\"\n      }}\n    ]\n  }}\n}}\n"
        )
    };
    let lengths = [
        ("", "ifMetagenerationMatch", 311),
        ("", "ifMetagenerationNotMatch", 314),
        ("1.5", "ifMetagenerationMatch", 317),
        ("1.5", "ifMetagenerationNotMatch", 320),
        ("not-a-number", "ifMetagenerationMatch", 335),
        ("not-a-number", "ifMetagenerationNotMatch", 338),
    ];
    for method in ["PATCH", "PUT", "DELETE"] {
        for (value, key, length) in lengths {
            let q = format!("ifGenerationMatch={generation}&{key}={value}");
            let r = call(method, &q);
            assert_eq!(r.status, 400, "{method} {q}");
            assert_eq!(r.body.len(), length, "{method} {q}");
            assert_eq!(String::from_utf8_lossy(&r.body), expected(value, key));
            assert_eq!(
                header(&r, "content-type"),
                Some("application/json; charset=UTF-8")
            );
        }
        // A generation guard is read by the same parser.
        let r = call(method, "ifGenerationNotMatch=abc");
        assert_eq!(r.status, 400, "{method}");
        assert_eq!(
            String::from_utf8_lossy(&r.body),
            expected("abc", "ifGenerationNotMatch")
        );
        // The refused write changed nothing.
        let read = call("GET", "");
        assert_eq!(read.status, 200, "{method}");
        assert_eq!(json_body(&read)["metageneration"], "1", "{method}");
    }
    // A negative value is a number: it fails a match guard and holds a not-match guard.
    assert_eq!(call("PATCH", "ifMetagenerationMatch=-1").status, 412);
    assert_eq!(call("PATCH", "ifMetagenerationNotMatch=-1").status, 200);
    assert_eq!(call("DELETE", "ifMetagenerationNotMatch=-1").status, 204);
    assert_eq!(call("GET", "").status, 404);
}

/// `PUT` on the JSON API object replaces the custom metadata and drops the download tokens
/// (recorded, lean-v4 1344 to 1349); `PATCH` merges and keeps the token. The metageneration rises
/// by one either way. The official emulator answers 501, so both profiles serve production's
/// answer.
#[test]
fn a_put_replaces_the_custom_metadata_and_the_download_tokens() {
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let owner = [
            ("authorization", "Bearer owner"),
            ("content-type", "application/json"),
        ];
        let object = format!("/storage/v1/b/{BUCKET}/o/r.bin");
        let seeded = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=r.bin"),
                &[
                    ("authorization", "Bearer owner"),
                    ("content-type", "application/octet-stream"),
                ],
                b"hello",
            ),
        );
        assert_eq!(seeded.status, 200, "{acceptance:?}");
        let minted = handle(
            &s,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o/r.bin?create_token=true"),
                &owner,
                b"",
            ),
        );
        assert_eq!(minted.status, 200, "{acceptance:?}");
        let token = json_body(&minted)["downloadTokens"]
            .as_str()
            .unwrap()
            .to_owned();
        let patch = handle(
            &s,
            req(
                "PATCH",
                &object,
                &owner,
                br#"{"metadata":{"marker":"advanced","keep":"1"}}"#,
            ),
        );
        let patched = json_body(&patch);
        assert_eq!(
            patched["metadata"]["firebaseStorageDownloadTokens"], token,
            "{acceptance:?}: a PATCH keeps the token"
        );
        assert_eq!(patched["metadata"]["keep"], "1");
        let before = patched["metageneration"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let put = handle(
            &s,
            req(
                "PUT",
                &object,
                &owner,
                br#"{"metadata":{"marker":"subject-update"}}"#,
            ),
        );
        assert_eq!(put.status, 200, "{acceptance:?}");
        let put = json_body(&put);
        assert_eq!(
            put["metadata"],
            json!({"marker": "subject-update"}),
            "{acceptance:?}: the earlier key and the token are gone"
        );
        assert_eq!(
            put["metageneration"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap(),
            before + 1
        );
        let read = handle(&s, req("GET", &object, &owner, b""));
        assert_eq!(
            json_body(&read)["metadata"],
            json!({"marker": "subject-update"})
        );
        // The old token is dead: the next Firebase metadata read mints another (recorded, lean-v4
        // 1352), so a download URL made before the PUT stops working.
        let v0 = handle(
            &s,
            req("GET", &format!("/v0/b/{BUCKET}/o/r.bin"), &owner, b""),
        );
        let reminted = json_body(&v0)["downloadTokens"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(reminted, token, "{acceptance:?}");
        // An empty `metadata` object replaces everything with nothing.
        let cleared = handle(&s, req("PUT", &object, &owner, br#"{"metadata":{}}"#));
        assert_eq!(json_body(&cleared).get("metadata"), None, "{acceptance:?}");
    }
}

/// A read of an object name with a line feed is a missing object on both dialects (recorded,
/// lean-v5: 404 on the metadata and the media read of the Firebase dialect and the JSON API),
/// not a 400 from the name check.
#[test]
fn a_read_of_a_name_with_a_line_feed_is_not_found() {
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let owner = [("authorization", "Bearer owner")];
        for (path, expect_json) in [
            (format!("/v0/b/{BUCKET}/o/a%0Ab.txt"), true),
            (format!("/v0/b/{BUCKET}/o/a%0Ab.txt?alt=media"), true),
            (format!("/storage/v1/b/{BUCKET}/o/a%0Ab.txt"), true),
            (
                format!("/storage/v1/b/{BUCKET}/o/a%0Ab.txt?alt=media"),
                false,
            ),
        ] {
            let r = handle(&s, req("GET", &path, &owner, b""));
            assert_eq!(r.status, 404, "{acceptance:?} {path}");
            let json = header(&r, "content-type")
                .unwrap()
                .starts_with("application/json");
            let v0 = path.starts_with("/v0/");
            assert_eq!(json, expect_json || v0, "{acceptance:?} {path}");
            if !v0 && json {
                assert!(String::from_utf8_lossy(&r.body).contains("No such object"));
            }
        }
    }
}

/// The emulator profile does what the official emulator does with every guard (measured,
/// firebase-tools 15.28.2): it reads none, so a not-match guard that names the current value, a
/// match guard that does not hold and a value that is not a number all let the request complete,
/// on PATCH, PUT, DELETE, upload, copy and the reads. It never refuses what the official emulator
/// completes.
#[test]
fn the_emulator_profile_ignores_every_json_api_guard() {
    let s = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::EmulatorMock);
    let owner = [
        ("authorization", "Bearer owner"),
        ("content-type", "application/json"),
    ];
    let upload = |q: &str| {
        handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=i.bin{q}"),
                &[
                    ("authorization", "Bearer owner"),
                    ("content-type", "application/octet-stream"),
                ],
                b"hello",
            ),
        )
    };
    let seeded = upload("");
    assert_eq!(seeded.status, 200);
    let generation = json_body(&seeded)["generation"]
        .as_str()
        .unwrap()
        .to_owned();
    let object = format!("/storage/v1/b/{BUCKET}/o/i.bin");
    let call = |method: &str, q: &str| {
        handle(
            &s,
            req(
                method,
                &format!("{object}?{q}"),
                &owner,
                br#"{"contentType":"application/octet-stream","metadata":{"m":"1"}}"#,
            ),
        )
        .status
    };
    // Reads: a not-match guard naming the current value, and a match guard that fails.
    assert_eq!(
        call("GET", &format!("ifGenerationNotMatch={generation}")),
        200
    );
    assert_eq!(
        call(
            "GET",
            "alt=media&ifGenerationNotMatch=999999&ifMetagenerationMatch=abc"
        ),
        200
    );
    assert_eq!(call("GET", "ifGenerationMatch=999999"), 200);
    // Updates: not-match naming the current value, a failing and a malformed match guard.
    for method in ["PATCH", "PUT"] {
        assert_eq!(
            call(method, &format!("ifGenerationNotMatch={generation}")),
            200,
            "{method}"
        );
        assert_eq!(call(method, "ifGenerationMatch=999999"), 200, "{method}");
        assert_eq!(call(method, "ifMetagenerationMatch=-1"), 200, "{method}");
    }
    // An upload over an existing object ignores `ifGenerationMatch=0` and a not-match guard.
    assert_eq!(upload("&ifGenerationMatch=0").status, 200);
    let current = json_body(&upload(""))
        .get("generation")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        upload(&format!("&ifGenerationNotMatch={current}")).status,
        200
    );
    // Copy source guards.
    let copy = handle(
        &s,
        req(
            "POST",
            &format!("/storage/v1/b/{BUCKET}/o/i.bin/copyTo/b/{BUCKET}/o/j.bin?ifSourceGenerationMatch=999999"),
            &owner,
            b"{}",
        ),
    );
    assert_eq!(copy.status, 200, "{}", String::from_utf8_lossy(&copy.body));
    // Deletes.
    assert_eq!(
        call(
            "DELETE",
            "ifGenerationNotMatch=999999&ifGenerationMatch=abc"
        ),
        204
    );
    assert_eq!(call("GET", ""), 404);
}

/// The JSON API list with `maxResults=0` is the bare kind under strict (recorded, lean-v4: 200, the
/// 32 bytes `{ "kind": "storage#objects" }` in the Google-fronted layout); the official emulator
/// answers a next-page token naming the first object (measured, firebase-tools 15.28.2), which the
/// emulator profile keeps.
#[test]
fn the_json_api_list_with_max_results_zero_is_the_bare_kind_only_under_strict() {
    let route = format!("/storage/v1/b/{BUCKET}/o?maxResults=0");
    let owner = [("authorization", "Bearer owner")];
    let strict = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    assert_eq!(anonymous_media_upload(&strict, "l.txt"), 200);
    let r = handle(&strict, req("GET", &route, &owner, b""));
    assert_eq!(r.status, 200);
    assert_eq!(
        String::from_utf8_lossy(&r.body),
        "{\n  \"kind\": \"storage#objects\"\n}\n"
    );
    assert_eq!(r.body.len(), 32);
    assert_eq!(
        header(&r, "content-type"),
        Some("application/json; charset=UTF-8")
    );
    let emulator = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::EmulatorMock);
    assert_eq!(anonymous_media_upload(&emulator, "l.txt"), 200);
    let r = handle(&emulator, req("GET", &route, &owner, b""));
    assert_eq!(r.status, 200);
    assert_eq!(json_body(&r)["nextPageToken"], "l.txt");
}

/// The headers of a media answer under strict follow what production sent (recorded, lean-v4 and
/// lean-v5): the stored content encoding and length and `x-goog-metageneration`, no empty
/// `content-encoding`, the JSON API without `accept-ranges` but with `vary` and an `attachment`
/// disposition, the Firebase dialect with `accept-ranges`, the custom metadata and the download
/// token as `x-goog-meta-*` headers and no disposition when none is stored. The emulator profile
/// keeps the official emulator's headers (measured, firebase-tools 15.28.2).
#[test]
#[allow(clippy::too_many_lines)]
fn media_headers_follow_production_only_under_strict() {
    let owner = [("authorization", "Bearer owner")];
    let (ct, body) = multipart(
        &json!({"contentType": "text/plain", "metadata": {"color": "red"}}),
        "text/plain",
        b"hello",
    );
    for acceptance in BOTH_PROFILES {
        let strict = acceptance == TokenAcceptance::Verified;
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let fb = handle(
            &s,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=fb.txt&uploadType=multipart"),
                &[
                    ("content-type", &ct),
                    ("x-goog-upload-protocol", "multipart"),
                ],
                &body,
            ),
        );
        assert_eq!(fb.status, 200);
        let token = json_body(&fb)["downloadTokens"]
            .as_str()
            .unwrap()
            .to_owned();
        let seeded = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=g.txt"),
                &[
                    ("authorization", "Bearer owner"),
                    ("content-type", "text/plain"),
                ],
                b"hello",
            ),
        );
        assert_eq!(seeded.status, 200);
        let v0 = handle(
            &s,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o/fb.txt?alt=media"),
                &[],
                b"",
            ),
        );
        let gcs = handle(
            &s,
            req(
                "GET",
                &format!("/storage/v1/b/{BUCKET}/o/g.txt?alt=media"),
                &owner,
                b"",
            ),
        );
        assert_eq!((v0.status, gcs.status), (200, 200));
        if strict {
            assert_eq!(header(&v0, "x-goog-metageneration"), Some("1"));
            assert_eq!(
                header(&v0, "x-goog-stored-content-encoding"),
                Some("identity")
            );
            assert_eq!(header(&v0, "x-goog-stored-content-length"), Some("5"));
            assert_eq!(header(&v0, "x-goog-meta-color"), Some("red"));
            assert_eq!(
                header(&v0, "x-goog-meta-firebasestoragedownloadtokens"),
                Some(token.as_str())
            );
            assert_eq!(header(&v0, "accept-ranges"), Some("bytes"));
            assert_eq!(header(&v0, "pragma"), Some("no-cache"));
            assert!(header(&v0, "content-encoding").is_none());
            assert!(header(&v0, "x-goog-metadatageneration").is_none());
            assert!(header(&v0, "vary").is_none());
            assert_eq!(
                header(&v0, "content-disposition"),
                Some("inline; filename*=utf-8''fb.txt")
            );
            assert_eq!(
                header(&v0, "x-goog-hash"),
                Some("crc32c=mnG7TA==, md5=XUFAKrxLKna5cZ2REBfFkg==")
            );
            assert_eq!(header(&gcs, "content-disposition"), Some("attachment"));
            let varies: Vec<&str> = gcs
                .headers
                .iter()
                .filter(|(name, _)| name == "vary")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(varies, ["Origin", "X-Origin"]);
            assert!(header(&gcs, "accept-ranges").is_none());
            assert_eq!(
                header(&gcs, "x-goog-hash"),
                Some("crc32c=mnG7TA==,md5=XUFAKrxLKna5cZ2REBfFkg==")
            );
            assert_eq!(
                header(&gcs, "cache-control"),
                Some("no-cache, no-store, max-age=0, must-revalidate")
            );
            assert!(header(&gcs, "x-goog-meta-color").is_none());
        } else {
            assert_eq!(header(&v0, "x-goog-metadatageneration"), Some("1"));
            assert_eq!(header(&v0, "content-encoding"), Some(""));
            assert!(header(&v0, "x-goog-meta-color").is_none());
            assert_eq!(header(&gcs, "accept-ranges"), Some("bytes"));
            assert!(header(&gcs, "x-goog-stored-content-length").is_none());
        }
    }
}

/// `PATCH /storage/v1/b/{bucket}/o/{object}` updates object metadata, as the Cloud Storage
/// JSON API does in production (recorded: stage 3 v9, `setup/seed-metadata` and
/// `boundary-gcs-admin-patch-present`, a 200 with the `storage#object` resource; an absent
/// object answers the 404 `No such object` JSON error). The official emulator registers PATCH
/// only on the short `/b/...` spelling and answers 501 here; fireemu implements it (a published
/// divergence), honouring `ifGenerationMatch` and `ifMetagenerationMatch` as production does.
#[test]
#[allow(clippy::too_many_lines)]
fn json_api_patch_on_the_storage_v1_spelling_updates_metadata_as_production_does() {
    let s = state(None);
    let (ct, body) = multipart(
        &json!({"name": "p.bin", "metadata": {"owner": "old"}}),
        "text/plain",
        b"base",
    );
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=multipart"),
            &[("content-type", &ct)],
            &body,
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let first = json_body(&r);
    let generation = first["generation"].as_str().unwrap().to_owned();
    assert_eq!(first["metageneration"], "1");
    let patch = |query: &str, body: &[u8]| {
        handle(
            &s,
            req(
                "PATCH",
                &format!("/storage/v1/b/{BUCKET}/o/p.bin{query}"),
                &[
                    ("authorization", "Bearer owner"),
                    ("content-type", "application/json"),
                ],
                body,
            ),
        )
    };
    // The metadata update answers the object resource with the metageneration advanced.
    let r = patch(
        &format!("?ifGenerationMatch={generation}&ifMetagenerationMatch=1"),
        br#"{"metadata": {"owner": "new", "extra": "x"}}"#,
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let patched = json_body(&r);
    assert_eq!(patched["kind"], "storage#object");
    assert_eq!(patched["name"], "p.bin");
    assert_eq!(patched["generation"].as_str(), Some(generation.as_str()));
    assert_eq!(patched["metageneration"], "2");
    assert_eq!(patched["metadata"]["owner"], "new");
    assert_eq!(patched["metadata"]["extra"], "x");
    // The object read back shows the update, and a null value removes a key.
    let r = patch("", br#"{"metadata": {"extra": null}}"#);
    assert_eq!(r.status, 200);
    assert_eq!(json_body(&r)["metageneration"], "3");
    assert!(json_body(&r)["metadata"].get("extra").is_none());
    // A stale precondition is refused without changing the object.
    let r = patch(
        "?ifMetagenerationMatch=1",
        br#"{"metadata": {"owner": "stale"}}"#,
    );
    assert_eq!(r.status, 412);
    assert_eq!(
        json_body(&r)["error"]["errors"][0]["reason"],
        "conditionNotMet"
    );
    let r = patch(
        "?ifGenerationMatch=99999",
        br#"{"metadata": {"owner": "stale"}}"#,
    );
    assert_eq!(r.status, 412);
    let r = handle(
        &s,
        req(
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/p.bin"),
            &[("authorization", "Bearer owner")],
            b"",
        ),
    );
    assert_eq!(json_body(&r)["metadata"]["owner"], "new");
    assert_eq!(json_body(&r)["metageneration"], "3");
    // An object that is not there is the JSON 404, a match guard that is no number is the 400
    // of production and a malformed body is a 400.
    let r = handle(
        &s,
        req(
            "PATCH",
            &format!("/storage/v1/b/{BUCKET}/o/missing.bin"),
            &[("content-type", "application/json")],
            br#"{"metadata": {"a": "b"}}"#,
        ),
    );
    assert_eq!(r.status, 404);
    assert_eq!(
        json_body(&r)["error"]["message"],
        format!("No such object: {BUCKET}/missing.bin")
    );
    assert_eq!(json_body(&r)["error"]["errors"][0]["reason"], "notFound");
    let refused = patch("?ifGenerationMatch=garbage", b"{}");
    assert_eq!(refused.status, 400);
    assert_eq!(
        json_body(&refused)["error"]["message"],
        "Invalid long value: 'garbage'."
    );
    assert_eq!(patch("", b"{not json").status, 400);
    // The download spelling stays GET-only, and the short spelling is unchanged.
    let r = handle(
        &s,
        req(
            "PATCH",
            &format!("/download/storage/v1/b/{BUCKET}/o/p.bin"),
            &[("content-type", "application/json")],
            b"{}",
        ),
    );
    assert_eq!(r.status, 501);
    let r = handle(
        &s,
        req(
            "PATCH",
            &format!("/b/{BUCKET}/o/p.bin"),
            &[("content-type", "application/json")],
            br#"{"metadata": {"short": "spelling"}}"#,
        ),
    );
    assert_eq!(r.status, 200);
    assert_eq!(json_body(&r)["metageneration"], "4");
}

#[test]
#[allow(clippy::too_many_lines)]
fn json_api_preconditions_generations_and_ranges_are_strict() {
    let s = state(None);
    let (ct, body) = multipart(
        &json!({"name": "g.bin"}),
        "application/octet-stream",
        b"0123456789",
    );
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=multipart"),
            &[("content-type", &ct)],
            &body,
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let generation = json_body(&r)["generation"].as_str().unwrap().to_owned();
    let object = format!("/storage/v1/b/{BUCKET}/o/g.bin");
    // A match guard that is no number is the 400 production answers (recorded, lean-v4; the
    // exact bytes are in the guards test) and the object stays.
    let r = handle(
        &s,
        req(
            "DELETE",
            &format!("{object}?ifGenerationMatch=garbage"),
            &[],
            b"",
        ),
    );
    assert_eq!(r.status, 400);
    assert_eq!(
        json_body(&r)["error"]["errors"][0]["reason"],
        "invalidParameter"
    );
    // A stale generation selector never targets the live object.
    let r = handle(
        &s,
        req("DELETE", &format!("{object}?generation=99999"), &[], b""),
    );
    assert_eq!(r.status, 404);
    assert_eq!(json_body(&r)["error"]["errors"][0]["reason"], "notFound");
    assert_eq!(
        handle(
            &s,
            req("GET", &format!("{object}?generation=99999"), &[], b"")
        )
        .status,
        404
    );
    assert_eq!(
        handle(
            &s,
            req(
                "GET",
                &format!("{object}?generation={generation}"),
                &[],
                b""
            )
        )
        .status,
        200
    );
    // Not-match preconditions and the core error shape (single JSON envelope).
    let r = handle(
        &s,
        req(
            "DELETE",
            &format!("{object}?ifGenerationNotMatch={generation}"),
            &[],
            b"",
        ),
    );
    // A not-match guard that names the current value is the bodiless 304 (recorded, lean-v4).
    assert_eq!(r.status, 304, "{}", String::from_utf8_lossy(&r.body));
    assert!(r.body.is_empty());
    // Ranges: suffix, open end, unsatisfiable.
    let get = |range: &str| {
        handle(
            &s,
            req(
                "GET",
                &format!("{object}?alt=media"),
                &[("range", range)],
                b"",
            ),
        )
    };
    let r = get("bytes=-3");
    assert_eq!((r.status, r.body.as_ref()), (206, &b"789"[..]));
    assert_eq!(header(&r, "content-range"), Some("bytes 7-9/10"));
    let r = get("bytes=8-");
    assert_eq!((r.status, r.body.as_ref()), (206, &b"89"[..]));
    let r = get("bytes=2-4");
    assert_eq!((r.status, r.body.as_ref()), (206, &b"234"[..]));
    // Production rejects a valid but unsatisfiable range, while emulator mode keeps the
    // official emulator's whole-object fallback.
    // https://cloud.google.com/storage/docs/json_api/v1/status-codes
    // https://www.rfc-editor.org/rfc/rfc9110.html#section-14.4
    // The recorded answers (lean-v4/v5): the JSON API says it in a sentence typed `text/html`,
    // the Firebase dialect in an XML error that names the range asked for.
    let r = get("bytes=10-");
    assert_eq!(r.status, 416);
    assert_eq!(header(&r, "content-range"), Some("bytes */10"));
    assert_eq!(
        String::from_utf8_lossy(&r.body),
        "Request range not satisfiable"
    );
    assert_eq!(header(&r, "content-type"), Some("text/html; charset=UTF-8"));
    let r = handle(
        &s,
        req(
            "GET",
            &format!("/v0/b/{BUCKET}/o/g.bin?alt=media"),
            &[("authorization", "Bearer owner"), ("range", "bytes=10-")],
            b"",
        ),
    );
    assert_eq!(r.status, 416);
    assert!(header(&r, "content-range").is_none());
    assert_eq!(
        String::from_utf8_lossy(&r.body),
        "<?xml version='1.0' encoding='UTF-8'?><Error><Code>InvalidRange</Code><Message>The requested range cannot be satisfied.</Message><Details>bytes=10-</Details></Error>"
    );
    assert_eq!(
        header(&r, "content-type"),
        Some("application/xml; charset=UTF-8")
    );
    let compatible = state_with(None, TokenAcceptance::EmulatorMock);
    let uploaded = handle(
        &compatible,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=multipart"),
            &[("content-type", &ct)],
            &body,
        ),
    );
    assert_eq!(uploaded.status, 200);
    let r = handle(
        &compatible,
        req(
            "GET",
            &format!("{object}?alt=media"),
            &[("range", "bytes=10-")],
            b"",
        ),
    );
    assert_eq!((r.status, r.body.as_ref()), (200, &b"0123456789"[..]));
    // Resumable JSON API: the declared span must match the body and the total.
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=r.bin"),
            &[("content-type", "application/json")],
            b"{}",
        ),
    );
    let session = header(&r, "location")
        .unwrap()
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap()
        .to_owned();
    let r = handle(
        &s,
        req(
            "PUT",
            &session,
            &[("content-range", "bytes 0-99/100")],
            b"x",
        ),
    );
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    let r = handle(
        &s,
        req("PUT", &session, &[("content-range", "bytes 0-2/6")], b"abc"),
    );
    assert_eq!(r.status, 308, "{}", String::from_utf8_lossy(&r.body));
    let r = handle(
        &s,
        req("PUT", &session, &[("content-range", "bytes 3-5/7")], b"def"),
    );
    assert_eq!(r.status, 400, "a different total is a size mismatch");
    let r = handle(
        &s,
        req("PUT", &session, &[("content-range", "bytes 3-5/6")], b"def"),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(json_body(&r)["size"], "6");
}

#[test]
fn an_empty_object_with_a_nonzero_suffix_range_is_an_empty_206_only_under_strict() {
    // Recorded on the JSON API (lean-v4): `bytes=-1` of an empty object answers 206 with
    // `Content-Range: bytes 0-0/0` and no body; the emulator profile keeps the official
    // emulator's whole-object 200.
    for (acceptance, status) in [
        (TokenAcceptance::Verified, 206),
        (TokenAcceptance::EmulatorMock, 200),
    ] {
        let s = state_with(None, acceptance);
        let object = format!("/storage/v1/b/{BUCKET}/o/empty.bin");
        let uploaded = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=empty.bin"),
                &[],
                b"",
            ),
        );
        assert_eq!(uploaded.status, 200);
        let response = handle(
            &s,
            req(
                "GET",
                &format!("{object}?alt=media"),
                &[("range", "bytes=-5")],
                b"",
            ),
        );
        assert_eq!(response.status, status, "{acceptance:?}");
        assert!(response.body.is_empty());
        if acceptance == TokenAcceptance::Verified {
            assert_eq!(header(&response, "content-range"), Some("bytes 0-0/0"));
        }
        // `bytes=0-` and `bytes=-0` of an empty object are unsatisfiable under strict.
        for range in ["bytes=0-", "bytes=0-0", "bytes=-0"] {
            let r = handle(
                &s,
                req(
                    "GET",
                    &format!("{object}?alt=media"),
                    &[("range", range)],
                    b"",
                ),
            );
            assert_eq!(
                r.status,
                if acceptance == TokenAcceptance::Verified {
                    416
                } else {
                    200
                },
                "{acceptance:?} {range}"
            );
        }
    }
}

#[test]
fn v1_rulesets_never_grant_lists() {
    let s = state(Some(
        "service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} { allow read; }
  }
}",
    ));
    let (_uid, auth) = user_token(&s);
    assert_eq!(
        handle(
            &s,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o/x"),
                &[("authorization", &auth)],
                b""
            )
        )
        .status,
        404,
        "get is allowed (and finds nothing)"
    );
    let r = handle(
        &s,
        req(
            "GET",
            &format!("/v0/b/{BUCKET}/o"),
            &[("authorization", &auth)],
            b"",
        ),
    );
    // Production refuses the list itself, before any rule is read (stage 3 v9,
    // `list-v1-read-list-present` and `-absent`): 400 with this message.
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(
        json_body(&r)["error"]["message"],
        "Listing objects in a bucket is disallowed for rules_version = \"1\".\nPlease update storage security rules to rules_version = \"2\" to use list."
    );
}

#[test]
fn rewrite_honours_source_preconditions_and_conditional_reads() {
    let s = state(Some(
        "rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /open/{file} { allow read, write: if true; }
  }
}",
    ));
    let (ct, body) = multipart(&json!({"name": "open/src"}), "text/plain", b"src");
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=multipart"),
            &[("content-type", &ct)],
            &body,
        ),
    );
    assert_eq!(r.status, 200);
    let generation = json_body(&r)["generation"].as_str().unwrap().to_owned();
    // The JSON API is the privileged dialect: rules never run on either spelling.
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/storage/v1/b/{BUCKET}/o/open%2Fsrc/rewriteTo/b/{BUCKET}/o/open%2Fdst"),
            &[],
            b"",
        ),
    );
    assert_eq!(r.status, 200);
    assert_eq!(json_body(&r)["resource"]["name"], "open/dst");
    let r = handle(&s, req(
            "POST",
            &format!("/b/{BUCKET}/o/closed%2Fmissing/rewriteTo/b/{BUCKET}/o/open%2Fdst?ifSourceGenerationMatch=1"),
            &[],
            b"",
        ),
    );
    assert_eq!(r.status, 404, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(
        json_body(&r)["error"]["message"],
        format!("No such object: {BUCKET}/closed/missing")
    );
    let r = handle(&s, req(
            "POST",
            &format!("/b/{BUCKET}/o/open%2Fsrc/rewriteTo/b/{BUCKET}/o/open%2Fdst?ifSourceGenerationMatch=999"),
            &[],
            b"",
        ),
    );
    assert_eq!(r.status, 412, "{}", String::from_utf8_lossy(&r.body));
    // Conditional reads: not-match naming the current generation is 304, match failing is 412.
    let object = format!("/storage/v1/b/{BUCKET}/o/open%2Fsrc");
    let r = handle(
        &s,
        req(
            "GET",
            &format!("{object}?ifGenerationNotMatch={generation}"),
            &[],
            b"",
        ),
    );
    assert_eq!(r.status, 304);
    assert!(r.body.is_empty());
    let r = handle(
        &s,
        req("GET", &format!("{object}?ifGenerationMatch=999"), &[], b""),
    );
    assert_eq!(r.status, 412);
    let r = handle(
        &s,
        req(
            "GET",
            &format!("{object}?ifGenerationMatch=1&ifGenerationNotMatch=2"),
            &[],
            b"",
        ),
    );
    assert_eq!(r.status, 400, "conflicting predicates");
    // A closing delimiter followed by more text is payload, not the end of the body.
    let data = b"--fireemu-boundary--tail\r\n";
    let (ct, body) = multipart(&json!({"name": "open/tail"}), "text/plain", data);
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=multipart"),
            &[("content-type", &ct)],
            &body,
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(json_body(&r)["size"], data.len().to_string());
}

struct Flags(Vec<String>);

impl fireemu_core_rules::eval::DocumentAccess for Flags {
    fn get(&self, segments: &[String]) -> Option<fireemu_core_rules::value::RulesValue> {
        let path = segments.join("/");
        self.0.contains(&path).then(|| {
            let mut m = std::collections::BTreeMap::new();
            m.insert(
                "data".to_owned(),
                fireemu_core_rules::value::RulesValue::Map(std::collections::BTreeMap::from([(
                    "open".to_owned(),
                    fireemu_core_rules::value::RulesValue::Bool(true),
                )])),
            );
            fireemu_core_rules::value::RulesValue::Map(m)
        })
    }
}

struct CountingFlags {
    present: Vec<String>,
    reads: Arc<AtomicUsize>,
}

impl fireemu_core_rules::eval::DocumentAccess for CountingFlags {
    fn get(&self, segments: &[String]) -> Option<fireemu_core_rules::value::RulesValue> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let path = segments.join("/");
        self.present.contains(&path).then(|| {
            let mut m = std::collections::BTreeMap::new();
            m.insert(
                "data".to_owned(),
                fireemu_core_rules::value::RulesValue::Map(std::collections::BTreeMap::from([(
                    "open".to_owned(),
                    fireemu_core_rules::value::RulesValue::Bool(true),
                )])),
            );
            fireemu_core_rules::value::RulesValue::Map(m)
        })
    }
}

#[test]
fn storage_rules_can_read_firestore_documents() {
    let rules = "rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /gated/{file} {
      allow read: if firestore.exists(/databases/(default)/documents/flags/open)
                  && firestore.get(/databases/(default)/documents/flags/open).data.open == true;
    }
  }
}";
    let mut s = state(Some(rules));
    let (ct, body) = multipart(&json!({"contentType": "text/plain"}), "text/plain", b"x");
    let upload = format!("/v0/b/{BUCKET}/o?name=gated%2Fa.txt&uploadType=multipart");
    let r = handle(
        &s,
        req(
            "POST",
            &upload,
            &[("authorization", "Bearer owner"), ("content-type", &ct)],
            &body,
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let read = format!("/v0/b/{BUCKET}/o/gated%2Fa.txt?alt=media");
    // No Firestore access: the rule fails closed.
    assert_eq!(handle(&s, req("GET", &read, &[], b"")).status, 403);
    // The flag is absent: denied; present: allowed.
    s.firestore = Some(Arc::new(Flags(vec![])));
    assert_eq!(handle(&s, req("GET", &read, &[], b"")).status, 403);
    s.firestore = Some(Arc::new(Flags(vec![
        "databases/(default)/documents/flags/open".to_owned(),
    ])));
    assert_eq!(handle(&s, req("GET", &read, &[], b"")).status, 200);
}

#[test]
fn storage_rules_cache_repeated_firestore_reads_and_bound_distinct_reads() {
    let repeated_rules = "rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o/gated/{file} {
    allow read: if firestore.exists(/databases/(default)/documents/flags/open)
                && firestore.exists(/databases/(default)/documents/flags/open);
  }
}";
    let mut repeated = state(Some(repeated_rules));
    let (content_type, body) = multipart(&json!({}), "text/plain", b"stable");
    assert_eq!(
        handle(
            &repeated,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=gated/repeated.txt&uploadType=multipart"),
                &[
                    ("authorization", "Bearer owner"),
                    ("content-type", &content_type),
                    ("x-goog-upload-protocol", "multipart"),
                ],
                &body,
            ),
        )
        .status,
        200
    );
    let repeated_reads = Arc::new(AtomicUsize::new(0));
    repeated.firestore = Some(Arc::new(CountingFlags {
        present: vec!["databases/(default)/documents/flags/open".to_owned()],
        reads: repeated_reads.clone(),
    }));
    let repeated_read = format!("/v0/b/{BUCKET}/o/gated%2Frepeated.txt?alt=media");
    let response = handle(&repeated, req("GET", &repeated_read, &[], b""));
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(repeated_reads.load(Ordering::SeqCst), 1);

    let distinct_rules = "rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o/gated/{file} {
    allow read: if firestore.exists(/databases/(default)/documents/flags/a)
                && firestore.exists(/databases/(default)/documents/flags/b)
                && firestore.exists(/databases/(default)/documents/flags/c);
  }
}";
    let mut distinct = state(Some(distinct_rules));
    let (content_type, body) = multipart(&json!({}), "text/plain", b"stable");
    assert_eq!(
        handle(
            &distinct,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=gated/distinct.txt&uploadType=multipart"),
                &[
                    ("authorization", "Bearer owner"),
                    ("content-type", &content_type),
                    ("x-goog-upload-protocol", "multipart"),
                ],
                &body,
            ),
        )
        .status,
        200
    );
    let distinct_reads = Arc::new(AtomicUsize::new(0));
    distinct.firestore = Some(Arc::new(CountingFlags {
        present: ["a", "b", "c"]
            .into_iter()
            .map(|name| format!("databases/(default)/documents/flags/{name}"))
            .collect(),
        reads: distinct_reads.clone(),
    }));
    let distinct_read = format!("/v0/b/{BUCKET}/o/gated%2Fdistinct.txt?alt=media");
    let response = handle(&distinct, req("GET", &distinct_read, &[], b""));
    assert_eq!(response.status, 403);
    assert_eq!(distinct_reads.load(Ordering::SeqCst), 2);
    let store = distinct.store.lock().unwrap();
    let metadata = store
        .get(
            &BucketName::try_new(BUCKET).unwrap(),
            &ObjectName::try_new("gated/distinct.txt").unwrap(),
        )
        .expect("denied read keeps the object");
    assert_eq!(store.bytes(metadata), b"stable");
}

#[test]
fn fault_plans_fail_storage_operations() {
    use fireemu_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule};
    let mut s = state(None);
    let registry = Arc::new(fireemu_core_session::fault::FaultRegistry::new());
    let faults = registry.default_state();
    faults.lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "storage.upload".into(),
                nth: Some(1),
                function: None,
                event_type: None,
            },
            action: FaultAction::ReturnError {
                code: "UNAVAILABLE".into(),
            },
        }],
    });
    s.faults = Some(registry);
    let (ct, body) = multipart(&json!({"contentType": "text/plain"}), "text/plain", b"x");
    let upload = format!("/v0/b/{BUCKET}/o?name=f.txt&uploadType=multipart");
    let r = handle(
        &s,
        req(
            "POST",
            &upload,
            &[("authorization", "Bearer owner"), ("content-type", &ct)],
            &body,
        ),
    );
    assert_eq!(r.status, 503, "{}", String::from_utf8_lossy(&r.body));
    let r = handle(
        &s,
        req(
            "POST",
            &upload,
            &[("authorization", "Bearer owner"), ("content-type", &ct)],
            &body,
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}

#[test]
fn storage_tokens_are_bound_to_the_buckets_project() {
    let mut s = state(Some(ALLOW_ALL_RULES));
    let mut tenancy = fireemu_core_session::tenancy::Tenancy::new("demo-app");
    tenancy.register("demo-b", &[], &[]).unwrap();
    s.tenancy = Some(Arc::new(RwLock::new(tenancy)));
    assert!(s.auth.register(
        "demo-b",
        AuthStore::new("demo-b", SplitMix64::new(4), TotpPolicy::default())
    ));
    let token_b = {
        let store = s.auth.store_for("demo-b").unwrap();
        let mut store = store.lock().unwrap();
        let uid = store
            .create_user(NewUser::email("b@example.com"), START)
            .unwrap();
        let claims = store.id_token_claims(&uid, None, START).unwrap();
        format!(
            "Firebase {}",
            fireemu_core_auth::jwt::encode_unsigned(&claims)
        )
    };
    let (_, token_a) = user_token(&s);
    let (ct, body) = multipart(&json!({"contentType": "text/plain"}), "text/plain", b"x");
    let upload = |bucket: &str| format!("/v0/b/{bucket}/o?name=f.txt&uploadType=multipart");
    // A demo-b user on demo-app's bucket, and a demo-app user on demo-b's: refused before
    // any rule runs, with production's answer to a token of another project (stage 3 v9,
    // `token-foreign-project`: 403 "Permission denied.", not an authentication failure).
    for (bucket, token) in [(BUCKET, &token_b), ("demo-b.appspot.com", &token_a)] {
        let r = handle(
            &s,
            req(
                "POST",
                &upload(bucket),
                &[("authorization", token), ("content-type", &ct)],
                &body,
            ),
        );
        assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
        assert!(String::from_utf8_lossy(&r.body).contains("Permission denied."));
    }
    // Each user on their own project's bucket.
    for (bucket, token) in [(BUCKET, &token_a), ("demo-b.appspot.com", &token_b)] {
        let r = handle(
            &s,
            req(
                "POST",
                &upload(bucket),
                &[("authorization", token), ("content-type", &ct)],
                &body,
            ),
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
}

#[test]
fn drop_connection_faults_mark_the_response_for_the_server_to_close() {
    use fireemu_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule};
    let mut s = state(None);
    let registry = Arc::new(fireemu_core_session::fault::FaultRegistry::new());
    registry.default_state().lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "storage.read".into(),
                nth: Some(1),
                function: None,
                event_type: None,
            },
            action: FaultAction::DropConnection,
        }],
    });
    s.faults = Some(registry);
    let path = format!("/v0/b/{BUCKET}/o/f.txt?alt=media");
    let r = handle(
        &s,
        req("GET", &path, &[("authorization", "Bearer owner")], b""),
    );
    assert!(r
        .headers
        .iter()
        .any(|(k, v)| k == fireemu_adapter_http::storage::DROP_CONNECTION_HEADER && v == "1"));
    let r = handle(
        &s,
        req("GET", &path, &[("authorization", "Bearer owner")], b""),
    );
    assert_eq!(r.status, 404);
    assert!(!r
        .headers
        .iter()
        .any(|(k, _)| k == fireemu_adapter_http::storage::DROP_CONNECTION_HEADER));
}

#[test]
fn json_api_uploads_count_as_uploads_for_fault_plans() {
    use fireemu_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule};
    let mut s = state(None);
    let registry = Arc::new(fireemu_core_session::fault::FaultRegistry::new());
    registry.default_state().lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "storage.upload".into(),
                nth: Some(1),
                function: None,
                event_type: None,
            },
            action: FaultAction::Timeout,
        }],
    });
    s.faults = Some(registry.clone());
    let (ct, body) = multipart(&json!({"name": "j.txt"}), "text/plain", b"x");
    let path = format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=multipart");
    let r = handle(&s, req("POST", &path, &[("content-type", &ct)], &body));
    assert_eq!(r.status, 504, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(
        registry.default_state().lock().unwrap().counters()["storage.upload"],
        1
    );
}

#[test]
fn resumable_uploads_answer_only_under_their_own_bucket() {
    let s = state(None);
    let start = format!("/v0/b/{BUCKET}/o?name=r.txt&uploadType=resumable");
    let r = handle(
        &s,
        req(
            "POST",
            &start,
            &[
                ("authorization", "Bearer owner"),
                ("content-type", "application/json"),
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "start"),
                ("x-goog-upload-header-content-type", "text/plain"),
            ],
            b"{}",
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let upload_url = r
        .headers
        .iter()
        .find(|(k, _)| k == "x-goog-upload-url")
        .map(|(_, v)| v.clone())
        .unwrap();
    let upload_id = upload_url.split("upload_id=").nth(1).unwrap().to_owned();
    // The same upload ID under another bucket's URL: not this bucket's upload.
    let elsewhere = format!("/v0/b/other-bucket/o?name=r.txt&upload_id={upload_id}");
    let r = handle(
        &s,
        req(
            "POST",
            &elsewhere,
            &[
                ("authorization", "Bearer owner"),
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "upload, finalize"),
                ("x-goog-upload-offset", "0"),
            ],
            b"hello",
        ),
    );
    assert_eq!(r.status, 404, "{}", String::from_utf8_lossy(&r.body));
    let own = format!("/v0/b/{BUCKET}/o?name=r.txt&upload_id={upload_id}");
    let r = handle(
        &s,
        req(
            "POST",
            &own,
            &[
                ("authorization", "Bearer owner"),
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "upload, finalize"),
                ("x-goog-upload-offset", "0"),
            ],
            b"hello",
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}

// ------------------------------------------------------------------------------------------
// Upload buffer ownership and the in-flight body budget (STG-MEM-01..04)
//
// Copy elimination is proven by buffer identity: the address of the blob the store keeps is
// the address of the buffer the request arrived in. A payload-sized clone anywhere on the
// path would move the bytes to a different allocation and fail these assertions.
// ------------------------------------------------------------------------------------------

/// Address of the bytes the store holds for `name`, and their length.
fn stored_buffer(s: &StorageState, name: &str) -> (*const u8, usize) {
    let store = s.store.lock().unwrap();
    let meta = store
        .get(
            &BucketName::try_new(BUCKET).unwrap(),
            &ObjectName::try_new(name).unwrap(),
        )
        .unwrap_or_else(|| panic!("{name} was not stored"));
    let bytes = store.bytes(meta);
    (bytes.as_ptr(), bytes.len())
}

const PAYLOAD_BYTES: usize = 1 << 20;

fn payload() -> Vec<u8> {
    (0..PAYLOAD_BYTES)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect()
}

#[test]
fn a_media_upload_hands_its_request_buffer_to_the_store() {
    let s = state(None);
    let body = payload();
    let (arrived_at, len) = (body.as_ptr(), body.len());
    let r = handle(
        &s,
        owned_req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=media.bin"),
            &[("content-type", "application/octet-stream")],
            body,
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(
        stored_buffer(&s, "media.bin"),
        (arrived_at, len),
        "the stored blob is the buffer the request arrived in"
    );
}

#[test]
fn a_multipart_upload_carves_the_data_part_out_of_its_request_buffer() {
    let s = state(None);
    let data = payload();
    let (ct, body) = multipart(
        &json!({"name": "multipart.bin"}),
        "application/octet-stream",
        &data,
    );
    let arrived_at = body.as_ptr();
    let r = handle(
        &s,
        owned_req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=multipart"),
            &[("content-type", &ct)],
            body,
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(
        stored_buffer(&s, "multipart.bin"),
        (arrived_at, data.len()),
        "the data part is carved out of the request buffer, not copied out of it"
    );
    let store = s.store.lock().unwrap();
    let meta = store
        .get(
            &BucketName::try_new(BUCKET).unwrap(),
            &ObjectName::try_new("multipart.bin").unwrap(),
        )
        .unwrap();
    assert_eq!(
        store.bytes(meta),
        data.as_slice(),
        "the exact bytes survive"
    );
}

#[test]
fn a_form_upload_carves_the_file_part_out_of_its_request_buffer() {
    let s = state(None);
    let data = payload();
    let boundary = "form-storage-buffer";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nform.bin\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"form.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(&data);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let arrived_at = body.as_ptr();
    let r = handle(
        &s,
        owned_req(
            "POST",
            &format!("/{BUCKET}"),
            &[(
                "content-type",
                &format!("multipart/form-data; boundary={boundary}"),
            )],
            body,
        ),
    );
    assert_eq!(r.status, 204, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(stored_buffer(&s, "form.bin"), (arrived_at, data.len()));
}

#[test]
fn a_resumable_upload_adopts_the_request_buffer_of_its_only_chunk() {
    let s = state(None);
    let start = handle(
        &s,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=resumable.bin"),
            &[
                ("authorization", "Bearer owner"),
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "start"),
                (
                    "x-goog-upload-header-content-length",
                    &PAYLOAD_BYTES.to_string(),
                ),
            ],
            b"",
        ),
    );
    assert_eq!(start.status, 200);
    let session = header(&start, "x-goog-upload-url").unwrap().to_owned();
    let (_, query) = session.split_once("/o?").unwrap();
    let body = payload();
    let (arrived_at, len) = (body.as_ptr(), body.len());
    let r = handle(
        &s,
        owned_req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?{query}"),
            &[
                ("authorization", "Bearer owner"),
                ("x-goog-upload-command", "upload, finalize"),
                ("x-goog-upload-offset", "0"),
            ],
            body,
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(
        stored_buffer(&s, "resumable.bin"),
        (arrived_at, len),
        "the session adopts the chunk buffer instead of copying it"
    );
}

#[test]
fn a_rejected_checksum_stores_nothing() {
    let s = state(None);
    let body = payload();
    let r = handle(
        &s,
        owned_req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=bad.bin"),
            &[
                ("content-type", "application/octet-stream"),
                ("x-goog-hash", "crc32c=AAAAAA=="),
            ],
            body,
        ),
    );
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    let store = s.store.lock().unwrap();
    assert!(store
        .get(
            &BucketName::try_new(BUCKET).unwrap(),
            &ObjectName::try_new("bad.bin").unwrap()
        )
        .is_none());
}

// ------------------------------------------------------------------------------------------
// The in-flight body budget over a real socket (STG-MEM-03).
// ------------------------------------------------------------------------------------------

const CHUNK: usize = 1 << 20;

fn upload_head(name: &str, len: usize) -> String {
    format!(
        "POST /upload/storage/v1/b/{BUCKET}/o?uploadType=media&name={name} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
    )
}

/// Waits until `budget` holds exactly `bytes` (the server charges a body before it reads it).
async fn await_in_flight(budget: &BodyBudget, bytes: usize) {
    for _ in 0..1_000_000 {
        if budget.in_flight() == bytes {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!(
        "in-flight budget stayed at {} bytes, expected {bytes}",
        budget.in_flight()
    );
}

async fn read_response(stream: &mut tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

#[test]
fn four_large_uploads_leave_tokio_workers_available() {
    use std::io::{Read, Write};
    use std::sync::mpsc;
    use std::time::Duration;

    static BUDGET: BodyBudget = BodyBudget::new(64 * 1024 * 1024);
    const BODY_BYTES: usize = 8 * 1024 * 1024;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let shared = Arc::new(state(None));
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = runtime.spawn(serve_storage_with_budget(listener, shared.clone(), &BUDGET));

    // Holding the store lock makes all admitted handlers wait at the same synchronous
    // boundary. Each 8 MiB write exceeds the socket buffer, so completed writes show
    // that at least two handlers have drained most of their request bodies.
    let store_guard = shared.store.lock().unwrap();
    let payload = Arc::new(vec![7u8; BODY_BYTES]);
    let (written_tx, written_rx) = mpsc::channel();
    let clients: Vec<_> = (0..4)
        .map(|index| {
            let payload = payload.clone();
            let written_tx = written_tx.clone();
            std::thread::spawn(move || {
                let mut stream = std::net::TcpStream::connect(address).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(120)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(30)))
                    .unwrap();
                stream
                    .write_all(upload_head(&format!("worker-{index}.bin"), BODY_BYTES).as_bytes())
                    .unwrap();
                stream.write_all(&payload).unwrap();
                written_tx.send(()).unwrap();
                let mut response = [0u8; 4096];
                let received = stream.read(&mut response).unwrap();
                String::from_utf8_lossy(&response[..received]).into_owned()
            })
        })
        .collect();
    drop(written_tx);
    let handlers_reached_lock =
        (0..2).all(|_| written_rx.recv_timeout(Duration::from_secs(10)).is_ok());
    std::thread::sleep(Duration::from_millis(20));

    let (heartbeat_tx, heartbeat_rx) = mpsc::channel();
    runtime.spawn(async move {
        let _ = heartbeat_tx.send(());
    });
    let heartbeat_responded = heartbeat_rx
        .recv_timeout(Duration::from_millis(500))
        .is_ok();

    drop(store_guard);
    for client in clients {
        let response = client.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }
    server.abort();
    runtime.block_on(async {
        let _ = server.await;
    });
    assert!(
        handlers_reached_lock,
        "two upload bodies did not reach the handler"
    );
    assert!(
        heartbeat_responded,
        "Storage handlers blocked both Tokio workers"
    );
    assert_eq!(BUDGET.in_flight(), 0);
}

#[test]
fn more_than_sixteen_storage_handlers_wait_instead_of_rejecting() {
    use std::io::{Read, Write};
    use std::sync::mpsc;
    use std::time::Duration;

    static BUDGET: BodyBudget = BodyBudget::new(32 * 1024 * 1024);
    const REQUESTS: usize = 17;
    const BODY_BYTES: usize = 1024;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let shared = Arc::new(state(None));
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = runtime.spawn(serve_storage_with_budget(listener, shared.clone(), &BUDGET));

    let store_guard = shared.store.lock().unwrap();
    let (written_tx, written_rx) = mpsc::channel();
    let clients: Vec<_> = (0..REQUESTS)
        .map(|index| {
            let written_tx = written_tx.clone();
            std::thread::spawn(move || {
                let mut stream = std::net::TcpStream::connect(address).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(60)))
                    .unwrap();
                stream
                    .write_all(upload_head(&format!("queued-{index}.bin"), BODY_BYTES).as_bytes())
                    .unwrap();
                stream.write_all(&[7u8; BODY_BYTES]).unwrap();
                written_tx.send(()).unwrap();
                let mut response = [0u8; 4096];
                let received = stream.read(&mut response).unwrap();
                String::from_utf8_lossy(&response[..received]).into_owned()
            })
        })
        .collect();
    drop(written_tx);
    for _ in 0..REQUESTS {
        written_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    // Give the server time to admit each buffered body while all handlers wait on the lock.
    std::thread::sleep(Duration::from_millis(200));
    let buffered = BUDGET.in_flight();
    drop(store_guard);
    for client in clients {
        let response = client.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }
    server.abort();
    runtime.block_on(async {
        let _ = server.await;
    });
    assert_eq!(buffered, REQUESTS * CHUNK);
    assert_eq!(BUDGET.in_flight(), 0);
}

#[tokio::test]
async fn set_rules_over_http_changes_later_storage_authorization() {
    use tokio::io::AsyncWriteExt;
    static BUDGET: BodyBudget = BodyBudget::new(1_572_864);

    let shared = Arc::new(state(Some(
        "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if false; } } }",
    )));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_storage_with_budget(listener, shared.clone(), &BUDGET));

    let send_upload = |name: &'static str| async move {
        let (content_type, body) = multipart(&json!({}), "text/plain", b"content");
        let head = format!(
            "POST /v0/b/{BUCKET}/o?name={name}&uploadType=multipart HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: {content_type}\r\nX-Goog-Upload-Protocol: multipart\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        read_response(&mut stream).await
    };

    let denied = send_upload("before.txt").await;
    assert!(denied.starts_with("HTTP/1.1 403"), "{denied}");

    let update = serde_json::to_vec(&json!({
        "rules": {"files": [{
            "name": "storage.rules",
            "content": "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if true; } } }"
        }]}
    }))
    .unwrap();
    let head = format!(
        "PUT /internal/setRules HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        update.len()
    );
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&update).await.unwrap();
    let activated = read_response(&mut stream).await;
    assert!(activated.starts_with("HTTP/1.1 200"), "{activated}");
    assert!(
        activated.contains("{\"message\":\"Rules updated successfully\"}"),
        "{activated}"
    );

    let allowed = send_upload("after.txt").await;
    assert!(allowed.starts_with("HTTP/1.1 200"), "{allowed}");
    server.abort();
}

#[tokio::test]
async fn the_body_budget_rejects_an_upload_that_does_not_fit_and_admits_it_once_released() {
    use tokio::io::AsyncWriteExt;
    /// 1.5 MiB: one 1 MiB body is admitted, two are not.
    static BUDGET: BodyBudget = BodyBudget::new(1_572_864);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shared = Arc::new(state(None));
    let server = tokio::spawn(serve_storage_with_budget(listener, shared, &BUDGET));
    assert_eq!(BUDGET.in_flight(), 0);

    // One upload in flight: its declared size is charged before the body is read.
    let mut first = tokio::net::TcpStream::connect(addr).await.unwrap();
    first
        .write_all(upload_head("first.bin", CHUNK).as_bytes())
        .await
        .unwrap();
    first.write_all(&[7u8; 4096]).await.unwrap();
    await_in_flight(&BUDGET, CHUNK).await;

    // A second one no longer fits and is refused before it allocates anything.
    let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
    second
        .write_all(upload_head("second.bin", CHUNK).as_bytes())
        .await
        .unwrap();
    let rejected = read_response(&mut second).await;
    assert!(
        rejected.starts_with("HTTP/1.1 503"),
        "over-budget upload: {rejected}"
    );
    assert!(
        rejected.to_lowercase().contains("retry-after: 1"),
        "{rejected}"
    );
    assert_eq!(
        BUDGET.in_flight(),
        CHUNK,
        "the refused upload charged nothing"
    );

    // The admitted upload finishes and gives its charge back.
    first.write_all(&vec![7u8; CHUNK - 4096]).await.unwrap();
    let accepted = read_response(&mut first).await;
    assert!(accepted.starts_with("HTTP/1.1 200"), "{accepted}");
    await_in_flight(&BUDGET, 0).await;

    // With the budget free again the same upload is admitted.
    let mut third = tokio::net::TcpStream::connect(addr).await.unwrap();
    third
        .write_all(upload_head("third.bin", CHUNK).as_bytes())
        .await
        .unwrap();
    third.write_all(&vec![7u8; CHUNK]).await.unwrap();
    let again = read_response(&mut third).await;
    assert!(again.starts_with("HTTP/1.1 200"), "{again}");
    await_in_flight(&BUDGET, 0).await;

    server.abort();
}

#[tokio::test]
async fn a_body_over_the_object_boundary_is_refused_without_buffering_it() {
    use tokio::io::AsyncWriteExt;
    static BUDGET: BodyBudget = BodyBudget::new(1_572_864);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shared = Arc::new(state(None));
    let server = tokio::spawn(serve_storage_with_budget(listener, shared, &BUDGET));
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(upload_head("over.bin", MAX_STORAGE_BODY_BYTES + 1).as_bytes())
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    assert_eq!(BUDGET.in_flight(), 0, "nothing was charged");
    server.abort();
}

#[tokio::test]
async fn a_failed_upload_releases_its_buffer() {
    use tokio::io::AsyncWriteExt;
    static BUDGET: BodyBudget = BodyBudget::new(1_572_864);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shared = Arc::new(state(None));
    let server = tokio::spawn(serve_storage_with_budget(listener, shared.clone(), &BUDGET));
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST /upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=failed.bin HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/octet-stream\r\nX-Goog-Hash: crc32c=AAAAAA==\r\nContent-Length: {CHUNK}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&vec![7u8; CHUNK]).await.unwrap();
    let response = read_response(&mut stream).await;
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "checksum mismatch: {response}"
    );
    await_in_flight(&BUDGET, 0).await;
    let store = shared.store.lock().unwrap();
    assert!(
        store
            .get(
                &BucketName::try_new(BUCKET).unwrap(),
                &ObjectName::try_new("failed.bin").unwrap()
            )
            .is_none(),
        "a failed upload publishes no object"
    );
    server.abort();
}

// ----------------------------------------------------------------------------------------
// The compatibility profile on the Storage Rules surface
// ----------------------------------------------------------------------------------------

/// `@firebase/util`'s `createMockUserToken` output: unsigned, `iat: 0` so `exp` is an hour
/// after the epoch, and a subject that need not exist. The official Storage emulator runs
/// `jwt.decode` on exactly this and builds `request.auth` from the result, verifying nothing
/// (`firebase-tools/lib/emulator/storage/rules/runtime.js`).
fn mock_user_token(sub: &str, project: &str) -> String {
    let header = base64url_encode(br#"{"alg":"none","type":"JWT"}"#);
    let payload = base64url_encode(
        format!(
            r#"{{"iss":"https://securetoken.google.com/{project}","aud":"{project}","iat":0,"exp":3600,"auth_time":0,"sub":"{sub}","user_id":"{sub}"}}"#
        )
        .as_bytes(),
    );
    format!("{header}.{payload}.")
}

fn mock_tenant_token(sub: &str, project: &str, tenant: &str) -> String {
    let header = base64url_encode(br#"{"alg":"none","type":"JWT"}"#);
    let payload = base64url_encode(
        format!(
            r#"{{"iss":"https://securetoken.google.com/{project}","aud":"{project}","iat":0,"exp":3600,"auth_time":0,"sub":"{sub}","user_id":"{sub}","firebase":{{"tenant":"{tenant}"}}}}"#
        )
        .as_bytes(),
    );
    format!("{header}.{payload}.")
}

const OWNED_STORAGE_RULES: &str = "rules_version = '2';\nservice firebase.storage { match /b/{bucket}/o { match /owned/{uid}/{file=**} { allow read, write: if request.auth != null && request.auth.uid == uid; } } }";

fn upload_to_bucket_as(s: &StorageState, bucket: &str, path: &str, authorization: &str) -> u16 {
    handle(
        s,
        req(
            "POST",
            &format!(
                "/v0/b/{bucket}/o?name={}&uploadType=media",
                path.replace('/', "%2F")
            ),
            &[
                ("authorization", authorization),
                ("content-type", "text/plain"),
            ],
            b"hello",
        ),
    )
    .status
}

fn upload_as(s: &StorageState, path: &str, authorization: &str) -> u16 {
    upload_to_bucket_as(s, BUCKET, path, authorization)
}

#[test]
fn tenant_tokens_authenticate_to_storage_rules() {
    let s = state(Some(OWNED_STORAGE_RULES));
    let tenant = s.auth.ensure_tenant("demo-app", "customer-a").unwrap();
    let mut tenant = tenant.lock().unwrap();
    let uid = tenant
        .create_user(NewUser::email("tenant@example.com"), START)
        .unwrap();
    let token = fireemu_core_auth::jwt::encode_unsigned(
        &tenant.id_token_claims(&uid, None, START).unwrap(),
    );
    drop(tenant);

    assert_eq!(
        upload_as(
            &s,
            &format!("owned/{}/x.txt", uid.as_str()),
            &format!("Firebase {token}"),
        ),
        200
    );
}

#[test]
fn the_profile_decides_whether_storage_rules_admit_a_mock_token() {
    let bearer = format!("Firebase {}", mock_user_token("alice", "demo-app"));

    let firebase = state_with(Some(OWNED_STORAGE_RULES), TokenAcceptance::EmulatorMock);
    assert_eq!(
        upload_as(&firebase, "owned/alice/x.txt", &bearer),
        200,
        "the emulator profile builds request.auth from the mock token, as the official emulator does"
    );
    assert_eq!(
        upload_as(&firebase, "owned/bob/x.txt", &bearer),
        403,
        "and the rule, not the token, is what refuses another subject's prefix"
    );
    // The emulator profile never reads the audience, as firebase-tools 15.28.2 does not: a
    // token minted for another project is the identity it names, and the rule still decides.
    let foreign = format!("Firebase {}", mock_user_token("alice", "demo-other"));
    assert_eq!(upload_as(&firebase, "owned/alice/y.txt", &foreign), 200);
    assert_eq!(upload_as(&firebase, "owned/bob/y.txt", &foreign), 403);

    let strict = state_with(Some(OWNED_STORAGE_RULES), TokenAcceptance::Verified);
    assert_eq!(
        upload_as(&strict, "owned/alice/x.txt", &bearer),
        401,
        "under strict the token names no user of the Auth store, so the caller is refused"
    );
    // Strict keeps the audience check and answers as production does: 403, whatever the rule.
    assert_eq!(upload_as(&strict, "owned/alice/y.txt", &foreign), 403);
}

#[test]
fn storage_rules_bind_mock_tokens_to_default_owned_bare_project_buckets() {
    let worker_0 = "demo-app-w0";
    let worker_1 = "demo-app-w1";
    let token_0 = format!("Firebase {}", mock_user_token("alice", worker_0));
    let token_1 = format!("Firebase {}", mock_user_token("alice", worker_1));
    let firebase = state_with(Some(OWNED_STORAGE_RULES), TokenAcceptance::EmulatorMock);
    let auth_projects_before = firebase.auth.projects();

    assert_eq!(
        upload_to_bucket_as(&firebase, worker_0, "owned/alice/x.txt", &token_0),
        200
    );
    assert_eq!(
        upload_to_bucket_as(&firebase, worker_0, "owned/bob/x.txt", &token_0),
        403
    );
    // The audience is not read in the emulator profile (firebase-tools 15.28.2 never reads it):
    // a mock token of another worker project is the identity it names.
    for (bucket, token) in [(worker_0, &token_1), (worker_1, &token_0)] {
        assert_eq!(
            upload_to_bucket_as(&firebase, bucket, "owned/alice/x.txt", token),
            200
        );
    }
    let tenant = format!(
        "Firebase {}",
        mock_tenant_token("alice", worker_0, "customer-a")
    );
    assert_eq!(
        upload_to_bucket_as(&firebase, worker_0, "owned/alice/x.txt", &tenant),
        401
    );
    assert_eq!(firebase.auth.projects(), auth_projects_before);

    let strict = state_with(Some(OWNED_STORAGE_RULES), TokenAcceptance::Verified);
    assert_eq!(
        upload_to_bucket_as(&strict, worker_0, "owned/alice/x.txt", &token_0),
        403,
        "strict answers a token of another project as production does"
    );

    let mut scoped = state_with(Some(OWNED_STORAGE_RULES), TokenAcceptance::EmulatorMock);
    let mut tenancy = fireemu_core_session::tenancy::Tenancy::new("demo-app");
    tenancy
        .register("demo-team", &["team-files".to_owned()], &[])
        .unwrap();
    let registered_before = tenancy.registered();
    scoped.tenancy = Some(Arc::new(RwLock::new(tenancy)));
    assert!(scoped.auth.register(
        "demo-team",
        AuthStore::new("demo-team", SplitMix64::new(4), TotpPolicy::default())
    ));
    let scoped_projects_before = scoped.auth.projects();
    let default_token = format!("Firebase {}", mock_user_token("alice", "demo-app"));
    let team_token = format!("Firebase {}", mock_user_token("alice", "demo-team"));
    let guest_token = format!("Firebase {}", mock_user_token("alice", "demo-guest"));

    assert_eq!(
        upload_to_bucket_as(
            &scoped,
            "demo-app.appspot.com",
            "owned/alice/x.txt",
            &default_token,
        ),
        200
    );
    assert_eq!(
        upload_to_bucket_as(
            &scoped,
            "demo-team.appspot.com",
            "owned/alice/x.txt",
            &team_token,
        ),
        200
    );
    assert_eq!(
        upload_to_bucket_as(&scoped, "team-files", "owned/alice/x.txt", &team_token,),
        200
    );
    assert_eq!(
        upload_to_bucket_as(&scoped, "demo-team", "owned/alice/x.txt", &team_token,),
        200,
        "the audience is not read in the emulator profile"
    );
    assert_eq!(
        upload_to_bucket_as(
            &scoped,
            "demo-guest.appspot.com",
            "owned/alice/x.txt",
            &guest_token,
        ),
        200,
        "a token of an unregistered project is admitted, and admitting it creates no project"
    );
    assert_eq!(scoped.auth.projects(), scoped_projects_before);
    assert_eq!(
        scoped
            .tenancy
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .registered(),
        registered_before
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn worker_project_resumable_uploads_reverify_the_same_mock_audience() {
    let bucket = "demo-app-w0";
    let matching = format!("Firebase {}", mock_user_token("alice", bucket));
    let foreign = format!("Firebase {}", mock_user_token("alice", "demo-app-w1"));
    let firebase = state_with(Some(OWNED_STORAGE_RULES), TokenAcceptance::EmulatorMock);
    let start_path = format!("/v0/b/{bucket}/o?name=owned%2Falice%2Fresumable.txt");
    let started = handle(
        &firebase,
        req(
            "POST",
            &start_path,
            &[
                ("authorization", &matching),
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "start"),
            ],
            b"{}",
        ),
    );
    assert_eq!(
        started.status,
        200,
        "{}",
        String::from_utf8_lossy(&started.body)
    );
    let session = header(&started, "x-goog-upload-url")
        .unwrap()
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap()
        .to_owned();
    let finalized = handle(
        &firebase,
        req(
            "POST",
            &session,
            &[
                ("x-goog-upload-command", "upload, finalize"),
                ("x-goog-upload-offset", "0"),
            ],
            b"hello",
        ),
    );
    assert_eq!(
        finalized.status,
        200,
        "{}",
        String::from_utf8_lossy(&finalized.body)
    );

    let foreign_start = handle(
        &firebase,
        req(
            "POST",
            &format!("/v0/b/{bucket}/o?name=owned%2Falice%2Fforeign.txt"),
            &[
                ("authorization", &foreign),
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "start"),
            ],
            b"{}",
        ),
    );
    // The emulator profile admits the other project's token, as the official emulator does.
    assert_eq!(foreign_start.status, 200);
    let foreign_session = header(&foreign_start, "x-goog-upload-url")
        .unwrap()
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap()
        .to_owned();
    let foreign_finalized = handle(
        &firebase,
        req(
            "POST",
            &foreign_session,
            &[
                ("x-goog-upload-command", "upload, finalize"),
                ("x-goog-upload-offset", "0"),
            ],
            b"hello",
        ),
    );
    assert_eq!(foreign_finalized.status, 200);

    // Strict answers it as production does, before the session exists.
    let strict = state_with(Some(OWNED_STORAGE_RULES), TokenAcceptance::Verified);
    let strict_start = handle(
        &strict,
        req(
            "POST",
            &format!("/v0/b/{bucket}/o?name=owned%2Falice%2Fstrict.txt"),
            &[
                ("authorization", &foreign),
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "start"),
            ],
            b"{}",
        ),
    );
    assert_eq!(strict_start.status, 403);
    assert_eq!(
        handle(
            &firebase,
            req(
                "GET",
                &format!("/v0/b/{bucket}/o/owned%2Falice%2Fstrict.txt"),
                &[("authorization", "Bearer owner")],
                b"",
            ),
        )
        .status,
        404
    );
}

// ---- Security regressions (storage parity review) ------------------------------------

/// A missing object served through a media route answers `text/html` with the plain sentence
/// naming it, as production and the official emulator do (measured with firebase-tools 15.28.2 on
/// the short, `/storage/v1`, `/download/storage/v1` and XML-style routes; recorded in production,
/// stage 3 v9: 994 rows). Strict writes production's uppercase charset, the emulator profile the
/// official emulator's lowercase one. The owner ruled (ledger "STORAGE-RULES media 404 content
/// type", 2026-10-01) that matching production takes priority over the reflected-HTML concern of a
/// tool that runs locally, which had made fireemu type this body `text/plain` until then.
#[test]
fn a_missing_media_object_answers_text_html_as_production_does() {
    for (acceptance, charset) in [
        (TokenAcceptance::Verified, "text/html; charset=UTF-8"),
        (TokenAcceptance::EmulatorMock, "text/html; charset=utf-8"),
    ] {
        let s = state_with(None, acceptance);
        for (path, headers) in [
            (format!("/b/{BUCKET}/o/absent.txt?alt=media"), true),
            (
                format!("/storage/v1/b/{BUCKET}/o/absent.txt?alt=media"),
                true,
            ),
            (
                format!("/download/storage/v1/b/{BUCKET}/o/absent.txt?alt=media"),
                true,
            ),
            (format!("/{BUCKET}/absent.txt?alt=media"), false),
        ] {
            let owner = [("authorization", "Bearer owner")];
            let r = handle(
                &s,
                req("GET", &path, if headers { &owner } else { &[] }, b""),
            );
            assert_eq!(r.status, 404, "{acceptance:?} {path}");
            assert_eq!(
                header(&r, "content-type"),
                Some(charset),
                "{acceptance:?} {path}"
            );
            assert_eq!(
                String::from_utf8_lossy(&r.body),
                format!("No such object: {BUCKET}/absent.txt")
            );
        }
    }
}

/// S-4: metadata strings that carry a control character are refused at the input boundary,
/// so they can never be echoed into a response header (the same rule the object name is
/// already held to). Covers both dialects' PATCH, a NUL in a custom value, and the
/// form-upload header fields where `value.trim()` would leave an internal CR/LF in place.
#[test]
fn metadata_with_control_characters_is_refused_at_the_boundary() {
    let s = state(None);
    // Firebase PATCH: a CR/LF in a standard field.
    let r = handle(
        &s,
        req(
            "PATCH",
            &format!("/v0/b/{BUCKET}/o/x"),
            &[
                ("authorization", "Bearer owner"),
                ("content-type", "application/json"),
            ],
            b"{\"contentType\": \"text/plain\r\nX-Injected: 1\"}",
        ),
    );
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    // JSON API PATCH: a CR/LF in contentDisposition.
    let r = handle(
        &s,
        req(
            "PATCH",
            &format!("/b/{BUCKET}/o/x"),
            &[
                ("authorization", "Bearer owner"),
                ("content-type", "application/json"),
            ],
            b"{\"contentDisposition\": \"inline\r\nX-Injected: 1\"}",
        ),
    );
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    // A NUL in a custom metadata value.
    let r = handle(
        &s,
        req(
            "PATCH",
            &format!("/v0/b/{BUCKET}/o/x"),
            &[
                ("authorization", "Bearer owner"),
                ("content-type", "application/json"),
            ],
            b"{\"metadata\": {\"k\": \"a\x00b\"}}",
        ),
    );
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    // The form-upload header fields: a CR/LF in a content-disposition field value.
    let boundary = "formbound";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nobj.txt\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"content-disposition\"\r\n\r\ninline\r\nX-Injected: 1\r\n").as_bytes(),
    );
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\nContent-Type: text/plain\r\n\r\nhi\r\n--{boundary}--\r\n").as_bytes(),
    );
    let r = handle(
        &s,
        owned_req(
            "POST",
            &format!("/{BUCKET}"),
            &[(
                "content-type",
                &format!("multipart/form-data; boundary={boundary}"),
            )],
            body,
        ),
    );
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
}

/// S-3: a multipart body whose bytes are all the boundary character parses in linear time.
/// Before the fix the delimiter scan was O(N*M) and this took minutes; the assertion is a
/// generous ceiling so it fixes the linear-time regression without being CI-flaky.
#[test]
fn a_multipart_body_of_boundary_bytes_parses_in_bounded_time() {
    let s = state(None);
    let boundary = "A".repeat(70);
    let content_type = format!("multipart/form-data; boundary={boundary}");
    // 8 MiB of the boundary character: every offset used to match-then-reject and advance one.
    let body = vec![b'A'; 8 * 1024 * 1024];
    let start = std::time::Instant::now();
    let r = handle(
        &s,
        owned_req(
            "POST",
            &format!("/{BUCKET}"),
            &[("content-type", &content_type)],
            body,
        ),
    );
    let elapsed = start.elapsed();
    // It is a malformed body, so the status is a 4xx; what matters is that it returned fast.
    assert!(r.status >= 400);
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "multipart parse took {elapsed:?} -- the O(N*M) regression is back"
    );
}

/// S-3 (double defence): a boundary longer than RFC 2046's 70-byte cap is refused outright.
#[test]
fn an_oversized_multipart_boundary_is_refused() {
    let s = state(None);
    let boundary = "b".repeat(8 * 1024);
    let content_type = format!("multipart/related; boundary={boundary}");
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=multipart&name=x"),
            &[
                ("authorization", "Bearer owner"),
                ("content-type", &content_type),
            ],
            b"body",
        ),
    );
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
}

/// S-4 (real server): an object with ordinary metadata still answers `?alt=media` with its
/// bytes and the CORS headers. This exercises the hyper response builder that the direct
/// `handle()` tests bypass -- the path whose silent "200, empty body, no CORS" failure mode
/// the S-4 boundary check and the 500 fallback close.
#[tokio::test]
async fn a_stored_object_always_answers_media_with_its_bytes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    static BUDGET: BodyBudget = BodyBudget::new(1_572_864);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // The emulator profile: the server stamps its CORS and `nosniff` headers on every answer; the
    // strict profile's framed answers carry production's header set instead (see the next test).
    let shared = Arc::new(state_with(None, TokenAcceptance::EmulatorMock));
    let server = tokio::spawn(serve_storage_with_budget(listener, shared, &BUDGET));

    // Upload an object with a full set of ordinary metadata fields.
    let body = b"hello bytes";
    let head = format!(
        "POST /upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=served.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut up = tokio::net::TcpStream::connect(addr).await.unwrap();
    up.write_all(head.as_bytes()).await.unwrap();
    up.write_all(body).await.unwrap();
    let uploaded = read_response(&mut up).await;
    assert!(uploaded.starts_with("HTTP/1.1 200"), "{uploaded}");

    // Read it back with an Origin, and assert the real bytes and the CORS header come back.
    let mut get = tokio::net::TcpStream::connect(addr).await.unwrap();
    get.write_all(
        format!("GET /b/{BUCKET}/o/served.txt?alt=media HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://localhost:5173\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut raw = Vec::new();
    get.read_to_end(&mut raw).await.unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a header/body split");
    let head_text = String::from_utf8_lossy(&raw[..split]).to_lowercase();
    let returned_body = &raw[split + 4..];
    assert!(head_text.starts_with("http/1.1 200"), "{head_text}");
    assert!(
        head_text.contains("access-control-allow-origin: http://localhost:5173"),
        "CORS header missing: {head_text}"
    );
    assert!(
        head_text.contains("x-content-type-options: nosniff"),
        "nosniff missing: {head_text}"
    );
    assert_eq!(returned_body, body, "the object bytes must come back");
    server.abort();
}

/// Rules source used by the `/internal/setRules` browser-policy tests.
const SETR_DENY_ALL: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if false; } } }";
const SETR_ALLOW_ALL: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if true; } } }";

fn set_rules_body() -> Vec<u8> {
    serde_json::to_vec(
        &json!({"rules": {"files": [{"name": "storage.rules", "content": SETR_ALLOW_ALL}]}}),
    )
    .unwrap()
}

/// SETR-1: `PUT /internal/setRules` replaces the authorization policy of the whole run, so a
/// page on a loopback origin must present the control token, exactly as the equivalent
/// control route requires. A foreign origin never reaches it, and the `@firebase/rules-unit-testing`
/// shape (no `Origin`, no `Sec-Fetch-Site`/`Sec-Fetch-Dest`; Node's built-in `fetch` does
/// attach `sec-fetch-mode: cors`) keeps working unauthenticated.
#[test]
fn set_rules_from_a_browser_needs_the_control_token() {
    let update = set_rules_body();
    let bearer = format!("Bearer {CONTROL_TOKEN}");

    for (label, headers) in [
        (
            "loopback origin without a token",
            vec![("origin", "http://localhost:5173")],
        ),
        (
            "loopback origin with the wrong token",
            vec![
                ("origin", "http://localhost:5173"),
                ("authorization", "Bearer not-the-control-token"),
            ],
        ),
        ("sec-fetch-site only", vec![("sec-fetch-site", "same-site")]),
        ("sec-fetch-dest only", vec![("sec-fetch-dest", "empty")]),
        (
            "foreign origin with the control token",
            vec![
                ("origin", "https://evil.example"),
                ("authorization", "Bearer storage-test-control-token"),
            ],
        ),
    ] {
        let s = state(Some(SETR_DENY_ALL));
        let mut headers = headers;
        headers.push(("content-type", "application/json"));
        let response = handle(&s, req("PUT", "/internal/setRules", &headers, &update));
        assert_eq!(
            response.status,
            403,
            "{label}: {}",
            String::from_utf8_lossy(&response.body)
        );
        assert!(
            json_body(&response)["message"]
                .as_str()
                .is_some_and(|m| !m.is_empty()),
            "{label}"
        );
        assert_eq!(
            anonymous_multipart_upload(&s, &format!("{label}.txt")).status,
            403,
            "{label}: the refused update must not have replaced the rules"
        );
    }

    let s = state(Some(SETR_DENY_ALL));
    let response = handle(
        &s,
        req(
            "PUT",
            "/internal/setRules",
            &[
                ("content-type", "application/json"),
                ("origin", "http://localhost:5173"),
                ("authorization", bearer.as_str()),
            ],
            &update,
        ),
    );
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(anonymous_multipart_upload(&s, "browser.txt").status, 200);

    let s = state(Some(SETR_DENY_ALL));
    assert_eq!(
        handle(
            &s,
            req(
                "PUT",
                "/internal/setRules",
                &[("content-type", "application/json")],
                &update,
            ),
        )
        .status,
        200
    );
    assert_eq!(anonymous_multipart_upload(&s, "sdk.txt").status, 200);

    // The header set Node 24's built-in `fetch` (undici) attaches when a script sets only
    // `Content-Type`: `sec-fetch-mode: cors` is among them and cannot be removed by the script.
    // This is what `@firebase/rules-unit-testing` 5.0.2's `loadStorageRules` sends, and it is
    // a process, not a page, so it is admitted without a token.
    let s = state(Some(SETR_DENY_ALL));
    let response = handle(
        &s,
        req(
            "PUT",
            "/internal/setRules",
            &[
                ("host", "127.0.0.1:9199"),
                ("connection", "keep-alive"),
                ("content-type", "application/json"),
                ("accept", "*/*"),
                ("accept-language", "*"),
                ("sec-fetch-mode", "cors"),
                ("user-agent", "node"),
                ("accept-encoding", "gzip, deflate"),
            ],
            &update,
        ),
    );
    assert_eq!(
        response.status,
        200,
        "undici shape: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(anonymous_multipart_upload(&s, "undici.txt").status, 200);
}

/// SETR-2: the rules body is bounded like the control port's (256 KiB), before it is parsed.
#[test]
fn set_rules_refuses_a_body_beyond_the_control_port_limit() {
    let s = state(Some(SETR_DENY_ALL));
    let mut oversized = set_rules_body();
    oversized.resize(256 * 1024 + 1, b' ');
    let response = handle(
        &s,
        req(
            "PUT",
            "/internal/setRules",
            &[("content-type", "application/json")],
            &oversized,
        ),
    );
    assert_eq!(response.status, 413);
    assert_eq!(anonymous_multipart_upload(&s, "oversized.txt").status, 403);
}

/// RESST-1: a `Content-Range: bytes */...` status check of a finalized resumable upload is
/// answered with the committed object, as the resumable protocol documents it. The Node
/// `@google-cloud/storage` client sends exactly this after losing the final response, so a
/// 400 here reports a successful upload as a failure. A data-bearing PUT into a finalized
/// session stays a 400.
#[test]
fn a_status_check_of_a_finalized_resumable_upload_answers_the_committed_object() {
    let s = state(None);
    let start = handle(
        &s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=recovered.bin"),
            &[
                ("authorization", "Bearer owner"),
                ("content-type", "application/json"),
                ("x-upload-content-type", "application/pdf"),
            ],
            b"{}",
        ),
    );
    assert_eq!(start.status, 200);
    let location = header(&start, "location")
        .unwrap()
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap()
        .to_owned();

    let first = handle(
        &s,
        req(
            "PUT",
            &location,
            &[
                ("authorization", "Bearer owner"),
                ("content-range", "bytes 0-2/6"),
            ],
            b"abc",
        ),
    );
    assert_eq!(first.status, 308);
    let commit = handle(
        &s,
        req(
            "PUT",
            &location,
            &[
                ("authorization", "Bearer owner"),
                ("content-range", "bytes 3-5/6"),
            ],
            b"def",
        ),
    );
    assert_eq!(
        commit.status,
        200,
        "{}",
        String::from_utf8_lossy(&commit.body)
    );

    for range in ["bytes */6", "bytes */*"] {
        let status = handle(
            &s,
            req(
                "PUT",
                &location,
                &[("authorization", "Bearer owner"), ("content-range", range)],
                b"",
            ),
        );
        assert_eq!(
            status.status,
            200,
            "{range}: {}",
            String::from_utf8_lossy(&status.body)
        );
        let body = json_body(&status);
        assert_eq!(body["name"], "recovered.bin", "{range}");
        assert_eq!(body["size"], "6", "{range}");
        assert_eq!(body["contentType"], "application/pdf", "{range}");
        assert_eq!(body, json_body(&commit), "{range}");
    }

    // A chunk sent into the finalized session is still a 400.
    assert_eq!(
        handle(
            &s,
            req(
                "PUT",
                &location,
                &[
                    ("authorization", "Bearer owner"),
                    ("content-range", "bytes 3-5/6"),
                ],
                b"def",
            ),
        )
        .status,
        400
    );
}

/// SNORULE-1: a run with no loaded Storage ruleset denies every end-user request instead of
/// admitting it, so forgetting `storage.rules` never silently publishes every object. Strict
/// answers as production answers a bucket without a release (recorded, stage 3 v9, both
/// recordings: 400 with the "Your bucket has not been set up properly" body). The emulator profile
/// keeps its own fail-closed 403 for a project that is not a `demo-*` one, where the official
/// emulator refuses to start without a rules file (measured, firebase-tools 15.28.2); for a
/// `demo-*` project it admits every request, as the official emulator does with its default open
/// rules (see the next test). The owner credential keeps its documented Rules bypass.
#[test]
fn a_run_with_no_loaded_ruleset_denies_every_end_user_request() {
    for acceptance in BOTH_PROFILES {
        no_loaded_ruleset_denies_every_end_user_request(acceptance);
    }
}

fn no_loaded_ruleset_denies_every_end_user_request(acceptance: TokenAcceptance) {
    let refused = if acceptance == TokenAcceptance::Verified {
        400
    } else {
        403
    };
    let mut s = state_with(None, acceptance);
    if acceptance == TokenAcceptance::EmulatorMock {
        // A project that is not a `demo-*` one: the official emulator refuses to start there
        // without a rules file, so fireemu keeps its own fail-closed 403.
        "real-app".clone_into(&mut s.project);
    }

    // Seed an object through the privileged JSON API, on which rules never run.
    let seeded = handle(
        &s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=seeded.txt"),
            &[
                ("authorization", "Bearer owner"),
                ("content-type", "text/plain"),
            ],
            b"seeded",
        ),
    );
    assert_eq!(
        seeded.status,
        200,
        "{}",
        String::from_utf8_lossy(&seeded.body)
    );

    assert_eq!(anonymous_multipart_upload(&s, "anon.txt").status, refused);
    assert_eq!(
        handle(
            &s,
            req("GET", &format!("/v0/b/{BUCKET}/o/seeded.txt"), &[], b"")
        )
        .status,
        refused
    );
    assert_eq!(
        handle(
            &s,
            req(
                "GET",
                &format!("/v0/b/{BUCKET}/o/seeded.txt?alt=media"),
                &[],
                b"",
            ),
        )
        .status,
        refused
    );
    assert_eq!(
        handle(&s, req("GET", &format!("/v0/b/{BUCKET}/o"), &[], b"")).status,
        refused
    );
    assert_eq!(
        handle(
            &s,
            req("DELETE", &format!("/v0/b/{BUCKET}/o/seeded.txt"), &[], b""),
        )
        .status,
        refused
    );

    if acceptance == TokenAcceptance::Verified {
        let denied = anonymous_multipart_upload(&s, "anon.txt");
        assert_eq!(
            String::from_utf8_lossy(&denied.body),
            "{\n  \"error\": {\n    \"code\": 400,\n    \"message\": \"Your bucket has not been set up properly for Firebase Storage. Please visit 'https://console.firebase.google.com/project/demo-app/storage/rules' to set up security rules.\"\n  }\n}"
        );
        assert_eq!(
            header(&denied, "content-type"),
            Some("application/json; charset=UTF-8")
        );
    }

    // The owner credential is unaffected on the Firebase dialect.
    for (method, path) in [
        ("GET", format!("/v0/b/{BUCKET}/o/seeded.txt")),
        ("GET", format!("/v0/b/{BUCKET}/o")),
    ] {
        let r = handle(
            &s,
            req(method, &path, &[("authorization", "Bearer owner")], b""),
        );
        assert_eq!(
            r.status,
            200,
            "{method} {path}: {}",
            String::from_utf8_lossy(&r.body)
        );
    }

    // The object survived every refusal.
    let r = handle(
        &s,
        req(
            "GET",
            &format!("/v0/b/{BUCKET}/o/seeded.txt"),
            &[("authorization", "Bearer owner")],
            b"",
        ),
    );
    assert_eq!(r.status, 200);
}

/// A `demo-*` project with no Storage rules gets the official emulator's default open rules in
/// the emulator profile (measured, firebase-tools 15.28.2: `allow read, write` for every path), so
/// nothing is refused that the official emulator admits; strict still answers production's 400.
#[test]
fn the_emulator_profile_opens_a_demo_project_without_storage_rules() {
    let s = state_with(None, TokenAcceptance::EmulatorMock);
    assert_eq!(s.project, "demo-app");
    assert_eq!(anonymous_media_upload(&s, "open.txt"), 200);
    for (method, path) in [
        ("GET", format!("/v0/b/{BUCKET}/o/open.txt")),
        ("GET", format!("/v0/b/{BUCKET}/o/open.txt?alt=media")),
        ("GET", format!("/v0/b/{BUCKET}/o")),
        ("DELETE", format!("/v0/b/{BUCKET}/o/open.txt")),
    ] {
        let r = handle(&s, req(method, &path, &[], b""));
        assert!(
            r.status == 200 || r.status == 204,
            "{method} {path}: {}",
            r.status
        );
    }
    let strict = state_with(None, TokenAcceptance::Verified);
    assert_eq!(anonymous_media_upload(&strict, "open.txt"), 400);
}

/// The browser-metadata set must not hinge on one header an old or unusual browser may omit:
/// `Referer` and `Cookie` mark a page-issued request just as `Origin` and `Sec-Fetch-*` do.
#[test]
fn set_rules_treats_every_browser_metadata_field_as_a_browser_request() {
    let update = set_rules_body();
    for field in ["referer", "cookie"] {
        let s = state(Some(SETR_DENY_ALL));
        let response = handle(
            &s,
            req(
                "PUT",
                "/internal/setRules",
                &[
                    ("content-type", "application/json"),
                    (field, "http://localhost:5173/index.html"),
                ],
                &update,
            ),
        );
        assert_eq!(
            response.status,
            403,
            "{field}: {}",
            String::from_utf8_lossy(&response.body)
        );
        assert_eq!(
            anonymous_multipart_upload(&s, &format!("{field}.txt")).status,
            403,
            "{field}: the refused update must not have replaced the rules"
        );
    }
}

/// Defence that does not depend on reading any request header: the CORS preflight of the
/// privileged rules route never admits `PUT`, so a compliant browser cannot issue the request
/// at all, whichever request metadata it would have attached.
#[tokio::test]
async fn the_preflight_of_the_privileged_rules_route_never_admits_put() {
    use tokio::io::AsyncWriteExt;
    static BUDGET: BodyBudget = BodyBudget::new(1_572_864);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shared = Arc::new(state(Some(SETR_DENY_ALL)));
    let server = tokio::spawn(serve_storage_with_budget(listener, shared, &BUDGET));

    let preflight = |path: &'static str| async move {
        let head = format!(
            "OPTIONS {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://localhost:5173\r\nAccess-Control-Request-Method: PUT\r\nAccess-Control-Request-Headers: authorization,content-type\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(head.as_bytes()).await.unwrap();
        read_response(&mut stream).await
    };

    let refused = preflight("/internal/setRules").await;
    assert!(
        !refused.to_ascii_lowercase().contains("put"),
        "the rules route must not be advertised to a browser: {refused}"
    );

    // Every other route keeps the official preflight, PUT included (resumable uploads use it).
    let ordinary = preflight("/v0/b/demo-app.appspot.com/o").await;
    assert!(
        ordinary.to_ascii_lowercase().contains("put"),
        "ordinary routes keep the official method list: {ordinary}"
    );
    server.abort();
}

/// SETR-2, streaming half: the 256 KiB bound holds for a body that declares no length. The
/// refusal has to arrive while the body is still being written, so the Storage port never
/// buffers a rules body up to the object limit just because the client withheld a length. What
/// the client keeps sending after the refusal is read and thrown away (so that the answer is
/// not lost to a reset), never kept.
#[tokio::test]
async fn an_undeclared_set_rules_body_is_cut_off_at_the_control_port_limit() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    static BUDGET: BodyBudget = BodyBudget::new(32 * 1024 * 1024);
    /// 16 KiB chunks to 8 MiB: far past the 256 KiB bound and far past the socket buffers
    /// pinned below, so a server that read the whole body would accept every chunk.
    const CHUNKS: usize = 512;
    /// Both ends' kernel buffers are pinned: Linux otherwise autotunes loopback buffers to
    /// several MiB, and the client could park that much in the kernel before the refusal's
    /// reset reaches it, which says nothing about how much the server read.
    const SOCKET_BUFFER: u32 = 64 * 1024;

    async fn write_chunks(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        header: &str,
        chunk: &[u8],
        count: usize,
    ) {
        for _ in 0..count {
            writer.write_all(header.as_bytes()).await.unwrap();
            writer.write_all(chunk).await.unwrap();
            writer.write_all(b"\r\n").await.unwrap();
        }
    }
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(SOCKET_BUFFER).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(1024).unwrap();
    let addr = listener.local_addr().unwrap();
    let shared = Arc::new(state(Some(SETR_DENY_ALL)));
    let server = tokio::spawn(serve_storage_with_budget(listener, shared.clone(), &BUDGET));

    // A declared oversized body is refused cleanly, before the budget is touched.
    let mut declared = tokio::net::TcpStream::connect(addr).await.unwrap();
    declared
        .write_all(
            format!(
                "PUT /internal/setRules HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                256 * 1024 + 1
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut refused = Vec::new();
    let _ = declared.read_to_end(&mut refused).await;
    let refused = String::from_utf8_lossy(&refused).into_owned();
    assert!(
        refused.starts_with("HTTP/1.1 413"),
        "a declared oversized rules body must be refused: {refused}"
    );

    // An undeclared one is cut off as it streams: the server stops reading long before the
    // 8 MiB the client is willing to send.
    let client = tokio::net::TcpSocket::new_v4().unwrap();
    client.set_send_buffer_size(SOCKET_BUFFER).unwrap();
    let mut stream = client.connect(addr).await.unwrap();
    stream
        .write_all(
            b"PUT /internal/setRules HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let (mut reader, mut writer) = stream.into_split();
    // The answer is read while the body is still being written: the refusal must not wait for
    // the end of the body.
    let (status_tx, status_rx) = tokio::sync::oneshot::channel::<String>();
    let reading = tokio::spawn(async move {
        let mut answer = Vec::new();
        let mut status_tx = Some(status_tx);
        let mut buf = [0_u8; 4096];
        loop {
            match reader.read(&mut buf).await {
                Ok(n) if n > 0 => answer.extend_from_slice(&buf[..n]),
                _ => break,
            }
            if answer.len() >= 12 {
                if let Some(tx) = status_tx.take() {
                    let _ = tx.send(String::from_utf8_lossy(&answer).into_owned());
                }
            }
        }
        String::from_utf8_lossy(&answer).into_owned()
    });
    let chunk = vec![b' '; 16 * 1024];
    let header = format!("{:x}\r\n", chunk.len());
    // 128 chunks are 2 MiB: eight times the bound, a quarter of what the client is willing to send.
    write_chunks(&mut writer, &header, &chunk, 128).await;
    let early = tokio::time::timeout(std::time::Duration::from_secs(10), status_rx)
        .await
        .expect("the refusal arrives while the body is still being sent")
        .expect("the answer is read");
    assert!(
        early.starts_with("HTTP/1.1 413"),
        "an undeclared oversized rules body must be refused: {early}"
    );
    // The rest of the body is read and thrown away, never buffered: the client can finish it, and
    // the connection then ends cleanly.
    write_chunks(&mut writer, &header, &chunk, CHUNKS - 128).await;
    let _ = writer.write_all(b"0\r\n\r\n").await;
    let _ = writer.shutdown().await;
    let answer = reading.await.unwrap();
    assert!(
        answer.starts_with("HTTP/1.1 413"),
        "an undeclared oversized rules body must be refused: {answer}"
    );
    assert_eq!(
        anonymous_multipart_upload(&shared, "chunked.txt").status,
        403,
        "the refused body must not have replaced the rules"
    );
    server.abort();
}

/// A signer that signs by reversing the input: enough to make the store verify signatures.
struct ReversingSigner;

impl fireemu_core_auth::jwt::IdTokenSigner for ReversingSigner {
    fn alg(&self) -> &'static str {
        "RS256"
    }
    fn kid(&self) -> &'static str {
        "test"
    }
    fn sign(&self, signing_input: &[u8]) -> Vec<u8> {
        signing_input.iter().rev().copied().collect()
    }
    fn verify(&self, signing_input: &[u8], signature: &[u8]) -> bool {
        self.sign(signing_input) == signature
    }
    fn public_jwk_json(&self) -> String {
        "{}".to_owned()
    }
}

/// Ledger 781 on Storage: a signed (session-RSA) ID token whose `iat` and `auth_time` are in
/// the future is refused in strict (`Verified`) with 401, as an expired token is, and
/// is evaluated as its user in the emulator profile (`EmulatorMock`), as the official emulator
/// reads no time claim.
#[test]
fn a_future_dated_signed_token_follows_the_profile_on_storage() {
    for acceptance in [TokenAcceptance::Verified, TokenAcceptance::EmulatorMock] {
        let s = state_with(
            Some(
                "rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /users/{uid}/{file=**} {
      allow write: if request.auth != null && request.auth.uid == uid;
    }
  }
}",
            ),
            acceptance,
        );
        let (uid, future, expired) = {
            let store = s.auth.default_store();
            let mut store = store.lock().unwrap();
            store.set_signer(Arc::new(ReversingSigner));
            let uid = store
                .create_user(NewUser::email("future@example.com"), START)
                .unwrap();
            let mut claims = store.id_token_claims(&uid, None, START).unwrap();
            let mut stale = claims.clone();
            stale.iat -= 7200;
            stale.auth_time -= 7200;
            stale.exp -= 7200;
            claims.iat += 600;
            claims.auth_time += 600;
            (
                uid.as_str().to_owned(),
                fireemu_core_auth::jwt::encode_with(&claims, store.signer()),
                fireemu_core_auth::jwt::encode_with(&stale, store.signer()),
            )
        };
        let (ct, body) = multipart(&json!({"contentType": "text/plain"}), "text/plain", b"mine");
        let own = format!("/v0/b/{BUCKET}/o?name=users%2F{uid}%2Fnote.txt&uploadType=multipart");
        let upload = |token: &str| {
            let firebase_auth = format!("Firebase {token}");
            handle(
                &s,
                req(
                    "POST",
                    &own,
                    &[
                        ("authorization", &firebase_auth),
                        ("content-type", &ct),
                        ("x-goog-upload-protocol", "multipart"),
                    ],
                    &body,
                ),
            )
        };
        let r = upload(&future);
        match acceptance {
            // Strict refuses it as it refuses an expired token of the same user, with 401 and the
            // same headers, never with the anonymous caller's Rules denial (403). Only the message
            // differs: a token issued after the session clock reads as malformed (the documented
            // fail-closed refusal of the clock-rewind issue).
            TokenAcceptance::Verified => {
                let stale = upload(&expired);
                assert_eq!((stale.status, r.status), (401, 401));
                assert_eq!(r.headers, stale.headers);
                assert_eq!(
                    String::from_utf8_lossy(&r.body),
                    r#"{"error":{"code":401,"message":"invalid ID token: malformed token","status":"UNAUTHENTICATED"}}"#
                );
            }
            TokenAcceptance::EmulatorMock => {
                assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            }
        }
    }
}

/// `storage.maxStoredBytes` (owner ledgers 759 and 788): a write past the bound answers 402 without
/// Retry-After, `storage.maxStoredBytes limit exceeded`, in the Firebase dialect's minimal
/// envelope and the JSON API's errors array with reason `storageCapacityExceeded`. Nothing is
/// stored, and the same in both profiles' token modes.
#[test]
fn a_write_past_the_stored_byte_limit_is_402_in_both_dialects() {
    for token_acceptance in [TokenAcceptance::Verified, TokenAcceptance::EmulatorMock] {
        let s = state_with(Some(ALLOW_ALL_RULES), token_acceptance);
        s.store.lock().unwrap().set_stored_bytes_limit(Some(8));
        let owner = [("authorization", "Bearer owner")];
        let firebase = |name: &str, body: &[u8]| {
            handle(
                &s,
                req(
                    "POST",
                    &format!("/v0/b/{BUCKET}/o?name={name}"),
                    &owner,
                    body,
                ),
            )
        };
        assert_eq!(firebase("a.bin", b"12345").status, 200);
        let refused = firebase("b.bin", b"6789");
        assert_eq!(
            refused.status,
            402,
            "{}",
            String::from_utf8_lossy(&refused.body)
        );
        assert_eq!(header(&refused, "retry-after"), None);
        assert_eq!(
            json_body(&refused),
            json!({"error": {"code": 402, "message": "storage.maxStoredBytes limit exceeded"}})
        );

        let refused = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=c.bin"),
                &owner,
                b"6789",
            ),
        );
        assert_eq!(
            refused.status,
            402,
            "{}",
            String::from_utf8_lossy(&refused.body)
        );
        assert_eq!(header(&refused, "retry-after"), None);
        let error = &json_body(&refused)["error"];
        assert_eq!(error["code"], 402);
        assert_eq!(error["message"], "storage.maxStoredBytes limit exceeded");
        assert_eq!(error["errors"][0]["reason"], "storageCapacityExceeded");
        assert_eq!(
            error["errors"][0]["message"],
            "storage.maxStoredBytes limit exceeded"
        );

        let store = s.store.lock().unwrap();
        assert_eq!(store.retained_blob_bytes(), 5);
        assert!(store
            .get(
                &BucketName::try_new(BUCKET).unwrap(),
                &ObjectName::try_new("b.bin").unwrap()
            )
            .is_none());
    }
}

/// A store bounded at 8 bytes that already holds a 5-byte `a.bin`.
fn bounded_state_holding_five_bytes() -> StorageState {
    let s = state(Some(ALLOW_ALL_RULES));
    s.store.lock().unwrap().set_stored_bytes_limit(Some(8));
    let stored = handle(
        &s,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=a.bin"),
            &[("authorization", "Bearer owner")],
            b"12345",
        ),
    );
    assert_eq!(stored.status, 200);
    s
}

fn delete_a(s: &StorageState) {
    let deleted = handle(
        s,
        req(
            "DELETE",
            &format!("/v0/b/{BUCKET}/o/a.bin"),
            &[("authorization", "Bearer owner")],
            b"",
        ),
    );
    assert_eq!(deleted.status, 204);
}

/// A finalizing chunk the bound refuses does not advance the session: the status query still
/// reports the bytes before it, and the same chunk finishes the upload once there is room.
#[test]
fn a_refused_finalizing_chunk_leaves_the_firebase_resumable_session_where_it_was() {
    let s = bounded_state_holding_five_bytes();
    let start = handle(
        &s,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=f.bin"),
            &[
                ("authorization", "Bearer owner"),
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "start"),
            ],
            b"{}",
        ),
    );
    let session = header(&start, "x-goog-upload-url")
        .unwrap()
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap()
        .to_owned();
    let chunk = |command: &str, offset: &str, body: &[u8]| {
        handle(
            &s,
            req(
                "POST",
                &session,
                &[
                    ("authorization", "Bearer owner"),
                    ("x-goog-upload-command", command),
                    ("x-goog-upload-offset", offset),
                ],
                body,
            ),
        )
    };
    assert_eq!(chunk("upload", "0", b"ab").status, 200);
    let refused = chunk("upload, finalize", "2", b"cd");
    assert_eq!(
        refused.status,
        402,
        "{}",
        String::from_utf8_lossy(&refused.body)
    );
    assert_eq!(header(&refused, "retry-after"), None);
    let status = chunk("query", "0", b"");
    assert_eq!(header(&status, "x-goog-upload-size-received"), Some("2"));
    assert_eq!(header(&status, "x-goog-upload-status"), Some("active"));

    delete_a(&s);
    let done = chunk("upload, finalize", "2", b"cd");
    assert_eq!(done.status, 200, "{}", String::from_utf8_lossy(&done.body));
    assert_eq!(json_body(&done)["size"], "4");
}

/// The JSON API dialect's resumable session behaves the same way.
#[test]
fn a_refused_finalizing_chunk_leaves_the_json_api_resumable_session_where_it_was() {
    let s = bounded_state_holding_five_bytes();
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=g.bin"),
            &[
                ("authorization", "Bearer owner"),
                ("content-type", "application/json"),
            ],
            b"{}",
        ),
    );
    let location = header(&r, "location")
        .unwrap()
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap()
        .to_owned();
    let put = |range: &str, body: &[u8]| {
        handle(
            &s,
            req(
                "PUT",
                &location,
                &[("authorization", "Bearer owner"), ("content-range", range)],
                body,
            ),
        )
    };
    assert_eq!(put("bytes 0-1/*", b"ab").status, 308);
    let refused = put("bytes 2-3/4", b"cd");
    assert_eq!(
        refused.status,
        402,
        "{}",
        String::from_utf8_lossy(&refused.body)
    );
    assert_eq!(header(&refused, "retry-after"), None);
    assert_eq!(
        json_body(&refused)["error"]["errors"][0]["reason"],
        "storageCapacityExceeded"
    );
    let status = put("bytes */*", b"");
    assert_eq!(status.status, 308);
    assert_eq!(header(&status, "range"), Some("bytes=0-1"));

    delete_a(&s);
    let done = put("bytes 2-3/4", b"cd");
    assert_eq!(done.status, 200, "{}", String::from_utf8_lossy(&done.body));
    assert_eq!(json_body(&done)["size"], "4");
}

/// A copy, a rewrite and an XML-style form upload past the bound answer the same 402, with
/// nothing stored.
#[test]
fn copies_rewrites_and_form_uploads_past_the_stored_byte_limit_are_402() {
    let s = bounded_state_holding_five_bytes();
    let owner = [("authorization", "Bearer owner")];
    for verb in ["copyTo", "rewriteTo"] {
        let refused = handle(
            &s,
            req(
                "POST",
                &format!("/storage/v1/b/{BUCKET}/o/a.bin/{verb}/b/{BUCKET}/o/{verb}.bin"),
                &owner,
                b"",
            ),
        );
        assert_eq!(
            refused.status,
            402,
            "{verb}: {}",
            String::from_utf8_lossy(&refused.body)
        );
        assert_eq!(header(&refused, "retry-after"), None);
        assert_eq!(
            json_body(&refused)["error"]["errors"][0]["reason"],
            "storageCapacityExceeded"
        );
    }
    let boundary = "stored-byte-limit";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nform.bin\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"form.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n6789\r\n--{boundary}--\r\n"
    );
    let refused = handle(
        &s,
        req(
            "POST",
            &format!("/{BUCKET}"),
            &[(
                "content-type",
                &format!("multipart/form-data; boundary={boundary}"),
            )],
            body.as_bytes(),
        ),
    );
    assert_eq!(
        refused.status,
        402,
        "{}",
        String::from_utf8_lossy(&refused.body)
    );
    assert_eq!(header(&refused, "retry-after"), None);
    let store = s.store.lock().unwrap();
    assert_eq!(store.retained_blob_bytes(), 5);
}

// ------------------------------------------------------------------------------------------
// the strict profile's production framing (headers, layout, order) and the answers around it
// ------------------------------------------------------------------------------------------

fn header_names(r: &fireemu_adapter_http::storage::StorageResponse) -> Vec<String> {
    let mut names: Vec<String> = r.headers.iter().map(|(k, _)| k.clone()).collect();
    names.sort();
    names.dedup();
    names
}

/// A strict state and an emulator state, each holding `g.bin` ("hello") uploaded through the JSON
/// API with a stored `cacheControl`.
fn seeded_pair() -> [(TokenAcceptance, StorageState); 2] {
    [TokenAcceptance::Verified, TokenAcceptance::EmulatorMock].map(|acceptance| {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let upload = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=g.bin"),
                &[
                    ("authorization", "Bearer owner"),
                    ("content-type", "application/octet-stream"),
                ],
                b"hello",
            ),
        );
        assert_eq!(upload.status, 200);
        (acceptance, s)
    })
}

/// The header sets of lean-v5 for the JSON API, end to end through `handle` (the sets of every
/// request shape are pinned against the recordings in `storage_production`'s own tests).
#[test]
fn strict_json_api_answers_carry_exactly_the_recorded_header_names() {
    let (_, strict) = &seeded_pair()[0];
    let owner = [("authorization", "Bearer owner")];
    let object = format!("/storage/v1/b/{BUCKET}/o/g.bin");
    let read = handle(strict, req("GET", &object, &owner, b""));
    assert_eq!(
        header_names(&read),
        ["cache-control", "content-type", "etag", "expires", "vary"]
    );
    assert_eq!(
        header(&read, "expires"),
        Some("Sat, 29 Aug 2026 12:01:00 GMT")
    );
    let media = handle(
        strict,
        req("GET", &format!("{object}?alt=media"), &owner, b""),
    );
    assert_eq!(
        header_names(&media),
        [
            "cache-control",
            "content-disposition",
            "content-type",
            "etag",
            "expires",
            "last-modified",
            "pragma",
            "vary",
            "x-goog-generation",
            "x-goog-hash",
            "x-goog-metageneration",
            "x-goog-storage-class",
            "x-goog-stored-content-encoding",
            "x-goog-stored-content-length"
        ]
    );
    assert_eq!(header(&media, "content-disposition"), Some("attachment"));
    assert_eq!(
        header(&media, "expires"),
        Some("Mon, 01 Jan 1990 00:00:00 GMT")
    );
    let missing = handle(
        strict,
        req(
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/absent.bin?alt=media"),
            &owner,
            b"",
        ),
    );
    assert_eq!(missing.status, 404);
    assert_eq!(
        header_names(&missing),
        ["cache-control", "content-type", "expires", "vary"]
    );
    assert_eq!(
        header(&missing, "cache-control"),
        Some("private, max-age=0")
    );
    let delete = handle(strict, req("DELETE", &object, &owner, b""));
    assert_eq!(delete.status, 204);
    assert_eq!(
        header_names(&delete),
        ["cache-control", "content-type", "expires", "pragma", "vary"]
    );
}

#[test]
fn strict_firebase_answers_carry_exactly_the_recorded_header_names() {
    let (_, strict) = &seeded_pair()[0];
    let owner = [("authorization", "Bearer owner")];
    let object = format!("/v0/b/{BUCKET}/o/g.bin");
    let read = handle(strict, req("GET", &object, &owner, b""));
    assert_eq!(
        header_names(&read),
        [
            "access-control-allow-origin",
            "access-control-expose-headers",
            "cache-control",
            "content-type",
            "expires",
            "x-content-type-options"
        ]
    );
    let media = handle(
        strict,
        req("GET", &format!("{object}?alt=media"), &owner, b""),
    );
    assert_eq!(
        header_names(&media),
        [
            "accept-ranges",
            "cache-control",
            "content-type",
            "etag",
            "expires",
            "last-modified",
            "pragma",
            "x-goog-generation",
            "x-goog-hash",
            "x-goog-meta-firebasestoragedownloadtokens",
            "x-goog-metageneration",
            "x-goog-storage-class",
            "x-goog-stored-content-encoding",
            "x-goog-stored-content-length"
        ]
    );
    // The v0 validator is the quoted MD5 of "hello" in hex.
    assert_eq!(
        header(&media, "etag"),
        Some("\"5d41402abc4b2a76b9719d911017c592\"")
    );
    let range = handle(
        strict,
        req(
            "GET",
            &format!("{object}?alt=media"),
            &[("authorization", "Bearer owner"), ("range", "bytes=50-60")],
            b"",
        ),
    );
    assert_eq!(range.status, 416);
    assert_eq!(header(&range, "cache-control"), Some("private, max-age=0"));
    assert_eq!(header(&range, "pragma"), None);
    assert!(header(&range, "etag").is_some() && header(&range, "x-goog-hash").is_some());
    assert_eq!(header(&range, "content-disposition"), None);
}

/// The emulator profile keeps the official emulator's headers, so none of the framing applies.
#[test]
fn the_emulator_profile_keeps_the_official_headers() {
    let (_, emulator) = &seeded_pair()[1];
    let owner = [("authorization", "Bearer owner")];
    let read = handle(
        emulator,
        req(
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/g.bin"),
            &owner,
            b"",
        ),
    );
    assert_eq!(header(&read, "cache-control"), None);
    assert_eq!(header(&read, "expires"), None);
    assert_eq!(header(&read, "etag"), None);
    assert!(read.body.starts_with(b"{\""), "compact body");
}

/// Reads of a name over the limit are 404s on both dialects, in both profiles (recorded, lean-v5;
/// the official emulator answers 404 too, measured with 1,100 characters).
#[test]
fn a_read_of_an_over_long_name_is_not_found() {
    let long = "x".repeat(1025);
    for (acceptance, s) in seeded_pair() {
        let owner = [("authorization", "Bearer owner")];
        for path in [
            format!("/v0/b/{BUCKET}/o/{long}"),
            format!("/v0/b/{BUCKET}/o/{long}?alt=media"),
            format!("/storage/v1/b/{BUCKET}/o/{long}"),
            format!("/storage/v1/b/{BUCKET}/o/{long}?alt=media"),
        ] {
            let r = handle(&s, req("GET", &path, &owner, b""));
            assert_eq!(r.status, 404, "{acceptance:?} {}", &path[..40]);
        }
    }
}

/// A `PUT` clears the header-like fields it omits (recorded: `cacheControl`) and keeps the
/// content type it names.
#[test]
fn a_put_clears_the_cache_control_it_omits() {
    for (acceptance, s) in seeded_pair() {
        let owner = [
            ("authorization", "Bearer owner"),
            ("content-type", "application/json"),
        ];
        let object = format!("/storage/v1/b/{BUCKET}/o/g.bin");
        let patched = handle(
            &s,
            req(
                "PATCH",
                &object,
                &owner,
                br#"{"cacheControl":"private, max-age=0"}"#,
            ),
        );
        assert_eq!(
            json_body(&patched)["cacheControl"],
            "private, max-age=0",
            "{acceptance:?}"
        );
        let put = handle(
            &s,
            req(
                "PUT",
                &object,
                &owner,
                br#"{"contentType":"text/plain","metadata":{"marker":"second"}}"#,
            ),
        );
        let body = json_body(&put);
        assert_eq!(body.get("cacheControl"), None, "{acceptance:?}");
        assert_eq!(body["contentType"], "text/plain");
        assert_eq!(body["metadata"], json!({"marker": "second"}));
    }
}

/// `copyTo` and `rewriteTo` name an owner under strict (recorded: `owner.entity`).
#[test]
fn a_copied_object_names_an_owner_only_under_strict() {
    for (acceptance, s) in seeded_pair() {
        let owner = [("authorization", "Bearer owner")];
        let copy = handle(
            &s,
            req(
                "POST",
                &format!("/storage/v1/b/{BUCKET}/o/g.bin/copyTo/b/{BUCKET}/o/h.bin"),
                &owner,
                b"",
            ),
        );
        assert_eq!(copy.status, 200, "{acceptance:?}");
        let strict = acceptance == TokenAcceptance::Verified;
        assert_eq!(json_body(&copy)["owner"]["entity"].is_string(), strict);
        let rewrite = handle(
            &s,
            req(
                "POST",
                &format!("/storage/v1/b/{BUCKET}/o/g.bin/rewriteTo/b/{BUCKET}/o/i.bin"),
                &owner,
                b"",
            ),
        );
        assert_eq!(
            json_body(&rewrite)["resource"]["owner"]["entity"].is_string(),
            strict
        );
    }
}

/// The JSON API refuses an upload name production refuses with the recorded bytes: a JSON error
/// served as `text/html`, 432 bytes for the recorded line-feed name and 504 for the 1,025-byte one.
#[test]
fn strict_json_api_upload_names_are_refused_with_the_recorded_bytes() {
    let strict = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    let scope = "storage-object/9d4b0726ac89c07f3d89/errors/object-name/gcs-";
    let long = format!("{scope}{}", "x".repeat(1025 - scope.len()));
    let refused = |name: &str| {
        handle(
            &strict,
            req(
                "POST",
                &format!(
                    "/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name={}",
                    name.replace('\n', "%0A")
                ),
                &[("authorization", "Bearer owner")],
                b"x",
            ),
        )
    };
    let line_feed = refused(&format!("{scope}line\nbreak.bin"));
    assert_eq!(line_feed.status, 400);
    assert_eq!(line_feed.body.len(), 432);
    assert_eq!(
        header(&line_feed, "content-type"),
        Some("text/html; charset=UTF-8")
    );
    assert!(String::from_utf8_lossy(&line_feed.body)
        .contains("Disallowed unicode characters present in object name"));
    let oversized = refused(&long);
    assert_eq!(oversized.status, 400);
    assert_eq!(oversized.body.len(), 504);
    let text = String::from_utf8_lossy(&oversized.body).into_owned();
    assert!(text.contains(
        "The maximum object length is 1024 characters, but got a name with 1025 characters: '"
    ));
    assert!(text.contains(&format!("{}...'", &long[..77])));
}

/// Declared checksums: strict refuses a mismatch with production's words; the emulator profile
/// accepts it as the official emulator does (measured: a wrong declared MD5 is a 200).
#[test]
fn declared_checksums_are_verified_only_under_strict() {
    for (acceptance, _) in seeded_pair() {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let upload = |hash: &str| {
            handle(
                &s,
                req(
                    "POST",
                    &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=c.bin"),
                    &[
                        ("authorization", "Bearer owner"),
                        ("content-type", "text/plain"),
                        ("x-goog-hash", hash),
                    ],
                    b"hello",
                ),
            )
        };
        let wrong = upload("md5=AAAAAAAAAAAAAAAAAAAAAA==");
        if acceptance == TokenAcceptance::Verified {
            assert_eq!(wrong.status, 400);
            assert!(json_body(&wrong)["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("Provided MD5 hash \"AAAAAAAAAAAAAAAAAAAAAA==\" doesn't match calculated MD5 hash \""));
            let crc = upload("crc32c=AAAAAA==");
            assert!(json_body(&crc)["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("Provided CRC32C \"AAAAAA==\" doesn't match calculated CRC32C \""));
            let malformed = upload("md5=!not-base64!");
            assert_eq!(
                json_body(&malformed)["error"]["message"],
                "Provided value (!not-base64!) is not a base64-encoded 128-bit MD5 hash."
            );
            assert_eq!(
                json_body(&upload("crc32c=AAA"))["error"]["message"],
                "Invalid argument."
            );
        } else {
            assert_eq!(wrong.status, 200, "the official emulator verifies nothing");
            assert_eq!(upload("crc32c=AAAAAA==").status, 200);
        }
    }
}

/// Declared checksums on resumable uploads, in both dialects: strict refuses a wrong or a
/// malformed one in production's words; the emulator profile completes the upload as the official
/// emulator does (firebase-tools 15.28.2 compares no declared checksum on any path).
#[test]
#[allow(clippy::too_many_lines)]
fn resumable_uploads_verify_declared_checksums_only_under_strict() {
    const WRONG: &str = "AAAAAAAAAAAAAAAAAAAAAA==";
    for (acceptance, _) in seeded_pair() {
        let strict = acceptance == TokenAcceptance::Verified;
        // Firebase dialect: a wrong md5Hash in the start metadata is found at finalize.
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let owner = [
            ("authorization", "Bearer owner"),
            ("x-goog-upload-protocol", "resumable"),
        ];
        let v0_start = |name: &str, metadata: &str| {
            handle(
                &s,
                req(
                    "POST",
                    &format!("/v0/b/{BUCKET}/o?name={name}"),
                    &[
                        owner[0],
                        owner[1],
                        ("x-goog-upload-command", "start"),
                        ("content-type", "application/json"),
                    ],
                    metadata.as_bytes(),
                ),
            )
        };
        let wrong = v0_start(
            "w.bin",
            &format!(r#"{{"name":"w.bin","md5Hash":"{WRONG}"}}"#),
        );
        assert_eq!(wrong.status, 200, "{acceptance:?} start");
        let url = header(&wrong, "x-goog-upload-url").unwrap().to_owned();
        let session = url
            .split_once("/v0/")
            .map(|(_, rest)| format!("/v0/{rest}"))
            .unwrap();
        let finalize = handle(
            &s,
            req(
                "POST",
                &session,
                &[
                    owner[0],
                    owner[1],
                    ("x-goog-upload-command", "upload, finalize"),
                    ("x-goog-upload-offset", "0"),
                ],
                b"hello",
            ),
        );
        assert_eq!(
            finalize.status,
            if strict { 400 } else { 200 },
            "{acceptance:?} finalize"
        );
        let crc = v0_start("c.bin", r#"{"name":"c.bin","crc32c":"AAA"}"#);
        assert_eq!(
            crc.status,
            if strict { 400 } else { 200 },
            "{acceptance:?} malformed crc32c"
        );
        let md5 = v0_start("m.bin", r#"{"name":"m.bin","md5Hash":"!not-base64!"}"#);
        assert_eq!(
            md5.status,
            if strict { 400 } else { 200 },
            "{acceptance:?} malformed md5Hash"
        );

        // JSON API: the same declarations in the start metadata, found at the last chunk.
        let start = |metadata: &str| {
            handle(
                &s,
                req(
                    "POST",
                    &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=j.bin"),
                    &[
                        ("authorization", "Bearer owner"),
                        ("content-type", "application/json"),
                    ],
                    metadata.as_bytes(),
                ),
            )
        };
        let started = start(&format!(r#"{{"md5Hash":"{WRONG}"}}"#));
        assert_eq!(started.status, 200, "{acceptance:?} JSON API start");
        let location = header(&started, "location")
            .unwrap()
            .strip_prefix("http://127.0.0.1:9199")
            .unwrap()
            .to_owned();
        let put = handle(
            &s,
            req(
                "PUT",
                &location,
                &[("authorization", "Bearer owner")],
                b"hello",
            ),
        );
        assert_eq!(
            put.status,
            if strict { 400 } else { 200 },
            "{acceptance:?} JSON API put"
        );
        assert_eq!(
            start(r#"{"crc32c":"AAA"}"#).status,
            if strict { 400 } else { 200 },
            "{acceptance:?} JSON API malformed crc32c"
        );
    }
}

/// A browser sends an `Origin`, and every recording was made without one. Under strict an answer to
/// such a request keeps production's headers and adds what a browser needs to read it: the origin
/// reflected and the official emulator's list of exposed headers (which names the `X-Goog-Upload-*`
/// headers the Firebase SDK reads). Without an `Origin` the recorded sets stay exactly as recorded.
#[test]
#[allow(clippy::too_many_lines)]
fn strict_answers_to_a_browser_origin_carry_the_reflection_and_the_exposed_headers() {
    const ORIGIN: &str = "http://localhost:5173";
    let s = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    let call = |origin: bool, method: &str, path: &str, extra: &[(&str, &str)], body: &[u8]| {
        let mut headers = vec![("authorization", "Bearer owner")];
        if origin {
            headers.push(("origin", ORIGIN));
        }
        headers.extend_from_slice(extra);
        handle(&s, req(method, path, &headers, body))
    };
    let reflected = |response: &fireemu_adapter_http::storage::StorageResponse, what: &str| {
        assert_eq!(
            header(response, "access-control-allow-origin"),
            Some(ORIGIN),
            "{what}"
        );
        let exposed = header(response, "access-control-expose-headers")
            .unwrap_or_default()
            .to_ascii_lowercase();
        for name in [
            "x-goog-upload-status",
            "x-goog-upload-url",
            "x-goog-upload-size-received",
            "x-goog-upload-chunk-granularity",
        ] {
            assert!(exposed.contains(name), "{what}: {name} in {exposed}");
        }
        let vary: Vec<_> = response
            .headers
            .iter()
            .filter(|(name, _)| name == "vary")
            .collect();
        assert!(!vary.is_empty(), "{what}: the reflection varies on Origin");
    };
    let v0_headers = |command: &'static str| -> Vec<(&'static str, &'static str)> {
        vec![
            ("x-goog-upload-protocol", "resumable"),
            ("x-goog-upload-command", command),
            ("content-type", "application/json"),
        ]
    };
    for origin in [true, false] {
        let start = call(
            origin,
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=cors.bin"),
            &v0_headers("start"),
            br#"{"name":"cors.bin","contentType":"application/octet-stream"}"#,
        );
        assert_eq!(start.status, 200);
        let url = header(&start, "x-goog-upload-url").unwrap().to_owned();
        let session = url
            .split_once("/v0/")
            .map(|(_, rest)| format!("/v0/{rest}"))
            .unwrap();
        let query = call(origin, "POST", &session, &v0_headers("query"), b"");
        let chunk = call(
            origin,
            "POST",
            &session,
            &[
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "upload"),
                ("x-goog-upload-offset", "0"),
            ],
            b"ab",
        );
        assert_eq!(chunk.status, 200);
        let finalize = call(
            origin,
            "POST",
            &session,
            &[
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "upload, finalize"),
                ("x-goog-upload-offset", "2"),
            ],
            b"",
        );
        assert_eq!(
            finalize.status,
            200,
            "{}",
            String::from_utf8_lossy(&finalize.body)
        );
        let download = call(
            origin,
            "GET",
            &format!("/v0/b/{BUCKET}/o/cors.bin?alt=media"),
            &[],
            b"",
        );
        assert_eq!(download.status, 200);
        let metadata = call(
            origin,
            "GET",
            &format!("/v0/b/{BUCKET}/o/cors.bin"),
            &[],
            b"",
        );
        let json_start = call(
            origin,
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=j.bin"),
            &[("content-type", "application/json")],
            b"{}",
        );
        let location = header(&json_start, "location")
            .unwrap()
            .strip_prefix("http://127.0.0.1:9199")
            .unwrap()
            .to_owned();
        let incomplete = call(
            origin,
            "PUT",
            &location,
            &[("content-range", "bytes 0-2/6")],
            b"abc",
        );
        assert_eq!(incomplete.status, 308);
        let json_api = call(
            origin,
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/cors.bin"),
            &[],
            b"",
        );
        let answers = [
            ("v0 start", &start),
            ("v0 query", &query),
            ("v0 upload chunk", &chunk),
            ("v0 finalize", &finalize),
            ("v0 media", &download),
            ("v0 metadata", &metadata),
            ("JSON API resumable start", &json_start),
            ("JSON API 308", &incomplete),
            ("JSON API metadata", &json_api),
        ];
        for (what, response) in answers {
            if origin {
                reflected(response, what);
            } else {
                // The recorded sets: the text answers carry no CORS, the v0 JSON answers carry
                // the wildcard and the two exposed headers of the recording.
                let wildcard = header(response, "access-control-allow-origin");
                match what {
                    "v0 finalize" | "v0 metadata" => {
                        assert_eq!(wildcard, Some("*"), "{what}");
                        assert_eq!(
                            header(response, "access-control-expose-headers"),
                            Some("Content-Range, X-Firebase-Storage-XSRF"),
                            "{what}"
                        );
                    }
                    _ => assert_eq!(wildcard, None, "{what}"),
                }
            }
        }
    }
}

/// The Firebase resumable protocol under strict (recorded, lean-v5): granularity 262144, a control
/// URL equal to the session URL, no `x-gupload-uploadid`, empty bodies, a cancel that says
/// `cancelled` and the wrong-offset text.
#[test]
fn strict_firebase_resumable_answers_follow_the_recording() {
    for (acceptance, _) in seeded_pair() {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let strict = acceptance == TokenAcceptance::Verified;
        let owner = [
            ("authorization", "Bearer owner"),
            ("x-goog-upload-protocol", "resumable"),
        ];
        let route = format!("/v0/b/{BUCKET}/o?name=r.bin");
        let start = handle(
            &s,
            req(
                "POST",
                &route,
                &[
                    owner[0],
                    owner[1],
                    ("x-goog-upload-command", "start"),
                    ("content-type", "application/json"),
                ],
                br#"{"name":"r.bin","contentType":"application/octet-stream"}"#,
            ),
        );
        assert_eq!(start.status, 200, "{acceptance:?}");
        assert!(start.body.is_empty());
        let url = header(&start, "x-goog-upload-url").unwrap().to_owned();
        assert_eq!(header(&start, "x-gupload-uploadid").is_none(), strict);
        if strict {
            assert_eq!(
                header(&start, "x-goog-upload-chunk-granularity"),
                Some("262144")
            );
            assert_eq!(
                header(&start, "x-goog-upload-control-url"),
                Some(url.as_str())
            );
        } else {
            assert_eq!(
                header(&start, "x-goog-upload-chunk-granularity"),
                Some("10000")
            );
        }
        let session = url
            .split_once("/v0/")
            .map(|(_, rest)| format!("/v0/{rest}"))
            .unwrap();
        let query = handle(
            &s,
            req(
                "POST",
                &session,
                &[owner[0], owner[1], ("x-goog-upload-command", "query")],
                b"",
            ),
        );
        assert_eq!(header(&query, "x-goog-upload-status"), Some("active"));
        assert_eq!(
            header(&query, "x-goog-upload-chunk-granularity").is_some(),
            strict
        );
        assert_eq!(query.body.is_empty(), strict);
        let wrong = handle(
            &s,
            req(
                "POST",
                &session,
                &[
                    owner[0],
                    owner[1],
                    ("x-goog-upload-command", "upload"),
                    ("x-goog-upload-offset", "1"),
                ],
                b"x",
            ),
        );
        assert_eq!(wrong.status, 400, "{acceptance:?}");
        if strict {
            assert_eq!(
                String::from_utf8_lossy(&wrong.body),
                "Client uploaded to the wrong offset (1 instead of 0)."
            );
            assert_eq!(
                header(&wrong, "content-type"),
                Some("text/plain; charset=utf-8")
            );
        }
        let cancel = handle(
            &s,
            req(
                "POST",
                &session,
                &[owner[0], owner[1], ("x-goog-upload-command", "cancel")],
                b"",
            ),
        );
        assert_eq!(cancel.status, 200);
        assert_eq!(header(&cancel, "x-goog-upload-status").is_some(), strict);
        assert_eq!(cancel.body.is_empty(), strict);
    }
}

/// Multipart on the Firebase dialect: strict types the object by its data part when the metadata
/// names no type, and answers the two refusals with production's bodies (recorded, lean-v5).
#[test]
fn strict_firebase_multipart_follows_the_recording() {
    for (acceptance, _) in seeded_pair() {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let strict = acceptance == TokenAcceptance::Verified;
        let (content_type, body) = multipart(&json!({"name": "m.txt"}), "text/plain", b"hello");
        let uploaded = handle(
            &s,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=m.txt&uploadType=multipart"),
                &[
                    ("authorization", "Bearer owner"),
                    ("x-goog-upload-protocol", "multipart"),
                    ("content-type", &content_type),
                ],
                &body,
            ),
        );
        assert_eq!(uploaded.status, 200, "{acceptance:?}");
        assert_eq!(
            json_body(&uploaded)["contentType"],
            if strict {
                "text/plain"
            } else {
                "application/octet-stream"
            }
        );
        let not_two_parts = handle(
            &s,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=n.txt"),
                &[
                    ("authorization", "Bearer owner"),
                    ("x-goog-upload-protocol", "multipart"),
                    ("content-type", "multipart/related; boundary=b"),
                ],
                b"--b\r\nContent-Type: application/json\r\n\r\n{}\r\n--b--",
            ),
        );
        assert_eq!(not_two_parts.status, 400, "{acceptance:?}");
        if strict {
            assert_eq!(
                String::from_utf8_lossy(&not_two_parts.body),
                "Multipart body does not contain 2 or 3 parts."
            );
            assert_eq!(
                header(&not_two_parts, "content-type"),
                Some("text/plain; charset=utf-8")
            );
        }
    }
}

/// The strict profile through the real server: a framed JSON API answer carries production's set
/// (no `nosniff`, the origin reflected) and a Firebase v0 JSON answer its own CORS header.
#[tokio::test]
async fn the_strict_server_sends_production_headers_on_framed_answers() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    static BUDGET: BodyBudget = BodyBudget::new(1_572_864);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_storage_with_budget(
        listener,
        Arc::new(state(None)),
        &BUDGET,
    ));
    let get_with = |path: &'static str, origin: &'static str| async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{origin}Authorization: Bearer owner\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        String::from_utf8_lossy(&raw).to_lowercase()
    };
    let get = |path: &'static str| get_with(path, "Origin: http://localhost:5173\r\n");
    let json_api = get("/storage/v1/b/demo-app.appspot.com/o/absent.bin").await;
    assert!(json_api.starts_with("http/1.1 404"), "{json_api}");
    assert!(
        json_api.contains("access-control-allow-origin: http://localhost:5173"),
        "{json_api}"
    );
    assert!(
        json_api.contains("vary: origin\r\nvary: x-origin"),
        "{json_api}"
    );
    assert!(!json_api.contains("x-content-type-options"), "{json_api}");
    // A browser's request is answered with what it needs to read the answer (the origin reflected,
    // the official emulator's exposed headers), on both dialects; the recorded wildcard of the
    // v0 JSON answers is for requests without an `Origin`.
    assert!(
        json_api.contains("access-control-expose-headers: content-type,x-firebase-storage-version"),
        "{json_api}"
    );
    let firebase = get("/v0/b/demo-app.appspot.com/o/absent.bin").await;
    assert!(
        firebase.contains("access-control-allow-origin: http://localhost:5173"),
        "{firebase}"
    );
    assert!(
        firebase.contains("access-control-expose-headers: content-type,x-firebase-storage-version"),
        "{firebase}"
    );
    assert!(
        firebase.contains("x-content-type-options: nosniff"),
        "{firebase}"
    );
    // Without an `Origin` the recorded set stays: the wildcard and its two exposed headers on the
    // v0 JSON answer, no CORS on the JSON API.
    let recorded = get_with("/v0/b/demo-app.appspot.com/o/absent.bin", "").await;
    assert!(
        recorded.contains("access-control-allow-origin: *"),
        "{recorded}"
    );
    assert!(
        recorded.contains("access-control-expose-headers: content-range, x-firebase-storage-xsrf"),
        "{recorded}"
    );
    let recorded_json = get_with("/storage/v1/b/demo-app.appspot.com/o/absent.bin", "").await;
    assert!(
        !recorded_json.contains("access-control-"),
        "{recorded_json}"
    );
    // A shape the recordings do not cover keeps the official emulator's stamps.
    let unframed = get("/b").await;
    assert!(
        unframed.contains("access-control-expose-headers: content-type,x-firebase-storage-version"),
        "{unframed}"
    );
    server.abort();
}

/// The remaining strict answers of the lean-v5 recording: `Bad Request.` for a v0 upload name
/// production refuses, no `x-goog-upload-status` on a refused simple upload, the `.txt` type
/// inference of a v0 upload and the recorded malformed metadata part on the JSON API.
#[test]
fn strict_answers_that_follow_single_recorded_rows() {
    for (acceptance, _) in seeded_pair() {
        let strict = acceptance == TokenAcceptance::Verified;
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        let owner = [("authorization", "Bearer owner")];
        // A v0 upload name with a line feed.
        let refused = handle(
            &s,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=a%0Ab.bin"),
                &owner,
                b"x",
            ),
        );
        assert_eq!(refused.status, 400, "{acceptance:?}");
        if strict {
            assert_eq!(
                String::from_utf8_lossy(&refused.body),
                "{\n  \"error\": {\n    \"code\": 400,\n    \"message\": \"Bad Request.\"\n  }\n}"
            );
        }
        // A `.txt` object uploaded as `application/octet-stream`.
        let uploaded = handle(
            &s,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=a.txt"),
                &[owner[0], ("content-type", "application/octet-stream")],
                b"hello",
            ),
        );
        assert_eq!(
            json_body(&uploaded)["contentType"],
            if strict {
                "text/plain"
            } else {
                "application/octet-stream"
            },
            "{acceptance:?}"
        );
        let binary = handle(
            &s,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=a.bin"),
                &[owner[0], ("content-type", "application/octet-stream")],
                b"hello",
            ),
        );
        assert_eq!(
            json_body(&binary)["contentType"],
            "application/octet-stream"
        );
        // A refused simple upload under a denying rule carries no upload-status header in strict.
        let denying = state_with(
            Some("rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read: if true; } } }"),
            TokenAcceptance::Verified,
        );
        let denied = handle(
            &denying,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=d.bin"),
                &[("content-type", "application/octet-stream")],
                b"x",
            ),
        );
        assert_eq!(denied.status, 403);
        assert!(
            header(&denied, "x-goog-upload-status").is_none(),
            "{acceptance:?}"
        );
        // The recorded malformed metadata part of the JSON API.
        let (content_type, body) = {
            let boundary = "b";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Type: application/json\r\n\r\n{{invalid-json\r\n--{boundary}\r\nContent-Type: text/plain\r\n\r\nhello\r\n--{boundary}--").as_bytes(),
            );
            (format!("multipart/related; boundary={boundary}"), body)
        };
        let bad = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=multipart&name=m.bin"),
                &[owner[0], ("content-type", &content_type)],
                &body,
            ),
        );
        assert_eq!(bad.status, 400, "{acceptance:?}");
        if strict {
            assert_eq!(
                header(&bad, "content-type"),
                Some("text/html; charset=UTF-8")
            );
            assert!(String::from_utf8_lossy(&bad.body).contains(
                "Parse Error: Unexpected end of string. Expected : between key:value pair.\\ninvalid-json\\n            ^"
            ));
        }
    }
}

// ------------------------------------------------------------------------------------------
// properties of the Firebase list over the handler
// ------------------------------------------------------------------------------------------

mod list_properties {
    use super::*;
    use proptest::prelude::*;

    const SEGMENTS: &[&str] = &["a", "b", "c", "dir", "dir2", "x"];

    /// The standard base64 (with padding) of an entry name, as production writes the page token.
    fn token_of(entry: &str) -> String {
        fireemu_core_storage::hash::base64(entry.as_bytes())
    }

    fn percent(text: &str) -> String {
        text.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    char::from(b).to_string()
                }
                other => format!("%{other:02X}"),
            })
            .collect()
    }

    proptest! {
        /// Following `nextPageToken` through the Firebase list of both profiles gives the
        /// single-page listing: items and prefixes in one name order, none twice, none missing,
        /// at most `maxResults` per page, and every token the base64 of the last entry returned.
        #[test]
        fn firebase_list_pages_follow_their_tokens(
            names in proptest::collection::btree_set(
                proptest::collection::vec(proptest::sample::select(SEGMENTS), 1..=3)
                    .prop_map(|segments| segments.join("/")),
                0..=16,
            ),
            prefix in proptest::sample::select(&["", "a/", "dir/"][..]),
            delimiter in proptest::sample::select(&["", "/"][..]),
            max in 1usize..=4,
            strict in any::<bool>(),
        ) {
            let acceptance = if strict { TokenAcceptance::Verified } else { TokenAcceptance::EmulatorMock };
            let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
            let owner = [("authorization", "Bearer owner")];
            for name in &names {
                let uploaded = handle(
                    &s,
                    req(
                        "POST",
                        &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name={}", percent(name)),
                        &owner,
                        b"x",
                    ),
                );
                prop_assert_eq!(uploaded.status, 200);
            }
            let mut expected: Vec<String> = Vec::new();
            {
                let mut entries = std::collections::BTreeSet::new();
                for name in &names {
                    let Some(rest) = name.strip_prefix(prefix) else { continue };
                    match (delimiter.is_empty(), rest.find(delimiter)) {
                        (false, Some(i)) => { entries.insert(format!("{prefix}{}{delimiter}", &rest[..i])); }
                        _ => { entries.insert(name.clone()); }
                    }
                }
                expected.extend(entries);
            }
            let mut seen: Vec<String> = Vec::new();
            let mut token: Option<String> = None;
            for _ in 0..expected.len() + 2 {
                let route = format!(
                    "/v0/b/{BUCKET}/o?maxResults={max}{}{}{}",
                    if prefix.is_empty() { String::new() } else { format!("&prefix={}", percent(prefix)) },
                    if delimiter.is_empty() { String::new() } else { format!("&delimiter={}", percent(delimiter)) },
                    token.as_ref().map_or_else(String::new, |t| format!("&pageToken={}", percent(t))),
                );
                let page = handle(&s, req("GET", &route, &owner, b""));
                prop_assert_eq!(page.status, 200);
                let body = json_body(&page);
                let mut page_entries: Vec<String> = body["items"].as_array().unwrap_or(&Vec::new()).iter()
                    .map(|item| item["name"].as_str().unwrap().to_owned())
                    .chain(body["prefixes"].as_array().unwrap_or(&Vec::new()).iter().map(|p| p.as_str().unwrap().to_owned()))
                    .collect();
                page_entries.sort();
                prop_assert!(page_entries.len() <= max);
                seen.extend(page_entries.clone());
                if let Some(next) = body["nextPageToken"].as_str() {
                    prop_assert_eq!(page_entries.len(), max);
                    prop_assert_eq!(next, token_of(page_entries.last().unwrap()));
                    token = Some(next.to_owned());
                } else {
                    prop_assert_eq!(seen, expected);
                    return Ok(());
                }
            }
            prop_assert!(false, "the walk did not end");
        }
    }
}

/// Puts `names` straight into the object store of `state`.
fn put_names(state: &StorageState, names: &[String]) {
    let mut store = state.store.lock().unwrap();
    for name in names {
        store
            .put(
                &BucketName::try_new(BUCKET).unwrap(),
                &ObjectName::try_new(name).unwrap(),
                vec![1],
                NewMetadata::default(),
                Precondition::default(),
                START,
            )
            .unwrap();
    }
}

/// A glob page read in batches and cut when it is complete is the page the whole listing filtered
/// by the glob gives, token after token, for patterns, delimiters, prefixes, offsets and sizes,
/// with a token that names no entry starting the listing over.
#[test]
#[allow(clippy::too_many_lines)]
fn a_glob_listing_in_batches_equals_the_filtered_listing_page_by_page() {
    let state = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    let mut names: Vec<String> = Vec::new();
    for dir in ["a", "b", "dir", "dir2", "z"] {
        for leaf in 0..40 {
            names.push(format!("{dir}/f{leaf:02}.txt"));
            if leaf % 7 == 0 {
                names.push(format!("{dir}/sub/g{leaf:02}.bin"));
            }
        }
    }
    names.extend([
        "top.txt".to_owned(),
        "top2.bin".to_owned(),
        "Z.txt".to_owned(),
    ]);
    put_names(&state, &names);
    let encode = |text: &str| -> String {
        text.bytes().fold(String::new(), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "%{byte:02X}");
            out
        })
    };
    let bucket = BucketName::try_new(BUCKET).unwrap();
    for (glob, prefix, delimiter, start, end) in [
        ("**", "", "", "", ""),
        ("**", "", "/", "", ""),
        ("dir/*", "", "", "", ""),
        ("*/f0[0-3].txt", "", "/", "", ""),
        ("{a,b}/**", "", "/", "", ""),
        ("**.bin", "dir", "/", "", ""),
        ("dir/**", "dir/", "/", "", ""),
        ("**/f1?.txt", "", "", "b/", "dir2"),
        ("nothing*", "", "/", "", ""),
        ("*", "", "/", "", ""),
    ] {
        for max in [1usize, 2, 3, 7, 50, 1000] {
            let filter = |name: &str| {
                fireemu_core_storage::glob::glob_matches(glob, name)
                    && (start.is_empty() || name >= start)
                    && (end.is_empty() || name < end)
            };
            let mut token: Option<String> = None;
            for round in 0..300 {
                let expected = state.store.lock().unwrap().list_matching(
                    &bucket,
                    prefix,
                    Some(delimiter),
                    token.as_deref(),
                    Some(max),
                    &filter,
                );
                let mut query = format!(
                    "matchGlob={}&maxResults={max}&prefix={}&delimiter={}",
                    encode(glob),
                    encode(prefix),
                    encode(delimiter)
                );
                if !start.is_empty() {
                    query = format!("{query}&startOffset={}", encode(start));
                }
                if !end.is_empty() {
                    query = format!("{query}&endOffset={}", encode(end));
                }
                if let Some(token) = &token {
                    query = format!("{query}&pageToken={}", encode(token));
                }
                let answered = handle(
                    &state,
                    req(
                        "GET",
                        &format!("/storage/v1/b/{BUCKET}/o?{query}"),
                        &[("authorization", "Bearer owner")],
                        b"",
                    ),
                );
                assert_eq!(
                    answered.status, 200,
                    "{glob} {prefix} {delimiter} {max} {round}"
                );
                let body = json_body(&answered);
                let got_items: Vec<&str> = body["items"]
                    .as_array()
                    .map(|items| items.iter().map(|i| i["name"].as_str().unwrap()).collect())
                    .unwrap_or_default();
                let want_items: Vec<&str> =
                    expected.items.iter().map(|m| m.name.as_str()).collect();
                let got_prefixes: Vec<&str> = body["prefixes"]
                    .as_array()
                    .map(|p| p.iter().map(|v| v.as_str().unwrap()).collect())
                    .unwrap_or_default();
                let context = format!("{glob} {prefix:?} {delimiter:?} max {max} round {round}");
                assert_eq!(got_items, want_items, "{context}");
                assert_eq!(got_prefixes, expected.prefixes, "{context}");
                assert_eq!(
                    body["nextPageToken"].as_str().map(str::to_owned),
                    expected.next_page_token,
                    "{context}"
                );
                token = expected.next_page_token;
                if token.is_none() {
                    break;
                }
            }
        }
    }
    // A token that names no entry starts the listing over, with or without a glob.
    let listed = |query: &str| {
        json_body(&handle(
            &state,
            req(
                "GET",
                &format!("/storage/v1/b/{BUCKET}/o?{query}"),
                &[("authorization", "Bearer owner")],
                b"",
            ),
        ))
    };
    let with_glob = listed(&format!(
        "matchGlob={}&maxResults=2&pageToken=nope",
        encode("**")
    ));
    let without_token = listed(&format!("matchGlob={}&maxResults=2", encode("**")));
    assert_eq!(with_glob, without_token);
}

/// A page reflects names as they are when it is read: a name deleted while the page is being made
/// leaves the page, and nothing else does. The listing never ends early (a next-page token stays
/// while matching names remain after the page), and a prefix stays listed while any name under it
/// exists, even when the one name that stood for it is deleted. A writer deletes and re-creates one
/// name of the first page while a reader lists that page again and again.
#[test]
fn a_glob_listing_keeps_its_token_and_prefixes_while_a_name_of_the_page_is_deleted_and_recreated() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let bucket = BucketName::try_new(BUCKET).unwrap();
    for (delimiter, victim) in [("", "a/00005.txt"), ("/", "d00/f0")] {
        let state = Arc::new(state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified));
        let names: Vec<String> = if delimiter.is_empty() {
            (0..1_500).map(|n| format!("a/{n:05}.txt")).collect()
        } else {
            (0..120)
                .flat_map(|d| (0..3).map(move |f| format!("d{d:02}/f{f}")))
                .collect()
        };
        put_names(&state, &names);
        let stop = Arc::new(AtomicBool::new(false));
        let writer = {
            let (state, stop, bucket) = (Arc::clone(&state), Arc::clone(&stop), bucket.clone());
            let victim = ObjectName::try_new(victim).unwrap();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = state.store.lock().unwrap().delete(
                        &bucket,
                        &victim,
                        Precondition::default(),
                    );
                    std::thread::yield_now();
                    put_names(&state, &[victim.as_str().to_owned()]);
                    std::thread::yield_now();
                }
            })
        };
        let (mut without_token, mut without_prefix) = (0, 0);
        for _ in 0..1_000 {
            let answered = handle(
                &state,
                req(
                    "GET",
                    &format!(
                        "/storage/v1/b/{BUCKET}/o?matchGlob=%2A%2A&maxResults=10&delimiter={}",
                        if delimiter.is_empty() { "" } else { "%2F" }
                    ),
                    &[("authorization", "Bearer owner")],
                    b"",
                ),
            );
            let body = json_body(&answered);
            without_token += usize::from(body.get("nextPageToken").is_none());
            if !delimiter.is_empty() {
                without_prefix += usize::from(
                    !body["prefixes"]
                        .as_array()
                        .is_some_and(|p| p.iter().any(|v| v == "d00/")),
                );
            }
        }
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();
        assert_eq!(
            without_token, 0,
            "pages that lost the token ({delimiter:?})"
        );
        assert_eq!(without_prefix, 0, "pages that lost d00/ ({delimiter:?})");
    }
}

/// Deletes `names` from the bucket of `state` (what a client does between the scan of a glob listing
/// and the page it makes).
fn delete_names(state: &StorageState, names: &[&str]) {
    let bucket = BucketName::try_new(BUCKET).unwrap();
    for name in names {
        let _ = state.store.lock().unwrap().delete(
            &bucket,
            &ObjectName::try_new(*name).unwrap(),
            Precondition::default(),
        );
    }
}

/// The page of a glob listing with `delete` run between the scan and the page.
fn glob_page_after(
    state: &StorageState,
    glob: &str,
    delimiter: &str,
    max: usize,
    delete: &[&str],
) -> fireemu_core_storage::store::ListPage {
    use fireemu_adapter_http::storage::{glob_page, GlobQuery};
    let bucket = BucketName::try_new(BUCKET).unwrap();
    let glob = fireemu_core_storage::glob::Glob::new(glob);
    let anything = |_: &str| true;
    glob_page(
        state,
        &bucket,
        &GlobQuery {
            prefix: "",
            delimiter,
            token: None,
            max,
            glob: &glob,
            in_offsets: &anything,
        },
        &|| delete_names(state, delete),
    )
    .unwrap()
}

/// The three ways a deletion between the scan and the page used to end a listing early (found by
/// the reviews of round 3): the name that stood for a folded prefix, the entry after the page, and
/// an item of the page itself.
#[test]
fn a_name_deleted_between_the_scan_and_the_page_neither_ends_the_listing_nor_hides_a_prefix() {
    let state = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    let mut names: Vec<String> = (0..300).map(|n| format!("a/{n:03}")).collect();
    names.push("z".to_owned());
    put_names(&state, &names);
    // `a/000` stood for the prefix `a/`; its 299 siblings remain.
    let page = glob_page_after(&state, "**", "/", 1, &["a/000"]);
    assert_eq!(page.prefixes, ["a/"]);
    assert_eq!(page.next_page_token.as_deref(), Some("z"));

    let state = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    put_names(&state, &["a".to_owned(), "b".to_owned(), "c".to_owned()]);
    // `b` was the entry after the page of one: it leaves nothing behind, and `c` is still next.
    let page = glob_page_after(&state, "**", "", 1, &["b"]);
    assert_eq!(
        page.items
            .iter()
            .map(|m| m.name.as_str())
            .collect::<Vec<_>>(),
        ["a"]
    );
    assert_eq!(page.next_page_token.as_deref(), Some("b"));

    let state = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    let names: Vec<String> = (0..2_000).map(|n| format!("a/{n:05}.txt")).collect();
    put_names(&state, &names);
    // An item of the page itself is gone: the page shows the nine that remain and the token stays.
    let page = glob_page_after(&state, "**", "", 10, &["a/00005.txt"]);
    assert_eq!(page.items.len(), 9);
    assert!(page.items.iter().all(|m| m.name.as_str() != "a/00005.txt"));
    assert_eq!(page.next_page_token.as_deref(), Some("a/00010.txt"));
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(200))]


    /// For any names, glob, delimiter and page size, a page made while a subset of its names is
    /// deleted is the page of the store before the deletion minus the deleted items: the same
    /// prefixes and the same next-page token, whatever was deleted.
    #[test]
    fn a_glob_page_made_during_deletions_is_the_page_before_them_minus_the_deleted_items(
        leaves in proptest::collection::btree_set(
            proptest::collection::vec(proptest::sample::select(vec!["a", "b", "c", "x.txt", "y.bin"]), 1..=3)
                .prop_map(|parts| parts.join("/")),
            1..=30,
        ),
        glob in proptest::sample::select(vec!["**", "*", "a/**", "**.txt", "{a,b}/*", "*/*"]),
        delimiter in proptest::sample::select(vec!["", "/"]),
        max in 1usize..=4,
        doomed in proptest::collection::vec(0usize..30, 0..=8),
    ) {
        // A name cannot be both an object and a prefix of another in the listing's folding, but the
        // store allows it; the reference below uses the same store, so it holds either way.
        let state = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
        let names: Vec<String> = leaves.iter().cloned().collect();
        put_names(&state, &names);
        let bucket = BucketName::try_new(BUCKET).unwrap();
        let matcher = fireemu_core_storage::glob::Glob::new(glob);
        let expected = state.store.lock().unwrap().list_matching(
            &bucket, "", Some(delimiter), None, Some(max), &|name| matcher.matches(name),
        );
        let deleted: Vec<&str> = doomed.iter().filter_map(|i| names.get(*i).map(String::as_str)).collect();
        let page = glob_page_after(&state, glob, delimiter, max, &deleted);
        proptest::prop_assert_eq!(&page.prefixes, &expected.prefixes);
        proptest::prop_assert_eq!(&page.next_page_token, &expected.next_page_token);
        let want: Vec<&str> = expected.items.iter().map(|m| m.name.as_str()).filter(|n| !deleted.contains(n)).collect();
        let got: Vec<&str> = page.items.iter().map(|m| m.name.as_str()).collect();
        proptest::prop_assert_eq!(got, want);
    }
}

/// Only a list that evaluates a glob goes through the slots of its own: strict, the Google-fronted
/// list route, a GET that carries `matchGlob`. The emulator profile ignores the parameter, and a
/// read or a Firebase list that carries it evaluates nothing.
#[test]
fn only_a_strict_json_api_list_with_a_match_glob_is_admitted_through_the_glob_slots() {
    use fireemu_adapter_http::storage::uses_match_glob;
    let list = format!("/storage/v1/b/{BUCKET}/o");
    assert!(uses_match_glob(true, "GET", &list, "matchGlob=%2A%2A"));
    assert!(uses_match_glob(
        true,
        "GET",
        &format!("/b/{BUCKET}/o"),
        "prefix=a&matchGlob=a"
    ));
    assert!(!uses_match_glob(false, "GET", &list, "matchGlob=%2A%2A"));
    assert!(!uses_match_glob(true, "GET", &list, "prefix=a"));
    assert!(!uses_match_glob(true, "POST", &list, "matchGlob=a"));
    assert!(!uses_match_glob(
        true,
        "GET",
        &format!("/v0/b/{BUCKET}/o"),
        "matchGlob=a"
    ));
    assert!(!uses_match_glob(
        true,
        "GET",
        &format!("{list}/object.txt"),
        "matchGlob=a"
    ));
    assert!(!uses_match_glob(
        true,
        "GET",
        &format!("/storage/v1/b/{BUCKET}"),
        "matchGlob=a"
    ));
}

/// How much of a large bucket a glob page reads and keeps: the names kept are one per entry of the
/// page (and the one past it), not one per name that matched, and the scan stops after the batch
/// that completes the page instead of walking the bucket.
#[test]
fn a_glob_page_reads_and_keeps_a_bounded_part_of_a_large_bucket() {
    use fireemu_adapter_http::storage::{glob_scan, GlobQuery, GLOB_BATCH};
    let state = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    let names: Vec<String> = (0..20_000).map(|n| format!("a/{n:05}.txt")).collect();
    put_names(&state, &names);
    let bucket = BucketName::try_new(BUCKET).unwrap();
    let all = fireemu_core_storage::glob::Glob::new("**");
    let none = fireemu_core_storage::glob::Glob::new("nothing*");
    let anything = |_: &str| true;
    let query = |delimiter, token, glob| GlobQuery {
        prefix: "",
        delimiter,
        token,
        max: 10,
        glob,
        in_offsets: &anything,
    };

    // A page of 10 items: 11 entries kept, and the scan ends inside the first batch.
    let scan = glob_scan(&state, &bucket, &query("", None, &all), None).unwrap();
    assert_eq!(scan.entries.len(), 11);
    assert_eq!(scan.until.as_deref(), Some(names[GLOB_BATCH - 1].as_str()));

    // With a delimiter every name folds into one entry: one entry kept for 20,000 matches, and the
    // scan has to read them all to know there is no second entry.
    let scan = glob_scan(&state, &bucket, &query("/", None, &all), None).unwrap();
    assert_eq!(scan.entries.len(), 1);
    assert_eq!(
        (scan.entries[0].key.as_str(), scan.entries[0].is_item),
        ("a/", false)
    );
    assert_eq!(scan.until.as_deref(), Some(names[19_999].as_str()));

    // From a token the scan starts there: the first entry it finds is the token's.
    let token = names[10_000].clone();
    let scan = glob_scan(
        &state,
        &bucket,
        &query("", Some(&token), &all),
        Some(&token),
    )
    .unwrap();
    assert_eq!(
        scan.entries.first().map(|e| e.key.as_str()),
        Some(token.as_str())
    );
    assert_eq!(scan.entries.len(), 11);
    assert_eq!(
        scan.until.as_deref(),
        Some(names[10_000 + GLOB_BATCH - 1].as_str())
    );

    // A glob nothing matches keeps nothing, whatever the bucket size.
    let scan = glob_scan(&state, &bucket, &query("", None, &none), None).unwrap();
    assert!(scan.entries.is_empty());
}

/// A flood of list requests that carry an expensive `matchGlob` (more than the handler slots, each
/// working through many long names) leaves the other requests their slots: a plain read answers
/// promptly while they run, and they wait for their own two slots without holding a thread.
#[tokio::test]
async fn a_flood_of_expensive_glob_lists_leaves_the_handler_slots_to_other_requests() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    static BUDGET: BodyBudget = BodyBudget::new(1_572_864);
    let state = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    let mut names: Vec<String> = (0..40)
        .map(|n| format!("{n:03}{}", "x".repeat(990)))
        .collect();
    names.push("plain.txt".to_owned());
    put_names(&state, &names);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_storage_with_budget(
        listener,
        Arc::new(state),
        &BUDGET,
    ));
    // Every byte of the pattern percent-encoded: about 18,000 characters of query.
    let pattern: String =
        format!("{}z", "*{,}".repeat(1_500))
            .bytes()
            .fold(String::new(), |mut out, byte| {
                use std::fmt::Write as _;
                let _ = write!(out, "%{byte:02X}");
                out
            });
    let mut flood = Vec::new();
    for _ in 0..24 {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                format!("GET /storage/v1/b/{BUCKET}/o?matchGlob={pattern} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer owner\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        flood.push(stream);
    }
    // Let the flood reach the server and start working.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let started = std::time::Instant::now();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!("GET /storage/v1/b/{BUCKET}/o/plain.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer owner\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut raw),
    )
    .await
    .expect("a plain read waited for the flood")
    .unwrap();
    assert!(String::from_utf8_lossy(&raw).starts_with("HTTP/1.1 200"));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    drop(flood);
    server.abort();
}

/// A glob list whose client has gone stops at the next name and gives its slot back: with both glob
/// slots held by expensive lists, a short glob list that waits behind them is answered soon after
/// the two clients disconnect, not when the abandoned scans would have ended.
#[tokio::test]
async fn an_abandoned_glob_scan_gives_its_slot_back_when_its_client_has_gone() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    static BUDGET: BodyBudget = BodyBudget::new(1_572_864);
    let state = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    let mut names: Vec<String> = (0..12)
        .map(|n| format!("{n:03}{}", "x".repeat(990)))
        .collect();
    names.push("plain.txt".to_owned());
    put_names(&state, &names);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_storage_with_budget(
        listener,
        Arc::new(state),
        &BUDGET,
    ));
    let pattern: String =
        format!("{}z", "*{,}".repeat(3_000))
            .bytes()
            .fold(String::new(), |mut out, byte| {
                use std::fmt::Write as _;
                let _ = write!(out, "%{byte:02X}");
                out
            });
    // A browser keeps its connection alive: the server learns of its going from the closed socket.
    let send = |query: String, close: &'static str| async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                format!("GET /storage/v1/b/{BUCKET}/o?{query} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer owner\r\n{close}\r\n").as_bytes(),
            )
            .await
            .unwrap();
        stream
    };
    let hostile = vec![
        send(format!("matchGlob={pattern}"), "").await,
        send(format!("matchGlob={pattern}"), "").await,
    ];
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let mut waiting = send("matchGlob=plain.%2A".to_owned(), "Connection: close\r\n").await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let started = std::time::Instant::now();
    drop(hostile);
    let mut raw = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        waiting.read_to_end(&mut raw),
    )
    .await
    .expect("the glob list waited for scans whose clients had gone")
    .unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("plain.txt"), "{text}");
    println!("answered {:?} after the clients left", started.elapsed());
    server.abort();
}

/// An unauthenticated list can carry any `matchGlob`: a pathological one is answered on a thread
/// with a blocking-pool sized stack, and a second request is not held up while it is evaluated.
#[test]
fn a_pathological_match_glob_neither_overflows_the_stack_nor_blocks_other_requests() {
    let s = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    for name in ["a.txt", "b.txt", "dir/c.txt"] {
        let uploaded = handle(
            &s,
            req(
                "POST",
                &format!(
                    "/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name={}",
                    name.replace('/', "%2F")
                ),
                &[("authorization", "Bearer owner")],
                b"x",
            ),
        );
        assert_eq!(uploaded.status, 200);
    }
    let encode = |pattern: &str| -> String {
        pattern.bytes().fold(String::new(), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "%{byte:02X}");
            out
        })
    };
    let patterns = [
        "{".repeat(40),
        format!("{}z", "{,}".repeat(2_000)),
        format!("**{}", "*a".repeat(2_000)),
        "{a,".repeat(30_000),
        format!("{}x{}", "{a,".repeat(30_000), "}".repeat(30_000)),
        "[".repeat(30_000),
    ];
    let listing = |pattern: &str| {
        handle(
            &s,
            req(
                "GET",
                &format!("/storage/v1/b/{BUCKET}/o?matchGlob={}", encode(pattern)),
                &[("authorization", "Bearer owner")],
                b"",
            ),
        )
    };
    std::thread::scope(|scope| {
        let hostile = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn_scoped(scope, || {
                for pattern in &patterns {
                    assert_eq!(listing(pattern).status, 200);
                }
            })
            .unwrap();
        while !hostile.is_finished() {
            let started = std::time::Instant::now();
            let read = handle(
                &s,
                req(
                    "GET",
                    &format!("/storage/v1/b/{BUCKET}/o/a.txt"),
                    &[("authorization", "Bearer owner")],
                    b"",
                ),
            );
            assert_eq!(read.status, 200);
            assert!(started.elapsed() < std::time::Duration::from_secs(2));
        }
        hostile.join().unwrap();
    });
}

/// The three list filters under strict, as lean-v5 recorded them (`startOffset=b.txt` with
/// `endOffset=zz.txt`, and the glob `dir/*`); the emulator profile and the official emulator
/// ignore all of them (measured: the whole listing).
#[test]
fn strict_json_list_filters_follow_the_recorded_rows() {
    let names = [
        "a.txt",
        "b.txt",
        "dir/c.txt",
        "dir/d.txt",
        "dir2/e.txt",
        "zz.txt",
    ];
    for acceptance in BOTH_PROFILES {
        let s = state_with(Some(ALLOW_ALL_RULES), acceptance);
        for name in names {
            let uploaded = handle(
                &s,
                req(
                    "POST",
                    &format!(
                        "/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name={}",
                        name.replace('/', "%2F")
                    ),
                    &[("authorization", "Bearer owner")],
                    b"x",
                ),
            );
            assert_eq!(uploaded.status, 200);
        }
        let listed = |query: &str| -> Vec<String> {
            let r = handle(
                &s,
                req(
                    "GET",
                    &format!("/storage/v1/b/{BUCKET}/o?{query}"),
                    &[("authorization", "Bearer owner")],
                    b"",
                ),
            );
            assert_eq!(r.status, 200, "{acceptance:?} {query}");
            json_body(&r)["items"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .map(|i| i["name"].as_str().unwrap().to_owned())
                        .collect()
                })
                .unwrap_or_default()
        };
        let all: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
        let strict = acceptance == TokenAcceptance::Verified;
        let expect = |filtered: &[&str]| -> Vec<String> {
            if strict {
                filtered.iter().map(|n| (*n).to_owned()).collect()
            } else {
                all.clone()
            }
        };
        assert_eq!(
            listed("startOffset=b.txt&endOffset=zz.txt"),
            expect(&["b.txt", "dir/c.txt", "dir/d.txt", "dir2/e.txt"]),
            "{acceptance:?}"
        );
        assert_eq!(
            listed("matchGlob=dir%2F*"),
            expect(&["dir/c.txt", "dir/d.txt"]),
            "{acceptance:?}"
        );
        assert_eq!(listed("matchGlob=**.txt"), all, "{acceptance:?}");
        assert_eq!(
            listed("matchGlob=*.txt"),
            expect(&["a.txt", "b.txt", "zz.txt"])
        );
        // A prefix appears only when a matching object lies under it.
        let r = handle(
            &s,
            req(
                "GET",
                &format!("/storage/v1/b/{BUCKET}/o?delimiter=%2F&matchGlob=dir2%2F*"),
                &[("authorization", "Bearer owner")],
                b"",
            ),
        );
        assert_eq!(
            json_body(&r)["prefixes"],
            if strict {
                json!(["dir2/"])
            } else {
                json!(["dir/", "dir2/"])
            }
        );
    }
}

/// Production numbers: strict draws generations as microsecond timestamps that never repeat, never
/// run backwards and give the production etag; a minted token is listed first; the emulator profile
/// keeps counting from 1 and appending (the official emulator draws epoch milliseconds).
#[test]
fn strict_generations_are_timestamps_and_tokens_are_newest_first() {
    for (acceptance, s) in seeded_pair() {
        let strict = acceptance == TokenAcceptance::Verified;
        let owner = [("authorization", "Bearer owner")];
        let first = json_body(&handle(
            &s,
            req(
                "GET",
                &format!("/storage/v1/b/{BUCKET}/o/g.bin"),
                &owner,
                b"",
            ),
        ));
        let again = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=g.bin"),
                &[owner[0], ("content-type", "text/plain")],
                b"second",
            ),
        );
        let second = json_body(&again);
        let (g1, g2) = (
            first["generation"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap(),
            second["generation"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap(),
        );
        assert!(g2 > g1, "{acceptance:?}: {g1} then {g2}");
        if strict {
            assert!(g1 >= 1_788_004_860_000_000, "a microsecond timestamp: {g1}");
            assert_eq!(second["etag"], production_etag_text(g2, 1));
        } else {
            assert!(g1 < 1_000, "a counter: {g1}");
        }
        // Two minted tokens: the newer one first under strict.
        let mint = |n: u8| {
            let _ = n;
            handle(
                &s,
                req(
                    "POST",
                    &format!("/v0/b/{BUCKET}/o/g.bin?create_token=true"),
                    &owner,
                    b"",
                ),
            )
        };
        let first_token = json_body(&mint(1))["downloadTokens"]
            .as_str()
            .unwrap()
            .to_owned();
        let tokens = json_body(&mint(2))["downloadTokens"]
            .as_str()
            .unwrap()
            .to_owned();
        let listed: Vec<&str> = tokens.split(',').collect();
        assert_eq!(listed.len(), 2, "{acceptance:?}");
        if strict {
            assert_eq!(listed[1], first_token, "the older token is last");
        } else {
            assert_eq!(listed[0], first_token, "the older token stays first");
        }
    }
}

/// The recorded checksums of a JSON API 308 under strict: `x-goog-running-hash` and `x-range-md5`
/// of the bytes the session holds (lean-v5: 262,144 bytes of 0x5A give md5 `fc47c91a...` and crc32c
/// `PjCw/w==`).
#[test]
fn strict_resumable_308_carries_the_running_checksums() {
    let s = state_with(Some(ALLOW_ALL_RULES), TokenAcceptance::Verified);
    let owner = [("authorization", "Bearer owner")];
    let start = handle(
        &s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=r.bin"),
            &[owner[0], ("content-type", "application/json")],
            b"{}",
        ),
    );
    let session = header(&start, "location")
        .unwrap()
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap()
        .to_owned();
    let chunk = vec![90u8; 262_144];
    let sent = handle(
        &s,
        req(
            "PUT",
            &session,
            &[owner[0], ("content-range", "bytes 0-262143/262147")],
            &chunk,
        ),
    );
    assert_eq!(sent.status, 308);
    assert_eq!(header(&sent, "range"), Some("bytes=0-262143"));
    assert_eq!(
        header(&sent, "x-range-md5"),
        Some("fc47c91acf3074fb684c73ef7584605f")
    );
    assert_eq!(
        header(&sent, "x-goog-running-hash"),
        Some("crc32c=PjCw/w==")
    );
    let query = handle(
        &s,
        req(
            "PUT",
            &session,
            &[owner[0], ("content-range", "bytes */262147")],
            b"",
        ),
    );
    assert_eq!(
        header(&query, "x-range-md5"),
        Some("fc47c91acf3074fb684c73ef7584605f")
    );
}

/// Production's etag text, computed here from the recorded vectors rather than by the code under
/// test: the protobuf of generation and metageneration in base64 (the recorded
/// `CNGTm8DplpcDEAI=` is checked in the module's own tests; this one uses a small value).
fn production_etag_text(generation: u64, metageneration: u64) -> String {
    let mut bytes = vec![0x08];
    let mut value = generation;
    while value >= 0x80 {
        bytes.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
        value >>= 7;
    }
    bytes.push(u8::try_from(value).unwrap());
    bytes.push(0x10);
    bytes.push(u8::try_from(metageneration).unwrap());
    fireemu_core_storage::hash::base64(&bytes)
}

// ------------------------------------------------------------------------------------------
// the rows mutation testing showed the first tests did not pin
// ------------------------------------------------------------------------------------------

/// Reads that production serves to an end user are private; the owner's are not; lists carry their
/// own header sets (recorded, lean-v5).
#[test]
fn strict_header_sets_follow_the_kind_of_read() {
    let (_, strict) = &seeded_pair()[0];
    let owner = [("authorization", "Bearer owner")];
    // A JSON API list and a Firebase list.
    let list = handle(
        strict,
        req("GET", &format!("/storage/v1/b/{BUCKET}/o"), &owner, b""),
    );
    assert_eq!(
        header_names(&list),
        ["cache-control", "content-type", "expires", "vary"]
    );
    assert_eq!(
        header(&list, "cache-control"),
        Some("private, max-age=0, must-revalidate, no-transform")
    );
    let v0_list = handle(
        strict,
        req("GET", &format!("/v0/b/{BUCKET}/o"), &owner, b""),
    );
    assert_eq!(
        header(&v0_list, "cache-control"),
        Some("private, max-age=0")
    );
    assert_eq!(header(&v0_list, "access-control-allow-origin"), Some("*"));
    // A v0 media read: the owner's is no-cache, a download-token read is private.
    let object = format!("/v0/b/{BUCKET}/o/g.bin");
    let meta = json_body(&handle(strict, req("GET", &object, &owner, b"")));
    let token = meta["downloadTokens"].as_str().unwrap().to_owned();
    let by_owner = handle(
        strict,
        req("GET", &format!("{object}?alt=media"), &owner, b""),
    );
    assert_eq!(
        header(&by_owner, "cache-control"),
        Some("no-cache, no-store, max-age=0, must-revalidate")
    );
    assert!(header(&by_owner, "pragma").is_some());
    let by_token = handle(
        strict,
        req(
            "GET",
            &format!("{object}?alt=media&token={token}"),
            &[],
            b"",
        ),
    );
    assert_eq!(by_token.status, 200);
    assert_eq!(
        header(&by_token, "cache-control"),
        Some("private, max-age=0")
    );
    assert_eq!(header(&by_token, "pragma"), None);
    // A media read of an absent v0 object is a JSON 404 with CORS and a private cache.
    let absent = handle(
        strict,
        req(
            "GET",
            &format!("/v0/b/{BUCKET}/o/absent.bin?alt=media"),
            &owner,
            b"",
        ),
    );
    assert_eq!(absent.status, 404);
    assert_eq!(header(&absent, "access-control-allow-origin"), Some("*"));
    assert_eq!(header(&absent, "cache-control"), Some("private, max-age=0"));
}

/// Partial JSON API answers carry no checksum of the whole object, the empty one the checksum of
/// no bytes alone, and the Firebase dialect keeps its checksum (recorded, lean-v5).
#[test]
fn strict_partial_answers_carry_the_recorded_checksums() {
    let (_, strict) = &seeded_pair()[0];
    let owner = [("authorization", "Bearer owner")];
    let partial = handle(
        strict,
        req(
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/g.bin?alt=media"),
            &[owner[0], ("range", "bytes=0-2")],
            b"",
        ),
    );
    assert_eq!(partial.status, 206);
    assert_eq!(header(&partial, "content-range"), Some("bytes 0-2/5"));
    assert_eq!(header(&partial, "x-goog-hash"), None);
    let v0 = handle(
        strict,
        req(
            "GET",
            &format!("/v0/b/{BUCKET}/o/g.bin?alt=media"),
            &[owner[0], ("range", "bytes=0-2")],
            b"",
        ),
    );
    assert_eq!(v0.status, 206);
    assert!(header(&v0, "x-goog-hash").unwrap().contains(", md5="));
    // The empty object and a nonzero suffix.
    let empty = handle(
        strict,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=e.bin"),
            &owner,
            b"",
        ),
    );
    assert_eq!(empty.status, 200);
    let suffix = handle(
        strict,
        req(
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/e.bin?alt=media"),
            &[owner[0], ("range", "bytes=-2")],
            b"",
        ),
    );
    assert_eq!(suffix.status, 206);
    assert_eq!(header(&suffix, "x-goog-hash"), Some("crc32c=AAAAAA=="));
}

/// The name length limit is 1,024 bytes: such a name uploads and reads back on every route and in
/// both profiles; one byte more is refused on upload (strict: production's words) and a 404 on read.
#[test]
fn a_name_of_exactly_the_limit_is_an_ordinary_object() {
    let name = "n".repeat(1024);
    for (acceptance, s) in seeded_pair() {
        let owner = [("authorization", "Bearer owner")];
        let uploaded = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name={name}"),
                &owner,
                b"x",
            ),
        );
        assert_eq!(uploaded.status, 200, "{acceptance:?}");
        for path in [
            format!("/storage/v1/b/{BUCKET}/o/{name}"),
            format!("/storage/v1/b/{BUCKET}/o/{name}?alt=media"),
            format!("/v0/b/{BUCKET}/o/{name}"),
            format!("/v0/b/{BUCKET}/o/{name}?alt=media"),
        ] {
            let read = handle(&s, req("GET", &path, &owner, b""));
            assert_eq!(
                read.status,
                200,
                "{acceptance:?} {}",
                &path[path.len() - 20..]
            );
        }
        let too_long = format!("{name}n");
        let refused = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name={too_long}"),
                &owner,
                b"x",
            ),
        );
        assert_eq!(refused.status, 400, "{acceptance:?}");
    }
}

/// A multipart boundary of 70 characters is accepted and one of 71 refused, on both dialects.
#[test]
fn a_multipart_boundary_is_limited_to_seventy_characters() {
    for (acceptance, s) in seeded_pair() {
        let owner = [("authorization", "Bearer owner")];
        let send = |boundary: &str, route: String, protocol: Option<&str>| {
            let body = format!(
                "--{boundary}\r\nContent-Type: application/json\r\n\r\n{{}}\r\n--{boundary}\r\nContent-Type: text/plain\r\n\r\nhello\r\n--{boundary}--"
            );
            let content_type = format!("multipart/related; boundary={boundary}");
            let mut headers = vec![owner[0], ("content-type", content_type.as_str())];
            if let Some(protocol) = protocol {
                headers.push(("x-goog-upload-protocol", protocol));
            }
            handle(&s, req("POST", &route, &headers, body.as_bytes())).status
        };
        let ok = "b".repeat(70);
        let long = "b".repeat(71);
        for (route, protocol) in [
            (
                format!("/v0/b/{BUCKET}/o?name=m70.txt&uploadType=multipart"),
                Some("multipart"),
            ),
            (
                format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=multipart&name=m70.txt"),
                None,
            ),
        ] {
            assert_eq!(
                send(&ok, route.clone(), protocol),
                200,
                "{acceptance:?} {route}"
            );
            assert_eq!(
                send(&long, route.clone(), protocol),
                400,
                "{acceptance:?} {route}"
            );
        }
    }
}

/// The JSON API's refusals of a multipart body: strict says `invalidPayloadSize` with the part
/// count, and the one recorded malformed metadata part has its parser message; the emulator
/// profile answers the official emulator's own JSON for both.
#[test]
fn json_api_multipart_refusals_differ_between_the_profiles() {
    for (acceptance, s) in seeded_pair() {
        let strict = acceptance == TokenAcceptance::Verified;
        let owner = [("authorization", "Bearer owner")];
        let route = format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=multipart&name=m.bin");
        let send = |metadata: &str| {
            let body = format!(
                "--b\r\nContent-Type: application/json\r\n\r\n{metadata}\r\n--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b--"
            );
            handle(
                &s,
                req(
                    "POST",
                    &route,
                    &[owner[0], ("content-type", "multipart/related; boundary=b")],
                    body.as_bytes(),
                ),
            )
        };
        // One part only.
        let one_part = handle(
            &s,
            req(
                "POST",
                &route,
                &[owner[0], ("content-type", "multipart/related; boundary=b")],
                b"--b\r\nContent-Type: application/json\r\n\r\n{}\r\n--b--",
            ),
        );
        assert_eq!(one_part.status, 400, "{acceptance:?}");
        let message = json_body(&one_part)["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned();
        if strict {
            assert_eq!(
                message,
                "Payload size invalid. Expected 2-3 payloads. Actual size: 1"
            );
            assert_eq!(
                json_body(&one_part)["error"]["errors"][0]["reason"],
                "invalidPayloadSize"
            );
        } else {
            assert_eq!(message, "Unexpected number of parts in request body");
        }
        // The recorded malformed metadata part.
        let recorded = send("{invalid-json");
        assert_eq!(recorded.status, 400);
        assert_eq!(
            header(&recorded, "content-type") == Some("text/html; charset=UTF-8"),
            strict,
            "{acceptance:?}"
        );
        // Shapes that were not recorded keep the generic answer in both profiles.
        for other in ["{", "{a b", "{\"a\":", "{a\"b", "[1"] {
            let generic = send(other);
            assert_eq!(generic.status, 400);
            assert!(
                !String::from_utf8_lossy(&generic.body).contains("between key:value pair"),
                "{acceptance:?} {other}"
            );
        }
        // A word with an underscore and digits is a bare word too (strict only).
        let wordy = send("{a_b-1");
        assert_eq!(
            String::from_utf8_lossy(&wordy.body).contains(r"a_b-1\n"),
            strict,
            "{acceptance:?}"
        );
    }
}

/// A chunk at the wrong offset: strict says production's text, the emulator profile the official
/// emulator's JSON error; the 308 of a JSON API session names its running checksums only under
/// strict and only once a byte is held.
#[test]
fn resumable_offsets_and_308_checksums_differ_between_the_profiles() {
    for (acceptance, s) in seeded_pair() {
        let strict = acceptance == TokenAcceptance::Verified;
        let owner = [("authorization", "Bearer owner")];
        // Firebase dialect: a chunk at offset 1 of an empty session.
        let start = handle(
            &s,
            req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=o.bin"),
                &[
                    owner[0],
                    ("x-goog-upload-protocol", "resumable"),
                    ("x-goog-upload-command", "start"),
                    ("content-type", "application/json"),
                ],
                br#"{"name":"o.bin"}"#,
            ),
        );
        let url = header(&start, "x-goog-upload-url").unwrap().to_owned();
        let session = url
            .split_once("/v0/")
            .map(|(_, rest)| format!("/v0/{rest}"))
            .unwrap();
        let wrong = handle(
            &s,
            req(
                "POST",
                &session,
                &[
                    owner[0],
                    ("x-goog-upload-protocol", "resumable"),
                    ("x-goog-upload-command", "upload"),
                    ("x-goog-upload-offset", "1"),
                ],
                b"x",
            ),
        );
        assert_eq!(wrong.status, 400);
        assert_eq!(
            header(&wrong, "content-type") == Some("text/plain; charset=utf-8"),
            strict,
            "{acceptance:?}"
        );
        // JSON API session: a status query before any chunk, then after one.
        let gstart = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=q.bin"),
                &[owner[0], ("content-type", "application/json")],
                b"{}",
            ),
        );
        let gsession = header(&gstart, "location")
            .unwrap()
            .strip_prefix("http://127.0.0.1:9199")
            .unwrap()
            .to_owned();
        let before = handle(
            &s,
            req(
                "PUT",
                &gsession,
                &[owner[0], ("content-range", "bytes */10")],
                b"",
            ),
        );
        assert_eq!(before.status, 308);
        assert_eq!(
            header(&before, "x-range-md5"),
            None,
            "{acceptance:?}: nothing is held yet"
        );
        assert_eq!(header(&before, "range"), None);
        let chunk = handle(
            &s,
            req(
                "PUT",
                &gsession,
                &[owner[0], ("content-range", "bytes 0-4/10")],
                b"hello",
            ),
        );
        assert_eq!(chunk.status, 308);
        assert_eq!(
            header(&chunk, "x-range-md5").is_some(),
            strict,
            "{acceptance:?}"
        );
        assert_eq!(
            header(&chunk, "x-goog-running-hash").is_some(),
            strict,
            "{acceptance:?}"
        );
    }
}
