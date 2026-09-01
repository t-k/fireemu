//! Storage surface at the handler level: both protocol dialects, uploads, downloads with
//! tokens and ranges, listing, metadata, rewrite and Storage Rules.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_http::storage::{handle, StorageRequest, StorageState};
use fireemu_adapter_http::storage_server::{
    serve_storage_with_budget, BodyBudget, MAX_STORAGE_BODY_BYTES,
};
use fireemu_core_auth::jwt::{base64url_encode, TokenAcceptance};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, NewUser};
use fireemu_core_rules::runtime::LoadedRules;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::StorageState as ObjectStore;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const BUCKET: &str = "demo-app.appspot.com";

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
        rules: Arc::new(RwLock::new(rules.map_or_else(LoadedRules::default, |r| {
            LoadedRules::from_source(r).unwrap()
        }))),
        project: "demo-app".to_owned(),
        events: None,
        barrier: None,
        firestore: None,
        faults: None,
        clock_observer: None,
        app_check_policy: None,
        admin_capability: None,
        token_acceptance,
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
    assert_eq!(json_body(&r)["generation"], "1");
    let r = handle(
        &s,
        req(
            "GET",
            &format!("/v0/b/{BUCKET}/o/{enc}?alt=media&token={token}"),
            &[],
            b"",
        ),
    );
    assert_eq!((r.status, r.body.as_slice()), (200, &b"PNGDATA"[..]));
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
    assert_eq!((r.status, r.body.as_slice()), (206, &b"NGD"[..]));
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
        (Some("1"), Some("2"))
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
    // The official Firebase dialect answers a missing object with a bare status text.
    assert_eq!(r.status, 404);
    assert_eq!(r.body, b"Not Found");
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
    assert_eq!(r.body, b"abcdef");
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
    assert_eq!(r.body, b"hello");
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
    // Copy routes exist only on the short /b/... spelling, as the official emulator
    // registers them; the /storage/v1 spelling is its 501 catch-all.
    assert_eq!(
        handle(
            &s,
            req(
                "POST",
                &format!("/storage/v1/b/{BUCKET}/o/a%2Fb.txt/rewriteTo/b/{BUCKET}/o/copy.txt"),
                &owner,
                b"",
            ),
        )
        .status,
        501
    );
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
fn rules_unit_testing_set_rules_rejects_invalid_updates_without_replacing_rules() {
    const DENY_ALL: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if false; } } }";
    const ALLOW_ALL: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if true; } } }";
    let cases = [
        ("empty body", Vec::new()),
        ("malformed JSON", b"{".to_vec()),
        ("JSON null", b"null".to_vec()),
        ("missing rules", br#"{}"#.to_vec()),
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
    // The denial body is the official emulator's fixed envelope.
    assert_eq!(
        json_body(&r)["error"]["message"],
        "Permission denied. No WRITE permission."
    );
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
    // Admin credentials bypass the rules; a forged token is unauthenticated.
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
        401
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
    assert_eq!((r.status, r.body.as_slice()), (200, &b"whole object"[..]));
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
    // Malformed preconditions are errors, not ignored.
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
    assert_eq!(json_body(&r)["error"]["errors"][0]["reason"], "invalid");
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
    assert_eq!(r.status, 412, "{}", String::from_utf8_lossy(&r.body));
    let err = json_body(&r);
    assert_eq!(err["error"]["errors"][0]["reason"], "conditionNotMet");
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("ifGenerationNotMatch"));
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
    assert_eq!((r.status, r.body.as_slice()), (206, &b"789"[..]));
    assert_eq!(header(&r, "content-range"), Some("bytes 7-9/10"));
    let r = get("bytes=8-");
    assert_eq!((r.status, r.body.as_slice()), (206, &b"89"[..]));
    let r = get("bytes=2-4");
    assert_eq!((r.status, r.body.as_slice()), (206, &b"234"[..]));
    // An unsatisfiable range is ignored and the whole object served, as the official
    // emulator (express `req.range` answering -1) serves it.
    let r = get("bytes=10-");
    assert_eq!((r.status, r.body.as_slice()), (200, &b"0123456789"[..]));
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
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
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
    // The JSON API is the privileged dialect: rules never run on it, and the copy routes
    // exist only on the short /b/... spelling (the long one is the official 501 catch-all).
    let r = handle(
        &s,
        req(
            "POST",
            &format!("/storage/v1/b/{BUCKET}/o/open%2Fsrc/rewriteTo/b/{BUCKET}/o/open%2Fdst"),
            &[],
            b"",
        ),
    );
    assert_eq!(r.status, 501);
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
    let mut s = state(None);
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
    // any rule runs.
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
        assert_eq!(r.status, 401, "{}", String::from_utf8_lossy(&r.body));
        assert!(String::from_utf8_lossy(&r.body).contains("audience"));
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

const OWNED_STORAGE_RULES: &str = "rules_version = '2';\nservice firebase.storage { match /b/{bucket}/o { match /owned/{uid}/{file=**} { allow read, write: if request.auth != null && request.auth.uid == uid; } } }";

fn upload_as(s: &StorageState, path: &str, authorization: &str) -> u16 {
    handle(
        s,
        req(
            "POST",
            &format!(
                "/v0/b/{BUCKET}/o?name={}&uploadType=media",
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
        "the firebase profile builds request.auth from the mock token, as the official emulator does"
    );
    assert_eq!(
        upload_as(&firebase, "owned/bob/x.txt", &bearer),
        403,
        "and the rule, not the token, is what refuses another subject's prefix"
    );
    // The audience binding survives the profile: a token minted for another project is not
    // an identity here even though the official emulator would accept it.
    let foreign = format!("Firebase {}", mock_user_token("alice", "demo-other"));
    assert_eq!(upload_as(&firebase, "owned/alice/y.txt", &foreign), 401);

    let strict = state_with(Some(OWNED_STORAGE_RULES), TokenAcceptance::Verified);
    assert_eq!(
        upload_as(&strict, "owned/alice/x.txt", &bearer),
        401,
        "under strict the token names no user of the Auth store, so the caller is refused"
    );
}

// ---- Security regressions (storage parity review) ------------------------------------

/// M-1: a missing object served through a media route must never be typed `text/html`, or
/// the reflected object name is a stored-data-stealing reflected-XSS vector on the emulator
/// origin (a top-level GET carries no Origin, so the loopback guard never fires). The body
/// still reflects the name, as the official emulator's does -- only the content-type differs.
#[test]
fn a_missing_media_object_never_answers_with_html() {
    let s = state(None);
    let evil = "a%3Cscript%3Ealert(1)%3C%2Fscript%3E.txt";
    // JSON API media read of a missing object.
    let r = handle(
        &s,
        req(
            "GET",
            &format!("/b/{BUCKET}/o/{evil}?alt=media"),
            &[("authorization", "Bearer owner")],
            b"",
        ),
    );
    assert_eq!(r.status, 404);
    assert!(
        !header(&r, "content-type")
            .unwrap_or("")
            .contains("text/html"),
        "media 404 must not be text/html: {:?}",
        header(&r, "content-type")
    );
    // The XML-style GET fallback reaches the same answer.
    let r = handle(
        &s,
        req("GET", &format!("/{BUCKET}/{evil}?alt=media"), &[], b""),
    );
    assert_eq!(r.status, 404);
    assert!(
        !header(&r, "content-type")
            .unwrap_or("")
            .contains("text/html"),
        "xml-style 404 must not be text/html: {:?}",
        header(&r, "content-type")
    );
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
    let shared = Arc::new(state(None));
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
