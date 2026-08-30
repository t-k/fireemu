//! Storage surface at the handler level: both protocol dialects, uploads, downloads with
//! tokens and ranges, listing, metadata, rewrite and Storage Rules.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use ftd_adapter_http::storage::{handle, StorageRequest, StorageState};
use ftd_core_auth::mfa::TotpPolicy;
use ftd_core_auth::store::{AuthStore, NewUser};
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_session::clock::VirtualClock;
use ftd_core_storage::store::StorageState as ObjectStore;
use ftd_core_types::determinism::SplitMix64;
use ftd_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const BUCKET: &str = "demo-app.appspot.com";

fn state(rules: Option<&str>) -> StorageState {
    StorageState {
        store: Mutex::new(ObjectStore::new(9)),
        clock: Arc::new(Mutex::new(VirtualClock::new(START))),
        auth: Arc::new(ftd_core_auth::store::AuthRegistry::new(
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
    }
}

fn req(
    method: &str,
    path_and_query: &str,
    headers: &[(&str, &str)],
    body: &[u8],
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
        body: body.to_vec(),
    }
}

fn json_body(r: &ftd_adapter_http::storage::StorageResponse) -> Value {
    serde_json::from_slice(&r.body).unwrap_or(Value::Null)
}

fn header<'a>(r: &'a ftd_adapter_http::storage::StorageResponse, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn multipart(meta: &Value, ct: &str, data: &[u8]) -> (String, Vec<u8>) {
    let boundary = "ftd-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{meta}\r\n--{boundary}\r\nContent-Type: {ct}\r\n\r\n").as_bytes());
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());
    (format!("multipart/related; boundary={boundary}"), body)
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
    let r = handle(&s, &req("POST", &format!("/v0/b/{BUCKET}/o?name=photos%2F%E8%AB%8B%E6%B1%82%E6%9B%B8.png&uploadType=multipart"), &[("authorization", "Bearer owner"), ("content-type", &ct), ("x-goog-upload-protocol", "multipart")], &body));
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
        &req("GET", &format!("/v0/b/{BUCKET}/o/{enc}"), &owner, b""),
    );
    assert_eq!(json_body(&r)["generation"], "1");
    let r = handle(
        &s,
        &req(
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
        &req(
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
        &req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=root.txt&uploadType=multipart"),
            &[("authorization", "Bearer owner"), ("content-type", &ct)],
            &multipart(&json!({}), "text/plain", b"r").1,
        ),
    );
    let r = handle(
        &s,
        &req(
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
        &req(
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
        &req("DELETE", &format!("/v0/b/{BUCKET}/o/{enc}"), &owner, b""),
    );
    assert_eq!(r.status, 204);
    let r = handle(
        &s,
        &req("GET", &format!("/v0/b/{BUCKET}/o/{enc}"), &owner, b""),
    );
    assert_eq!(r.status, 404);
    assert_eq!(json_body(&r)["error"]["status"], "NOT_FOUND");
}

#[test]
fn firebase_resumable_upload_protocol() {
    let s = state(None);
    let r = handle(
        &s,
        &req(
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
        &req(
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
    assert_eq!(header(&r, "x-goog-upload-size-received"), Some("3"));
    let r = handle(
        &s,
        &req(
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
        &req(
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
        &req(
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
    // Bucket metadata, multipart upload, media upload.
    assert_eq!(
        handle(
            &s,
            &req("GET", &format!("/storage/v1/b/{BUCKET}"), &owner, b"")
        )
        .status,
        200
    );
    let (ct, body) = multipart(
        &json!({"name": "a/b.txt", "contentType": "text/plain", "metadata": {"owner": "x"}}),
        "text/plain",
        b"hello",
    );
    let r = handle(
        &s,
        &req(
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
        &req(
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
        &req(
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
        &req(
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
        &req(
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
        &req(
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
        &req(
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
        &req(
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o?prefix=a/"),
            &owner,
            b"",
        ),
    );
    let listed = json_body(&r);
    assert_eq!(listed["kind"], "storage#objects");
    assert_eq!(listed["items"][0]["name"], "a/b.txt");
    let r = handle(
        &s,
        &req(
            "POST",
            &format!("/storage/v1/b/{BUCKET}/o/a%2Fb.txt/rewriteTo/b/{BUCKET}/o/copy.txt"),
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
        &req(
            "DELETE",
            &format!("/storage/v1/b/{BUCKET}/o/copy.txt?ifGenerationMatch=999"),
            &owner,
            b"",
        ),
    );
    assert_eq!(r.status, 412);
    let r = handle(
        &s,
        &req(
            "DELETE",
            &format!("/storage/v1/b/{BUCKET}/o/copy.txt"),
            &owner,
            b"",
        ),
    );
    assert_eq!(r.status, 204);
    let r = handle(
        &s,
        &req(
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
            ftd_core_auth::jwt::encode_unsigned(&claims),
        )
    };
    let firebase_auth = format!("Firebase {token}");
    let (ct, body) = multipart(&json!({"contentType": "text/plain"}), "text/plain", b"mine");
    // Own folder: allowed; someone else's folder: denied; anonymous: denied.
    let own = format!("/v0/b/{BUCKET}/o?name=users%2F{uid}%2Fnote.txt&uploadType=multipart");
    let r = handle(
        &s,
        &req(
            "POST",
            &own,
            &[("authorization", &firebase_auth), ("content-type", &ct)],
            &body,
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let other = format!("/v0/b/{BUCKET}/o?name=users%2Fsomeone%2Fnote.txt&uploadType=multipart");
    let r = handle(
        &s,
        &req(
            "POST",
            &other,
            &[("authorization", &firebase_auth), ("content-type", &ct)],
            &body,
        ),
    );
    assert_eq!(r.status, 403);
    assert_eq!(json_body(&r)["error"]["status"], "PERMISSION_DENIED");
    let r = handle(&s, &req("POST", &own, &[("content-type", &ct)], &body));
    assert_eq!(r.status, 403);
    // Reads: own object ok, without credentials denied, public readable, token bypass.
    let enc = format!("users%2F{uid}%2Fnote.txt");
    assert_eq!(
        handle(
            &s,
            &req(
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
            &req(
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
        &req(
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
            &req(
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
            &req("GET", &format!("/v0/b/{BUCKET}/o/public%2Fx"), &[], b"")
        )
        .status,
        404,
        "public read allowed, object missing"
    );
    // A listing of the own folder is allowed; the root is not.
    assert_eq!(
        handle(
            &s,
            &req(
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
            &req(
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
            &req(
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
            &req(
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
        &req(
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
        &req(
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
        &req(
            "GET",
            &format!("/b/{BUCKET}/o/stream.bin?alt=media"),
            &[],
            b"",
        ),
    );
    assert_eq!((r.status, r.body.as_slice()), (200, &b"whole object"[..]));
    let r = handle(
        &s,
        &req("GET", &format!("/b/{BUCKET}/o?prefix=stream"), &owner, b""),
    );
    assert_eq!(json_body(&r)["items"][0]["name"], "stream.bin");
    let r = handle(&s, &req("GET", &format!("/b/{BUCKET}"), &[], b""));
    assert_eq!(json_body(&r)["kind"], "storage#bucket");
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
        format!("Firebase {}", ftd_core_auth::jwt::encode_unsigned(&claims)),
    )
}

#[test]
fn multipart_payloads_keep_their_trailing_line_breaks() {
    let s = state(None);
    for data in [
        &b"line\n"[..],
        b"crlf\r\n",
        b"\r\n\r\n",
        b"--ftd-boundary-ish\r\n",
    ] {
        let (ct, body) = multipart(&json!({"name": "t.txt"}), "text/plain", data);
        let r = handle(
            &s,
            &req(
                "POST",
                &format!("/v0/b/{BUCKET}/o?uploadType=multipart"),
                &[("authorization", "Bearer owner"), ("content-type", &ct)],
                &body,
            ),
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(json_body(&r)["size"], data.len().to_string());
        let r = handle(
            &s,
            &req(
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
        &req(
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
        &req(
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
            &req(
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
        &req(
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
        &req(
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
        &req(
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
            &req(
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
        &req(
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
        &req(
            "POST",
            &session,
            &[
                ("x-goog-upload-command", "upload, finalize"),
                ("x-goog-upload-offset", "0"),
                (
                    "x-goog-hash",
                    &format!(
                        "crc32c={}",
                        ftd_core_storage::hash::base64(
                            &ftd_core_storage::hash::crc32c(b"abc").to_be_bytes()
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
        &req("POST", &session, &[("x-goog-upload-command", "query")], b""),
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
                    && !('generation' in request.resource.keys());
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
        &req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=docs%2Fa.txt&uploadType=multipart"),
            &[("authorization", &auth), ("content-type", &ct)],
            &body,
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let patch = |body: &[u8]| {
        handle(
            &s,
            &req(
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
        &req(
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
        &req(
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
        &req("DELETE", &format!("{object}?generation=99999"), &[], b""),
    );
    assert_eq!(r.status, 404);
    assert_eq!(json_body(&r)["error"]["errors"][0]["reason"], "notFound");
    assert_eq!(
        handle(
            &s,
            &req("GET", &format!("{object}?generation=99999"), &[], b"")
        )
        .status,
        404
    );
    assert_eq!(
        handle(
            &s,
            &req(
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
        &req(
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
            &req(
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
    assert_eq!(header(&r, "content-length"), Some("3"));
    let r = get("bytes=10-");
    assert_eq!(r.status, 416);
    assert_eq!(header(&r, "content-range"), Some("bytes */10"));
    // Resumable JSON API: the declared span must match the body and the total.
    let r = handle(
        &s,
        &req(
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
        &req(
            "PUT",
            &session,
            &[("content-range", "bytes 0-99/100")],
            b"x",
        ),
    );
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    let r = handle(
        &s,
        &req("PUT", &session, &[("content-range", "bytes 0-2/6")], b"abc"),
    );
    assert_eq!(r.status, 308, "{}", String::from_utf8_lossy(&r.body));
    let r = handle(
        &s,
        &req("PUT", &session, &[("content-range", "bytes 3-5/7")], b"def"),
    );
    assert_eq!(r.status, 400, "a different total is a size mismatch");
    let r = handle(
        &s,
        &req("PUT", &session, &[("content-range", "bytes 3-5/6")], b"def"),
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
            &req(
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
        &req(
            "GET",
            &format!("/v0/b/{BUCKET}/o"),
            &[("authorization", &auth)],
            b"",
        ),
    );
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
}

#[test]
fn rewrite_authorizes_the_source_before_revealing_it_and_gets_honour_preconditions() {
    let s = state(Some(
        "rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /open/{file} { allow read, write: if true; }
  }
}",
    ));
    let (_uid, auth) = user_token(&s);
    let (ct, body) = multipart(&json!({"name": "open/src"}), "text/plain", b"src");
    let r = handle(
        &s,
        &req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=multipart"),
            &[("content-type", &ct)],
            &body,
        ),
    );
    assert_eq!(r.status, 200);
    let generation = json_body(&r)["generation"].as_str().unwrap().to_owned();
    // A denied caller sees 403 whether or not the source exists.
    for src in ["closed%2Fmissing", "closed%2Fother"] {
        let r = handle(
            &s,
            &req(
                "POST",
                &format!("/storage/v1/b/{BUCKET}/o/{src}/rewriteTo/b/{BUCKET}/o/open%2Fdst?ifSourceGenerationMatch=1"),
                &[("authorization", &auth)],
                b"",
            ),
        );
        assert_eq!(r.status, 403, "{src}");
    }
    let r = handle(
        &s,
        &req(
            "POST",
            &format!("/storage/v1/b/{BUCKET}/o/open%2Fsrc/rewriteTo/b/{BUCKET}/o/open%2Fdst?ifSourceGenerationMatch=999"),
            &[("authorization", &auth)],
            b"",
        ),
    );
    assert_eq!(r.status, 412, "{}", String::from_utf8_lossy(&r.body));
    // Conditional reads: not-match naming the current generation is 304, match failing is 412.
    let object = format!("/storage/v1/b/{BUCKET}/o/open%2Fsrc");
    let r = handle(
        &s,
        &req(
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
        &req("GET", &format!("{object}?ifGenerationMatch=999"), &[], b""),
    );
    assert_eq!(r.status, 412);
    let r = handle(
        &s,
        &req(
            "GET",
            &format!("{object}?ifGenerationMatch=1&ifGenerationNotMatch=2"),
            &[],
            b"",
        ),
    );
    assert_eq!(r.status, 400, "conflicting predicates");
    // A closing delimiter followed by more text is payload, not the end of the body.
    let data = b"--ftd-boundary--tail\r\n";
    let (ct, body) = multipart(&json!({"name": "open/tail"}), "text/plain", data);
    let r = handle(
        &s,
        &req(
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

impl ftd_core_rules::eval::DocumentAccess for Flags {
    fn get(&self, segments: &[String]) -> Option<ftd_core_rules::value::RulesValue> {
        let path = segments.join("/");
        self.0.contains(&path).then(|| {
            let mut m = std::collections::BTreeMap::new();
            m.insert(
                "data".to_owned(),
                ftd_core_rules::value::RulesValue::Map(std::collections::BTreeMap::from([(
                    "open".to_owned(),
                    ftd_core_rules::value::RulesValue::Bool(true),
                )])),
            );
            ftd_core_rules::value::RulesValue::Map(m)
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
        &req(
            "POST",
            &upload,
            &[("authorization", "Bearer owner"), ("content-type", &ct)],
            &body,
        ),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let read = format!("/v0/b/{BUCKET}/o/gated%2Fa.txt?alt=media");
    // No Firestore access: the rule fails closed.
    assert_eq!(handle(&s, &req("GET", &read, &[], b"")).status, 403);
    // The flag is absent: denied; present: allowed.
    s.firestore = Some(Arc::new(Flags(vec![])));
    assert_eq!(handle(&s, &req("GET", &read, &[], b"")).status, 403);
    s.firestore = Some(Arc::new(Flags(vec![
        "databases/(default)/documents/flags/open".to_owned(),
    ])));
    assert_eq!(handle(&s, &req("GET", &read, &[], b"")).status, 200);
}

#[test]
fn fault_plans_fail_storage_operations() {
    use ftd_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule};
    let mut s = state(None);
    let registry = Arc::new(ftd_core_session::fault::FaultRegistry::new());
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
        &req(
            "POST",
            &upload,
            &[("authorization", "Bearer owner"), ("content-type", &ct)],
            &body,
        ),
    );
    assert_eq!(r.status, 503, "{}", String::from_utf8_lossy(&r.body));
    let r = handle(
        &s,
        &req(
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
    let mut tenancy = ftd_core_session::tenancy::Tenancy::new("demo-app");
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
        format!("Firebase {}", ftd_core_auth::jwt::encode_unsigned(&claims))
    };
    let (_, token_a) = user_token(&s);
    let (ct, body) = multipart(&json!({"contentType": "text/plain"}), "text/plain", b"x");
    let upload = |bucket: &str| format!("/v0/b/{bucket}/o?name=f.txt&uploadType=multipart");
    // A demo-b user on demo-app's bucket, and a demo-app user on demo-b's: refused before
    // any rule runs.
    for (bucket, token) in [(BUCKET, &token_b), ("demo-b.appspot.com", &token_a)] {
        let r = handle(
            &s,
            &req(
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
            &req(
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
    use ftd_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule};
    let mut s = state(None);
    let registry = Arc::new(ftd_core_session::fault::FaultRegistry::new());
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
        &req("GET", &path, &[("authorization", "Bearer owner")], b""),
    );
    assert!(r
        .headers
        .iter()
        .any(|(k, v)| k == ftd_adapter_http::storage::DROP_CONNECTION_HEADER && v == "1"));
    let r = handle(
        &s,
        &req("GET", &path, &[("authorization", "Bearer owner")], b""),
    );
    assert_eq!(r.status, 404);
    assert!(!r
        .headers
        .iter()
        .any(|(k, _)| k == ftd_adapter_http::storage::DROP_CONNECTION_HEADER));
}

#[test]
fn json_api_uploads_count_as_uploads_for_fault_plans() {
    use ftd_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule};
    let mut s = state(None);
    let registry = Arc::new(ftd_core_session::fault::FaultRegistry::new());
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
    let r = handle(&s, &req("POST", &path, &[("content-type", &ct)], &body));
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
        &req(
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
        &req(
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
        &req(
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
