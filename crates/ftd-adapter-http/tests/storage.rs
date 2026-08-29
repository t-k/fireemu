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
        auth: Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(3),
            TotpPolicy::default(),
        ))),
        rules: Arc::new(RwLock::new(rules.map_or_else(LoadedRules::default, |r| {
            LoadedRules::from_source(r).unwrap()
        }))),
        project: "demo-app".to_owned(),
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
        let mut store = s.auth.lock().unwrap();
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
