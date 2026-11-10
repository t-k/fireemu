//! A configured `storage.maxObjectBytes` bounds every way an object can be uploaded: the JSON
//! API media, multipart and resumable dialects (including continuation chunks and the final
//! size), the Firebase dialect, the XML-style PUT and the POST form. Each path admits an object
//! of exactly the limit, refuses one byte more, and publishes nothing for a refused upload.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fireemu_adapter_http::storage::{
    handle, StorageRequest, StorageResponse, StorageRulesRegistry, StorageState,
};
use fireemu_core_auth::jwt::TokenAcceptance;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::StorageState as ObjectStore;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;

const BUCKET: &str = "demo-app.appspot.com";
const LIMIT: usize = 3;
const OWNER: (&str, &str) = ("authorization", "Bearer owner");
const ALLOW_ALL_RULES: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if true; } } }";
const BOTH_PROFILES: [TokenAcceptance; 2] =
    [TokenAcceptance::Verified, TokenAcceptance::EmulatorMock];

fn state(acceptance: TokenAcceptance) -> StorageState {
    let state = StorageState {
        store: Mutex::new(ObjectStore::new(9)),
        clock: Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
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
            LoadedRules::from_source(ALLOW_ALL_RULES).unwrap(),
        )))),
        project: "demo-app".to_owned(),
        events: None,
        barrier: None,
        firestore: None,
        faults: None,
        clock_observer: None,
        app_check_policy: None,
        admin_capability: None,
        server_requests: fireemu_adapter_http::storage::StorageServerRequests::default(),
        token_acceptance: acceptance,
        allow_unsigned_id_tokens: acceptance == TokenAcceptance::EmulatorMock,
        control_token: Some("storage-test-control-token".to_owned()),
    };
    state
        .store
        .lock()
        .unwrap()
        .set_max_object_bytes(LIMIT as u64);
    state
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
        app_check: Vec::new(),
        body: body.to_vec(),
        remote_peer: false,
    }
}

fn text(r: &StorageResponse) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn exists(s: &StorageState, name: &str) -> bool {
    s.store
        .lock()
        .unwrap()
        .get(
            &BucketName::try_new(BUCKET).unwrap(),
            &ObjectName::try_new(name).unwrap(),
        )
        .is_some()
}

fn size_of(s: &StorageState, name: &str) -> Option<u64> {
    s.store
        .lock()
        .unwrap()
        .get(
            &BucketName::try_new(BUCKET).unwrap(),
            &ObjectName::try_new(name).unwrap(),
        )
        .map(|m| m.size)
}

/// Asserts the answer is the refusal for an object over the limit and that nothing was stored.
fn assert_too_large(s: &StorageState, response: &StorageResponse, name: &str, what: &str) {
    assert_eq!(response.status, 413, "{what}: {}", text(response));
    assert!(
        !exists(s, name),
        "{what}: a refused upload stored an object"
    );
}

fn assert_stored(s: &StorageState, response: &StorageResponse, name: &str, what: &str) {
    assert!(
        (200..300).contains(&response.status),
        "{what}: {}",
        text(response)
    );
    assert_eq!(size_of(s, name), Some(LIMIT as u64), "{what}");
}

fn multipart(data: &[u8]) -> (String, Vec<u8>) {
    let boundary = "fireemu-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{{}}\r\n--{boundary}\r\nContent-Type: text/plain\r\n\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());
    (format!("multipart/related; boundary={boundary}"), body)
}

#[test]
fn media_and_multipart_uploads_in_both_dialects_admit_the_limit_and_refuse_one_byte_more() {
    for acceptance in BOTH_PROFILES {
        let s = state(acceptance);
        for (n, size) in [(0, LIMIT), (1, LIMIT + 1)] {
            let data = vec![b'x'; size];
            let (content_type, body) = multipart(&data);
            let json_multipart = handle(
                &s,
                req(
                    "POST",
                    &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=multipart&name=jm{n}.txt"),
                    &[OWNER, ("content-type", &content_type)],
                    &body,
                ),
            );
            let firebase_multipart = handle(
                &s,
                req(
                    "POST",
                    &format!("/v0/b/{BUCKET}/o?name=fm{n}.txt&uploadType=multipart"),
                    &[
                        OWNER,
                        ("content-type", &content_type),
                        ("x-goog-upload-protocol", "multipart"),
                    ],
                    &body,
                ),
            );
            let media = handle(
                &s,
                req(
                    "POST",
                    &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name=md{n}.txt"),
                    &[OWNER, ("content-type", "text/plain")],
                    &data,
                ),
            );
            let firebase_media = handle(
                &s,
                req(
                    "POST",
                    &format!("/v0/b/{BUCKET}/o?name=fd{n}.txt"),
                    &[OWNER, ("content-type", "text/plain")],
                    &data,
                ),
            );
            for (response, name, what) in [
                (&json_multipart, format!("jm{n}.txt"), "JSON multipart"),
                (
                    &firebase_multipart,
                    format!("fm{n}.txt"),
                    "Firebase multipart",
                ),
                (&media, format!("md{n}.txt"), "JSON media"),
                (&firebase_media, format!("fd{n}.txt"), "Firebase media"),
            ] {
                if size == LIMIT {
                    assert_stored(&s, response, &name, what);
                } else {
                    assert_too_large(&s, response, &name, what);
                }
            }
        }
    }
}

fn start_json_resumable(
    s: &StorageState,
    name: &str,
    extra: &[(&str, &str)],
) -> (StorageResponse, String) {
    let mut headers = vec![OWNER];
    headers.extend_from_slice(extra);
    let start = handle(
        s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name={name}"),
            &headers,
            b"{}",
        ),
    );
    let session = start
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .and_then(|(_, v)| v.strip_prefix("http://127.0.0.1:9199"))
        .unwrap_or("")
        .to_owned();
    (start, session)
}

fn put_chunk(s: &StorageState, session: &str, range: &str, chunk: &[u8]) -> StorageResponse {
    handle(
        s,
        req("PUT", session, &[OWNER, ("content-range", range)], chunk),
    )
}

#[test]
fn json_resumable_uploads_obey_the_limit_across_chunks_and_the_final_size() {
    for acceptance in BOTH_PROFILES {
        // One request carrying the whole object.
        let s = state(acceptance);
        let (start, session) = start_json_resumable(&s, "whole-ok.bin", &[]);
        assert_eq!(start.status, 200, "{}", text(&start));
        let ok = put_chunk(&s, &session, "bytes 0-2/3", b"abc");
        assert_stored(&s, &ok, "whole-ok.bin", "single chunk at the limit");
        let (_, session) = start_json_resumable(&s, "whole-over.bin", &[]);
        let over = put_chunk(&s, &session, "bytes 0-3/4", b"abcd");
        assert_too_large(&s, &over, "whole-over.bin", "single chunk over the limit");

        // Continuation chunks with an unknown total, then a final chunk that lands on the limit.
        let (_, session) = start_json_resumable(&s, "chunks-ok.bin", &[]);
        let first = put_chunk(&s, &session, "bytes 0-1/*", b"ab");
        assert_eq!(first.status, 308, "{}", text(&first));
        let last = put_chunk(&s, &session, "bytes 2-2/3", b"c");
        assert_stored(&s, &last, "chunks-ok.bin", "continuation to the limit");

        // The same upload with a final chunk one byte too many.
        let (_, session) = start_json_resumable(&s, "chunks-over.bin", &[]);
        let first = put_chunk(&s, &session, "bytes 0-1/*", b"ab");
        assert_eq!(first.status, 308, "{}", text(&first));
        let last = put_chunk(&s, &session, "bytes 2-3/4", b"cd");
        assert_too_large(&s, &last, "chunks-over.bin", "continuation past the limit");

        // An unknown total never lets the running size pass the limit, even without a final chunk.
        let (_, session) = start_json_resumable(&s, "chunks-open.bin", &[]);
        assert_eq!(put_chunk(&s, &session, "bytes 0-1/*", b"ab").status, 308);
        let past = put_chunk(&s, &session, "bytes 2-3/*", b"cd");
        assert_too_large(
            &s,
            &past,
            "chunks-open.bin",
            "open-ended continuation past the limit",
        );
    }
}

#[test]
fn a_declared_total_over_the_limit_is_refused_on_the_first_chunk() {
    for acceptance in BOTH_PROFILES {
        let s = state(acceptance);
        let (_, session) = start_json_resumable(&s, "declared-over.bin", &[]);
        let over = put_chunk(&s, &session, "bytes 0-1/4", b"ab");
        assert_too_large(
            &s,
            &over,
            "declared-over.bin",
            "declared total past the limit",
        );
        let (_, session) = start_json_resumable(&s, "declared-ok.bin", &[]);
        let first = put_chunk(&s, &session, "bytes 0-1/3", b"ab");
        assert_eq!(first.status, 308, "{}", text(&first));
        let last = put_chunk(&s, &session, "bytes 2-2/3", b"c");
        assert_stored(&s, &last, "declared-ok.bin", "declared total at the limit");
    }
}

fn firebase_session(s: &StorageState, name: &str) -> String {
    let start = handle(
        s,
        req(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name={name}&uploadType=resumable"),
            &[
                OWNER,
                ("content-type", "application/json"),
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "start"),
                ("x-goog-upload-header-content-type", "text/plain"),
            ],
            b"{}",
        ),
    );
    assert_eq!(start.status, 200, "{}", text(&start));
    let url = start
        .headers
        .iter()
        .find(|(k, _)| k == "x-goog-upload-url")
        .map(|(_, v)| v.clone())
        .unwrap();
    let id = url.split("upload_id=").nth(1).unwrap().to_owned();
    format!("/v0/b/{BUCKET}/o?name={name}&upload_id={id}")
}

fn firebase_command(
    s: &StorageState,
    url: &str,
    command: &str,
    offset: usize,
    chunk: &[u8],
) -> StorageResponse {
    handle(
        s,
        req(
            "POST",
            url,
            &[
                OWNER,
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", command),
                ("x-goog-upload-offset", &offset.to_string()),
            ],
            chunk,
        ),
    )
}

#[test]
fn firebase_resumable_uploads_obey_the_limit_across_commands_and_the_final_size() {
    for acceptance in BOTH_PROFILES {
        let s = state(acceptance);

        // Upload chunks, then finalize with a separate empty command.
        let url = firebase_session(&s, "fb-sep-ok.bin");
        assert_eq!(firebase_command(&s, &url, "upload", 0, b"ab").status, 200);
        assert_eq!(firebase_command(&s, &url, "upload", 2, b"c").status, 200);
        let done = firebase_command(&s, &url, "finalize", 3, b"");
        assert_stored(&s, &done, "fb-sep-ok.bin", "separate finalize at the limit");

        // The chunk that would carry the running size past the limit is refused and the session
        // publishes nothing, whether or not it finalizes.
        let url = firebase_session(&s, "fb-over-upload.bin");
        assert_eq!(firebase_command(&s, &url, "upload", 0, b"ab").status, 200);
        let past = firebase_command(&s, &url, "upload", 2, b"cd");
        assert_too_large(
            &s,
            &past,
            "fb-over-upload.bin",
            "upload chunk past the limit",
        );

        let url = firebase_session(&s, "fb-over-final.bin");
        assert_eq!(firebase_command(&s, &url, "upload", 0, b"ab").status, 200);
        let past = firebase_command(&s, &url, "upload, finalize", 2, b"cd");
        assert_too_large(
            &s,
            &past,
            "fb-over-final.bin",
            "finalizing chunk past the limit",
        );

        // One request with the whole object.
        let url = firebase_session(&s, "fb-one-ok.bin");
        let ok = firebase_command(&s, &url, "upload, finalize", 0, b"abc");
        assert_stored(&s, &ok, "fb-one-ok.bin", "one request at the limit");
        let url = firebase_session(&s, "fb-one-over.bin");
        let over = firebase_command(&s, &url, "upload, finalize", 0, b"abcd");
        assert_too_large(&s, &over, "fb-one-over.bin", "one request past the limit");
    }
}

#[test]
fn the_xml_style_put_admits_the_limit_and_refuses_one_byte_more() {
    // The strict profile answers this unsigned XML-style PUT with AccessDenied before any size
    // check, so the emulator profile (which admits it, as the official emulator does) is the one
    // that reaches the cap.
    for acceptance in [TokenAcceptance::EmulatorMock] {
        let s = state(acceptance);
        let ok = handle(
            &s,
            req(
                "PUT",
                &format!("/{BUCKET}/xml-ok.txt"),
                &[OWNER, ("content-type", "text/plain")],
                b"abc",
            ),
        );
        assert_stored(&s, &ok, "xml-ok.txt", "XML PUT at the limit");
        let over = handle(
            &s,
            req(
                "PUT",
                &format!("/{BUCKET}/xml-over.txt"),
                &[OWNER, ("content-type", "text/plain")],
                b"abcd",
            ),
        );
        assert_too_large(&s, &over, "xml-over.txt", "XML PUT over the limit");
    }
}

fn form_post(s: &StorageState, key: &str, file: &[u8]) -> StorageResponse {
    let boundary = "fireemu-form";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n{key}\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f.txt\"\r\nContent-Type: text/plain\r\n\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(file);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    handle(
        s,
        req(
            "POST",
            &format!("/{BUCKET}"),
            &[(
                "content-type",
                &format!("multipart/form-data; boundary={boundary}"),
            )],
            &body,
        ),
    )
}

#[test]
fn the_post_form_upload_admits_the_limit_and_refuses_one_byte_more() {
    // The emulator profile accepts a form with no signed policy, as the official emulator does;
    // under the strict profile the same refusal comes from the size check once a policy admits it.
    let s = state(TokenAcceptance::EmulatorMock);
    let ok = form_post(&s, "form-ok.txt", b"abc");
    assert_eq!(ok.status, 204, "{}", text(&ok));
    assert_eq!(size_of(&s, "form-ok.txt"), Some(LIMIT as u64));
    let over = form_post(&s, "form-over.txt", b"abcd");
    assert_eq!(over.status, 413, "{}", text(&over));
    assert!(!exists(&s, "form-over.txt"));
}
