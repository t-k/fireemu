//! The strict profile refuses what production refuses and the Storage emulator used to accept:
//! an object operation on a bucket that does not exist, an anonymous read of a private object by
//! its public URL, a Firebase ID token used as an OAuth bearer, an expired signed URL, a form
//! upload with no signed policy, an invalid ACL. The `emulator` profile keeps the official
//! emulator's behaviour for every one of them.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fireemu_adapter_http::storage::{
    handle, NoRulesNotice, NoticeEvent, NoticeLimit, StorageRequest, StorageResponse,
    StorageRulesRegistry, StorageState,
};
use fireemu_core_auth::jwt::TokenAcceptance;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::StorageState as ObjectStore;
use fireemu_core_storage::store::{NewMetadata, Precondition};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const DEFAULT_BUCKET: &str = "demo-app.appspot.com";
const NEW_DEFAULT_BUCKET: &str = "demo-app.firebasestorage.app";
const OWNER: (&str, &str) = ("authorization", "Bearer owner");
const ALLOW_ALL_RULES: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if true; } } }";

fn state(acceptance: TokenAcceptance) -> StorageState {
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
        token_acceptance: acceptance,
        allow_unsigned_id_tokens: acceptance == TokenAcceptance::EmulatorMock,
        control_token: Some("storage-test-control-token".to_owned()),
    }
}

fn strict() -> StorageState {
    state(TokenAcceptance::Verified)
}

fn emulator() -> StorageState {
    state(TokenAcceptance::EmulatorMock)
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

fn json_body(r: &StorageResponse) -> Value {
    serde_json::from_slice(&r.body).unwrap_or(Value::Null)
}

fn text(r: &StorageResponse) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn seed(s: &StorageState, bucket: &str, name: &str, bytes: &[u8]) {
    s.store
        .lock()
        .unwrap()
        .put(
            &BucketName::try_new(bucket).unwrap(),
            &ObjectName::try_new(name).unwrap(),
            bytes.to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            START,
        )
        .unwrap();
}

fn has_bucket(s: &StorageState, bucket: &str) -> bool {
    s.store
        .lock()
        .unwrap()
        .buckets()
        .iter()
        .any(|b| b.as_str() == bucket)
}

/// Every object operation of both dialects against `bucket`, each as a closure-free request list
/// with the credential the dialect needs to reach the bucket check.
#[allow(clippy::too_many_lines)]
fn object_requests(bucket: &str) -> Vec<(&'static str, StorageRequest)> {
    let media = [
        ("authorization", "Bearer owner"),
        ("content-type", "text/plain"),
    ];
    vec![
        (
            "firebase upload",
            req(
                "POST",
                &format!("/v0/b/{bucket}/o?name=a.txt&uploadType=media"),
                &[
                    ("authorization", "Bearer owner"),
                    ("content-type", "text/plain"),
                ],
                b"hello",
            ),
        ),
        (
            "firebase get",
            req("GET", &format!("/v0/b/{bucket}/o/a.txt"), &[OWNER], b""),
        ),
        (
            "firebase media get",
            req(
                "GET",
                &format!("/v0/b/{bucket}/o/a.txt?alt=media"),
                &[OWNER],
                b"",
            ),
        ),
        (
            "firebase list",
            req("GET", &format!("/v0/b/{bucket}/o"), &[OWNER], b""),
        ),
        (
            "firebase delete",
            req("DELETE", &format!("/v0/b/{bucket}/o/a.txt"), &[OWNER], b""),
        ),
        (
            "json upload",
            req(
                "POST",
                &format!("/upload/storage/v1/b/{bucket}/o?uploadType=media&name=a.txt"),
                &media,
                b"hello",
            ),
        ),
        (
            "json get",
            req(
                "GET",
                &format!("/storage/v1/b/{bucket}/o/a.txt"),
                &[OWNER],
                b"",
            ),
        ),
        (
            "json media get",
            req(
                "GET",
                &format!("/storage/v1/b/{bucket}/o/a.txt?alt=media"),
                &[OWNER],
                b"",
            ),
        ),
        (
            "json list",
            req("GET", &format!("/storage/v1/b/{bucket}/o"), &[OWNER], b""),
        ),
        (
            "json delete",
            req(
                "DELETE",
                &format!("/storage/v1/b/{bucket}/o/a.txt"),
                &[OWNER],
                b"",
            ),
        ),
        (
            "json copy source",
            req(
                "POST",
                &format!("/storage/v1/b/{bucket}/o/a.txt/copyTo/b/{DEFAULT_BUCKET}/o/b.txt"),
                &[OWNER],
                b"",
            ),
        ),
        (
            "json copy destination",
            req(
                "POST",
                &format!("/storage/v1/b/{DEFAULT_BUCKET}/o/a.txt/copyTo/b/{bucket}/o/b.txt"),
                &[OWNER],
                b"",
            ),
        ),
        (
            "json rewrite destination",
            req(
                "POST",
                &format!("/storage/v1/b/{DEFAULT_BUCKET}/o/a.txt/rewriteTo/b/{bucket}/o/b.txt"),
                &[OWNER],
                b"",
            ),
        ),
        (
            "json acl",
            req(
                "POST",
                &format!("/b/{bucket}/o/a.txt/acl"),
                &[OWNER],
                br#"{"entity":"allUsers","role":"READER"}"#,
            ),
        ),
        (
            "xml-style get",
            req("GET", &format!("/{bucket}/a.txt"), &[OWNER], b""),
        ),
    ]
}

// ----------------------------------------------------------------------------------------
// ST-1: a write to a bucket nothing declared is served and noted once
// ----------------------------------------------------------------------------------------

/// Installs a notice sink on `s` and returns what it receives.
fn noting(s: &StorageState) -> Arc<Mutex<Vec<String>>> {
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = seen.clone();
    s.rules
        .set_unknown_bucket_notice(NoRulesNotice(Arc::new(move |event| {
            sink.lock().unwrap().push(match event {
                NoticeEvent::First(bucket) => bucket.to_owned(),
                NoticeEvent::Suppressed => "<suppressed>".to_owned(),
            });
        })));
    seen
}

const WRITES: [&str; 4] = [
    "firebase upload",
    "json upload",
    "json copy destination",
    "json rewrite destination",
];

#[test]
fn an_undeclared_bucket_is_created_by_a_write_and_noted_once_under_strict() {
    for label in WRITES {
        let s = strict();
        seed(&s, DEFAULT_BUCKET, "a.txt", b"hello");
        let seen = noting(&s);
        let request = |bucket: &str| {
            object_requests(bucket)
                .into_iter()
                .find(|(l, _)| *l == label)
                .unwrap()
                .1
        };
        let first = handle(&s, request("typo-bucket"));
        assert_eq!(first.status, 200, "{label}: {}", text(&first));
        assert!(
            has_bucket(&s, "typo-bucket"),
            "{label}: the write still creates it"
        );
        assert_eq!(*seen.lock().unwrap(), ["typo-bucket"], "{label}");
        // The same bucket is not noted again; another one is.
        assert_eq!(handle(&s, request("typo-bucket")).status, 200);
        assert_eq!(handle(&s, request("other-typo")).status, 200);
        assert_eq!(
            *seen.lock().unwrap(),
            ["typo-bucket", "other-typo"],
            "{label}"
        );
    }
}

#[test]
fn a_form_upload_to_an_undeclared_bucket_is_noted_too() {
    let s = strict();
    let seen = noting(&s);
    let policy = signed_policy(&json!([]), "2026-08-29T13:00:00Z");
    let response = form_post(
        &s,
        "typo-bucket",
        &[
            ("key", "a.txt"),
            ("policy", &policy),
            ("x-goog-signature", "abc"),
        ],
        b"hello",
    );
    assert_eq!(response.status, 204, "{}", text(&response));
    assert_eq!(*seen.lock().unwrap(), ["typo-bucket"]);
}

#[test]
fn reads_and_other_routes_on_an_undeclared_bucket_are_not_noted() {
    let s = strict();
    let seen = noting(&s);
    for (label, request) in object_requests("typo-bucket") {
        if WRITES.contains(&label) {
            continue;
        }
        let _ = handle(&s, request);
    }
    // The upload route's other verbs create nothing: a cancel with no session is a bare 400.
    let cancel = handle(
        &s,
        req(
            "DELETE",
            "/upload/storage/v1/b/typo-bucket/o",
            &[OWNER],
            b"",
        ),
    );
    assert_eq!(cancel.status, 400);
    for method in ["GET", "PATCH", "DELETE"] {
        let _ = handle(
            &s,
            req(method, "/v0/b/typo-bucket/o/a.txt", &[OWNER], b"{}"),
        );
    }
    assert!(
        seen.lock().unwrap().is_empty(),
        "{:?}",
        seen.lock().unwrap()
    );
}

#[test]
fn a_declared_default_trigger_imported_or_public_bucket_is_not_noted() {
    let s = strict();
    let seen = noting(&s);
    s.rules.set_configured_buckets(["extra-bucket".to_owned()]);
    s.rules.set_public_buckets(["public-bucket".to_owned()]);
    s.rules.set_trigger_buckets(["trigger-bucket".to_owned()]);
    seed(&s, "imported-bucket", "seed.txt", b"seed");
    for bucket in [
        DEFAULT_BUCKET,
        NEW_DEFAULT_BUCKET,
        "extra-bucket",
        "public-bucket",
        "trigger-bucket",
        "imported-bucket",
    ] {
        for (label, request) in object_requests(bucket) {
            if label == "json upload" || label == "firebase upload" {
                let response = handle(&s, request);
                assert_eq!(
                    response.status,
                    200,
                    "{bucket} {label}: {}",
                    text(&response)
                );
            }
        }
    }
    assert!(
        seen.lock().unwrap().is_empty(),
        "{:?}",
        seen.lock().unwrap()
    );
}

#[test]
fn the_emulator_profile_creates_a_bucket_on_first_use_without_a_note() {
    let s = emulator();
    seed(&s, DEFAULT_BUCKET, "a.txt", b"hello");
    let seen = noting(&s);
    for bucket in ["implicit-bucket", "another-implicit"] {
        for (label, request) in object_requests(bucket) {
            if WRITES.contains(&label) {
                let response = handle(&s, request);
                assert_eq!(response.status, 200, "{label}: {}", text(&response));
            }
        }
        assert!(has_bucket(&s, bucket));
    }
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn a_resumable_continuation_is_not_noted_and_the_start_is() {
    let s = strict();
    let seen = noting(&s);
    let start = handle(
        &s,
        req(
            "POST",
            "/upload/storage/v1/b/typo-bucket/o?uploadType=resumable&name=r.txt",
            &[OWNER],
            b"{}",
        ),
    );
    assert_eq!(start.status, 200, "{}", text(&start));
    assert_eq!(*seen.lock().unwrap(), ["typo-bucket"]);
    let location = start
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .map(|(_, v)| v.clone())
        .unwrap();
    let session = location.strip_prefix("http://127.0.0.1:9199").unwrap();
    assert_eq!(
        handle(&s, req("PUT", session, &[OWNER], b"hello")).status,
        200
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[test]
fn the_notes_are_bounded_then_suppressed_once() {
    let s = strict();
    let seen = noting(&s);
    for i in 0..(NoticeLimit::LIMIT + 8) {
        let response = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/typo-{i}-bucket/o?uploadType=media&name=a.txt"),
                &[OWNER, ("content-type", "text/plain")],
                b"x",
            ),
        );
        assert_eq!(response.status, 200);
    }
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), NoticeLimit::LIMIT + 1);
    assert_eq!(seen[NoticeLimit::LIMIT], "<suppressed>");
}

mod bucket_notes {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// A reference model: the notes are the distinct undeclared buckets written to, in order
        /// of first write; a declared bucket is never noted.
        #[test]
        fn notes_follow_the_distinct_undeclared_buckets_written(
            writes in proptest::collection::vec(0usize..6, 0..30)
        ) {
            let names = ["alpha-bucket", "beta-bucket", "gamma-bucket", DEFAULT_BUCKET, "declared-bucket", "delta-bucket"];
            let s = strict();
            s.rules.set_configured_buckets(["declared-bucket".to_owned()]);
            let seen = noting(&s);
            let mut expected: Vec<&str> = Vec::new();
            let mut done = BTreeSet::new();
            for i in writes {
                let name = names[i];
                let response = handle(
                    &s,
                    req(
                        "POST",
                        &format!("/upload/storage/v1/b/{name}/o?uploadType=media&name=a.txt"),
                        &[OWNER, ("content-type", "text/plain")],
                        b"x",
                    ),
                );
                prop_assert_eq!(response.status, 200);
                if name != DEFAULT_BUCKET && name != "declared-bucket" && done.insert(name) {
                    expected.push(name);
                }
            }
            prop_assert_eq!(seen.lock().unwrap().clone(), expected);
        }
    }
}

// ----------------------------------------------------------------------------------------
// ST-2, ST-8: the public URL and the ACL that makes an object public
// ----------------------------------------------------------------------------------------

fn upload_as_owner(s: &StorageState, name: &str) {
    let response = handle(
        s,
        req(
            "POST",
            &format!("/upload/storage/v1/b/{DEFAULT_BUCKET}/o?uploadType=media&name={name}"),
            &[OWNER, ("content-type", "text/plain")],
            b"hello",
        ),
    );
    assert_eq!(response.status, 200, "{}", text(&response));
}

fn anonymous_public_get(s: &StorageState, name: &str) -> StorageResponse {
    handle(
        s,
        req("GET", &format!("/{DEFAULT_BUCKET}/{name}"), &[], b""),
    )
}

fn make_public(s: &StorageState, name: &str, long_spelling: bool) -> StorageResponse {
    let path = if long_spelling {
        format!("/storage/v1/b/{DEFAULT_BUCKET}/o/{name}/acl")
    } else {
        format!("/b/{DEFAULT_BUCKET}/o/{name}/acl")
    };
    handle(
        s,
        req(
            "POST",
            &path,
            &[OWNER],
            br#"{"entity":"allUsers","role":"READER"}"#,
        ),
    )
}

#[test]
fn strict_refuses_an_anonymous_read_of_a_private_object_by_its_public_url() {
    let s = strict();
    upload_as_owner(&s, "a.txt");
    let refused = anonymous_public_get(&s, "a.txt");
    assert_eq!(refused.status, 403);
    let body = text(&refused);
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert!(body.contains("storage.objects.get"), "{body}");
    assert!(!body.contains("hello"));
    assert!(refused
        .headers
        .iter()
        .any(|(k, v)| k == "content-type" && v.starts_with("application/xml")));
    // A missing object answers the same: the permission check comes before the lookup.
    assert_eq!(anonymous_public_get(&s, "missing.txt").status, 403);
    // A caller who proves who it is reads the object.
    let owner = handle(
        &s,
        req("GET", &format!("/{DEFAULT_BUCKET}/a.txt"), &[OWNER], b""),
    );
    assert_eq!(owner.status, 200);
    assert_eq!(owner.body.as_ref(), b"hello");
}

#[test]
fn the_emulator_profile_serves_the_public_url_to_anyone() {
    let s = emulator();
    upload_as_owner(&s, "a.txt");
    let response = anonymous_public_get(&s, "a.txt");
    assert_eq!(response.status, 200);
    assert_eq!(response.body.as_ref(), b"hello");
}

#[test]
fn make_public_opens_the_public_url_until_the_object_is_overwritten() {
    for long_spelling in [false, true] {
        let s = strict();
        upload_as_owner(&s, "a.txt");
        assert_eq!(anonymous_public_get(&s, "a.txt").status, 403);
        let acl = make_public(&s, "a.txt", long_spelling);
        assert_eq!(acl.status, 200, "{}", text(&acl));
        assert_eq!(json_body(&acl)["entity"], "allUsers");
        assert_eq!(json_body(&acl)["role"], "READER");
        let read = anonymous_public_get(&s, "a.txt");
        assert_eq!(read.status, 200);
        assert_eq!(read.body.as_ref(), b"hello");
        // Another object stays private.
        upload_as_owner(&s, "b.txt");
        assert_eq!(anonymous_public_get(&s, "b.txt").status, 403);
        // A new generation of the object starts private again.
        upload_as_owner(&s, "a.txt");
        assert_eq!(anonymous_public_get(&s, "a.txt").status, 403);
    }
}

#[test]
fn only_all_users_reader_makes_an_object_public() {
    for (entity, role) in [
        ("allAuthenticatedUsers", "READER"),
        ("user-alice@example.com", "READER"),
        ("allUsers", "OWNER"),
    ] {
        let s = strict();
        upload_as_owner(&s, "a.txt");
        let acl = handle(
            &s,
            req(
                "POST",
                &format!("/b/{DEFAULT_BUCKET}/o/a.txt/acl"),
                &[OWNER],
                json!({"entity": entity, "role": role})
                    .to_string()
                    .as_bytes(),
            ),
        );
        assert_eq!(acl.status, 200, "{entity} {role}: {}", text(&acl));
        assert_eq!(
            anonymous_public_get(&s, "a.txt").status,
            403,
            "{entity} {role}"
        );
    }
}

#[test]
fn an_acl_entry_cloud_storage_does_not_know_is_a_400_under_strict() {
    for body in [
        r#"{"entity":"bogus","role":"READER"}"#,
        r#"{"entity":"allUsers","role":"WRITER"}"#,
        r#"{"entity":"allUsers","role":"reader"}"#,
        r#"{"entity":"user-","role":"READER"}"#,
        r#"{"entity":"project-owners-","role":"READER"}"#,
        r#"{"entity":"project-admins-demo","role":"READER"}"#,
    ] {
        let s = strict();
        upload_as_owner(&s, "a.txt");
        let response = handle(
            &s,
            req(
                "POST",
                &format!("/b/{DEFAULT_BUCKET}/o/a.txt/acl"),
                &[OWNER],
                body.as_bytes(),
            ),
        );
        assert_eq!(response.status, 400, "{body}: {}", text(&response));
        assert_eq!(
            json_body(&response)["error"]["errors"][0]["reason"],
            "invalid"
        );
        assert_eq!(anonymous_public_get(&s, "a.txt").status, 403, "{body}");
    }
    for body in [
        "",
        "{}",
        r#"{"entity":"allUsers"}"#,
        r#"{"role":"READER"}"#,
        "not json",
    ] {
        let s = strict();
        upload_as_owner(&s, "a.txt");
        let response = handle(
            &s,
            req(
                "POST",
                &format!("/b/{DEFAULT_BUCKET}/o/a.txt/acl"),
                &[OWNER],
                body.as_bytes(),
            ),
        );
        assert_eq!(response.status, 400, "{body:?}");
        assert_eq!(
            json_body(&response)["error"]["errors"][0]["reason"],
            "required"
        );
    }
    for entity in [
        "allUsers",
        "allAuthenticatedUsers",
        "user-alice@example.com",
        "group-team@example.com",
        "domain-example.com",
        "project-owners-demo-app",
        "project-editors-demo-app",
        "project-viewers-demo-app",
    ] {
        let s = strict();
        upload_as_owner(&s, "a.txt");
        let response = handle(
            &s,
            req(
                "POST",
                &format!("/b/{DEFAULT_BUCKET}/o/a.txt/acl"),
                &[OWNER],
                json!({"entity": entity, "role": "OWNER"})
                    .to_string()
                    .as_bytes(),
            ),
        );
        assert_eq!(response.status, 200, "{entity}: {}", text(&response));
        assert_eq!(json_body(&response)["entity"], entity);
    }
}

#[test]
fn the_emulator_profile_accepts_any_acl_as_the_official_emulator_does() {
    let s = emulator();
    upload_as_owner(&s, "a.txt");
    let response = handle(
        &s,
        req(
            "POST",
            &format!("/b/{DEFAULT_BUCKET}/o/a.txt/acl"),
            &[OWNER],
            br#"{"entity":"bogus","role":"WRITER"}"#,
        ),
    );
    assert_eq!(response.status, 200);
}

#[test]
fn predefined_acl_public_read_on_an_upload_makes_the_object_public() {
    let s = strict();
    let media = handle(
        &s,
        req(
            "POST",
            &format!(
                "/upload/storage/v1/b/{DEFAULT_BUCKET}/o?uploadType=media&name=media.txt&predefinedAcl=publicRead"
            ),
            &[OWNER, ("content-type", "text/plain")],
            b"hello",
        ),
    );
    assert_eq!(media.status, 200);
    assert_eq!(anonymous_public_get(&s, "media.txt").status, 200);

    let boundary = "fireemu-boundary";
    let body = format!(
        "--{boundary}\r\nContent-Type: application/json\r\n\r\n{{}}\r\n--{boundary}\r\nContent-Type: text/plain\r\n\r\nhello\r\n--{boundary}--"
    );
    let multipart = handle(
        &s,
        req(
            "POST",
            &format!(
                "/upload/storage/v1/b/{DEFAULT_BUCKET}/o?uploadType=multipart&name=multi.txt&predefinedAcl=publicRead"
            ),
            &[
                OWNER,
                ("content-type", &format!("multipart/related; boundary={boundary}")),
            ],
            body.as_bytes(),
        ),
    );
    assert_eq!(multipart.status, 200, "{}", text(&multipart));
    assert_eq!(anonymous_public_get(&s, "multi.txt").status, 200);

    // The resumable session URL repeats the start query, `predefinedAcl` included.
    let start = handle(
        &s,
        req(
            "POST",
            &format!(
                "/upload/storage/v1/b/{DEFAULT_BUCKET}/o?uploadType=resumable&name=resumable.txt&predefinedAcl=publicRead"
            ),
            &[OWNER],
            b"{}",
        ),
    );
    assert_eq!(start.status, 200, "{}", text(&start));
    let location = start
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .map(|(_, v)| v.clone())
        .unwrap();
    let session = location.strip_prefix("http://127.0.0.1:9199").unwrap();
    let finished = handle(&s, req("PUT", session, &[OWNER], b"hello"));
    assert_eq!(finished.status, 200, "{}", text(&finished));
    assert_eq!(anonymous_public_get(&s, "resumable.txt").status, 200);

    // Any other predefined ACL leaves the object private.
    let private = handle(
        &s,
        req(
            "POST",
            &format!(
                "/upload/storage/v1/b/{DEFAULT_BUCKET}/o?uploadType=media&name=private.txt&predefinedAcl=private"
            ),
            &[OWNER, ("content-type", "text/plain")],
            b"hello",
        ),
    );
    assert_eq!(private.status, 200);
    assert_eq!(anonymous_public_get(&s, "private.txt").status, 403);
}

#[test]
fn a_firebase_download_token_url_does_not_need_the_public_bit() {
    let s = strict();
    let upload = handle(
        &s,
        req(
            "POST",
            &format!("/v0/b/{DEFAULT_BUCKET}/o?name=token.txt&uploadType=media"),
            &[OWNER, ("content-type", "text/plain")],
            b"hello",
        ),
    );
    assert_eq!(upload.status, 200, "{}", text(&upload));
    let token = json_body(&upload)["downloadTokens"]
        .as_str()
        .unwrap()
        .to_owned();
    let read = handle(
        &s,
        req(
            "GET",
            &format!("/v0/b/{DEFAULT_BUCKET}/o/token.txt?alt=media&token={token}"),
            &[],
            b"",
        ),
    );
    assert_eq!(read.status, 200);
}

#[test]
fn a_public_bucket_serves_every_object_to_a_credential_less_read() {
    let s = strict();
    s.rules.set_public_buckets([DEFAULT_BUCKET.to_owned()]);
    upload_as_owner(&s, "a.txt");
    seed(&s, NEW_DEFAULT_BUCKET, "a.txt", b"private");
    let read = anonymous_public_get(&s, "a.txt");
    assert_eq!(read.status, 200);
    assert_eq!(read.body.as_ref(), b"hello");
    // Another bucket stays private, and a missing object in the public bucket is a 404.
    let other = handle(
        &s,
        req("GET", &format!("/{NEW_DEFAULT_BUCKET}/a.txt"), &[], b""),
    );
    assert_eq!(other.status, 403);
    assert_eq!(anonymous_public_get(&s, "missing.txt").status, 404);
}

#[test]
fn the_refusal_names_both_ways_to_make_an_object_public() {
    let s = strict();
    upload_as_owner(&s, "a.txt");
    let refused = anonymous_public_get(&s, "a.txt");
    assert_eq!(refused.status, 403);
    let body = text(&refused);
    assert!(body.contains("makePublic"), "{body}");
    assert!(body.contains("storage.publicBuckets"), "{body}");
    assert!(body.contains(DEFAULT_BUCKET), "the bucket is named: {body}");
}

// ----------------------------------------------------------------------------------------
// ST-3: a Firebase ID token presented as an OAuth bearer on the JSON API
// ----------------------------------------------------------------------------------------

fn jwt(payload: &Value) -> String {
    use fireemu_core_auth::jwt::base64url_encode;
    format!(
        "{}.{}.{}",
        base64url_encode(br#"{"alg":"RS256","kid":"k","typ":"JWT"}"#),
        base64url_encode(payload.to_string().as_bytes()),
        base64url_encode(b"signature")
    )
}

fn id_token() -> String {
    jwt(&json!({
        "iss": "https://securetoken.google.com/demo-app",
        "aud": "demo-app",
        "sub": "alice",
        "firebase": {"sign_in_provider": "password", "identities": {}}
    }))
}

#[test]
fn strict_refuses_a_firebase_id_token_as_a_bearer_on_every_json_api_route() {
    let s = strict();
    seed(&s, DEFAULT_BUCKET, "a.txt", b"hello");
    let bearer = format!("Bearer {}", id_token());
    let routes = [
        (
            "GET",
            format!("/storage/v1/b/{DEFAULT_BUCKET}/o/a.txt?alt=media"),
            "",
        ),
        ("GET", format!("/storage/v1/b/{DEFAULT_BUCKET}/o"), ""),
        (
            "DELETE",
            format!("/storage/v1/b/{DEFAULT_BUCKET}/o/a.txt"),
            "",
        ),
        (
            "POST",
            format!("/upload/storage/v1/b/{DEFAULT_BUCKET}/o?uploadType=media&name=b.txt"),
            "x",
        ),
        (
            "POST",
            format!("/storage/v1/b/{DEFAULT_BUCKET}/o/a.txt/copyTo/b/{DEFAULT_BUCKET}/o/c.txt"),
            "",
        ),
        (
            "POST",
            format!("/b/{DEFAULT_BUCKET}/o/a.txt/acl"),
            r#"{"entity":"allUsers","role":"READER"}"#,
        ),
        ("GET", format!("/{DEFAULT_BUCKET}/a.txt"), ""),
        (
            "PATCH",
            format!("/storage/v1/b/{DEFAULT_BUCKET}/o/a.txt"),
            "{}",
        ),
    ];
    for (method, path, body) in routes {
        let response = handle(
            &s,
            req(
                method,
                &path,
                &[("authorization", &bearer)],
                body.as_bytes(),
            ),
        );
        assert_eq!(response.status, 401, "{method} {path}: {}", text(&response));
        assert_eq!(
            json_body(&response)["error"]["message"],
            "Invalid Credentials"
        );
    }
    // Nothing changed.
    assert!(handle(
        &s,
        req("GET", &format!("/{DEFAULT_BUCKET}/a.txt"), &[OWNER], b"")
    )
    .body
    .as_ref()
    .eq(b"hello"));
}

#[test]
fn a_bearer_that_is_not_a_firebase_id_token_is_still_served_on_the_json_api() {
    let s = strict();
    seed(&s, DEFAULT_BUCKET, "a.txt", b"hello");
    let service_account = jwt(
        &json!({"iss": "sa@demo-app.iam.gserviceaccount.com", "aud": "https://storage.googleapis.com/"}),
    );
    let issuer_only_lookalike =
        jwt(&json!({"iss": "https://example.com/securetoken.google.com/", "sub": "x"}));
    for credential in [
        "Bearer owner".to_owned(),
        "Bearer ya29.a0AfH6SMBx".to_owned(),
        "Bearer opaque".to_owned(),
        format!("Bearer {service_account}"),
        format!("Bearer {issuer_only_lookalike}"),
        "Bearer a.b.c".to_owned(),
        "Bearer one.two".to_owned(),
        "Bearer a.b.c.d".to_owned(),
    ] {
        let response = handle(
            &s,
            req(
                "GET",
                &format!("/storage/v1/b/{DEFAULT_BUCKET}/o/a.txt"),
                &[("authorization", &credential)],
                b"",
            ),
        );
        assert_eq!(response.status, 200, "{credential}: {}", text(&response));
    }
}

#[test]
fn either_claim_alone_makes_a_bearer_a_firebase_id_token() {
    let s = strict();
    seed(&s, DEFAULT_BUCKET, "a.txt", b"hello");
    let only_firebase_claim =
        jwt(&json!({"iss": "https://example.com/", "firebase": {"sign_in_provider": "custom"}}));
    let only_issuer =
        jwt(&json!({"iss": "https://securetoken.google.com/demo-app", "sub": "alice"}));
    let firebase_claim_not_an_object =
        jwt(&json!({"iss": "https://example.com/", "firebase": "yes"}));
    for (token, refused) in [
        (only_firebase_claim, true),
        (only_issuer, true),
        (firebase_claim_not_an_object, false),
    ] {
        let response = handle(
            &s,
            req(
                "GET",
                &format!("/storage/v1/b/{DEFAULT_BUCKET}/o/a.txt"),
                &[("authorization", &format!("Bearer {token}"))],
                b"",
            ),
        );
        assert_eq!(response.status, if refused { 401 } else { 200 }, "{token}");
    }
}

#[test]
fn the_id_token_refusal_is_strict_only_and_json_api_only() {
    let token = id_token();
    let s = emulator();
    seed(&s, DEFAULT_BUCKET, "a.txt", b"hello");
    let json_api = handle(
        &s,
        req(
            "GET",
            &format!("/storage/v1/b/{DEFAULT_BUCKET}/o/a.txt"),
            &[("authorization", &format!("Bearer {token}"))],
            b"",
        ),
    );
    assert_eq!(
        json_api.status, 200,
        "the official emulator ignores the credential"
    );
    // The Firebase dialect reads the same credential as an end user's token: not this refusal.
    let s = strict();
    seed(&s, DEFAULT_BUCKET, "a.txt", b"hello");
    let firebase = handle(
        &s,
        req(
            "GET",
            &format!("/v0/b/{DEFAULT_BUCKET}/o/a.txt"),
            &[("authorization", &format!("Firebase {token}"))],
            b"",
        ),
    );
    assert_ne!(
        json_body(&firebase)["error"]["message"],
        "Invalid Credentials",
        "{}",
        text(&firebase)
    );
}

// ----------------------------------------------------------------------------------------
// ST-4: signed URLs
// ----------------------------------------------------------------------------------------

fn signed_get(s: &StorageState, date: &str, expires: &str) -> StorageResponse {
    handle(
        s,
        req(
            "GET",
            &format!(
                "/{DEFAULT_BUCKET}/a.txt?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=sa%40demo-app.iam.gserviceaccount.com%2F20260829%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date={date}&X-Goog-Expires={expires}&X-Goog-SignedHeaders=host&X-Goog-Signature=0123abcd"
            ),
            &[],
            b"",
        ),
    )
}

#[test]
fn a_signed_url_reads_a_private_object_until_it_expires() {
    let s = strict();
    seed(&s, DEFAULT_BUCKET, "a.txt", b"hello");
    // The run's clock is 2026-08-29T12:01:00Z.
    let live = signed_get(&s, "20260829T120000Z", "3600");
    assert_eq!(live.status, 200, "{}", text(&live));
    assert_eq!(live.body.as_ref(), b"hello");
    let expired = signed_get(&s, "20260829T100000Z", "60");
    assert_eq!(expired.status, 400);
    assert!(
        text(&expired).contains("<Code>ExpiredToken</Code>"),
        "{}",
        text(&expired)
    );
    assert!(!text(&expired).contains("hello"));
    let invalid = signed_get(&s, "20260829T120000Z", "9999999");
    assert_eq!(invalid.status, 400);
    assert!(text(&invalid).contains("<Code>InvalidArgument</Code>"));
}

#[test]
fn a_signed_url_follows_the_virtual_clock() {
    let s = strict();
    seed(&s, DEFAULT_BUCKET, "a.txt", b"hello");
    assert_eq!(signed_get(&s, "20260829T120000Z", "120").status, 200);
    let _ =
        s.clock
            .lock()
            .unwrap()
            .advance(fireemu_core_types::time::LogicalDuration::from_millis(
                120_000,
            ));
    assert_eq!(signed_get(&s, "20260829T120000Z", "120").status, 400);
}

#[test]
fn a_v2_signed_url_expires_at_its_unix_time() {
    let s = strict();
    seed(&s, DEFAULT_BUCKET, "a.txt", b"hello");
    let get = |expires: i64| {
        handle(
            &s,
            req(
                "GET",
                &format!(
                    "/{DEFAULT_BUCKET}/a.txt?GoogleAccessId=sa%40demo-app.iam.gserviceaccount.com&Expires={expires}&Signature=abc"
                ),
                &[],
                b"",
            ),
        )
    };
    assert_eq!(get(1_788_004_860).status, 200);
    assert_eq!(get(1_788_004_859).status, 400);
}

#[test]
fn the_emulator_profile_ignores_a_signed_urls_expiry() {
    let s = emulator();
    seed(&s, DEFAULT_BUCKET, "a.txt", b"hello");
    assert_eq!(signed_get(&s, "20260829T100000Z", "60").status, 200);
}

// ----------------------------------------------------------------------------------------
// ST-5: the form (POST policy) upload
// ----------------------------------------------------------------------------------------

fn base64(text: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in text.as_bytes().chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
        for _ in chunk.len()..3 {
            out.push('=');
        }
    }
    out
}

fn form_post(
    s: &StorageState,
    bucket: &str,
    fields: &[(&str, &str)],
    file: &[u8],
) -> StorageResponse {
    let boundary = "fireemu-form";
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
                .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f.txt\"\r\nContent-Type: text/plain\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(file);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    handle(
        s,
        req(
            "POST",
            &format!("/{bucket}"),
            &[(
                "content-type",
                &format!("multipart/form-data; boundary={boundary}"),
            )],
            &body,
        ),
    )
}

fn signed_policy(conditions: &Value, expiration: &str) -> String {
    base64(&json!({"expiration": expiration, "conditions": conditions}).to_string())
}

fn object_exists(s: &StorageState, bucket: &str, name: &str) -> bool {
    s.store
        .lock()
        .unwrap()
        .get(
            &BucketName::try_new(bucket).unwrap(),
            &ObjectName::try_new(name).unwrap(),
        )
        .is_some()
}

#[test]
fn strict_refuses_a_form_upload_with_no_signed_policy() {
    let s = strict();
    let response = form_post(&s, DEFAULT_BUCKET, &[("key", "up/a.txt")], b"hello");
    assert_eq!(response.status, 403);
    assert!(
        text(&response).contains("<Code>AccessDenied</Code>"),
        "{}",
        text(&response)
    );
    assert!(!object_exists(&s, DEFAULT_BUCKET, "up/a.txt"));
    // A policy with no signature is just as anonymous.
    let policy = signed_policy(&json!([]), "2026-08-29T13:00:00Z");
    let unsigned = form_post(
        &s,
        DEFAULT_BUCKET,
        &[("key", "up/a.txt"), ("policy", &policy)],
        b"hello",
    );
    assert_eq!(unsigned.status, 403);
    assert!(!object_exists(&s, DEFAULT_BUCKET, "up/a.txt"));
}

#[test]
fn a_signed_policy_whose_conditions_hold_stores_the_object() {
    let s = strict();
    let policy = signed_policy(
        &json!([
            {"bucket": DEFAULT_BUCKET},
            ["starts-with", "$key", "up/"],
            ["content-length-range", 1, 10],
            {"x-goog-meta-owner": "alice"}
        ]),
        "2026-08-29T13:00:00Z",
    );
    let response = form_post(
        &s,
        DEFAULT_BUCKET,
        &[
            ("key", "up/a.txt"),
            ("policy", &policy),
            ("x-goog-algorithm", "GOOG4-RSA-SHA256"),
            ("x-goog-signature", "abcdef"),
            ("x-goog-meta-owner", "alice"),
        ],
        b"hello",
    );
    assert_eq!(response.status, 204, "{}", text(&response));
    assert!(object_exists(&s, DEFAULT_BUCKET, "up/a.txt"));
}

#[test]
fn a_form_that_breaks_its_policy_stores_nothing() {
    #[allow(clippy::type_complexity)]
    let cases: [(&str, Value, &str, &[u8], u16, &str); 6] = [
        (
            "expired",
            json!([]),
            "2026-08-29T12:00:59Z",
            b"hello",
            400,
            "ExpiredToken",
        ),
        (
            "key prefix",
            json!([["starts-with", "$key", "other/"]]),
            "2026-08-29T13:00:00Z",
            b"hello",
            400,
            "InvalidPolicyDocument",
        ),
        (
            "bucket",
            json!([{"bucket": "another-bucket"}]),
            "2026-08-29T13:00:00Z",
            b"hello",
            400,
            "InvalidPolicyDocument",
        ),
        (
            "too large",
            json!([["content-length-range", 0, 4]]),
            "2026-08-29T13:00:00Z",
            b"hello",
            400,
            "EntityTooLarge",
        ),
        (
            "too small",
            json!([["content-length-range", 6, 10]]),
            "2026-08-29T13:00:00Z",
            b"hello",
            400,
            "EntityTooSmall",
        ),
        (
            "malformed",
            json!([["between", "$key", "a"]]),
            "2026-08-29T13:00:00Z",
            b"hello",
            400,
            "InvalidPolicyDocument",
        ),
    ];
    for (label, conditions, expiration, file, status, code) in cases {
        let s = strict();
        let policy = signed_policy(&conditions, expiration);
        let response = form_post(
            &s,
            DEFAULT_BUCKET,
            &[
                ("key", "up/a.txt"),
                ("policy", &policy),
                ("x-goog-signature", "abcdef"),
            ],
            file,
        );
        assert_eq!(response.status, status, "{label}: {}", text(&response));
        assert!(
            text(&response).contains(&format!("<Code>{code}</Code>")),
            "{label}: {}",
            text(&response)
        );
        assert!(!object_exists(&s, DEFAULT_BUCKET, "up/a.txt"), "{label}");
    }
}

#[test]
fn a_form_upload_names_its_object_as_strictly_as_every_other_upload() {
    let s = strict();
    let policy = signed_policy(&json!([]), "2026-08-29T13:00:00Z");
    let response = form_post(
        &s,
        DEFAULT_BUCKET,
        &[
            ("key", "bad\nname.txt"),
            ("policy", &policy),
            ("x-goog-signature", "abc"),
        ],
        b"hello",
    );
    assert_eq!(response.status, 400, "{}", text(&response));
    assert!(text(&response).contains("Disallowed unicode characters"));
    assert!(s.store.lock().unwrap().buckets().is_empty());
}

#[test]
fn the_emulator_profile_stores_a_form_upload_with_no_policy() {
    let s = emulator();
    let response = form_post(&s, DEFAULT_BUCKET, &[("key", "up/a.txt")], b"hello");
    assert_eq!(response.status, 204);
    assert!(object_exists(&s, DEFAULT_BUCKET, "up/a.txt"));
}

// ----------------------------------------------------------------------------------------
// ST-9: malformed list parameters on the Firebase dialect
// ----------------------------------------------------------------------------------------

fn firebase_list(s: &StorageState, query: &str) -> StorageResponse {
    handle(
        s,
        req(
            "GET",
            &format!("/v0/b/{DEFAULT_BUCKET}/o?{query}"),
            &[OWNER],
            b"",
        ),
    )
}

#[test]
fn strict_refuses_a_malformed_max_results_or_page_token_instead_of_listing_from_the_start() {
    let s = strict();
    for name in ["a", "b", "c"] {
        seed(&s, DEFAULT_BUCKET, name, b"x");
    }
    for query in [
        "maxResults=abc",
        "maxResults=-1",
        "maxResults=1.5",
        "maxResults=",
        "pageToken=%25%25%25",
        "pageToken=%00%FF",
    ] {
        let response = firebase_list(&s, query);
        assert_eq!(response.status, 400, "{query}: {}", text(&response));
        assert!(json_body(&response)["items"].is_null(), "{query}");
    }
    // The recorded refusal of 0 is unchanged, and well-formed values still page.
    assert_eq!(firebase_list(&s, "maxResults=0").status, 400);
    let first = firebase_list(&s, "maxResults=2");
    assert_eq!(first.status, 200);
    let token = json_body(&first)["nextPageToken"]
        .as_str()
        .unwrap()
        .to_owned();
    let encoded = token
        .replace('=', "%3D")
        .replace('+', "%2B")
        .replace('/', "%2F");
    let second = firebase_list(&s, &format!("maxResults=2&pageToken={encoded}"));
    assert_eq!(second.status, 200, "{}", text(&second));
    assert_eq!(json_body(&second)["items"].as_array().unwrap().len(), 1);
    assert_eq!(firebase_list(&s, "maxResults=1000").status, 200);
}

#[test]
fn the_emulator_profile_ignores_malformed_list_parameters_as_the_official_emulator_does() {
    let s = emulator();
    seed(&s, DEFAULT_BUCKET, "a", b"x");
    for query in ["maxResults=abc", "pageToken=%25%25%25"] {
        let response = firebase_list(&s, query);
        assert_eq!(response.status, 200, "{query}: {}", text(&response));
        assert_eq!(json_body(&response)["items"].as_array().unwrap().len(), 1);
    }
}

// ----------------------------------------------------------------------------------------
// ST-6: which default bucket exists (opt-in)
// ----------------------------------------------------------------------------------------

#[test]
fn both_default_bucket_names_exist_unless_one_is_chosen() {
    use fireemu_adapter_http::storage::DefaultBuckets;
    let resource = |s: &StorageState, bucket: &str| {
        handle(
            s,
            req("GET", &format!("/storage/v1/b/{bucket}"), &[OWNER], b""),
        )
        .status
    };
    let write = |s: &StorageState, bucket: &str| {
        handle(
            s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{bucket}/o?uploadType=media&name=a.txt"),
                &[OWNER, ("content-type", "text/plain")],
                b"x",
            ),
        )
        .status
    };
    let listed_first = |s: &StorageState| {
        json_body(&handle(s, req("GET", "/b", &[OWNER], b"")))["items"][0]["name"]
            .as_str()
            .unwrap()
            .to_owned()
    };

    let s = strict();
    let seen = noting(&s);
    assert_eq!(
        (
            resource(&s, DEFAULT_BUCKET),
            resource(&s, NEW_DEFAULT_BUCKET)
        ),
        (200, 200)
    );
    assert_eq!(listed_first(&s), DEFAULT_BUCKET);
    assert_eq!(
        (write(&s, DEFAULT_BUCKET), write(&s, NEW_DEFAULT_BUCKET)),
        (200, 200)
    );
    assert!(seen.lock().unwrap().is_empty());

    // The new name only: the legacy name becomes an undeclared bucket, which is still served.
    let s = strict();
    let seen = noting(&s);
    s.rules
        .set_default_buckets(DefaultBuckets::FirebaseStorageApp);
    assert_eq!(
        (
            resource(&s, DEFAULT_BUCKET),
            resource(&s, NEW_DEFAULT_BUCKET)
        ),
        (404, 200)
    );
    assert_eq!(listed_first(&s), NEW_DEFAULT_BUCKET);
    assert_eq!(write(&s, NEW_DEFAULT_BUCKET), 200);
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(
        write(&s, DEFAULT_BUCKET),
        200,
        "served, as any undeclared bucket is"
    );
    assert_eq!(*seen.lock().unwrap(), [DEFAULT_BUCKET]);

    // The legacy name only.
    let s = strict();
    s.rules.set_default_buckets(DefaultBuckets::AppspotCom);
    assert_eq!(
        (
            resource(&s, DEFAULT_BUCKET),
            resource(&s, NEW_DEFAULT_BUCKET)
        ),
        (200, 404)
    );
    assert_eq!(listed_first(&s), DEFAULT_BUCKET);

    // A declared bucket of either name still exists, and the emulator profile ignores the choice.
    let s = strict();
    s.rules
        .set_default_buckets(DefaultBuckets::FirebaseStorageApp);
    s.rules.set_configured_buckets([DEFAULT_BUCKET.to_owned()]);
    assert_eq!(resource(&s, DEFAULT_BUCKET), 200);
    let s = emulator();
    s.rules
        .set_default_buckets(DefaultBuckets::FirebaseStorageApp);
    assert_eq!(resource(&s, DEFAULT_BUCKET), 200);
    assert_eq!(listed_first(&s), DEFAULT_BUCKET);
}

// ----------------------------------------------------------------------------------------
// Review fixes: client libraries, credential forms, ACL paths, emulator profile, notes, names
// ----------------------------------------------------------------------------------------

#[test]
fn a_google_client_library_read_without_credentials_is_admitted_and_a_plain_fetch_is_not() {
    // The Go client library reads through the XML API with no Authorization header against an
    // emulator host and sends `x-goog-api-client` on every request; a browser fetch of a public
    // URL does not.
    let s = strict();
    upload_as_owner(&s, "a.txt");
    let library = handle(
        &s,
        req(
            "GET",
            &format!("/{DEFAULT_BUCKET}/a.txt"),
            &[(
                "x-goog-api-client",
                "gl-go/1.22 gccl/1.50.0 gccl-invocation-id/x",
            )],
            b"",
        ),
    );
    assert_eq!(library.status, 200, "{}", text(&library));
    assert_eq!(library.body.as_ref(), b"hello");
    assert_eq!(anonymous_public_get(&s, "a.txt").status, 403);
    let blank = handle(
        &s,
        req(
            "GET",
            &format!("/{DEFAULT_BUCKET}/a.txt"),
            &[("x-goog-api-client", "")],
            b"",
        ),
    );
    assert_eq!(blank.status, 403, "an empty header proves nothing");
}

#[test]
fn only_a_non_empty_bearer_counts_as_a_credential_on_the_public_url() {
    let s = strict();
    upload_as_owner(&s, "a.txt");
    let status = |authorization: &str| {
        handle(
            &s,
            req(
                "GET",
                &format!("/{DEFAULT_BUCKET}/a.txt"),
                &[("authorization", authorization)],
                b"",
            ),
        )
        .status
    };
    for served in ["Bearer owner", "Bearer ya29.a0AfH6", "Bearer x"] {
        assert_eq!(status(served), 200, "{served}");
    }
    for refused in [
        "",
        "Bearer",
        "Bearer ",
        "Basic dXNlcjpwdw==",
        "Firebase abc.def.ghi",
        "bearer x",
    ] {
        assert_eq!(status(refused), 403, "{refused:?}");
    }
}

fn is_public(s: &StorageState, bucket: &str, name: &str) -> bool {
    handle(s, req("GET", &format!("/{bucket}/{name}"), &[], b"")).status == 200
}

#[test]
fn a_copy_or_rewrite_is_private_unless_it_asks_for_a_public_destination() {
    for verb in ["copyTo", "rewriteTo"] {
        let s = strict();
        upload_as_owner(&s, "a.txt");
        assert_eq!(make_public(&s, "a.txt", false).status, 200);
        let copy = |dst: &str, query: &str| {
            handle(
                &s,
                req(
                    "POST",
                    &format!(
                        "/storage/v1/b/{DEFAULT_BUCKET}/o/a.txt/{verb}/b/{DEFAULT_BUCKET}/o/{dst}{query}"
                    ),
                    &[OWNER],
                    b"",
                ),
            )
        };
        assert_eq!(copy("private.txt", "").status, 200, "{verb}");
        assert!(
            !is_public(&s, DEFAULT_BUCKET, "private.txt"),
            "{verb}: a copy is private"
        );
        assert_eq!(
            copy("public.txt", "?destinationPredefinedAcl=publicRead").status,
            200
        );
        assert!(is_public(&s, DEFAULT_BUCKET, "public.txt"), "{verb}");
        assert_eq!(
            copy("other.txt", "?destinationPredefinedAcl=private").status,
            200
        );
        assert!(!is_public(&s, DEFAULT_BUCKET, "other.txt"), "{verb}");
    }
}

#[test]
fn a_multipart_upload_whose_resource_carries_an_all_users_reader_acl_is_public() {
    let s = strict();
    let upload = |name: &str, resource: Value| {
        let boundary = "fireemu-boundary";
        let body = format!(
            "--{boundary}\r\nContent-Type: application/json\r\n\r\n{resource}\r\n--{boundary}\r\nContent-Type: text/plain\r\n\r\nhello\r\n--{boundary}--"
        );
        handle(
            &s,
            req(
                "POST",
                &format!(
                    "/upload/storage/v1/b/{DEFAULT_BUCKET}/o?uploadType=multipart&name={name}"
                ),
                &[
                    OWNER,
                    (
                        "content-type",
                        &format!("multipart/related; boundary={boundary}"),
                    ),
                ],
                body.as_bytes(),
            ),
        )
        .status
    };
    assert_eq!(
        upload(
            "public.txt",
            json!({"acl": [{"entity": "allUsers", "role": "READER"}]})
        ),
        200
    );
    assert!(is_public(&s, DEFAULT_BUCKET, "public.txt"));
    assert_eq!(
        upload(
            "owner-only.txt",
            json!({"acl": [{"entity": "user-a@b.c", "role": "OWNER"}]})
        ),
        200
    );
    assert!(!is_public(&s, DEFAULT_BUCKET, "owner-only.txt"));
    // The entry needs both halves: the public entity with another role, another entity with READER.
    assert_eq!(
        upload(
            "all-owner.txt",
            json!({"acl": [{"entity": "allUsers", "role": "OWNER"}]})
        ),
        200
    );
    assert!(!is_public(&s, DEFAULT_BUCKET, "all-owner.txt"));
    assert_eq!(
        upload(
            "user-reader.txt",
            json!({"acl": [{"entity": "user-a@b.c", "role": "READER"}]})
        ),
        200
    );
    assert!(!is_public(&s, DEFAULT_BUCKET, "user-reader.txt"));
    assert_eq!(upload("plain.txt", json!({})), 200);
    assert!(!is_public(&s, DEFAULT_BUCKET, "plain.txt"));
}

#[test]
fn make_private_and_a_deleted_all_users_entry_end_the_public_bit() {
    let patch = |s: &StorageState, query: &str, body: &str| {
        handle(
            s,
            req(
                "PATCH",
                &format!("/storage/v1/b/{DEFAULT_BUCKET}/o/a.txt{query}"),
                &[OWNER],
                body.as_bytes(),
            ),
        )
        .status
    };
    for (label, undo) in [
        ("predefinedAcl=private", ("?predefinedAcl=private", "{}")),
        (
            "predefinedAcl=projectPrivate",
            ("?predefinedAcl=projectPrivate", "{}"),
        ),
        ("acl: []", ("", r#"{"acl":[]}"#)),
        (
            "acl without allUsers",
            ("", r#"{"acl":[{"entity":"user-a@b.c","role":"OWNER"}]}"#),
        ),
    ] {
        let s = strict();
        upload_as_owner(&s, "a.txt");
        make_public(&s, "a.txt", false);
        assert!(is_public(&s, DEFAULT_BUCKET, "a.txt"));
        assert_eq!(patch(&s, undo.0, undo.1), 200, "{label}");
        assert!(!is_public(&s, DEFAULT_BUCKET, "a.txt"), "{label}");
    }
    // A patch that says nothing about the ACL leaves it, and one that grants it makes it public.
    let s = strict();
    upload_as_owner(&s, "a.txt");
    make_public(&s, "a.txt", false);
    assert_eq!(patch(&s, "", r#"{"contentType":"text/x"}"#), 200);
    assert!(is_public(&s, DEFAULT_BUCKET, "a.txt"));
    let s = strict();
    upload_as_owner(&s, "a.txt");
    assert_eq!(
        patch(&s, "", r#"{"acl":[{"entity":"allUsers","role":"READER"}]}"#),
        200
    );
    assert!(is_public(&s, DEFAULT_BUCKET, "a.txt"));
    let s = strict();
    upload_as_owner(&s, "a.txt");
    assert_eq!(patch(&s, "?predefinedAcl=publicRead", "{}"), 200);
    assert!(is_public(&s, DEFAULT_BUCKET, "a.txt"));

    for path in [
        format!("/b/{DEFAULT_BUCKET}/o/a.txt/acl/allUsers"),
        format!("/storage/v1/b/{DEFAULT_BUCKET}/o/a.txt/acl/allUsers"),
    ] {
        let s = strict();
        upload_as_owner(&s, "a.txt");
        make_public(&s, "a.txt", false);
        let other = handle(
            &s,
            req(
                "DELETE",
                &path.replace("allUsers", "user-a%40b.c"),
                &[OWNER],
                b"",
            ),
        );
        assert_eq!(other.status, 204);
        assert!(
            is_public(&s, DEFAULT_BUCKET, "a.txt"),
            "another entity's entry is not the public one"
        );
        let deleted = handle(&s, req("DELETE", &path, &[OWNER], b""));
        assert_eq!(deleted.status, 204, "{path}: {}", text(&deleted));
        assert!(!is_public(&s, DEFAULT_BUCKET, "a.txt"), "{path}");
        let missing = handle(
            &s,
            req(
                "DELETE",
                &path.replace("a.txt", "missing.txt"),
                &[OWNER],
                b"",
            ),
        );
        assert_eq!(missing.status, 404, "{path}");
    }
}

#[test]
fn deleting_an_acl_entry_is_the_official_emulators_501_outside_strict() {
    let s = emulator();
    upload_as_owner(&s, "a.txt");
    for path in [
        format!("/b/{DEFAULT_BUCKET}/o/a.txt/acl/allUsers"),
        format!("/storage/v1/b/{DEFAULT_BUCKET}/o/a.txt/acl/allUsers"),
    ] {
        assert_eq!(
            handle(&s, req("DELETE", &path, &[OWNER], b"")).status,
            501,
            "{path}"
        );
    }
}

#[test]
fn the_emulator_profile_ignores_the_bucket_lists() {
    for acceptance in [TokenAcceptance::Verified, TokenAcceptance::EmulatorMock] {
        let s = state(acceptance);
        s.rules.set_configured_buckets(["listed-bucket".to_owned()]);
        s.rules.set_public_buckets(["public-bucket".to_owned()]);
        let status = |bucket: &str| {
            handle(
                &s,
                req("GET", &format!("/storage/v1/b/{bucket}"), &[OWNER], b""),
            )
            .status
        };
        let strict_profile = acceptance == TokenAcceptance::Verified;
        let expected = if strict_profile { 200 } else { 404 };
        assert_eq!(status("listed-bucket"), expected, "{acceptance:?}");
        assert_eq!(status("public-bucket"), expected, "{acceptance:?}");
        let listed = json_body(&handle(&s, req("GET", "/b", &[OWNER], b"")));
        let names: Vec<&str> = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|i| i["name"].as_str())
            .collect();
        assert_eq!(
            names.contains(&"listed-bucket"),
            strict_profile,
            "{acceptance:?} {names:?}"
        );
        assert_eq!(
            names.contains(&"public-bucket"),
            strict_profile,
            "{acceptance:?} {names:?}"
        );
        assert!(names.contains(&DEFAULT_BUCKET));
    }
}

#[test]
fn a_refused_write_to_an_undeclared_bucket_is_not_noted() {
    // A form upload against its policy.
    let s = strict();
    let seen = noting(&s);
    let policy = signed_policy(
        &json!([["content-length-range", 0, 1]]),
        "2026-08-29T13:00:00Z",
    );
    let refused = form_post(
        &s,
        "typo-bucket",
        &[
            ("key", "a.txt"),
            ("policy", &policy),
            ("x-goog-signature", "abc"),
        ],
        b"too long",
    );
    assert_eq!(refused.status, 400);
    // A Firebase upload the rules deny.
    s.rules
        .replace_loaded(
            fireemu_core_rules::runtime::LoadedRules::from_source(
                "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read: if true; allow write: if false; } } }",
            )
            .unwrap(),
        )
        .unwrap();
    let denied = handle(
        &s,
        req(
            "POST",
            "/v0/b/typo-bucket/o?name=a.txt&uploadType=media",
            &[("content-type", "text/plain")],
            b"x",
        ),
    );
    assert_eq!(denied.status, 403);
    // A copy whose source is missing.
    let missing = handle(
        &s,
        req(
            "POST",
            &format!("/storage/v1/b/{DEFAULT_BUCKET}/o/none.txt/copyTo/b/typo-bucket/o/b.txt"),
            &[OWNER],
            b"",
        ),
    );
    assert_eq!(missing.status, 404);
    assert!(
        seen.lock().unwrap().is_empty(),
        "{:?}",
        seen.lock().unwrap()
    );
    // The same bucket is noted once a write to it succeeds.
    let ok = handle(
        &s,
        req(
            "POST",
            "/upload/storage/v1/b/typo-bucket/o?uploadType=media&name=a.txt",
            &[OWNER, ("content-type", "text/plain")],
            b"x",
        ),
    );
    assert_eq!(ok.status, 200);
    assert_eq!(*seen.lock().unwrap(), ["typo-bucket"]);
}

#[test]
fn strict_refuses_a_bucket_name_cloud_storage_never_accepts_unless_such_a_bucket_exists() {
    for name in ["ab", "goog-x", "1.2.3.4", "a..b", "-abc", "abc-"] {
        let s = strict();
        let json = handle(
            &s,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{name}/o?uploadType=media&name=a.txt"),
                &[OWNER, ("content-type", "text/plain")],
                b"x",
            ),
        );
        assert_eq!(json.status, 400, "{name}: {}", text(&json));
        assert_eq!(
            json_body(&json)["error"]["message"],
            format!("Invalid bucket name: '{name}'")
        );
        let read = handle(
            &s,
            req(
                "GET",
                &format!("/storage/v1/b/{name}/o/a.txt"),
                &[OWNER],
                b"",
            ),
        );
        assert_eq!(read.status, 400, "{name}");
        for path in [format!("/v0/b/{name}/o/a.txt"), format!("/v0/b/{name}/o")] {
            let firebase = handle(&s, req("GET", &path, &[OWNER], b""));
            assert_eq!(firebase.status, 404, "{path}");
            assert!(
                text(&firebase).contains("Could not access bucket"),
                "{path}: {}",
                text(&firebase)
            );
        }
        seed(&s, DEFAULT_BUCKET, "src.txt", b"hello");
        for to_invalid in [
            format!("/storage/v1/b/{DEFAULT_BUCKET}/o/src.txt/copyTo/b/{name}/o/b.txt"),
            format!("/storage/v1/b/{name}/o/src.txt/copyTo/b/{DEFAULT_BUCKET}/o/b.txt"),
        ] {
            let copy = handle(&s, req("POST", &to_invalid, &[OWNER], b""));
            assert_eq!(copy.status, 400, "{to_invalid}: {}", text(&copy));
        }
        let xml = handle(&s, req("GET", &format!("/{name}/a.txt"), &[OWNER], b""));
        assert_eq!(xml.status, 400, "{name}");
        assert!(text(&xml).contains("InvalidBucketName"));
        assert!(!has_bucket(&s, name), "{name}");

        // The emulator profile is the official emulator's: it creates the bucket.
        let e = emulator();
        let created = handle(
            &e,
            req(
                "POST",
                &format!("/upload/storage/v1/b/{name}/o?uploadType=media&name=a.txt"),
                &[OWNER, ("content-type", "text/plain")],
                b"x",
            ),
        );
        assert_eq!(created.status, 200, "{name}");

        // A bucket that exists, imported or declared, is never refused for its name.
        let s = strict();
        seed(&s, name, "a.txt", b"hello");
        let read = handle(
            &s,
            req(
                "GET",
                &format!("/storage/v1/b/{name}/o/a.txt"),
                &[OWNER],
                b"",
            ),
        );
        assert_eq!(read.status, 200, "{name}");
    }
    // A valid undeclared name is still served (noted), and a resumable continuation is not rechecked.
    let s = strict();
    let ok = handle(
        &s,
        req(
            "POST",
            "/upload/storage/v1/b/valid-name/o?uploadType=media&name=a.txt",
            &[OWNER, ("content-type", "text/plain")],
            b"x",
        ),
    );
    assert_eq!(ok.status, 200);
}
