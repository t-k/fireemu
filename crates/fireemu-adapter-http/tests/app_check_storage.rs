//! App Check enforcement for Cloud Storage for Firebase (specification sections 12, 13.2, 17
//! and 19; obligations `AC-ST-001`, `AC-BOUNDARY-001` and `AC-HEADER-001`).
//!
//! Milestone AC1 covered the non-resumable operations plus the admission of a resumable start;
//! milestone AC2 added the session binding of section 13.2. The Storage scenarios checked here
//! are 1 (an enforced upload creates no upload session), 2 (a continuation from another app
//! does not advance the offset), 3 (token expiry during a resumable upload preserves the
//! resumable state), 4 (a valid download-token URL follows the explicit bypass) and 5
//! (privileged JSON API traffic follows the explicit bypass).

mod app_check_support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use app_check_support as fixture;
use fireemu_adapter_http::storage::{
    handle, StorageRequest, StorageResponse, StorageServerRequests, StorageState,
};
use fireemu_core_app_check::verify::BaselineMode;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_storage::store::StorageState as ObjectStore;
use fireemu_core_types::determinism::SplitMix64;
use serde_json::Value;

const BUCKET: &str = "demo-app.appspot.com";
const OWNER: (&str, &str) = ("authorization", "Bearer owner");

struct Harness {
    storage: StorageState,
    app_check: Arc<fireemu_adapter_http::app_check::AppCheckState>,
    clock: Arc<Mutex<fireemu_core_session::clock::VirtualClock>>,
}

fn harness(mode: BaselineMode) -> Harness {
    harness_with(mode, StorageServerRequests::Loopback)
}

/// The pre-`storageServerRequests` behaviour: only the per-run capability or the owner
/// credential passes an `enforced` policy on the JSON API.
fn capability_harness(mode: BaselineMode) -> Harness {
    harness_with(mode, StorageServerRequests::Capability)
}

fn harness_with(mode: BaselineMode, server_requests: StorageServerRequests) -> Harness {
    let clock = fixture::clock();
    let app_check = fixture::app_check_state(1, clock.clone());
    let storage = StorageState {
        store: Mutex::new(ObjectStore::new(9)),
        clock: clock.clone(),
        auth: Arc::new(fireemu_core_auth::store::AuthRegistry::new(
            "demo-app",
            Arc::new(Mutex::new(AuthStore::new(
                "demo-app",
                SplitMix64::new(3),
                TotpPolicy::default(),
            ))),
        )),
        tenancy: None,
        rules: Arc::new(fireemu_adapter_http::storage::StorageRulesRegistry::default()),
        project: "demo-app".to_owned(),
        events: None,
        barrier: None,
        firestore: None,
        faults: None,
        clock_observer: None,
        app_check_policy: fixture::policy(&app_check, "storage", mode),
        admin_capability: Some("storage-capability".to_owned()),
        server_requests,
        token_acceptance: fireemu_core_auth::jwt::TokenAcceptance::default(),
        allow_unsigned_id_tokens: false,
        control_token: None,
    };
    Harness {
        storage,
        app_check,
        clock,
    }
}

impl Harness {
    fn call(
        &self,
        method: &str,
        path_and_query: &str,
        headers: &[(&str, &str)],
        app_check: &[&str],
        body: &[u8],
    ) -> StorageResponse {
        self.call_from(false, method, path_and_query, headers, app_check, body)
    }

    /// Like [`Harness::call`], from a peer on `remote` (non-loopback) or loopback.
    fn call_from(
        &self,
        remote_peer: bool,
        method: &str,
        path_and_query: &str,
        headers: &[(&str, &str)],
        app_check: &[&str],
        body: &[u8],
    ) -> StorageResponse {
        self.call_full(
            remote_peer,
            Some("127.0.0.1:9199"),
            method,
            path_and_query,
            headers,
            app_check,
            body,
        )
    }

    /// Like [`Harness::call_from`], with an explicit `Host` (`None`: the request has none).
    #[allow(clippy::too_many_arguments)]
    fn call_full(
        &self,
        remote_peer: bool,
        host: Option<&str>,
        method: &str,
        path_and_query: &str,
        headers: &[(&str, &str)],
        app_check: &[&str],
        body: &[u8],
    ) -> StorageResponse {
        let (path, query) = path_and_query
            .split_once('?')
            .map_or((path_and_query, ""), |(p, q)| (p, q));
        handle(
            &self.storage,
            StorageRequest {
                method: method.to_owned(),
                path: path.to_owned(),
                query: query.to_owned(),
                host: host.map(str::to_owned),
                headers: headers
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect::<BTreeMap<_, _>>(),
                app_check: app_check.iter().map(|v| (*v).to_owned()).collect(),
                body: body.to_vec(),
                remote_peer,
            },
        )
    }

    fn token(&self) -> String {
        fixture::token(&self.app_check, "demo-app", fixture::APP_ID)
    }

    /// A valid token for the *other app of the same project*.
    fn other_app_token(&self) -> String {
        fixture::other_app(&self.app_check)
    }

    /// Moves the virtual clock forward, as the control API clock route does.
    fn advance(&self, seconds: i64) {
        self.clock
            .lock()
            .expect("the clock is not poisoned")
            .advance(fireemu_core_types::time::LogicalDuration::from_seconds(
                seconds,
            ))
            .expect("the fixture clock moves forward");
    }

    /// Starts a resumable upload of six bytes and returns the whole response.
    fn start_resumable(&self, name: &str, app_check: &[&str]) -> StorageResponse {
        self.call(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name={name}"),
            &[
                OWNER,
                ("x-goog-upload-protocol", "resumable"),
                ("x-goog-upload-command", "start"),
                ("x-goog-upload-header-content-type", "application/zip"),
                ("x-goog-upload-header-content-length", "6"),
                ("content-type", "application/json; charset=utf-8"),
            ],
            app_check,
            b"{}",
        )
    }

    /// Uploads one object as owner, bypassing enforcement through the privileged JSON API.
    fn seed_object(&self, name: &str) -> Value {
        let r = self.call(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name={name}&uploadType=media"),
            &[OWNER, ("content-type", "text/plain")],
            &[&self.token()],
            b"hello",
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        serde_json::from_slice(&r.body).expect("the metadata is JSON")
    }
}

fn header<'a>(r: &'a StorageResponse, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn body_of(r: &StorageResponse) -> Value {
    serde_json::from_slice(&r.body).unwrap_or(Value::Null)
}

fn admin_storage_authorization() -> String {
    format!(
        "Basic {}",
        fireemu_core_storage::hash::base64(b"fireemu:storage-capability")
    )
}

// ------------------------------------------------------------------------------------------
// Scenario 1: an enforced upload without App Check creates no upload session
// ------------------------------------------------------------------------------------------

/// The denial happens before the object store is touched at all: the upload-session
/// identifier the next admitted start receives is the one it would have received had the
/// denied request never arrived (`INV-APPCHECK-003`).
#[test]
fn an_enforced_upload_without_app_check_creates_no_upload_session() {
    let start_headers: &[(&str, &str)] = &[
        OWNER,
        ("x-goog-upload-protocol", "resumable"),
        ("x-goog-upload-command", "start"),
        ("x-goog-upload-header-content-type", "application/zip"),
        ("x-goog-upload-header-content-length", "6"),
        ("content-type", "application/json; charset=utf-8"),
    ];
    let path = format!("/v0/b/{BUCKET}/o?name=big.bin");

    let denied_then_admitted = harness(BaselineMode::Enforced);
    let denied = denied_then_admitted.call("POST", &path, start_headers, &[], b"{}");
    assert_eq!(
        denied.status,
        403,
        "{}",
        String::from_utf8_lossy(&denied.body)
    );
    assert_eq!(body_of(&denied)["error"]["status"], "PERMISSION_DENIED");
    assert_eq!(body_of(&denied)["error"]["reason"], "APP_CHECK_REQUIRED");
    assert_eq!(
        header(&denied, "x-goog-upload-url"),
        None,
        "a denied start hands out no upload session URL"
    );
    let token = denied_then_admitted.token();
    let after = denied_then_admitted.call("POST", &path, start_headers, &[&token], b"{}");
    assert_eq!(
        after.status,
        200,
        "{}",
        String::from_utf8_lossy(&after.body)
    );

    let clean = harness(BaselineMode::Enforced);
    let token = clean.token();
    let only = clean.call("POST", &path, start_headers, &[&token], b"{}");
    assert_eq!(only.status, 200);
    assert_eq!(
        header(&after, "x-goog-upload-url"),
        header(&only, "x-goog-upload-url"),
        "the denied start consumed no upload session identifier"
    );
}

/// A simple upload is refused before any generation exists.
#[test]
fn an_enforced_simple_upload_without_app_check_creates_no_object() {
    let h = harness(BaselineMode::Enforced);
    let denied = h.call(
        "POST",
        &format!("/v0/b/{BUCKET}/o?name=note.txt&uploadType=media"),
        &[OWNER, ("content-type", "text/plain")],
        &[],
        b"hello",
    );
    assert_eq!(denied.status, 403);
    let read = h.call(
        "GET",
        &format!("/v0/b/{BUCKET}/o/note.txt"),
        &[OWNER],
        &[&h.token()],
        b"",
    );
    assert_eq!(read.status, 404, "no generation was created");
}

/// A delete is refused before the object is removed.
#[test]
fn an_enforced_delete_without_app_check_leaves_the_object() {
    let h = harness(BaselineMode::Enforced);
    h.seed_object("keep.txt");
    let denied = h.call(
        "DELETE",
        &format!("/v0/b/{BUCKET}/o/keep.txt"),
        &[OWNER],
        &[],
        b"",
    );
    assert_eq!(denied.status, 403);
    let read = h.call(
        "GET",
        &format!("/v0/b/{BUCKET}/o/keep.txt"),
        &[OWNER],
        &[&h.token()],
        b"",
    );
    assert_eq!(read.status, 200, "the object survived the denial");
}

// ------------------------------------------------------------------------------------------
// Scenario 4: a valid download-token URL follows the explicit bypass
// ------------------------------------------------------------------------------------------

#[test]
fn a_valid_download_token_url_follows_the_explicit_bypass() {
    let h = harness(BaselineMode::Enforced);
    let meta = h.seed_object("public.txt");
    let token = meta["downloadTokens"]
        .as_str()
        .expect("a Firebase upload mints a download token")
        .split(',')
        .next()
        .expect("at least one token")
        .to_owned();

    let admitted = h.call(
        "GET",
        &format!("/v0/b/{BUCKET}/o/public.txt?alt=media&token={token}"),
        &[],
        &[],
        b"",
    );
    assert_eq!(
        admitted.status,
        200,
        "{}",
        String::from_utf8_lossy(&admitted.body)
    );
    assert_eq!(admitted.body.as_ref(), b"hello");
}

/// The bypass is the token, not the query parameter: a wrong or absent token is an ordinary
/// end-user download and is refused before the rules run.
#[test]
fn a_download_token_that_does_not_bind_to_the_object_does_not_bypass() {
    let h = harness(BaselineMode::Enforced);
    let meta = h.seed_object("guarded.txt");
    let real = meta["downloadTokens"]
        .as_str()
        .expect("a download token")
        .split(',')
        .next()
        .expect("one token")
        .to_owned();
    h.seed_object("other.txt");

    for (name, query) in [
        ("no token", "alt=media".to_owned()),
        (
            "a token of another object",
            format!(
                "alt=media&token={}",
                body_of(&h.call(
                    "GET",
                    &format!("/v0/b/{BUCKET}/o/other.txt"),
                    &[OWNER],
                    &[&h.token()],
                    b"",
                ))["downloadTokens"]
                    .as_str()
                    .expect("a download token")
                    .split(',')
                    .next()
                    .expect("one token")
            ),
        ),
        (
            "a truncated token",
            format!("alt=media&token={}", &real[..real.len() - 1]),
        ),
        ("an empty token", "alt=media&token=".to_owned()),
    ] {
        let denied = h.call(
            "GET",
            &format!("/v0/b/{BUCKET}/o/guarded.txt?{query}"),
            &[],
            &[],
            b"",
        );
        assert_eq!(denied.status, 403, "{name} must not bypass App Check");
        assert_eq!(body_of(&denied)["error"]["reason"], "APP_CHECK_REQUIRED");
    }
}

// ------------------------------------------------------------------------------------------
// Scenario 5: privileged JSON API traffic follows the explicit bypass
// ------------------------------------------------------------------------------------------

#[test]
fn privileged_json_api_traffic_follows_the_explicit_bypass() {
    let h = harness(BaselineMode::Enforced);
    h.seed_object("listed.txt");
    let listed = h.call(
        "GET",
        &format!("/storage/v1/b/{BUCKET}/o"),
        &[OWNER],
        &[],
        b"",
    );
    assert_eq!(
        listed.status,
        200,
        "the owner credential on the JSON API dialect bypasses: {}",
        String::from_utf8_lossy(&listed.body)
    );
}

/// The bypass is the credential, not the path. A JSON API path bypasses Security Rules
/// without one, as the official Emulator does, but specification section 12.2 grants the App
/// Check bypass to the *authenticated* dialect only: otherwise an enforced Storage service
/// would be defeated by rewriting `/v0/b/...` to `/storage/v1/b/...`.
#[test]
fn an_unauthenticated_json_api_path_never_bypasses_app_check() {
    let h = capability_harness(BaselineMode::Enforced);
    h.seed_object("guarded-json.txt");
    let paths = [
        format!("/storage/v1/b/{BUCKET}/o"),
        format!("/storage/v1/b/{BUCKET}/o/guarded-json.txt"),
        format!("/b/{BUCKET}/o/guarded-json.txt"),
        format!("/download/storage/v1/b/{BUCKET}/o/guarded-json.txt?alt=media"),
        format!("/storage/v1/b/{BUCKET}"),
    ];
    for path in &paths {
        for (name, headers) in [
            ("no credential at all", Vec::new()),
            (
                "an unverified bearer credential",
                vec![("authorization", "Bearer garbage")],
            ),
        ] {
            let denied = h.call("GET", path, &headers, &[], b"");
            assert_eq!(
                denied.status,
                403,
                "{path} with {name}: {}",
                String::from_utf8_lossy(&denied.body)
            );
            assert_eq!(body_of(&denied)["error"]["reason"], "APP_CHECK_REQUIRED");
        }
    }
    // A mutating JSON API route is refused before it creates anything.
    let upload = h.call(
        "POST",
        &format!("/upload/storage/v1/b/{BUCKET}/o?name=json-api.txt&uploadType=media"),
        &[("content-type", "text/plain")],
        &[],
        b"hello",
    );
    assert_eq!(
        upload.status,
        403,
        "{}",
        String::from_utf8_lossy(&upload.body)
    );
    let read = h.call(
        "GET",
        &format!("/v0/b/{BUCKET}/o/json-api.txt"),
        &[OWNER],
        &[&h.token()],
        b"",
    );
    assert_eq!(read.status, 404, "no object was created");
}

/// The same object, through either dialect, reaches the same admission decision when neither
/// carries the dialect's privileged credential.
#[test]
fn both_dialects_enforce_app_check_identically_without_a_privileged_credential() {
    let h = capability_harness(BaselineMode::Enforced);
    h.seed_object("both.txt");
    let firebase = h.call("GET", &format!("/v0/b/{BUCKET}/o/both.txt"), &[], &[], b"");
    let json_api = h.call(
        "GET",
        &format!("/storage/v1/b/{BUCKET}/o/both.txt"),
        &[],
        &[],
        b"",
    );
    assert_eq!(firebase.status, json_api.status);
    assert_eq!(
        body_of(&firebase)["error"]["reason"],
        body_of(&json_api)["error"]["reason"]
    );
    assert_eq!(firebase.status, 403);
}

/// Section 13.2: every mutating resumable request is checked, not only the initiation. AC1
/// admits each continuation on its own token; binding the continuation to the *app* that
/// started the upload is AC2.
#[test]
fn a_resumable_continuation_without_app_check_does_not_advance_the_offset() {
    let h = harness(BaselineMode::Enforced);
    let token = h.token();
    let start = h.call(
        "POST",
        &format!("/v0/b/{BUCKET}/o?name=resume.bin"),
        &[
            OWNER,
            ("x-goog-upload-protocol", "resumable"),
            ("x-goog-upload-command", "start"),
            ("x-goog-upload-header-content-type", "application/zip"),
            ("x-goog-upload-header-content-length", "6"),
            ("content-type", "application/json; charset=utf-8"),
        ],
        &[&token],
        b"{}",
    );
    assert_eq!(
        start.status,
        200,
        "{}",
        String::from_utf8_lossy(&start.body)
    );
    let session = header(&start, "x-goog-upload-url")
        .expect("a session URL")
        .strip_prefix("http://127.0.0.1:9199")
        .expect("the session URL names this host")
        .to_owned();

    let denied = h.call(
        "POST",
        &session,
        &[
            OWNER,
            ("x-goog-upload-command", "upload"),
            ("x-goog-upload-offset", "0"),
        ],
        &[],
        b"abc",
    );
    assert_eq!(
        denied.status,
        403,
        "{}",
        String::from_utf8_lossy(&denied.body)
    );

    let queried = h.call(
        "POST",
        &session,
        &[OWNER, ("x-goog-upload-command", "query")],
        &[&token],
        b"",
    );
    assert_eq!(
        header(&queried, "x-goog-upload-size-received"),
        Some("0"),
        "the denied continuation advanced nothing"
    );
    let resumed = h.call(
        "POST",
        &session,
        &[
            OWNER,
            ("x-goog-upload-command", "upload"),
            ("x-goog-upload-offset", "0"),
        ],
        &[&token],
        b"abc",
    );
    assert_eq!(resumed.status, 200, "the session survived the denial");
}

// ------------------------------------------------------------------------------------------
// Scenario 2: a resumable continuation from another app does not advance the offset
// ------------------------------------------------------------------------------------------

/// Section 13.2: the initiation stores the admitted app, and a continuation must present a
/// valid token for that same app. The other app's token is perfectly valid — it verifies, it
/// names the same project and it carries the current epoch — so this is exactly the case that
/// admitting each request on its own merits would let through.
#[test]
fn a_resumable_continuation_from_another_app_does_not_advance_the_offset() {
    let h = harness(BaselineMode::Enforced);
    let token = h.token();
    let intruder = h.other_app_token();
    let start = h.start_resumable("bound.bin", &[&token]);
    assert_eq!(
        start.status,
        200,
        "{}",
        String::from_utf8_lossy(&start.body)
    );
    let session = header(&start, "x-goog-upload-url")
        .expect("a session URL")
        .strip_prefix("http://127.0.0.1:9199")
        .expect("the session URL names this host")
        .to_owned();

    // The intruder's own admission succeeds; the session binding is what refuses it.
    let denied = h.call(
        "POST",
        &session,
        &[
            OWNER,
            ("x-goog-upload-command", "upload"),
            ("x-goog-upload-offset", "0"),
        ],
        &[&intruder],
        b"abc",
    );
    assert_eq!(
        denied.status,
        403,
        "{}",
        String::from_utf8_lossy(&denied.body)
    );
    assert_eq!(body_of(&denied)["error"]["reason"], "APP_CHECK_INVALID");

    // Neither the offset nor the session moved.
    let queried = h.call(
        "POST",
        &session,
        &[OWNER, ("x-goog-upload-command", "query")],
        &[&token],
        b"",
    );
    assert_eq!(
        header(&queried, "x-goog-upload-size-received"),
        Some("0"),
        "the foreign continuation advanced nothing"
    );
    assert_eq!(header(&queried, "x-goog-upload-status"), Some("active"));

    // A cancel from the intruder cannot delete it either.
    let cancelled = h.call(
        "POST",
        &session,
        &[OWNER, ("x-goog-upload-command", "cancel")],
        &[&intruder],
        b"",
    );
    assert_eq!(cancelled.status, 403);

    let owner_upload = h.call(
        "POST",
        &session,
        &[
            OWNER,
            ("x-goog-upload-command", "upload, finalize"),
            ("x-goog-upload-offset", "0"),
        ],
        &[&token],
        b"abcdef",
    );
    assert_eq!(
        owner_upload.status,
        200,
        "the app that started the upload still owns it: {}",
        String::from_utf8_lossy(&owner_upload.body)
    );
}

/// The finalization is bound too: it commits the object, so it is the request a foreign app
/// would most like to reach.
#[test]
fn a_resumable_finalization_from_another_app_commits_nothing() {
    let h = harness(BaselineMode::Enforced);
    let token = h.token();
    let start = h.start_resumable("finalize.bin", &[&token]);
    let session = header(&start, "x-goog-upload-url")
        .expect("a session URL")
        .strip_prefix("http://127.0.0.1:9199")
        .expect("the session URL names this host")
        .to_owned();
    let uploaded = h.call(
        "POST",
        &session,
        &[
            OWNER,
            ("x-goog-upload-command", "upload"),
            ("x-goog-upload-offset", "0"),
        ],
        &[&token],
        b"abcdef",
    );
    assert_eq!(uploaded.status, 200);

    let denied = h.call(
        "POST",
        &session,
        &[OWNER, ("x-goog-upload-command", "finalize")],
        &[&h.other_app_token()],
        b"",
    );
    assert_eq!(denied.status, 403);
    let read = h.call(
        "GET",
        &format!("/v0/b/{BUCKET}/o/finalize.bin"),
        &[OWNER],
        &[&token],
        b"",
    );
    assert_eq!(read.status, 404, "no generation was committed");

    let finalized = h.call(
        "POST",
        &session,
        &[OWNER, ("x-goog-upload-command", "finalize")],
        &[&token],
        b"",
    );
    assert_eq!(
        finalized.status,
        200,
        "{}",
        String::from_utf8_lossy(&finalized.body)
    );
}

// ------------------------------------------------------------------------------------------
// Scenario 3: token expiry during a resumable upload preserves the resumable state
// ------------------------------------------------------------------------------------------

/// A session token lives an hour; an upload may not. When the token expires mid-upload the
/// continuation is refused, but the session keeps its bytes, so the client refreshes its token
/// and resumes from the offset it already reached rather than starting again.
#[test]
fn token_expiry_during_a_resumable_upload_preserves_the_resumable_state() {
    let h = harness(BaselineMode::Enforced);
    let token = h.token();
    let start = h.start_resumable("expiry.bin", &[&token]);
    let session = header(&start, "x-goog-upload-url")
        .expect("a session URL")
        .strip_prefix("http://127.0.0.1:9199")
        .expect("the session URL names this host")
        .to_owned();
    let first = h.call(
        "POST",
        &session,
        &[
            OWNER,
            ("x-goog-upload-command", "upload"),
            ("x-goog-upload-offset", "0"),
        ],
        &[&token],
        b"abc",
    );
    assert_eq!(first.status, 200);

    // Two hours later the token issued at the start is past its one-hour expiry.
    h.advance(7200);
    let denied = h.call(
        "POST",
        &session,
        &[
            OWNER,
            ("x-goog-upload-command", "upload"),
            ("x-goog-upload-offset", "3"),
        ],
        &[&token],
        b"def",
    );
    assert_eq!(denied.status, 403);
    assert_eq!(body_of(&denied)["error"]["reason"], "APP_CHECK_INVALID");

    // A fresh token for the same app resumes exactly where the upload stopped.
    let fresh = fixture::token_at(
        &h.app_check,
        "demo-app",
        fixture::APP_ID,
        fixture::START + 7200,
    );
    let queried = h.call(
        "POST",
        &session,
        &[OWNER, ("x-goog-upload-command", "query")],
        &[&fresh],
        b"",
    );
    assert_eq!(
        header(&queried, "x-goog-upload-size-received"),
        Some("3"),
        "the three bytes accepted before the expiry are still there"
    );
    let resumed = h.call(
        "POST",
        &session,
        &[
            OWNER,
            ("x-goog-upload-command", "upload, finalize"),
            ("x-goog-upload-offset", "3"),
        ],
        &[&fresh],
        b"def",
    );
    assert_eq!(
        resumed.status,
        200,
        "{}",
        String::from_utf8_lossy(&resumed.body)
    );
    assert_eq!(body_of(&resumed)["size"], "6");
}

/// An `unenforced` policy binds nothing: it never denies, so a client that stops presenting a
/// token mid-upload must not be locked out of its own session by the back door.
#[test]
fn an_unenforced_resumable_upload_binds_no_app() {
    let h = harness(BaselineMode::Unenforced);
    let start = h.start_resumable("unenforced.bin", &[&h.token()]);
    let session = header(&start, "x-goog-upload-url")
        .expect("a session URL")
        .strip_prefix("http://127.0.0.1:9199")
        .expect("the session URL names this host")
        .to_owned();
    let continued = h.call(
        "POST",
        &session,
        &[
            OWNER,
            ("x-goog-upload-command", "upload, finalize"),
            ("x-goog-upload-offset", "0"),
        ],
        &[],
        b"abcdef",
    );
    assert_eq!(
        continued.status,
        200,
        "{}",
        String::from_utf8_lossy(&continued.body)
    );
}

/// The privileged JSON API dialect keeps its bypass on a bound session: the Admin surface is
/// exempt from App Check by the bypass matrix, not by carrying an app identity.
#[test]
fn the_privileged_json_api_continues_a_bound_resumable_upload() {
    let h = harness(BaselineMode::Enforced);
    let token = h.token();
    let start = h.start_resumable("admin.bin", &[&token]);
    let session_id = header(&start, "x-goog-upload-url")
        .expect("a session URL")
        .split("upload_id=")
        .nth(1)
        .expect("the session URL carries its upload id")
        .split('&')
        .next()
        .expect("an upload id")
        .to_owned();
    let admin = h.call(
        "PUT",
        &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&upload_id={session_id}"),
        &[OWNER, ("content-range", "bytes 0-5/6")],
        &[],
        b"abcdef",
    );
    assert_eq!(
        admin.status,
        200,
        "{}",
        String::from_utf8_lossy(&admin.body)
    );
}

/// Dialect confusion: a JSON-API-shaped path with an end-user `Firebase <token>` credential is
/// not the privileged dialect, so it neither bypasses Security Rules nor App Check.
#[test]
fn a_json_api_path_with_an_end_user_credential_does_not_bypass() {
    let h = capability_harness(BaselineMode::Enforced);
    let denied = h.call(
        "GET",
        &format!("/storage/v1/b/{BUCKET}/o"),
        &[("authorization", "Firebase not-a-real-token")],
        &[],
        b"",
    );
    assert_eq!(
        denied.status,
        403,
        "{}",
        String::from_utf8_lossy(&denied.body)
    );
    assert_eq!(body_of(&denied)["error"]["reason"], "APP_CHECK_REQUIRED");
}

/// The Firebase dialect is always an end-user surface, whatever credential it carries.
#[test]
fn the_firebase_dialect_never_bypasses_on_the_owner_credential_alone() {
    let h = harness(BaselineMode::Enforced);
    let denied = h.call("GET", &format!("/v0/b/{BUCKET}/o"), &[OWNER], &[], b"");
    assert_eq!(
        denied.status,
        403,
        "{}",
        String::from_utf8_lossy(&denied.body)
    );
}

#[test]
fn the_admin_storage_capability_bypasses_only_the_server_side_gcs_dialect() {
    let h = capability_harness(BaselineMode::Enforced);
    h.seed_object("admin/listed.txt");
    let authorization = admin_storage_authorization();
    let path = format!("/storage/v1/b/{BUCKET}/o?prefix=admin/");

    let admitted = h.call("GET", &path, &[("authorization", &authorization)], &[], b"");
    assert_eq!(
        admitted.status,
        200,
        "{}",
        String::from_utf8_lossy(&admitted.body)
    );

    for (label, headers) in [
        ("missing capability", vec![]),
        (
            "wrong capability",
            vec![("authorization", "Basic ZmlyZWVtdTp3cm9uZw==")],
        ),
        (
            "browser origin",
            vec![
                ("authorization", authorization.as_str()),
                ("origin", "http://127.0.0.1:5173"),
            ],
        ),
        (
            "browser fetch metadata",
            vec![
                ("authorization", authorization.as_str()),
                ("sec-fetch-site", "same-origin"),
            ],
        ),
        (
            "sec-fetch-dest alone",
            vec![
                ("authorization", authorization.as_str()),
                ("sec-fetch-dest", "empty"),
            ],
        ),
        (
            "referer alone",
            vec![
                ("authorization", authorization.as_str()),
                ("referer", "http://127.0.0.1:5173/"),
            ],
        ),
        (
            "cookie alone",
            vec![
                ("authorization", authorization.as_str()),
                ("cookie", "session=1"),
            ],
        ),
    ] {
        let denied = h.call("GET", &path, &headers, &[], b"");
        assert_eq!(
            denied.status,
            403,
            "{label}: {}",
            String::from_utf8_lossy(&denied.body)
        );
        assert_eq!(
            body_of(&denied)["error"]["reason"],
            "APP_CHECK_REQUIRED",
            "{label}"
        );
    }

    let firebase = h.call(
        "GET",
        &format!("/v0/b/{BUCKET}/o"),
        &[("authorization", &authorization)],
        &[],
        b"",
    );
    assert_eq!(firebase.status, 403);
    assert_eq!(body_of(&firebase)["error"]["reason"], "APP_CHECK_REQUIRED");
}

/// The exact header set Node's built-in `fetch` (undici) attaches to a request a script issues
/// with no headers of its own: `sec-fetch-mode: cors` and nothing else from
/// [`fireemu_core_session::loopback::BROWSER_METADATA_HEADERS`]. This is what
/// `@firebase/rules-unit-testing` 5.x sends from an admin-capability request, and it is a
/// process, not a page, so it must not be refused for it (same rule BROWSER-GUARD-001 gave the
/// `/internal/setRules` route).
#[test]
fn the_admin_storage_capability_admits_the_exact_undici_header_set() {
    let h = capability_harness(BaselineMode::Enforced);
    h.seed_object("undici/listed.txt");
    let authorization = admin_storage_authorization();
    let path = format!("/storage/v1/b/{BUCKET}/o?prefix=undici/");

    let admitted = h.call(
        "GET",
        &path,
        &[
            ("authorization", authorization.as_str()),
            ("accept", "*/*"),
            ("accept-language", "*"),
            ("accept-encoding", "gzip, deflate"),
            ("user-agent", "node"),
            ("sec-fetch-mode", "cors"),
        ],
        &[],
        b"",
    );
    assert_eq!(
        admitted.status,
        200,
        "{}",
        String::from_utf8_lossy(&admitted.body)
    );
}

/// A real browser attaches `Sec-Fetch-Site` and `Sec-Fetch-Dest` (and usually `Origin` and
/// `Referer`) alongside `Sec-Fetch-Mode`; that full set is browser evidence and keeps the
/// capability refused even though `Sec-Fetch-Mode` alone is not.
#[test]
fn the_admin_storage_capability_refuses_a_full_browser_header_set() {
    let h = capability_harness(BaselineMode::Enforced);
    let authorization = admin_storage_authorization();
    let path = format!("/storage/v1/b/{BUCKET}/o");

    let denied = h.call(
        "GET",
        &path,
        &[
            ("authorization", authorization.as_str()),
            ("origin", "http://127.0.0.1:5173"),
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-dest", "empty"),
            ("sec-fetch-mode", "cors"),
            ("referer", "http://127.0.0.1:5173/"),
        ],
        &[],
        b"",
    );
    assert_eq!(
        denied.status,
        403,
        "{}",
        String::from_utf8_lossy(&denied.body)
    );
    assert_eq!(body_of(&denied)["error"]["reason"], "APP_CHECK_REQUIRED");
}

// ------------------------------------------------------------------------------------------
// Server-side Admin traffic under enforcement: `appCheck.storageServerRequests` (owner ledger
// 1431). Production does not apply App Check to the Admin SDK's OAuth traffic; the emulator
// recognises it by shape: a Cloud Storage JSON API route, a loopback peer, no browser evidence.
// ------------------------------------------------------------------------------------------

/// Every header a request needs to count as browser evidence, one at a time.
const BROWSER_EVIDENCE: [(&str, &str); 5] = [
    ("origin", "http://127.0.0.1:5173"),
    ("sec-fetch-site", "same-origin"),
    ("sec-fetch-dest", "empty"),
    ("referer", "http://127.0.0.1:5173/"),
    ("cookie", "session=1"),
];

fn session_id_of(start: &StorageResponse) -> String {
    header(start, "location")
        .or_else(|| header(start, "x-goog-upload-url"))
        .expect("a session URL")
        .split("upload_id=")
        .nth(1)
        .expect("the session URL carries its upload id")
        .split('&')
        .next()
        .expect("an upload id")
        .to_owned()
}

#[test]
fn a_loopback_json_api_request_without_browser_evidence_is_admitted_under_enforcement() {
    let h = harness(BaselineMode::Enforced);
    h.seed_object("server/seeded.txt");
    // The shapes the Admin SDK sends: no credential at all, and a bearer access token.
    for headers in [
        vec![],
        vec![("authorization", "Bearer ya29.not-checked")],
        // Node's built-in fetch attaches `sec-fetch-mode: cors` and nothing else browser-like.
        vec![("sec-fetch-mode", "cors"), ("user-agent", "node")],
    ] {
        let list = h.call(
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o?prefix=server/"),
            &headers,
            &[],
            b"",
        );
        assert_eq!(
            list.status,
            200,
            "{headers:?}: {}",
            String::from_utf8_lossy(&list.body)
        );
        let get = h.call(
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/server%2Fseeded.txt"),
            &headers,
            &[],
            b"",
        );
        assert_eq!(get.status, 200, "{headers:?}");
        let download = h.call(
            "GET",
            &format!("/download/storage/v1/b/{BUCKET}/o/server%2Fseeded.txt?alt=media"),
            &headers,
            &[],
            b"",
        );
        assert_eq!(download.status, 200, "{headers:?}");
        assert_eq!(&download.body[..], b"hello");
    }
    let upload = h.call(
        "POST",
        &format!("/upload/storage/v1/b/{BUCKET}/o?name=server/up.txt&uploadType=media"),
        &[("content-type", "text/plain")],
        &[],
        b"written",
    );
    assert_eq!(
        upload.status,
        200,
        "{}",
        String::from_utf8_lossy(&upload.body)
    );
    let delete = h.call(
        "DELETE",
        &format!("/storage/v1/b/{BUCKET}/o/server%2Fup.txt"),
        &[],
        &[],
        b"",
    );
    assert_eq!(
        delete.status,
        204,
        "{}",
        String::from_utf8_lossy(&delete.body)
    );
}

/// Admitted server-side requests are counted as the server-side bypass, the same label the
/// `unenforced` policy gives them.
#[test]
fn an_admitted_server_side_request_is_observed_as_a_bypass() {
    use fireemu_core_app_check::CredentialCategory::Bypass;

    let h = harness(BaselineMode::Enforced);
    let before = h
        .app_check
        .registry
        .read()
        .expect("readable")
        .observations("demo-app")
        .len();
    let list = h.call("GET", &format!("/storage/v1/b/{BUCKET}/o"), &[], &[], b"");
    assert_eq!(list.status, 200);
    let observed = h
        .app_check
        .registry
        .read()
        .expect("readable")
        .observations("demo-app");
    let fresh = &observed[before..];
    assert_eq!(fresh.len(), 1);
    assert!(
        fresh[0].category == Bypass && fresh[0].admitted,
        "{fresh:?}"
    );
}

#[test]
fn the_firebase_dialect_still_needs_a_token_under_loopback_server_requests() {
    let h = harness(BaselineMode::Enforced);
    h.seed_object("v0/guarded.txt");
    for (label, headers) in [
        ("no headers", vec![]),
        ("owner credential", vec![OWNER]),
        (
            "bearer access token",
            vec![("authorization", "Bearer ya29.x")],
        ),
        (
            "capability",
            vec![(
                "authorization",
                "Basic ZmlyZWVtdTpzdG9yYWdlLWNhcGFiaWxpdHk=",
            )],
        ),
    ] {
        for (method, path, body) in [
            ("GET", format!("/v0/b/{BUCKET}/o"), &b""[..]),
            (
                "GET",
                format!("/v0/b/{BUCKET}/o/v0%2Fguarded.txt"),
                &b""[..],
            ),
            (
                "DELETE",
                format!("/v0/b/{BUCKET}/o/v0%2Fguarded.txt"),
                &b""[..],
            ),
            (
                "POST",
                format!("/v0/b/{BUCKET}/o?name=v0/new.txt&uploadType=media"),
                &b"x"[..],
            ),
        ] {
            let denied = h.call(method, &path, &headers, &[], body);
            assert_eq!(
                denied.status,
                403,
                "{label}: {method} {path}: {}",
                String::from_utf8_lossy(&denied.body)
            );
            assert_eq!(body_of(&denied)["error"]["reason"], "APP_CHECK_REQUIRED");
        }
    }
    // The denied requests changed nothing.
    let still = h.call(
        "GET",
        &format!("/storage/v1/b/{BUCKET}/o/v0%2Fguarded.txt"),
        &[],
        &[],
        b"",
    );
    assert_eq!(still.status, 200);
    let created = h.call(
        "GET",
        &format!("/storage/v1/b/{BUCKET}/o/v0%2Fnew.txt"),
        &[],
        &[],
        b"",
    );
    assert_eq!(created.status, 404);
}

#[test]
fn browser_evidence_keeps_a_json_api_request_ordinary_under_loopback_server_requests() {
    let h = harness(BaselineMode::Enforced);
    h.seed_object("browser/guarded.txt");
    for (name, value) in BROWSER_EVIDENCE {
        for (method, path, body) in [
            ("GET", format!("/storage/v1/b/{BUCKET}/o"), &b""[..]),
            (
                "GET",
                format!("/storage/v1/b/{BUCKET}/o/browser%2Fguarded.txt"),
                &b""[..],
            ),
            (
                "GET",
                format!("/download/storage/v1/b/{BUCKET}/o/browser%2Fguarded.txt?alt=media"),
                &b""[..],
            ),
            (
                "POST",
                format!("/upload/storage/v1/b/{BUCKET}/o?name=browser/new.txt&uploadType=media"),
                &b"x"[..],
            ),
            (
                "DELETE",
                format!("/storage/v1/b/{BUCKET}/o/browser%2Fguarded.txt"),
                &b""[..],
            ),
        ] {
            let denied = h.call(method, &path, &[(name, value)], &[], body);
            assert_eq!(
                denied.status,
                403,
                "{name}: {method} {path}: {}",
                String::from_utf8_lossy(&denied.body)
            );
            assert_eq!(body_of(&denied)["error"]["reason"], "APP_CHECK_REQUIRED");
        }
    }
    // The denied requests changed nothing: the object is still there and nothing was created.
    let kept = h.call(
        "GET",
        &format!("/storage/v1/b/{BUCKET}/o/browser%2Fguarded.txt"),
        &[],
        &[],
        b"",
    );
    assert_eq!(kept.status, 200);
    let created = h.call(
        "GET",
        &format!("/storage/v1/b/{BUCKET}/o/browser%2Fnew.txt"),
        &[],
        &[],
        b"",
    );
    assert_eq!(created.status, 404);
}

#[test]
fn a_non_loopback_peer_is_not_server_side() {
    let h = harness(BaselineMode::Enforced);
    h.seed_object("remote/guarded.txt");
    let denied = h.call_from(
        true,
        "GET",
        &format!("/storage/v1/b/{BUCKET}/o/remote%2Fguarded.txt"),
        &[],
        &[],
        b"",
    );
    assert_eq!(
        denied.status,
        403,
        "{}",
        String::from_utf8_lossy(&denied.body)
    );
    assert_eq!(body_of(&denied)["error"]["reason"], "APP_CHECK_REQUIRED");
    let denied_upload = h.call_from(
        true,
        "POST",
        &format!("/upload/storage/v1/b/{BUCKET}/o?name=remote/new.txt&uploadType=media"),
        &[("content-type", "text/plain")],
        &[],
        b"x",
    );
    assert_eq!(denied_upload.status, 403);
    // The same request from loopback is admitted.
    let admitted = h.call(
        "GET",
        &format!("/storage/v1/b/{BUCKET}/o/remote%2Fguarded.txt"),
        &[],
        &[],
        b"",
    );
    assert_eq!(admitted.status, 200);
}

/// Only the Cloud Storage JSON API routes are server-side. The XML-style object read and the
/// form-data upload are the URLs a page navigates to or posts a form to.
#[test]
fn the_xml_style_read_and_the_form_upload_are_not_server_side() {
    let h = harness(BaselineMode::Enforced);
    h.seed_object("xml/guarded.txt");
    let read = h.call("GET", &format!("/{BUCKET}/xml/guarded.txt"), &[], &[], b"");
    assert_eq!(read.status, 403, "{}", String::from_utf8_lossy(&read.body));
    // App Check refused it, not the private-object AccessDenied of the XML-style read.
    assert_eq!(body_of(&read)["error"]["reason"], "APP_CHECK_REQUIRED");
    let form = h.call(
        "POST",
        &format!("/{BUCKET}"),
        &[("content-type", "multipart/form-data; boundary=x")],
        &[],
        b"--x--\r\n",
    );
    assert_eq!(form.status, 403, "{}", String::from_utf8_lossy(&form.body));
}

/// The Admin SDK's resumable `file.save()`: the start and every continuation are JSON API
/// requests with no capability, so both pass; a client app's own bound session also continues.
#[test]
fn a_resumable_upload_started_and_continued_server_side_passes_under_enforcement() {
    let h = harness(BaselineMode::Enforced);
    let start = h.call(
        "POST",
        &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=admin/resumable.bin"),
        &[
            ("content-type", "application/json"),
            ("x-upload-content-type", "application/octet-stream"),
        ],
        &[],
        b"{}",
    );
    assert_eq!(
        start.status,
        200,
        "{}",
        String::from_utf8_lossy(&start.body)
    );
    let session = session_id_of(&start);
    let path = format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&upload_id={session}");

    let first = h.call(
        "PUT",
        &path,
        &[("content-range", "bytes 0-2/6")],
        &[],
        b"abc",
    );
    assert_eq!(
        (first.status, header(&first, "range")),
        (308, Some("bytes=0-2"))
    );
    let status = h.call("PUT", &path, &[("content-range", "bytes */6")], &[], b"");
    assert_eq!(status.status, 308);
    let last = h.call(
        "PUT",
        &path,
        &[("content-range", "bytes 3-5/6")],
        &[],
        b"def",
    );
    assert_eq!(last.status, 200, "{}", String::from_utf8_lossy(&last.body));
    let read = h.call(
        "GET",
        &format!("/download/storage/v1/b/{BUCKET}/o/admin%2Fresumable.bin?alt=media"),
        &[],
        &[],
        b"",
    );
    assert_eq!(&read.body[..], b"abcdef");
}

#[test]
fn a_browser_shaped_or_remote_continuation_of_a_resumable_session_is_refused_and_leaves_it_intact()
{
    let h = harness(BaselineMode::Enforced);
    let start = h.call(
        "POST",
        &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=admin/guarded.bin"),
        &[("content-type", "application/json")],
        &[],
        b"{}",
    );
    assert_eq!(start.status, 200);
    let session = session_id_of(&start);
    let path = format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&upload_id={session}");
    for (name, value) in BROWSER_EVIDENCE {
        let denied = h.call(
            "PUT",
            &path,
            &[(name, value), ("content-range", "bytes 0-2/6")],
            &[],
            b"abc",
        );
        assert_eq!(
            denied.status,
            403,
            "{name}: {}",
            String::from_utf8_lossy(&denied.body)
        );
    }
    let remote = h.call_from(
        true,
        "PUT",
        &path,
        &[("content-range", "bytes 0-2/6")],
        &[],
        b"abc",
    );
    assert_eq!(remote.status, 403);
    // The refusals advanced nothing: the session still has no byte, and finishes normally.
    let status = h.call("PUT", &path, &[("content-range", "bytes */6")], &[], b"");
    assert_eq!(status.status, 308);
    assert_eq!(
        header(&status, "range"),
        None,
        "no byte was stored: {:?}",
        status.headers
    );
    let done = h.call(
        "PUT",
        &path,
        &[("content-range", "bytes 0-5/6")],
        &[],
        b"abcdef",
    );
    assert_eq!(done.status, 200);
}

/// A session id that was never issued, or that belongs to another bucket, answers as it does
/// without App Check: the admission only decides whether the request may look the session up.
#[test]
fn a_foreign_or_unknown_upload_id_is_still_not_found_for_a_server_side_request() {
    let h = harness(BaselineMode::Enforced);
    let start = h.call(
        "POST",
        &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=admin/own.bin"),
        &[("content-type", "application/json")],
        &[],
        b"{}",
    );
    let session = session_id_of(&start);
    let unknown = h.call(
        "PUT",
        &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&upload_id=not-a-session"),
        &[("content-range", "bytes 0-2/6")],
        &[],
        b"abc",
    );
    assert_eq!(
        unknown.status,
        404,
        "{}",
        String::from_utf8_lossy(&unknown.body)
    );
    let other_bucket = h.call(
        "PUT",
        &format!("/upload/storage/v1/b/other-bucket/o?uploadType=resumable&upload_id={session}"),
        &[("content-range", "bytes 0-2/6")],
        &[],
        b"abc",
    );
    assert_eq!(
        other_bucket.status,
        404,
        "{}",
        String::from_utf8_lossy(&other_bucket.body)
    );
    // The same ids from a browser are refused by App Check before the lookup.
    let browser = h.call(
        "PUT",
        &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&upload_id=not-a-session"),
        &[
            ("origin", "http://127.0.0.1:5173"),
            ("content-range", "bytes 0-2/6"),
        ],
        &[],
        b"abc",
    );
    assert_eq!(browser.status, 403);
}

/// A session a client app started (bound to its app) stays bound for other clients: a
/// different app's token cannot continue it, while the server-side request, like the owner
/// credential before it, can.
#[test]
fn a_bound_session_stays_bound_to_clients_and_is_open_to_server_side_requests() {
    let h = harness(BaselineMode::Enforced);
    let token = h.token();
    let start = h.start_resumable("bound.bin", &[&token]);
    assert_eq!(start.status, 200);
    let session = session_id_of(&start);
    let json_path =
        format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&upload_id={session}");
    let other = h.other_app_token();
    let foreign = h.call(
        "PUT",
        &json_path,
        &[
            ("origin", "http://127.0.0.1:5173"),
            ("content-range", "bytes 0-5/6"),
        ],
        &[&other],
        b"abcdef",
    );
    assert_eq!(
        foreign.status,
        403,
        "{}",
        String::from_utf8_lossy(&foreign.body)
    );
    let server = h.call(
        "PUT",
        &json_path,
        &[("content-range", "bytes 0-5/6")],
        &[],
        b"abcdef",
    );
    assert_eq!(
        server.status,
        200,
        "{}",
        String::from_utf8_lossy(&server.body)
    );
}

/// `capability`: exactly the behaviour before the setting existed.
#[test]
fn capability_mode_admits_only_the_capability_and_refuses_a_credential_less_continuation() {
    let h = capability_harness(BaselineMode::Enforced);
    let authorization = admin_storage_authorization();
    let list = format!("/storage/v1/b/{BUCKET}/o");
    let refused = h.call("GET", &list, &[], &[], b"");
    assert_eq!(refused.status, 403);
    assert_eq!(body_of(&refused)["error"]["reason"], "APP_CHECK_REQUIRED");
    let admitted = h.call("GET", &list, &[("authorization", &authorization)], &[], b"");
    assert_eq!(admitted.status, 200);

    // The capability starts a session; the continuation URL has no capability, so it is
    // refused (the 8.1 / resumable limitation this mode keeps).
    let start = h.call(
        "POST",
        &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=capability.bin"),
        &[
            ("authorization", &authorization),
            ("content-type", "application/json"),
        ],
        &[],
        b"{}",
    );
    assert_eq!(
        start.status,
        200,
        "{}",
        String::from_utf8_lossy(&start.body)
    );
    let session = session_id_of(&start);
    let path = format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&upload_id={session}");
    let continuation = h.call(
        "PUT",
        &path,
        &[("content-range", "bytes 0-5/6")],
        &[],
        b"abcdef",
    );
    assert_eq!(continuation.status, 403);
    assert_eq!(
        body_of(&continuation)["error"]["reason"],
        "APP_CHECK_REQUIRED"
    );
}

#[test]
fn an_unenforced_remote_json_api_request_is_observed_as_missing() {
    use fireemu_core_app_check::CredentialCategory::Missing;

    let h = harness(BaselineMode::Unenforced);
    let before = h
        .app_check
        .registry
        .read()
        .expect("readable")
        .observations("demo-app")
        .len();
    let r = h.call_from(
        true,
        "GET",
        &format!("/storage/v1/b/{BUCKET}/o"),
        &[],
        &[],
        b"",
    );
    assert_eq!(r.status, 200, "unenforced admits everything");
    let observed = h
        .app_check
        .registry
        .read()
        .expect("readable")
        .observations("demo-app");
    assert!(observed[before..]
        .iter()
        .all(|o| o.category == Missing && o.admitted));
}

/// `Authorization: Firebase <token>` is the client SDK's credential, not the Admin SDK's: on a
/// JSON API path it is still an ordinary request (coordinator ruling, 2026-10-15). An OAuth
/// `Bearer` token, which the Admin SDK sends, is not affected.
#[test]
fn a_firebase_client_credential_on_a_json_api_path_is_not_server_side() {
    let h = harness(BaselineMode::Enforced);
    h.seed_object("fb/guarded.txt");
    let path = format!("/storage/v1/b/{BUCKET}/o/fb%2Fguarded.txt");
    for value in [
        "Firebase not-a-real-token",
        "firebase not-a-real-token",
        "FIREBASE x",
        "  Firebase   x",
        "Firebase",
    ] {
        let denied = h.call("GET", &path, &[("authorization", value)], &[], b"");
        assert_eq!(
            denied.status,
            403,
            "{value:?}: {}",
            String::from_utf8_lossy(&denied.body)
        );
        assert_eq!(
            body_of(&denied)["error"]["reason"],
            "APP_CHECK_REQUIRED",
            "{value:?}"
        );
    }
    for value in [
        "Bearer ya29.x",
        "Basic Zm9vOmJhcg==",
        "Firebaseish x",
        "Bearer Firebase",
    ] {
        let admitted = h.call("GET", &path, &[("authorization", value)], &[], b"");
        assert_eq!(admitted.status, 200, "{value:?}");
    }
    // A valid App Check token still passes the same request: only the server-side shortcut is
    // withdrawn, not the ordinary path.
    let token = h.token();
    let with_token = h.call(
        "GET",
        &path,
        &[("authorization", "Firebase not-a-real-token")],
        &[&token],
        b"",
    );
    assert_eq!(
        with_token.status,
        200,
        "{}",
        String::from_utf8_lossy(&with_token.body)
    );
}

/// DNS rebinding: a page on `http://evil.example:9199` whose name was rebound to 127.0.0.1
/// sends a same-origin request with no `Origin`, no Fetch Metadata (the URL is not potentially
/// trustworthy), no `Referer` and no `Cookie`. Only its `Host` gives it away.
#[test]
fn a_request_whose_host_is_not_loopback_is_not_server_side() {
    let h = harness(BaselineMode::Enforced);
    h.seed_object("rebind/guarded.txt");
    let path = format!("/storage/v1/b/{BUCKET}/o/rebind%2Fguarded.txt");
    for host in [
        Some("evil.example:9199"),
        Some("evil.example"),
        Some("localhost.:9199"),
        Some("127.0.0.1.nip.io:9199"),
        Some("localhost.evil.example:9199"),
        Some("host.containers.internal:9199"),
        Some("127.0.0.1@evil.example:9199"),
        Some("127.0.0.1:99999"),
        Some(""),
        None,
    ] {
        for (method, route, body) in [
            ("GET", path.clone(), &b""[..]),
            ("GET", format!("/storage/v1/b/{BUCKET}/o"), &b""[..]),
            (
                "POST",
                format!("/upload/storage/v1/b/{BUCKET}/o?name=rebind/new.txt&uploadType=media"),
                &b"x"[..],
            ),
            ("DELETE", path.clone(), &b""[..]),
        ] {
            let denied = h.call_full(false, host, method, &route, &[], &[], body);
            assert_eq!(
                denied.status,
                403,
                "{host:?}: {method} {route}: {}",
                String::from_utf8_lossy(&denied.body)
            );
            assert_eq!(
                body_of(&denied)["error"]["reason"],
                "APP_CHECK_REQUIRED",
                "{host:?}"
            );
        }
    }
    for host in [
        "127.0.0.1:9199",
        "127.0.0.1",
        "localhost:9199",
        "LOCALHOST:9199",
        "[::1]:9199",
        "127.1.2.3:9199",
    ] {
        let admitted = h.call_full(false, Some(host), "GET", &path, &[], &[], b"");
        assert_eq!(
            admitted.status,
            200,
            "{host}: {}",
            String::from_utf8_lossy(&admitted.body)
        );
    }
    // Nothing the rebound page sent changed the store.
    let kept = h.call("GET", &path, &[], &[], b"");
    assert_eq!(kept.status, 200);
    let created = h.call(
        "GET",
        &format!("/storage/v1/b/{BUCKET}/o/rebind%2Fnew.txt"),
        &[],
        &[],
        b"",
    );
    assert_eq!(created.status, 404);
}

/// The short bucket spelling `/b/{bucket}` the Admin SDK uses for `getMetadata()` and
/// `setMetadata()` is a JSON API route whatever the profile later does with it.
#[test]
fn the_short_bucket_spelling_is_server_side_and_a_browser_still_is_not() {
    // Under the emulator profile the spelling falls through to the official emulator's routes
    // (an object read, the 501 catch-all) before dispatch; under strict it is the bucket
    // resource. The admission follows the spelling the request used, not what it became.
    for emulator_profile in [false, true] {
        let mut h = harness(BaselineMode::Enforced);
        if emulator_profile {
            h.storage.token_acceptance = fireemu_core_auth::jwt::TokenAcceptance::EmulatorMock;
        }
        short_bucket_cases(&h, emulator_profile);
    }
}

fn short_bucket_cases(h: &Harness, emulator_profile: bool) {
    for method in ["GET", "PATCH"] {
        let admitted = h.call(method, &format!("/b/{BUCKET}"), &[], &[], b"{}");
        let refused =
            admitted.status == 403 && body_of(&admitted)["error"]["reason"] == "APP_CHECK_REQUIRED";
        assert!(
            !refused,
            "emulator profile {emulator_profile}: {method}: {}",
            String::from_utf8_lossy(&admitted.body)
        );
        let browser = h.call(
            method,
            &format!("/b/{BUCKET}"),
            &[("origin", "http://127.0.0.1:5173")],
            &[],
            b"{}",
        );
        assert_eq!(browser.status, 403, "{method}");
        assert_eq!(
            body_of(&browser)["error"]["reason"],
            "APP_CHECK_REQUIRED",
            "{method}"
        );
    }
}

/// Under `unenforced` the shape only labels the observation. Everything that is not a
/// loopback, browser-free, non-client-credential JSON API request is a missing token, in either
/// `storageServerRequests` mode.
#[test]
fn unenforced_observation_labels_follow_the_server_side_shape() {
    use fireemu_core_app_check::CredentialCategory::{Bypass, Missing};

    for mode in [
        StorageServerRequests::Loopback,
        StorageServerRequests::Capability,
    ] {
        let h = harness_with(BaselineMode::Unenforced, mode);
        h.seed_object("labels/o.txt");
        let list = format!("/storage/v1/b/{BUCKET}/o?prefix=labels/");
        let observe = |remote: bool,
                       host: Option<&str>,
                       method: &str,
                       path: &str,
                       headers: &[(&str, &str)]| {
            let before = h
                .app_check
                .registry
                .read()
                .expect("readable")
                .observations("demo-app")
                .len();
            let r = h.call_full(remote, host, method, path, headers, &[], b"x");
            // The XML-style read of a private object is refused for its own reasons (403
            // AccessDenied); what `unenforced` never does is refuse for App Check.
            assert!(
                body_of(&r)["error"]["reason"]
                    .as_str()
                    .is_none_or(|reason| !reason.starts_with("APP_CHECK")),
                "unenforced never refuses for App Check: {method} {path}"
            );
            let observed = h
                .app_check
                .registry
                .read()
                .expect("readable")
                .observations("demo-app");
            assert_eq!(observed.len(), before + 1, "{method} {path}");
            observed[before].category
        };
        let host = Some("127.0.0.1:9199");
        assert_eq!(observe(false, host, "GET", &list, &[]), Bypass, "{mode:?}");
        assert_eq!(
            observe(true, host, "GET", &list, &[]),
            Missing,
            "{mode:?} remote peer"
        );
        assert_eq!(
            observe(false, Some("evil.example:9199"), "GET", &list, &[]),
            Missing,
            "{mode:?} foreign host"
        );
        assert_eq!(
            observe(
                false,
                host,
                "GET",
                &list,
                &[("authorization", "Firebase t")]
            ),
            Missing,
            "{mode:?} client credential"
        );
        assert_eq!(
            observe(false, host, "GET", &format!("/{BUCKET}/labels/o.txt"), &[]),
            Missing,
            "{mode:?} XML-style read"
        );
        assert_eq!(
            observe(
                false,
                host,
                "POST",
                &format!("/{BUCKET}"),
                &[("content-type", "multipart/form-data; boundary=x")]
            ),
            Missing,
            "{mode:?} form upload"
        );
    }
}

/// The configuration spellings round-trip, and nothing else parses (the loader refuses it).
#[test]
fn storage_server_requests_spellings_round_trip() {
    assert_eq!(
        StorageServerRequests::default(),
        StorageServerRequests::Loopback
    );
    for (text, mode) in [
        ("loopback", StorageServerRequests::Loopback),
        ("capability", StorageServerRequests::Capability),
    ] {
        assert_eq!(StorageServerRequests::parse_config(text), Some(mode));
        assert_eq!(mode.as_config_str(), text);
    }
    for bad in [
        "",
        "Loopback",
        "LOOPBACK",
        "capability ",
        "all",
        "off",
        "true",
    ] {
        assert_eq!(StorageServerRequests::parse_config(bad), None, "{bad:?}");
    }
}

/// Every route of the table: a plain loopback request is admitted exactly on the Cloud Storage
/// JSON API routes, under `loopback`, and never under `capability`.
#[test]
fn every_json_api_route_is_server_side_and_no_other_route_is() {
    for (mode, expect_admitted) in [
        (StorageServerRequests::Loopback, true),
        (StorageServerRequests::Capability, false),
    ] {
        let h = harness_with(BaselineMode::Enforced, mode);
        for (method, path, json_api) in server_side_properties::routes() {
            let response = h.call(method, &path, &[], &[], b"");
            let refused = response.status == 403
                && body_of(&response)["error"]["reason"] == "APP_CHECK_REQUIRED";
            assert_eq!(
                !refused,
                expect_admitted && json_api,
                "{mode:?}: {method} {path} -> {} {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            );
        }
    }
}

mod server_side_properties {
    use super::*;
    use proptest::prelude::*;

    /// (method, path template, expected to be a Cloud Storage JSON API route)
    pub(super) fn routes() -> Vec<(&'static str, String, bool)> {
        vec![
            ("GET", format!("/storage/v1/b/{BUCKET}/o"), true),
            ("GET", format!("/storage/v1/b/{BUCKET}/o/p%2Fo.txt"), true),
            (
                "GET",
                format!("/download/storage/v1/b/{BUCKET}/o/p%2Fo.txt?alt=media"),
                true,
            ),
            ("GET", format!("/storage/v1/b/{BUCKET}"), true),
            ("GET", format!("/b/{BUCKET}/o"), true),
            ("GET", "/b".to_owned(), true),
            ("GET", format!("/b/{BUCKET}"), true),
            ("PATCH", format!("/b/{BUCKET}"), true),
            (
                "POST",
                format!("/storage/v1/b/{BUCKET}/o/p%2Fo.txt/copyTo/b/{BUCKET}/o/copy.txt"),
                true,
            ),
            ("POST", format!("/b/{BUCKET}/o/p%2Fo.txt/acl"), true),
            (
                "DELETE",
                format!("/b/{BUCKET}/o/p%2Fo.txt/acl/allUsers"),
                true,
            ),
            (
                "POST",
                format!("/upload/storage/v1/b/{BUCKET}/o?name=u.txt&uploadType=media"),
                true,
            ),
            ("PATCH", format!("/storage/v1/b/{BUCKET}/o/p%2Fo.txt"), true),
            ("POST", format!("/{BUCKET}"), false),
            ("GET", format!("/v0/b/{BUCKET}/o"), false),
            ("GET", format!("/v0/b/{BUCKET}/o/p%2Fo.txt"), false),
            ("GET", format!("/{BUCKET}/p/o.txt"), false),
        ]
    }

    proptest! {
        /// Under `enforced` and no credential, a request is admitted exactly when it is a JSON
        /// API route from a loopback peer with no browser evidence and the setting is
        /// `loopback`; `capability` admits none of them without the capability.
        #[test]
        fn admission_is_the_conjunction_of_route_peer_and_browser_evidence(
            route in 0..routes().len(),
            // Weighted so that a case without browser evidence, from a loopback peer, under
            // `loopback`, is common enough for every route to be admitted several times.
            remote in proptest::bool::weighted(0.2),
            evidence in proptest::collection::vec(proptest::bool::weighted(0.1), 5),
            sec_fetch_mode in any::<bool>(),
            client_credential in proptest::bool::weighted(0.15),
            host in 0usize..4,
            loopback in proptest::bool::weighted(0.8),
        ) {
            let mode = if loopback {
                StorageServerRequests::Loopback
            } else {
                StorageServerRequests::Capability
            };
            let h = harness_with(BaselineMode::Enforced, mode);
            let (method, path, json_api) = routes()[route].clone();
            let mut headers: Vec<(&str, &str)> = BROWSER_EVIDENCE
                .iter()
                .zip(&evidence)
                .filter(|(_, on)| **on)
                .map(|(pair, _)| *pair)
                .collect();
            if sec_fetch_mode {
                headers.push(("sec-fetch-mode", "cors"));
            }
            if client_credential {
                headers.push(("authorization", "Firebase not-a-real-token"));
            }
            let browser = evidence.iter().any(|on| *on);
            let host_name = [Some("127.0.0.1:9199"), Some("localhost:9199"), Some("evil.example:9199"), None][host];
            let response = h.call_full(remote, host_name, method, &path, &headers, &[], b"");
            let refused_by_app_check = response.status == 403
                && body_of(&response)["error"]["reason"] == "APP_CHECK_REQUIRED";
            let expected_admitted =
                loopback && json_api && !remote && !browser && !client_credential && host < 2;
            prop_assert_eq!(
                !refused_by_app_check,
                expected_admitted,
                "{} {} remote={} host={:?} headers={:?} -> {}",
                method, path, remote, host_name, headers, response.status
            );
        }
    }
}

// ------------------------------------------------------------------------------------------
// The enforcement matrix: mode x credential state (section 19)
// ------------------------------------------------------------------------------------------

#[test]
fn the_storage_enforcement_matrix_holds_for_every_mode_and_credential_state() {
    for (mode, denies) in [
        (BaselineMode::Off, false),
        (BaselineMode::Unenforced, false),
        (BaselineMode::Enforced, true),
    ] {
        let h = harness(mode);
        for (index, (name, value)) in fixture::credential_states(&h.app_check)
            .into_iter()
            .enumerate()
        {
            let values: Vec<&str> = value.iter().map(String::as_str).collect();
            let response = h.call(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name=m{index}.txt&uploadType=media"),
                &[OWNER, ("content-type", "text/plain")],
                &values,
                b"hello",
            );
            if denies && name != "valid" {
                assert_eq!(
                    response.status,
                    403,
                    "{mode} must deny {name}: {}",
                    String::from_utf8_lossy(&response.body)
                );
                assert_eq!(
                    body_of(&response)["error"]["reason"],
                    if name == "missing" {
                        "APP_CHECK_REQUIRED"
                    } else {
                        "APP_CHECK_INVALID"
                    }
                );
            } else {
                assert_eq!(
                    response.status,
                    200,
                    "{mode} must admit {name}: {}",
                    String::from_utf8_lossy(&response.body)
                );
            }
        }
    }
}

// ------------------------------------------------------------------------------------------
// The header contract on this transport (AC-HEADER-001)
// ------------------------------------------------------------------------------------------

#[test]
fn the_storage_transport_refuses_duplicate_folded_empty_and_oversized_app_check_fields() {
    let h = harness(BaselineMode::Enforced);
    let valid = h.token();
    let folded = format!("{valid},{valid}");
    let oversized = "a".repeat(16 * 1024 + 1);
    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("duplicate", vec![valid.as_str(), valid.as_str()]),
        ("folded", vec![folded.as_str()]),
        ("empty", vec![""]),
        ("oversized", vec![oversized.as_str()]),
    ];
    for (name, values) in cases {
        let response = h.call(
            "POST",
            &format!("/v0/b/{BUCKET}/o?name=hdr.txt&uploadType=media"),
            &[OWNER, ("content-type", "text/plain")],
            &values,
            b"hello",
        );
        assert_eq!(response.status, 403, "{name} must never be admitted");
        assert_eq!(body_of(&response)["error"]["reason"], "APP_CHECK_INVALID");
    }
    let read = h.call(
        "GET",
        &format!("/v0/b/{BUCKET}/o/hdr.txt"),
        &[OWNER],
        &[&valid],
        b"",
    );
    assert_eq!(
        read.status, 404,
        "no ambiguous header ever created an object"
    );
}

// ------------------------------------------------------------------------------------------
// Observations (AC-OBS-001)
// ------------------------------------------------------------------------------------------

#[test]
fn storage_observations_name_the_operation_and_never_carry_the_token() {
    let h = harness(BaselineMode::Unenforced);
    let token = h.token();
    let _ = h.call(
        "POST",
        &format!("/v0/b/{BUCKET}/o?name=obs.txt&uploadType=media"),
        &[OWNER, ("content-type", "text/plain")],
        &[&token],
        b"hello",
    );
    let _ = h.call(
        "DELETE",
        &format!("/v0/b/{BUCKET}/o/obs.txt"),
        &[OWNER],
        &["junk"],
        b"",
    );
    let observed = h
        .app_check
        .registry
        .read()
        .expect("readable")
        .observations("demo-app");
    assert_eq!(observed.len(), 2);
    assert_eq!(observed[0].service, "storage");
    assert_eq!(observed[0].operation, "storage.upload");
    assert_eq!(observed[0].app_id, fixture::APP_ID);
    assert_eq!(observed[1].operation, "storage.delete");
    assert_eq!(observed[1].app_id, "unknown");
    assert!(
        !format!("{observed:?}").contains(&token),
        "an observation never carries the raw token"
    );
}

/// Without enforcement `exec` gives the Admin SDK no capability (the plain
/// `STORAGE_EMULATOR_HOST`), so its JSON API traffic is recognised by its dialect and by the
/// absence of browser evidence. That recognition only labels the observation (counters and UI):
/// an `unenforced` policy admits everything either way.
#[test]
fn unenforced_server_side_json_api_traffic_is_observed_as_bypass() {
    use fireemu_core_app_check::CredentialCategory::{Bypass, Missing};

    let h = harness(BaselineMode::Unenforced);
    h.seed_object("obs/admin.txt");
    let before = h
        .app_check
        .registry
        .read()
        .expect("readable")
        .observations("demo-app")
        .len();
    let list = format!("/storage/v1/b/{BUCKET}/o?prefix=obs/");
    // The header set Node's fetch sends from a script (`sec-fetch-mode` only) is a process.
    for (label, headers) in [
        ("no headers", vec![]),
        ("undici sec-fetch-mode", vec![("sec-fetch-mode", "cors")]),
    ] {
        let r = h.call("GET", &list, &headers, &[], b"");
        assert_eq!(
            r.status,
            200,
            "{label}: {}",
            String::from_utf8_lossy(&r.body)
        );
    }
    let upload = h.call(
        "POST",
        &format!("/upload/storage/v1/b/{BUCKET}/o?name=obs/up.txt&uploadType=media"),
        &[("content-type", "text/plain")],
        &[],
        b"hello",
    );
    assert_eq!(upload.status, 200);
    let observed = h
        .app_check
        .registry
        .read()
        .expect("readable")
        .observations("demo-app");
    let fresh = &observed[before..];
    assert_eq!(fresh.len(), 3);
    assert!(
        fresh.iter().all(|o| o.category == Bypass && o.admitted),
        "{fresh:?}"
    );

    // Near misses stay what they were: browser evidence on the JSON API, and the Firebase
    // dialect without a token, are `missing`; both are still admitted, as `unenforced` admits.
    let browser = h.call(
        "GET",
        &list,
        &[("origin", "http://127.0.0.1:5173")],
        &[],
        b"",
    );
    let fetch_metadata = h.call("GET", &list, &[("sec-fetch-site", "same-origin")], &[], b"");
    let firebase = h.call("GET", &format!("/v0/b/{BUCKET}/o"), &[], &[], b"");
    // The Firebase dialect then stops at its own missing Security Rules (400), not at App Check.
    for r in [&browser, &fetch_metadata, &firebase] {
        assert_ne!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    }
    let observed = h
        .app_check
        .registry
        .read()
        .expect("readable")
        .observations("demo-app");
    let tail = &observed[before + 3..];
    assert_eq!(tail.len(), 3);
    assert!(
        tail.iter().all(|o| o.category == Missing && o.admitted),
        "{tail:?}"
    );
}

/// The label never changes a decision: under `enforced` the same credential-less JSON API
/// request is refused, and so is its browser-shaped variant.
#[test]
fn an_enforced_server_side_json_api_request_without_the_capability_is_still_refused() {
    let h = capability_harness(BaselineMode::Enforced);
    let list = format!("/storage/v1/b/{BUCKET}/o");
    for headers in [vec![], vec![("sec-fetch-mode", "cors")]] {
        let r = h.call("GET", &list, &headers, &[], b"");
        assert_eq!(r.status, 403);
        assert_eq!(body_of(&r)["error"]["reason"], "APP_CHECK_REQUIRED");
    }
}

#[test]
fn an_off_storage_service_classifies_nothing() {
    let h = harness(BaselineMode::Off);
    let admitted = h.call(
        "POST",
        &format!("/v0/b/{BUCKET}/o?name=off.txt&uploadType=media"),
        &[OWNER, ("content-type", "text/plain")],
        &["junk", "junk"],
        b"hello",
    );
    assert_eq!(admitted.status, 200);
    assert!(h
        .app_check
        .registry
        .read()
        .expect("readable")
        .observed_projects()
        .is_empty());
}

// ------------------------------------------------------------------------------------------
// Over a real socket: the Storage header allowlist and the preflight (AC-HEADER-001)
// ------------------------------------------------------------------------------------------

async fn raw(addr: std::net::SocketAddr, request: &str) -> String {
    raw_bytes(addr, request.as_bytes()).await
}

async fn raw_bytes(addr: std::net::SocketAddr, request: &[u8]) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    stream.write_all(request).await.expect("write the request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read the response");
    String::from_utf8_lossy(&response).into_owned()
}

/// The Storage listener must forward the App Check field, and must forward every instance:
/// one value is a credential, two are ambiguous and never become one (`INV-APPCHECK-009`).
#[tokio::test]
async fn the_storage_listener_forwards_the_app_check_field_and_refuses_duplicates() {
    let h = harness(BaselineMode::Enforced);
    let token = h.token();
    let state = Arc::new(h.storage);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("a local address");
    let server = tokio::spawn(fireemu_adapter_http::storage_server::serve_storage(
        listener, state,
    ));

    let one = raw(
        addr,
        &format!(
            "POST /v0/b/{BUCKET}/o?name=sock.txt&uploadType=media HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer owner\r\nContent-Type: text/plain\r\nX-Firebase-AppCheck: {token}\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
        ),
    )
    .await;
    assert!(one.starts_with("HTTP/1.1 200"), "{one}");

    let two = raw(
        addr,
        &format!(
            "POST /v0/b/{BUCKET}/o?name=sock2.txt&uploadType=media HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer owner\r\nContent-Type: text/plain\r\nX-Firebase-AppCheck: {token}\r\nx-firebase-appcheck: {token}\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
        ),
    )
    .await;
    assert!(two.starts_with("HTTP/1.1 403"), "{two}");
    assert!(two.contains("APP_CHECK_INVALID"), "{two}");

    let none = raw(
        addr,
        &format!(
            "POST /v0/b/{BUCKET}/o?name=sock3.txt&uploadType=media HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer owner\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
        ),
    )
    .await;
    assert!(none.starts_with("HTTP/1.1 403"), "{none}");
    server.abort();
}

/// Over a real loopback socket the Storage transport forwards the browser evidence the
/// server-side rule reads, and sets the peer flag from the connection: a plain JSON API
/// request passes under `enforced`, and the same request with any browser header, or on the
/// Firebase dialect, does not.
#[tokio::test]
async fn the_storage_listener_admits_server_side_json_api_requests_only() {
    let h = harness(BaselineMode::Enforced);
    h.seed_object("sock/listed.txt");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("a local address");
    let server = tokio::spawn(fireemu_adapter_http::storage_server::serve_storage(
        listener,
        Arc::new(h.storage),
    ));
    let request = |path: &str, extra: &str| {
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{extra}Connection: close\r\n\r\n")
    };
    let list = format!("/storage/v1/b/{BUCKET}/o?prefix=sock/");

    let server_side = raw(addr, &request(&list, "")).await;
    assert!(server_side.starts_with("HTTP/1.1 200"), "{server_side}");
    let undici = raw(addr, &request(&list, "Sec-Fetch-Mode: cors\r\n")).await;
    assert!(undici.starts_with("HTTP/1.1 200"), "{undici}");
    for header in [
        "Origin: http://localhost:5173",
        "Sec-Fetch-Site: same-origin",
        "Sec-Fetch-Dest: empty",
        "Referer: http://localhost:5173/",
        "Cookie: session=1",
    ] {
        let page = raw(addr, &request(&list, &format!("{header}\r\n"))).await;
        assert!(page.starts_with("HTTP/1.1 403"), "{header}: {page}");
        assert!(page.contains("APP_CHECK_REQUIRED"), "{header}: {page}");
    }
    let firebase = raw(addr, &request(&format!("/v0/b/{BUCKET}/o"), "")).await;
    assert!(firebase.starts_with("HTTP/1.1 403"), "{firebase}");
    server.abort();
}

/// A browser header whose value is not ASCII is still browser evidence: presence decides, not
/// the decoded value, so the bytes cannot be used to make a page look like a process.
#[tokio::test]
async fn a_non_ascii_browser_header_still_keeps_the_request_ordinary() {
    let h = harness(BaselineMode::Enforced);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("a local address");
    let server = tokio::spawn(fireemu_adapter_http::storage_server::serve_storage(
        listener,
        Arc::new(h.storage),
    ));
    let list = format!("/storage/v1/b/{BUCKET}/o");
    for header in [
        "Cookie",
        "Referer",
        "Sec-Fetch-Site",
        "Sec-Fetch-Dest",
        "Origin",
    ] {
        let mut request =
            format!("GET {list} HTTP/1.1\r\nHost: 127.0.0.1\r\n{header}: ").into_bytes();
        request.extend_from_slice(&[0xff, 0xfe, b'x']);
        request.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
        let response = raw_bytes(addr, &request).await;
        assert!(
            !response.starts_with("HTTP/1.1 200"),
            "{header}: {response}"
        );
        assert!(
            response.contains("APP_CHECK_REQUIRED") || response.starts_with("HTTP/1.1 403"),
            "{header}: {response}"
        );
    }
    // A non-ASCII `Authorization` is a credential that is present: it cannot be shown not to be
    // the client SDK's, so the request stays ordinary.
    let mut request =
        format!("GET {list} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Firebase ").into_bytes();
    request.extend_from_slice(&[0xff, b'x']);
    request.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    let response = raw_bytes(addr, &request).await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    // Any other header with a non-ASCII value is still dropped, as before: here the content type
    // of an upload falls back to the default instead of carrying replacement characters.
    let mut upload = format!(
        "POST /upload/storage/v1/b/{BUCKET}/o?name=ct.txt&uploadType=media HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1\r\nConnection: close\r\nContent-Type: text/"
    )
    .into_bytes();
    upload.extend_from_slice(&[0xff]);
    upload.extend_from_slice(b"\r\n\r\nx");
    let stored = raw_bytes(addr, &upload).await;
    assert!(stored.starts_with("HTTP/1.1 200"), "{stored}");
    assert!(!stored.contains('\u{fffd}'), "{stored}");
    // The same request without the header is a process and passes.
    let plain = raw(
        addr,
        &format!("GET {list} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(plain.starts_with("HTTP/1.1 200"), "{plain}");
    server.abort();
}

/// A browser-evidence or `Authorization` header that appears more than once is present, never
/// absent: the transport folds a duplicate to an empty value, which must not erase the evidence
/// (or the client SDK's credential) the request carries.
#[tokio::test]
async fn a_duplicated_browser_or_authorization_header_still_keeps_the_request_ordinary() {
    let h = harness(BaselineMode::Enforced);
    h.seed_object("dup/o.txt");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("a local address");
    let server = tokio::spawn(fireemu_adapter_http::storage_server::serve_storage(
        listener,
        Arc::new(h.storage),
    ));
    let list = format!("/storage/v1/b/{BUCKET}/o?prefix=dup/");
    let request = |extra: &str| {
        format!("GET {list} HTTP/1.1\r\nHost: 127.0.0.1\r\n{extra}Connection: close\r\n\r\n")
    };
    for extra in [
        "Sec-Fetch-Site: same-origin\r\nSec-Fetch-Site: same-origin\r\n",
        "Sec-Fetch-Dest: empty\r\nSec-Fetch-Dest: empty\r\n",
        "Cookie: a=1\r\nCookie: b=2\r\n",
        "Referer: http://127.0.0.1:5173/\r\nReferer: http://127.0.0.1:5173/\r\n",
        "Origin: http://127.0.0.1:5173\r\nOrigin: http://127.0.0.1:5173\r\n",
        "Authorization: Firebase a\r\nAuthorization: Firebase b\r\n",
        "Authorization: Bearer a\r\nAuthorization: Firebase b\r\n",
    ] {
        let response = raw(addr, &request(extra)).await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "{extra:?}: {response}"
        );
        assert!(
            response.contains("APP_CHECK_REQUIRED"),
            "{extra:?}: {response}"
        );
    }
    // A header that is not evidence may repeat, and the single header is still a process.
    for extra in [
        "X-Goog-Hash: crc32c=AAAAAA==\r\nX-Goog-Hash: md5=1B2M2Y8AsgTpgAmY7PhCfg==\r\n",
        "Range: bytes=0-1\r\nRange: bytes=2-3\r\n",
        "Sec-Fetch-Mode: cors\r\nSec-Fetch-Mode: cors\r\n",
        "Sec-Fetch-Mode: cors\r\n",
    ] {
        let response = raw(addr, &request(extra)).await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "{extra:?}: {response}"
        );
    }
    // The privileged rules route reads the same evidence: a duplicated `Sec-Fetch-Site` is a page.
    let set_rules = |extra: &str| {
        format!("PUT /internal/setRules HTTP/1.1\r\nHost: 127.0.0.1\r\n{extra}Content-Length: 2\r\nConnection: close\r\n\r\n{{}}")
    };
    let page = raw(
        addr,
        &set_rules("Sec-Fetch-Site: same-origin\r\nSec-Fetch-Site: same-origin\r\n"),
    )
    .await;
    assert!(page.starts_with("HTTP/1.1 403"), "{page}");
    let process = raw(addr, &set_rules("")).await;
    assert!(!process.starts_with("HTTP/1.1 403"), "{process}");
    server.abort();
}

/// The Storage preflight advertises the App Check request header so a browser SDK may send it.
#[tokio::test]
async fn the_storage_preflight_allows_the_app_check_request_header() {
    let h = harness(BaselineMode::Enforced);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("a local address");
    let server = tokio::spawn(fireemu_adapter_http::storage_server::serve_storage(
        listener,
        Arc::new(h.storage),
    ));
    // The preflight reflects the requested headers, as the official emulator's cors
    // middleware reflects them, so a browser SDK that asks for the App Check field gets it.
    let response = raw(
        addr,
        &format!("OPTIONS /v0/b/{BUCKET}/o HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://localhost:5173\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: authorization,x-firebase-appcheck\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 204"), "{response}");
    assert!(
        response.to_lowercase().contains("x-firebase-appcheck"),
        "{response}"
    );
    server.abort();
}
