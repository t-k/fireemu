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
use std::sync::{Arc, Mutex, RwLock};

use app_check_support as fixture;
use ftd_adapter_http::storage::{handle, StorageRequest, StorageResponse, StorageState};
use ftd_core_app_check::verify::BaselineMode;
use ftd_core_auth::mfa::TotpPolicy;
use ftd_core_auth::store::AuthStore;
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_storage::store::StorageState as ObjectStore;
use ftd_core_types::determinism::SplitMix64;
use serde_json::Value;

const BUCKET: &str = "demo-app.appspot.com";
const OWNER: (&str, &str) = ("authorization", "Bearer owner");

struct Harness {
    storage: StorageState,
    app_check: Arc<ftd_adapter_http::app_check::AppCheckState>,
    clock: Arc<Mutex<ftd_core_session::clock::VirtualClock>>,
}

fn harness(mode: BaselineMode) -> Harness {
    let clock = fixture::clock();
    let app_check = fixture::app_check_state(1, clock.clone());
    let storage = StorageState {
        store: Mutex::new(ObjectStore::new(9)),
        clock: clock.clone(),
        auth: Arc::new(ftd_core_auth::store::AuthRegistry::new(
            "demo-app",
            Arc::new(Mutex::new(AuthStore::new(
                "demo-app",
                SplitMix64::new(3),
                TotpPolicy::default(),
            ))),
        )),
        tenancy: None,
        rules: Arc::new(RwLock::new(LoadedRules::default())),
        project: "demo-app".to_owned(),
        events: None,
        barrier: None,
        firestore: None,
        faults: None,
        clock_observer: None,
        app_check_policy: fixture::policy(&app_check, "storage", mode),
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
        let (path, query) = path_and_query
            .split_once('?')
            .map_or((path_and_query, ""), |(p, q)| (p, q));
        handle(
            &self.storage,
            StorageRequest {
                method: method.to_owned(),
                path: path.to_owned(),
                query: query.to_owned(),
                host: Some("127.0.0.1:9199".to_owned()),
                headers: headers
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect::<BTreeMap<_, _>>(),
                app_check: app_check.iter().map(|v| (*v).to_owned()).collect(),
                body: body.to_vec(),
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
            .advance(ftd_core_types::time::LogicalDuration::from_seconds(seconds))
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
    assert_eq!(admitted.body, b"hello");
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
    let h = harness(BaselineMode::Enforced);
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
    let h = harness(BaselineMode::Enforced);
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
    let h = harness(BaselineMode::Enforced);
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
        .observations();
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
        .observations()
        .is_empty());
}

// ------------------------------------------------------------------------------------------
// Over a real socket: the Storage header allowlist and the preflight (AC-HEADER-001)
// ------------------------------------------------------------------------------------------

async fn raw(addr: std::net::SocketAddr, request: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write the request");
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
    let server = tokio::spawn(ftd_adapter_http::storage_server::serve_storage(
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

/// The Storage preflight advertises the App Check request header so a browser SDK may send it.
#[tokio::test]
async fn the_storage_preflight_allows_the_app_check_request_header() {
    let h = harness(BaselineMode::Enforced);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("a local address");
    let server = tokio::spawn(ftd_adapter_http::storage_server::serve_storage(
        listener,
        Arc::new(h.storage),
    ));
    let response = raw(
        addr,
        &format!("OPTIONS /v0/b/{BUCKET}/o HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://localhost:5173\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 204"), "{response}");
    assert!(
        response.to_lowercase().contains("x-firebase-appcheck"),
        "{response}"
    );
    server.abort();
}
