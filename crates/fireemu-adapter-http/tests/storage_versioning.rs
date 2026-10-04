//! Object versioning on the JSON API: the bucket resource's `versioning` (GET and PATCH), the
//! `generation` selector on object reads and deletes, `versions=true` listing, and the events an
//! overwrite or a delete announces. Production-only behaviour (the official emulator has no bucket
//! route and no versioning): the emulator profile serves it as an extension. The Archived event
//! shape, its order before Finalized and the absence of a Deleted event on a plain live delete are
//! unrecorded (see `StorageEvent::Archived`).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fireemu_adapter_http::storage::{
    handle, AtomicStorageEventSink, StorageEventPublication, StorageRequest, StorageResponse,
    StorageRulesRegistry, StorageState,
};
use fireemu_core_auth::jwt::TokenAcceptance;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_storage::store::StorageEvent;
use fireemu_core_storage::store::StorageState as ObjectStore;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const BUCKET: &str = "demo-app.appspot.com";
const OWNER: (&str, &str) = ("authorization", "Bearer owner");

type Seen = Arc<Mutex<Vec<(&'static str, u64)>>>;

struct Recording(Seen);
struct Publication(Seen, Vec<(&'static str, u64)>);

impl StorageEventPublication for Publication {
    fn publish(self: Box<Self>) {
        self.0.lock().unwrap().extend(self.1);
    }
}
impl AtomicStorageEventSink for Recording {
    fn reserve(
        &self,
        event: &StorageEvent,
    ) -> Result<Box<dyn StorageEventPublication>, fireemu_core_types::admission::EventAdmissionError>
    {
        let entry = match event {
            StorageEvent::Finalized(m) => ("finalized", m.generation),
            StorageEvent::Deleted(m) => ("deleted", m.generation),
            StorageEvent::MetadataUpdated(m) => ("metadata", m.generation),
            StorageEvent::Archived { object, .. } => ("archived", object.generation),
        };
        Ok(Box::new(Publication(self.0.clone(), vec![entry])))
    }
}

fn state(acceptance: TokenAcceptance) -> (StorageState, Seen) {
    let seen: Seen = Arc::default();
    let state = StorageState {
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
            LoadedRules::default(),
        )))),
        project: "demo-app".to_owned(),
        events: Some(Arc::new(Recording(seen.clone()))),
        barrier: None,
        firestore: None,
        faults: None,
        clock_observer: None,
        app_check_policy: None,
        admin_capability: None,
        token_acceptance: acceptance,
        control_token: Some("storage-test-control-token".to_owned()),
    };
    (state, seen)
}

const PROFILES: [TokenAcceptance; 2] = [TokenAcceptance::Verified, TokenAcceptance::EmulatorMock];

fn call(s: &StorageState, method: &str, target: &str, body: &[u8]) -> StorageResponse {
    let (path, query) = target.split_once('?').map_or((target, ""), |(p, q)| (p, q));
    handle(
        s,
        StorageRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            query: query.to_owned(),
            host: Some("127.0.0.1:9199".to_owned()),
            headers: BTreeMap::from([
                (OWNER.0.to_owned(), OWNER.1.to_owned()),
                ("content-type".to_owned(), "application/json".to_owned()),
            ]),
            app_check: Vec::new(),
            body: body.to_vec(),
        },
    )
}
fn body(r: &StorageResponse) -> Value {
    serde_json::from_slice(&r.body).unwrap_or(Value::Null)
}
fn set_versioning(s: &StorageState, enabled: bool) {
    let r = call(
        s,
        "PATCH",
        &format!("/storage/v1/b/{BUCKET}"),
        json!({"versioning": {"enabled": enabled}})
            .to_string()
            .as_bytes(),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}
fn upload(s: &StorageState, name: &str, data: &str) -> Value {
    let r = call(
        s,
        "POST",
        &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name={name}"),
        data.as_bytes(),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    body(&r)
}
fn drain(seen: &Seen) -> Vec<(&'static str, u64)> {
    std::mem::take(&mut seen.lock().unwrap())
}
fn gen(v: &Value) -> u64 {
    v["generation"].as_str().unwrap().parse().unwrap()
}

#[test]
fn the_bucket_resource_reads_and_writes_versioning_only() {
    for acceptance in PROFILES {
        let (s, _) = state(acceptance);
        let r = call(&s, "GET", &format!("/storage/v1/b/{BUCKET}"), b"");
        assert_eq!(r.status, 200);
        let bucket = body(&r);
        assert_eq!(bucket["kind"], "storage#bucket");
        assert_eq!(bucket["name"], BUCKET);
        assert!(
            bucket.get("versioning").is_none(),
            "never configured: {bucket}"
        );

        let r = call(
            &s,
            "PATCH",
            &format!("/storage/v1/b/{BUCKET}"),
            br#"{"versioning":{"enabled":true}}"#,
        );
        assert_eq!(r.status, 200);
        assert_eq!(body(&r)["versioning"], json!({"enabled": true}));
        let read = body(&call(&s, "GET", &format!("/storage/v1/b/{BUCKET}"), b""));
        assert_eq!(read["versioning"], json!({"enabled": true}), "readback");

        // `fields` narrows the answer to the named top-level fields, as the recorder asks.
        let narrowed = body(&call(
            &s,
            "GET",
            &format!("/storage/v1/b/{BUCKET}?fields=versioning"),
            b"",
        ));
        assert_eq!(narrowed, json!({"versioning": {"enabled": true}}));

        set_versioning(&s, false);
        let off = body(&call(&s, "GET", &format!("/storage/v1/b/{BUCKET}"), b""));
        assert_ne!(off["versioning"], json!({"enabled": true}), "{off}");
    }
}

#[test]
fn a_bucket_patch_refuses_anything_but_versioning_enabled() {
    for acceptance in PROFILES {
        let (s, _) = state(acceptance);
        for bad in [
            "[]",
            r#"{"versioning": true}"#,
            r#"{"versioning": {"enabled": "yes"}}"#,
            r#"{"versioning": {"enabled": true, "extra": 1}}"#,
            r#"{"labels": {"a": "b"}}"#,
            r#"{"versioning": {"enabled": true}, "location": "EU"}"#,
            "not json",
        ] {
            let r = call(
                &s,
                "PATCH",
                &format!("/storage/v1/b/{BUCKET}"),
                bad.as_bytes(),
            );
            assert_eq!(r.status, 400, "{bad}: {}", String::from_utf8_lossy(&r.body));
            let read = body(&call(&s, "GET", &format!("/storage/v1/b/{BUCKET}"), b""));
            assert!(
                read.get("versioning").is_none(),
                "{bad} changed nothing: {read}"
            );
        }
        // An empty body changes nothing and succeeds.
        assert_eq!(
            call(&s, "PATCH", &format!("/storage/v1/b/{BUCKET}"), b"{}").status,
            200
        );
    }
}

#[test]
fn an_overwrite_in_a_versioned_bucket_archives_and_the_old_generation_is_readable_by_number() {
    for acceptance in PROFILES {
        let (s, seen) = state(acceptance);
        set_versioning(&s, true);
        let first = upload(&s, "o.txt", "before");
        let _ = drain(&seen);
        let second = upload(&s, "o.txt", "updated");
        assert_eq!(
            drain(&seen),
            vec![("archived", gen(&first)), ("finalized", gen(&second))]
        );
        // Without a generation: the live one.
        let live = call(
            &s,
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/o.txt?alt=media"),
            b"",
        );
        assert_eq!(live.body.as_ref(), b"updated");
        // By number: the noncurrent one, bytes and metadata with timeDeleted.
        let old_media = call(
            &s,
            "GET",
            &format!(
                "/storage/v1/b/{BUCKET}/o/o.txt?alt=media&generation={}",
                gen(&first)
            ),
            b"",
        );
        assert_eq!(old_media.status, 200);
        assert_eq!(old_media.body.as_ref(), b"before");
        let old_meta = body(&call(
            &s,
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/o.txt?generation={}", gen(&first)),
            b"",
        ));
        assert_eq!(gen(&old_meta), gen(&first));
        assert!(old_meta["timeDeleted"].is_string(), "{old_meta}");
        let live_meta = body(&call(
            &s,
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/o.txt?generation={}", gen(&second)),
            b"",
        ));
        assert!(live_meta.get("timeDeleted").is_none(), "{live_meta}");
        // An unknown generation is not found.
        let missing = call(
            &s,
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/o.txt?generation=424242"),
            b"",
        );
        assert_eq!(missing.status, 404);
    }
}

#[test]
fn an_overwrite_in_an_unversioned_bucket_keeps_nothing_and_announces_no_archive() {
    let (s, seen) = state(TokenAcceptance::EmulatorMock);
    let first = upload(&s, "o.txt", "before");
    let _ = drain(&seen);
    let second = upload(&s, "o.txt", "updated");
    // DOCUMENTED, UNRECORDED: the replaced generation is announced as deleted before the new one
    // is finalized (https://firebase.google.com/docs/functions/gcp-storage-events).
    assert_eq!(
        drain(&seen),
        vec![("deleted", gen(&first)), ("finalized", gen(&second))]
    );
    let gone = call(
        &s,
        "GET",
        &format!("/storage/v1/b/{BUCKET}/o/o.txt?generation={}", gen(&first)),
        b"",
    );
    assert_eq!(gone.status, 404);
}

#[test]
fn deleting_by_number_is_permanent_and_a_plain_delete_of_a_versioned_object_archives_it() {
    for acceptance in PROFILES {
        let (s, seen) = state(acceptance);
        set_versioning(&s, true);
        let first = upload(&s, "o.txt", "one");
        let second = upload(&s, "o.txt", "two");
        let _ = drain(&seen);
        // A noncurrent generation, by number: gone for good, a delete event.
        let r = call(
            &s,
            "DELETE",
            &format!("/storage/v1/b/{BUCKET}/o/o.txt?generation={}", gen(&first)),
            b"",
        );
        assert_eq!(r.status, 204);
        assert_eq!(drain(&seen), vec![("deleted", gen(&first))]);
        let gone = call(
            &s,
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/o.txt?generation={}", gen(&first)),
            b"",
        );
        assert_eq!(gone.status, 404);
        // A plain delete: the live one is archived, not removed, and no Deleted event.
        let r = call(
            &s,
            "DELETE",
            &format!("/storage/v1/b/{BUCKET}/o/o.txt"),
            b"",
        );
        assert_eq!(r.status, 204);
        assert_eq!(drain(&seen), vec![("archived", gen(&second))]);
        assert_eq!(
            call(&s, "GET", &format!("/storage/v1/b/{BUCKET}/o/o.txt"), b"").status,
            404,
            "no live object"
        );
        let kept = call(
            &s,
            "GET",
            &format!(
                "/storage/v1/b/{BUCKET}/o/o.txt?alt=media&generation={}",
                gen(&second)
            ),
            b"",
        );
        assert_eq!(kept.body.as_ref(), b"two");
        // The archived generation can then be deleted by number.
        let r = call(
            &s,
            "DELETE",
            &format!("/storage/v1/b/{BUCKET}/o/o.txt?generation={}", gen(&second)),
            b"",
        );
        assert_eq!(r.status, 204);
        assert_eq!(drain(&seen), vec![("deleted", gen(&second))]);
    }
}

#[test]
fn versions_true_lists_every_generation_by_name_then_generation() {
    for acceptance in PROFILES {
        let (s, _) = state(acceptance);
        set_versioning(&s, true);
        let a1 = upload(&s, "a.txt", "1");
        let a2 = upload(&s, "a.txt", "22");
        let c1 = upload(&s, "c.txt", "3");
        let listed = |query: &str| -> Vec<(String, u64, bool)> {
            let r = call(&s, "GET", &format!("/storage/v1/b/{BUCKET}/o{query}"), b"");
            assert_eq!(r.status, 200);
            body(&r)["items"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|item| {
                    (
                        item["name"].as_str().unwrap().to_owned(),
                        gen(item),
                        item.get("timeDeleted").is_some(),
                    )
                })
                .collect()
        };
        assert_eq!(
            listed(""),
            vec![
                ("a.txt".to_owned(), gen(&a2), false),
                ("c.txt".to_owned(), gen(&c1), false)
            ],
            "live objects only by default"
        );
        assert_eq!(
            listed("?versions=true"),
            vec![
                ("a.txt".to_owned(), gen(&a1), true),
                ("a.txt".to_owned(), gen(&a2), false),
                ("c.txt".to_owned(), gen(&c1), false),
            ]
        );
        assert_eq!(
            listed("?versions=true&prefix=c"),
            vec![("c.txt".to_owned(), gen(&c1), false)]
        );
        assert_eq!(listed("?versions=false").len(), 2);
    }
}

#[test]
fn copy_resumable_and_multipart_overwrites_archive_too() {
    let (s, seen) = state(TokenAcceptance::EmulatorMock);
    set_versioning(&s, true);
    let src = upload(&s, "src.txt", "source");
    let dst1 = upload(&s, "dst.txt", "old");
    let _ = drain(&seen);
    let r = call(
        &s,
        "POST",
        &format!("/storage/v1/b/{BUCKET}/o/src.txt/copyTo/b/{BUCKET}/o/dst.txt"),
        b"{}",
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let dst2 = body(&r);
    assert_eq!(
        drain(&seen),
        vec![("archived", gen(&dst1)), ("finalized", gen(&dst2))]
    );
    assert_ne!(gen(&dst2), gen(&src));
    // The resumable upload path.
    let start = call(
        &s,
        "POST",
        &format!("/upload/storage/v1/b/{BUCKET}/o?uploadType=resumable&name=dst.txt"),
        b"{}",
    );
    assert_eq!(start.status, 200);
    let location = start
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .map(|(_, v)| v.clone())
        .unwrap();
    let target = location
        .strip_prefix("http://127.0.0.1:9199")
        .unwrap()
        .to_owned();
    let done = call(&s, "PUT", &target, b"resumed");
    assert_eq!(done.status, 200, "{}", String::from_utf8_lossy(&done.body));
    let dst3 = body(&done);
    assert_eq!(
        drain(&seen),
        vec![("archived", gen(&dst2)), ("finalized", gen(&dst3))]
    );
}

#[test]
fn a_versions_listing_folds_prefixes_and_pages_through_every_generation() {
    for acceptance in PROFILES {
        let (s, _) = state(acceptance);
        set_versioning(&s, true);
        let d1 = upload(&s, "dir/a.txt", "1");
        let d2 = upload(&s, "dir/a.txt", "22");
        let d3 = upload(&s, "dir/b.txt", "3");
        let top = upload(&s, "top.txt", "4");
        // Folded: both generations of `dir/a.txt` and `dir/b.txt` fold into one prefix.
        let folded = body(&call(
            &s,
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o?versions=true&delimiter=/"),
            b"",
        ));
        assert_eq!(folded["prefixes"], json!(["dir/"]), "{folded}");
        let items = folded["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(gen(&items[0]), gen(&top));
        // Paged: every generation exactly once, in order, across pages of two.
        let mut seen = Vec::new();
        let mut token: Option<String> = None;
        for _ in 0..10 {
            let query = token
                .as_ref()
                .map_or(String::new(), |t| format!("&pageToken={t}"));
            let page = body(&call(
                &s,
                "GET",
                &format!("/storage/v1/b/{BUCKET}/o?versions=true&maxResults=2{query}"),
                b"",
            ));
            for item in page["items"].as_array().cloned().unwrap_or_default() {
                seen.push(gen(&item));
            }
            token = page["nextPageToken"].as_str().map(str::to_owned);
            if token.is_none() {
                break;
            }
        }
        assert_eq!(seen, vec![gen(&d1), gen(&d2), gen(&d3), gen(&top)]);
    }
}

#[test]
fn deleting_an_unknown_generation_is_not_found_and_changes_nothing() {
    let (s, seen) = state(TokenAcceptance::Verified);
    set_versioning(&s, true);
    let live = upload(&s, "o.txt", "data");
    let _ = drain(&seen);
    let r = call(
        &s,
        "DELETE",
        &format!("/storage/v1/b/{BUCKET}/o/o.txt?generation=424242"),
        b"",
    );
    assert_eq!(r.status, 404);
    assert!(drain(&seen).is_empty());
    let still = call(
        &s,
        "GET",
        &format!("/storage/v1/b/{BUCKET}/o/o.txt?generation={}", gen(&live)),
        b"",
    );
    assert_eq!(still.status, 200);
}

fn media(s: &StorageState, name: &str) -> Vec<u8> {
    let r = call(
        s,
        "GET",
        &format!("/storage/v1/b/{BUCKET}/o/{name}?alt=media"),
        b"",
    );
    assert_eq!(r.status, 200);
    r.body.to_vec()
}

#[test]
fn copy_and_rewrite_can_read_a_noncurrent_source_generation() {
    for acceptance in PROFILES {
        let (s, seen) = state(acceptance);
        set_versioning(&s, true);
        let one = upload(&s, "o.txt", "one");
        let two = upload(&s, "o.txt", "two");
        let _ = drain(&seen);
        // Restoring an old generation: copy it over the live name.
        let r = call(
            &s,
            "POST",
            &format!(
                "/storage/v1/b/{BUCKET}/o/o.txt/copyTo/b/{BUCKET}/o/o.txt?sourceGeneration={}",
                gen(&one)
            ),
            b"{}",
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let restored = body(&r);
        assert_eq!(media(&s, "o.txt"), b"one");
        assert_ne!(gen(&restored), gen(&one), "a copy is a new generation");
        assert_eq!(
            drain(&seen),
            vec![("archived", gen(&two)), ("finalized", gen(&restored))]
        );
        // The source version is still there, and a rewrite reads it too.
        let r = call(
            &s,
            "POST",
            &format!(
                "/storage/v1/b/{BUCKET}/o/o.txt/rewriteTo/b/{BUCKET}/o/copy.txt?sourceGeneration={}",
                gen(&two)
            ),
            b"{}",
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(body(&r)["resource"]["size"], "3");
        assert_eq!(media(&s, "copy.txt"), b"two");
        // A generation that never existed is still not found, and changes nothing.
        let _ = drain(&seen);
        let r = call(
            &s,
            "POST",
            &format!(
                "/storage/v1/b/{BUCKET}/o/o.txt/copyTo/b/{BUCKET}/o/x.txt?sourceGeneration=424242"
            ),
            b"{}",
        );
        assert_eq!(r.status, 404);
        assert!(drain(&seen).is_empty());
    }
}

#[test]
fn patching_a_generation_changes_that_generation_and_never_the_live_object() {
    for acceptance in PROFILES {
        let (s, seen) = state(acceptance);
        set_versioning(&s, true);
        let one = upload(&s, "o.txt", "one");
        let two = upload(&s, "o.txt", "two");
        let _ = drain(&seen);
        let r = call(
            &s,
            "PATCH",
            &format!("/storage/v1/b/{BUCKET}/o/o.txt?generation={}", gen(&one)),
            br#"{"metadata":{"k":"v"}}"#,
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let patched = body(&r);
        assert_eq!(gen(&patched), gen(&one));
        assert_eq!(patched["metageneration"], "2");
        assert_eq!(patched["metadata"], json!({"k": "v"}));
        // The live object is untouched.
        let live = body(&call(
            &s,
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/o.txt"),
            b"",
        ));
        assert_eq!(gen(&live), gen(&two));
        assert_eq!(live["metageneration"], "1");
        assert!(live.get("metadata").is_none(), "{live}");
        // The noncurrent version keeps the change.
        let old = body(&call(
            &s,
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/o.txt?generation={}", gen(&one)),
            b"",
        ));
        assert_eq!(old["metageneration"], "2");
        // UNRECORDED: a metadata change of a noncurrent version announces nothing.
        assert!(drain(&seen).is_empty());
        // The live generation by number patches the live object, as a plain patch does.
        let r = call(
            &s,
            "PATCH",
            &format!("/storage/v1/b/{BUCKET}/o/o.txt?generation={}", gen(&two)),
            br#"{"contentType":"text/x-live"}"#,
        );
        assert_eq!(r.status, 200);
        assert_eq!(body(&r)["metageneration"], "2");
        assert_eq!(drain(&seen), vec![("metadata", gen(&two))]);
    }
}

#[test]
fn patching_an_unknown_generation_is_not_found_in_strict_and_patches_the_live_object_in_the_emulator(
) {
    let (s, _) = state(TokenAcceptance::Verified);
    upload(&s, "o.txt", "one");
    let r = call(
        &s,
        "PATCH",
        &format!("/storage/v1/b/{BUCKET}/o/o.txt?generation=424242"),
        br#"{"contentType":"text/x"}"#,
    );
    assert_eq!(r.status, 404);
    let live = body(&call(
        &s,
        "GET",
        &format!("/storage/v1/b/{BUCKET}/o/o.txt"),
        b"",
    ));
    assert_eq!(live["metageneration"], "1", "nothing changed");
    // The official emulator never reads `generation` on a patch and completes it; the emulator
    // profile keeps completing it rather than refusing what that emulator accepts.
    let (s, _) = state(TokenAcceptance::EmulatorMock);
    upload(&s, "o.txt", "one");
    let r = call(
        &s,
        "PATCH",
        &format!("/storage/v1/b/{BUCKET}/o/o.txt?generation=424242"),
        br#"{"contentType":"text/x"}"#,
    );
    assert_eq!(r.status, 200);
}

#[test]
fn a_bucket_that_does_not_exist_is_not_found_and_patching_it_stores_nothing() {
    for acceptance in PROFILES {
        let (s, _) = state(acceptance);
        let ghost = "/storage/v1/b/ghost-bucket";
        assert_eq!(call(&s, "GET", ghost, b"").status, 404);
        let r = call(&s, "PATCH", ghost, br#"{"versioning":{"enabled":true}}"#);
        assert_eq!(r.status, 404, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(body(&r)["error"]["code"], 404);
        assert_eq!(body(&r)["error"]["errors"][0]["reason"], "notFound");
        assert_eq!(
            call(&s, "GET", ghost, b"").status,
            404,
            "nothing was stored"
        );
        // The project's default buckets exist from the start; any bucket holding an object, or
        // configured earlier, exists too.
        assert_eq!(
            call(&s, "GET", "/storage/v1/b/demo-app.firebasestorage.app", b"").status,
            200
        );
        assert_eq!(
            call(&s, "GET", &format!("/storage/v1/b/{BUCKET}"), b"").status,
            200
        );
        let r = call(
            &s,
            "POST",
            "/upload/storage/v1/b/other-bucket/o?uploadType=media&name=a.txt",
            b"x",
        );
        assert_eq!(r.status, 200);
        assert_eq!(
            call(&s, "GET", "/storage/v1/b/other-bucket", b"").status,
            200
        );
        assert_eq!(
            call(
                &s,
                "PATCH",
                "/storage/v1/b/other-bucket",
                br#"{"versioning":{"enabled":true}}"#
            )
            .status,
            200
        );
    }
}

#[test]
fn the_fields_projection_selects_nested_fields() {
    for acceptance in PROFILES {
        let (s, _) = state(acceptance);
        set_versioning(&s, true);
        let get = |fields: &str| {
            body(&call(
                &s,
                "GET",
                &format!("/storage/v1/b/{BUCKET}?fields={fields}"),
                b"",
            ))
        };
        assert_eq!(
            get("versioning/enabled"),
            json!({"versioning": {"enabled": true}})
        );
        assert_eq!(
            get("versioning(enabled)"),
            json!({"versioning": {"enabled": true}})
        );
        assert_eq!(
            get("name,versioning(enabled)"),
            json!({"name": BUCKET, "versioning": {"enabled": true}})
        );
        // A comma inside parentheses belongs to the group; one outside separates selectors.
        assert_eq!(
            get("versioning(enabled,nothing),name"),
            json!({"name": BUCKET, "versioning": {"enabled": true}})
        );
        assert_eq!(
            get("name,versioning(nothing,enabled)"),
            json!({"name": BUCKET, "versioning": {"enabled": true}})
        );
        assert_eq!(get("versioning/nothing"), json!({"versioning": {}}));
        assert_eq!(get("nothing"), json!({}));
    }
}

#[test]
fn a_versions_listing_refuses_a_page_token_it_cannot_read() {
    for acceptance in PROFILES {
        let (s, _) = state(acceptance);
        set_versioning(&s, true);
        upload(&s, "a.txt", "1");
        for token in ["garbage", "3", "", "i:notanumber:a.txt"] {
            let r = call(
                &s,
                "GET",
                &format!("/storage/v1/b/{BUCKET}/o?versions=true&pageToken={token}"),
                b"",
            );
            if token.is_empty() {
                // An empty token is no token.
                assert_eq!(r.status, 200, "{token:?}");
            } else {
                assert_eq!(
                    r.status,
                    400,
                    "{token:?}: {}",
                    String::from_utf8_lossy(&r.body)
                );
            }
        }
    }
}

#[test]
fn a_versions_page_token_is_a_cursor_that_survives_writes_between_pages() {
    for acceptance in PROFILES {
        let (s, _) = state(acceptance);
        set_versioning(&s, true);
        let a1 = upload(&s, "a.txt", "1");
        let a2 = upload(&s, "a.txt", "22");
        let b1 = upload(&s, "b.txt", "3");
        let c1 = upload(&s, "c.txt", "4");
        let page = |token: Option<&str>| {
            let query = token.map_or(String::new(), |t| format!("&pageToken={t}"));
            body(&call(
                &s,
                "GET",
                &format!("/storage/v1/b/{BUCKET}/o?versions=true&maxResults=1{query}"),
                b"",
            ))
        };
        let first = page(None);
        assert_eq!(gen(&first["items"][0]), gen(&a1));
        let token = first["nextPageToken"].as_str().unwrap().to_owned();
        // An entry before the cursor disappears between the pages: an offset would now skip `a2`.
        let r = call(
            &s,
            "DELETE",
            &format!("/storage/v1/b/{BUCKET}/o/a.txt?generation={}", gen(&a1)),
            b"",
        );
        assert_eq!(r.status, 204);
        // A new generation of an earlier name appears before the cursor too.
        let mut seen = Vec::new();
        let mut next = Some(token);
        while let Some(t) = next {
            let p = page(Some(&t));
            for item in p["items"].as_array().cloned().unwrap_or_default() {
                seen.push(gen(&item));
            }
            next = p["nextPageToken"].as_str().map(str::to_owned);
        }
        assert_eq!(seen, vec![gen(&a2), gen(&b1), gen(&c1)]);
    }
}
