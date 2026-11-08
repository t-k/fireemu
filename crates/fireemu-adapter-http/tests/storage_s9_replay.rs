//! Replays every row of the STORAGE-RULES-S9 production recording (two recordings, 2026-11-08)
//! through the Storage handler in both profiles.
//!
//! The fixture `fixtures/storage_s9_production.json` holds the answers production gave to
//! anonymous Firebase v0 requests (object metadata, media, list) under three released rulesets
//! (`s9`, `units`, `lists`) and the outcome of loading three more rulesets. The project, bucket
//! and run prefix are masked (`<bucket>`, `<P>`). Objects are created with the owner credential
//! (rules never apply to it), exactly as the recorder did.
//!
//! The strict profile follows production; the emulator profile is held to the same statuses.
//! `pub-plain-media` is excluded: recording 1 answered 403 and recording 2 answered 200 while
//! the `s9` publication was not in force, so the row is not settled and needs a re-record.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use fireemu_adapter_http::storage::{handle, StorageRequest, StorageRulesRegistry, StorageState};
use fireemu_core_auth::jwt::TokenAcceptance;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_storage::store::StorageState as ObjectStore;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::Value;

const BUCKET: &str = "demo-storage-s9.appspot.com";
const P: &str = "storage-rules-s9/sr-test/rec1";
const FIXTURE: &str = include_str!("fixtures/storage_s9_production.json");
const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const FIRE_NAME: &str = "é\u{1F525}x";
const FIRE_META: &str = "\u{1F525}x";

/// Rows that are not settled by the recordings (see the module comment).
const EXCLUDED_ROWS: &[&str] = &["pub-plain-media"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Strict,
    Emulator,
}

fn state(profile: Profile, rules: &str) -> StorageState {
    let acceptance = match profile {
        Profile::Strict => TokenAcceptance::Verified,
        Profile::Emulator => TokenAcceptance::EmulatorMock,
    };
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
            LoadedRules::from_source(rules).unwrap(),
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
    }
}

fn request(
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

fn enc(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            write!(out, "%{b:02X}").unwrap();
        }
    }
    out
}

fn wrap(body: &str) -> String {
    format!(
        "rules_version = '2';\nservice firebase.storage {{\n  match /b/{{bucket}}/o {{\n{body}  }}\n}}\n"
    )
}

fn allow(path: &str, grant: &str, condition: &str) -> String {
    format!("    match /{path} {{\n      allow {grant}: if {condition};\n    }}\n")
}

/// The three released rulesets of the recorder (`plan.mjs`), in the recorder's order.
fn program_rules(program: &str) -> String {
    match program {
        "s9" => wrap(
            &(allow(&format!("{P}/mk/a"), "read", "true")
                + &allow(&format!("{P}/pub/{{f}}"), "read", "true")),
        ),
        "units" => {
            let full = format!("{P}/s1r/{FIRE_NAME}");
            let units = full.encode_utf16().count();
            let points = full.chars().count();
            let e = "é\u{1F525}";
            wrap(
                &(allow(&format!("{P}/mk/b"), "read", "true")
                    + &allow(&format!("{P}/c1/{{n}}"), "read", "n.size() == 3")
                    + &allow(&format!("{P}/c2/{{n}}"), "read", "n.size() == 4")
                    + &allow(&format!("{P}/s1a/{{n}}"), "read", "n.size() == 4")
                    + &allow(&format!("{P}/s1b/{{n}}"), "read", "n.size() == 3")
                    + &allow(
                        &format!("{P}/s1r/{{n}}"),
                        "read",
                        &format!("resource.name.size() == {units}"),
                    )
                    + &allow(
                        &format!("{P}/s1p/{{n}}"),
                        "read",
                        &format!("resource.name.size() == {points}"),
                    )
                    + &allow(&format!("{P}/s2a/{{n}}"), "read", "n[3] == 'x'")
                    + &allow(&format!("{P}/s2b/{{n}}"), "read", "n[2] == 'x'")
                    + &allow(
                        &format!("{P}/s3a/{{n}}"),
                        "read",
                        &format!("n[0:3] == '{e}'"),
                    )
                    + &allow(
                        &format!("{P}/s3b/{{n}}"),
                        "read",
                        &format!("n[0:2] == '{e}'"),
                    )
                    + &allow(
                        &format!("{P}/s4a/{{n}}"),
                        "read",
                        "resource.metadata.k.size() == 3",
                    )
                    + &allow(
                        &format!("{P}/s4b/{{n}}"),
                        "read",
                        "resource.metadata.k.size() == 2",
                    )
                    + &allow(
                        &format!("{P}/s4c/{{n}}"),
                        "read",
                        "resource.metadata.k.size() == 2",
                    )),
            )
        }
        "lists" => wrap(
            &(allow(&format!("{P}/mk/c"), "read", "true")
                + &allow(&format!("{P}/l0/{{file=**}}"), "list", "true")
                + &allow(&format!("{P}/l1/{{file=**}}"), "list", "[file] != null")
                + &allow(&format!("{P}/l2/{{file=**}}"), "list", "false")
                + &allow(
                    &format!("{P}/l3/{{file=**}}"),
                    "list",
                    &format!("request.path == /b/$(bucket)/o/{P}/l3"),
                )
                + &allow(&format!("{P}/l4/{{file}}"), "list", "true")
                + &allow(&format!("{P}/l5/{{file=**}}"), "list", "file == ''")),
        ),
        other => panic!("unknown program {other}"),
    }
}

/// The objects a program reads: name and custom metadata.
fn program_objects(program: &str) -> Vec<(String, Vec<(&'static str, &'static str)>)> {
    let plain = |names: &[String]| names.iter().map(|n| (n.clone(), Vec::new())).collect();
    match program {
        "s9" => plain(&[
            format!("{P}/mk/a"),
            format!("{P}/pub/x"),
            format!("{P}/pub//x"),
            format!("/{P}/pub/x"),
            format!("{P}/pub/x/"),
            format!("{P}/den/x"),
        ]),
        "units" => {
            let mut v: Vec<(String, Vec<(&str, &str)>)> = plain(&[
                format!("{P}/mk/b"),
                format!("{P}/c1/abc"),
                format!("{P}/c2/abc"),
                format!("{P}/s1a/{FIRE_NAME}"),
                format!("{P}/s1b/{FIRE_NAME}"),
                format!("{P}/s1r/{FIRE_NAME}"),
                format!("{P}/s1p/{FIRE_NAME}"),
                format!("{P}/s2a/{FIRE_NAME}"),
                format!("{P}/s2b/{FIRE_NAME}"),
                format!("{P}/s3a/{FIRE_NAME}"),
                format!("{P}/s3b/{FIRE_NAME}"),
            ]);
            v.push((format!("{P}/s4a/o"), vec![("k", FIRE_META)]));
            v.push((format!("{P}/s4b/o"), vec![("k", FIRE_META)]));
            v.push((format!("{P}/s4c/o"), vec![("k", "ab")]));
            v
        }
        "lists" => plain(&[
            format!("{P}/mk/c"),
            format!("{P}/l0/o1"),
            format!("{P}/l1/o1"),
            format!("{P}/l2/o1"),
            format!("{P}/l3/o1"),
            format!("{P}/l4/o1"),
            format!("{P}/l5/o1"),
        ]),
        other => panic!("unknown program {other}"),
    }
}

const OWNER: [(&str, &str); 1] = [("authorization", "Bearer owner")];

/// A state that holds the program's ruleset and objects (created with the owner credential).
fn program_state(profile: Profile, program: &str) -> StorageState {
    let s = state(profile, &program_rules(program));
    for (name, metadata) in program_objects(program) {
        let r = handle(
            &s,
            request(
                "POST",
                &format!(
                    "/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name={}",
                    enc(&name)
                ),
                &[
                    ("authorization", "Bearer owner"),
                    ("content-type", "text/plain"),
                ],
                name.as_bytes(),
            ),
        );
        assert_eq!(
            r.status,
            200,
            "create {name}: {}",
            String::from_utf8_lossy(&r.body)
        );
        if !metadata.is_empty() {
            let body = serde_json::json!({"metadata": metadata.iter().copied().collect::<BTreeMap<_, _>>()});
            let r = handle(
                &s,
                request(
                    "PATCH",
                    &format!("/storage/v1/b/{BUCKET}/o/{}", enc(&name)),
                    &[
                        ("authorization", "Bearer owner"),
                        ("content-type", "application/json"),
                    ],
                    body.to_string().as_bytes(),
                ),
            );
            assert_eq!(
                r.status,
                200,
                "patch {name}: {}",
                String::from_utf8_lossy(&r.body)
            );
        }
    }
    s
}

fn unmask(text: &str) -> String {
    text.replace("<P>", P)
}

fn content_type(r: &fireemu_adapter_http::storage::StorageResponse) -> Option<&str> {
    r.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
}

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).unwrap()
}

#[allow(clippy::too_many_lines)]
fn replay(profile: Profile) {
    let fixture = fixture();
    let mut states: BTreeMap<&str, StorageState> = BTreeMap::new();
    let mut replayed = 0;
    for row in fixture["rows"].as_array().unwrap() {
        let id = row["id"].as_str().unwrap();
        if EXCLUDED_ROWS.contains(&id) {
            continue;
        }
        let program = row["program"].as_str().unwrap();
        let s = states
            .entry(program)
            .or_insert_with(|| program_state(profile, program));
        let req = &row["request"];
        let path = match req["kind"].as_str().unwrap() {
            "v0-meta" => format!(
                "/v0/b/{BUCKET}/o/{}",
                enc(&unmask(req["name"].as_str().unwrap()))
            ),
            "v0-media" => format!(
                "/v0/b/{BUCKET}/o/{}?alt=media",
                enc(&unmask(req["name"].as_str().unwrap()))
            ),
            "v0-list" => {
                let mut q = format!("prefix={}", enc(&unmask(req["prefix"].as_str().unwrap())));
                if let Some(d) = req["delimiter"].as_str() {
                    write!(q, "&delimiter={}", enc(d)).unwrap();
                }
                format!("/v0/b/{BUCKET}/o?{q}")
            }
            other => panic!("unknown request kind {other}"),
        };
        let response = handle(s, request("GET", &path, &[], b""));
        let answer = &row["answer"];
        let label = format!("{profile:?} {id} (recording {})", row["recording"]);
        assert_eq!(
            u64::from(response.status),
            answer["status"].as_u64().unwrap(),
            "{label}: status; body {}",
            String::from_utf8_lossy(&response.body)
        );
        match row["class"].as_str().unwrap() {
            "allow" => {
                let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
                if let Some(list) = answer.get("list") {
                    let names = |v: &Value, key: &str| -> Vec<String> {
                        v[key]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .map(|x| {
                                        x.as_str()
                                            .or_else(|| x["name"].as_str())
                                            .unwrap()
                                            .to_owned()
                                    })
                                    .collect()
                            })
                            .unwrap_or_default()
                    };
                    let expected = |key: &str| -> Vec<String> {
                        list[key]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|n| unmask(n.as_str().unwrap()))
                            .collect()
                    };
                    assert_eq!(names(&body, "items"), expected("items"), "{label}: items");
                    assert_eq!(
                        names(&body, "prefixes"),
                        expected("prefixes"),
                        "{label}: prefixes"
                    );
                } else if answer.get("resource").is_some() {
                    assert_eq!(
                        body["name"].as_str().unwrap(),
                        unmask(answer["resource"]["name"].as_str().unwrap()),
                        "{label}: resource name"
                    );
                }
            }
            "deny" if profile == Profile::Strict => {
                assert_eq!(
                    content_type(&response),
                    answer["contentType"].as_str(),
                    "{label}"
                );
                assert_eq!(
                    response.body.len() as u64,
                    answer["bodyBytes"].as_u64().unwrap(),
                    "{label}: bodyBytes"
                );
            }
            "other" => {
                // The recorded 400 of the path check: the bytes are production's in both profiles.
                assert_eq!(
                    content_type(&response),
                    answer["contentType"].as_str(),
                    "{label}"
                );
                assert_eq!(
                    response.body.len() as u64,
                    answer["bodyBytes"].as_u64().unwrap(),
                    "{label}: bodyBytes"
                );
                let body: Value = serde_json::from_slice(&response.body).unwrap();
                assert_eq!(
                    body["error"]["message"], answer["error"]["message"],
                    "{label}"
                );
            }
            _ => {}
        }
        replayed += 1;
    }
    // 32 rows x 2 recordings, less the excluded row in both recordings.
    assert_eq!(replayed, 32 * 2 - 2);
}

#[test]
fn every_recorded_row_replays_in_the_strict_profile() {
    replay(Profile::Strict);
}

#[test]
fn every_recorded_row_replays_in_the_emulator_profile() {
    replay(Profile::Emulator);
}

#[test]
fn the_three_load_only_rulesets_load() {
    let fixture = fixture();
    let loads = fixture["loads"].as_array().unwrap();
    assert_eq!(loads.len(), 6);
    let sources = [
        (
            "s7-lone-surrogate",
            wrap(&allow(&format!("{P}/ls/{{f}}"), "read", "\"\\ud83d\".size() == 1")),
        ),
        (
            "s8-function-before",
            format!(
                "rules_version = '2';\nfunction ok() {{ return true; }}\nservice firebase.storage {{\n  match /b/{{bucket}}/o {{\n{}  }}\n}}\n",
                allow(&format!("{P}/fn/{{f}}"), "read", "ok()")
            ),
        ),
        (
            "s8-function-after",
            format!(
                "rules_version = '2';\nservice firebase.storage {{\n  match /b/{{bucket}}/o {{\n{}  }}\n}}\nfunction ok() {{ return true; }}\n",
                allow(&format!("{P}/fn/{{f}}"), "read", "ok()")
            ),
        ),
    ];
    for load in loads {
        assert_eq!(load["compiled"], Value::Bool(true));
        let id = load["id"].as_str().unwrap();
        let source = &sources.iter().find(|(i, _)| *i == id).unwrap().1;
        for profile in [Profile::Strict, Profile::Emulator] {
            let s = state(profile, &wrap(""));
            let r = handle(
                &s,
                request(
                    "PUT",
                    "/internal/setRules",
                    &OWNER,
                    serde_json::json!({"rules": {"files": [{"name": "storage.rules", "content": source}]}})
                        .to_string()
                        .as_bytes(),
                ),
            );
            assert_eq!(
                r.status,
                200,
                "{profile:?} {id}: {}",
                String::from_utf8_lossy(&r.body)
            );
        }
    }
}

const ALLOW_ALL: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if true; } } }";

fn put(s: &StorageState, name: &str, body: &str) {
    let r = put_status(s, name, body);
    assert_eq!(
        r.status,
        200,
        "create {name}: {}",
        String::from_utf8_lossy(&r.body)
    );
}

/// An upload whose answer the caller reads (the emulator profile drops one leading slash, so the
/// name `/` becomes an empty one).
fn put_status(
    s: &StorageState,
    name: &str,
    body: &str,
) -> fireemu_adapter_http::storage::StorageResponse {
    handle(
        s,
        request(
            "POST",
            &format!(
                "/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name={}",
                enc(name)
            ),
            &[
                ("authorization", "Bearer owner"),
                ("content-type", "text/plain"),
            ],
            body.as_bytes(),
        ),
    )
}

fn gcs_media(s: &StorageState, name: &str) -> (u16, String) {
    let r = handle(
        s,
        request(
            "GET",
            &format!("/storage/v1/b/{BUCKET}/o/{}?alt=media", enc(name)),
            &OWNER,
            b"",
        ),
    );
    (r.status, String::from_utf8_lossy(&r.body).into_owned())
}

#[test]
fn the_strict_profile_keeps_names_that_differ_by_a_leading_or_trailing_slash_apart() {
    let s = state(Profile::Strict, ALLOW_ALL);
    put(&s, "a/x", "plain");
    put(&s, "/a/x", "leading");
    put(&s, "a/x/", "trailing");
    put(&s, "a//x", "interior");
    assert_eq!(gcs_media(&s, "a/x"), (200, "plain".into()));
    assert_eq!(gcs_media(&s, "/a/x"), (200, "leading".into()));
    assert_eq!(gcs_media(&s, "a/x/"), (200, "trailing".into()));
    assert_eq!(gcs_media(&s, "a//x"), (200, "interior".into()));
}

/// The official emulator drops one leading slash of an uploaded name; the emulator profile keeps
/// that (it never refuses what the official emulator admits), so `/a/x` is the object `a/x`.
#[test]
fn the_emulator_profile_keeps_the_official_leading_slash_strip() {
    let s = state(Profile::Emulator, ALLOW_ALL);
    put(&s, "/a/x", "leading");
    assert_eq!(gcs_media(&s, "a/x"), (200, "leading".into()));
}

const PATH_MESSAGE: &str = "The path may not end with '/' or contain two consecutive '/'s";

fn v0_get(
    s: &StorageState,
    name: &str,
    media: bool,
) -> fireemu_adapter_http::storage::StorageResponse {
    handle(
        s,
        request(
            "GET",
            &format!(
                "/v0/b/{BUCKET}/o/{}{}",
                enc(name),
                if media { "?alt=media" } else { "" }
            ),
            &[],
            b"",
        ),
    )
}

fn v0_list(
    s: &StorageState,
    prefix: &str,
    delimiter: Option<&str>,
) -> fireemu_adapter_http::storage::StorageResponse {
    let delimiter = delimiter.map_or(String::new(), |d| format!("&delimiter={}", enc(d)));
    handle(
        s,
        request(
            "GET",
            &format!("/v0/b/{BUCKET}/o?prefix={}{delimiter}", enc(prefix)),
            &[],
            b"",
        ),
    )
}

fn assert_path_refusal(r: &fireemu_adapter_http::storage::StorageResponse, label: &str) {
    assert_eq!(
        r.status,
        400,
        "{label}: {}",
        String::from_utf8_lossy(&r.body)
    );
    assert_eq!(
        content_type(r),
        Some("application/json; charset=UTF-8"),
        "{label}"
    );
    assert_eq!(r.body.len(), 116, "{label}");
    let body: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(body["error"]["message"], PATH_MESSAGE, "{label}");
    assert_eq!(body["error"]["code"], 400, "{label}");
}

#[test]
fn a_name_with_an_empty_segment_is_refused_before_the_rules_in_both_profiles() {
    for profile in [Profile::Strict, Profile::Emulator] {
        let s = state(profile, ALLOW_ALL);
        for name in [
            "p/pub//x", "/p/pub/x", "p/pub/x/", "p//", "/", "//x", "a///b",
        ] {
            put_status(&s, name, "body");
            for media in [false, true] {
                assert_path_refusal(
                    &v0_get(&s, name, media),
                    &format!("{profile:?} {name} media={media}"),
                );
            }
        }
        // Near misses: single slashes inside the name, and absent objects with a good name.
        put(&s, "p/pub/x", "body");
        assert_eq!(v0_get(&s, "p/pub/x", false).status, 200);
        assert_eq!(v0_get(&s, "p/pub/x", true).status, 200);
        assert_eq!(v0_get(&s, "p/pub/absent", false).status, 404);
        // A name production reads as absent keeps its 404 over this check.
        assert_eq!(v0_get(&s, "p//\n", false).status, 404);
    }
}

#[test]
fn a_prefix_with_a_leading_slash_or_consecutive_slashes_is_refused_in_both_profiles() {
    for profile in [Profile::Strict, Profile::Emulator] {
        let s = state(profile, ALLOW_ALL);
        put(&s, "p/pub/x", "body");
        for prefix in ["/p/pub/", "p//pub/", "/p/", "//", "p/pub//x/"] {
            for delimiter in [None, Some("/")] {
                assert_path_refusal(
                    &v0_list(&s, prefix, delimiter),
                    &format!("{profile:?} {prefix} {delimiter:?}"),
                );
            }
        }
        // Near misses: the single trailing slash every prefix ends with, the empty prefix and
        // the root slash are not this refusal.
        for prefix in ["p/pub/", "p/", ""] {
            assert_eq!(
                v0_list(&s, prefix, None).status,
                200,
                "{profile:?} {prefix:?}"
            );
        }
        assert_ne!(v0_list(&s, "/", None).body.len(), 116);
    }
}

#[test]
fn the_emulator_profile_accepts_the_one_level_proof_for_a_delimited_listing() {
    let rules = |condition: &str| wrap(&allow("p/pub/{f}", "list", condition));
    let list_status = |profile: Profile, condition: &str, prefix: &str, delimiter: Option<&str>| {
        let s = state(profile, &rules(condition));
        put(&s, "p/pub/x", "body");
        v0_list(&s, prefix, delimiter).status
    };
    for profile in [Profile::Strict, Profile::Emulator] {
        // The recorded shape: every entry one level below the prefix is granted.
        assert_eq!(
            list_status(profile, "true", "p/pub/", Some("/")),
            200,
            "{profile:?}"
        );
        // Near misses, all refused as before: no delimiter, another delimiter, a rule that
        // refuses, a rule that depends on the entry, another prefix.
        assert_eq!(
            list_status(profile, "true", "p/pub/", None),
            403,
            "{profile:?} no delimiter"
        );
        assert_eq!(
            list_status(profile, "true", "p/pub/", Some("x")),
            403,
            "{profile:?} delimiter x"
        );
        assert_eq!(
            list_status(profile, "false", "p/pub/", Some("/")),
            403,
            "{profile:?} false"
        );
        assert_eq!(
            list_status(profile, "f == 'x'", "p/pub/", Some("/")),
            403,
            "{profile:?} entry"
        );
        assert_eq!(
            list_status(profile, "true", "p/", Some("/")),
            403,
            "{profile:?} parent prefix"
        );
        assert_eq!(
            list_status(profile, "true", "p/other/", Some("/")),
            403,
            "{profile:?} other prefix"
        );
    }
}

/// The same one-level proof with a denial log installed (the evaluation takes the traced path): the
/// listing is granted and nothing is logged; a refusal still logs exactly once.
#[test]
fn the_one_level_proof_is_accepted_on_the_traced_path_without_a_denial() {
    use fireemu_adapter_http::storage::StorageDenialLog;
    for (condition, delimiter, status, denials) in [
        ("true", Some("/"), 200, 0),
        ("true", None, 403, 1),
        ("false", Some("/"), 403, 1),
    ] {
        let s = state(
            Profile::Emulator,
            &wrap(&allow("p/pub/{f}", "list", condition)),
        );
        put(&s, "p/pub/x", "body");
        let seen: Arc<Mutex<usize>> = Arc::default();
        let sink = seen.clone();
        s.rules.set_denial_log(StorageDenialLog(Arc::new(move |_| {
            *sink.lock().unwrap() += 1;
        })));
        assert_eq!(
            v0_list(&s, "p/pub/", delimiter).status,
            status,
            "{condition} {delimiter:?}"
        );
        assert_eq!(*seen.lock().unwrap(), denials, "{condition} {delimiter:?}");
    }
}

#[test]
fn strict_admits_the_recorded_list_shapes_only() {
    let s = |rules: &str| {
        let s = state(Profile::Strict, &wrap(rules));
        for n in ["p/a/o1", "p/b/o1", "p/c/o1", "p/d/o1", "p/e/o1"] {
            put(&s, n, "body");
        }
        s
    };
    // l1 and l3 of the recording.
    let admitted = s(&(allow("p/a/{file=**}", "list", "[file] != null")
        + &allow(
            "p/b/{file=**}",
            "list",
            "request.path == /b/$(bucket)/o/p/b",
        )
        + &allow(
            "p/c/{file=**}",
            "list",
            "request.path == /b/$(bucket)/o/p/other",
        )
        + &allow("p/d/{file=**}", "list", "file != null")
        + &allow("p/e/{file}", "list", "[file] != null")));
    let status =
        |prefix: &str, delimiter: Option<&str>| v0_list(&admitted, prefix, delimiter).status;
    assert_eq!(status("p/a/", None), 200);
    assert_eq!(status("p/b/", None), 200);
    // The path of another prefix, a bare capture and a single-segment capture stay refused.
    assert_eq!(status("p/c/", None), 403);
    assert_eq!(status("p/d/", None), 403);
    assert_eq!(status("p/e/", None), 403);
    // `request.path` of a delimited listing and of another delimiter was not recorded.
    assert_eq!(status("p/b/", Some("/")), 403);
    assert_eq!(status("p/b/", Some("x")), 403);
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The v0 read answers the path refusal exactly for a name with an empty segment.
        #[test]
        fn the_path_refusal_is_exactly_an_empty_segment(name in "[ab/]{1,7}") {
            let empty_segment = name.split('/').any(str::is_empty);
            for profile in [Profile::Strict, Profile::Emulator] {
                let s = state(profile, ALLOW_ALL);
                put_status(&s, &name, "body");
                let r = v0_get(&s, &name, false);
                if empty_segment {
                    assert_path_refusal(&r, &format!("{profile:?} {name}"));
                } else {
                    prop_assert_eq!(r.status, 200, "{:?} {}", profile, name);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Writes through the Firebase v0 API. UNRECORDED (inferred, coordinator ruling 2026-11-09):
// production answered the path refusal on every v0 route that was read, before the rules, so the
// same validator is applied to every v0 route that takes an object name.
// ---------------------------------------------------------------------------------------------

fn multipart_body(meta: &Value, data: &[u8]) -> (String, Vec<u8>) {
    let boundary = "fireemu-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{meta}\r\n--{boundary}\r\nContent-Type: text/plain\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());
    (format!("multipart/related; boundary={boundary}"), body)
}

/// Every v0 route that takes an object name: (label, request builder for `name`).
type RouteBuilder = fn(&str, &[(&str, &str)]) -> StorageRequest;

#[allow(clippy::too_many_lines)]
fn v0_write_routes() -> Vec<(&'static str, RouteBuilder)> {
    fn with(auth: &[(&str, &str)], extra: &[(&str, &str)]) -> Vec<(String, String)> {
        auth.iter()
            .chain(extra.iter())
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }
    fn build(
        method: &str,
        path: &str,
        auth: &[(&str, &str)],
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> StorageRequest {
        let headers = with(auth, extra);
        let refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        request(method, path, &refs, body)
    }
    vec![
        ("post-path-media", |n, a| {
            build(
                "POST",
                &format!("/v0/b/{BUCKET}/o/{}", enc(n)),
                a,
                &[("content-type", "text/plain")],
                b"x",
            )
        }),
        ("put-path-media", |n, a| {
            build(
                "PUT",
                &format!("/v0/b/{BUCKET}/o/{}", enc(n)),
                a,
                &[("content-type", "text/plain")],
                b"x",
            )
        }),
        ("post-query-media", |n, a| {
            build(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name={}&uploadType=media", enc(n)),
                a,
                &[("content-type", "text/plain")],
                b"x",
            )
        }),
        ("put-query-media", |n, a| {
            build(
                "PUT",
                &format!("/v0/b/{BUCKET}/o?name={}&uploadType=media", enc(n)),
                a,
                &[("content-type", "text/plain")],
                b"x",
            )
        }),
        ("post-query-multipart", |n, a| {
            let (ct, body) = multipart_body(&serde_json::json!({"name": n}), b"x");
            build(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name={}&uploadType=multipart", enc(n)),
                a,
                &[
                    ("content-type", &ct),
                    ("x-goog-upload-protocol", "multipart"),
                ],
                &body,
            )
        }),
        ("post-path-multipart", |n, a| {
            let (ct, body) = multipart_body(&serde_json::json!({}), b"x");
            build(
                "POST",
                &format!("/v0/b/{BUCKET}/o/{}", enc(n)),
                a,
                &[
                    ("content-type", &ct),
                    ("x-goog-upload-protocol", "multipart"),
                ],
                &body,
            )
        }),
        ("post-query-resumable-start", |n, a| {
            build(
                "POST",
                &format!("/v0/b/{BUCKET}/o?name={}", enc(n)),
                a,
                &[
                    ("x-goog-upload-protocol", "resumable"),
                    ("x-goog-upload-command", "start"),
                    ("content-type", "application/json"),
                ],
                b"{}",
            )
        }),
        ("post-path-resumable-start", |n, a| {
            build(
                "POST",
                &format!("/v0/b/{BUCKET}/o/{}", enc(n)),
                a,
                &[
                    ("x-goog-upload-protocol", "resumable"),
                    ("x-goog-upload-command", "start"),
                    ("content-type", "application/json"),
                ],
                b"{}",
            )
        }),
        ("post-path-create-token", |n, a| {
            build(
                "POST",
                &format!("/v0/b/{BUCKET}/o/{}?create_token=true", enc(n)),
                a,
                &[],
                b"",
            )
        }),
        ("post-path-delete-token", |n, a| {
            build(
                "POST",
                &format!("/v0/b/{BUCKET}/o/{}?delete_token=t", enc(n)),
                a,
                &[],
                b"",
            )
        }),
        ("patch", |n, a| {
            build(
                "PATCH",
                &format!("/v0/b/{BUCKET}/o/{}", enc(n)),
                a,
                &[("content-type", "application/json")],
                br#"{"contentType":"text/x-new"}"#,
            )
        }),
        ("put-method-override-patch", |n, a| {
            build(
                "PUT",
                &format!("/v0/b/{BUCKET}/o/{}", enc(n)),
                a,
                &[
                    ("content-type", "application/json"),
                    ("x-http-method-override", "PATCH"),
                ],
                br#"{"contentType":"text/x-new"}"#,
            )
        }),
        ("delete", |n, a| {
            build(
                "DELETE",
                &format!("/v0/b/{BUCKET}/o/{}", enc(n)),
                a,
                &[],
                b"",
            )
        }),
    ]
}

const EMPTY_SEGMENT_NAMES: [&str; 3] = ["p/pub//x", "/p/pub/x", "p/pub/x/"];

#[test]
fn every_v0_route_that_takes_an_object_name_refuses_an_empty_segment_before_the_rules() {
    for profile in [Profile::Strict, Profile::Emulator] {
        for (route, build) in v0_write_routes() {
            for name in EMPTY_SEGMENT_NAMES {
                for credentials in [&OWNER[..], &[][..]] {
                    let s = state(profile, ALLOW_ALL);
                    // The object exists under the odd name (the JSON API creates it), so a delete
                    // or a patch would find something to change.
                    let existed = put_status(&s, name, "original").status == 200;
                    let r = handle(&s, build(name, credentials));
                    let label = format!(
                        "{profile:?} {route} {name} owner={}",
                        !credentials.is_empty()
                    );
                    assert_path_refusal(&r, &label);
                    // The emulator profile stores `/x` as `x` (the official leading-slash strip).
                    let stored = if profile == Profile::Emulator {
                        name.strip_prefix('/').unwrap_or(name)
                    } else {
                        name
                    };
                    if existed {
                        assert_eq!(
                            gcs_media(&s, stored),
                            (200, "original".into()),
                            "{label}: untouched"
                        );
                    } else {
                        assert_eq!(gcs_media(&s, stored).0, 404, "{label}: nothing created");
                    }
                }
            }
        }
    }
}

/// Near misses of the same routes: a name with single slashes only is not this refusal. The
/// answer is whatever the route answered before (an upload commits, a patch or a delete of an
/// absent object is not a path refusal).
#[test]
fn the_v0_write_routes_still_serve_a_well_formed_name() {
    for profile in [Profile::Strict, Profile::Emulator] {
        for (route, build) in v0_write_routes() {
            let s = state(profile, ALLOW_ALL);
            put(&s, "p/pub/x", "original");
            let r = handle(&s, build("p/pub/x", &OWNER));
            let label = format!("{profile:?} {route}");
            let refusal = r.status == 400
                && serde_json::from_slice::<Value>(&r.body)
                    .is_ok_and(|b| b["error"]["message"] == PATH_MESSAGE);
            assert!(!refusal, "{label}: {}", String::from_utf8_lossy(&r.body));
        }
    }
}
