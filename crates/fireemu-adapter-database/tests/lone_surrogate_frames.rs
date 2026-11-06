//! A lone surrogate escape in a WebSocket frame, as the official emulator (4.11.2) answers it
//! (`docs.local/runs/rtdb-lone-surrogate/probe-ws.mjs`, jar-ws.json; owner row "RTDB closure lone surrogates in claims
//! and query values", 2026-11-06). On the emulator profile a value stores `?` (a valid pair stays), a path that holds
//! one is `Invalid token in path`, a data key that holds one is refused as any invalid key is (the connection error;
//! for a merge entry `Invalid token in path`, as for any invalid key), a listen's bound reads `?`, and the claims of an `auth`
//! credential and the `authvar` of a `gauth` frame are not read with one (owner ledger line 2291). The strict profile refuses every such frame as before (production has not answered
//! them).

use fireemu_adapter_database::realtime::{Opened, Session};
use fireemu_adapter_database::rest::{Credentials, Database, Handled, HttpRequest, RestOptions};

const NOW: i64 = 1_792_464_733_000;

fn database(strict: bool) -> Database {
    Database::new(
        RestOptions {
            production_shapes: strict,
            credentials: Credentials {
                strict,
                ..Credentials::default()
            },
            ..RestOptions::default()
        },
        1,
    )
}

fn rest(db: &mut Database, method: &str, target: &str, body: &str) -> (u16, String) {
    let request = HttpRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        headers: vec![("Authorization".to_owned(), "Bearer owner".to_owned())],
        body: body.as_bytes().to_vec(),
    };
    match db.handle(&request, NOW) {
        Handled::Response { response, .. } => (
            response.status,
            String::from_utf8_lossy(&response.body).into_owned(),
        ),
        Handled::Stream { .. } => panic!("unexpected stream"),
    }
}

/// The replies to `frames` sent in order over a new session.
fn replies(db: &mut Database, frames: &[&str]) -> Vec<String> {
    let Ok(Opened::Session(mut session, _)) =
        db.open_realtime("/.ws?v=5&ns=c", Some("127.0.0.1:9000"), NOW)
    else {
        panic!("no session");
    };
    let send = |session: &mut Session, db: &mut Database, frame: &str| {
        session.receive(db, frame, NOW).replies
    };
    let out = frames
        .iter()
        .flat_map(|frame| send(&mut session, db, frame))
        .collect();
    db.close_realtime(session.client(), NOW);
    out
}

fn put(path_and_data: &str) -> String {
    format!(r#"{{"t":"d","d":{{"r":1,"a":"p","b":{path_and_data}}}}}"#)
}

#[test]
fn a_lone_surrogate_in_a_frame_is_read_as_the_official_emulator_reads_it() {
    // (frame, emulator reply fragment, read back /t, strict reply fragment)
    let ok = r#""s":"ok""#;
    let invalid = r#""s":"invalid_parameters","d":"Invalid token in path""#;
    let connection_error = r#""t":"c","d":{"t":"e""#;
    let cases: Vec<(String, &str, &str)> = vec![
        (put(r#"{"p":"/t","d":"x\ud83d"}"#), ok, r#""x?""#),
        (put(r#"{"p":"/t","d":"x😀"}"#), ok, "\"x\u{1F600}\""),
        (
            put(r#"{"p":"/t","d":{"a":"y\ude00"}}"#),
            ok,
            r#"{"a":"y?"}"#,
        ),
        (
            put(r#"{"p":"/t","d":{"a\ud83d":1}}"#),
            connection_error,
            "null",
        ),
        (put(r#"{"p":"/t/a\ud83d","d":1}"#), invalid, "null"),
        (
            r#"{"t":"d","d":{"r":1,"a":"m","b":{"p":"/t","d":{"a":"z\ud83d"}}}}"#.to_owned(),
            ok,
            r#"{"a":"z?"}"#,
        ),
        (
            r#"{"t":"d","d":{"r":1,"a":"m","b":{"p":"/t","d":{"b\ud83d":1}}}}"#.to_owned(),
            invalid,
            "null",
        ),
        (
            put(r#"{"p":"/t","d":{".value":1,".priority":"p\ud83d"}}"#),
            ok,
            "1",
        ),
    ];
    for strict in [false, true] {
        for (frame, emulator, readback) in &cases {
            let mut db = database(strict);
            let got = replies(&mut db, &[frame]).join("\n");
            let stored = rest(&mut db, "GET", "/t.json?ns=c", "").1;
            let valid_pair = frame.contains(r"😀");
            if !strict || valid_pair {
                assert!(got.contains(emulator), "emulator {frame}: {got}");
                assert_eq!(&stored, readback, "emulator {frame}");
            } else if frame.contains("a\\ud83d\",\"d\":1") || frame.contains("b\\ud83d") {
                // A path or merge key: the frame is not read, as before.
                assert!(got.contains(connection_error), "strict {frame}: {got}");
                assert_eq!(stored, "null", "strict {frame}");
            } else {
                assert!(got.contains(connection_error), "strict {frame}: {got}");
                assert_eq!(stored, "null", "strict {frame}");
            }
        }
    }
}

#[test]
fn a_listen_bound_with_a_lone_surrogate_reads_as_a_question_mark() {
    for strict in [false, true] {
        let mut db = database(strict);
        rest(&mut db, "PUT", "/t.json?ns=c", r#"{"a":1,"b":2}"#);
        // The key index starts at `?` (U+003F), before `a`: both children come; equalTo `?` matches none.
        let start = replies(
            &mut db,
            &[r#"{"t":"d","d":{"r":1,"a":"q","b":{"p":"/t","q":{"sp":"\ud83d","i":".key"},"t":1,"h":""}}}"#],
        )
        .join("\n");
        let equal = replies(
            &mut db,
            &[r#"{"t":"d","d":{"r":1,"a":"q","b":{"p":"/t","q":{"sp":"\ud83d","ep":"\ud83d","i":".key"},"t":1,"h":""}}}"#],
        )
        .join("\n");
        if strict {
            assert!(start.contains(r#""t":"c","d":{"t":"e""#), "{start}");
            assert!(equal.contains(r#""t":"c","d":{"t":"e""#), "{equal}");
        } else {
            assert!(start.contains(r#""d":{"a":1,"b":2}"#), "{start}");
            assert!(start.contains(r#""s":"ok""#), "{start}");
            assert!(
                !equal.contains(r#""a":1"#) && equal.contains(r#""s":"ok""#),
                "{equal}"
            );
        }
    }
}

/// The claims of an `auth` credential are not read when they hold a lone surrogate, on either profile (owner ledger
/// line 2291: the claims and the `authvar` return to the behaviour before 2286, a declared difference; the official
/// emulator keeps the surrogate in the claims): the credential is not a token, and a rule that needs the claim denies.
#[test]
fn a_credential_whose_claims_hold_a_lone_surrogate_is_not_a_token() {
    let b64 = |text: &str| {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in text.as_bytes().chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
            for i in 0..=chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            }
        }
        out
    };
    let token = format!(
        "{}.{}.",
        b64(r#"{"alg":"none","typ":"JWT"}"#),
        b64(r#"{"sub":"u1","uid":"u1","iat":1,"exp":9999999999,"x":"\ud83d"}"#)
    );
    let auth = format!(r#"{{"t":"d","d":{{"r":1,"a":"auth","b":{{"cred":"{token}"}}}}}}"#);
    let listen = r#"{"t":"d","d":{"r":2,"a":"q","b":{"p":"/t","h":""}}}"#;
    for strict in [false, true] {
        let mut db = database(strict);
        rest(&mut db, "PUT", "/t.json?ns=c", r#"{"a":1}"#);
        rest(
            &mut db,
            "PUT",
            "/.settings/rules.json?ns=c",
            r#"{"rules":{"t":{".read":"auth.token.x == '\\uD83D'"}}}"#,
        );
        let got = replies(&mut db, &[&auth, listen]).join("\n");
        assert!(
            got.contains("Could not parse auth token"),
            "strict={strict}: {got}"
        );
        assert!(got.contains("permission_denied"), "strict={strict}: {got}");
    }
}

/// A merge entry whose key is not a valid path is `invalid_parameters` for the official emulator (a lone surrogate
/// included); the strict profile keeps the connection error and accepts the empty key as before. Jar rows:
/// jar-ws3.json (probe-ws.mjs).
#[test]
fn a_merge_entry_with_an_invalid_key_is_answered_as_the_official_emulator_answers_it() {
    let long = "k".repeat(800);
    let deep = vec!["a"; 40].join("/");
    let token = "Invalid token in path";
    let rows: Vec<(String, String)> = vec![
        ("b.c".to_owned(), token.to_owned()),
        ("b$c".to_owned(), token.to_owned()),
        ("b#c".to_owned(), token.to_owned()),
        ("b[c".to_owned(), token.to_owned()),
        ("a/b.c".to_owned(), token.to_owned()),
        ("a/.priority/b".to_owned(), token.to_owned()),
        ("b\\ud83d".to_owned(), token.to_owned()),
        (String::new(), "Empty strings are not valid keys".to_owned()),
        (
            long,
            "Path specified exceeds the maximum length that can be written (768 bytes).".to_owned(),
        ),
        (
            deep,
            "Path specified exceeds the maximum depth that can be written (32).".to_owned(),
        ),
    ];
    for (key, message) in rows {
        let frame =
            format!(r#"{{"t":"d","d":{{"r":1,"a":"m","b":{{"p":"/t","d":{{"{key}":1}}}}}}}}"#);
        let mut emulator = database(false);
        let got = replies(&mut emulator, &[&frame]).join("\n");
        assert!(
            got.contains(&format!(r#""s":"invalid_parameters","d":"{message}""#)),
            "emulator {key:?}: {got}"
        );
        assert_eq!(rest(&mut emulator, "GET", "/t.json?ns=c", "").1, "null");
        let mut strict = database(true);
        let got = replies(&mut strict, &[&frame]).join("\n");
        if key.is_empty() {
            assert!(got.contains(r#""s":"ok""#), "strict {key:?}: {got}");
        } else {
            assert!(
                got.contains(r#""t":"c","d":{"t":"e""#),
                "strict {key:?}: {got}"
            );
        }
    }
    // The depth boundary of the official emulator, recorded (jar-ws5.json: a merge below `/t` with 30, 31, 32 and 33
    // segments): 31 segments make 32 levels, which is the limit, and 32 are refused.
    let depth: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "fixtures/ws-merge-depth-official-emulator-4.11.2.json"
    ))
    .unwrap();
    assert_eq!(depth.len(), 4);
    for row in &depth {
        let segments = usize::try_from(row["segments"].as_u64().unwrap()).unwrap();
        let key = vec!["a"; segments].join("/");
        let frame =
            format!(r#"{{"t":"d","d":{{"r":1,"a":"m","b":{{"p":"/t","d":{{"{key}":1}}}}}}}}"#);
        let mut emulator = database(false);
        let got = replies(&mut emulator, &[&frame]).join("");
        let status = row["status"].as_str().unwrap();
        assert!(
            got.contains(&format!(r#""s":"{status}""#)),
            "{segments}: {got}"
        );
        if let Some(message) = row["message"].as_str() {
            assert!(got.contains(message), "{segments}: {got}");
        }
    }
    // A valid key and a `//` key are unchanged.
    for key in ["a/b", "a//b"] {
        let frame =
            format!(r#"{{"t":"d","d":{{"r":1,"a":"m","b":{{"p":"/t","d":{{"{key}":1}}}}}}}}"#);
        let mut emulator = database(false);
        assert!(replies(&mut emulator, &[&frame])
            .join("")
            .contains(r#""s":"ok""#));
        assert_eq!(
            rest(&mut emulator, "GET", "/t.json?ns=c", "").1,
            r#"{"a":{"b":1}}"#
        );
    }
}

/// The `authvar` of a `gauth` frame is read as before 2286 (owner ledger line 2291, a declared difference: the
/// official emulator keeps a lone surrogate in it and echoes the object): the answer is null, and a frame whose
/// `authvar` holds a lone surrogate, in a value or a name, is refused as a whole, on either profile. The member is
/// found in the parsed frame, so spelling `authvar` or its enclosing `b` with an escape changes nothing.
#[test]
fn the_authvar_of_a_gauth_frame_is_read_as_before_and_refuses_a_lone_surrogate() {
    let rules = r#"{"rules":{"t":{".read":"auth.x == 'a'"}}}"#;
    let listen = r#"{"t":"d","d":{"r":2,"a":"q","b":{"p":"/t","h":""}}}"#;
    let run = |strict: bool, frame: &str| {
        let mut db = database(strict);
        rest(&mut db, "PUT", "/t.json?ns=c", r#"{"a":1}"#);
        rest(&mut db, "PUT", "/.settings/rules.json?ns=c", rules);
        replies(&mut db, &[frame, listen]).join("\n")
    };
    for strict in [false, true] {
        let plain = r#"{"t":"d","d":{"r":1,"a":"gauth","b":{"cred":"owner","authvar":{"uid":"u1","x":"a"}}}}"#;
        let got = run(strict, plain);
        assert!(got.contains(r#""auth":null"#), "strict={strict}: {got}");
        assert!(
            got.contains(r#""r":2,"b":{"s":"ok""#),
            "strict={strict}: {got}"
        );
        for (b, member) in [("b", "authvar"), (r"\u0062", r"auth\u0076ar")] {
            for lone in [
                r#"{"uid":"u1","x":"\ud83d"}"#,
                r#"{"uid":"u1","\ud83d":1}"#,
                r#"{"uid":"u1","o":{"p":["\ude00"]}}"#,
            ] {
                let frame = format!(
                    r#"{{"t":"d","d":{{"r":1,"a":"gauth","{b}":{{"cred":"owner","{member}":{lone}}}}}}}"#
                );
                let got = run(strict, &frame);
                assert!(
                    got.contains(r#""t":"c","d":{"t":"e""#),
                    "strict={strict} {frame}: {got}"
                );
            }
        }
        // A lone surrogate outside the authvar is a value read as `?` on the emulator profile, and refused on strict.
        let outside = r#"{"t":"d","d":{"r":1,"a":"gauth","b":{"cred":"owner","authvar":{"uid":"u1","x":"a"},"note":"\ud83d"}}}"#;
        let got = run(strict, outside);
        assert_eq!(
            got.contains(r#""t":"c","d":{"t":"e""#),
            strict,
            "strict={strict}: {got}"
        );
    }
}

/// A frame whose path holds a lone surrogate writes nothing, whatever else the frame holds: the path is made invalid
/// while the frame is read (not by a second reading that can fail), so an unrelated member that the reader refuses
/// cannot leave `/bad?` as the path (coordinator review of 985528f1c).
#[test]
fn a_frame_with_a_lone_surrogate_in_its_path_writes_nothing() {
    let frames = [
        r#"{"t":"d","d":{"r":1,"a":"p","b":{"p":"/bad\ud83d","d":1,"unused":{"\ud83d":0}}}}"#,
        r#"{"t":"d","d":{"r":1,"a":"p","b":{"p":"/bad\ud83d","d":1}}}"#,
        r#"{"t":"d","d":{"r":1,"a":"m","b":{"p":"/bad\ude00","d":{"k":1},"unused":{"\ud83d":0}}}}"#,
        r#"{"t":"d","d":{"r":1,"a":"q","b":{"p":"/bad\ud83d","h":"","unused":{"\ud83d":0}}}}"#,
    ];
    for frame in frames {
        let mut db = database(false);
        let got = replies(&mut db, &[frame]).join("\n");
        assert!(
            got.contains(r#""s":"invalid_parameters","d":"Invalid token in path""#),
            "{frame}: {got}"
        );
        assert_eq!(rest(&mut db, "GET", "/.json?ns=c", "").1, "null", "{frame}");
        // The strict profile refuses the frame as before.
        let mut strict = database(true);
        let got = replies(&mut strict, &[frame]).join("\n");
        assert!(
            got.contains(r#""t":"c","d":{"t":"e""#),
            "strict {frame}: {got}"
        );
        assert_eq!(rest(&mut strict, "GET", "/.json?ns=c", "").1, "null");
    }
}

/// A lone surrogate in a path or a key is never `.priority` (nor any other valid path): the frames of Astra's review
/// of 2258af58e write nothing, register nothing and cancel nothing on the emulator profile, over put, merge and the
/// three on-disconnect routes (`o`, `om`, `oc`). The disconnect writes run when the session closes, so a registration
/// that wrongly succeeded would show in `/t` afterwards.
#[test]
fn a_lone_surrogate_in_a_path_never_becomes_a_priority_path() {
    let invalid = r#""s":"invalid_parameters","d":"Invalid token in path""#;
    let frames = [
        r#"{"t":"d","d":{"r":1,"a":"p","b":{"p":"/t/\ud83dpriority","d":7}}}"#,
        r#"{"t":"d","d":{"r":1,"a":"m","b":{"p":"/t","d":{"\ud83dpriority":7}}}}"#,
        r#"{"t":"d","d":{"r":1,"a":"o","b":{"p":"/t/\ud83dpriority","d":7}}}"#,
        r#"{"t":"d","d":{"r":1,"a":"om","b":{"p":"/t","d":{"\ud83dpriority":7}}}}"#,
        r#"{"t":"d","d":{"r":1,"a":"om","b":{"p":"/t/\ude00priority","d":{"k":7}}}}"#,
    ];
    for frame in frames {
        let mut db = database(false);
        rest(&mut db, "PUT", "/t.json?ns=c", "1");
        let got = replies(&mut db, &[frame]).join("\n");
        // The disconnect merge refuses a bad key with the connection error, as it did (the official emulator's answer
        // to it is not recorded); every other route answers the invalid token.
        let refused = if frame.contains(r#""a":"om""#) {
            got.contains(invalid) || got.contains(r#""t":"c","d":{"t":"e""#)
        } else {
            got.contains(invalid)
        };
        assert!(refused, "{frame}: {got}");
        // Nothing was written, and no disconnect write ran when the session closed.
        assert_eq!(
            rest(&mut db, "GET", "/t.json?ns=c&format=export", "").1,
            "1",
            "{frame}"
        );
    }
    // `oc` cancels registrations by path: a path with a lone surrogate cancels nothing, and the valid registration
    // made for `/t/.priority` stays and runs.
    let mut db = database(false);
    rest(&mut db, "PUT", "/t.json?ns=c", "1");
    let got = replies(
        &mut db,
        &[
            r#"{"t":"d","d":{"r":1,"a":"o","b":{"p":"/t/.priority","d":7}}}"#,
            r#"{"t":"d","d":{"r":2,"a":"oc","b":{"p":"/t/\ud83dpriority"}}}"#,
        ],
    )
    .join("\n");
    assert!(got.contains(invalid), "{got}");
    assert_eq!(
        rest(&mut db, "GET", "/t.json?ns=c&format=export", "").1,
        r#"{".value":1,".priority":7.0}"#,
        "the registration for /t/.priority was not cancelled and ran on close"
    );
}
