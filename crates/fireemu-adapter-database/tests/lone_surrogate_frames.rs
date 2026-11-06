//! A lone surrogate escape in a WebSocket frame, as the official emulator (4.11.2) answers it
//! (`docs.local/runs/rtdb-lone-surrogate/probe-ws.mjs`, jar-ws.json; owner row "RTDB closure lone surrogates in claims
//! and query values", 2026-11-06). On the emulator profile a value stores `?` (a valid pair stays), a path that holds
//! one is `Invalid token in path`, a data key that holds one is refused as any invalid key is (the connection error;
//! for a merge entry `Invalid token in path`, as for any invalid key), a listen's bound reads `?`, and the claims of an `auth`
//! credential keep the surrogate. The strict profile refuses every such frame as before (production has not answered
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

#[test]
fn the_claims_of_an_auth_credential_keep_a_lone_surrogate() {
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
        if strict {
            assert!(got.contains("Could not parse auth token"), "{got}");
            assert!(got.contains("permission_denied"), "{got}");
        } else {
            // The credential's answer shows the claim as the escape, in `token` and as a member of `auth`.
            assert_eq!(got.matches(r#""x":"\uD83D""#).count(), 2, "{got}");
            assert!(
                got.contains(r#""s":"ok""#) && !got.contains("permission_denied"),
                "{got}"
            );
        }
    }
}

/// Only the answer to an `auth` frame shows the claims encoding as escapes: a reply to any other frame keeps a
/// real character that the encoding reserves, whatever the profile.
#[test]
fn a_reply_other_than_the_credential_answer_keeps_a_reserved_character() {
    let stored = "a\u{10F03D}b\u{10FFFF}c";
    for strict in [false, true] {
        let mut db = database(strict);
        rest(&mut db, "PUT", "/t.json?ns=c", &format!("\"{stored}\""));
        let got = replies(
            &mut db,
            &[r#"{"t":"d","d":{"r":1,"a":"g","b":{"p":"/t"}}}"#],
        )
        .join("\n");
        assert!(got.contains(stored), "strict={strict}: {got}");
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
    // The depth counts the path below `/t`: 31 segments make 32 levels, which is the limit.
    for (segments, accepted) in [(31, true), (32, false)] {
        let key = vec!["a"; segments].join("/");
        let frame =
            format!(r#"{{"t":"d","d":{{"r":1,"a":"m","b":{{"p":"/t","d":{{"{key}":1}}}}}}}}"#);
        let mut emulator = database(false);
        let got = replies(&mut emulator, &[&frame]).join("");
        assert_eq!(got.contains(r#""s":"ok""#), accepted, "{segments}: {got}");
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

/// The `authvar` of a `gauth` frame: the emulator profile keeps a lone surrogate in it, as the official emulator does,
/// and answers with the object (the strict profile answers null, and refuses a lone surrogate as before). Jar rows:
/// jar-ws3.json and jar-ws4.json.
#[test]
fn the_authvar_of_a_gauth_frame_keeps_a_lone_surrogate_on_the_emulator_profile() {
    let rules = r#"{"rules":{"t":{".read":"auth.x == '\\uD83D'"}}}"#;
    let gauth = |authvar: &str| {
        format!(
            r#"{{"t":"d","d":{{"r":1,"a":"gauth","b":{{"cred":"owner","authvar":{authvar}}}}}}}"#
        )
    };
    let listen = r#"{"t":"d","d":{"r":2,"a":"q","b":{"p":"/t","h":""}}}"#;
    let run = |strict: bool, authvar: &str| {
        let mut db = database(strict);
        rest(&mut db, "PUT", "/t.json?ns=c", r#"{"a":1}"#);
        rest(&mut db, "PUT", "/.settings/rules.json?ns=c", rules);
        replies(&mut db, &[&gauth(authvar), listen]).join("\n")
    };
    // The object is echoed (its members in the order of the map), and the rule sees the surrogate.
    let lone = run(false, r#"{"uid":"u1","x":"\ud83d"}"#);
    assert!(
        lone.contains(r#""x":"\uD83D""#) && lone.contains(r#""uid":"u1""#),
        "{lone}"
    );
    assert!(lone.contains(r#""r":2,"b":{"s":"ok""#), "{lone}");
    let pair = run(false, r#"{"uid":"u1","x":"😀"}"#);
    assert!(pair.contains(r#""x":"😀""#), "{pair}");
    assert!(pair.contains("permission_denied"), "{pair}");
    let key = run(false, r#"{"uid":"u1","\ud83d":1}"#);
    assert!(key.contains(r#""\uD83D":1"#), "{key}");
    let plain = run(false, r#"{"uid":"u1","n":1,"o":{"p":[1,"a"]}}"#);
    assert!(
        plain.contains(r#""auth":{"n":1,"o":{"p":[1,"a"]},"uid":"u1"}"#),
        "{plain}"
    );
    // A reserved character stays itself.
    let reserved = run(false, "{\"uid\":\"u1\",\"x\":\"\u{10F03D}\"}");
    assert!(reserved.contains("\u{10F03D}"), "{reserved}");
    // Strict: a null echo; the surrogate is refused as before.
    let strict_plain = run(true, r#"{"uid":"u1","n":1}"#);
    assert!(strict_plain.contains(r#""auth":null"#), "{strict_plain}");
    let strict_lone = run(true, r#"{"uid":"u1","x":"\ud83d"}"#);
    assert!(
        strict_lone.contains(r#""t":"c","d":{"t":"e""#),
        "{strict_lone}"
    );
}

/// The `authvar` member is found in the parsed frame, so spelling it with an escape (`"authvar"`) changes
/// nothing; and valid strings that look like any internal encoding stay themselves: U+10FFFF followed by `a` is
/// not `a`, and shows as the character in the answer (coordinator review of 985528f1c).
#[test]
fn an_authvar_spelled_with_an_escape_is_the_authvar_and_valid_strings_stay_distinct() {
    let rules = r#"{"rules":{"t":{".read":"auth.x == auth.y"}}}"#;
    let listen = r#"{"t":"d","d":{"r":2,"a":"q","b":{"p":"/t","h":""}}}"#;
    for member in ["authvar", r"authvar"] {
        let frame = format!(
            r#"{{"t":"d","d":{{"r":1,"a":"gauth","b":{{"cred":"owner","{member}":{{"uid":"u1","x":"a","y":"􏿿a"}}}}}}}}"#
        );
        let mut db = database(false);
        rest(&mut db, "PUT", "/t.json?ns=c", r#"{"a":1}"#);
        rest(&mut db, "PUT", "/.settings/rules.json?ns=c", rules);
        let got = replies(&mut db, &[&frame, listen]).join("\n");
        assert!(
            got.contains(&format!("\"y\":\"{}a\"", '\u{10FFFF}')),
            "{member}: {got}"
        );
        assert!(got.contains("permission_denied"), "{member}: {got}");
        // The same strings are equal when they are.
        let same = frame.replace(r#""x":"a""#, r#""x":"􏿿a""#);
        let mut db = database(false);
        rest(&mut db, "PUT", "/t.json?ns=c", r#"{"a":1}"#);
        rest(&mut db, "PUT", "/.settings/rules.json?ns=c", rules);
        let got = replies(&mut db, &[&same, listen]).join("\n");
        assert!(got.contains(r#""r":2,"b":{"s":"ok""#), "{member}: {got}");
    }
    // A lone surrogate in an escaped `authvar` is read as in a plain one.
    let lone = r#"{"t":"d","d":{"r":1,"a":"gauth","b":{"cred":"owner","authvar":{"uid":"u1","x":"\ud83d","y":"\ud83d"}}}}"#;
    let mut db = database(false);
    rest(&mut db, "PUT", "/t.json?ns=c", r#"{"a":1}"#);
    rest(&mut db, "PUT", "/.settings/rules.json?ns=c", rules);
    let got = replies(&mut db, &[lone, listen]).join("\n");
    assert!(got.contains(r#""x":"\uD83D""#), "{got}");
    assert!(got.contains(r#""r":2,"b":{"s":"ok""#), "{got}");
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
