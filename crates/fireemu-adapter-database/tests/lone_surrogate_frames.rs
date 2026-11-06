//! A lone surrogate escape in a WebSocket frame, as the official emulator (4.11.2) answers it
//! (`docs.local/runs/rtdb-lone-surrogate/probe-ws.mjs`, jar-ws.json; owner row "RTDB closure lone surrogates in claims
//! and query values", 2026-11-06). On the emulator profile a value stores `?` (a valid pair stays), a path that holds
//! one is `Invalid token in path`, a data key that holds one is refused as any invalid key is (the connection error;
//! for a merge entry the official emulator says `Invalid token in path`, which fireemu does for no invalid key), a listen's bound reads `?`, and the claims of an `auth`
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
            // The official emulator answers `invalid_parameters` here, as it does for any invalid merge key
            // (`b.c`, `b$c`); fireemu answers the connection error for all of them. Older than the surrogate and
            // not followed.
            r#"{"t":"d","d":{"r":1,"a":"m","b":{"p":"/t","d":{"b\ud83d":1}}}}"#.to_owned(),
            connection_error,
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
