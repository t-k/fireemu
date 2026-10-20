//! Security Rules at the adapter: who a request is, what the rules let it read and write over
//! REST, event streams and realtime connections, the rules endpoint, and what a rules change
//! cancels. Unless a test says otherwise, every expected answer is what the official emulator
//! (firebase-database-emulator v4.11.2) answered for the same requests.

#![allow(clippy::too_many_lines)]

use std::collections::BTreeSet;

use fireemu_adapter_database::realtime::{Opened, Session};
use fireemu_adapter_database::rest::{
    Database, Handled, HttpRequest, HttpResponse, RestOptions, RulesMode, SseEvent,
};

const NOW: i64 = 1_792_464_733_000;
const LATER: i64 = NOW + 1_234;

fn db() -> Database {
    Database::new(RestOptions::default(), 7)
}

fn request(method: &str, target: &str, headers: &[(&str, &str)], body: &str) -> HttpRequest {
    HttpRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        body: body.as_bytes().to_vec(),
    }
}

fn respond(
    db: &mut Database,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (HttpResponse, Vec<(u64, SseEvent)>) {
    match db.handle(&request(method, target, headers, body), NOW) {
        Handled::Response { response, events } => (response, events),
        Handled::Stream { .. } => panic!("unexpected stream for {method} {target}"),
    }
}

fn call(
    db: &mut Database,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String) {
    let (response, _) = respond(db, method, target, headers, body);
    (response.status, String::from_utf8(response.body).unwrap())
}

const OWNER: &[(&str, &str)] = &[("Authorization", "Bearer owner")];

fn load(db: &mut Database, ns: &str, rules: &str) -> Vec<(u64, SseEvent)> {
    let (response, events) = respond(
        db,
        "PUT",
        &format!("/.settings/rules.json?ns={ns}"),
        OWNER,
        rules,
    );
    assert_eq!(
        (response.status, String::from_utf8(response.body).unwrap()),
        (200, r#"{"status":"ok"}"#.to_owned()),
        "{rules}"
    );
    events
}

fn denied() -> String {
    "{\n  \"error\" : \"Permission denied\"\n}\n".to_owned()
}

/// An unsigned ID token with `claims`.
fn token(claims: &str) -> String {
    format!("{}.{}.", b64(r#"{"alg":"none","typ":"JWT"}"#), b64(claims))
}

fn b64(text: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes = text.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

fn open(db: &mut Database, ns: &str) -> Session {
    match db.open_realtime(&format!("/.ws?v=5&ns={ns}"), Some("127.0.0.1:9000"), NOW) {
        Ok(Opened::Session(session, _)) => session,
        other => panic!("{other:?}"),
    }
}

fn send(db: &mut Database, session: &mut Session, r: u64, action: &str, body: &str) -> Vec<String> {
    let frame = format!(r#"{{"t":"d","d":{{"r":{r},"a":"{action}","b":{body}}}}}"#);
    session.receive(db, &frame, NOW).replies
}

fn reply(r: u64, status: &str, data: &str) -> String {
    format!(r#"{{"t":"d","d":{{"r":{r},"b":{{"s":"{status}","d":{data}}}}}}}"#)
}

fn refused(r: u64) -> String {
    reply(r, "permission_denied", r#""Permission denied""#)
}

fn pushes_to(db: &mut Database, client: u64) -> Vec<String> {
    db.drain_pushes()
        .into_iter()
        .filter(|(to, _)| *to == client)
        .map(|(_, frame)| frame)
        .collect()
}

#[test]
fn the_rules_endpoint_serves_and_loads_rules_for_administrators_only() {
    let mut db = db();
    let open_default =
        "{\n    \"rules\": {\n        \".read\": true,\n        \".write\": true\n    }\n}";
    assert_eq!(
        call(&mut db, "GET", "/.settings/rules.json?ns=r1", OWNER, ""),
        (200, open_default.to_owned())
    );
    for method in ["GET", "PUT"] {
        assert_eq!(
            call(
                &mut db,
                method,
                "/.settings/rules.json?ns=r1",
                &[],
                r#"{"rules":{}}"#
            ),
            (
                403,
                "{\n  \"error\" : \"Permission denied.\"\n}\n".to_owned()
            ),
            "{method}"
        );
    }
    // The text is kept as loaded, comments included.
    let text = "{\n  // c\n  \"rules\": {\".read\": true}\n}";
    load(&mut db, "r1", text);
    assert_eq!(
        call(&mut db, "GET", "/.settings/rules.json?ns=r1", OWNER, ""),
        (200, text.to_owned())
    );
    // Another administrator credential may load rules too.
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/.settings/rules.json?ns=r1",
            &[("Authorization", "Bearer ya29.other")],
            r#"{"rules":{".read":false}}"#
        ),
        (200, r#"{"status":"ok"}"#.to_owned())
    );
    // A refused file keeps the rules in force.
    let (status, body) = call(
        &mut db,
        "PUT",
        "/.settings/rules.json?ns=r1",
        OWNER,
        r#"{"rules":{".read":"auth.foo()"}}"#,
    );
    assert_eq!(status, 400);
    assert!(body.contains("Type error"), "{body}");
    assert_eq!(
        call(&mut db, "GET", "/.json?ns=r1", &[], ""),
        (401, denied())
    );
    // Namespaces do not share rules.
    assert_eq!(call(&mut db, "GET", "/.json?ns=r2", &[], "").0, 200);
}

#[test]
fn the_locked_default_is_served_under_deny_all() {
    let mut db = Database::new(
        RestOptions {
            rules: RulesMode::DenyAll,
            ..RestOptions::default()
        },
        1,
    );
    assert_eq!(
        call(&mut db, "GET", "/.settings/rules.json?ns=r1", OWNER, ""),
        (
            200,
            "{\n    \"rules\": {\n        \".read\": false,\n        \".write\": false\n    }\n}"
                .to_owned()
        )
    );
    // Loaded rules replace the locked default.
    load(&mut db, "r1", r#"{"rules":{".read":true}}"#);
    assert_eq!(call(&mut db, "GET", "/.json?ns=r1", &[], "").0, 200);
}

#[test]
fn rest_reads_and_writes_follow_the_rules() {
    let mut db = db();
    load(
        &mut db,
        "rw",
        r#"{"rules":{"a":{".read":true,".write":true},"b":{".read":false},
            "n":{".write":true,".validate":"newData.isNumber()"},
            "q":{".read":"query.limitToFirst <= 2",".indexOn":["n"]}}}"#,
    );
    call(
        &mut db,
        "PUT",
        "/.json?ns=rw",
        OWNER,
        r#"{"a":1,"b":2,"q":{"x":{"n":1},"y":{"n":2},"z":{"n":3}}}"#,
    );
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=rw", &[], ""),
        (200, "1".to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/b.json?ns=rw", &[], ""),
        (401, denied())
    );
    assert_eq!(
        call(&mut db, "GET", "/.json?ns=rw", &[], ""),
        (401, denied())
    );
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/q.json?ns=rw&orderBy=\"n\"&limitToFirst=2",
            &[],
            ""
        )
        .0,
        200
    );
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/q.json?ns=rw&orderBy=\"n\"&limitToFirst=3",
            &[],
            ""
        ),
        (401, denied())
    );
    for (method, target, body) in [
        ("PUT", "/b.json?ns=rw", "1"),
        ("POST", "/b.json?ns=rw", "1"),
        ("PATCH", "/.json?ns=rw", r#"{"a":2,"b":3}"#),
        ("PUT", "/n.json?ns=rw", r#""text""#),
        ("DELETE", "/b.json?ns=rw", ""),
    ] {
        assert_eq!(
            call(&mut db, method, target, &[], body),
            (401, denied()),
            "{method} {target}"
        );
    }
    assert_eq!(call(&mut db, "PUT", "/n.json?ns=rw", &[], "5").0, 200);
    assert_eq!(
        call(&mut db, "PATCH", "/.json?ns=rw", &[], r#"{"a":2,"n":6}"#).0,
        200
    );
    // A delete leaves nothing to validate.
    assert_eq!(call(&mut db, "DELETE", "/n.json?ns=rw", &[], "").0, 200);
    // Refused writes changed nothing.
    assert_eq!(
        call(&mut db, "GET", "/b.json?ns=rw", OWNER, ""),
        (200, "2".to_owned())
    );
}

#[test]
fn credentials_decide_who_the_rules_see() {
    let mut db = db();
    let checks = [
        ("auth.uid == 's1'", r#"{"sub":"s1","iat":1}"#, 200),
        // `uid` and `user_id` claims do not name the user; `sub` does.
        (
            "auth.uid == 'u2'",
            r#"{"sub":"s1","uid":"u2","iat":1}"#,
            401,
        ),
        (
            "auth.uid == 'x'",
            r#"{"sub":"s1","user_id":"x","iat":1}"#,
            401,
        ),
        (
            "auth.provider == 'password'",
            r#"{"sub":"s1","iat":1,"firebase":{"sign_in_provider":"password"}}"#,
            200,
        ),
        (
            "auth.provider == 'anonymous'",
            r#"{"sub":"s1","iat":1}"#,
            200,
        ),
        (
            "auth.token.firebase.sign_in_provider == 'password'",
            r#"{"sub":"s1","iat":1,"firebase":{"sign_in_provider":"password"}}"#,
            200,
        ),
        (
            "auth.token.email_verified == false",
            r#"{"sub":"s1","iat":1}"#,
            401,
        ),
        ("auth.token.email == null", r#"{"sub":"s1","iat":1}"#, 200),
        (
            "auth.token.exp == 5",
            r#"{"sub":"s1","iat":1,"exp":5}"#,
            200,
        ),
        // Without `iat` the token is no user.
        ("auth != null", r#"{"sub":"s1"}"#, 401),
        // Custom claims are members of `auth`, and replace `provider` and `token`; the
        // reserved ones are not, and `uid` stays `sub`.
        ("auth.admin == true", r#"{"sub":"s1","iat":1,"admin":true}"#, 200),
        ("auth.provider == 'p'", r#"{"sub":"s1","iat":1,"provider":"p","firebase":{"sign_in_provider":"password"}}"#, 200),
        ("auth.token == 't'", r#"{"sub":"s1","iat":1,"token":"t"}"#, 200),
        ("auth.user_id == 'x'", r#"{"sub":"s1","iat":1,"user_id":"x"}"#, 200),
        ("auth.uid == 's1'", r#"{"sub":"s1","iat":1,"uid":"u2"}"#, 200),
        (
            "auth.sub == null && auth.iat == null && auth.exp == null && auth.nbf == null && auth.aud == null && auth.iss == null && auth.jti == null && auth.auth_time == null && auth.firebase == null",
            r#"{"sub":"s1","iat":1,"exp":2,"nbf":3,"aud":"a","iss":"i","jti":"j","auth_time":4,"firebase":{}}"#,
            200,
        ),
    ];
    for (n, (rule, claims, status)) in checks.into_iter().enumerate() {
        let ns = format!("cr{n}");
        load(
            &mut db,
            &ns,
            &format!(r#"{{"rules":{{".read":"{rule}"}}}}"#),
        );
        let token = token(claims);
        assert_eq!(
            call(
                &mut db,
                "GET",
                &format!("/.json?ns={ns}&auth={token}"),
                &[],
                ""
            )
            .0,
            status,
            "{rule} {claims}"
        );
        // An access token is an administrator, whatever it is.
        let bearer = format!("Bearer {token}");
        assert_eq!(
            call(
                &mut db,
                "GET",
                &format!("/.json?ns={ns}"),
                &[("Authorization", &bearer)],
                ""
            )
            .0,
            200
        );
        assert_eq!(
            call(
                &mut db,
                "GET",
                &format!("/.json?ns={ns}&access_token=x"),
                &[],
                ""
            )
            .0,
            200
        );
    }
    // A token that is not a JWT is anonymous.
    load(&mut db, "bad", r#"{"rules":{".read":"auth == null"}}"#);
    assert_eq!(
        call(&mut db, "GET", "/.json?ns=bad&auth=nonsense", &[], ""),
        (200, "null".to_owned())
    );
}

#[test]
fn administrators_bypass_rules_except_under_deny_all() {
    let mut db = db();
    load(&mut db, "ad", r#"{"rules":{".read":false,".write":false}}"#);
    let admin = &[("Authorization", "Bearer ya29.other")];
    assert_eq!(call(&mut db, "PUT", "/a.json?ns=ad", admin, "1").0, 200);
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=ad", admin, ""),
        (200, "1".to_owned())
    );

    // Under `productionExact` only the emulator's owner passes the rules.
    let mut exact = Database::new(
        RestOptions {
            rules: RulesMode::DenyAll,
            ..RestOptions::default()
        },
        1,
    );
    load(
        &mut exact,
        "ad",
        r#"{"rules":{".read":false,".write":false}}"#,
    );
    assert_eq!(
        call(&mut exact, "GET", "/a.json?ns=ad", admin, ""),
        (401, denied())
    );
    assert_eq!(call(&mut exact, "GET", "/a.json?ns=ad", OWNER, "").0, 200);
}

#[test]
fn a_refused_event_stream_is_answered_in_plain_text() {
    let mut db = db();
    load(&mut db, "es", r#"{"rules":{".read":false}}"#);
    let (response, _) = respond(
        &mut db,
        "GET",
        "/.json?ns=es",
        &[("Accept", "text/event-stream")],
        "",
    );
    assert_eq!(response.status, 401);
    assert_eq!(
        String::from_utf8(response.body).unwrap(),
        "Permission denied"
    );
}

#[test]
fn a_rules_change_cancels_the_event_streams_it_no_longer_allows() {
    let mut db = db();
    load(&mut db, "ec", r#"{"rules":{".read":true}}"#);
    let mut ids = Vec::new();
    for target in ["/a.json?ns=ec", "/b.json?ns=ec"] {
        match db.handle(
            &request("GET", target, &[("Accept", "text/event-stream")], ""),
            NOW,
        ) {
            Handled::Stream { id, .. } => ids.push(id),
            Handled::Response { response, .. } => panic!("{response:?}"),
        }
    }
    let events = load(&mut db, "ec", r#"{"rules":{"a":{".read":true}}}"#);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].0, ids[1]);
    assert_eq!(
        events[0].1.to_text(),
        "event: cancel\ndata: Permission denied\n\n"
    );
    // The cancelled stream hears nothing more; the other still does.
    let (_, events) = respond(&mut db, "PUT", "/.json?ns=ec", OWNER, r#"{"a":1,"b":2}"#);
    let later: Vec<u64> = events.into_iter().map(|(id, _)| id).collect();
    assert_eq!(later, vec![ids[0]]);
}

#[test]
fn realtime_reads_and_listens_follow_the_rules_and_a_change_cancels_them() {
    let mut db = db();
    load(
        &mut db,
        "lr",
        r#"{"rules":{"a":{".read":true},"b":{".read":false},
            "q":{".read":"query.limitToFirst <= 2",".indexOn":["n"]}}}"#,
    );
    call(
        &mut db,
        "PUT",
        "/.json?ns=lr",
        OWNER,
        r#"{"a":1,"b":2,"q":{"x":{"n":1},"y":{"n":2},"z":{"n":3}}}"#,
    );
    let mut session = open(&mut db, "lr");
    let client = session.client();
    let mut frames = Vec::new();
    for (r, (action, body)) in (1..).zip([
        ("q", r#"{"p":"/a","h":""}"#),
        ("q", r#"{"p":"/b","h":""}"#),
        ("q", r#"{"p":"/","h":""}"#),
        (
            "q",
            r#"{"p":"/q","q":{"i":"n","l":2,"vf":"l"},"t":1,"h":""}"#,
        ),
        (
            "q",
            r#"{"p":"/q","q":{"i":"n","l":3,"vf":"l"},"t":2,"h":""}"#,
        ),
        ("g", r#"{"p":"/b","q":{}}"#),
    ]) {
        frames.extend(send(&mut db, &mut session, r, action, body));
        frames.extend(pushes_to(&mut db, client));
    }
    assert_eq!(
        frames,
        vec![
            r#"{"t":"d","d":{"b":{"p":"a","d":1},"a":"d"}}"#.to_owned(),
            reply(1, "ok", "{}"),
            refused(2),
            refused(3),
            r#"{"t":"d","d":{"b":{"p":"q","d":{"x":{"n":1},"y":{"n":2}},"t":1},"a":"d"}}"#
                .to_owned(),
            reply(4, "ok", "{}"),
            refused(5),
            refused(6),
        ]
    );
    load(&mut db, "lr", r#"{"rules":{"a":{".read":false}}}"#);
    // The official emulator sends the cancellations in an order of its own.
    let cancelled: BTreeSet<String> = pushes_to(&mut db, client).into_iter().collect();
    assert_eq!(
        cancelled,
        BTreeSet::from([
            r#"{"t":"d","d":{"b":{"p":"a","q":null},"a":"c"}}"#.to_owned(),
            r#"{"t":"d","d":{"b":{"p":"q","q":[{"i":"n","sin":true,"ein":true,"l":2,"vf":"l"}]},"a":"c"}}"#
                .to_owned(),
        ])
    );
    assert_eq!(
        send(&mut db, &mut session, 7, "q", r#"{"p":"/a","h":""}"#),
        vec![refused(7)]
    );
    // Cancelled listens hear no more changes.
    call(&mut db, "PUT", "/a.json?ns=lr", OWNER, "5");
    assert_eq!(pushes_to(&mut db, client), Vec::<String>::new());
}

#[test]
fn cancellations_spell_the_query_as_the_official_emulator_does() {
    let mut db = db();
    load(
        &mut db,
        "rv",
        r#"{"rules":{".read":true,"q":{".indexOn":["n"]}}}"#,
    );
    let mut session = open(&mut db, "rv");
    let client = session.client();
    send(&mut db, &mut session, 1, "q", r#"{"p":"/a","h":""}"#);
    for (t, q) in (1..).zip([
        r#"{"i":"n","l":2,"vf":"l"}"#,
        r#"{"i":".key","sp":"a","ep":"z"}"#,
        r#"{"i":".value","sp":1,"sn":"k","l":3,"vf":"r"}"#,
        r#"{"sp":2}"#,
        r#"{"i":"n","sp":1,"sin":false,"ep":5,"ein":false}"#,
        r#"{"i":".priority","l":1,"vf":"r"}"#,
    ]) {
        send(
            &mut db,
            &mut session,
            t + 1,
            "q",
            &format!(r#"{{"p":"/q","q":{q},"t":{t},"h":""}}"#),
        );
    }
    pushes_to(&mut db, client);
    load(&mut db, "rv", r#"{"rules":{".read":false}}"#);
    let cancelled: BTreeSet<String> = pushes_to(&mut db, client).into_iter().collect();
    let expected: BTreeSet<String> = [
        r#"{"t":"d","d":{"b":{"p":"q","q":[{"i":"n","sp":1,"sin":false,"ep":5,"ein":false}]},"a":"c"}}"#,
        r#"{"t":"d","d":{"b":{"p":"a","q":null},"a":"c"}}"#,
        r#"{"t":"d","d":{"b":{"p":"q","q":[{"sin":true,"ein":true,"l":1,"vf":"r"}]},"a":"c"}}"#,
        r#"{"t":"d","d":{"b":{"p":"q","q":[{"i":".value","sn":"k","sp":1,"sin":true,"ein":true,"l":3,"vf":"r"}]},"a":"c"}}"#,
        r#"{"t":"d","d":{"b":{"p":"q","q":[{"i":"n","sin":true,"ein":true,"l":2,"vf":"l"}]},"a":"c"}}"#,
        r#"{"t":"d","d":{"b":{"p":"q","q":[{"sp":2,"sin":true,"ein":true}]},"a":"c"}}"#,
        r#"{"t":"d","d":{"b":{"p":"q","q":[{"i":".key","sp":"a","sin":true,"ep":"z","ein":true}]},"a":"c"}}"#,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(cancelled, expected);
}

#[test]
fn signing_in_and_out_changes_what_a_connection_may_do() {
    let mut db = db();
    load(
        &mut db,
        "si",
        r#"{"rules":{"users":{"$uid":{".read":"auth != null && auth.uid === $uid",
            ".write":"auth != null && auth.uid === $uid"}}}}"#,
    );
    let mut session = open(&mut db, "si");
    let client = session.client();
    assert_eq!(
        send(&mut db, &mut session, 1, "p", r#"{"p":"/users/u1","d":1}"#),
        vec![refused(1)]
    );
    let token = token(r#"{"sub":"u1","iat":1}"#);
    send(
        &mut db,
        &mut session,
        2,
        "auth",
        &format!(r#"{{"cred":"{token}"}}"#),
    );
    assert_eq!(
        send(&mut db, &mut session, 3, "p", r#"{"p":"/users/u1","d":1}"#),
        vec![reply(3, "ok", r#""""#)]
    );
    assert_eq!(
        send(
            &mut db,
            &mut session,
            4,
            "m",
            r#"{"p":"/users","d":{"u1":2,"u2":2}}"#
        ),
        vec![refused(4)]
    );
    send(&mut db, &mut session, 5, "q", r#"{"p":"/users/u1","h":""}"#);
    pushes_to(&mut db, client);
    // Signing out, or in as someone else, cancels the listens the connection may no longer
    // read, before the answer.
    let cancel = r#"{"t":"d","d":{"b":{"p":"users/u1","q":null},"a":"c"}}"#.to_owned();
    assert_eq!(
        send(&mut db, &mut session, 6, "unauth", "{}"),
        vec![cancel.clone(), reply(6, "ok", r#""unauthenticated""#)]
    );
    send(
        &mut db,
        &mut session,
        7,
        "auth",
        &format!(r#"{{"cred":"{token}"}}"#),
    );
    send(&mut db, &mut session, 8, "q", r#"{"p":"/users/u1","h":""}"#);
    pushes_to(&mut db, client);
    let other = self::token(r#"{"sub":"u2","iat":1}"#);
    let answer = send(
        &mut db,
        &mut session,
        9,
        "auth",
        &format!(r#"{{"cred":"{other}"}}"#),
    );
    assert_eq!(answer.len(), 2, "{answer:?}");
    assert_eq!(answer[0], cancel);
    // The owner reads everything until it signs out.
    send(&mut db, &mut session, 10, "gauth", r#"{"cred":"owner"}"#);
    send(
        &mut db,
        &mut session,
        11,
        "q",
        r#"{"p":"/users/u1","h":""}"#,
    );
    pushes_to(&mut db, client);
    assert_eq!(
        send(&mut db, &mut session, 12, "unauth", "{}"),
        vec![cancel, reply(12, "ok", r#""unauthenticated""#)]
    );
    assert_eq!(
        call(&mut db, "GET", "/users.json?ns=si", OWNER, ""),
        (200, r#"{"u1":1}"#.to_owned())
    );
}

#[test]
fn on_disconnect_writes_are_checked_when_registered_and_when_made() {
    let rules = r#"{"rules":{".read":true,"x":{".write":false},"y":{".write":true},
        "z":{".write":true,".validate":"newData.isNumber()"}}}"#;
    for change in [false, true] {
        let mut db = db();
        load(&mut db, "od", rules);
        let mut session = open(&mut db, "od");
        let mut frames = Vec::new();
        for (r, (action, body)) in (1..).zip([
            ("o", r#"{"p":"/x","d":1}"#),
            ("o", r#"{"p":"/y","d":1}"#),
            ("o", r#"{"p":"/z","d":"str"}"#),
            ("oc", r#"{"p":"/x"}"#),
            ("p", r#"{"p":"/x","d":1}"#),
        ]) {
            frames.extend(send(&mut db, &mut session, r, action, body));
        }
        assert_eq!(
            frames,
            vec![
                refused(1),
                reply(2, "ok", r#""""#),
                refused(3),
                reply(4, "ok", r#""""#),
                refused(5),
            ]
        );
        if change {
            load(&mut db, "od", r#"{"rules":{".read":true,".write":false}}"#);
        }
        db.close_realtime(session.client(), LATER);
        let expected = if change { "null" } else { r#"{"y":1}"# };
        assert_eq!(
            call(&mut db, "GET", "/.json?ns=od", &[], ""),
            (200, expected.to_owned()),
            "change {change}"
        );
    }
}

#[test]
fn on_disconnect_writes_are_made_as_the_connection_is_at_its_end() {
    let mut db = db();
    load(
        &mut db,
        "oi",
        r#"{"rules":{".read":true,"users":{"$uid":{".write":"auth != null && auth.uid === $uid"}}}}"#,
    );
    let mut session = open(&mut db, "oi");
    let token = token(r#"{"sub":"u1","uid":"u1","iat":1,"exp":9999999999}"#);
    assert_eq!(
        send(
            &mut db,
            &mut session,
            1,
            "auth",
            &format!(r#"{{"cred":"{token}"}}"#)
        ),
        vec![reply(
            1,
            "ok",
            r#"{"auth":{"provider":"anonymous","token":{"exp":9999999999,"iat":1,"sub":"u1","uid":"u1"},"uid":"u1"},"expires":null}"#
        )]
    );
    assert_eq!(
        send(
            &mut db,
            &mut session,
            2,
            "o",
            r#"{"p":"/users/u1","d":"gone"}"#
        ),
        vec![reply(2, "ok", r#""""#)]
    );
    send(&mut db, &mut session, 3, "unauth", "{}");
    db.close_realtime(session.client(), LATER);
    assert_eq!(
        call(&mut db, "GET", "/.json?ns=oi", &[], ""),
        (200, "null".to_owned())
    );
}

#[test]
fn rules_loaded_outside_a_request_reach_streams_through_the_flush_queue() {
    let mut db = db();
    assert_eq!(
        db.load_rules("bad.name", r#"{"rules":{}}"#, NOW),
        Err("Invalid Firebase database name".to_owned())
    );
    assert_eq!(
        db.load_rules("lo", r#"{"rules":{".read":"auth.foo()"}}"#, NOW),
        Err("1:20: Type error: Function call on target that is not a function.".to_owned())
    );
    db.load_rules("lo", r#"{"rules":{".read":true}}"#, NOW)
        .unwrap();
    let id = match db.handle(
        &request(
            "GET",
            "/.json?ns=lo",
            &[("Accept", "text/event-stream")],
            "",
        ),
        NOW,
    ) {
        Handled::Stream { id, .. } => id,
        Handled::Response { response, .. } => panic!("{response:?}"),
    };
    db.load_rules("lo", r#"{"rules":{".read":false}}"#, NOW)
        .unwrap();
    assert_eq!(db.drain_events(), vec![(id, SseEvent::cancel())]);
    assert_eq!(db.rules_text("lo"), r#"{"rules":{".read":false}}"#);
}
