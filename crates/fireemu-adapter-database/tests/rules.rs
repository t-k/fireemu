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

#[test]
fn on_disconnect_updates_are_checked_as_one_update() {
    let mut db = db();
    load(
        &mut db,
        "om",
        r#"{"rules":{".read":true,"x":{".write":false},"y":{".write":true},
            "z":{".write":true,".validate":"newData.isNumber()"}}}"#,
    );
    let mut session = open(&mut db, "om");
    let mut frames = Vec::new();
    for (r, body) in (1..).zip([
        r#"{"p":"/","d":{"x":1,"y":1}}"#,
        r#"{"p":"/","d":{"y":2}}"#,
        r#"{"p":"/","d":{"z":"s"}}"#,
        r#"{"p":"/","d":{"z":3,"y":4}}"#,
    ]) {
        frames.extend(send(&mut db, &mut session, r, "om", body));
    }
    assert_eq!(
        frames,
        vec![
            refused(1),
            reply(2, "ok", r#""""#),
            refused(3),
            reply(4, "ok", r#""""#),
        ]
    );
    db.close_realtime(session.client(), LATER);
    assert_eq!(
        call(&mut db, "GET", "/.json?ns=om", &[], ""),
        (200, r#"{"y":4,"z":3}"#.to_owned())
    );
}

#[test]
fn rules_loaded_outside_a_request_wake_the_flush() {
    let mut db = db();
    let woken = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&woken);
    db.set_waker(std::sync::Arc::new(move || {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }));
    db.load_rules("wk", r#"{"rules":{".read":true}}"#, NOW)
        .unwrap();
    assert!(woken.load(std::sync::atomic::Ordering::SeqCst) > 0);
}

/// A credential shape: its name, the path and query, the headers, and the status under the
/// emulator profile and under strict.
type Case<'a> = (&'a str, String, Vec<(&'a str, &'a str)>, u16, u16);

/// A verifier that accepts only tokens whose `sub` starts with `ok-`, presented to
/// `demo-default-rtdb` (standing in for fireemu's Auth), answering the claims it decoded.
fn verifier() -> fireemu_adapter_database::rest::IdTokenVerifier {
    std::sync::Arc::new(|token: &str, namespace: &str, _now: i64| {
        let claims = token.split('.').nth(1)?;
        let text = b64_decode(claims)?;
        (namespace == "demo-default-rtdb" && text.contains("\"sub\":\"ok-")).then_some(text)
    })
}

fn b64_decode(text: &str) -> Option<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for c in text.bytes() {
        let value = u32::try_from(ALPHABET.iter().position(|a| *a == c)?).ok()?;
        bits = (bits << 6) | value;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).ok()?);
        }
    }
    String::from_utf8(out).ok()
}

fn with_credentials(strict: bool, verify: bool) -> Database {
    Database::new(
        RestOptions {
            credentials: fireemu_adapter_database::rest::Credentials {
                strict,
                id_tokens: verify.then(verifier),
            },
            ..RestOptions::default()
        },
        7,
    )
}

#[test]
fn each_profile_reads_each_credential_shape_as_the_ruling_says() {
    let good = token(r#"{"sub":"ok-1","iat":1}"#);
    let unverified = token(r#"{"sub":"u1","iat":1}"#);
    // (shape, emulator profile with a verifier, strict profile with a verifier):
    // 200 allowed as the expected caller, 401 refused or denied.
    let rules = r#"{"rules":{"admin":{".read":false},"user":{".read":"auth.uid == 'ok-1'"},"anon":{".read":"auth == null"}}}"#;
    let cases: [Case; 9] = [
        (
            "owner bearer",
            "/admin".to_owned(),
            vec![("Authorization", "Bearer owner")],
            200,
            200,
        ),
        (
            "other bearer",
            "/admin".to_owned(),
            vec![("Authorization", "Bearer ya29.x")],
            200,
            401,
        ),
        (
            "owner access_token",
            "/admin?access_token=owner".to_owned(),
            vec![],
            200,
            200,
        ),
        (
            "other access_token",
            "/admin?access_token=x".to_owned(),
            vec![],
            200,
            401,
        ),
        (
            "verified token",
            format!("/user?auth={good}"),
            vec![],
            200,
            200,
        ),
        (
            "unverified token",
            format!("/anon?auth={unverified}"),
            vec![],
            200,
            401,
        ),
        (
            "auth=owner",
            "/anon?auth=owner".to_owned(),
            vec![],
            200,
            401,
        ),
        ("auth=garbage", "/anon?auth=x".to_owned(), vec![], 200, 401),
        ("no credential", "/anon".to_owned(), vec![], 200, 200),
    ];
    for strict in [false, true] {
        let mut db = with_credentials(strict, true);
        load(&mut db, "demo-default-rtdb", rules);
        for (shape, path, headers, emulator, strict_status) in &cases {
            let (base, query) = path.split_once('?').unwrap_or((path.as_str(), ""));
            let target = format!("{base}.json?ns=demo-default-rtdb&{query}");
            let status = call(&mut db, "GET", &target, headers, "").0;
            let expected = if strict { *strict_status } else { *emulator };
            assert_eq!(status, expected, "strict {strict}: {shape}");
        }
    }
    // An unverified token under the emulator profile is anonymous, not its user.
    let mut db = with_credentials(false, true);
    load(&mut db, "demo-default-rtdb", rules);
    assert_eq!(
        call(
            &mut db,
            "GET",
            &format!("/user.json?ns=demo-default-rtdb&auth={unverified}"),
            &[],
            ""
        )
        .0,
        401
    );
    // A token for another project is no user of this one.
    assert_eq!(
        call(
            &mut db,
            "GET",
            &format!("/user.json?ns=other-default-rtdb&auth={good}"),
            &[],
            ""
        )
        .0,
        200
    );
}

#[test]
fn the_rules_endpoint_needs_an_administrator_of_the_profile() {
    let mut db = with_credentials(true, true);
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/.settings/rules.json?ns=r1",
            &[("Authorization", "Bearer ya29.x")],
            ""
        )
        .0,
        401
    );
    assert_eq!(
        call(&mut db, "GET", "/.settings/rules.json?ns=r1", OWNER, "").0,
        200
    );
}

#[test]
fn realtime_credentials_follow_the_profile() {
    let good = token(r#"{"sub":"ok-1","iat":1}"#);
    let unverified = token(r#"{"sub":"u1","iat":1}"#);
    let unparsable = reply(1, "invalid_token", r#""Could not parse auth token.""#);
    for strict in [false, true] {
        let mut db = with_credentials(strict, true);
        let mut session = open(&mut db, "demo-default-rtdb");
        let other = send(&mut db, &mut session, 1, "gauth", r#"{"cred":"ya29.x"}"#);
        if strict {
            assert_eq!(
                other,
                vec![reply(1, "permission_denied", r#""Permission denied""#)]
            );
        } else {
            assert!(other[0].contains(r#""s":"ok""#), "{other:?}");
        }
        let owner = send(&mut db, &mut session, 2, "gauth", r#"{"cred":"owner"}"#);
        assert!(owner[0].contains(r#""s":"ok""#), "{owner:?}");
        assert_eq!(
            send(
                &mut db,
                &mut session,
                1,
                "auth",
                &format!(r#"{{"cred":"{unverified}"}}"#)
            ),
            vec![unparsable.clone()],
            "strict {strict}"
        );
        let user = send(
            &mut db,
            &mut session,
            3,
            "auth",
            &format!(r#"{{"cred":"{good}"}}"#),
        );
        assert!(user[0].contains(r#""uid":"ok-1""#), "{user:?}");
    }
}

#[test]
fn credentials_debug_says_whether_a_verifier_is_set() {
    let credentials = fireemu_adapter_database::rest::Credentials {
        strict: true,
        id_tokens: Some(verifier()),
    };
    assert_eq!(
        format!("{credentials:?}"),
        "Credentials { strict: true, id_tokens: true }"
    );
    let text = format!("{:?}", RestOptions::default().credentials);
    assert_eq!(text, "Credentials { strict: false, id_tokens: false }");
}

/// Runs `f` on a thread with the stack of the daemon's server workers, where requests run
/// (`RUNTIME_THREAD_STACK_BYTES`, 8 MiB).
fn on_worker_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn deep_rules_are_refused_without_exhausting_the_stack() {
    on_worker_stack(|| {
        let mut db = db();
        let put = |db: &mut Database, rule: &str| {
            let body = format!(r#"{{"rules":{{".read":"{rule}"}}}}"#);
            call(db, "PUT", "/.settings/rules.json?ns=deep", OWNER, &body)
        };
        let levels = |n: usize| {
            format!(
                r#"{{"rules":{}{{}}{}}}"#,
                r#"{"a":"#.repeat(n),
                "}".repeat(n)
            )
        };
        // Deep rules within the bounds load, and are evaluated.
        for rule in [
            format!("{}true{}", "(".repeat(500), ")".repeat(500)),
            format!("{}true", "!".repeat(500)),
            format!("root{}.val() == null", ".child('a')".repeat(250)),
            format!("{}true{}", "true ? ".repeat(500), " : false".repeat(500)),
        ] {
            let (status, text) = put(&mut db, &rule);
            assert_eq!(status, 200, "{text}");
            call(&mut db, "GET", "/a.json?ns=deep", &[], "");
        }
        let (status, text) = call(
            &mut db,
            "PUT",
            "/.settings/rules.json?ns=deep",
            OWNER,
            &levels(1000),
        );
        assert_eq!(status, 200, "{text}");
        call(&mut db, "GET", "/a.json?ns=deep", &[], "");
        // Deeper ones are refused with the official emulator's text, whatever the shape.
        for rule in [
            format!("{}true{}", "(".repeat(10_000), ")".repeat(10_000)),
            format!("{}true", "!".repeat(10_000)),
            format!("root{}.val() == null", ".child('a')".repeat(10_000)),
            format!("data{}.val() == null", ".parent()".repeat(10_000)),
            format!("auth{} == null", "['a']".repeat(10_000)),
            format!(
                "{}true{}",
                "true ? ".repeat(10_000),
                " : false".repeat(10_000)
            ),
            format!("{}true", "false ? false : ".repeat(10_000)),
        ] {
            let (status, text) = put(&mut db, &rule);
            assert_eq!(status, 400);
            assert!(
                text.contains("1:20: Rule expression may not be empty."),
                "{text}"
            );
        }
        for n in [1001, 10_000] {
            assert_eq!(
                call(
                    &mut db,
                    "PUT",
                    "/.settings/rules.json?ns=deep",
                    OWNER,
                    &levels(n)
                )
                .0,
                400,
                "{n}"
            );
        }
        // The database still answers.
        assert_eq!(call(&mut db, "GET", "/.json?ns=other", &[], "").0, 200);
    });
}

#[test]
fn conditional_writes_need_the_read_too() {
    // Recorded on the official emulator (docs.local cond-probe): rules let `w` be written
    // but not read, and `r` be read and written.
    let mut db = db();
    load(
        &mut db,
        "cw",
        r#"{"rules":{"w":{".write":true},"r":{".read":true,".write":true}}}"#,
    );
    call(
        &mut db,
        "PUT",
        "/.json?ns=cw",
        OWNER,
        r#"{"w":{"hidden":"h1"},"r":1}"#,
    );
    let tag = {
        let (response, _) = respond(
            &mut db,
            "GET",
            "/w.json?ns=cw",
            &[
                ("Authorization", "Bearer owner"),
                ("X-Firebase-ETag", "true"),
            ],
            "",
        );
        response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("etag"))
            .unwrap()
            .1
            .clone()
    };
    for (method, headers, body) in [
        ("PUT", vec![("if-match", "bogus")], r#""x""#),
        ("PUT", vec![("if-match", tag.as_str())], r#""x""#),
        ("PUT", vec![("if-none-match", "bogus")], r#""x""#),
        ("DELETE", vec![("if-match", "bogus")], ""),
    ] {
        let (response, _) = respond(&mut db, method, "/w.json?ns=cw", &headers, body);
        assert_eq!(response.status, 401, "{method} {headers:?}");
        assert_eq!(String::from_utf8(response.body).unwrap(), denied());
        assert!(!response
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("etag")));
    }
    // Where the caller may read, the comparison answers as before.
    let (response, _) = respond(
        &mut db,
        "PUT",
        "/r.json?ns=cw",
        &[("if-match", "bogus")],
        "2",
    );
    assert_eq!(response.status, 412);
    // An unconditional write answers the ETag of what it wrote.
    let (response, _) = respond(
        &mut db,
        "PUT",
        "/w.json?ns=cw",
        &[("X-Firebase-ETag", "true")],
        r#"{"hidden":"h1"}"#,
    );
    assert_eq!(response.status, 200);
    let mut session = open(&mut db, "cw");
    assert_eq!(
        send(
            &mut db,
            &mut session,
            1,
            "p",
            r#"{"p":"/w","d":"x","h":"bogus"}"#
        ),
        vec![refused(1)]
    );
    assert_eq!(
        send(
            &mut db,
            &mut session,
            2,
            "p",
            r#"{"p":"/r","d":3,"h":"bogus"}"#
        ),
        vec![reply(
            2,
            "datastale",
            r#""Transaction ETag does not match""#
        )]
    );
    assert_eq!(
        send(&mut db, &mut session, 3, "p", r#"{"p":"/w","d":"z"}"#),
        vec![reply(3, "ok", r#""""#)]
    );
    assert_eq!(
        call(&mut db, "GET", "/.json?ns=cw", OWNER, ""),
        (200, r#"{"r":1,"w":"z"}"#.to_owned())
    );
}

#[test]
fn a_priority_write_is_judged_at_its_node() {
    // Recorded on the official emulator (docs.local prio-probe).
    let field = r#"{"rules":{"users":{"$uid":{"$field":{".write":true}}}}}"#;
    let uid = r#"{"rules":{"users":{"$uid":{".write":true}}}}"#;
    let validated =
        r#"{"rules":{"users":{"$uid":{".write":true,".validate":"newData.getPriority() == 5"}}}}"#;
    let child_invalid =
        r#"{"rules":{"users":{"$uid":{".write":true,"$field":{".validate":false}}}}}"#;
    for (rules, method, path, body, status) in [
        (field, "PUT", "/users/u1/.priority", "5", 401),
        (uid, "PUT", "/users/u1/.priority", "5", 200),
        (field, "PATCH", "/users/u1", r#"{".priority":5}"#, 401),
        (uid, "PATCH", "/users/u1", r#"{".priority":5}"#, 200),
        (
            field,
            "PATCH",
            "/users/u1",
            r#"{"name":"b",".priority":5}"#,
            401,
        ),
        (field, "PATCH", "/", r#"{"users/u1/.priority":5}"#, 401),
        (validated, "PUT", "/users/u1/.priority", "5", 200),
        (validated, "PUT", "/users/u1/.priority", "6", 401),
        (child_invalid, "PUT", "/users/u1/.priority", "5", 401),
        (field, "PUT", "/users/u1/name/.priority", "5", 200),
    ] {
        let mut db = db();
        load(&mut db, "pr", rules);
        call(
            &mut db,
            "PUT",
            "/.json?ns=pr",
            OWNER,
            r#"{"users":{"u1":{"name":"a"}}}"#,
        );
        let target = format!("{path}.json?ns=pr");
        assert_eq!(
            call(&mut db, method, &target, &[], body).0,
            status,
            "{rules} {method} {path} {body}"
        );
    }
    // The realtime protocol and onDisconnect judge it the same way.
    let mut db = db();
    load(&mut db, "pr", field);
    call(
        &mut db,
        "PUT",
        "/.json?ns=pr",
        OWNER,
        r#"{"users":{"u1":{"name":"a"}}}"#,
    );
    let mut session = open(&mut db, "pr");
    for (r, action, body) in [
        (1, "p", r#"{"p":"/users/u1/.priority","d":5}"#),
        (2, "m", r#"{"p":"/users/u1","d":{".priority":5}}"#),
        (3, "o", r#"{"p":"/users/u1/.priority","d":5}"#),
        (4, "om", r#"{"p":"/users/u1","d":{".priority":5}}"#),
    ] {
        assert_eq!(
            send(&mut db, &mut session, r, action, body),
            vec![refused(r)],
            "{action}"
        );
    }
}

#[test]
fn on_disconnect_writes_are_judged_one_by_one_when_made() {
    // Recorded on the official emulator (docs.local odfire-probe): the writes registered
    // for u2 and u4 are denied when the connection ends, the others are made as one update.
    let mut db = db();
    load(
        &mut db,
        "of",
        r#"{"rules":{".read":true,"users":{"$uid":{".write":"root.child('closed').child($uid).val() !== true"}}}}"#,
    );
    let mut listener = open(&mut db, "of");
    send(&mut db, &mut listener, 1, "q", r#"{"p":"/users","h":""}"#);
    let mut session = open(&mut db, "of");
    for (r, action, body) in [
        (1, "o", r#"{"p":"/users/u1","d":"gone1"}"#),
        (2, "o", r#"{"p":"/users/u2","d":"gone2"}"#),
        (3, "om", r#"{"p":"/users","d":{"u3":"gone3","u4":"gone4"}}"#),
        (4, "om", r#"{"p":"/users","d":{"u5":"gone5","u6":"gone6"}}"#),
        (5, "o", r#"{"p":"/users/u7","d":"gone7"}"#),
    ] {
        assert_eq!(
            send(&mut db, &mut session, r, action, body),
            vec![reply(r, "ok", r#""""#)]
        );
    }
    call(
        &mut db,
        "PUT",
        "/closed.json?ns=of",
        OWNER,
        r#"{"u2":true,"u4":true}"#,
    );
    pushes_to(&mut db, listener.client());
    db.close_realtime(session.client(), LATER);
    let heard = pushes_to(&mut db, listener.client());
    assert_eq!(heard.len(), 1, "{heard:?}");
    assert!(heard[0].contains(r#""a":"m""#), "{heard:?}");
    assert_eq!(
        call(&mut db, "GET", "/users.json?ns=of", &[], ""),
        (
            200,
            r#"{"u1":"gone1","u3":"gone3","u5":"gone5","u6":"gone6","u7":"gone7"}"#.to_owned()
        )
    );
}

#[test]
fn a_write_that_makes_a_read_false_cancels_the_listens_instead_of_telling_them() {
    // Recorded on the official emulator (docs.local datarevoke-probe): the write that turns
    // the rule false reaches the listener as the cancellation, not as data.
    let mut db = db();
    load(
        &mut db,
        "dr",
        r#"{"rules":{"x":{".read":"data.child('ok').val() === true"},
            "y":{".read":"root.child('open').val() === true"},
            "z":{".read":"root.child('zopen').val() === true"}}}"#,
    );
    call(
        &mut db,
        "PUT",
        "/.json?ns=dr",
        OWNER,
        r#"{"open":true,"zopen":true,"x":{"ok":true,"v":1},"y":{"v":1},"z":{"v":1}}"#,
    );
    let mut listener = open(&mut db, "dr");
    let client = listener.client();
    for (r, path) in [(1, "/x"), (2, "/y"), (3, "/z")] {
        send(
            &mut db,
            &mut listener,
            r,
            "q",
            &format!(r#"{{"p":"{path}","h":""}}"#),
        );
    }
    let mut streams = Vec::new();
    for path in ["/x", "/y"] {
        match db.handle(
            &request(
                "GET",
                &format!("{path}.json?ns=dr"),
                &[("Accept", "text/event-stream")],
                "",
            ),
            NOW,
        ) {
            Handled::Stream { id, .. } => streams.push(id),
            Handled::Response { response, .. } => panic!("{response:?}"),
        }
    }
    pushes_to(&mut db, client);
    let cancel =
        |path: &str| format!(r#"{{"t":"d","d":{{"b":{{"p":"{path}","q":null}},"a":"c"}}}}"#);
    // A REST write inside the listened location.
    let (_, events) = respond(&mut db, "PUT", "/x/ok.json?ns=dr", OWNER, "false");
    assert_eq!(pushes_to(&mut db, client), vec![cancel("x")]);
    assert_eq!(events, vec![(streams[0], SseEvent::cancel())]);
    // A realtime write elsewhere.
    let mut writer = open(&mut db, "dr");
    send(&mut db, &mut writer, 1, "gauth", r#"{"cred":"owner"}"#);
    let mut events = Vec::new();
    let frame = r#"{"t":"d","d":{"r":2,"a":"p","b":{"p":"/open","d":false}}}"#;
    events.extend(writer.receive(&mut db, frame, NOW).events);
    assert_eq!(pushes_to(&mut db, client), vec![cancel("y")]);
    assert_eq!(events, vec![(streams[1], SseEvent::cancel())]);
    // An onDisconnect write.
    send(&mut db, &mut writer, 3, "o", r#"{"p":"/zopen","d":false}"#);
    db.close_realtime(writer.client(), LATER);
    assert_eq!(pushes_to(&mut db, client), vec![cancel("z")]);
    // Nothing more reaches the cancelled listens and streams.
    let (_, events) = respond(
        &mut db,
        "PATCH",
        "/.json?ns=dr",
        OWNER,
        r#"{"x/v":2,"y/v":2,"z/v":2}"#,
    );
    assert_eq!(pushes_to(&mut db, client), Vec::<String>::new());
    assert!(events.is_empty(), "{events:?}");
}

#[test]
fn a_refused_gauth_signs_the_connection_out_under_strict() {
    let rules = r#"{"rules":{"users":{"$uid":{".read":"auth != null && auth.uid === $uid"}},"anon":{".read":"auth == null"}}}"#;
    let good = token(r#"{"sub":"ok-1","iat":1}"#);
    let mut db = with_credentials(true, true);
    load(&mut db, "demo-default-rtdb", rules);
    let mut session = open(&mut db, "demo-default-rtdb");
    let client = session.client();
    // Signed in as the owner, then as a user, each refused gauth signs the connection out.
    send(&mut db, &mut session, 1, "gauth", r#"{"cred":"owner"}"#);
    let unparsable = |r| reply(r, "invalid_token", r#""Could not parse auth token.""#);
    assert_eq!(
        send(&mut db, &mut session, 2, "gauth", r#"{"cred":"ya29.x"}"#),
        vec![reply(2, "permission_denied", r#""Permission denied""#)]
    );
    assert_eq!(
        send(&mut db, &mut session, 3, "g", r#"{"p":"/anon"}"#),
        vec![reply(3, "ok", "null")]
    );
    send(
        &mut db,
        &mut session,
        4,
        "auth",
        &format!(r#"{{"cred":"{good}"}}"#),
    );
    send(
        &mut db,
        &mut session,
        5,
        "q",
        r#"{"p":"/users/ok-1","h":""}"#,
    );
    pushes_to(&mut db, client);
    let cancel = r#"{"t":"d","d":{"b":{"p":"users/ok-1","q":null},"a":"c"}}"#.to_owned();
    assert_eq!(
        send(&mut db, &mut session, 6, "gauth", r#"{"cred":7}"#),
        vec![cancel, unparsable(6)]
    );
    assert_eq!(
        send(&mut db, &mut session, 7, "g", r#"{"p":"/users/ok-1"}"#),
        vec![refused(7)]
    );
}

#[test]
fn a_refused_token_signs_the_connection_out_under_strict_only() {
    // The official emulator keeps the user after a refused token (docs.local reauth-probe).
    let rules = r#"{"rules":{"users":{"$uid":{".read":"auth != null && auth.uid === $uid"}},"anon":{".read":"auth == null"}}}"#;
    let good = token(r#"{"sub":"ok-1","iat":1}"#);
    for strict in [false, true] {
        let mut db = with_credentials(strict, true);
        load(&mut db, "demo-default-rtdb", rules);
        let mut session = open(&mut db, "demo-default-rtdb");
        let client = session.client();
        send(
            &mut db,
            &mut session,
            1,
            "auth",
            &format!(r#"{{"cred":"{good}"}}"#),
        );
        send(
            &mut db,
            &mut session,
            2,
            "q",
            r#"{"p":"/users/ok-1","h":""}"#,
        );
        pushes_to(&mut db, client);
        let refused_token = send(&mut db, &mut session, 3, "auth", r#"{"cred":"garbage"}"#);
        let own = send(&mut db, &mut session, 4, "g", r#"{"p":"/users/ok-1"}"#);
        let anon = send(&mut db, &mut session, 5, "g", r#"{"p":"/anon"}"#);
        let unparsable = reply(3, "invalid_token", r#""Could not parse auth token.""#);
        if strict {
            let cancel = r#"{"t":"d","d":{"b":{"p":"users/ok-1","q":null},"a":"c"}}"#.to_owned();
            assert_eq!(refused_token, vec![cancel, unparsable]);
            assert_eq!(own, vec![refused(4)]);
            assert_eq!(anon, vec![reply(5, "ok", "null")]);
        } else {
            assert_eq!(refused_token, vec![unparsable]);
            assert_eq!(own, vec![reply(4, "ok", "null")]);
            assert_eq!(anon, vec![refused(5)]);
        }
    }
}

#[test]
fn the_rules_come_before_the_index() {
    // Recorded on the official emulator (docs.local indexorder-probe).
    let mut db = db();
    load(
        &mut db,
        "io",
        r#"{"rules":{"q":{".read":false},"o":{".read":true}}}"#,
    );
    call(
        &mut db,
        "PUT",
        "/.json?ns=io",
        OWNER,
        r#"{"q":{"a":{"n":1}},"o":{"a":{"n":1}}}"#,
    );
    assert_eq!(
        call(&mut db, "GET", "/q.json?ns=io&orderBy=\"n\"", &[], ""),
        (401, denied())
    );
    assert_eq!(
        call(&mut db, "GET", "/o.json?ns=io&orderBy=\"n\"", &[], "").0,
        400
    );
    let mut session = open(&mut db, "io");
    assert_eq!(
        send(&mut db, &mut session, 1, "g", r#"{"p":"/q","q":{"i":"n"}}"#),
        vec![refused(1)]
    );
    assert_eq!(
        send(
            &mut db,
            &mut session,
            2,
            "q",
            r#"{"p":"/q","q":{"i":"n","l":1,"vf":"l"},"t":1,"h":""}"#
        ),
        vec![refused(2)]
    );
    let no_index = send(&mut db, &mut session, 3, "g", r#"{"p":"/o","q":{"i":"n"}}"#);
    assert!(no_index[0].contains(r#""s":"no_index""#), "{no_index:?}");
}

#[test]
fn a_long_chain_loads_and_is_evaluated_on_a_worker_stack() {
    // The official emulator loads chains of 5,000 operands.
    on_worker_stack(|| {
        let mut db = db();
        for (rule, status) in [
            (vec!["auth == null"; 5_000].join(" && "), 200),
            (vec!["auth != null"; 5_000].join(" || "), 401),
        ] {
            let body = format!(r#"{{"rules":{{".read":"{rule}"}}}}"#);
            assert_eq!(
                call(&mut db, "PUT", "/.settings/rules.json?ns=ch", OWNER, &body).0,
                200
            );
            assert_eq!(call(&mut db, "GET", "/.json?ns=ch", &[], "").0, status);
        }
    });
}

#[test]
fn a_restore_or_a_reset_cancels_the_reads_its_data_no_longer_allows() {
    // Review r9 M27: a session snapshot restore or a reset changes the data under open reads
    // as a write does, so the reads the rules no longer allow are cancelled before any data
    // is sent (the official emulator has no snapshots; this follows its writes).
    for reset in [false, true] {
        let mut db = db();
        let clock_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reads = clock_reads.clone();
        db.set_clock(std::sync::Arc::new(move || {
            reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            LATER
        }));
        load(
            &mut db,
            "dr",
            r#"{"rules":{"doc":{".read":"data.child('open').val() == true && now < 1792464734000"}}}"#,
        );
        call(
            &mut db,
            "PUT",
            "/.json?ns=dr",
            OWNER,
            r#"{"doc":{"open":false,"secret":"HIDDEN"}}"#,
        );
        let snapshot = db.capture_namespaces_where(|ns| ns == "dr");
        call(
            &mut db,
            "PUT",
            "/.json?ns=dr",
            OWNER,
            r#"{"doc":{"open":true,"secret":"visible"}}"#,
        );
        let mut listener = open(&mut db, "dr");
        let client = listener.client();
        send(&mut db, &mut listener, 1, "q", r#"{"p":"/doc","h":""}"#);
        let stream = match db.handle(
            &request(
                "GET",
                "/doc.json?ns=dr",
                &[("Accept", "text/event-stream")],
                "",
            ),
            NOW,
        ) {
            Handled::Stream { id, .. } => id,
            Handled::Response { response, .. } => panic!("{response:?}"),
        };
        pushes_to(&mut db, client);
        db.drain_events();
        let before = clock_reads.load(std::sync::atomic::Ordering::SeqCst);
        if reset {
            db.clear_namespaces_where(|ns| ns == "dr");
        } else {
            db.restore_namespaces_where(|ns| ns == "dr", &snapshot);
        }
        assert!(clock_reads.load(std::sync::atomic::Ordering::SeqCst) > before);
        assert_eq!(
            pushes_to(&mut db, client),
            vec![r#"{"t":"d","d":{"b":{"p":"doc","q":null},"a":"c"}}"#.to_owned()],
            "reset {reset}"
        );
        assert_eq!(
            db.drain_events(),
            vec![(stream, SseEvent::cancel())],
            "reset {reset}"
        );
    }
}

#[test]
fn a_write_has_no_key_ordering() {
    // Review r9 M24, recorded on the official emulator: `query.orderByKey` is true for a read
    // without a query and false in `.write` and `.validate`, over REST and the realtime
    // protocol, onDisconnect writes included.
    let user = format!("auth={}", token(r#"{"sub":"u1","uid":"u1","iat":1}"#));
    for (rules, allowed) in [
        (
            r#"{"rules":{".read":true,".write":"query.orderByKey"}}"#,
            false,
        ),
        (
            r#"{"rules":{".read":true,".write":"!query.orderByKey"}}"#,
            true,
        ),
        (
            r#"{"rules":{".read":true,".write":"query.orderByKey == false"}}"#,
            true,
        ),
        (
            r#"{"rules":{".read":true,".write":true,".validate":"query.orderByKey"}}"#,
            false,
        ),
        (
            r#"{"rules":{".read":true,".write":true,".validate":"!query.orderByKey"}}"#,
            true,
        ),
        (r#"{"rules":{".read":"query.orderByKey"}}"#, true),
    ] {
        let mut db = db();
        load(&mut db, "ok", rules);
        let reading = rules.contains(r#"".read":"query"#);
        let expected = if allowed { 200 } else { 401 };
        if reading {
            assert_eq!(
                call(&mut db, "GET", "/a.json?ns=ok", &[], "").0,
                expected,
                "{rules}"
            );
            continue;
        }
        for credential in ["", user.as_str()] {
            let target = format!("/a.json?ns=ok&{credential}");
            assert_eq!(
                call(&mut db, "PUT", &target, &[], "1").0,
                expected,
                "{rules}"
            );
        }
        let mut session = open(&mut db, "ok");
        let status = if allowed { "ok" } else { "permission_denied" };
        assert!(
            send(&mut db, &mut session, 1, "p", r#"{"p":"/b","d":1}"#)
                .iter()
                .any(|frame| frame.contains(&format!(r#""s":"{status}""#))),
            "{rules}"
        );
        assert!(
            send(&mut db, &mut session, 2, "o", r#"{"p":"/c","d":1}"#)
                .iter()
                .any(|frame| frame.contains(&format!(r#""s":"{status}""#))),
            "{rules}"
        );
    }
}

#[test]
fn the_database_debug_says_whether_a_server_clock_is_set() {
    let mut db = db();
    assert!(format!("{db:?}").contains("ServerClock(system)"));
    db.set_clock(std::sync::Arc::new(|| NOW));
    assert!(format!("{db:?}").contains("ServerClock(set)"));
}

#[test]
fn a_read_without_a_query_is_ordered_as_its_kind_is_read() {
    // Review r10 M32 and the r11 read-kind probes, recorded on the official emulator: a REST
    // GET without a query is ordered by key, an event stream and every realtime read (a listen,
    // a `get`) by priority, and the read a transaction or a conditional REST write checks not
    // at all.
    for (rule, get, stream, check) in [
        ("query.orderByKey", true, false, false),
        ("!query.orderByKey", false, true, true),
        ("query.orderByPriority", false, true, false),
        (
            "!query.orderByPriority && !query.orderByValue",
            true,
            false,
            true,
        ),
    ] {
        let mut db = db();
        load(
            &mut db,
            "rk",
            &format!(r#"{{"rules":{{".read":"{rule}",".write":true}}}}"#),
        );
        call(&mut db, "PUT", "/a.json?ns=rk", OWNER, "1");
        let expect = |allowed: bool| if allowed { 200 } else { 401 };
        assert_eq!(
            call(&mut db, "GET", "/a.json?ns=rk", &[], "").0,
            expect(get),
            "{rule} GET"
        );
        let streamed = match db.handle(
            &request(
                "GET",
                "/a.json?ns=rk",
                &[("Accept", "text/event-stream")],
                "",
            ),
            NOW,
        ) {
            Handled::Stream { .. } => true,
            Handled::Response { .. } => false,
        };
        assert_eq!(streamed, stream, "{rule} stream");
        let mut session = open(&mut db, "rk");
        let status = |allowed: bool| {
            if allowed {
                r#""s":"ok""#
            } else {
                r#""s":"permission_denied""#
            }
        };
        let listened = send(&mut db, &mut session, 1, "q", r#"{"p":"/a","h":""}"#);
        assert!(
            listened.iter().any(|f| f.contains(status(stream))),
            "{rule} listen {listened:?}"
        );
        let got = send(&mut db, &mut session, 2, "g", r#"{"p":"/a","q":{}}"#);
        assert!(
            got.iter().any(|f| f.contains(status(stream))),
            "{rule} get {got:?}"
        );
        let transaction = send(&mut db, &mut session, 3, "p", r#"{"p":"/a","d":2,"h":"x"}"#);
        let denied = transaction.iter().any(|f| f.contains("permission_denied"));
        assert_eq!(!denied, check, "{rule} transaction {transaction:?}");
        let conditional = call(&mut db, "PUT", "/a.json?ns=rk", &[("if-match", "x")], "3").0;
        assert_eq!(
            conditional != 401,
            check,
            "{rule} conditional {conditional}"
        );
    }
}

#[test]
fn get_priority_answers_a_string_priority() {
    // The r10 review's seed (`c` with priority `'p'`), recorded on the official emulator.
    let mut db = db();
    load(
        &mut db,
        "gp",
        r#"{"rules":{"c":{".read":"data.getPriority() == 'p' && data.child('.priority').val() == 'p'"}}}"#,
    );
    call(
        &mut db,
        "PUT",
        "/c.json?ns=gp",
        OWNER,
        r#"{".value":1,".priority":"p"}"#,
    );
    assert_eq!(call(&mut db, "GET", "/c.json?ns=gp", &[], "").0, 200);
}

#[test]
fn a_remote_peer_is_refused_the_rules_route_however_its_path_is_written() {
    // Review r11 M34: the refusal follows the router's own reading of the path, so no
    // spelling of the rules route reaches it from another host, under any profile and with
    // any credential; data and the other routes stay served.
    use fireemu_adapter_database::rest::{Credentials, Peer};
    let strict = || Credentials {
        strict: true,
        id_tokens: None,
    };
    for (profile, credentials, rules) in [
        ("emulator", Credentials::default(), RulesMode::AllowAll),
        ("strict", strict(), RulesMode::AllowAll),
        ("strict locked", strict(), RulesMode::DenyAll),
    ] {
        let mut db = Database::new(
            RestOptions {
                credentials,
                rules,
                ..RestOptions::default()
            },
            7,
        );
        for target in [
            "/.settings/rules.json?ns=r",
            "//.settings/rules.json?ns=r",
            "///.settings/rules.json?ns=r",
            "/%2Esettings/rules.json?ns=r",
            "/%2esettings/rules.json?ns=r",
            "/.settings/rules?ns=r",
            "/.settings?ns=r",
        ] {
            for (method, body) in [("GET", ""), ("PUT", r#"{"rules":{".read":true}}"#)] {
                for credential in [&[("Authorization", "Bearer owner")][..], &[]] {
                    let request = request(method, target, credential, body);
                    let Handled::Response { response, .. } =
                        db.handle_from(&request, None, NOW, Peer::Remote)
                    else {
                        panic!("stream")
                    };
                    let text = String::from_utf8(response.body).unwrap();
                    assert_eq!(response.status, 403, "{profile} {method} {target}: {text}");
                    assert!(
                        text.contains("this route answers loopback peers only"),
                        "{text}"
                    );
                }
            }
        }
        // Dot segments are not collapsed: the router reads them as the keys they spell, which
        // no path accepts, from any peer. An encoded slash decodes to the rules route.
        for (target, remote_status) in [
            ("/./.settings/rules.json?ns=r", 400),
            ("/../.settings/rules.json?ns=r", 400),
            ("/x/../.settings/rules.json?ns=r", 400),
            ("/%2E/.settings/rules.json?ns=r", 400),
            ("/%2F.settings/rules.json?ns=r", 403),
        ] {
            for peer in [Peer::Remote, Peer::Loopback] {
                let request = request("GET", target, OWNER, "");
                let Handled::Response { response, .. } = db.handle_from(&request, None, NOW, peer)
                else {
                    panic!("stream")
                };
                let text = String::from_utf8(response.body).unwrap();
                if remote_status == 400 || peer == Peer::Remote {
                    assert_eq!(response.status, remote_status, "{profile} {target}: {text}");
                }
                assert!(!text.contains(".read"), "{profile} {target}: {text}");
            }
        }
        for target in [
            "/.json?ns=r",
            "/a/.settings.json?ns=r",
            "/settings/rules.json?ns=r",
        ] {
            let request = request("GET", target, OWNER, "");
            let Handled::Response { response, .. } =
                db.handle_from(&request, None, NOW, Peer::Remote)
            else {
                panic!("stream")
            };
            assert_ne!(response.status, 403, "{profile} {target}");
        }
        let local = request("GET", "//.settings/rules.json?ns=r", OWNER, "");
        let Handled::Response { response, .. } = db.handle_from(&local, None, NOW, Peer::Loopback)
        else {
            panic!("stream")
        };
        assert_eq!(response.status, 200, "{profile} loopback");
    }
}

#[test]
fn an_ambiguous_request_is_refused() {
    // Review r11 M35/M36 and ruling 18: the official emulator takes the first of a repeated
    // parameter and prefers `auth` among credentials; a request that could mean two things is
    // refused here, before the rules (a listed difference).
    let mut db = db();
    load(&mut db, "am", r#"{"rules":{".read":"auth.uid == 'u2'"}}"#);
    let one = format!("auth={}", token(r#"{"sub":"u1","uid":"u1","iat":1}"#));
    let two = format!("auth={}", token(r#"{"sub":"u2","uid":"u2","iat":1}"#));
    for (target, headers) in [
        (format!("/a.json?ns=am&{one}&{two}"), &[][..]),
        (format!("/a.json?ns=am&{two}&access_token=x"), &[][..]),
        (
            format!("/a.json?ns=am&{two}"),
            &[("Authorization", "Bearer x")][..],
        ),
        (
            "/a.json?ns=am&access_token=x".to_owned(),
            &[("Authorization", "Bearer owner")][..],
        ),
        ("/a.json?ns=am&ns=am".to_owned(), &[][..]),
        (
            "/a.json?ns=am&orderBy=%22$key%22&orderBy=%22$key%22".to_owned(),
            &[][..],
        ),
        (
            "/a.json?ns=am&print=pretty&print=silent".to_owned(),
            &[][..],
        ),
    ] {
        for method in ["GET", "PUT"] {
            let (status, body) = call(&mut db, method, &target, headers, "1");
            assert_eq!(status, 400, "{method} {target}: {body}");
            assert!(body.contains("Ambiguous request"), "{body}");
        }
    }
    // One credential, one of each parameter: served.
    assert_eq!(
        call(&mut db, "GET", &format!("/a.json?ns=am&{two}"), &[], "").0,
        200
    );
}

#[test]
fn repeated_authorization_headers_are_ambiguous_in_every_profile() {
    use fireemu_adapter_database::rest::Credentials;
    let mut failures = Vec::new();
    for (profile, strict, rules) in [
        ("emulator", false, RulesMode::AllowAll),
        ("strict", true, RulesMode::AllowAll),
        ("productionExact", true, RulesMode::DenyAll),
    ] {
        let mut db = Database::new(
            RestOptions {
                credentials: Credentials {
                    strict,
                    id_tokens: None,
                },
                rules,
                ..RestOptions::default()
            },
            7,
        );
        for headers in [
            [
                ("Authorization", "Bearer owner"),
                ("Authorization", "Bearer other"),
            ],
            [
                ("authorization", "Bearer other"),
                ("AUTHORIZATION", "Bearer owner"),
            ],
            [
                ("Authorization", "Bearer owner"),
                ("authorization", "Bearer owner"),
            ],
        ] {
            for method in ["GET", "PUT"] {
                let (status, body) = call(&mut db, method, "/a.json?ns=dupauth", &headers, "1");
                if status != 400 || !body.contains("Ambiguous request") {
                    failures.push(format!("{profile} {method} {headers:?}: {status} {body}"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

proptest::proptest! {
    #[test]
    fn authorization_multiplicity_does_not_depend_on_header_case(
        cases in proptest::collection::vec(proptest::bool::ANY, 0..10),
        writing in proptest::bool::ANY,
    ) {
        let mut db = db();
        let headers: Vec<_> = cases.iter().map(|upper| {
            (if *upper { "AUTHORIZATION" } else { "authorization" }, "Bearer owner")
        }).collect();
        let method = if writing { "PUT" } else { "GET" };
        let (status, body) = call(&mut db, method, "/a.json?ns=authproperty", &headers, "1");
        proptest::prop_assert_eq!(status, if cases.len() > 1 { 400 } else { 200 }, "{}", body);
    }
}

#[test]
fn a_stream_is_judged_without_its_query_and_a_shallow_read_unordered() {
    // Review r11 M37 and M38, recorded on the official emulator: an event stream's rules see
    // the stream kind's `query` whatever its URL asks for, and a `shallow` GET has no ordering.
    for (rule, stream_allowed, shallow_allowed) in [
        ("query.orderByPriority", true, false),
        ("query.orderByKey", false, false),
        ("query.orderByChild == 'm'", false, false),
        (
            "query.orderByChild == null && !query.orderByKey",
            true,
            true,
        ),
    ] {
        let mut db = db();
        load(
            &mut db,
            "sq",
            &format!(r#"{{"rules":{{".read":"{rule}","a":{{".indexOn":["m"]}}}}}}"#),
        );
        call(&mut db, "PUT", "/a.json?ns=sq", OWNER, r#"{"x":{"m":1}}"#);
        for target in [
            "/a.json?ns=sq&orderBy=%22m%22",
            "/a.json?ns=sq&orderBy=%22$key%22",
        ] {
            let streamed = matches!(
                db.handle(
                    &request("GET", target, &[("Accept", "text/event-stream")], ""),
                    NOW
                ),
                Handled::Stream { .. }
            );
            assert_eq!(streamed, stream_allowed, "{rule} {target}");
        }
        let status = call(&mut db, "GET", "/a.json?ns=sq&shallow=true", &[], "").0;
        assert_eq!(status == 200, shallow_allowed, "{rule} shallow");
    }
}

#[test]
fn a_stream_with_a_filtered_query_is_judged_with_it_and_one_loading_everything_is_not() {
    // Recorded on the official emulator (r12 hand5 rerun): an event stream whose query
    // bounds or limits its window is judged with that query, as a GET is, while one that
    // only orders loads all the data and is a plain stream: judged without its query and
    // needing no index.
    for (rule, filtered_allowed) in [
        ("query.orderByChild == 'm' && query.startAt == 1", true),
        ("query.limitToFirst == 2", true),
        ("query.orderByPriority", false),
        ("query.orderByChild == null", false),
    ] {
        let mut db = db();
        load(
            &mut db,
            "sf",
            &format!(r#"{{"rules":{{".read":"{rule}","a":{{".indexOn":["m"]}}}}}}"#),
        );
        call(&mut db, "PUT", "/a.json?ns=sf", OWNER, r#"{"x":{"m":1}}"#);
        let streamed = matches!(
            db.handle(
                &request(
                    "GET",
                    "/a.json?ns=sf&orderBy=%22m%22&startAt=1&limitToFirst=2",
                    &[("Accept", "text/event-stream")],
                    ""
                ),
                NOW
            ),
            Handled::Stream { .. }
        );
        assert_eq!(streamed, filtered_allowed, "{rule}");
    }
    let mut db = db();
    load(
        &mut db,
        "sv",
        r#"{"rules":{".read":"query.orderByPriority"}}"#,
    );
    call(&mut db, "PUT", "/a.json?ns=sv", OWNER, r#"{"x":1}"#);
    assert!(matches!(
        db.handle(
            &request(
                "GET",
                "/a.json?ns=sv&orderBy=%22$value%22",
                &[("Accept", "text/event-stream")],
                ""
            ),
            NOW
        ),
        Handled::Stream { .. }
    ));
    load(&mut db, "sv", r#"{"rules":{".read":true}}"#);
    assert!(!matches!(
        db.handle(
            &request(
                "GET",
                "/a.json?ns=sv&orderBy=%22$value%22&limitToFirst=1",
                &[("Accept", "text/event-stream")],
                ""
            ),
            NOW
        ),
        Handled::Stream { .. }
    ));
}

#[test]
fn an_on_disconnect_merge_is_judged_as_its_entries_when_registered() {
    // Review r11 M39, recorded on the official emulator: each entry of an onDisconnect merge
    // is judged as a set on the current tree, and the registration fails if any fails, so a
    // rule reading a sibling the merge also writes sees the sibling as it is now.
    let mut db = db();
    load(
        &mut db,
        "odm",
        r#"{"rules":{".read":true,"t":{"$k":{".write":true,".validate":"newData.child('a').val() == newData.child('b').val()"}}}}"#,
    );
    call(
        &mut db,
        "PUT",
        "/t/o.json?ns=odm",
        OWNER,
        r#"{"a":1,"b":2}"#,
    );
    let mut session = open(&mut db, "odm");
    assert_eq!(
        send(
            &mut db,
            &mut session,
            1,
            "om",
            r#"{"p":"/t/o","d":{"a":5,"b":5}}"#
        ),
        vec![refused(1)]
    );
    // Every entry is judged, not the first alone: `a` set to 2 passes on the current tree,
    // `b` set to 2 does not.
    assert_eq!(
        send(
            &mut db,
            &mut session,
            2,
            "om",
            r#"{"p":"/t/o","d":{"a":2,"b":2}}"#
        ),
        vec![refused(2)]
    );
    // A plain merge is one update, judged on its result, on both servers.
    assert_eq!(
        send(
            &mut db,
            &mut session,
            3,
            "m",
            r#"{"p":"/t/o","d":{"a":5,"b":5}}"#
        ),
        vec![reply(3, "ok", r#""""#)]
    );
}

#[test]
fn an_on_disconnect_update_that_fails_whole_makes_none_of_the_writes() {
    // Recorded on the official emulator (r12 table odmix, hand3): each registered value
    // passes alone, so all register, but made together the merge fails the rule at `o`, and
    // then none of them is made, not even the set at `p`, in either order and whether the
    // rule is `.validate` or `.write`.
    let rule = "!(newData.child('a').val() == newData.child('b').val())";
    for place in [
        format!(r#"".write":true,".validate":"{rule}""#),
        format!(r#"".write":"{rule}""#),
    ] {
        for order in [["om", "o"], ["o", "om"]] {
            let mut db = db();
            load(
                &mut db,
                "odu",
                &format!(r#"{{"rules":{{".read":true,"t":{{"$k":{{{place}}}}}}}}}"#),
            );
            call(
                &mut db,
                "PUT",
                "/t.json?ns=odu",
                OWNER,
                r#"{"o":{"a":1,"b":2},"p":{"a":1,"b":2}}"#,
            );
            let mut session = open(&mut db, "odu");
            for (r, action) in (1..).zip(order) {
                let body = if action == "om" {
                    r#"{"p":"/t/o","d":{"a":5,"b":5}}"#
                } else {
                    r#"{"p":"/t/p/a","d":7}"#
                };
                assert_eq!(
                    send(&mut db, &mut session, r, action, body),
                    vec![reply(r, "ok", r#""""#)],
                    "{place} {order:?}"
                );
            }
            db.close_realtime(session.client(), LATER);
            assert_eq!(
                call(&mut db, "GET", "/t.json?ns=odu", OWNER, "").1,
                r#"{"o":{"a":1,"b":2},"p":{"a":1,"b":2}}"#,
                "{place} {order:?}"
            );
        }
    }
}

#[test]
fn an_on_disconnect_write_its_rules_now_deny_alone_is_dropped() {
    // Recorded on the official emulator (r12 table odmix2): a gate shut after registration
    // makes the value at `o` fail alone, by `.validate` or by `.write`, so it is dropped and
    // the value at `p` is made, whether they were two sets or one merge.
    let gate = "root.child('gate').child($k).val() != 'shut'";
    for place in [
        format!(r#"".write":true,".validate":"{gate}""#),
        format!(r#"".write":"{gate}""#),
    ] {
        for registered in [
            vec![
                ("o", r#"{"p":"/t/o/a","d":3}"#),
                ("o", r#"{"p":"/t/p/a","d":4}"#),
            ],
            vec![("om", r#"{"p":"/t","d":{"o/a":3,"p/a":4}}"#)],
        ] {
            let mut db = db();
            load(
                &mut db,
                "odg",
                &format!(r#"{{"rules":{{".read":true,"t":{{"$k":{{{place}}}}}}}}}"#),
            );
            call(
                &mut db,
                "PUT",
                "/t.json?ns=odg",
                OWNER,
                r#"{"o":{"a":1},"p":{"a":1}}"#,
            );
            let mut session = open(&mut db, "odg");
            for (r, (action, body)) in (1..).zip(&registered) {
                assert_eq!(
                    send(&mut db, &mut session, r, action, body),
                    vec![reply(r, "ok", r#""""#)]
                );
            }
            call(&mut db, "PUT", "/gate/o.json?ns=odg", OWNER, r#""shut""#);
            db.close_realtime(session.client(), LATER);
            assert_eq!(
                call(&mut db, "GET", "/t.json?ns=odg", OWNER, "").1,
                r#"{"o":{"a":1},"p":{"a":4}}"#,
                "{place} {registered:?}"
            );
        }
    }
}

#[test]
fn on_disconnect_writes_run_as_one_update_validated_whole() {
    // Recorded on the official emulator (gen11 seed 1201 rows 1760 and 2288, r12; hand3):
    // when the connection ends, the values that pass alone are made as one update judged
    // whole, so a child that fails `.validate` or `.write` there stops all of them, deletes
    // included.
    for (rules, merge) in [
        (
            r#"{"rules":{".read":true,"t":{"$k":{".write":true,"$c":{".validate":"newData.parent().child('a').exists()"}}}}}"#,
            r#"{"p":"/t/o","d":{"a":null,"x":1}}"#,
        ),
        (
            r#"{"rules":{".read":true,"t":{"$k":{".write":"!(newData.child('a').val() == newData.child('b').val())"}}}}"#,
            r#"{"p":"/t/o","d":{"a":5,"b":5}}"#,
        ),
    ] {
        let mut db = db();
        load(&mut db, "odw", rules);
        call(
            &mut db,
            "PUT",
            "/t.json?ns=odw",
            OWNER,
            r#"{"o":{"a":1,"b":2}}"#,
        );
        let mut session = open(&mut db, "odw");
        assert_eq!(
            send(&mut db, &mut session, 1, "om", merge),
            vec![reply(1, "ok", r#""""#)],
            "{rules}"
        );
        db.close_realtime(session.client(), LATER);
        assert_eq!(
            call(&mut db, "GET", "/t.json?ns=odw", OWNER, "").1,
            r#"{"o":{"a":1,"b":2}}"#,
            "{rules}"
        );
    }
}

#[test]
fn a_rules_change_judges_an_event_stream_with_the_query_it_follows() {
    // An event stream with a filtered query stays open after a rules change that allows that
    // query, and is cancelled by one that does not (review r11 M37).
    let mut db = db();
    let rules = r#"{"rules":{".read":"query.limitToFirst == 2","a":{".indexOn":["m"]}}}"#;
    load(&mut db, "eq", rules);
    call(&mut db, "PUT", "/a.json?ns=eq", OWNER, r#"{"x":{"m":1}}"#);
    let Handled::Stream { id, .. } = db.handle(
        &request(
            "GET",
            "/a.json?ns=eq&orderBy=%22m%22&limitToFirst=2",
            &[("Accept", "text/event-stream")],
            "",
        ),
        NOW,
    ) else {
        panic!("not streamed");
    };
    assert!(load(&mut db, "eq", rules).is_empty());
    let events = load(
        &mut db,
        "eq",
        r#"{"rules":{".read":"query.limitToFirst == 3","a":{".indexOn":["m"]}}}"#,
    );
    assert_eq!(events.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![id]);
}

#[test]
fn a_priority_written_through_its_path_is_no_number_to_order_or_add() {
    // Review r11 M40, recorded on the official emulator: a priority written through a
    // `.priority` path equals its number, but `<`, `>`, `+` and `-` fail on it, in the write
    // and in later reads; one written inside an object body is a number.
    for (rule, path_write, body_write) in [
        ("newData.getPriority() > 1", false, true),
        ("newData.getPriority() - 5 == 0", false, true),
        ("newData.getPriority() + '' == '5'", false, true),
        ("newData.getPriority() == 5", true, true),
        ("newData.getPriority() === 5", true, true),
        ("newData.child('.priority').val() > 1", true, true),
    ] {
        let mut db = db();
        load(
            &mut db,
            "pp",
            &format!(
                r#"{{"rules":{{".read":true,"t":{{"$k":{{".write":true,".validate":"{rule}"}}}}}}}}"#
            ),
        );
        call(&mut db, "PUT", "/t/o.json?ns=pp", OWNER, r#"{"a":1}"#);
        let expect = |allowed: bool| if allowed { 200 } else { 401 };
        assert_eq!(
            call(&mut db, "PUT", "/t/o/.priority.json?ns=pp", &[], "5").0,
            expect(path_write),
            "{rule} path"
        );
        assert_eq!(
            call(
                &mut db,
                "PUT",
                "/t/o.json?ns=pp",
                &[],
                r#"{"a":1,".priority":5}"#
            )
            .0,
            expect(body_write),
            "{rule} body"
        );
    }
    let mut db = db();
    load(
        &mut db,
        "pr",
        r#"{"rules":{".read":"data.getPriority() > 1"}}"#,
    );
    call(&mut db, "PUT", "/a.json?ns=pr", OWNER, "1");
    call(&mut db, "PUT", "/.priority.json?ns=pr", OWNER, "5");
    assert_eq!(call(&mut db, "GET", "/.json?ns=pr", &[], "").0, 401);
    // A fresh database: an equal value written over it would keep the stored form.
    let mut db = self::db();
    load(
        &mut db,
        "pr",
        r#"{"rules":{".read":"data.getPriority() > 1"}}"#,
    );
    call(
        &mut db,
        "PUT",
        "/.json?ns=pr",
        OWNER,
        r#"{"a":1,".priority":5}"#,
    );
    assert_eq!(call(&mut db, "GET", "/.json?ns=pr", &[], "").0, 200);
}

#[test]
fn a_realtime_query_with_an_unknown_or_malformed_field_is_refused() {
    // Review r11 M42, recorded on the official emulator: an unknown query field and a
    // non-boolean inclusive flag are errors there; a limit without a known side is read
    // otherwise there and refused here (a listed difference). The SDK's own forms are served.
    let mut db = db();
    load(
        &mut db,
        "wq",
        r#"{"rules":{".read":true,"a":{".indexOn":["m"]}}}"#,
    );
    call(&mut db, "PUT", "/a.json?ns=wq", OWNER, r#"{"x":{"m":1}}"#);
    for (r, query, served) in [
        (1, r#"{"i":"m","l":2,"vf":"l"}"#, true),
        (2, r#"{"i":"m","sp":1,"sin":true}"#, true),
        (3, r#"{"i":"m","l":2}"#, false),
        (4, r#"{"i":"m","l":2,"vf":"x"}"#, false),
        (5, r#"{"i":"m","sp":1,"sin":"b"}"#, false),
        (6, r#"{"i":"m","sp":1,"ein":1}"#, false),
        (7, r#"{"i":"m","zz":1}"#, false),
    ] {
        let mut session = open(&mut db, "wq");
        let frames = send(
            &mut db,
            &mut session,
            r,
            "q",
            &format!(r#"{{"p":"/a","q":{query},"t":{r},"h":""}}"#),
        );
        let ok = frames.iter().any(|f| f.contains(r#""s":"ok""#));
        assert_eq!(ok, served, "{query}: {frames:?}");
    }
}

#[test]
fn a_value_member_holding_an_object_is_refused() {
    // Review r11 S29, recorded on the official emulator.
    let mut db = db();
    for body in [
        r#"{".value":{"a":1},".priority":1}"#,
        r#"{".value":[1]}"#,
        r#"{"x":{".value":{"a":1}}}"#,
    ] {
        let (status, text) = call(&mut db, "PUT", "/a.json?ns=vo", OWNER, body);
        assert_eq!(status, 400, "{body}: {text}");
        assert!(
            text.contains("Invalid data; couldn't parse JSON object, array, or value."),
            "{text}"
        );
    }
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/a.json?ns=vo",
            OWNER,
            r#"{".value":1,".priority":1}"#
        )
        .0,
        200
    );
}

#[test]
fn orphan_realtime_query_fields_keep_their_wire_types() {
    // Recorded on the official emulator in r12/takeover/orphan-observe-v2: the field's type is checked even without its limit or bound. A string side without a limit and a null or string name without its bound are ignored, including an unknown side.
    let mut db = db();
    load(
        &mut db,
        "orphan",
        r#"{"rules":{".read":true,"a":{".indexOn":["m"]}}}"#,
    );
    let mut failures = Vec::new();
    for action in ["q", "g"] {
        for (query, malformed) in [
            (r#"{"i":"m","vf":0}"#, true),
            (r#"{"i":"m","vf":null}"#, true),
            (r#"{"i":"m","vf":true}"#, true),
            (r#"{"i":"m","vf":{}}"#, true),
            (r#"{"i":"m","vf":[]}"#, true),
            (r#"{"i":"m","sn":1}"#, true),
            (r#"{"i":"m","sn":true}"#, true),
            (r#"{"i":"m","sn":{}}"#, true),
            (r#"{"i":"m","sn":[]}"#, true),
            (r#"{"i":"m","en":1}"#, true),
            (r#"{"i":"m","en":true}"#, true),
            (r#"{"i":"m","en":{}}"#, true),
            (r#"{"i":"m","en":[]}"#, true),
            (r#"{"i":"m","vf":"l"}"#, false),
            (r#"{"i":"m","vf":"r"}"#, false),
            (r#"{"i":"m","vf":"x"}"#, false),
            (r#"{"i":"m","sn":null}"#, false),
            (r#"{"i":"m","sn":"a"}"#, false),
            (r#"{"i":"m","en":null}"#, false),
            (r#"{"i":"m","en":"a"}"#, false),
        ] {
            let mut session = open(&mut db, "orphan");
            let body = if action == "q" {
                format!(r#"{{"p":"/a","q":{query},"t":1,"h":""}}"#)
            } else {
                format!(r#"{{"p":"/a","q":{query}}}"#)
            };
            let frame = format!(r#"{{"t":"d","d":{{"r":1,"a":"{action}","b":{body}}}}}"#);
            let received = session.receive(&mut db, &frame, NOW);
            let frames: Vec<serde_json::Value> = received
                .replies
                .iter()
                .map(|r| serde_json::from_str(r).unwrap())
                .collect();
            let allowed = frames
                .iter()
                .any(|r| r["t"] == "d" && r["d"]["r"] == 1 && r["d"]["b"]["s"] == "ok");
            let errors: Vec<_> = frames
                .iter()
                .filter(|r| r["t"] == "c" && r["d"]["t"] == "e")
                .collect();
            let error_texts_match = errors.iter().all(|r| {
                r["d"]["d"].as_str().and_then(|text| {
                    let (client, error) =
                        text.strip_prefix("ClientId[")?.split_once("]:ErrorId[")?;
                    let error = error.strip_suffix("]: Error on incoming message")?;
                    Some(client.parse::<u64>().is_ok() && error.parse::<u64>().is_ok())
                }) == Some(true)
            });
            if errors.len() != usize::from(malformed)
                || !error_texts_match
                || allowed == malformed
                || received.drop_connection
                || received.close.is_some()
            {
                failures.push(format!("{action} {query}: {received:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

proptest::proptest! {
    #[test]
    fn malformed_wire_field_types_are_rejected_with_or_without_their_dependency(
        field in 0usize..3,
        value in 0usize..4,
        with_dependency in proptest::bool::ANY,
        get in proptest::bool::ANY,
    ) {
        let mut db = db();
        load(&mut db, "wireproperty", r#"{"rules":{".read":true,"a":{".indexOn":["m"]}}}"#);
        let name = ["vf", "sn", "en"][field];
        let value = ["0", "true", "{}", "[]"][value];
        let dependency = if with_dependency { [r#","l":2"#, r#","sp":1"#, r#","ep":1"#][field] } else { "" };
        let query = format!(r#"{{"i":"m","{name}":{value}{dependency}}}"#);
        let action = if get { "g" } else { "q" };
        let mut session = open(&mut db, "wireproperty");
        let frame = format!(r#"{{"t":"d","d":{{"r":1,"a":"{action}","b":{{"p":"/a","q":{query}}}}}}}"#);
        let received = session.receive(&mut db, &frame, NOW);
        proptest::prop_assert!(!received.drop_connection);
        proptest::prop_assert!(received.close.is_none());
        proptest::prop_assert_eq!(received.replies.len(), 1);
        let error: serde_json::Value = serde_json::from_str(&received.replies[0]).unwrap();
        proptest::prop_assert_eq!(&error["t"], "c");
        proptest::prop_assert_eq!(&error["d"]["t"], "e");
    }
}

proptest::proptest! {
    #[test]
    fn a_null_realtime_bound_name_is_the_absent_name(
        bound in -2i32..=2,
        start in proptest::bool::ANY,
        get in proptest::bool::ANY,
    ) {
        // The canonical q/g oracle tables accept null names with their bounds. Compare the reply and initial selected data, not just whether the request was authorized.
        let judge = |null_name: bool| {
            let mut database = db();
            load(&mut database, "nullname", r#"{"rules":{".read":true,"a":{".indexOn":["m"]}}}"#);
            call(&mut database, "PUT", "/a.json?ns=nullname", OWNER, r#"{"x":{"m":-1},"y":{"m":0},"z":{"m":1}}"#);
            let (value, name) = if start { ("sp", "sn") } else { ("ep", "en") };
            let name = if null_name { format!(r#","{name}":null"#) } else { String::new() };
            let query = format!(r#"{{"i":"m","{value}":{bound}{name}}}"#);
            let action = if get { "g" } else { "q" };
            let body = if get { format!(r#"{{"p":"/a","q":{query}}}"#) }
                else { format!(r#"{{"p":"/a","q":{query},"t":1,"h":""}}"#) };
            let mut session = open(&mut database, "nullname");
            let replies = send(&mut database, &mut session, 1, action, &body);
            let pushes = pushes_to(&mut database, session.client());
            (replies, pushes)
        };
        let absent = judge(false);
        proptest::prop_assert!(absent.0.iter().any(|reply| reply.contains(r#""s":"ok""#)));
        proptest::prop_assert_eq!(judge(true), absent);
    }
}

/// The finite Jar4.11.2 coverage observation, with only opaque object IDs normalized.
#[test]
fn coverage_replays_the_observed_compound_tree_and_primitive_histograms() {
    fn normalize(
        value: &mut serde_json::Value,
        identities: &mut std::collections::BTreeMap<String, String>,
    ) {
        match value {
            serde_json::Value::String(text) if text.starts_with("hash@") => {
                let next = identities.len();
                *text = identities
                    .entry(text.clone())
                    .or_insert_with(|| format!("hash@class{next}"))
                    .clone();
            }
            serde_json::Value::Array(items) => items
                .iter_mut()
                .for_each(|item| normalize(item, identities)),
            serde_json::Value::Object(items) => items
                .values_mut()
                .for_each(|item| normalize(item, identities)),
            _ => {}
        }
    }
    let steps: Vec<(String,String,String,bool,String,u16)> = serde_json::from_str(r#"[["unconfigured-a-json", "GET", "/.inspect/coverage.json?ns=demo-cv12-a", false, "", 200], ["unconfigured-b-json", "GET", "/.inspect/coverage.json?ns=demo-cv12-b", false, "", 200], ["empty-load", "PUT", "/.settings/rules.json?ns=demo-cv12-a", true, "{\"rules\":{}}\n", 200], ["empty-rules-readback", "GET", "/.settings/rules.json?ns=demo-cv12-a", true, "", 200], ["empty-before-json", "GET", "/.inspect/coverage.json?ns=demo-cv12-a", false, "", 200], ["empty-read-0", "GET", "/sample.json?ns=demo-cv12-a", false, "", 401], ["empty-write-0", "PUT", "/sample.json?ns=demo-cv12-a", false, "1", 401], ["empty-after-json", "GET", "/.inspect/coverage.json?ns=demo-cv12-a", false, "", 200], ["literal-load", "PUT", "/.settings/rules.json?ns=demo-cv12-a", true, "{\"rules\":{\".read\":true,\".write\":false}}\n", 200], ["literal-rules-readback", "GET", "/.settings/rules.json?ns=demo-cv12-a", true, "", 200], ["literal-before-json", "GET", "/.inspect/coverage.json?ns=demo-cv12-a", false, "", 200], ["literal-read-0", "GET", "/sample.json?ns=demo-cv12-a", false, "", 200], ["literal-write-0", "PUT", "/sample.json?ns=demo-cv12-a", false, "1", 401], ["literal-read-1", "GET", "/sample.json?ns=demo-cv12-a", false, "", 200], ["literal-write-1", "PUT", "/sample.json?ns=demo-cv12-a", false, "1", 401], ["literal-after-json", "GET", "/.inspect/coverage.json?ns=demo-cv12-a", false, "", 200], ["literal-repeat-json", "GET", "/.inspect/coverage.json?ns=demo-cv12-a", false, "", 200], ["owner-write", "PUT", "/sample.json?ns=demo-cv12-a", true, "2", 200], ["owner-read", "GET", "/sample.json?ns=demo-cv12-a", true, "", 200], ["owner-after-json", "GET", "/.inspect/coverage.json?ns=demo-cv12-a", false, "", 200], ["compound-load", "PUT", "/.settings/rules.json?ns=demo-cv12-a", true, "{\r\n  \"rules\": {\r\n    \".read\": \"true && (false || data.child(\\\"é😀\\\").exists())\",\r\n    \".write\": \"false && data.child(\\\"missing\\\").val().contains(\\\"x\\\")\",\r\n    \"allowed\": {\".read\":\"true || data.child(\\\"missing\\\").val().contains(\\\"x\\\")\", \".write\":true, \".validate\":\"newData.isString() && newData.val().length > 0\"},\r\n    \"denied\": {\".read\":false},\r\n    \"runtimeError\": {\".read\":\"data.child(\\\"missing\\\").val().contains(\\\"x\\\")\"}\r\n  }\r\n}\r\n", 200], ["compound-rules-readback", "GET", "/.settings/rules.json?ns=demo-cv12-a", true, "", 200], ["compound-before-json", "GET", "/.inspect/coverage.json?ns=demo-cv12-a", false, "", 200], ["compound-root-read", "GET", "/.json?ns=demo-cv12-a", false, "", 401], ["compound-root-write", "PUT", "/.json?ns=demo-cv12-a", false, "{\"x\":1}", 401], ["shortcircuit-read", "GET", "/allowed.json?ns=demo-cv12-a", false, "", 200], ["validate-write", "PUT", "/allowed.json?ns=demo-cv12-a", false, "\"observed\"", 200], ["validate-denied-write", "PUT", "/allowed.json?ns=demo-cv12-a", false, "0", 401], ["denied-read", "GET", "/denied.json?ns=demo-cv12-a", false, "", 401], ["runtime-error-read", "GET", "/runtimeError.json?ns=demo-cv12-a", false, "", 401], ["compound-after-json", "GET", "/.inspect/coverage.json?ns=demo-cv12-a", false, "", 200]]"#).unwrap();
    let expected: serde_json::Value = serde_json::from_str(r#"{"report":{".read":{"children":[{"location-end":"2:17","location-start":"2:14","text":"true","values":[{"count":4,"value":true}]},{"children":[{"location-end":"2:27","location-start":"2:23","text":"false","values":[{"count":4,"value":false}]},{"children":[{"children":[{"children":[{"children":[{"location-end":"2:35","location-start":"2:32","text":"data","values":[{"count":1,"value":"hash@class0"},{"count":1,"value":"hash@class1"},{"count":1,"value":"hash@class2"},{"count":1,"value":"hash@class3"}]},{"location-end":"2:41","location-start":"2:37","text":"child","values":[{"count":4,"value":"child"}]}],"location-end":"2:41","location-start":"2:32","text":"data.child","values":[{"count":1,"value":"hash@class4"},{"count":1,"value":"hash@class5"},{"count":1,"value":"hash@class6"},{"count":1,"value":"hash@class7"}]},{"location-end":"2:47","location-start":"2:43","text":"\"é😀\"","values":[{"count":4,"value":"é😀"}]}],"location-end":"2:48","location-start":"2:32","text":"data.child(\"é😀\")","values":[{"count":1,"value":"hash@class8"},{"count":1,"value":"hash@class9"},{"count":1,"value":"hash@class10"},{"count":1,"value":"hash@class11"}]},{"location-end":"2:55","location-start":"2:50","text":"exists","values":[{"count":4,"value":"exists"}]}],"location-end":"2:55","location-start":"2:32","text":"data.child(\"é😀\").exists","values":[{"count":1,"value":"hash@class12"},{"count":1,"value":"hash@class13"},{"count":1,"value":"hash@class14"},{"count":1,"value":"hash@class15"}]}],"location-end":"2:57","location-start":"2:32","text":"data.child(\"é😀\").exists()","values":[{"count":4,"value":false}]}],"location-end":"2:57","location-start":"2:23","text":"false || data.child(\"é😀\").exists()","values":[{"count":4,"value":false}]}],"location-end":"2:58","location-start":"2:14","text":"true && (false || data.child(\"é😀\").exists())","values":[{"count":4,"value":false}]},".write":{"children":[{"location-end":"3:19","location-start":"3:15","text":"false","values":[{"count":3,"value":false}]},{"children":[{"children":[{"children":[{"children":[{"children":[{"children":[{"location-end":"3:27","location-start":"3:24","text":"data","values":[]},{"location-end":"3:33","location-start":"3:29","text":"child","values":[]}],"location-end":"3:33","location-start":"3:24","text":"data.child","values":[]},{"location-end":"3:43","location-start":"3:35","text":"\"missing\"","values":[]}],"location-end":"3:44","location-start":"3:24","text":"data.child(\"missing\")","values":[]},{"location-end":"3:48","location-start":"3:46","text":"val","values":[]}],"location-end":"3:48","location-start":"3:24","text":"data.child(\"missing\").val","values":[]}],"location-end":"3:50","location-start":"3:24","text":"data.child(\"missing\").val()","values":[]},{"location-end":"3:59","location-start":"3:52","text":"contains","values":[]}],"location-end":"3:59","location-start":"3:24","text":"data.child(\"missing\").val().contains","values":[]},{"location-end":"3:63","location-start":"3:61","text":"\"x\"","values":[]}],"location-end":"3:64","location-start":"3:24","text":"data.child(\"missing\").val().contains(\"x\")","values":[]}],"location-end":"3:64","location-start":"3:15","text":"false && data.child(\"missing\").val().contains(\"x\")","values":[{"count":3,"value":false}]},"allowed":{".read":{"children":[{"location-end":"4:28","location-start":"4:25","text":"true","values":[{"count":1,"value":true}]},{"children":[{"children":[{"children":[{"children":[{"children":[{"children":[{"location-end":"4:36","location-start":"4:33","text":"data","values":[]},{"location-end":"4:42","location-start":"4:38","text":"child","values":[]}],"location-end":"4:42","location-start":"4:33","text":"data.child","values":[]},{"location-end":"4:52","location-start":"4:44","text":"\"missing\"","values":[]}],"location-end":"4:53","location-start":"4:33","text":"data.child(\"missing\")","values":[]},{"location-end":"4:57","location-start":"4:55","text":"val","values":[]}],"location-end":"4:57","location-start":"4:33","text":"data.child(\"missing\").val","values":[]}],"location-end":"4:59","location-start":"4:33","text":"data.child(\"missing\").val()","values":[]},{"location-end":"4:68","location-start":"4:61","text":"contains","values":[]}],"location-end":"4:68","location-start":"4:33","text":"data.child(\"missing\").val().contains","values":[]},{"location-end":"4:72","location-start":"4:70","text":"\"x\"","values":[]}],"location-end":"4:73","location-start":"4:33","text":"data.child(\"missing\").val().contains(\"x\")","values":[]}],"location-end":"4:73","location-start":"4:25","text":"true || data.child(\"missing\").val().contains(\"x\")","values":[{"count":1,"value":true}]},".validate":{"children":[{"children":[{"children":[{"location-end":"4:115","location-start":"4:109","text":"newData","values":[{"count":1,"value":"hash@class16"},{"count":1,"value":"hash@class17"}]},{"location-end":"4:124","location-start":"4:117","text":"isString","values":[{"count":2,"value":"isString"}]}],"location-end":"4:124","location-start":"4:109","text":"newData.isString","values":[{"count":1,"value":"hash@class18"},{"count":1,"value":"hash@class19"}]}],"location-end":"4:126","location-start":"4:109","text":"newData.isString()","values":[{"count":1,"value":true},{"count":1,"value":false}]},{"children":[{"children":[{"children":[{"children":[{"location-end":"4:137","location-start":"4:131","text":"newData","values":[{"count":1,"value":"hash@class16"}]},{"location-end":"4:141","location-start":"4:139","text":"val","values":[{"count":1,"value":"val"}]}],"location-end":"4:141","location-start":"4:131","text":"newData.val","values":[{"count":1,"value":"hash@class20"}]}],"location-end":"4:143","location-start":"4:131","text":"newData.val()","values":[{"count":1,"value":"observed"}]},{"location-end":"4:150","location-start":"4:145","text":"length","values":[{"count":1,"value":"length"}]}],"location-end":"4:150","location-start":"4:131","text":"newData.val().length","values":[{"count":1,"value":8.0}]},{"location-end":"4:154","location-start":"4:154","text":"0","values":[{"count":1,"value":0.0}]}],"location-end":"4:154","location-start":"4:131","text":"newData.val().length > 0","values":[{"count":1,"value":true}]}],"location-end":"4:154","location-start":"4:109","text":"newData.isString() && newData.val().length > 0","values":[{"count":1,"value":true},{"count":1,"value":false}]},".write":{"location-end":"4:93","location-start":"4:90","text":"true","values":[{"count":2,"value":true}]}},"denied":{".read":{"location-end":"5:27","location-start":"5:23","text":"false","values":[{"count":1,"value":false}]}},"runtimeError":{".read":{"children":[{"children":[{"children":[{"children":[{"children":[{"children":[{"location-end":"6:33","location-start":"6:30","text":"data","values":[{"count":1,"value":"hash@class21"}]},{"location-end":"6:39","location-start":"6:35","text":"child","values":[{"count":1,"value":"child"}]}],"location-end":"6:39","location-start":"6:30","text":"data.child","values":[{"count":1,"value":"hash@class22"}]},{"location-end":"6:49","location-start":"6:41","text":"\"missing\"","values":[{"count":1,"value":"missing"}]}],"location-end":"6:50","location-start":"6:30","text":"data.child(\"missing\")","values":[{"count":1,"value":"hash@class23"}]},{"location-end":"6:54","location-start":"6:52","text":"val","values":[{"count":1,"value":"val"}]}],"location-end":"6:54","location-start":"6:30","text":"data.child(\"missing\").val","values":[{"count":1,"value":"hash@class24"}]}],"location-end":"6:56","location-start":"6:30","text":"data.child(\"missing\").val()","values":[{"count":1,"value":null}]},{"location-end":"6:65","location-start":"6:58","text":"contains","values":[{"count":1,"value":"contains"}]}],"location-end":"6:65","location-start":"6:30","text":"data.child(\"missing\").val().contains","values":[]},{"location-end":"6:69","location-start":"6:67","text":"\"x\"","values":[]}],"location-end":"6:70","location-start":"6:30","text":"data.child(\"missing\").val().contains(\"x\")","values":[]}}},"rules":"{\r\n  \"rules\": {\r\n    \".read\": \"true && (false || data.child(\\\"é😀\\\").exists())\",\r\n    \".write\": \"false && data.child(\\\"missing\\\").val().contains(\\\"x\\\")\",\r\n    \"allowed\": {\".read\":\"true || data.child(\\\"missing\\\").val().contains(\\\"x\\\")\", \".write\":true, \".validate\":\"newData.isString() && newData.val().length > 0\"},\r\n    \"denied\": {\".read\":false},\r\n    \"runtimeError\": {\".read\":\"data.child(\\\"missing\\\").val().contains(\\\"x\\\")\"}\r\n  }\r\n}\r\n"}"#).unwrap();
    let mut database = db();
    for (name, method, target, owner, body, status) in steps {
        let (actual, response) = call(
            &mut database,
            &method,
            &target,
            if owner { OWNER } else { &[] },
            &body,
        );
        assert_eq!(actual, status, "{name}: {response}");
        if name == "compound-after-json" {
            let encoded: String = serde_json::from_str(&response).unwrap();
            let mut report: serde_json::Value = serde_json::from_str(&encoded).unwrap();
            normalize(&mut report, &mut std::collections::BTreeMap::new());
            assert_eq!(report, expected);
        }
    }
}

fn coverage(database: &mut Database, namespace: &str) -> serde_json::Value {
    let (status, body) = call(
        database,
        "GET",
        &format!("/.inspect/coverage.json?ns={namespace}"),
        &[],
        "",
    );
    assert_eq!(status, 200, "{body}");
    let inner: String = serde_json::from_str(&body).unwrap();
    serde_json::from_str(&inner).unwrap()
}

#[test]
fn coverage_lifetime_is_scoped_to_source_and_namespace() {
    let mut database = db();
    let text = "{\"rules\":{\".read\":true,\".write\":false}}\n";
    load(&mut database, "coverage-a", text);
    assert_eq!(
        call(&mut database, "GET", "/.json?ns=coverage-a", &[], "").0,
        200
    );
    assert_eq!(
        call(&mut database, "PUT", "/.json?ns=coverage-a", &[], "1").0,
        401
    );
    let before = coverage(&mut database, "coverage-a");
    assert_eq!(
        before["report"][".read"]["values"],
        serde_json::json!([{"value":true,"count":1}])
    );
    assert_eq!(
        before["report"][".write"]["values"],
        serde_json::json!([{"value":false,"count":1}])
    );
    assert!(before["report"][".read"].get("children").is_none());
    load(&mut database, "coverage-a", text);
    assert_eq!(coverage(&mut database, "coverage-a"), before);
    assert_eq!(
        call(
            &mut database,
            "PUT",
            "/.settings/rules.json?ns=coverage-a",
            OWNER,
            r#"{"rules":{".read":"true &&"}}"#
        )
        .0,
        400
    );
    for (method, body) in [("PUT", "1"), ("GET", ""), ("DELETE", "")] {
        assert_eq!(
            call(&mut database, method, "/.json?ns=coverage-a", OWNER, body).0,
            200
        );
    }
    load(&mut database, "coverage-b", text);
    call(&mut database, "GET", "/.json?ns=coverage-b", &[], "");
    assert_eq!(coverage(&mut database, "coverage-a"), before);
    load(
        &mut database,
        "coverage-a",
        r#"{"rules":{".read":false,".write":true}}"#,
    );
    assert_eq!(
        coverage(&mut database, "coverage-a")["report"][".read"]["values"],
        serde_json::json!([])
    );
    assert_eq!(
        call(&mut database, "GET", "/.json?ns=coverage-a", &[], "").0,
        401
    );
    assert_eq!(
        coverage(&mut database, "coverage-a")["report"][".read"]["values"],
        serde_json::json!([{"value":false,"count":1}])
    );
}

#[test]
fn coverage_consumes_seeded_pairwise_lifecycle_cases() {
    // PICT pairwise rows include the four mandatory regression seeds.
    let table = r"Outcome	ShortCircuit	Kind	Bypass	Namespace	Reload
allow	and	boolean	anonymous	same	none
error	none	call	anonymous	same	rejected
deny	or	unicode	override	other	same
allow	and	call	owner	other	changed
error	or	unicode	owner	same	none
deny	none	boolean	owner	other	same
error	and	unicode	anonymous	other	same
deny	none	boolean	override	same	changed
allow	or	call	override	same	same
error	or	unicode	anonymous	other	changed
deny	and	unicode	owner	other	rejected
deny	none	call	override	other	none
error	or	boolean	override	same	rejected
allow	and	unicode	override	other	rejected
allow	none	unicode	owner	same	same
deny	none	boolean	anonymous	other	none
";
    for row in table.lines().skip(1) {
        let values: Vec<_> = row.split('\t').collect();
        let [outcome, short_circuit, kind, bypass, scope, reload] = values.as_slice() else {
            panic!("invalid row {row}")
        };
        let result = match *outcome {
            "allow" => "true",
            "deny" => "false",
            _ => "data.child('absent').val().contains('x')",
        };
        let result = match *kind {
            "unicode" => format!("'é😀'.length == 3 && ({result})"),
            "call" => format!("!data.exists() && ({result})"),
            _ => result.to_owned(),
        };
        let expression = match *short_circuit {
            "and" => format!("true && ({result})"),
            "or" => format!("false || ({result})"),
            _ => result,
        };
        let source = serde_json::json!({"rules":{".read":expression,".write":false}}).to_string();
        let mut database = db();
        load(&mut database, "coverage-pict-a", &source);
        let namespace = if *scope == "same" {
            "coverage-pict-a"
        } else {
            load(&mut database, "coverage-pict-b", &source);
            "coverage-pict-b"
        };
        let untouched = coverage(&mut database, "coverage-pict-a");
        let headers = if *bypass == "anonymous" {
            &[][..]
        } else {
            OWNER
        };
        let suffix = if *bypass == "override" {
            "&auth_variable_override=null"
        } else {
            ""
        };
        let status = call(
            &mut database,
            "GET",
            &format!("/.json?ns={namespace}{suffix}"),
            headers,
            "",
        )
        .0;
        assert_eq!(
            status,
            if *bypass == "owner" || *outcome == "allow" {
                200
            } else {
                401
            },
            "{row}"
        );
        let before = coverage(&mut database, namespace);
        let values = before["report"][".read"]["values"].as_array().unwrap();
        assert_eq!(
            values.is_empty(),
            *bypass == "owner" || *outcome == "error",
            "{row}"
        );
        match *reload {
            "same" => {
                load(&mut database, namespace, &source);
            }
            "rejected" => {
                assert_eq!(
                    call(
                        &mut database,
                        "PUT",
                        &format!("/.settings/rules.json?ns={namespace}"),
                        OWNER,
                        r#"{"rules":{".read":"true &&"}}"#
                    )
                    .0,
                    400
                );
            }
            "changed" => {
                load(&mut database, namespace, r#"{"rules":{".read":false}}"#);
            }
            _ => {}
        }
        let after = coverage(&mut database, namespace);
        if *reload == "changed" {
            assert_eq!(after["report"][".read"]["values"], serde_json::json!([]));
        } else {
            assert_eq!(after, before, "{row}");
        }
        if *scope == "other" {
            assert_eq!(
                coverage(&mut database, "coverage-pict-a"),
                untouched,
                "{row}"
            );
        }
        assert_eq!(
            call(
                &mut database,
                "GET",
                &format!("/.json?ns={namespace}"),
                OWNER,
                ""
            )
            .1,
            "null"
        );
    }
}

#[test]
fn coverage_html_embeds_the_same_data_and_escapes_script_breakers() {
    let mut database = db();
    let source = serde_json::json!({"rules":{".read":"'</script><img src=x onerror=alert(1)>😀'.length > 0"}}).to_string();
    let source = format!("/*\u{2028}*/{source}");
    load(&mut database, "coverage-html", &source);
    let expected = coverage(&mut database, "coverage-html");
    let (response, _) = respond(
        &mut database,
        "GET",
        "/.inspect/coverage?ns=coverage-html",
        &[],
        "",
    );
    assert_eq!(response.status, 200);
    assert!(response.headers.contains(&(
        "Content-Type".to_owned(),
        "text/html; charset=UTF-8".to_owned()
    )));
    let html = String::from_utf8(response.body).unwrap();
    let data = html
        .split_once("<script id=\"coverage-data\" type=\"application/json\">")
        .unwrap()
        .1
        .split_once("</script>")
        .unwrap()
        .0;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(data).unwrap(),
        expected
    );
    assert!(!data.contains("</script>"));
    assert!(!data.contains('\u{2028}'));
    assert!(!html.contains("innerHTML"));
    for name in ["coverage", "coverage.json"] {
        let (status, body) = call(
            &mut database,
            "POST",
            &format!("/.inspect/{name}?ns=coverage-html"),
            &[],
            "",
        );
        assert_eq!(status, 405);
        assert!(serde_json::from_str::<serde_json::Value>(&body)
            .unwrap()
            .is_object());
    }
    let mut protected = Database::new(
        RestOptions {
            inspect_needs_owner: true,
            ..RestOptions::default()
        },
        7,
    );
    for name in ["coverage", "coverage.json"] {
        assert_eq!(
            call(
                &mut protected,
                "GET",
                &format!("/.inspect/{name}?ns=coverage-html"),
                &[],
                ""
            )
            .0,
            401
        );
        assert_eq!(
            call(
                &mut protected,
                "GET",
                &format!("/.inspect/{name}?ns=coverage-html"),
                OWNER,
                ""
            )
            .0,
            200
        );
    }
}

#[test]
fn coverage_valid_callees_record_arguments_and_invalid_callees_keep_completed_children() {
    let mut database = db();
    let text = r#"{"rules":{".read":"data.val().contains('argument')"}}"#;
    load(&mut database, "coverage-callee", text);
    assert_eq!(
        call(&mut database, "GET", "/.json?ns=coverage-callee", &[], "").0,
        401
    );
    let report = coverage(&mut database, "coverage-callee");
    let expression = &report["report"][".read"];
    assert_eq!(expression["values"], serde_json::json!([]));
    assert_eq!(expression["children"][1]["values"], serde_json::json!([]));
    assert_eq!(
        expression["children"][0]["children"][1]["values"],
        serde_json::json!([{"value":"contains","count":1}])
    );
    assert_eq!(
        expression["children"][0]["children"][0]["values"],
        serde_json::json!([{"value":null,"count":1}])
    );
    call(
        &mut database,
        "PUT",
        "/.json?ns=coverage-callee",
        OWNER,
        r#""argument""#,
    );
    assert_eq!(
        call(&mut database, "GET", "/.json?ns=coverage-callee", &[], "").0,
        200
    );
    let report = coverage(&mut database, "coverage-callee");
    assert_eq!(
        report["report"][".read"]["children"][1]["values"],
        serde_json::json!([{"value":"argument","count":1}])
    );
    assert_eq!(
        call(&mut database, "GET", "/.json?ns=coverage-callee", OWNER, "").1,
        r#""argument""#
    );
}

#[test]
fn coverage_same_source_reload_still_revalidates_streams() {
    let mut database = db();
    let text = serde_json::json!({"rules":{".read":format!("now < {LATER}")}}).to_string();
    load(&mut database, "coverage-revalidate", &text);
    let request = request(
        "GET",
        "/.json?ns=coverage-revalidate",
        &[("Accept", "text/event-stream")],
        "",
    );
    let Handled::Stream { id, .. } = database.handle(&request, NOW) else {
        panic!("stream")
    };
    let before = coverage(&mut database, "coverage-revalidate");
    assert_eq!(
        before["report"][".read"]["values"],
        serde_json::json!([{"value":true,"count":1}])
    );
    let events = database
        .set_rules("coverage-revalidate", &text, LATER)
        .unwrap();
    assert_eq!(events, vec![(id, SseEvent::cancel())]);
    assert_eq!(database.subscription_count(), 0);
    assert_eq!(
        coverage(&mut database, "coverage-revalidate")["report"][".read"]["values"],
        serde_json::json!([{"value":true,"count":1},{"value":false,"count":1}])
    );
}

#[test]
fn coverage_local_decoded_coordinates_keep_raw_unicode_and_escape_anchors_separate() {
    let mut database = db();
    for (source, expected_text, leading) in [
        (
            serde_json::json!({"rules":{"é😀":{".read":"  '😀'.length > 0 && (\ntrue)"}}})
                .to_string(),
            "'😀'.length > 0 && (\ntrue)",
            2,
        ),
        (
            r#"{"rules":{"é😀":{".read":"\u0074rue"}}}"#.to_owned(),
            "true",
            0,
        ),
    ] {
        load(&mut database, "coverage-positions", &source);
        let anchor = source.find("\".read\":\"").unwrap() + "\".read\":\"".len();
        let column = source[..anchor].encode_utf16().count() + leading;
        let report = coverage(&mut database, "coverage-positions");
        let node = &report["report"]["é😀"][".read"];
        assert_eq!(node["text"], expected_text);
        assert_eq!(node["location-start"], format!("0:{column}"));
        if expected_text.contains('\n') {
            assert_eq!(node["location-end"], "1:4");
        } else {
            assert_eq!(node["location-end"], format!("0:{}", column + 3));
        }
    }
}

#[test]
fn coverage_html_preserves_prototype_named_rule_children_as_json_data() {
    let mut database = db();
    let source = r#"{"rules":{"__proto__":{".read":true},"constructor":{".read":false},"prototype":{".read":"true || data.child('unvisited').exists()"}}}"#;
    load(&mut database, "coverage-properties", source);
    for name in ["__proto__", "constructor", "prototype"] {
        call(
            &mut database,
            "GET",
            &format!("/{name}.json?ns=coverage-properties"),
            &[],
            "",
        );
    }
    let expected = coverage(&mut database, "coverage-properties");
    let (status, html) = call(
        &mut database,
        "GET",
        "/.inspect/coverage?ns=coverage-properties",
        &[],
        "",
    );
    assert_eq!(status, 200);
    let data = html
        .split_once("<script id=\"coverage-data\" type=\"application/json\">")
        .unwrap()
        .1
        .split_once("</script>")
        .unwrap()
        .0;
    let parsed: serde_json::Value = serde_json::from_str(data).unwrap();
    assert_eq!(parsed, expected);
    for name in ["__proto__", "constructor", "prototype"] {
        assert!(parsed["report"].get(name).is_some());
    }
    assert!(html.contains("JSON.parse(document.getElementById('coverage-data').textContent)"));
    assert!(html.contains("Object.hasOwn(report,key)"));
}

#[test]
fn gauth_refusal_profile_shape_and_prior_access_matrix() {
    let mut cases = Vec::new();
    for profile in ["strict", "emulator"] {
        for prior in ["anonymous", "owner", "user"] {
            for shape in ["fixed", "other", "owner", "scalar", "missing"] {
                cases.push((profile.to_owned(), prior.to_owned(), shape.to_owned()));
            }
        }
    }
    if let Ok(path) = std::env::var("FIREEMU_GAUTH_PICT_TABLE") {
        let table = std::fs::read_to_string(path).unwrap();
        for row in table.lines().skip(1) {
            let cells: Vec<_> = row.split('\t').collect();
            assert_eq!(cells.len(), 3);
            cases.push((
                cells[0].to_owned(),
                cells[1].to_owned(),
                cells[2].to_owned(),
            ));
        }
    }
    for (profile, prior, shape) in cases {
        let strict = profile == "strict";
        let mut db = with_credentials(strict, true);
        load(
            &mut db,
            "demo-default-rtdb",
            r#"{"rules":{"private":{".read":"auth != null && auth.uid === 'ok-1'"},"anonymous":{".read":"auth == null"},"closed":{".read":false}}}"#,
        );
        let mut session = open(&mut db, "demo-default-rtdb");
        match prior.as_str() {
            "owner" => {
                send(&mut db, &mut session, 1, "gauth", r#"{"cred":"owner"}"#);
            }
            "user" => {
                send(
                    &mut db,
                    &mut session,
                    1,
                    "auth",
                    &format!(r#"{{"cred":"{}"}}"#, token(r#"{"sub":"ok-1","iat":1}"#)),
                );
            }
            "anonymous" => {}
            _ => panic!("unexpected prior access"),
        }
        let credential = match shape.as_str() {
            "fixed" => r#"{"cred":"cv11-portless-fixed-invalid-nonsecret"}"#,
            "other" => r#"{"cred":"ya29.x"}"#,
            "owner" => r#"{"cred":"owner"}"#,
            "scalar" => r#"{"cred":7}"#,
            "missing" => "{}",
            _ => panic!("unexpected credential shape"),
        };
        let answer = send(&mut db, &mut session, 3, "gauth", credential);
        let refused_string = strict && matches!(shape.as_str(), "fixed" | "other");
        let refused_scalar = strict && shape == "scalar";
        if shape == "missing" {
            assert!(answer.is_empty());
        } else if refused_string {
            assert_eq!(
                answer,
                vec![reply(3, "permission_denied", r#""Permission denied""#)],
                "{profile}/{prior}/{shape}"
            );
        } else if refused_scalar {
            assert_eq!(
                answer,
                vec![reply(
                    3,
                    "invalid_token",
                    r#""Could not parse auth token.""#
                )]
            );
        } else {
            assert_eq!(
                answer,
                vec![reply(
                    3,
                    "ok",
                    &format!(r#"{{"auth":null,"expires":{}}}"#, NOW / 1000 + 3600)
                )]
            );
        }
        let expected_owner = if shape == "missing" {
            prior == "owner"
        } else {
            !refused_string && !refused_scalar
        };
        let expected_user = shape == "missing" && prior == "user";
        for (request, path, allowed) in [
            (4, "/closed", expected_owner),
            (5, "/private", expected_owner || expected_user),
            (6, "/anonymous", !expected_user),
        ] {
            assert_eq!(
                send(
                    &mut db,
                    &mut session,
                    request,
                    "g",
                    &format!(r#"{{"p":"{path}"}}"#)
                ),
                vec![if allowed {
                    reply(request, "ok", "null")
                } else {
                    refused(request)
                }],
                "{profile}/{prior}/{shape}/{path}"
            );
        }
    }
}

/// Review M1 (2026-10-25): every read mints fresh opaque `data` identities, so a long-lived
/// daemon's coverage keeps the first values of each expression and counts the rest instead of
/// growing; the JSON and the HTML viewer both carry the omitted count.
#[test]
fn coverage_of_a_long_run_keeps_its_first_values_and_counts_the_rest() {
    const READS: usize = 100;
    let mut database = db();
    let source = r#"{"rules":{".read":"data.child('x').exists() || true"}}"#;
    load(&mut database, "coverage-bounded", source);
    for _ in 0..READS {
        assert_eq!(
            call(&mut database, "GET", "/.json?ns=coverage-bounded", &[], "").0,
            200
        );
    }
    let report = coverage(&mut database, "coverage-bounded");
    let read = &report["report"][".read"];
    assert_eq!(
        read["values"],
        serde_json::json!([{"value": true, "count": READS}])
    );
    assert!(read.get("values-omitted").is_none(), "{read}");
    let mut data = &read["children"][0];
    while let Some(first) = data.get("children") {
        data = &first[0];
    }
    assert_eq!(data["text"], "data");
    let kept = data["values"].as_array().unwrap();
    assert_eq!(
        kept.len(),
        fireemu_core_database::rules::COVERAGE_VALUES_PER_EXPRESSION
    );
    assert!(kept.iter().all(|entry| entry["count"] == 1));
    assert_eq!(data["values-omitted"], READS - kept.len());
    let (status, html) = call(
        &mut database,
        "GET",
        "/.inspect/coverage?ns=coverage-bounded",
        &[],
        "",
    );
    assert_eq!(status, 200);
    assert!(html.contains(r#""values-omitted":36"#), "{html}");
    assert!(html.contains("more result(s) with other values"));
}
