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
            assert_eq!(other, vec![unparsable.clone()]);
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

/// Runs `f` on a thread with the stack of a tokio worker (2 MiB), where requests run.
fn on_worker_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn deep_rules_are_refused_without_exhausting_the_stack() {
    on_worker_stack(|| {
        let mut db = db();
        let put = |db: &mut Database, body: &str| {
            call(db, "PUT", "/.settings/rules.json?ns=deep", OWNER, body)
        };
        let groups = |n: usize| {
            format!(
                r#"{{"rules":{{".read":"{}true{}"}}}}"#,
                "(".repeat(n),
                ")".repeat(n)
            )
        };
        let nots = |n: usize| format!(r#"{{"rules":{{".read":"{}true"}}}}"#, "!".repeat(n));
        let levels = |n: usize| {
            format!(
                r#"{{"rules":{}{{}}{}}}"#,
                r#"{"a":"#.repeat(n),
                "}".repeat(n)
            )
        };
        // Up to the local budget an expression loads and is evaluated (the official emulator
        // loads up to 600 groups and 1,000 `!`); rule levels load as deep as it loads them.
        for body in [groups(255), nots(255), levels(1000)] {
            let (status, text) = put(&mut db, &body);
            assert_eq!(status, 200, "{text}");
            call(&mut db, "GET", "/a.json?ns=deep", &[], "");
        }
        for (body, message) in [
            (groups(256), "1:20: Rule expression may not be empty."),
            (nots(256), "1:20: Rule expression may not be empty."),
            (groups(10_000), "1:20: Rule expression may not be empty."),
            (nots(10_000), "1:20: Rule expression may not be empty."),
        ] {
            let (status, text) = put(&mut db, &body);
            assert_eq!(status, 400);
            assert!(text.contains(message), "{text}");
        }
        for n in [1001, 10_000] {
            assert_eq!(put(&mut db, &levels(n)).0, 400, "{n}");
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
